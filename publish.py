"""Write the outcome: a Proposal object per suggestion, and a pull request carrying the change.

THE SERVICE WRITES; THE AGENT NEVER DOES. Everything here runs on validated, redacted data and a
credential the model cannot reach. That split is the whole safety argument: a prompt injection can at
worst produce a malformed or out-of-allowlist proposal, which is refused upstream of this file.
"""
import base64
import datetime as dt
import os

import requests

GH_API = os.environ.get("GITHUB_API", "https://api.github.com")
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
GROUP, VERSION = "review.krateo.io", "v1alpha1"


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def open_pull_request(proposal, run_name):
    """Branch, commit one file, open a PR. Returns {url, number, state} or raises."""
    repo = proposal["target"]["repo"]
    path = proposal["target"].get("path") or f"proposals/{proposal['fingerprint']}.yaml"
    branch = f"review/{proposal['kind'].lower()}-{proposal['fingerprint'][:12]}"
    h = {"Authorization": f"Bearer {GH_TOKEN}", "Accept": "application/vnd.github+json"}

    default = requests.get(f"{GH_API}/repos/{repo}", headers=h, timeout=30).json()["default_branch"]
    base = requests.get(f"{GH_API}/repos/{repo}/git/refs/heads/{default}", headers=h, timeout=30).json()
    sha = base["object"]["sha"]

    r = requests.post(f"{GH_API}/repos/{repo}/git/refs", headers=h, timeout=30,
                      json={"ref": f"refs/heads/{branch}", "sha": sha})
    if r.status_code not in (201, 422):        # 422 = branch exists from an earlier attempt; reuse it
        r.raise_for_status()

    existing = requests.get(f"{GH_API}/repos/{repo}/contents/{path}",
                            headers=h, params={"ref": branch}, timeout=30)
    body = {
        "message": f"review: {proposal['title']}",
        "content": base64.b64encode(proposal["change"]["content"].encode()).decode(),
        "branch": branch,
    }
    if existing.status_code == 200:
        body["sha"] = existing.json()["sha"]
    requests.put(f"{GH_API}/repos/{repo}/contents/{path}", headers=h, json=body, timeout=60).raise_for_status()

    pr = requests.post(f"{GH_API}/repos/{repo}/pulls", headers=h, timeout=30, json={
        "title": f"review: {proposal['title']}",
        "head": branch, "base": default,
        "body": _pr_body(proposal, run_name),
    })
    if pr.status_code == 422:                  # a PR for this branch already exists
        found = requests.get(f"{GH_API}/repos/{repo}/pulls", headers=h,
                             params={"head": f"{repo.split('/')[0]}:{branch}", "state": "open"},
                             timeout=30).json()
        if found:
            return {"url": found[0]["html_url"], "number": found[0]["number"], "state": "open"}
    pr.raise_for_status()
    return {"url": pr.json()["html_url"], "number": pr.json()["number"], "state": "open"}


def _pr_body(proposal, run_name):
    """The body leads with the EVIDENCE, not the suggestion.

    A reviewer's first question is "why do you think so", and a proposal that answers it last gets
    approved on tone. Each query is included verbatim so the claim can be re-run and disagreed with."""
    ev = "\n".join(
        f"- **{e['source']}**"
        + (f" ({e['observedCount']} observed)" if e.get("observedCount") is not None else "")
        + f" — {e['summary']}"
        + (f"\n  ```\n  {e['query']}\n  ```" if e.get("query") else "")
        for e in proposal["evidence"]
    )
    return f"""**Proposed by the nightly platform review — not by a person.** Confidence: `{proposal['confidence']}`.

## Why

{proposal['rationale']}

## Evidence

{ev}

## What this changes

`{proposal['target'].get('path') or '(new file)'}` — {proposal['change']['format']}, {len(proposal['change']['content'])} bytes.

---

Confidence describes the evidence above, not the reviewer's enthusiasm: a proposal resting on a single
observation is capped to `medium` before it reaches you. If the evidence does not persuade you, the
right outcome is to close this — a rejected proposal is a working loop, not a failed one.

Produced by `ReviewRun/{run_name}` · tracked as `Proposal` in `{NAMESPACE}`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
"""


def create_proposal_cr(api, proposal, run_name, pr=None, phase="Proposed", error=None):
    obj = {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "Proposal",
        "metadata": {
            "name": f"p-{proposal['fingerprint'][:16]}",
            "namespace": NAMESPACE,
            "labels": {
                "review.krateo.io/kind": proposal["kind"],
                "review.krateo.io/run": run_name,
                "review.krateo.io/confidence": proposal["confidence"],
            },
        },
        "spec": {k: proposal[k] for k in
                 ("kind", "title", "rationale", "evidence", "confidence", "target", "change", "fingerprint")}
                | {"producedBy": {"runRef": run_name, "agent": "krateo-autopilot"}},
    }
    created = api.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals", obj)
    status = {"phase": phase, "conditions": []}
    if pr:
        status |= {"phase": "PrOpen", "pullRequest": pr}
    if error:
        status |= {"phase": "Failed", "error": str(error)[:500]}
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "proposals", created["metadata"]["name"], {"status": status})
    return created["metadata"]["name"]


def open_fingerprints(api):
    """Fingerprints already carried by a proposal that is still undecided. Night two supersedes rather
    than reproposes; without this the reviewer is handed the same suggestions every morning until they
    stop reading them."""
    got = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals").get("items", [])
    return {
        (p.get("spec") or {}).get("fingerprint"): p["metadata"]["name"]
        for p in got
        if (p.get("status") or {}).get("phase") in (None, "Proposed", "PrOpen")
    }
