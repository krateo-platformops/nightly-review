"""Write the outcome: a Proposal object per suggestion, and a pull request carrying the change.

THE SERVICE WRITES; THE AGENT NEVER DOES. Everything here runs on validated, redacted data and a
credential the model cannot reach. That split is the whole safety argument: a prompt injection can at
worst produce a malformed or out-of-allowlist proposal, which is refused upstream of this file.
"""
import base64
import datetime as dt
import os

import requests
from kubernetes.client.rest import ApiException

import proposals

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


# THE PHASE VOCABULARY, DECLARED ONCE.
#
# These values used to be bare strings written in one function and matched by literal in another, a few
# dozen lines apart. They agreed, so nothing was wrong today — but the agreement was invisible and
# unenforced, and renaming one of them would have made `open_index` match nothing, which does not
# raise: it silently reports every proposal as new and re-proposes the entire backlog. A contract whose
# breach produces no error and no missing output is the kind worth spending eight lines on.
#
# WRITTEN_PHASES is asserted against the CRD's own enum by the test suite, because the apiserver
# rejects an undeclared phase at WRITE time — long after the review has been done and paid for.
PHASE_PROPOSED = "Proposed"
PHASE_PR_OPEN = "PrOpen"
PHASE_SUPERSEDED = "Superseded"
PHASE_REFUSED = "Refused"
PHASE_FAILED = "Failed"

OPEN_PHASES = frozenset({None, PHASE_PROPOSED, PHASE_PR_OPEN})
WRITTEN_PHASES = frozenset({PHASE_PROPOSED, PHASE_PR_OPEN, PHASE_SUPERSEDED, PHASE_REFUSED, PHASE_FAILED})


def create_proposal_cr(api, proposal, run_name, pr=None, phase=PHASE_PROPOSED, error=None):
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
    try:
        created = api.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals", obj)
    except ApiException as exc:
        # ALREADY THERE, AND THAT IS NORMAL NOW. The name is derived from the fingerprint, and a refused
        # proposal recurs every night with the same one (a refusal is not `open`, so dedup does not
        # suppress it). Before this, night two died on a 409 from a name night one had created.
        if exc.status != 409:
            raise
        api.patch_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals", obj["metadata"]["name"],
                                           {"spec": obj["spec"]})
        created = api.get_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals",
                                                   obj["metadata"]["name"])
    status = {"phase": phase, "conditions": []}
    if pr:
        status |= {"phase": PHASE_PR_OPEN, "pullRequest": pr}
    if error:
        status |= {"phase": PHASE_FAILED, "error": str(error)[:500]}
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "proposals", created["metadata"]["name"], {"status": status})
    return created["metadata"]["name"]


def open_index(api):
    """(by_fingerprint, by_target) over proposals that are still undecided.

    Two indexes because there are two questions, and the old code could only ask one. By fingerprint
    answers "have we said exactly this?" — a duplicate, dropped. By target answers "have we said
    something else about this same file?" — a replacement, which supersedes. Returning only the first
    is why every re-worded repeat looked new."""
    got = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals").get("items", [])
    by_fingerprint, by_target = {}, {}
    for p in got:
        if (p.get("status") or {}).get("phase") not in OPEN_PHASES:
            continue
        spec = p.get("spec") or {}
        fp, name = spec.get("fingerprint"), p["metadata"]["name"]
        if not fp or not spec.get("kind"):
            continue
        by_fingerprint[fp] = name
        by_target[proposals.target_key(spec)] = {"fingerprint": fp, "name": name}
    return by_fingerprint, by_target


def mark_superseded(api, name):
    """The open proposal this one replaces. Status only — the spec of a superseded proposal is left
    exactly as it was, because it is the record of what was suggested and when."""
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "proposals", name, {"status": {"phase": PHASE_SUPERSEDED}})
