"""Write the outcome: a Proposal object per suggestion, and a BuilderPublish claim carrying the change.

THIS SERVICE NO LONGER TALKS TO GITHUB, AND NO LONGER HOLDS A TOKEN. It used to branch, PUT a file and
open a pull request over the REST API with its own credential. Everything below now renders a claim to
the platform's own publish chain — Repository -> Repo -> LocalResource per file -> PullRequest — which
portal-builder and blueprint-builder already use. The credential is git-provider's, the ordering gate
that stops GitHub's 422 ("no commits between main and the branch") is the chain's, and PullRequest is
level-based so a re-render cannot open a second one.

THE AGENT STILL NEVER WRITES. That split is unchanged and is still the whole safety argument; what
changed is that the service does not hold a write credential either.
"""
import datetime as dt
import os

from kubernetes import client
from kubernetes.client.rest import ApiException

import proposals

NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
GROUP, VERSION = "review.krateo.io", "v1alpha1"

# The publish chain's own group. The KIND is version-pinned in the served CRD (v1-8-46 and so on), and
# that version moves with every portal release — so it is DISCOVERED at run time rather than compiled
# in. A hardcoded version would publish nothing the morning after a portal bump, and would do it
# quietly, because the apiserver simply reports the kind as unknown.
PUBLISH_GROUP = "composition.krateo.io"
PUBLISH_PLURAL = "builderpublishes"
PUBLISH_BUILDER = os.environ.get("PUBLISH_BUILDER", "review")


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def publish_version():
    """The served version of the BuilderPublish kind, read from the CRD rather than assumed.

    The kind is version-pinned by the portal release that shipped it, so this changes under us. Reading
    it costs one GET and turns "publishing silently stopped after a portal roll" into a normal failure
    with a name attached."""
    crd = client.ApiextensionsV1Api().read_custom_resource_definition(
        f"{PUBLISH_PLURAL}.{PUBLISH_GROUP}")
    # SERVED, NEVER STORAGE. On 057 this CRD carries two versions: the composition version that is
    # actually served (v1-8-46 and so on), and `vacuum` — which is marked storage:true and served:FALSE,
    # and carries no spec schema at all. Preferring the storage version, which is the reflex, returns
    # `vacuum` and every claim then fails with "no matches for kind", because the apiserver does not
    # serve it. Measured on the cluster rather than reasoned about: this code picked `vacuum` first.
    served = [v.name for v in crd.spec.versions if v.served]
    if not served:
        raise RuntimeError(f"{PUBLISH_PLURAL}.{PUBLISH_GROUP} serves no version")
    if len(served) > 1:
        # Several served versions is a portal mid-migration. Take the newest by the v<major>-<minor>-
        # <patch> ordering the composition versions use, rather than whichever the API happened to list.
        def key(name):
            return [int(x) for x in name.lstrip("v").split("-") if x.isdigit()]
        served = sorted(served, key=key, reverse=True)
    return served[0]


def create_publish_claim(api, proposal, run_name, version=None, queries_run=None):
    """Render one proposal as a BuilderPublish claim. Returns {name, apiVersion, branch}.

    IT IS `builder: review`, AND THAT MATTERS MORE THAN IT LOOKS. The value sets krateo.io/builder on
    every CR the chain renders and is interpolated into each commit message, and the portal's lists
    select on it. Publishing as `blueprint` would make an overnight machine suggestion indistinguishable
    from a blueprint a person authored, in their lists and in the git history. The enum gained `review`
    for exactly this (portal 1.8.46).

    REPOSITORY CREATION IS OFF. A review proposal targets a repository that already exists; the chain's
    default is to create one, which for a typo'd target would mean conjuring a repository rather than
    failing. `target.base` is left at the chain's default rather than discovered, because discovering a
    default branch is a GitHub call and not holding a GitHub credential is the point of this change."""
    org, _, repo = proposal["target"]["repo"].partition("/")
    if not org or not repo:
        raise ValueError(f"target.repo {proposal['target']['repo']!r} is not owner/name")
    fp = proposal["fingerprint"][:12]
    name = f"review-{fp}"
    branch = f"review/{proposal['kind'].lower()}-{fp}"
    path = proposal["target"].get("path") or f"proposals/{proposal['fingerprint']}.yaml"
    version = version or publish_version()

    body = {
        "apiVersion": f"{PUBLISH_GROUP}/{version}",
        "kind": "BuilderPublish",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                "review.krateo.io/run": run_name,
                "review.krateo.io/fingerprint": proposal["fingerprint"][:63],
            },
        },
        "spec": {
            "name": name,
            "branch": branch,
            "builder": PUBLISH_BUILDER,
            "target": {"namespace": org, "repo": repo},
            "repository": {"create": False},
            "files": [{"path": path, "content": proposal["change"]["content"]}],
            "pullRequest": {
                "create": True,
                "title": f"review: {proposal['title']}",
                "body": _pr_body(proposal, run_name, queries_run),
            },
        },
    }
    try:
        api.create_namespaced_custom_object(PUBLISH_GROUP, version, NAMESPACE, PUBLISH_PLURAL, body)
    except ApiException as exc:
        # ALREADY THERE IS NORMAL. The name derives from the fingerprint, so the same suggestion on a
        # later night lands on the same claim. The chain is level-based; re-asserting the spec is how it
        # is meant to be driven, and it will not open a second pull request.
        if exc.status != 409:
            raise
        api.patch_namespaced_custom_object(PUBLISH_GROUP, version, NAMESPACE, PUBLISH_PLURAL, name,
                                           {"spec": body["spec"]})
    return {"name": name, "apiVersion": body["apiVersion"], "branch": branch}


def _pr_body(proposal, run_name, queries_run=None):
    """The body leads with the EVIDENCE, not the suggestion.

    A reviewer's first question is "why do you think so", and a proposal that answers it last gets
    approved on tone. The queries THIS SERVICE ISSUED are rendered below, verbatim, so the claim can be
    re-run and disagreed with — the model is no longer asked to restate them, because when it was it
    supplied a reconstruction that matched nothing that ran."""
    ev = "\n".join(
        f"- **{e['source']}**"
        + (f" ({e['observedCount']} observed)" if e.get("observedCount") is not None else "")
        + f" — {e['summary']}"
        for e in proposal["evidence"]
    )
    # THE QUERIES THE SERVICE RAN, NOT THE ONES THE MODEL REMEMBERS RUNNING. The contract asks a proposal
    # to carry its query so a reviewer can re-run it and disagree — and the model supplied a plausible
    # paraphrase with no window clause, matching nothing that was issued. A reviewer who re-runs that
    # gets a different number and concludes the reviewer is unreliable: correctly, for the wrong reason.
    # These come from evidence.py, which issued them.
    ran = ""
    if queries_run:
        ran = "\n\n## Queries this run issued\n\n" + "\n\n".join(
            f"`{name}`\n```sql\n{sql}\n```" for name, sql in sorted(queries_run.items()))
    return f"""**Proposed by the nightly platform review — not by a person.** Confidence: `{proposal['confidence']}`.

## Why

{proposal['rationale']}

## Evidence

{ev}{ran}

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
PHASE_FAILED = "Failed"

OPEN_PHASES = frozenset({None, PHASE_PROPOSED, PHASE_PR_OPEN})
WRITTEN_PHASES = frozenset({PHASE_PROPOSED, PHASE_PR_OPEN, PHASE_SUPERSEDED, PHASE_FAILED})


def create_proposal_cr(api, proposal, run_name, claim=None, phase=PHASE_PROPOSED, error=None):
    obj = {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "Proposal",
        "metadata": {
            "name": f"p-{proposal['fingerprint'][:16]}",
            "namespace": NAMESPACE,
            "labels": {
                "review.krateo.io/kind": proposal["kind"],
                "review.krateo.io/run": run_name,
                "review.krateo.io/confidence": proposal["confidence"],
            }
            # THE CLAIM IS RECORDED AS A LABEL, NOT A STATUS FIELD, and deliberately so: the Proposal
            # CRD is structural with no preserve-unknown-fields, so an undeclared status key is pruned
            # SILENTLY — the object would come back looking as though nothing had been published. A
            # label needs no schema change and is selectable, which is what a later reconciler will use
            # to find the claim whose pull request it must read back.
            | ({"review.krateo.io/publish-claim": claim["name"]} if claim else {}),
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
    # PUBLISHING IS ASYNCHRONOUS NOW, so this run cannot know the pull request. It created a claim; the
    # chain opens the PR minutes later, on its own reconcile. Writing PrOpen here would be a guess, and
    # writing status.pullRequest would be a fabrication — both stay for the reconciler that reads the
    # real outcome back. Proposed is the honest phase for "handed to the chain, not yet decided".
    status = {"phase": phase, "conditions": []}
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
