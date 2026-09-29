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

Confidence is the reviewing model's own judgement of the evidence above, and nothing checks it. If
the evidence does not persuade you, the
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

PHASE_REJECTED = "Rejected"
PHASE_MERGED = "Merged"

OPEN_PHASES = frozenset({None, PHASE_PROPOSED, PHASE_PR_OPEN})
# Rejected is written now, as the mirror of a person's spec.decision.
WRITTEN_PHASES = frozenset({PHASE_PROPOSED, PHASE_PR_OPEN, PHASE_SUPERSEDED, PHASE_FAILED, PHASE_REJECTED})
# What a person may record in spec.decision. Asserted against the CRD's decision enum by the suite.
DECISION_PHASES = frozenset({PHASE_PR_OPEN, PHASE_REJECTED})
# A PERSON'S VERDICT, as opposed to the service's own bookkeeping. Superseded and Failed are this
# service's to set and to undo — the same finding coming back is a reason to re-open one. Rejected and
# Merged are somebody's answer, and a later night re-proposing the same fingerprint must not rewrite them.
PERSON_DECIDED_PHASES = frozenset({PHASE_REJECTED, PHASE_MERGED})


def decision(p):
    """spec.decision when it carries a phase this service recognises, else None. A malformed one is
    ignored rather than trusted: the CRD enum should make it impossible, and a proposal this code
    cannot read is left for a person rather than guessed at."""
    d = (p.get("spec") or {}).get("decision")
    if isinstance(d, dict) and d.get("phase") in DECISION_PHASES:
        return d
    return None


def effective_phase(p):
    """THE PHASE TO ACT ON: spec.decision's when there is one, status.phase otherwise.

    The spec wins because it is newer by construction. The portal writes the decision into the spec
    (snowplow /call cannot reach the status subresource) and this service copies it to status only on
    its next run — so for up to a night status still says Proposed about a proposal a person has
    already rejected. Reading status there is how a rejected suggestion gets superseded, or rewritten
    back to Proposed, by the very run that should have respected it.

    ONE EXCEPTION: a PrOpen decision whose status has already moved on to Merged. Merge is the outcome
    the pull request reached, written by whatever reads it back, and it is later than the decision
    that opened it — not a disagreement to settle in the decision's favour."""
    status_phase = (p.get("status") or {}).get("phase")
    d = decision(p)
    if d is None:
        return status_phase
    if d["phase"] == PHASE_PR_OPEN and status_phase == PHASE_MERGED:
        return status_phase
    return d["phase"]


def person_decided(p):
    """Whether a person has answered this proposal. Either route counts: spec.decision (the portal,
    from now on) or a person-decided phase already on status (written by hand, or by the portal
    before it could write the spec)."""
    return decision(p) is not None or effective_phase(p) in PERSON_DECIDED_PHASES


def proposal_name(proposal):
    """The Proposal's object name, derived from its fingerprint. Exposed so a supersession can name its
    successor BEFORE the successor is written — the old proposal's supersededBy is set first."""
    return f"p-{proposal['fingerprint'][:16]}"


def create_proposal_cr(api, proposal, run_name, claim=None, phase=PHASE_PROPOSED, error=None,
                       conditions=None):
    obj = {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "Proposal",
        "metadata": {
            "name": proposal_name(proposal),
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
        # `subject` only when there is one. The field is optional in the CRD — every proposal written
        # before it existed lacks it — and a JSON null is not an absent string to the apiserver.
        "spec": {k: proposal[k] for k in
                 ("kind", "subject", "title", "rationale", "evidence", "confidence", "target", "change",
                  "fingerprint") if proposal.get(k) is not None}
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
    status = {"phase": phase,
              "conditions": [c | {"lastTransitionTime": _now()} for c in (conditions or [])]}
    if error:
        status |= {"phase": PHASE_FAILED, "error": str(error)[:500]}
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "proposals", created["metadata"]["name"], {"status": status})
    return created["metadata"]["name"]


def open_index(api, run_name=None, decided=None):
    """(by_fingerprint, by_target, by_subject) over proposals that are still undecided.

    Three indexes because there are three questions. By fingerprint answers "have we said exactly
    this?" — a duplicate, dropped. By target answers "have we said something else about this same
    file?" — and by subject "have we said something else about this same FINDING?". Both of those are
    replacements, which supersede. Returning only the first is why every re-worded repeat looked new.

    THE TWO REPLACEMENT INDEXES ARE NARROWER THAN THE FINGERPRINT ONE, deliberately:
    - PROPOSED ONLY, not PrOpen — for target AND subject. The portal opens pull requests per proposal; a
      proposal in PrOpen has a person's pull request hanging off it, and retiring it on the strength of
      a model's next opinion would orphan work somebody is doing. That holds for a same-file replacement
      too: the PR is where that file's change is now being decided, and a newer body lands beside it as
      a new proposal for the person to weigh, not as a silent retirement of the one they acted on.
    - EARLIER RUNS ONLY (subject).  Two proposals in one run sharing a subject are the model splitting one finding
      across two changes, not tonight replacing last night.
    - NEVER A NULL SUBJECT. Legacy proposals carry none; see proposals.subject_key.

    A PERSON-DECIDED PROPOSAL IS IN NONE OF THE THREE — not even the fingerprint index, though PrOpen is
    otherwise "open". Superseding one would retire a person's answer on a model's next opinion, and
    deduplicating into one would count tonight's repeat as if it were still awaiting that answer. They
    go to `decided` (fingerprint -> name) when the caller passes a dict, so classify can say the
    suggestion was already answered and the run leaves the object alone. Read through effective_phase,
    so a decision the service has not mirrored yet already counts."""
    got = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals").get("items", [])
    by_fingerprint, by_target, by_subject = {}, {}, {}
    for p in got:
        spec = p.get("spec") or {}
        fp, name = spec.get("fingerprint"), p["metadata"]["name"]
        if not fp or not spec.get("kind"):
            continue
        if person_decided(p):
            if decided is not None:
                decided[fp] = name
            continue
        phase = effective_phase(p)
        if phase not in OPEN_PHASES:
            continue
        by_fingerprint[fp] = name
        if phase == PHASE_PROPOSED:
            by_target[proposals.target_key(spec)] = {"fingerprint": fp, "name": name}
        key = proposals.subject_key(spec)
        if (key is not None and phase == PHASE_PROPOSED
                and (spec.get("producedBy") or {}).get("runRef") != run_name):
            by_subject.setdefault(key, []).append({"fingerprint": fp, "name": name})
    return by_fingerprint, by_target, by_subject


def forget(name, by_target, by_subject):
    """Drop a superseded proposal from the indexes, so a second proposal in the same run cannot
    supersede it again and count it twice."""
    for k in [k for k, v in by_target.items() if v["name"] == name]:
        del by_target[k]
    for k in list(by_subject):
        by_subject[k] = [v for v in by_subject[k] if v["name"] != name]


def mark_superseded(api, name, by=None, reason=None):
    """The open proposal this one replaces. Status only — the spec of a superseded proposal is left
    exactly as it was, because it is the record of what was suggested and when.

    supersededBy was declared in the CRD from the start and never written, so a Superseded proposal
    said it had been replaced without saying by what. `decidedAt` is set because Superseded is terminal:
    this is the moment the question it asked stopped being open."""
    status = {"phase": PHASE_SUPERSEDED, "decidedAt": _now(), "decidedBy": "nightly-review"}
    if by:
        status["supersededBy"] = by
    if reason:
        status["reason"] = reason
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "proposals", name, {"status": status})


CLAIM_LABEL = "review.krateo.io/publish-claim"
_MIRRORED = ("phase", "decidedBy", "decidedAt", "reason")


def mirror_decisions(api):
    """Copy every person's spec.decision onto status. Returns the number of proposals written.

    STATUS STAYS THE SERVICE'S RECORD; spec.decision IS THE PERSON'S INPUT. The portal can only write
    the spec (snowplow /call cannot reach the status subresource), so without this the status of a
    decided proposal would say Proposed forever, and every reader — the printer columns, the portal's
    lists, the next run's own indexes — would have to know to look in two places. The mirror makes
    status true again; effective_phase covers the gap until it runs.

    IDEMPOTENT BY COMPARISON, NOT BY FLAG: a proposal is written only when a mirrored field differs, so a
    run over a hundred already-mirrored decisions makes no writes at all, and a run that died halfway
    finishes the rest next time. Fields the decision does not carry are left as they are rather than
    cleared — a decision predating the stamping policy has no decidedAt, and erasing one status already
    had would lose the only record of it.

    THE CLAIM IS MIRRORED TO THE LABEL, not to status: status has no field for it, and the label is
    where this service already records the claims it creates itself (create_proposal_cr), so one
    selector finds every proposal with a change request behind it, whoever opened it."""
    got = api.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "proposals").get("items", [])
    written = 0
    for p in got:
        d = decision(p)
        if d is None:
            continue
        name, status = p["metadata"]["name"], p.get("status") or {}
        diff = {}
        # A merged PR is later than the decision that opened it (see effective_phase): status already
        # says more than the decision does, so it is left alone.
        if effective_phase(p) == d["phase"]:
            diff = {k: d[k] for k in _MIRRORED if d.get(k) is not None and status.get(k) != d[k]}
        claim = d.get("claim")
        labels = (p.get("metadata") or {}).get("labels") or {}
        wrote = False
        if diff:
            api.patch_namespaced_custom_object_status(
                GROUP, VERSION, NAMESPACE, "proposals", name, {"status": diff})
            wrote = True
        if claim and labels.get(CLAIM_LABEL) != claim:
            api.patch_namespaced_custom_object(
                GROUP, VERSION, NAMESPACE, "proposals", name, {"metadata": {"labels": {CLAIM_LABEL: claim}}})
            wrote = True
        written += wrote
    return written
