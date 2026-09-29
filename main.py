"""One nightly run, start to finish. Invoked by the CronJob; runs once and exits.

THE RUN MUST NEVER END QUIETLY WRONG. Its phase distinguishes Completed from PartiallyCompleted from
Failed, and every source records why it did or did not answer. A guard that turns failure into green is
how a sink can be dead for a week while every tick is a tick — this file exists partly to not do that.
"""
import datetime as dt
import json
import os
import sys

import jsonschema
from kubernetes import client, config

import autopilot
import evidence
import prompt
import proposals as P
import publish
import targets

GROUP, VERSION = "review.krateo.io", "v1alpha1"
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
WINDOW_HOURS = int(os.environ.get("WINDOW_HOURS", "24"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"


def _now():
    return dt.datetime.now(dt.timezone.utc)


class _Steps:
    """status.steps[]: gather, ask, validate, publish, record — each with its own clock and outcome.

    WHY A RUN NEEDS MORE THAN ITS PHASE. A Failed run said THAT it failed and, through `error`, roughly
    why, but not WHERE: a 900-second ask that timed out and a validation that refused the answer in
    40ms both read `Failed`. The portal's run view needs the stage, and a person needs to know whether
    the model was ever called — which is the expensive part — before deciding what to rerun.

    Every transition is patched immediately rather than at the end, so a run killed mid-ask (the Job's
    deadline, an evicted node) still says which step it died in. The list is written whole each time:
    a merge-patch replaces arrays, which is what keeps the entries in order."""
    ORDER = ("gather", "ask", "validate", "publish", "record")

    def __init__(self, api, run_name, st):
        self.api, self.run_name, self.st = api, run_name, st
        st["steps"] = []

    def _entry(self, name):
        for e in self.st["steps"]:
            if e["name"] == name:
                return e
        e = {"name": name}
        self.st["steps"].append(e)
        return e

    def start(self, name):
        self._entry(name).update({"phase": "Running", "startedAt": _now().isoformat()})
        _patch(self.api, self.run_name, self.st)

    def end(self, name, phase="Succeeded", message=None):
        e = self._entry(name)
        now = _now().isoformat()
        e.setdefault("startedAt", now)
        e |= {"phase": phase, "finishedAt": now}
        if message:
            e["message"] = str(message)[:500]
        # No patch here: every end is followed by the next start or by the run's own final patch, and
        # the final patch carries this entry. One write per transition, not two.

    def skip(self, name, message):
        self.end(name, "Skipped", message)


def main():
    config.load_incluster_config()
    api = client.CustomObjectsApi()

    to = _now()
    frm = to - dt.timedelta(hours=WINDOW_HOURS)
    window = {"from": frm.isoformat(), "to": to.isoformat()}
    run_name = f"rr-{to.strftime('%Y%m%d-%H%M')}"

    api.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "reviewruns", {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "ReviewRun",
        "metadata": {"name": run_name, "namespace": NAMESPACE},
        "spec": {"window": window, "sources": ["clickhouse", "kagent-sessions", "kubernetes"],
                 "dryRun": DRY_RUN},
    })
    st = {"phase": "Running", "startedAt": to.isoformat(), "evidence": {}}
    steps = _Steps(api, run_name, st)
    steps.start("gather")

    token = autopilot.service_jwt()
    queries = json.loads(os.environ.get("CLICKHOUSE_QUERIES", "{}"))

    blocks = {}
    for name, (body, stats) in {
        "clickhouse": evidence.clickhouse(queries, window),
        "kagent-sessions": evidence.kagent_sessions(api, window),
        "kubernetes": evidence.kubernetes(api),
    }.items():
        st["evidence"][name] = stats
        if body:
            blocks[name] = body

    # A SOURCE THAT FAILED IS DEGRADATION. A SOURCE THAT IS LEGITIMATELY EMPTY IS NOT.
    #
    # `empty` used to count as degraded on the reasoning that a source returning nothing has not really
    # been read. That was right for a source that might have had something; it is wrong for one that
    # CANNOT. The original case was kagent-sessions: it read /api/sessions as itself, and kagent scopes
    # that to the caller, so it saw none of its own by construction. Counting it made every successful
    # run report PartiallyCompleted forever — a status carrying no information, which people learn to
    # ignore and then miss the night it means something.
    #
    # That source now reads kagent's Postgres across all users, so its emptiness is real information
    # rather than a scoping artefact. The rule stays, because it is the right rule for any source that
    # can legitimately have nothing to say; it just no longer has that one standing exception.
    #
    # So: not-ok is degradation; empty is degradation only when nothing explains it. A source that says
    # `ok` and carries a note about why it is empty has been read, and the answer was "nothing".
    degraded = [n for n, st_ in st["evidence"].items()
                if not st_.get("ok") or (st_.get("empty") and not st_.get("note"))]
    unexplained_empty = [n for n, st_ in st["evidence"].items()
                         if st_.get("ok") and st_.get("empty") and st_.get("note")]
    if unexplained_empty:
        print(f"[run] empty but explained, not counted as degraded: {unexplained_empty}", flush=True)

    if not blocks:
        # Nothing answered. This is a FAILED run, not an uneventful one — the distinction matters
        # because "no proposals" from a healthy night and "no proposals" from a blind one look
        # identical on a dashboard and mean opposite things.
        steps.end("gather", "Failed", "no evidence source answered")
        st |= {"phase": "Failed", "finishedAt": _now().isoformat(),
               "error": "no evidence source answered; nothing was reviewed"}
        _patch(api, run_name, st)
        print("[run] no evidence; failed", flush=True)
        return 1
    steps.end("gather", message=f"answered: {', '.join(sorted(blocks))}"
                                + (f"; degraded: {', '.join(degraded)}" if degraded else ""))

    # `raw` is bound OUTSIDE the try on purpose. When validation refuses a response, the one thing
    # needed to fix it is the response, and until now the run recorded only that it was unusable — a
    # night failed with "no `proposals` array" and left nothing to say WHAT had arrived instead.
    #
    # ASK AND VALIDATE ARE TWO STEPS NOW, in two tries, because they fail for unrelated reasons and the
    # fix for each is different: an ask that fails is the agent or the network; a validation that fails
    # is the contract. One try around both recorded them identically.
    raw = None
    step = "ask"
    try:
        steps.start("ask")
        payload, raw, usage = autopilot.ask(
            prompt.SYSTEM, prompt.build_user_message(window, blocks), run_name, token)
        steps.end("ask")
        # THE MODEL FIELD IS WRITTEN ONLY WHEN THE AGENT REPORTED USAGE. It was written unconditionally
        # from a key kagent never sends, so every run on 057 carried zeros that looked like a
        # measurement. Absent now means "not reported"; see autopilot.token_usage.
        if usage:
            st["model"] = usage
        step = "validate"
        steps.start("validate")
        kept, notes = P.validate_batch(
            payload,
            lambda p: jsonschema.validate(p, prompt.RESPONSE_SCHEMA),
            item_check=lambda p: jsonschema.validate(p, prompt.ITEM_SCHEMA),
        )
    except Exception as exc:                                  # noqa: BLE001
        steps.end(step, "Failed", f"{type(exc).__name__}: {exc}")
        st |= {"phase": "Failed", "finishedAt": _now().isoformat(), "error": f"{type(exc).__name__}: {exc}"[:500]}
        # REDACTED BEFORE IT IS STORED OR PRINTED, through the same path a proposal takes. This text is
        # model output summarising a corpus that has held credentials, and a diagnostic that leaks one
        # into a CR and a pod log is a worse bug than the failure it explains.
        excerpt = P.redact(raw)[:1800] if isinstance(raw, str) and raw else ""
        if excerpt:
            st["conditions"] = [{"type": "AgentResponse", "status": "False", "reason": "Unusable",
                                 "message": excerpt, "lastTransitionTime": _now().isoformat()}]
        _patch(api, run_name, st)
        print(f"[run] agent/validation failed: {exc}", flush=True)
        if excerpt:
            print(f"[run] response began: {excerpt[:600]}", flush=True)
        return 1

    # The model's own account of the night, which the response contract has always asked for and the
    # run never kept. Redacted like every other model string before it reaches a CR.
    summary = payload.get("summary") if isinstance(payload, dict) else None
    if isinstance(summary, str) and summary.strip():
        st["summary"] = P.redact(summary)[:2000]

    # Decided per proposal, BEFORE anything is written: which are duplicates, which replace an open
    # one, and whether the repository each names exists. The existence check lives in validate because
    # it is a fact about the proposal, not about publishing — a dry run needs it as much as a live one.
    by_fingerprint, by_target, by_subject = publish.open_index(api, run_name)
    plan, deduped, resolved = [], 0, {}
    for prop in kept:
        # THREE OUTCOMES, NOT TWO. Identical to something already open is a duplicate; the same finding
        # (kind + subject) or the same file with a different body is a replacement, and saying so is
        # what `superseded` meant.
        action, priors = P.classify(prop, by_fingerprint, by_target, by_subject)
        if action == "dedup":
            deduped += 1
            continue
        target_cond = targets.resolve(prop["target"]["repo"], cache=resolved)
        plan.append((prop, priors if action == "supersede" else [], target_cond))
        # Forgotten as soon as they are claimed, so a second proposal in this run with the same subject
        # does not supersede the same prior again and count it twice.
        for name in (priors if action == "supersede" else []):
            publish.forget(name, by_target, by_subject)
    unresolved = sum(1 for _, _, c in plan if c["status"] == "False")
    steps.end("validate", message=f"{len(kept)} valid, {deduped} duplicate, {unresolved} unresolved target(s)"
                                  + (f", {len(notes)} note(s)" if notes else ""))

    # Resolved ONCE per run rather than per proposal: the BuilderPublish kind is version-pinned by the
    # portal release that shipped it, and a run that published ten proposals should not make ten
    # identical discovery calls — nor straddle a version change halfway through a night.
    # The queries this run ACTUALLY issued, by name, straight from the source that issued them. The
    # pull-request body quotes these rather than the model's recollection of them.
    queries_run = (st["evidence"].get("clickhouse") or {}).get("queries") or {}
    claims = {}
    if DRY_RUN:
        # THE NORMAL CASE, NOT A DEGRADED ONE. The portal opens pull requests per proposal, from the
        # Proposal object, when a person decides to; this service stays in dry run permanently. The
        # step is recorded as Skipped so the run says so rather than implying publishing was attempted.
        steps.skip("publish", "dryRun: pull requests are opened from the portal, per proposal")
    else:
        steps.start("publish")
        publish_version = None
        try:
            publish_version = publish.publish_version()
        except Exception as exc:                              # noqa: BLE001
            print(f"[publish] cannot resolve the BuilderPublish version: {exc}", flush=True)
        failed = 0
        for prop, _, target_cond in plan:
            # A repository GitHub says does not exist gets no claim: repository.create is false, so the
            # chain would fail on it, later and less legibly. The proposal is still written below.
            if target_cond["status"] == "False":
                continue
            try:
                claims[prop["fingerprint"]] = (publish.create_publish_claim(
                    api, prop, run_name, version=publish_version, queries_run=queries_run), None)
            except Exception as exc:                          # noqa: BLE001
                failed += 1
                claims[prop["fingerprint"]] = (None, exc)
                print(f"[publish] claim failed for {prop['title']!r}: {exc}", flush=True)
        steps.end("publish", "Failed" if failed else "Succeeded",
                  f"{len(claims) - failed} claim(s), {failed} failed" if claims else "nothing to publish")

    steps.start("record")
    created, superseded, refs = 0, 0, []
    for prop, priors, target_cond in plan:
        name = publish.proposal_name(prop)
        for prior in priors:
            publish.mark_superseded(api, prior, by=name, reason=f"superseded by {name} in {run_name}")
            superseded += 1
        claim, err = claims.get(prop["fingerprint"], (None, None))
        refs.append(publish.create_proposal_cr(api, prop, run_name, claim=claim, error=err,
                                               conditions=[target_cond]))
        created += 1
    steps.end("record", message=f"{created} written, {superseded} superseded")

    st |= {
        "phase": "PartiallyCompleted" if degraded else "Completed",
        "finishedAt": _now().isoformat(),
        # `refused` is intentionally not written any more: the allowlist that produced it is gone.
        # The field stays in the CRD so the runs that recorded one remain readable.
        "proposals": {"created": created, "deduplicated": deduped,
                      "superseded": superseded, "refs": refs},
        "expiresAt": (_now() + dt.timedelta(days=int(os.environ.get("RUN_RETENTION_DAYS", "30")))).isoformat(),
    }
    if notes:
        # Validation notes are part of the record: a dropped alert kind, a subject that could not be
        # normalised, a redaction — each is something the next change to the prompt needs to know.
        st["conditions"] = [{"type": "ValidationNotes", "status": "True", "reason": "Notes",
                             "message": " | ".join(notes)[:2000],
                             "lastTransitionTime": _now().isoformat()}]
    _patch(api, run_name, st)
    print(f"[run] {st['phase']}: {created} proposed, {deduped} deduped, "
          f"{superseded} superseded, {unresolved} unresolved target(s), degraded={degraded}", flush=True)
    return 0


def _patch(api, name, status):
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "reviewruns", name, {"status": status})


if __name__ == "__main__":
    sys.exit(main())
