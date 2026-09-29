"""One nightly run, start to finish. Invoked by the CronJob; runs once and exits.

THE RUN MUST NEVER END QUIETLY WRONG. Its phase distinguishes Completed from PartiallyCompleted from
Failed, and every source records why it did or did not answer. A guard that turns failure into green is
how a sink can be dead for a week while every tick is a tick — this file exists partly to not do that.
"""
import datetime as dt
import json
import os
import signal
import sys

import jsonschema
from kubernetes import client, config

import analysis
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
    """status.steps[]: gather, analyse, ask, validate, publish, record — each with its own clock and outcome.

    WHY A RUN NEEDS MORE THAN ITS PHASE. A Failed run said THAT it failed and, through `error`, roughly
    why, but not WHERE: a 900-second ask that timed out and a validation that refused the answer in
    40ms both read `Failed`. The portal's run view needs the stage, and a person needs to know whether
    the model was ever called — which is the expensive part — before deciding what to rerun.

    Every transition is patched immediately rather than at the end, so a run killed mid-ask (the Job's
    deadline, an evicted node) still says which step it died in. The list is written whole each time:
    a merge-patch replaces arrays, which is what keeps the entries in order."""
    ORDER = ("gather", "analyse", "ask", "validate", "publish", "record")

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
    core = client.CoreV1Api()

    to = _now()
    frm = to - dt.timedelta(hours=WINDOW_HOURS)
    window = {"from": frm.isoformat(), "to": to.isoformat()}
    run_name = f"rr-{to.strftime('%Y%m%d-%H%M')}"

    api.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, "reviewruns", {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "ReviewRun",
        "metadata": {"name": run_name, "namespace": NAMESPACE},
        "spec": {"window": window, "sources": ["clickhouse", "kagent-sessions", "kubernetes", "agent-analysis"],
                 "dryRun": DRY_RUN},
    })
    # PEOPLE'S DECISIONS FIRST, AND ON EVERY RUN — before the gather, so a night whose ask or validation
    # fails still brings status up to date. The portal records a decision in spec.decision and this
    # copies it onto status. open_index reads spec.decision as authoritative anyway, so a failure here
    # costs the status its freshness for a night and nothing else, which is why it is logged and does
    # not fail the run.
    try:
        mirrored = publish.mirror_decisions(api)
        if mirrored:
            print(f"[run] mirrored {mirrored} decision(s) onto status", flush=True)
    except Exception as exc:                                  # noqa: BLE001
        print(f"[run] could not mirror decisions: {exc}", flush=True)

    st = {"phase": "Running", "startedAt": to.isoformat(), "evidence": {}}
    steps = _Steps(api, run_name, st)
    _on_terminate(api, run_name, st)
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
    failed_sources = [n for n, st_ in st["evidence"].items() if not st_.get("ok")]
    steps.end("gather", message=f"answered: {', '.join(sorted(blocks))}"
                                + (f"; failed: {', '.join(failed_sources)}" if failed_sources else ""))

    # EVERY MODEL CALL THE RUN MAKES, with the usage each reported — see _usage below.
    calls = []

    # THE ANALYSE STAGE: one call per agent over its conversations in full, and only the ASSESSMENTS go
    # on to the main call. See analysis.py for why the transcripts must not. It degrades, never blanks:
    # one agent's failure is recorded on that agent; all of them failing is ok:false on the source, the
    # run becomes PartiallyCompleted, and the main review still runs on everything else.
    steps.start("analyse")
    try:
        assessments, astats, acalls = analysis.analyse(api, core, window, run_name, token)
    except Exception as exc:                                  # noqa: BLE001
        assessments, astats, acalls = [], {"ok": False, "scope": analysis.SCOPE,
                                           "error": P.redact(f"{type(exc).__name__}: {exc}")[:300]}, []
    st["evidence"]["agent-analysis"] = astats
    calls += acalls
    if assessments:
        blocks["agent-analysis"] = analysis.render_for_review(assessments)
        st["agentAnalysis"] = {"assessments": analysis.stored(assessments)}
        # Not paid for twice: the questions of every agent the analysis read are folded to a pointer.
        if "kagent-sessions" in blocks:
            blocks["kagent-sessions"] = evidence.fold_questions(
                blocks["kagent-sessions"], st["evidence"]["kagent-sessions"],
                analysis.covered_agent_keys(assessments))
    agents_failed = sum(1 for r in astats.get("agents") or [] if r.get("error"))
    steps.end("analyse", "Succeeded" if astats.get("ok") else "Failed",
              astats.get("error") or astats.get("note")
              or f"{astats.get('returned', 0)} agent(s) analysed, {agents_failed} failed")

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
        calls.append({"step": "ask", **(usage or {})})
        st["usage"] = _usage(calls)
        step = "validate"
        steps.start("validate")
        kept, notes = P.validate_batch(
            payload,
            lambda p: jsonschema.validate(p, prompt.RESPONSE_SCHEMA),
            item_check=lambda p: jsonschema.validate(p, prompt.ITEM_SCHEMA),
        )
    except Exception as exc:                                  # noqa: BLE001
        if calls:
            st["usage"] = _usage(calls)
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

    # A Prompt proposal about an agent whose prompt repository is DECLARED on the Agent goes there,
    # whatever the model chose — before fingerprinting, because the target is part of the fingerprint.
    for prop in kept:
        moved = analysis.retarget(prop, assessments)
        if moved:
            notes.append(moved)

    # Decided per proposal, BEFORE anything is written: which are duplicates, which replace an open
    # one, and whether the repository each names exists. The existence check lives in validate because
    # it is a fact about the proposal, not about publishing — a dry run needs it as much as a live one.
    decided = {}
    by_fingerprint, by_target, by_subject = publish.open_index(api, run_name, decided=decided)
    plan, deduped, answered, resolved = [], 0, 0, {}
    for prop in kept:
        # FOUR OUTCOMES. Identical to something already open is a duplicate; identical to something a
        # person already answered is left alone; the same finding (kind + subject) or the same file
        # with a different body is a replacement, and saying so is what `superseded` meant.
        action, priors = P.classify(prop, by_fingerprint, by_target, by_subject, decided=decided)
        if action == "dedup":
            deduped += 1
            continue
        if action == "decided":
            # Not counted as deduplicated: the ReviewRun declares that as "an OPEN proposal already
            # carried the fingerprint", and this one is closed. The step message carries the count.
            answered += 1
            continue
        target_cond = targets.resolve(prop["target"]["repo"], cache=resolved)
        plan.append((prop, priors if action == "supersede" else [], target_cond))
        # Forgotten as soon as they are claimed, so a second proposal in this run with the same subject
        # does not supersede the same prior again and count it twice.
        for name in (priors if action == "supersede" else []):
            publish.forget(name, by_target, by_subject)
    unresolved = sum(1 for _, _, c in plan if c["status"] == "False")
    steps.end("validate", message=f"{len(kept)} valid, {deduped} duplicate, {answered} already decided, "
                                  f"{unresolved} unresolved target(s)"
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
    print(f"[run] {st['phase']}: {created} proposed, {deduped} deduped, {answered} already decided, "
          f"{superseded} superseded, {unresolved} unresolved target(s), degraded={degraded}", flush=True)
    return 0


def _usage(calls):
    """status.usage: every model call with the tokens IT reported, and a total over the ones that did.

    HONEST ABOUT WHAT IT DOES NOT KNOW. A call that reported nothing is listed with no token fields, and
    the total says how many calls it covers — a total summed over three of five calls is not the night's
    cost, and without `reportedCalls` beside it nothing would say so."""
    keys = ("inputTokens", "outputTokens", "totalTokens")
    reported = [c for c in calls if any(k in c for k in keys)]
    total = {"calls": len(calls), "reportedCalls": len(reported)}
    for k in keys:
        if any(k in c for c in reported):
            total[k] = sum(c.get(k, 0) for c in reported)
    return {"calls": calls[:40], "total": total}


def _on_terminate(api, run_name, st):
    """A run the Job kills must not stay Running forever.

    The analyse stage made the run depend on external model calls for up to ~25 more minutes, so the
    CronJob now carries activeDeadlineSeconds. When that deadline (or an eviction) fires, the kubelet
    sends SIGTERM and waits terminationGracePeriodSeconds before SIGKILL. Without this handler the
    ReviewRun would say Running, with a step Running, indefinitely: a record that lies about a run that
    is over. PEP 475 retries an interrupted socket read after the handler runs, so the handler fires even
    while a model call is blocked, and SystemExit then unwinds it."""
    def handler(signum, _frame):
        now = _now().isoformat()
        for e in st.get("steps", []):
            if e.get("phase") == "Running":
                e |= {"phase": "Failed", "finishedAt": now, "message": "terminated (SIGTERM)"}
        st.update({"phase": "Failed", "finishedAt": now,
                   "error": "terminated before finishing: the Job's activeDeadlineSeconds was reached, "
                            "or the pod was evicted"})
        try:
            _patch(api, run_name, st)
        finally:
            print(f"[run] terminated by signal {signum}; recorded as Failed", flush=True)
            sys.exit(143)
    signal.signal(signal.SIGTERM, handler)


def _patch(api, name, status):
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "reviewruns", name, {"status": status})


if __name__ == "__main__":
    sys.exit(main())
