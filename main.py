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

GROUP, VERSION = "review.krateo.io", "v1alpha1"
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
WINDOW_HOURS = int(os.environ.get("WINDOW_HOURS", "24"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"


def _now():
    return dt.datetime.now(dt.timezone.utc)


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
    _patch(api, run_name, st)

    token = autopilot.service_jwt()
    queries = json.loads(os.environ.get("CLICKHOUSE_QUERIES", "{}"))

    blocks = {}
    for name, (body, stats) in {
        "clickhouse": evidence.clickhouse(queries, window),
        "kagent-sessions": evidence.kagent_sessions(window),
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
        st |= {"phase": "Failed", "finishedAt": _now().isoformat(),
               "error": "no evidence source answered; nothing was reviewed"}
        _patch(api, run_name, st)
        print("[run] no evidence; failed", flush=True)
        return 1

    # `raw` is bound OUTSIDE the try on purpose. When validation refuses a response, the one thing
    # needed to fix it is the response, and until now the run recorded only that it was unusable — a
    # night failed with "no `proposals` array" and left nothing to say WHAT had arrived instead.
    raw = None
    try:
        payload, raw, usage = autopilot.ask(
            prompt.SYSTEM, prompt.build_user_message(window, blocks), run_name, token)
        kept, notes = P.validate_batch(
            payload,
            lambda p: jsonschema.validate(p, prompt.RESPONSE_SCHEMA),
            item_check=lambda p: jsonschema.validate(p, prompt.ITEM_SCHEMA),
        )
    except Exception as exc:                                  # noqa: BLE001
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

    # Resolved ONCE per run rather than per proposal: the BuilderPublish kind is version-pinned by the
    # portal release that shipped it, and a run that published ten proposals should not make ten
    # identical discovery calls — nor straddle a version change halfway through a night.
    # The queries this run ACTUALLY issued, by name, straight from the source that issued them. The
    # pull-request body quotes these rather than the model's recollection of them.
    queries_run = (st["evidence"].get("clickhouse") or {}).get("queries") or {}

    publish_version = None
    if not DRY_RUN:
        try:
            publish_version = publish.publish_version()
        except Exception as exc:                              # noqa: BLE001
            print(f"[publish] cannot resolve the BuilderPublish version: {exc}", flush=True)

    by_fingerprint, by_target = publish.open_index(api)
    created, deduped, superseded, refs = 0, 0, 0, []
    for prop in kept:
        # THREE OUTCOMES, NOT TWO. Identical to something already open is a duplicate; aimed at the
        # same file with a different body is a replacement, and saying so is what `superseded` meant.
        action, prior = P.classify(prop, by_fingerprint, by_target)
        if action == "dedup":
            deduped += 1
            continue
        claim = None
        err = None
        if action == "supersede":
            publish.mark_superseded(api, prior)
            superseded += 1
        if not DRY_RUN:
            try:
                claim = publish.create_publish_claim(api, prop, run_name, version=publish_version,
                                                     queries_run=queries_run)
            except Exception as exc:                          # noqa: BLE001
                err = exc
                print(f"[publish] claim failed for {prop['title']!r}: {exc}", flush=True)
        refs.append(publish.create_proposal_cr(api, prop, run_name, claim=claim, error=err))
        created += 1

    st |= {
        "phase": "PartiallyCompleted" if degraded else "Completed",
        "finishedAt": _now().isoformat(),
        # `refused` is intentionally not written any more: the allowlist that produced it is gone.
        # The field stays in the CRD so the runs that recorded one remain readable.
        "proposals": {"created": created, "deduplicated": deduped,
                      "superseded": superseded, "refs": refs},
        "model": {"name": usage.get("model", ""),
                  "inputTokens": usage.get("inputTokens", 0),
                  "outputTokens": usage.get("outputTokens", 0)},
        "expiresAt": (_now() + dt.timedelta(days=int(os.environ.get("RUN_RETENTION_DAYS", "30")))).isoformat(),
    }
    if notes:
        # Validation notes are part of the record. A refused target especially: it is the clearest
        # signal available that something in the corpus tried to steer the reviewer.
        st["conditions"] = [{"type": "ValidationNotes", "status": "True", "reason": "Notes",
                             "message": " | ".join(notes)[:2000],
                             "lastTransitionTime": _now().isoformat()}]
    _patch(api, run_name, st)
    print(f"[run] {st['phase']}: {created} proposed, {deduped} deduped, "
          f"{superseded} superseded, degraded={degraded}", flush=True)
    return 0


def _patch(api, name, status):
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "reviewruns", name, {"status": status})


if __name__ == "__main__":
    sys.exit(main())
