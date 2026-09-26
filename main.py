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
        "kagent-sessions": evidence.kagent_sessions(token),
        "kubernetes": evidence.kubernetes(api),
    }.items():
        st["evidence"][name] = stats
        if body:
            blocks[name] = body

    # `empty` counts as degraded: a source that answered but returned nothing has not been read, and a
    # review that saw no agent conversations must not present itself as a complete one.
    degraded = [n for n, s in st["evidence"].items() if not s.get("ok") or s.get("empty")]

    if not blocks:
        # Nothing answered. This is a FAILED run, not an uneventful one — the distinction matters
        # because "no proposals" from a healthy night and "no proposals" from a blind one look
        # identical on a dashboard and mean opposite things.
        st |= {"phase": "Failed", "finishedAt": _now().isoformat(),
               "error": "no evidence source answered; nothing was reviewed"}
        _patch(api, run_name, st)
        print("[run] no evidence; failed", flush=True)
        return 1

    try:
        payload, raw, usage = autopilot.ask(
            prompt.SYSTEM, prompt.build_user_message(window, blocks), run_name, token)
        kept, notes = P.validate_batch(
            payload,
            P.load_allowlist(os.environ.get("PROPOSAL_ALLOWLIST", "{}")),
            lambda p: jsonschema.validate(p, prompt.RESPONSE_SCHEMA),
            item_check=lambda p: jsonschema.validate(p, prompt.ITEM_SCHEMA),
        )
    except Exception as exc:                                  # noqa: BLE001
        st |= {"phase": "Failed", "finishedAt": _now().isoformat(), "error": f"{type(exc).__name__}: {exc}"[:500]}
        _patch(api, run_name, st)
        print(f"[run] agent/validation failed: {exc}", flush=True)
        return 1

    by_fingerprint, by_target = publish.open_index(api)
    created, deduped, refused, superseded, refs = 0, 0, 0, 0, []
    for prop in kept:
        # THREE OUTCOMES, NOT TWO. Identical to something already open is a duplicate; aimed at the
        # same file with a different body is a replacement, and saying so is what `superseded` meant.
        action, prior = P.classify(prop, by_fingerprint, by_target)
        if action == "dedup":
            deduped += 1
            continue
        pr = None
        err = None
        # A REFUSED PROPOSAL IS RECORDED AND NEVER PUBLISHED. The allowlist gates the write credential,
        # so the check that matters is this one, here, next to the only code that can reach a repository.
        # It is asked BEFORE anything is superseded: a proposal the allowlist refuses must not be able
        # to retire a legitimately open one, which would let an injected target silence a real finding.
        if not P.is_publishable(prop):
            refs.append(publish.create_proposal_cr(api, prop, run_name, phase=publish.PHASE_REFUSED))
            refused += 1
            continue
        if action == "supersede":
            publish.mark_superseded(api, prior)
            superseded += 1
        if not DRY_RUN:
            try:
                pr = publish.open_pull_request(prop, run_name)
            except Exception as exc:                          # noqa: BLE001
                err = exc
                print(f"[pr] failed for {prop['title']!r}: {exc}", flush=True)
        refs.append(publish.create_proposal_cr(api, prop, run_name, pr=pr, error=err))
        created += 1

    st |= {
        "phase": "PartiallyCompleted" if degraded else "Completed",
        "finishedAt": _now().isoformat(),
        "proposals": {"created": created, "deduplicated": deduped, "refused": refused,
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
    print(f"[run] {st['phase']}: {created} proposed, {refused} refused, {deduped} deduped, "
          f"{superseded} superseded, degraded={degraded}", flush=True)
    return 0


def _patch(api, name, status):
    api.patch_namespaced_custom_object_status(
        GROUP, VERSION, NAMESPACE, "reviewruns", name, {"status": status})


if __name__ == "__main__":
    sys.exit(main())
