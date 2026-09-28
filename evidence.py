"""Gather the corpus the agent reasons over. Deterministic, bounded, and reviewable.

THE QUERIES ARE CONFIGURATION, NOT CODE. They ship in the chart's values as named SQL and API reads, so
an operator can read exactly what this service will ask for, adapt them to their own ClickHouse schema,
and change them without a new image. A model is never asked to author the SQL: open-ended query
generation against a store that has held live credentials is a risk with no matching benefit, because
what we want from the model is judgement about patterns, not the ability to go looking.

EVERY SOURCE FAILS INDEPENDENTLY AND VISIBLY. A source that errors is recorded with its error and the
run becomes PartiallyCompleted. It is never dropped silently, because a proposal built on half the
evidence must be readable as such.
"""
import datetime as dt
import os

import requests

from proposals import redact

CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
KAGENT_API = os.environ.get("KAGENT_API_URL", "http://kagent-controller.krateo-system.svc:8083")
MAX_ROWS = int(os.environ.get("EVIDENCE_MAX_ROWS", "200"))
MAX_CHARS = int(os.environ.get("EVIDENCE_MAX_CHARS", "60000"))


def _cap(text, stats=None):
    """Bound what reaches the prompt. An unbounded corpus is a cost problem, a context problem, and —
    because older spans predate the collector's JWT redaction — a disclosure problem.

    THE TRUNCATION IS NOW RECORDED ON THE RUN, not only marked inside the corpus. Before, the marker went
    where only the model could see it while the status still read `returned: 75` and looked complete —
    so whoever wrote the most logs quietly decided what got reviewed, and nothing said so. The marker
    stays as well: the model should know its evidence was cut."""
    if len(text) <= MAX_CHARS:
        return text
    if stats is not None:
        stats["truncated"] = True
        stats["truncatedAtChars"] = MAX_CHARS
        stats["droppedChars"] = len(text) - MAX_CHARS
    return text[:MAX_CHARS] + f"\n... [truncated at {MAX_CHARS} chars]"


def _ch_time(value):
    """A window bound ClickHouse can use its primary-key index on.

    THIS ONE LINE WAS THE WHOLE OF THE TIMEOUT. The run records its window as ISO-8601, which is right
    for the CR, and the same string was substituted straight into SQL — so ClickHouse compared a
    DateTime64 column against '2026-09-27T14:17:43.745807+00:00' and could not prune by range, and
    full-scanned 13.9M rows every night.

    Measured on 057, same predicate, same 96k matching rows: the ISO literal takes 167 SECONDS, past
    the 120s read timeout; 'YYYY-MM-DD HH:MM:SS' takes 15.7s, and the full grouped query 2.3s. That is
    a 6.4x difference from the shape of a timestamp, and it is why this query failed on roughly half of
    all runs while the other two never did — they read the same window and scan far less.

    The ReviewRun keeps the ISO form: its CRD types the window as date-time, and the record should stay
    readable. Only what goes into SQL is converted."""
    v = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(v, fmt)
        except ValueError:
            continue
        # ONLY CONVERT WHAT CARRIES AN OFFSET. astimezone() on a NAIVE datetime assumes the machine's
        # local zone, which would silently slide the review window by that offset — on a box at UTC+2
        # the first version of this shifted 14:17 to 12:17, and a window that is quietly two hours wrong
        # is worse than the slow query it was written to fix. A naive value is already UTC here, because
        # main.py builds the window with datetime.now(timezone.utc).
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(dt.timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    # Unparseable: hand it through untouched rather than guess. A slow query beats a wrong window.
    return v


def clickhouse(queries, window):
    """queries: {name: sql} from chart values. `{from}`/`{to}` are substituted, nothing else is."""
    if not CLICKHOUSE_URL:
        return None, {"ok": False, "error": "CLICKHOUSE_URL not configured"}
    blocks, stats = [], {"ok": True, "queried": 0, "returned": 0}
    # THE REAL SQL, KEPT BY NAME. A proposal is supposed to carry the query that produced it so a human
    # can re-run it and disagree; asking the MODEL to repeat it back produced a plausible paraphrase
    # instead — one with no window clause, matching nothing that ran. The service knows exactly what it
    # asked, so it is the service that records it.
    stats["queries"] = {}
    for name, sql in (queries or {}).items():
        # THE WINDOW IS A SAFETY CONTROL, NOT A COST ONE: spans older than the collector's JWT redaction
        # can still carry live credentials, so an unbounded scan is a disclosure risk. Substitution is
        # textual, so a query that simply omits the placeholders used to scan everything, silently.
        if "{from}" not in sql or "{to}" not in sql:
            stats["ok"] = False
            stats.setdefault("error", "")
            stats["error"] += (f"{name}: refused — the query does not carry both {{from}} and {{to}}, "
                               f"so it would not be bounded to the review window; ")
            continue
        bound = sql.replace("{from}", _ch_time(window["from"])).replace("{to}", _ch_time(window["to"]))
        try:
            r = requests.post(
                CLICKHOUSE_URL,
                data=f"{bound}\nFORMAT JSONCompactEachRow",
                params={"max_result_rows": MAX_ROWS, "result_overflow_mode": "break"},
                auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD) if CLICKHOUSE_USER else None,
                timeout=120,
            )
            r.raise_for_status()
            rows = [ln for ln in r.text.splitlines() if ln.strip()]
            stats["queried"] += 1
            stats["returned"] += len(rows)
            stats["queries"][name] = bound
            blocks.append(f"-- {name}\n-- query: {bound}\n" + "\n".join(rows[:MAX_ROWS]))
        except Exception as exc:                              # noqa: BLE001
            stats["ok"] = False
            stats.setdefault("error", "")
            stats["error"] += f"{name}: {exc}; "
    # Redact on the way IN as well as out. The agent should never be handed a credential it could
    # faithfully quote back into a proposal.
    return _cap(redact("\n\n".join(blocks)), stats), stats


def kagent_sessions(token, limit=50):
    """Read sessions through kagent's own API rather than its Postgres.

    Going through the API inherits the per-user RBAC that is already live on this platform; a direct
    database read would have had none, and would have seen every user's conversations regardless of
    who was asking. The API path is both less to build and less to be trusted with."""
    if not token:
        return None, {"ok": False, "error": "no service JWT; kagent API requires an identity"}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{KAGENT_API}/api/sessions", headers=headers, timeout=60)
        if r.status_code == 401:
            return None, {"ok": False, "error": "401 from kagent /api/sessions (identity rejected)"}
        r.raise_for_status()
        payload = r.json()
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": f"/api/sessions: {exc}"}

    # ZERO SESSIONS HAS THREE DIFFERENT CAUSES AND THEY ARE NOT INTERCHANGEABLE: no conversations
    # happened in the window; this service identity is only shown its OWN sessions and it creates none;
    # or the list is nested under a key we did not look under. The first run reported `returned: 0` for
    # all three, so the review silently proceeded without the conversations it exists to read. Report
    # WHICH, on the run, rather than a number that cannot be interpreted.
    shape = "list" if isinstance(payload, list) else f"dict{sorted(payload.keys())}" if isinstance(payload, dict) else type(payload).__name__
    sessions = payload if isinstance(payload, list) else None
    if sessions is None and isinstance(payload, dict):
        for key in ("sessions", "data", "items", "results"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                sessions = candidate
                break
            if isinstance(candidate, dict):                    # one level of nesting, e.g. {"data": {"sessions": []}}
                for inner in ("sessions", "items", "results"):
                    if isinstance(candidate.get(inner), list):
                        sessions = candidate[inner]
                        break
            if sessions is not None:
                break
    if sessions is None:
        # kagent OMITS `data` on a successful empty list: /api/sessions answers
        # {"error":false,"message":"Successfully listed sessions"} with no list at all, while /api/agents
        # returns {"error":false,"data":[…]}. Verified against the live API. So error:false + no list is
        # EMPTY, not malformed — calling it malformed was my own misreading in 0.1.2.
        if isinstance(payload, dict) and payload.get("error") in (False, None):
            sessions = []
        else:
            return None, {"ok": False, "error": f"no session list found in response ({shape})", "shape": shape}

    lines, read = [], 0
    for s in sessions[:limit]:
        sid = s.get("id") or s.get("name") or ""
        lines.append(f"- session {sid} agent={s.get('agent_ref') or s.get('agentRef') or '?'} "
                     f"updated={s.get('updated_at') or s.get('updatedAt') or '?'}")
        read += 1

    meta = {"ok": True, "queried": 1, "returned": read, "shape": shape}
    if read == 0:
        # A degraded run, not a clean one. The agent is told, and the run says so, so "no proposals
        # tonight" cannot be mistaken for "nothing worth proposing in the conversations".
        meta["empty"] = True
        meta["note"] = ("kagent returned an empty session list for this service identity; sessions may be "
                        "scoped per caller (A2A sessions are created under A2A_USER_<contextId>)")
        return None, meta
    return _cap(redact("\n".join(lines))), meta


def kubernetes(api):
    """What the platform ALREADY notices, so the agent proposes gaps rather than duplicates.

    Without this the most likely proposal every night is an alert for something already alerted on —
    the model cannot know what exists unless it is shown."""
    try:
        alerts = api.list_namespaced_custom_object(
            "observability.krateo.io", "v1alpha1", os.environ.get("NAMESPACE", "krateo-system"), "alerts"
        ).get("items", [])
        lines = [f"- existing Alert {a['metadata']['name']}: "
                 f"{(a.get('spec') or {}).get('displayName', '')!r} "
                 f"threshold={(a.get('spec') or {}).get('threshold')} "
                 f"{(a.get('spec') or {}).get('thresholdType', '')}"
                 for a in alerts]
        st = {"ok": True, "queried": 1, "returned": len(alerts)}
        return _cap("\n".join(lines), st), st
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": f"alerts: {exc}"}
