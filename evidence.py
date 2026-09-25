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
import os

import requests

from proposals import redact

CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
KAGENT_API = os.environ.get("KAGENT_API_URL", "http://kagent-controller.krateo-system.svc:8083")
MAX_ROWS = int(os.environ.get("EVIDENCE_MAX_ROWS", "200"))
MAX_CHARS = int(os.environ.get("EVIDENCE_MAX_CHARS", "60000"))


def _cap(text):
    """Bound what reaches the prompt. An unbounded corpus is a cost problem, a context problem, and —
    because older spans predate the collector's JWT redaction — a disclosure problem."""
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS] + f"\n... [truncated at {MAX_CHARS} chars]"


def clickhouse(queries, window):
    """queries: {name: sql} from chart values. `{from}`/`{to}` are substituted, nothing else is."""
    if not CLICKHOUSE_URL:
        return None, {"ok": False, "error": "CLICKHOUSE_URL not configured"}
    blocks, stats = [], {"ok": True, "queried": 0, "returned": 0}
    for name, sql in (queries or {}).items():
        bound = sql.replace("{from}", window["from"]).replace("{to}", window["to"])
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
            blocks.append(f"-- {name}\n-- query: {bound}\n" + "\n".join(rows[:MAX_ROWS]))
        except Exception as exc:                              # noqa: BLE001
            stats["ok"] = False
            stats.setdefault("error", "")
            stats["error"] += f"{name}: {exc}; "
    # Redact on the way IN as well as out. The agent should never be handed a credential it could
    # faithfully quote back into a proposal.
    return _cap(redact("\n\n".join(blocks))), stats


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
        return _cap("\n".join(lines)), {"ok": True, "queried": 1, "returned": len(alerts)}
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": f"alerts: {exc}"}
