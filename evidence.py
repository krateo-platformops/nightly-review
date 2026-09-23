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
import json
import os

import requests

from proposals import redact
from sessiontext import _event_text

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


def kagent_sessions(token, window=None, limit=None, per_session=None):
    """Read sessions AND their messages through kagent's own API.

    Going through the API rather than its Postgres is the whole privacy argument: the API path
    inherits the per-user RBAC that is already live on this platform, so this service sees exactly
    what its own identity is allowed to see. A direct database read would have had none, and would
    have seen every user's conversations regardless of who was asking.

    WHY CONTENT AND NOT JUST METADATA. Session ids and timestamps cannot support the thing this
    service exists to notice — "a question asked repeatedly whose answer is not written down". That
    requires the questions. Content is bounded per session, cut to the review window, and passes
    through the same redact() as everything else before it reaches the model.
    """
    if not token:
        return None, {"ok": False, "error": "no service JWT; kagent API requires an identity"}
    limit = limit or int(os.environ.get("SESSION_LIMIT", "50"))
    per_session = per_session or int(os.environ.get("SESSION_EVENT_LIMIT", "40"))
    headers = {"Authorization": f"Bearer {token}"}

    try:
        r = requests.get(f"{KAGENT_API}/api/sessions", headers=headers, timeout=60)
        if r.status_code == 401:
            return None, {"ok": False, "error": "401 from kagent /api/sessions (identity rejected)"}
        r.raise_for_status()
        payload = r.json()
        sessions = payload if isinstance(payload, list) else payload.get("data") or payload.get("items") or []
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": f"/api/sessions: {exc}"}

    # Only events inside the review window. `after` is an RFC3339 timestamp the controller parses
    # directly (eventQueryOptionsFromRequest), so the window is enforced server-side rather than by
    # fetching everything and discarding most of it.
    params = {"order": "asc", "limit": per_session}
    if window:
        params["after"] = window["from"]

    blocks, stats = [], {"ok": True, "queried": 0, "returned": 0,
                         "sessions": 0, "events": 0, "shapes": {}, "partial": []}
    for s in sessions[:limit]:
        sid = s.get("id") or s.get("name") or ""
        if not sid:
            continue
        stats["sessions"] += 1
        agent = s.get("agent_ref") or s.get("agentRef") or s.get("agent_id") or "?"
        try:
            er = requests.get(f"{KAGENT_API}/api/sessions/{sid}", headers=headers,
                              params=params, timeout=60)
            er.raise_for_status()
            body = er.json()
            data = body.get("data") if isinstance(body, dict) else body
            events = (data or {}).get("events") if isinstance(data, dict) else None
            events = events or []
        except Exception as exc:                              # noqa: BLE001
            # One unreadable session must not blind the whole source. Record it and continue; the
            # run is still PartiallyCompleted-worthy only if the LIST call failed.
            stats["partial"].append(f"{sid}: {exc}")
            continue

        turns = []
        for ev in events:
            role, text, shape = _event_text(ev.get("data") if isinstance(ev, dict) else ev)
            stats["shapes"][shape] = stats["shapes"].get(shape, 0) + 1
            if not text:
                continue
            stats["events"] += 1
            turns.append(f"  [{role or 'unknown'}] {text.strip()}")

        if turns:
            blocks.append(f"- session {sid} agent={agent}\n" + "\n".join(turns))
            stats["returned"] += 1

    stats["queried"] = stats["sessions"]
    if stats["partial"]:
        stats["partial"] = stats["partial"][:10]
    else:
        stats.pop("partial")
    return _cap(redact("\n\n".join(blocks))), stats


def kubernetes(api):
    """What the platform ALREADY has, so the agent proposes gaps rather than duplicates.

    Without this the most likely proposal every night is an alert for something already alerted on —
    the model cannot know what exists unless it is shown. The same argument applies to the Widget
    kind, which is why pages are listed too: a reviewer handed "add a page showing X" for a page that
    already shows X stops reading the next one.

    Each read fails independently. A namespace with no Alerts CRD installed is a normal condition,
    not an error, so a missing kind is reported and the rest still answers.
    """
    ns = os.environ.get("NAMESPACE", "krateo-system")
    blocks, stats = [], {"ok": True, "queried": 0, "returned": 0}

    def _read(group, version, plural, render, keep=None):
        nonlocal blocks
        try:
            items = api.list_namespaced_custom_object(group, version, ns, plural).get("items", [])
            if keep:
                items = [i for i in items if keep(i)]
            stats["queried"] += 1
            stats["returned"] += len(items)
            if items:
                blocks.append("\n".join(render(i) for i in items))
        except Exception as exc:                              # noqa: BLE001
            stats["ok"] = False
            stats.setdefault("error", "")
            stats["error"] += f"{plural}: {exc}; "

    _read("observability.krateo.io", "v1alpha1", "alerts",
          lambda a: (f"- existing Alert {a['metadata']['name']}: "
                     f"{(a.get('spec') or {}).get('displayName', '')!r} "
                     f"threshold={(a.get('spec') or {}).get('threshold')} "
                     f"{(a.get('spec') or {}).get('thresholdType', '')}"))

    # Pages the portal already serves. There is NO Page kind — verified against a live cluster rather
    # than assumed: templates.krateo.io holds only restactions. A page IS a Flex widget whose name
    # begins with "page-", so that is what we list. Listing page ROOTS rather than every widget also
    # keeps this bounded: 057 carries 553 widget CRs against 33 page roots, and dumping all of them
    # would crowd out the telemetry the proposals are supposed to come from.
    _read("widgets.templates.krateo.io", "v1beta1", "flexes",
          lambda f: f"- existing Page {f['metadata']['name']}",
          keep=lambda f: f["metadata"]["name"].startswith("page-"))

    if not blocks:
        return None, stats
    return _cap("\n".join(blocks)), stats
