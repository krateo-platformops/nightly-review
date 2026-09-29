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
# kagent's Postgres, read with a role granted SELECT on `session` AND NOTHING ELSE. See kagent_sessions.
KAGENT_DB_HOST = os.environ.get("KAGENT_DB_HOST", "kagent-postgresql.krateo-system.svc")
KAGENT_DB_PORT = int(os.environ.get("KAGENT_DB_PORT", "5432"))
KAGENT_DB_NAME = os.environ.get("KAGENT_DB_NAME", "kagent")
KAGENT_DB_USER = os.environ.get("KAGENT_DB_USER", "")
KAGENT_DB_PASSWORD = os.environ.get("KAGENT_DB_PASSWORD", "")
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


# THE ONLY QUERY THIS SERVICE MAKES AGAINST kagent. Hoisted so it can be read and tested on its own.
# Three properties are load-bearing and each is asserted by a test:
#   - `deleted_at IS NULL`, because kagent soft-deletes and without it this returns sessions users
#     deleted, which their own API would never show them;
#   - count(DISTINCT user_id) and NEVER user_id itself, because this corpus reaches a model and from
#     there a pull request body, and aggregate counts answer the question without naming real people;
#   - `session` and no other table, so it does not even ask for the content tables the role is revoked on.
SESSION_SQL = """
    SELECT coalesce(agent_id, '(none)')                       AS agent,
           count(*)                                            AS all_time,
           count(*) FILTER (WHERE updated_at >= :frm
                              AND updated_at <= :to)           AS in_window,
           count(DISTINCT user_id)                             AS users,
           max(updated_at)                                     AS last_seen
      FROM session
     WHERE deleted_at IS NULL
     GROUP BY coalesce(agent_id, '(none)')
     ORDER BY last_seen DESC NULLS LAST
     LIMIT :lim
"""

def kagent_sessions(api, window, limit=200):
    """Which agents are being USED, and — the part that matters — which are not.

    THE FIRST VERSION OF THIS WAS SHAPED WRONG AND THE MODEL CORRECTLY IGNORED IT. It grouped sessions
    inside the review window, so it reported four healthy agents and a total. That is a census: nothing
    in it is a problem, so there was nothing to propose. Measured on 057: three sources went to the
    model, ClickHouse's 60 rows of error patterns were problem-shaped, Kubernetes' 25 existing Alerts
    were coverage-shaped, and these four rows were neither. Zero proposals cited it.

    WORSE, THE WINDOW DESTROYED THE ONE REAL SIGNAL. Filtering rows by updated_at means an agent idle for
    three weeks does not appear at all — the very fact that makes it interesting is what excludes it from
    the result. A GROUP BY over rows that exist can never report absence, and absence is where the
    findings are. So the window no longer filters; it only marks which agents were active inside it.

    TWO SIGNALS THAT DIED ON CONTACT WITH THE DATA, recorded so nobody rebuilds them. `source` looked
    like it would separate human from bench traffic; it holds exactly two values across 3,224 rows,
    (null) 2128 and 'agent' 1096, and separates nothing. And abandonment as created_at = updated_at
    occurs ZERO times in 3,224 rows, because a session's first message updates it — a field built on
    that would have been permanently empty, which is the same dead-check shape as the confidence cap
    removed in #14.

    WHY IT READS THE DEPLOYED SET TOO. An agent that has never had a session has no row to group, so the
    only way to see it is to compare against what is deployed. kagent's agent_id is
    ConvertToPythonIdentifier(namespace + "/" + name), so krateo-system/tk-swarm-ro becomes
    krateo_system__NS__tk_swarm_ro and the two sides can be matched. On 057 that difference is exactly
    one agent, deployed and never once used, invisible to every version of this query that did not look.
    """
    if not (KAGENT_DB_USER and KAGENT_DB_PASSWORD):
        return None, {"ok": False, "error": "kagent DB credentials not configured (KAGENT_DB_USER/PASSWORD)"}
    try:
        import pg8000.native                                  # pure-python: no libpq in the image
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": f"pg8000 unavailable: {exc}"}

    conn = None
    try:
        conn = pg8000.native.Connection(
            user=KAGENT_DB_USER, password=KAGENT_DB_PASSWORD, host=KAGENT_DB_HOST,
            port=KAGENT_DB_PORT, database=KAGENT_DB_NAME, timeout=30,
        )
        rows = conn.run(SESSION_SQL, frm=window["from"], to=window["to"], lim=limit)
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": redact(f"session query: {exc}")[:300]}
    finally:
        if conn is not None:
            try: conn.close()
            except Exception: pass                            # noqa: BLE001,S110

    # The deployed set. A failure here is NOT fatal: the session half still carries the staleness
    # signal, so degrade to "no deployed-set comparison" and say so rather than losing the whole source.
    deployed, deployed_err = {}, None
    try:
        for a in (api.list_cluster_custom_object("kagent.dev", "v1alpha1", "agents").get("items") or []):
            ns, nm = a["metadata"]["namespace"], a["metadata"]["name"]
            deployed[f"{ns}/{nm}".replace("-", "_").replace("/", "__NS__")] = f"{ns}/{nm}"
    except Exception as exc:                                  # noqa: BLE001
        deployed_err = str(exc)[:160]

    now = dt.datetime.now(dt.timezone.utc)
    seen, lines = {}, []
    for agent, all_time, in_window, users, last_seen in rows:
        idle = None
        if last_seen is not None:
            ls = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=dt.timezone.utc)
            idle = (now - ls).days
        seen[agent] = (all_time, in_window, users, idle)

    never = sorted(deployed[k] for k in deployed if k not in seen) if deployed else []
    stale = sorted(((v[3], k) for k, v in seen.items() if v[3] is not None and v[3] >= 7), reverse=True)
    rare = sorted((v[0], k) for k, v in seen.items() if v[0] <= 3)
    active = sorted(((v[1], k) for k, v in seen.items() if v[1] > 0), reverse=True)

    # Problems first. The model reads this top-down and the interesting rows must not be buried under a
    # census of everything that is fine.
    if never:
        lines.append(f"- DEPLOYED BUT NEVER USED ({len(never)}): {', '.join(never)} — no session has ever "
                     f"existed for these; either unreachable, undiscoverable, or no longer wanted")
    for idle, agent in stale:
        a, w, u, _ = seen[agent]
        lines.append(f"- IDLE {idle}d: {agent} — {a} sessions all-time, last activity {idle} days ago, "
                     f"{w} in this window")
    for cnt, agent in rare:
        lines.append(f"- BARELY EVER USED: {agent} — {cnt} session(s) in its entire history")
    for w, agent in active:
        a, _, u, idle = seen[agent]
        lines.append(f"- active: {agent} — {w} sessions in window, {a} all-time, {u} distinct users")
    if deployed_err:
        lines.append(f"- NOTE: the deployed-agent list could not be read ({deployed_err}), so "
                     f"'never used' could not be computed; idle/active figures are unaffected")

    stats = {"ok": True, "queried": 1, "returned": len(rows),
             "agentsDeployed": len(deployed) or None, "agentsNeverUsed": len(never),
             "agentsIdle7d": len(stale), "agentsActiveInWindow": len(active),
             "scope": "all-users metadata (SELECT on session only; cannot read event/task)"}
    if deployed_err:
        stats["note"] = f"deployed-agent list unreadable: {deployed_err}"
    if not lines:
        stats |= {"empty": True, "note": "no kagent agents and no sessions found at all"}
        return None, stats
    return _cap(redact("\n".join(lines))), stats


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
