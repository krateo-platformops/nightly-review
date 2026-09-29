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
import json
import os
import re

import requests

from proposals import redact

CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
KAGENT_API = os.environ.get("KAGENT_API_URL", "http://kagent-controller.krateo-system.svc:8083")
# kagent's Postgres, read with a role granted SELECT on `session` and `event` AND NOTHING ELSE. See
# kagent_sessions and QUESTIONS_SQL.
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
        # ADDED TO, not overwritten: kagent-sessions may already have recorded characters it cut per
        # session before the source as a whole reached this cap, and both are "what the model never saw".
        stats["truncated"] = True
        stats["truncatedAtChars"] = MAX_CHARS
        stats["droppedChars"] = stats.get("droppedChars", 0) + len(text) - MAX_CHARS
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
#   - `session` and no other table. Message text is read by QUESTIONS_SQL below, separately and on
#     purpose, so the agent census never depends on the content read succeeding.
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

# WHAT PEOPLE ASKED, which is the one thing this service exists to notice and the one thing metadata
# cannot carry: "a question asked repeatedly whose answer is not written down" needs the questions.
# Read from the SAME Postgres, as the SAME all-users role, as SESSION_SQL — not through kagent's HTTP
# API, which scopes /api/sessions to the caller and would show this service only its own identity's
# conversations, i.e. none of anybody's questions. The role therefore needs SELECT on `event` as well as
# `session`, and still nothing on `task`.
#
# ONLY USER-AUTHORED EVENTS. Agent replies and tool output are left out on purpose: they are the bulk of
# the table, they are where logs, manifests and credentials pasted back by tools live, and what is
# worth reviewing is the question — the answer the agent gave is exactly what a proposal would change.
# Two things decide "user-authored", both from kagent 0.10.1's source because the stored shape is
# pinned nowhere readable:
#   - event.data is the ADK Event serialised whole. The Python runtime writes model_dump_json()
#     (`"author":"user"`); the Go runtime json.Marshal's adk-go's session.Event, whose Author field
#     carries NO json tag (`"Author":"user"`). 13 of 16 agents on 057 run the Go runtime, so both are
#     matched. A tool's reply is authored by the agent, even though its content role is "user".
#   - session.source = 'agent' marks a session a PARENT AGENT opened over A2A; its "user" turns are a
#     model's delegation prompt, not a person's question.
# The LIKE is a prefilter to keep agent output off the wire, never the decision — _question_text
# re-reads every row, and QUESTIONS_CENSUS_SQL counts what the prefilter left behind, so a renamed
# field shows up as events-with-no-questions rather than as a quiet night.
#
# BOUNDED THREE WAYS IN THE DATABASE: the review window (event.created_at), a message cap per session
# (row_number), and a session cap (LIMIT over the most recently active). Characters are capped per
# session in Python, after redaction. No user_id is selected, and a session is named to the model by a
# per-run ordinal rather than its id.
_USER_AUTHORED = """(e.data LIKE '%"author":"user"%' OR e.data LIKE '%"Author":"user"%')"""
_ELIGIBLE = """
      FROM event e
      JOIN session s ON s.id = e.session_id AND s.user_id = e.user_id
     WHERE e.deleted_at IS NULL AND s.deleted_at IS NULL
       AND e.created_at >= :frm AND e.created_at <= :to
       -- Implied by the line above (an insert bumps its session's updated_at), and here because
       -- `event` has no index on created_at: this lets the planner start from the few sessions active
       -- in the window and reach their events through idx_event_session_id, instead of scanning a
       -- table that has filled a PVC on this platform before.
       AND s.updated_at >= :frm
       AND s.source IS DISTINCT FROM 'agent'
       AND NOT (coalesce(s.agent_id, '') = ANY(string_to_array(:excluded, ',')))
"""
QUESTIONS_SQL = f"""
    WITH q AS (
    SELECT e.session_id,
           coalesce(s.agent_id, '(none)')                                           AS agent,
           e.created_at,
           e.data,
           row_number() OVER (PARTITION BY e.session_id ORDER BY e.created_at)      AS n,
           count(*)     OVER (PARTITION BY e.session_id)                            AS in_session,
           max(e.created_at) OVER (PARTITION BY e.session_id)                       AS last_at
    {_ELIGIBLE}
       AND {_USER_AUTHORED}
    )
    SELECT session_id, agent, data, in_session
      FROM q
     WHERE n <= :per
       AND session_id IN (SELECT session_id FROM q GROUP BY session_id
                           ORDER BY max(last_at) DESC LIMIT :sessions)
     ORDER BY last_at DESC, session_id, created_at
"""
# The denominator. Without it "no questions" cannot be told apart from "questions in a shape we no
# longer recognise": both return zero rows from QUESTIONS_SQL.
QUESTIONS_CENSUS_SQL = f"""
    SELECT count(*)                                              AS events,
           count(*) FILTER (WHERE {_USER_AUTHORED})              AS user_authored,
           count(DISTINCT e.session_id) FILTER (WHERE {_USER_AUTHORED}) AS sessions,
           count(DISTINCT e.session_id)                          AS active
    {_ELIGIBLE}
"""
QUESTIONS_MAX_SESSIONS = int(os.environ.get("KAGENT_QUESTIONS_MAX_SESSIONS", "40"))
QUESTIONS_PER_SESSION = int(os.environ.get("KAGENT_QUESTIONS_PER_SESSION", "6"))
QUESTIONS_CHARS_PER_SESSION = int(os.environ.get("KAGENT_QUESTIONS_CHARS_PER_SESSION", "1500"))
# The reviewer's OWN sessions. Its user turn is last night's whole evidence corpus, so reading it back
# would feed the review its own previous input and crowd out every real question. "namespace/name",
# comma-separated; the chart sets it to the reviewer agent it creates.
QUESTIONS_EXCLUDE_AGENTS = os.environ.get("KAGENT_QUESTIONS_EXCLUDE_AGENTS", "")


def _agent_key(ns_name):
    """kagent's agent_id: ConvertToPythonIdentifier(namespace + "/" + name)."""
    return ns_name.strip().replace("-", "_").replace("/", "__NS__")


def _question_text(data):
    """The text of one stored event IF a person wrote it. Returns (text, shape).

    shape is one of four, and they are kept apart because they mean different things:
      matched      a user-authored event with text — a question
      unmatched    valid JSON that is not a user's text: a HITL approval (a function_response the user
                   authored), a thought, or a shape this reader does not know
      unparseable  not a JSON object at all
      empty        no payload
    Lumping unparseable into empty would hide a decoding problem behind legitimately empty events, and
    lumping unmatched into matched-with-no-text is how a renamed field reads as a quiet night."""
    if data is None or (isinstance(data, str) and not data.strip()):
        return "", "empty"
    try:
        ev = json.loads(data) if isinstance(data, str) else data
    except (ValueError, TypeError):
        return "", "unparseable"
    if not isinstance(ev, dict):
        return "", "unparseable"
    # Python runtime: snake_case pydantic dump. Go runtime: untagged exported fields, so Author and
    # Content are capitalised while genai.Content's own tags keep `parts`/`role`/`text` lowercase.
    author = ev.get("author", ev.get("Author"))
    content = ev.get("content", ev.get("Content"))
    if author != "user" or not isinstance(content, dict):
        return "", "unmatched"
    texts = [p["text"] for p in (content.get("parts") or [])
             if isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"].strip()
             and not p.get("thought")]
    if not texts:
        return "", "unmatched"
    return "\n".join(t.strip() for t in texts), "matched"


def _read_questions(conn, window, stats):
    """The questions block's lines, with the question stats filled in as a side effect — before any
    raise, so a failed read still records the shapes that explain it. Raises on a database error or an
    unreadable corpus, so the caller can degrade the source without losing the metadata half."""
    if QUESTIONS_MAX_SESSIONS <= 0:
        stats["note"] = "question reading disabled (maxSessions: 0)"
        return []
    excluded = ",".join(_agent_key(a) for a in QUESTIONS_EXCLUDE_AGENTS.split(",") if a.strip())
    args = {"frm": window["from"], "to": window["to"], "excluded": excluded}
    ((events, user_authored, sessions, active),) = conn.run(QUESTIONS_CENSUS_SQL, **args)
    rows = conn.run(QUESTIONS_SQL, per=QUESTIONS_PER_SESSION, sessions=QUESTIONS_MAX_SESSIONS, **args)

    shapes = {"matched": 0, "unmatched": 0, "unparseable": 0, "empty": 0,
              # Everything the prefilter left in the database: agent replies, tool calls and results.
              "notUserAuthored": max(0, (events or 0) - (user_authored or 0))}
    by_session, order, in_session = {}, [], {}
    for session_id, agent, data, total in rows:
        text, shape = _question_text(data)
        shapes[shape] += 1
        if session_id not in by_session:
            by_session[session_id], in_session[session_id] = (agent, []), total
            order.append(session_id)
        if text:
            by_session[session_id][1].append(text)

    lines, quoted, dropped_msgs, dropped_chars = [], 0, 0, 0
    for i, sid in enumerate(order, 1):
        agent, texts = by_session[sid]
        dropped_msgs += max(0, in_session[sid] - QUESTIONS_PER_SESSION)
        budget, out = QUESTIONS_CHARS_PER_SESSION, []
        for t in texts:
            # REDACT BEFORE CUTTING. A token cut in half by the budget is no longer long enough to match
            # its pattern, so truncating first would hand the model the first half of a credential.
            t = redact(t)
            if budget <= 0:
                dropped_msgs += 1
                dropped_chars += len(t)
                continue
            if len(t) > budget:
                dropped_chars += len(t) - budget
                t = t[:budget] + " …[cut]"
            budget -= len(t)
            out.append("    > " + t.replace("\n", "\n      "))
        if out:
            quoted += len(out)
            lines.append(f"  - conversation {i} with {agent}:")
            lines.extend(out)
    dropped_sessions = max(0, (sessions or 0) - len(order))

    stats["questions"] = quoted
    stats["questionSessions"] = len(order)
    stats["shapes"] = shapes
    if dropped_msgs or dropped_chars or dropped_sessions:
        # The fields every source already uses for "the model did not see all of it".
        stats["truncated"] = True
        stats["droppedChars"] = stats.get("droppedChars", 0) + dropped_chars
        stats["droppedMessages"] = dropped_msgs
        stats["droppedSessions"] = dropped_sessions
    # AN UNREADABLE CORPUS MUST NOT LOOK LIKE A QUIET NIGHT. People talked to agents inside the window
    # and not one question came out: either the stored shape changed or the prefilter no longer
    # matches it. Either way the reader is broken, and the run must say so.
    if events and not shapes["matched"]:
        raise RuntimeError(f"{events} event(s) in the window but no question recognised "
                           f"(shapes {shapes}); the stored event shape may have changed")
    # THE PARTIAL VERSION OF THE SAME FAILURE. Two runtimes write two spellings; if one of them changes,
    # the other still matches and the total above never reaches zero — a night would quietly lose every
    # conversation with, on 057, 13 of 16 agents. A conversation active in the window with no question
    # in it happens only at the window's edge, so when that is most of them, say so. A note, not an
    # error: it is a suspicion, and the questions that WERE read are real.
    silent = (active or 0) - (sessions or 0)
    if silent and silent * 2 >= (active or 0):
        stats["note"] = (f"{silent} of {active} conversation(s) active in the window had no recognisable "
                         f"question — one runtime's stored event shape may have changed")
    if not lines:
        return []
    return [f"- QUESTIONS PEOPLE ASKED in this window ({quoted} quoted from {len(order)} conversation(s), "
            f"user-authored only, redacted):"] + lines


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

    AND WHAT PEOPLE ASKED, on the same connection and after the census: see QUESTIONS_SQL. That half
    fails on its own, so a role still revoked on `event` costs the questions and not the census.
    """
    if not (KAGENT_DB_USER and KAGENT_DB_PASSWORD):
        return None, {"ok": False, "error": "kagent DB credentials not configured (KAGENT_DB_USER/PASSWORD)"}
    try:
        import pg8000.native                                  # pure-python: no libpq in the image
    except Exception as exc:                                  # noqa: BLE001
        return None, {"ok": False, "error": f"pg8000 unavailable: {exc}"}

    conn = None
    questions, questions_err, qstats = [], None, {}
    try:
        conn = pg8000.native.Connection(
            user=KAGENT_DB_USER, password=KAGENT_DB_PASSWORD, host=KAGENT_DB_HOST,
            port=KAGENT_DB_PORT, database=KAGENT_DB_NAME, timeout=30,
        )
        rows = conn.run(SESSION_SQL, frm=window["from"], to=window["to"], lim=limit)
        # THE QUESTIONS FAIL ON THEIR OWN. A role still revoked on `event`, or a shape this reader no
        # longer recognises, must cost the questions and not the idle/never-used findings beside them.
        try:
            questions = _read_questions(conn, window, qstats)
        except Exception as exc:                              # noqa: BLE001
            questions_err = redact(f"questions: {exc}")[:300]
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
            deployed[_agent_key(f"{ns}/{nm}")] = f"{ns}/{nm}"
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

    # EVERY FINDING IS GATED ON THE AGENT STILL BEING DEPLOYED. Session rows outlive the agent that made
    # them: delete an agent and its history stays, so a source that derives staleness from sessions alone
    # reports "IDLE 21d" forever for something that no longer exists. That is not a stale finding, it is a
    # permanent false one, and it gets worse over time as more agents are retired. An idle agent that is
    # not deployed is history, not a problem.
    #
    # When the deployed set could not be read we cannot make that distinction, so `live` falls back to
    # every agent seen and the note already appended says the comparison was unavailable — degrading to
    # over-reporting with an explanation, rather than silently reporting nothing.
    live = set(deployed) if deployed else set(seen)
    never = sorted(deployed[k] for k in deployed if k not in seen) if deployed else []
    stale = sorted(((v[3], k) for k, v in seen.items()
                    if k in live and v[3] is not None and v[3] >= 7), reverse=True)
    rare = sorted((v[0], k) for k, v in seen.items() if k in live and v[0] <= 3)
    active = sorted(((v[1], k) for k, v in seen.items() if k in live and v[1] > 0), reverse=True)

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

    # The questions go AFTER the agent findings: absence first, then what the present users asked.
    lines += questions

    stats = {"ok": True, "queried": 1, "returned": len(rows),
             "agentsDeployed": len(deployed) or None, "agentsNeverUsed": len(never),
             "agentsIdle7d": len(stale), "agentsActiveInWindow": len(active),
             "scope": ("all-users: session metadata, and the text of USER-AUTHORED messages inside the "
                       "window, redacted (SELECT on session and event; never task, never user ids)")}
    notes = [qstats.pop("note", None),
             f"deployed-agent list unreadable: {deployed_err}" if deployed_err else None]
    stats |= qstats
    if questions_err:
        # DEGRADED, NOT BLANKED. The metadata half still answers; ok:false is what makes the run
        # PartiallyCompleted, because a review that meant to read the questions and could not is a
        # half-finished review, and the record must not read like a quiet night.
        stats["ok"] = False
        stats["error"] = questions_err
    if any(notes):
        stats["note"] = "; ".join(n for n in notes if n)
    if not lines:
        stats |= {"empty": True, "note": "no kagent agents and no sessions found at all"}
        return None, stats
    return _sessions_body(lines[:len(lines) - len(questions)], questions, stats), stats


class SessionsBody(str):
    """The kagent-sessions block, which still remembers which lines were questions and whose.

    A str, so everything that reads a block reads this unchanged. It exists for fold_questions: the
    agent-analysis stage runs AFTER this source and reads the same people's messages in full, so the
    questions it covered are paid for twice unless they can be taken back out — and taking them out of
    the rendered text by pattern would be parsing our own output after the cap had already cut it."""
    head = questions = snapshot = None


_TRUNCATION_KEYS = ("truncated", "truncatedAtChars", "droppedChars")


def _sessions_body(head, questions, stats):
    snapshot = {k: stats.get(k) for k in _TRUNCATION_KEYS}
    body = SessionsBody(_cap(redact("\n".join(head + questions)), stats))
    body.head, body.questions, body.snapshot = head, questions, snapshot
    return body


_CONVERSATION = re.compile(r"^  - conversation \d+ with (\S+):$")


def fold_questions(body, stats, covered):
    """The kagent-sessions block with the questions of every agent in `covered` (kagent agent_ids)
    replaced by one pointer line each, re-capped, with the truncation fields recomputed for what is now
    sent. The census half — idle, never used, active — and the questions of agents the analysis did NOT
    read (over its agent cap, excluded, or failed) are untouched: those still reach the review only here.

    WHY #32's READ STAYS RATHER THAN BEING REPLACED. Its census and `shapes` are the denominator that
    tells "nobody asked" from "the stored shape changed", and it is the fallback for every agent the
    analysis does not cover tonight. What it no longer does is spend the main corpus's budget quoting a
    conversation that a separate call has already read in full."""
    if not isinstance(body, SessionsBody) or not covered or not body.questions:
        return body
    header, groups = body.questions[0], []
    for line in body.questions[1:]:
        m = _CONVERSATION.match(line)
        if m:
            groups.append((m.group(1), [line]))
        elif groups:
            groups[-1][1].append(line)
    folded = {}
    for agent, _ in groups:
        if agent in covered:
            folded[agent] = folded.get(agent, 0) + 1
    if not folded:
        return body
    kept = [ln for agent, g in groups if agent not in covered for ln in g]
    questions = ([header] + kept if kept else []) + [
        f"- QUESTIONS to {agent} in {n} conversation(s): read IN FULL by agent-analysis, with the replies "
        f"and tool calls — see that evidence; not repeated here" for agent, n in sorted(folded.items())]
    for k, v in body.snapshot.items():
        if v is None:
            stats.pop(k, None)
        else:
            stats[k] = v
    stats["questionsFolded"] = sum(folded.values())
    return _sessions_body(body.head, questions, stats)


# Bounds for the page list. 057 carries 33 page roots in krateo-system against 184 Flex widgets and 553
# widget CRs in all; the roots are what a proposal would duplicate, and the rest would crowd out the
# telemetry the proposals are supposed to come from.
MAX_PAGES = int(os.environ.get("EVIDENCE_MAX_PAGES", "100"))


def kubernetes(api):
    """What the platform ALREADY has, so the agent proposes gaps rather than duplicates.

    Without this the most likely proposal every night is an alert for something already alerted on —
    the model cannot know what exists unless it is shown. The same holds for Widget proposals, which is
    why page roots are listed too: "add a page showing X" for a page that already shows X is the Widget
    kind's version of the duplicate alert.

    EACH READ FAILS ON ITS OWN. A cluster without one of these kinds is a normal condition, so a read
    that errors is recorded and the others still answer; the source is degraded, never blanked by it."""
    ns = os.environ.get("NAMESPACE", "krateo-system")
    blocks, st = [], {"ok": True, "queried": 0, "returned": 0}

    def _read(what, group, version, plural, render, keep=lambda i: True, cap=None):
        try:
            items = [i for i in api.list_namespaced_custom_object(group, version, ns, plural)
                     .get("items", []) if keep(i)]
        except Exception as exc:                              # noqa: BLE001
            st["ok"] = False
            st["error"] = st.get("error", "") + f"{what}: {str(exc)[:160]}; "
            return
        st["queried"] += 1
        st["returned"] += len(items)
        items.sort(key=lambda i: i["metadata"]["name"])
        shown = items[:cap] if cap else items
        lines = [render(i) for i in shown]
        if len(items) > len(shown):
            lines.append(f"- ... and {len(items) - len(shown)} more {what} not listed")
            st["note"] = st.get("note", "") + f"{what}: listed {len(shown)} of {len(items)}; "
        if lines:
            blocks.append("\n".join(lines))

    _read("alerts", "observability.krateo.io", "v1alpha1", "alerts",
          lambda a: (f"- existing Alert {a['metadata']['name']}: "
                     f"{(a.get('spec') or {}).get('displayName', '')!r} "
                     f"threshold={(a.get('spec') or {}).get('threshold')} "
                     f"{(a.get('spec') or {}).get('thresholdType', '')}"))

    # THERE IS NO Page KIND. templates.krateo.io serves only restactions; a portal page IS a Flex widget
    # whose name begins with "page-", and its route is the krateo.io/nav-path annotation when it has one.
    # Listed in this namespace only, which is also what keeps krateo-preview's 99 draft page roots on 057
    # out of the corpus: those are previews, not pages anyone can reach.
    _read("pages", "widgets.templates.krateo.io", "v1beta1", "flexes",
          lambda f: (f"- existing Page {f['metadata']['name']}"
                     + (f" at {nav}" if (nav := (f['metadata'].get('annotations') or {})
                                          .get('krateo.io/nav-path')) else "")),
          keep=lambda f: f["metadata"]["name"].startswith("page-"), cap=MAX_PAGES)

    if not blocks:
        if st["ok"]:
            # Read and found nothing: explained emptiness, which main.py does not count as degraded.
            st |= {"empty": True, "note": f"no Alerts and no page roots in {ns}"}
        return None, st
    return _cap("\n".join(blocks), st), st
