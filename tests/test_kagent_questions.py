"""What people asked: the question read out of kagent's Postgres, and the page roots beside the Alerts.

THE PROPERTY WORTH GUARDING HARDEST IS THAT AN UNREADABLE CORPUS IS REPORTED. event.data is an ADK event
serialised verbatim, by two runtimes that spell it differently, and the shape is pinned nowhere readable.
"Nobody asked anything last night" and "I could not read any of the questions" produce the same empty
block and mean opposite things, so the shapes histogram and the unreadable-corpus failure are what these
tests pin. The second is that nothing reaches the prompt unredacted, including a credential a person
pasted into a question, and including one the per-session cap would have cut in half.
"""
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import evidence as E

WINDOW = {"from": "2026-09-28T02:00:00+00:00", "to": "2026-09-29T02:00:00+00:00"}


def _py(text, author="user", **part):
    """The Python runtime: pydantic model_dump_json(), snake_case, None fields present."""
    return json.dumps({"author": author, "content": {"role": "user", "parts": [dict(text=text, **part)]},
                       "invocation_id": "i", "partial": None})


def _go(text, author="user"):
    """The Go runtime: json.Marshal of adk-go's session.Event, whose fields carry no json tags."""
    return json.dumps({"Author": author, "Content": {"role": "user", "parts": [{"text": text}]},
                       "ID": "e", "InvocationID": "i", "Partial": False})


# --- one event ------------------------------------------------------------------------------------

def test_a_python_runtime_question_is_read():
    assert E._question_text(_py("why is my composition not ready?")) == (
        "why is my composition not ready?", "matched")


def test_a_go_runtime_question_is_read():
    """13 of 16 agents on 057 run the Go runtime. Reading only the pydantic spelling would have read
    one conversation in five and reported the rest as silence."""
    assert E._question_text(_go("how do I add a cluster?")) == ("how do I add a cluster?", "matched")


def test_an_agent_reply_is_not_a_question():
    assert E._question_text(_go("Your composition is waiting on ...", author="autopilot")) == ("", "unmatched")


def test_a_tool_result_is_not_a_question_even_though_its_role_is_user():
    """ADK files a function_response under content role "user". The AUTHOR is what says a person wrote
    it; reading the role would quote tool output, which is where logs and credentials live."""
    ev = json.dumps({"author": "k8s-agent", "content": {"role": "user", "parts": [
        {"function_response": {"name": "k8s_get", "response": {"result": "apiVersion: v1 ..."}}}]}})
    assert E._question_text(ev) == ("", "unmatched")


def test_a_hitl_approval_the_user_authored_is_not_text():
    ev = json.dumps({"author": "user", "content": {"role": "user", "parts": [
        {"function_response": {"name": "adk_request_confirmation", "response": {"confirmed": True}}}]}})
    assert E._question_text(ev) == ("", "unmatched")


def test_thought_parts_are_not_quoted():
    assert E._question_text(_py("internal reasoning", thought=True)) == ("", "unmatched")


def test_unparseable_and_empty_are_kept_apart():
    assert E._question_text("not json")[1] == "unparseable"
    assert E._question_text("[1, 2]")[1] == "unparseable"          # valid JSON, wrong type
    assert E._question_text(None)[1] == "empty"
    assert E._question_text("   ")[1] == "empty"


def test_an_unknown_shape_is_unmatched_not_silent():
    assert E._question_text(json.dumps({"message": {"text": "hello"}}))[1] == "unmatched"


# --- the read -------------------------------------------------------------------------------------

class _Conn:
    """pg8000.native.Connection, answering the census and the questions query by what they select."""
    def __init__(self, rows, census=None):
        self.rows, self.sql = rows, []
        users, sessions = len(rows), len({r[0] for r in rows})
        self.census = census or (users + 3, users, sessions, sessions)

    def run(self, sql, **k):
        self.sql.append((sql, k))
        if "AS user_authored" in sql:
            return [self.census]
        if "WITH q AS" in sql:
            return self.rows
        raise AssertionError("unexpected query")


def test_questions_are_grouped_by_conversation_without_ids():
    conn = _Conn([("sid-a", "krateo_system__NS__autopilot", _go("how do I add a cluster?"), 1),
                  ("sid-b", "krateo_system__NS__autopilot", _py("how do I add a cluster"), 1)])
    stats = {}
    out = "\n".join(E._read_questions(conn, WINDOW, stats))
    assert "conversation 1 with krateo_system__NS__autopilot" in out and "conversation 2" in out
    assert "sid-a" not in out, "a session is named by a per-run ordinal, not its id"
    assert stats["questions"] == 2 and stats["questionSessions"] == 2
    assert stats["shapes"] == {"matched": 2, "unmatched": 0, "unparseable": 0, "empty": 0,
                               "notUserAuthored": 3}
    assert "truncated" not in stats


def test_an_unreadable_corpus_fails_instead_of_reading_as_a_quiet_night():
    """People talked to agents and no question came out: the shape changed, or the prefilter no longer
    matches it. The source must fail, so the run is PartiallyCompleted and says why."""
    conn = _Conn([("s", "a", json.dumps({"who": "user", "body": "renamed fields"}), 1)])
    with pytest.raises(RuntimeError, match="no question recognised"):
        E._read_questions(conn, WINDOW, {})


def test_events_with_no_user_authored_row_also_fail():
    """If kagent renamed Author, the LIKE prefilter would match nothing and QUESTIONS_SQL return no rows
    at all. The census is what still sees the events."""
    with pytest.raises(RuntimeError):
        E._read_questions(_Conn([], census=(40, 0, 0, 6)), WINDOW, {})


def test_one_runtime_going_unreadable_is_noted_even_though_the_other_still_reads():
    """Measured against kagent's own schema on Postgres 18.6: renaming the Go runtime's Author field
    left the Python conversation readable, the total above zero, and the Go conversation gone without a
    word. On 057 that is 13 agents of 16. The census of conversations is what notices."""
    stats = {}
    E._read_questions(_Conn([("s", "a", _py("q"), 1)], census=(30, 1, 1, 8)), WINDOW, stats)
    assert "7 of 8 conversation(s)" in stats["note"] and "shape may have changed" in stats["note"]


def test_a_conversation_at_the_window_edge_is_not_a_suspicion():
    stats = {}
    E._read_questions(_Conn([("s", "a", _py("q"), 1), ("t", "a", _go("r"), 1)],
                            census=(30, 2, 2, 3)), WINDOW, stats)
    assert "note" not in stats


def test_a_night_nobody_talked_to_an_agent_is_empty_not_an_error():
    stats = {}
    assert E._read_questions(_Conn([], census=(0, 0, 0, 0)), WINDOW, stats) == []
    assert stats["questions"] == 0


def test_the_per_session_caps_are_recorded_in_the_existing_fields(monkeypatch):
    monkeypatch.setattr(E, "QUESTIONS_PER_SESSION", 2)
    monkeypatch.setattr(E, "QUESTIONS_CHARS_PER_SESSION", 30)
    long_q = "x" * 50
    conn = _Conn([("s", "a", _go(long_q), 5), ("s", "a", _go("second"), 5)],
                 census=(12, 7, 3, 3))
    stats = {}
    out = "\n".join(E._read_questions(conn, WINDOW, stats))
    assert "…[cut]" in out and "second" not in out, "the budget was spent by the first question"
    assert stats["truncated"] is True
    assert stats["droppedChars"] == 20 + len("second")
    # 5 in the session, 2 read (cap), and the second of those two over the character budget.
    assert stats["droppedMessages"] == 3 + 1
    assert stats["droppedSessions"] == 2


def test_the_query_parameters_carry_the_window_caps_and_the_reviewer_exclusion(monkeypatch):
    monkeypatch.setattr(E, "QUESTIONS_EXCLUDE_AGENTS", "krateo-system/nightly-review-agent")
    conn = _Conn([("s", "a", _go("q"), 1)])
    E._read_questions(conn, WINDOW, {})
    (_, census), (_, questions) = conn.sql
    assert census["excluded"] == "krateo_system__NS__nightly_review_agent"
    assert questions["frm"] == WINDOW["from"] and questions["to"] == WINDOW["to"]
    assert questions["per"] == E.QUESTIONS_PER_SESSION and questions["sessions"] == E.QUESTIONS_MAX_SESSIONS


def test_zero_sessions_turns_the_read_off(monkeypatch):
    monkeypatch.setattr(E, "QUESTIONS_MAX_SESSIONS", 0)
    conn = _Conn([])
    assert E._read_questions(conn, WINDOW, {}) == [] and conn.sql == []


# --- the SQL --------------------------------------------------------------------------------------

def test_questions_sql_is_windowed_on_the_event_and_never_selects_a_user():
    from evidence import QUESTIONS_SQL as sql, QUESTIONS_CENSUS_SQL as census
    for q in (sql, census):
        assert "e.created_at >= :frm AND e.created_at <= :to" in q, "unbounded read of every conversation"
        assert "e.deleted_at IS NULL AND s.deleted_at IS NULL" in q
        assert "s.source IS DISTINCT FROM 'agent'" in q, "a parent agent's delegation is not a question"
        assert "FROM task" not in q and "JOIN task" not in q
    select_list = sql[sql.index("SELECT session_id, agent"):sql.index("FROM q")]
    assert "user_id" not in select_list, "identities must stay out of a corpus that reaches a model"
    assert "n <= :per" in sql and "LIMIT :sessions" in sql


def test_the_prefilter_matches_both_runtimes_spelling():
    assert '"author":"user"' in E.QUESTIONS_SQL and '"Author":"user"' in E.QUESTIONS_SQL
    # And the spelling each runtime actually writes has no space after the colon.
    assert '"author":"user"' in json.dumps({"author": "user"}, separators=(",", ":"))


# --- redaction: a person pasted a credential into a question -------------------------------------
# Assembled from fragments, each line carrying gitleaks:allow, for the reason test_review_bookkeeping
# gives: the repository is scanned and these are shaped like credentials. None is real.

JWT = "ey" + "J" + "hbGciOiJIUzI1NiJ9." + "e" * 30                                 # gitleaks:allow
PAT = "gh" + "p_" + "A" * 36                                                        # gitleaks:allow
PASSWORD = "hunter" + "2hunter2"                                                    # gitleaks:allow


@pytest.mark.parametrize("question,secret", [
    (f"my token {JWT} returns 401 from snowplow, why?", JWT),
    (f"I set Authorization: Bearer {PAT} and git-provider still fails", PAT),
    (f"the chart has password: {PASSWORD} — is that why the db will not start?", PASSWORD),
    (f"clone https://diego:{PASSWORD}@github.com/org/repo fails", PASSWORD),
])
def test_a_credential_pasted_into_a_question_never_reaches_the_prompt(question, secret):
    lines = E._read_questions(_Conn([("s", "a", _go(question), 1)]), WINDOW, {})
    out = "\n".join(lines)
    assert secret not in out, f"{secret[:8]}... reached the corpus"
    assert "REDACTED" in out


def test_redaction_runs_before_the_character_cap(monkeypatch):
    """Cut first and a JWT cut to 20 characters no longer matches its pattern — the model gets the
    first half of a credential. Redact first and the cut lands on the marker."""
    monkeypatch.setattr(E, "QUESTIONS_CHARS_PER_SESSION", 40)
    question = "why does this fail: " + JWT
    out = "\n".join(E._read_questions(_Conn([("s", "a", _go(question), 1)]), WINDOW, {}))
    assert JWT[:15] not in out, "a truncated, unredacted prefix of the token reached the corpus"


def test_the_whole_source_is_redacted_again_on_the_way_out(monkeypatch):
    """Belt and braces: kagent_sessions redacts the joined block too, as every source does."""
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    conn = types.SimpleNamespace(close=lambda: None, run=lambda sql, **k: (
        [(2, 1, 1, 1)] if "AS user_authored" in sql else
        [("s", "krateo_system__NS__a", _go(f"token {JWT}"), 1)] if "WITH q AS" in sql else
        [("krateo_system__NS__a", 5, 1, 1, now)]))
    _fake_pg(monkeypatch, conn)
    api = types.SimpleNamespace(list_cluster_custom_object=lambda *a: {"items": [
        {"metadata": {"namespace": "krateo-system", "name": "a"}}]})
    body, stats = E.kagent_sessions(api, WINDOW)
    assert JWT not in body and stats["ok"] is True
    assert stats["scope"].startswith("all-users")


# --- degradation ---------------------------------------------------------------------------------

def _fake_pg(monkeypatch, conn):
    native = types.SimpleNamespace(Connection=lambda **k: conn)
    monkeypatch.setitem(sys.modules, "pg8000", types.SimpleNamespace(native=native))
    monkeypatch.setitem(sys.modules, "pg8000.native", native)
    monkeypatch.setattr(E, "KAGENT_DB_USER", "u")
    monkeypatch.setattr(E, "KAGENT_DB_PASSWORD", "p")


def test_a_role_still_revoked_on_event_degrades_the_source_and_keeps_the_metadata(monkeypatch):
    """THE STATE 057 IS IN UNTIL THE GRANT CHANGES. The census of idle and never-used agents must
    survive; the run must still say the questions were not read."""
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)

    def run(sql, **k):
        if "FROM event" in sql:
            raise RuntimeError("permission denied for table event")
        return [("krateo_system__NS__a", 40, 4, 3, now - dt.timedelta(days=9))]
    _fake_pg(monkeypatch, types.SimpleNamespace(run=run, close=lambda: None))
    api = types.SimpleNamespace(list_cluster_custom_object=lambda *a: {"items": [
        {"metadata": {"namespace": "krateo-system", "name": "a"}}]})
    body, stats = E.kagent_sessions(api, WINDOW)
    assert "IDLE 9d" in body, "the metadata half was lost with the questions"
    assert stats["ok"] is False and "permission denied for table event" in stats["error"]


# --- page roots ------------------------------------------------------------------------------------

class _K8s:
    def __init__(self, alerts=(), flexes=(), fail=()):
        self.data, self.fail = {"alerts": list(alerts), "flexes": list(flexes)}, set(fail)

    def list_namespaced_custom_object(self, group, version, ns, plural):
        if plural in self.fail:
            raise RuntimeError(f"403 {plural}")
        return {"items": self.data[plural]}


def _flex(name, nav=None):
    md = {"name": name}
    if nav:
        md["annotations"] = {"krateo.io/nav-path": nav}
    return {"metadata": md}


def test_page_roots_are_listed_and_other_widgets_are_not():
    body, st = E.kubernetes(_K8s(flexes=[_flex("page-alerts", "/alerts"), _flex("alerts-table-row")]))
    assert "existing Page page-alerts at /alerts" in body and "alerts-table-row" not in body
    assert st == {"ok": True, "queried": 2, "returned": 1}


def test_a_missing_page_kind_degrades_the_source_rather_than_blanking_it():
    body, st = E.kubernetes(_K8s(alerts=[{"metadata": {"name": "a"}, "spec": {}}], fail={"flexes"}))
    assert "existing Alert a" in body, "one failed read blanked the other"
    assert st["ok"] is False and "pages: 403 flexes" in st["error"]


def test_a_missing_alert_kind_still_lists_pages():
    body, st = E.kubernetes(_K8s(flexes=[_flex("page-x")], fail={"alerts"}))
    assert "existing Page page-x" in body and st["ok"] is False


def test_the_page_list_is_bounded_and_says_so(monkeypatch):
    monkeypatch.setattr(E, "MAX_PAGES", 3)
    body, st = E.kubernetes(_K8s(flexes=[_flex(f"page-{i:02}") for i in range(10)]))
    assert body.count("existing Page") == 3 and "7 more pages not listed" in body
    assert st["returned"] == 10 and "listed 3 of 10" in st["note"]


def test_nothing_to_list_is_explained_emptiness_not_degradation():
    body, st = E.kubernetes(_K8s())
    assert body is None and st["ok"] is True and st["empty"] is True and st["note"]


# --- the chart's default queries -----------------------------------------------------------------

def test_the_default_queries_can_return_rows_on_this_platform():
    """SeverityText is ALWAYS empty here; a default filtering on it returned nothing, forever, and a
    platform with no errors looks exactly like that. The schema's default is what the installer applies,
    so it must match values.yaml."""
    import pathlib
    import yaml
    root = pathlib.Path(__file__).resolve().parent.parent / "helm/nightly-review"
    values = yaml.safe_load((root / "values.yaml").read_text())["clickhouseQueries"]
    schema = json.loads((root / "values.schema.json").read_text())["properties"]["clickhouseQueries"]
    assert set(values) == {"errorPatternsByService", "kubernetesEventReasons", "logVolumeByService"}
    assert schema["default"] == values
    for name, sql in values.items():
        assert "SeverityText" not in sql, name
        assert "'{from}'" in sql and "'{to}'" in sql, f"{name} would be refused as unwindowed"
        assert "GROUP BY" in sql and "count()" in sql, f"{name} returns rows, not an aggregate"
    assert "'k8s-events'" in values["kubernetesEventReasons"]
    assert "JSONExtractString(Body, 'object', 'reason')" in values["kubernetesEventReasons"]
