"""status.coverage: how much of the night the review saw, counted by the service, said in words.

The fixture is rr-20260930-0200's status.evidence, trimmed to the fields coverage reads: the first
analysis run on 057, which read 21 of 65 conversations and whose summary did not say so."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import coverage as C


def _agent(name, sessions, conversations, dropped_chars, dropped_messages=0, dropped_sessions=0, error=None,
           chars=None):
    r = {"agent": f"krateo-system/{name}", "sessions": sessions, "conversations": conversations,
         "droppedChars": dropped_chars, "droppedMessages": dropped_messages, "droppedSessions": dropped_sessions}
    if error:
        r["error"] = error
    if chars is not None:
        r["chars"] = chars
    return r


def rr_20260930_0200(chars=False):
    agents = [("autopilot", 45, 10, 287120, 383, 35, None), ("incident-agent", 6, 4, 1206530, 425, 2, None),
              ("snowplow-agent", 5, 5, 201113, 10, 0, "ValueError: agent task failed: Request blocked"),
              ("frontend-agent", 2, 2, 40277, 230, 0, None), ("core-provider-agent", 2, 2, 289576, 92, 0, None),
              ("clickstack-agent", 1, 1, 30057, 64, 0, None), ("installer-agent", 1, 1, 291188, 28, 0, None),
              ("helm-agent", 1, 1, 123825, 16, 0, None)]
    return {
        "agent-analysis": {
            "ok": True, "truncated": True, "droppedChars": 2469686,
            "agents": [_agent(n, s, c, d, m, ds, e, chars=80000 if chars else None) for n, s, c, d, m, ds, e in agents],
            "skipped": [{"agent": "krateo-system/nightly-review-agent", "reason": "excluded", "sessions": 5},
                        {"agent": "krateo-system/authn-agent", "reason": "over maxAgents", "sessions": 1},
                        {"agent": "krateo-system/k8s-agent", "reason": "over maxAgents", "sessions": 1}]},
        "clickhouse": {"ok": True, "returned": 56},
        "kagent-sessions": {"ok": True, "truncated": True, "truncatedAtChars": 60000, "droppedChars": 374811,
                            "questionsFolded": 40},
        "kubernetes": {"ok": True, "returned": 60},
    }


def test_rr_20260930_0200_reads_as_the_fraction_it_was():
    cov = C.compute(rr_20260930_0200())
    assert cov["complete"] is False
    assert (cov["conversationsRead"], cov["conversationsTotal"]) == (21, 65)
    assert cov["sentence"].startswith("Coverage: Based on 21 of 65 agent conversations; 3 agent(s) skipped: ")
    assert "krateo-system/snowplow-agent (analysis failed)" in cov["sentence"]
    assert "krateo-system/authn-agent (over maxAgents)" in cov["sentence"]
    assert "kagent-sessions (374,811 characters not shown)" in cov["sentence"]


def test_excluded_and_retired_agents_are_out_of_scope_not_missed():
    """The reviewer's own sessions are excluded on purpose; counting them as missed would make every run
    look partial for a reason nobody can act on."""
    cov = C.compute(rr_20260930_0200())
    assert "nightly-review-agent" not in cov["sentence"]
    assert [s["reason"] for s in cov["agentsSkipped"]] == ["over maxAgents", "over maxAgents", "analysis failed"]


def test_characters_are_a_lower_bound_when_anything_went_unfetched():
    cov = C.compute(rr_20260930_0200(chars=True))
    # A failed agent's characters were shown to a call that returned nothing usable: not read.
    assert cov["charsRead"] == 7 * 80000
    assert cov["charsTotal"] == 8 * 80000 + 2469686 and cov["charsTotalIsLowerBound"] is True
    assert "(560,000 of at least 3,109,686 characters)" in cov["sentence"]


def test_a_complete_night_says_all_and_leaves_the_summary_alone():
    ev = {"agent-analysis": {"ok": True, "agents": [_agent("a", 3, 3, 0, chars=500)]},
          "clickhouse": {"ok": True}}
    cov = C.compute(ev)
    assert cov["complete"] is True
    assert cov["sentence"] == "Coverage: Based on all 3 agent conversations (500 characters)."
    assert C.summary(cov, "the model's words") == "the model's words"


def test_a_cut_night_opens_the_summary_with_the_sentence():
    cov = C.compute(rr_20260930_0200())
    s = C.summary(cov, "Nightly review identified three significant unalerted platform error patterns")
    assert s.startswith(cov["sentence"] + " Nightly review identified")
    assert C.summary(cov, "") == cov["sentence"]
    assert len(C.summary(cov, "x" * 5000)) == 2000


def test_the_assessment_block_being_cut_is_a_source_cut():
    ev = rr_20260930_0200()
    ev["agent-analysis"]["corpusDroppedChars"] = 1234
    assert {"source": "agent-analysis", "droppedChars": 1234} in C.compute(ev)["sourcesCut"]


def test_no_analysis_at_all_is_said_rather_than_omitted():
    cov = C.compute({"agent-analysis": {"ok": False, "error": "kagent DB credentials not configured"},
                     "clickhouse": {"ok": True}})
    assert cov["complete"] is False
    assert cov["sentence"] == ("Coverage: No agent conversation was analysed (kagent DB credentials not "
                               "configured); did not answer: agent-analysis.")


def test_a_source_that_did_not_answer_is_named():
    ev = rr_20260930_0200()
    ev["clickhouse"] = {"ok": False, "error": "timeout"}
    cov = C.compute(ev)
    assert cov["sourcesFailed"] == ["clickhouse"] and cov["sentence"].endswith("; did not answer: clickhouse.")
