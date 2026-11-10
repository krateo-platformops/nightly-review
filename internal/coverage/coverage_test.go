package coverage_test

// status.coverage: how much of the night the review saw, counted by the service, said in words
// (tests/test_coverage.py). The fixture is rr-20260930-0200's status.evidence, trimmed to the fields
// coverage reads: the first analysis run on 057, which read 21 of 65 conversations and whose summary did
// not say so.

import (
	"reflect"
	"strings"
	"testing"

	C "github.com/krateo-platformops/nightly-review/internal/coverage"
)

func agent(name string, sessions, conversations, droppedChars, droppedMessages, droppedSessions int64, err string, chars int64) map[string]any {
	r := map[string]any{"agent": "krateo-system/" + name, "sessions": sessions, "conversations": conversations,
		"droppedChars": droppedChars, "droppedMessages": droppedMessages, "droppedSessions": droppedSessions}
	if err != "" {
		r["error"] = err
	}
	if chars >= 0 {
		r["chars"] = chars
	}
	return r
}

func rr20260930(chars bool) map[string]map[string]any {
	c := int64(-1)
	if chars {
		c = 80000
	}
	agents := []any{
		agent("autopilot", 45, 10, 287120, 383, 35, "", c), agent("incident-agent", 6, 4, 1206530, 425, 2, "", c),
		agent("snowplow-agent", 5, 5, 201113, 10, 0, "ValueError: agent task failed: Request blocked", c),
		agent("frontend-agent", 2, 2, 40277, 230, 0, "", c), agent("core-provider-agent", 2, 2, 289576, 92, 0, "", c),
		agent("clickstack-agent", 1, 1, 30057, 64, 0, "", c), agent("installer-agent", 1, 1, 291188, 28, 0, "", c),
		agent("helm-agent", 1, 1, 123825, 16, 0, "", c),
	}
	return map[string]map[string]any{
		"agent-analysis": {"ok": true, "truncated": true, "droppedChars": int64(2469686), "agents": agents,
			"skipped": []any{
				map[string]any{"agent": "krateo-system/nightly-review-agent", "reason": "excluded", "sessions": int64(5)},
				map[string]any{"agent": "krateo-system/authn-agent", "reason": "over maxAgents", "sessions": int64(1)},
				map[string]any{"agent": "krateo-system/k8s-agent", "reason": "over maxAgents", "sessions": int64(1)}}},
		"clickhouse": {"ok": true, "returned": int64(56)},
		"kagent-sessions": {"ok": true, "truncated": true, "truncatedAtChars": int64(60000), "droppedChars": int64(374811),
			"questionsFolded": int64(40)},
		"kubernetes": {"ok": true, "returned": int64(60)},
	}
}

func TestRr202609300200ReadsAsTheFractionItWas(t *testing.T) {
	cov := C.Compute(rr20260930(false))
	s := cov["sentence"].(string)
	if cov["complete"] != false || cov["conversationsRead"] != int64(21) || cov["conversationsTotal"] != int64(65) ||
		!strings.HasPrefix(s, "Coverage: Based on 21 of 65 agent conversations; 3 agent(s) skipped: ") ||
		!strings.Contains(s, "krateo-system/snowplow-agent (analysis failed)") ||
		!strings.Contains(s, "krateo-system/authn-agent (over maxAgents)") ||
		!strings.Contains(s, "kagent-sessions (374,811 characters not shown)") {
		t.Fatal(cov)
	}
}

func TestExcludedAndRetiredAgentsAreOutOfScopeNotMissed(t *testing.T) {
	cov := C.Compute(rr20260930(false))
	if strings.Contains(cov["sentence"].(string), "nightly-review-agent") {
		t.Fatal(cov["sentence"])
	}
	var reasons []string
	for _, s := range cov["agentsSkipped"].([]any) {
		reasons = append(reasons, s.(map[string]any)["reason"].(string))
	}
	if !reflect.DeepEqual(reasons, []string{"over maxAgents", "over maxAgents", "analysis failed"}) {
		t.Fatal(reasons)
	}
}

func TestCharactersAreALowerBoundWhenAnythingWentUnfetched(t *testing.T) {
	cov := C.Compute(rr20260930(true))
	// A failed agent's characters were shown to a call that returned nothing usable: not read.
	if cov["charsRead"] != int64(7*80000) || cov["charsTotal"] != int64(8*80000+2469686) || cov["charsTotalIsLowerBound"] != true ||
		!strings.Contains(cov["sentence"].(string), "(560,000 of at least 3,109,686 characters)") {
		t.Fatal(cov)
	}
}

func TestACompleteNightSaysAllAndLeavesTheSummaryAlone(t *testing.T) {
	ev := map[string]map[string]any{"agent-analysis": {"ok": true, "agents": []any{agent("a", 3, 3, 0, 0, 0, "", 500)}},
		"clickhouse": {"ok": true}}
	cov := C.Compute(ev)
	if cov["complete"] != true || cov["sentence"] != "Coverage: Based on all 3 agent conversations (500 characters)." ||
		C.Summary(cov, "the model's words") != "the model's words" {
		t.Fatal(cov)
	}
}

func TestACutNightOpensTheSummaryWithTheSentence(t *testing.T) {
	cov := C.Compute(rr20260930(false))
	s := C.Summary(cov, "Nightly review identified three significant unalerted platform error patterns")
	if !strings.HasPrefix(s, cov["sentence"].(string)+" Nightly review identified") || C.Summary(cov, "") != cov["sentence"] ||
		len([]rune(C.Summary(cov, strings.Repeat("x", 5000)))) != 2000 {
		t.Fatal(s)
	}
}

func TestTheAssessmentBlockBeingCutIsASourceCut(t *testing.T) {
	ev := rr20260930(false)
	ev["agent-analysis"]["corpusDroppedChars"] = int64(1234)
	found := false
	for _, c := range C.Compute(ev)["sourcesCut"].([]any) {
		m := c.(map[string]any)
		found = found || (m["source"] == "agent-analysis" && m["droppedChars"] == int64(1234))
	}
	if !found {
		t.Fatal("not recorded")
	}
}

func TestNoAnalysisAtAllIsSaidRatherThanOmitted(t *testing.T) {
	cov := C.Compute(map[string]map[string]any{"agent-analysis": {"ok": false, "error": "kagent DB credentials not configured"},
		"clickhouse": {"ok": true}})
	if cov["complete"] != false || cov["sentence"] != "Coverage: No agent conversation was analysed (kagent DB credentials not "+
		"configured); did not answer: agent-analysis." {
		t.Fatal(cov["sentence"])
	}
}

func TestASourceThatDidNotAnswerIsNamed(t *testing.T) {
	ev := rr20260930(false)
	ev["clickhouse"] = map[string]any{"ok": false, "error": "timeout"}
	cov := C.Compute(ev)
	if !reflect.DeepEqual(cov["sourcesFailed"], []string{"clickhouse"}) || !strings.HasSuffix(cov["sentence"].(string), "; did not answer: clickhouse.") {
		t.Fatal(cov)
	}
}
