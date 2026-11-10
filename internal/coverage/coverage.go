// Package coverage says how much of the night the review actually saw, counted by the service and said
// in words.
//
// WHY THIS EXISTS. rr-20260930-0200, the first analysis run on 057, cut 2,469,686 characters out of the
// agent-analysis stage, left two agents unanalysed for the agent cap and one for a failed call, and
// folded all forty of kagent-sessions' questions into that analysis. The model saw a small fraction of
// the conversations, and its summary read like a full review. Every number needed to say otherwise was
// already on the run, spread over status.evidence where no reader of the summary would add it up.
//
// SO THE SERVICE ADDS IT UP. status.coverage carries the counts; its `sentence` is prepended to
// status.summary whenever anything was cut, and the same sentence goes into the main model's corpus note
// so its proposals stop claiming more than it read. It is computed from the sources' own stats, never
// asked of a model: a model that saw a fraction cannot be the one to say how large a fraction.
//
// WHAT THE NUMBERS MEAN, precisely, because "X of Y" invites rounding in the reader's head.
//   - conversations: the agent-analysis stage's. Read = conversations shown to an agent's call THAT
//     RETURNED an assessment. Total = every conversation in the window of the agents chosen for analysis
//     plus those skipped for the agent cap. Agents excluded by configuration and agents no longer
//     deployed are outside the total: they are out of scope, not missed.
//   - characters: in the stage's rendered units. It is a LOWER BOUND whenever events or conversations
//     were dropped without being fetched, and the sentence then says "at least".
//   - sourcesCut: every main-corpus source that was truncated before the main call, and the
//     agent-analysis block itself when the assessments overran corpusMaxChars.
//   - sourcesFailed: every source that did not answer (ok: false).
package coverage

import (
	"sort"
	"strings"

	"github.com/krateo-platformops/nightly-review/internal/py"
)

// SkipReasons are the skip reasons that count as missed rather than out of scope.
var SkipReasons = []string{"over maxAgents"}

func n(v int64) string { return py.Thousands(v) }

func isSkipReason(r any) bool {
	for _, s := range SkipReasons {
		if r == s {
			return true
		}
	}
	return false
}

// Compute builds status.coverage from status.evidence. It always returns a map; `complete` says whether
// anything was cut, and `sentence` is always set so the corpus note can carry it either way.
func Compute(evidence map[string]map[string]any) map[string]any {
	var aa map[string]any
	if a := evidence["agent-analysis"]; len(a) > 0 {
		aa = a
	}
	records := py.List(py.Get(aa, "agents"))
	var overCap []any
	for _, s := range py.List(py.Get(aa, "skipped")) {
		if isSkipReason(py.Get(s, "reason")) {
			overCap = append(overCap, s)
		}
	}
	var convRead, convTotal, charsRead, charsTotal int64
	measured, lowerBound := false, len(overCap) > 0
	for _, r := range records {
		if !py.Truthy(py.Get(r, "error")) {
			convRead += py.Int(py.Get(r, "conversations"))
			charsRead += py.Int(py.Get(r, "chars"))
		}
		convTotal += py.Int(py.Get(r, "sessions"))
		if py.Has(r, "chars") {
			measured = true
		}
		charsTotal += py.Int(py.Get(r, "chars")) + py.Int(py.Get(r, "droppedChars"))
		if py.Truthy(py.Get(r, "droppedMessages")) || py.Truthy(py.Get(r, "droppedSessions")) || py.Truthy(py.Get(r, "error")) {
			lowerBound = true
		}
	}
	for _, s := range overCap {
		convTotal += py.Int(py.Get(s, "sessions"))
	}

	skipped := []any{}
	for _, s := range overCap {
		skipped = append(skipped, map[string]any{"agent": py.Get(s, "agent"), "reason": py.Get(s, "reason")})
	}
	for _, r := range records {
		if py.Truthy(py.Get(r, "error")) {
			reason := "nothing readable"
			if py.Truthy(py.Get(r, "conversations")) {
				reason = "analysis failed"
			}
			skipped = append(skipped, map[string]any{"agent": py.Get(r, "agent"), "reason": reason})
		}
	}

	cut := []any{}
	names := py.SortedKeys(evidence)
	for _, name := range names {
		st := evidence[name]
		if name == "agent-analysis" {
			if py.Truthy(st["corpusDroppedChars"]) {
				cut = append(cut, map[string]any{"source": name, "droppedChars": st["corpusDroppedChars"]})
			}
		} else if py.Truthy(st["truncated"]) {
			dropped := st["droppedChars"]
			if _, ok := st["droppedChars"]; !ok {
				dropped = 0
			}
			cut = append(cut, map[string]any{"source": name, "droppedChars": dropped})
		}
	}

	// A source that did not answer at all is not "cut", but a summary that stayed silent about it would
	// read as a whole night all the same. The phase says PartiallyCompleted; the sentence says which.
	failed := []string{}
	for _, name := range names {
		if ok, isBool := evidence[name]["ok"].(bool); isBool && !ok {
			failed = append(failed, name)
		}
	}
	sort.Strings(failed)

	complete := !(len(skipped) > 0 || len(cut) > 0 || len(failed) > 0 || py.Truthy(py.Get(aa, "truncated")) ||
		convRead < convTotal || (measured && charsRead < charsTotal))

	var parts []string
	if len(records) > 0 || len(overCap) > 0 {
		head := "Based on "
		if convRead == convTotal {
			head += "all "
		}
		head += n(convRead)
		if convRead != convTotal {
			head += " of " + n(convTotal)
		}
		head += " agent conversations"
		if measured {
			if charsRead < charsTotal {
				lb := ""
				if lowerBound {
					lb = "at least "
				}
				head += " (" + n(charsRead) + " of " + lb + n(charsTotal) + " characters)"
			} else {
				head += " (" + n(charsRead) + " characters)"
			}
		}
		parts = append(parts, head)
	} else if len(aa) > 0 {
		p := "No agent conversation was analysed"
		if e := py.Or(py.Get(aa, "error"), py.Get(aa, "note")); py.Truthy(e) {
			p += " (" + py.Str(e) + ")"
		}
		parts = append(parts, p)
	}
	if len(skipped) > 0 {
		items := make([]string, len(skipped))
		for i, s := range skipped {
			items[i] = py.Str(py.Get(s, "agent")) + " (" + py.Str(py.Get(s, "reason")) + ")"
		}
		parts = append(parts, py.Str(int64(len(skipped)))+" agent(s) skipped: "+strings.Join(items, ", "))
	}
	if len(cut) > 0 {
		items := make([]string, len(cut))
		for i, c := range cut {
			items[i] = py.Str(py.Get(c, "source")) + " (" + n(py.Int(py.Get(c, "droppedChars"))) + " characters not shown)"
		}
		parts = append(parts, "evidence cut before the review: "+strings.Join(items, ", "))
	}
	if len(failed) > 0 {
		parts = append(parts, "did not answer: "+strings.Join(failed, ", "))
	}
	sentence := "Coverage: nothing was measured."
	if len(parts) > 0 {
		sentence = "Coverage: " + strings.Join(parts, "; ") + "."
	}

	out := map[string]any{
		"complete":      complete,
		"sentence":      py.Trunc(sentence, 600),
		"agentsSkipped": head(skipped, 30),
		"sourcesCut":    head(cut, 10),
		"sourcesFailed": failed,
	}
	if len(records) > 0 || len(overCap) > 0 {
		out["conversationsRead"], out["conversationsTotal"] = convRead, convTotal
	}
	if measured {
		out["charsRead"], out["charsTotal"], out["charsTotalIsLowerBound"] = charsRead, charsTotal, lowerBound
	}
	return out
}

func head(xs []any, k int) []any {
	if len(xs) > k {
		return xs[:k]
	}
	return xs
}

// Summary is status.summary: the coverage sentence FIRST when anything was cut, then the model's words.
// The sentence goes first because a summary is read from the top and truncated from the bottom. An
// empty result means "no summary" (Python's None).
func Summary(cov map[string]any, modelSummary string) string {
	const limit = 2000
	modelSummary = py.Strip(modelSummary)
	if py.Truthy(cov["complete"]) {
		return py.Trunc(modelSummary, limit)
	}
	s := py.Str(cov["sentence"])
	if modelSummary != "" {
		s += " " + modelSummary
	}
	return py.Trunc(s, limit)
}
