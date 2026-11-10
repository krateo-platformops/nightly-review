package autopilot_test

// Parsing the agent's reply (tests/test_response_parsing.py), its token usage
// (test_platform_review_service.py) and the A2A request shape (test_agent_analysis.py). A response we had
// to guess at is a response we should refuse.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	A "github.com/krateo-platformops/nightly-review/internal/autopilot"
	"github.com/krateo-platformops/nightly-review/internal/fake"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

func extract(t *testing.T, s string) any {
	t.Helper()
	v, err := A.ExtractJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	return py.Plain(v)
}

var empty = map[string]any{"proposals": []any{}}

func TestBareJSONIsAccepted(t *testing.T) {
	if !reflect.DeepEqual(extract(t, `{"proposals": []}`), empty) {
		t.Fatal()
	}
}

func TestAFencedObjectIsAcceptedBecauseModelsFenceAnyway(t *testing.T) {
	if !reflect.DeepEqual(extract(t, "here you go\n```json\n{\"proposals\": []}\n```\n"), empty) {
		t.Fatal()
	}
}

func TestProseAroundTheObjectIsTolerated(t *testing.T) {
	if !reflect.DeepEqual(extract(t, "I reviewed it.\n{\"proposals\": []}\nHope that helps."), empty) {
		t.Fatal()
	}
}

func TestMalformedIsRefusedNeverRepaired(t *testing.T) {
	for _, bad := range []string{"", "   ", "no json here", `{"proposals": `, "}{"} {
		if _, err := A.ExtractJSON(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestTheContextIDIsStablePerRunAndDistinctAcrossRuns(t *testing.T) {
	if A.ContextID("rr-1", "") != A.ContextID("rr-1", "") || A.ContextID("rr-1", "") == A.ContextID("rr-2", "") {
		t.Fatal()
	}
}

// endless is a stream that never stops talking. This is the 02:00 run: the agent delegated, kept calling
// tools, and emitted a `working` event well inside any per-read timeout — forever.
type endless struct {
	closed  atomic.Bool
	emitted atomic.Int64
}

func (e *endless) Read(p []byte) (int, error) {
	if e.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	e.emitted.Add(1)
	return copy(p, "data: {\"result\": {\"status\": {\"state\": \"working\"}}}\n"), nil
}

func (e *endless) Close() error { e.closed.Store(true); return nil }

func serve(t *testing.T, body io.ReadCloser, sent *map[string]any) {
	t.Helper()
	saved := A.HTTPClient
	A.HTTPClient = fake.Client(func(r *http.Request) (*http.Response, error) {
		if sent != nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, sent)
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: body, Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() { A.HTTPClient = saved })
}

func lines(ls ...string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(strings.Join(ls, "\n")))
}

func TestAStreamThatNeverEndsIsCutOffByTheTotalBudget(t *testing.T) {
	stream := &endless{}
	serve(t, stream, nil)
	saved := A.A2ATimeout
	A.A2ATimeout = 0
	t.Cleanup(func() { A.A2ATimeout = saved })
	// timeout 0 means "the default", so the default is what is set to zero here, as the Python test does
	_, _, _, err := A.Ask(context.Background(), "sys", "msg", "rr-endless", "", "", 0)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || !strings.Contains(err.Error(), "0s") {
		t.Fatalf("got %v", err)
	}
	if !stream.closed.Load() {
		t.Fatal("the response must be closed, not left dangling")
	}
}

func TestTheReadTimeoutIsSeparateFromTheTotalBudget(t *testing.T) {
	if !(A.A2AReadTimeout < A.A2ATimeout) {
		t.Fatal("two clocks, two knobs")
	}
}

func TestANormalAnswerIsUnaffectedByTheDeadline(t *testing.T) {
	serve(t, lines(`data: {"result": {"status": {"state": "submitted"}}}`,
		`data: {"result": {"status": {"state": "working"}}}`,
		`data: {"result": {"status": {"state": "completed", "message": {"parts": [{"kind": "text", "text": "{\"proposals\": []}"}]}}}}`), nil)
	obj, _, _, err := A.Ask(context.Background(), "sys", "msg", "rr-ok", "", "", 0)
	if err != nil || !reflect.DeepEqual(py.Plain(obj), empty) {
		t.Fatal(obj, err)
	}
}

func TestTokenUsageIsReadWhereKagentActuallyPutsIt(t *testing.T) {
	result := map[string]any{"metadata": map[string]any{"kagent_usage_metadata": map[string]any{
		"promptTokenCount": int64(1200), "candidatesTokenCount": int64(300), "totalTokenCount": int64(1500)}}}
	if got := A.TokenUsage(result); !reflect.DeepEqual(map[string]any(got), map[string]any{"inputTokens": int64(1200),
		"outputTokens": int64(300), "totalTokens": int64(1500)}) {
		t.Fatal(got)
	}
}

func TestNoUsageIsEmptyNotZeros(t *testing.T) {
	if len(A.TokenUsage(map[string]any{"usage": map[string]any{"inputTokens": int64(5)}})) != 0 ||
		len(A.TokenUsage(map[string]any{})) != 0 {
		t.Fatal("zeros were the bug: they read as a measurement")
	}
}

func TestAskReturnsTheUsageFromTheFinalEvent(t *testing.T) {
	serve(t, lines(`data: {"result": {"status": {"state": "working"}, "metadata": {"kagent_usage_metadata": `+
		`{"promptTokenCount": 10, "candidatesTokenCount": 2, "totalTokenCount": 12}}}}`,
		`data: {"result": {"status": {"state": "completed", "message": {"parts": [{"kind": "text", "text": "{\"proposals\": []}"}]}}}}`), nil)
	_, _, usage, err := A.Ask(context.Background(), "sys", "msg", "rr-usage", "", "", 0)
	if err != nil || !reflect.DeepEqual(map[string]any(usage), map[string]any{"inputTokens": int64(10), "outputTokens": int64(2),
		"totalTokens": int64(12)}) {
		t.Fatal(usage, err)
	}
}

func TestTheInstructionsTravelInTheMessageBecauseKagentDropsMetadata(t *testing.T) {
	sent := map[string]any{}
	serve(t, lines(`data: {"result": {"status": {"state": "completed", "message": {"parts": [{"kind": "text", "text": "{\"proposals\": []}"}]}}}}`), &sent)
	if _, _, _, err := A.Ask(context.Background(), "THE RULES", "THE EVIDENCE", "rr-1", "", "analyse/x", 0); err != nil {
		t.Fatal(err)
	}
	params := sent["params"].(map[string]any)
	msg := params["message"].(map[string]any)
	parts := msg["parts"].([]any)
	if !strings.Contains(parts[0].(map[string]any)["text"].(string), "THE RULES") || parts[1].(map[string]any)["text"] != "THE EVIDENCE" {
		t.Fatal(parts)
	}
	if _, has := params["metadata"]; has {
		t.Fatal("metadata reached no model, ever")
	}
	if msg["contextId"] != A.ContextID("rr-1", "analyse/x") || msg["contextId"] == A.ContextID("rr-1", "") {
		t.Fatal(msg["contextId"])
	}
}
