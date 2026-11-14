package autopilot_test

// Parsing the agent's reply (tests/test_response_parsing.py), its token usage
// (test_platform_review_service.py) and the A2A request shape (test_agent_analysis.py). A response we had
// to guess at is a response we should refuse.

import (
	"context"
	"encoding/json"
	"errors"
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

// The Go runtime (kagent 0.10.1 golang-adk) names the key adk_usage_metadata and, through its OpenAI provider,
// reports no total. The total stays absent rather than being summed here: it is what the agent reported.
func TestTokenUsageIsReadWhereTheGoRuntimePutsIt(t *testing.T) {
	result := map[string]any{"metadata": map[string]any{"adk_usage_metadata": map[string]any{
		"promptTokenCount": int64(111), "candidatesTokenCount": int64(22)}}}
	if got := A.TokenUsage(result); !reflect.DeepEqual(map[string]any(got), map[string]any{"inputTokens": int64(111),
		"outputTokens": int64(22)}) {
		t.Fatal(got)
	}
}

// The shape measured from golang-adk on message/stream: usage rides the working event that carries the model's
// final turn; the artifact and the final completed status carry none, and must not erase it.
func TestAskKeepsTheGoRuntimesUsageAcrossTheFinalEvents(t *testing.T) {
	serve(t, lines(`data: {"result": {"kind": "status-update", "status": {"state": "working"}, "metadata": {"adk_partial": true}}}`,
		`data: {"result": {"kind": "status-update", "status": {"state": "working", "message": {"parts": [{"kind": "text", "text": "{\"proposals\": []}"}]}}, `+
			`"metadata": {"adk_usage_metadata": {"promptTokenCount": 111, "candidatesTokenCount": 22}}}}`,
		`data: {"result": {"kind": "artifact-update", "artifact": {"parts": [{"kind": "text", "text": "{\"proposals\": []}"}]}}}`,
		`data: {"result": {"kind": "status-update", "final": true, "status": {"state": "completed"}, "metadata": {"adk_app_name": "x"}}}`), nil)
	_, _, usage, err := A.Ask(context.Background(), "sys", "msg", "rr-go-usage", "", "", 0)
	if err != nil || !reflect.DeepEqual(map[string]any(usage), map[string]any{"inputTokens": int64(111), "outputTokens": int64(22)}) {
		t.Fatal(usage, err)
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

// rr-20261113-0911, reduced. The evidence we send embeds a JSON object of its own; the model's final
// reply is JSON with ONE invalid escape. The old reader fell back to our echoed message, parsed the
// evidence, and reported "no proposals array" with an excerpt of our own prompt.
const evidenceMsg = "Review window: 2026-11-12 .. 2026-11-13 (UTC)\nSources that answered: clickhouse\n" +
	`{"source": "clickhouse", "rows": [{"service": "x", "n": 3}]}`

func sse(event map[string]any) string {
	b, _ := json.Marshal(event)
	return "data: " + string(b)
}

func status(state, role, text string) map[string]any {
	msg := map[string]any{"parts": []any{map[string]any{"kind": "text", "text": text}}}
	if role != "" {
		msg["role"] = role
	}
	return map[string]any{"result": map[string]any{"status": map[string]any{"state": state, "message": msg}}}
}

func TestTheRequestEchoedBackIsNeverTheAnswer(t *testing.T) {
	badReply := `{"summary": "s", "proposals": [{"evidence": "matched a\.b in the log"}]}`
	serve(t, lines(
		sse(status("working", "user", evidenceMsg)),
		sse(status("completed", "agent", badReply))), nil)
	obj, raw, _, err := A.Ask(context.Background(), "sys", evidenceMsg, "rr-echo", "", "", 0)
	if err == nil {
		t.Fatalf("the echoed request was taken as the answer: %v (raw begins %q)", py.Plain(obj), py.Trunc(raw, 40))
	}
	if !strings.Contains(err.Error(), "not valid JSON") || !strings.Contains(strings.ToLower(err.Error()), "escape") {
		t.Fatalf("the error must be the reply's own parse error, got: %v", err)
	}
}

func TestAnEchoWithoutARoleIsStillNotTheAnswer(t *testing.T) {
	// The same echo arriving as an artifact with no role: matched by its text, not its role.
	echo := map[string]any{"result": map[string]any{"artifact": map[string]any{
		"parts": []any{map[string]any{"kind": "text", "text": evidenceMsg}}}}}
	serve(t, lines(sse(echo), sse(status("completed", "agent", `{"proposals": [`))), nil)
	if obj, _, _, err := A.Ask(context.Background(), "sys", evidenceMsg, "rr-echo2", "", "", 0); err == nil {
		t.Fatalf("an unroled echo of the request was taken as the answer: %v", py.Plain(obj))
	}
}

func TestAValidReplyAfterTheEchoIsTheAnswer(t *testing.T) {
	serve(t, lines(
		sse(status("working", "user", evidenceMsg)),
		sse(status("completed", "agent", `{"proposals": []}`))), nil)
	obj, _, _, err := A.Ask(context.Background(), "sys", evidenceMsg, "rr-echo3", "", "", 0)
	if err != nil || !reflect.DeepEqual(py.Plain(obj), empty) {
		t.Fatal(obj, err)
	}
}

// THROUGH THE AGENT GATEWAY. The agents' NetworkPolicy admits an agent's port only from the kagent
// controller and the gateway, so the reviewer is reached through the gateway, which routes by
// `x-kagent-host` and admits a sub-agent route only with a Krateo JWT.

// gatewayAt stands in for the gateway, recording each request it receives.
func gatewayAt(t *testing.T, host string) *[]*http.Request {
	t.Helper()
	savedHost, savedClient := A.AutopilotA2AHost, A.HTTPClient
	A.AutopilotA2AHost = host
	got := &[]*http.Request{}
	A.HTTPClient = fake.Client(func(r *http.Request) (*http.Response, error) {
		*got = append(*got, r)
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}, Request: r,
			Body: lines(`data: {"result": {"status": {"state": "completed", "message": {"parts": [{"kind": "text", "text": "{\"proposals\": []}"}]}}}}`)}, nil
	})
	t.Cleanup(func() { A.AutopilotA2AHost, A.HTTPClient = savedHost, savedClient })
	return got
}

func TestTheGatewayIsToldWhichAgentAndWhoIsAsking(t *testing.T) {
	got := gatewayAt(t, "nightly-review-agent.krateo-system")
	if _, _, _, err := A.Ask(context.Background(), "sys", "msg", "rr-gw", "service-jwt", "", 0); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("%d requests", len(*got))
	}
	h := (*got)[0].Header
	if h.Get("x-kagent-host") != "nightly-review-agent.krateo-system" || h.Get("Authorization") != "Bearer service-jwt" {
		t.Fatal(h)
	}
}

func TestWithoutAServiceJWTTheGatewayIsNeverCalled(t *testing.T) {
	got := gatewayAt(t, "nightly-review-agent.krateo-system")
	_, _, _, err := A.Ask(context.Background(), "sys", "msg", "rr-gw", "", "", 0)
	if !errors.Is(err, A.ErrGatewayNeedsToken) || !strings.Contains(err.Error(), "config.authnUrl") {
		t.Fatalf("got %v", err)
	}
	if len(*got) != 0 {
		t.Fatal("a request the gateway can only refuse must not be sent")
	}
}

func TestADirectURLGetsNoRoutingHeaderAndNeedsNoToken(t *testing.T) {
	got := gatewayAt(t, "")
	if _, _, _, err := A.Ask(context.Background(), "sys", "msg", "rr-direct", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || (*got)[0].Header.Get("x-kagent-host") != "" || (*got)[0].Header.Get("Authorization") != "" {
		t.Fatal((*got)[0].Header)
	}
}
