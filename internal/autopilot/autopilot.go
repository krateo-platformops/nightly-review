// Package autopilot reaches the reviewer over A2A, as an authenticated Krateo identity.
//
// ADAPTED FROM alert-troubleshooter's handler, deliberately rather than reinvented: it already solved the
// only genuinely hard part, which is getting past agentgateway. The service's Kubernetes ServiceAccount
// is mapped to a Krateo identity by a serviceaccount.authn.krateo.io CR, authn exchanges that SA's
// projected token for a Krateo JWT, and the JWT rides the A2A call so the agent can reach its
// gateway-gated tools.
//
// THE AGENT IS NEVER GIVEN A WRITE TOOL AND IS NEVER ASKED TO ACT. It returns JSON. Everything that
// touches a repository or the cluster is done afterwards, by code, from validated data.
package autopilot

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/krateo-platformops/nightly-review/internal/env"
	"github.com/krateo-platformops/nightly-review/internal/httpx"
	"github.com/krateo-platformops/nightly-review/internal/logging"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
)

// Configuration.
//
// TWO DIFFERENT CLOCKS, AND CONFLATING THEM IS WHY A RUN COULD OVERRUN ITS WINDOW BY AN HOUR. A
// per-read timeout on a STREAMING response is a silence timeout, not a total: as long as the agent emits
// one event inside it, the client waits forever. The 02:00 run delegated to another agent that was
// still calling tools 90 minutes in, and nothing here stopped reading. A2ATimeout is therefore the TOTAL
// wall-clock budget for one Ask() — enforced in the read loop — and A2AReadTimeout is the separate, much
// shorter allowance for silence.
var (
	AutopilotA2A   = env.Str("AUTOPILOT_A2A_URL", "http://krateo-autopilot.krateo-system.svc:8080/")
	AuthnURL       = env.Str("AUTHN_URL", "")
	SATokenPath    = env.Str("SA_TOKEN_PATH", "/var/run/secrets/krateo/authn/token")
	A2ATimeout     = env.Int("A2A_TIMEOUT", "900")      // total budget for one Ask(), seconds
	A2AReadTimeout = env.Int("A2A_READ_TIMEOUT", "180") // max silence BETWEEN events, seconds
)

// namespace is the stable UUID namespace for this component's context ids.
var namespace = [16]byte{0x6f, 0x1a, 0x1f, 0x4e, 0x0b, 0x1a, 0x4a, 0x2e, 0x9f, 0x7c, 0x2c, 0x1d, 0x5f, 0x0b, 0x9a, 0x31}

// HTTPClient is used for the token exchange and for the A2A stream. The stream has no client timeout:
// its clocks are the read loop's, as above. Connects time out after 30 seconds, as requests'
// timeout=(30, …) did.
var HTTPClient = &http.Client{Transport: &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
	TLSHandshakeTimeout:   30 * time.Second,
	ResponseHeaderTimeout: time.Duration(A2AReadTimeout) * time.Second,
}}

// ServiceJWT exchanges the projected SA token for a Krateo JWT. It returns "" if intra-service auth is
// not configured — the caller then proceeds unauthenticated and the agent simply has fewer tools, which
// is a degraded run, NOT a failed one, and the run status must say which. A variable so a test can stand
// in for authn.
var ServiceJWT = func(ctx context.Context) string {
	if AuthnURL == "" {
		return ""
	}
	if _, err := os.Stat(SATokenPath); err != nil {
		return ""
	}
	tok, err := exchange(ctx)
	if err != nil {
		// Never fatal, and never silent: a degraded run that claims to be a clean one is the failure this
		// codebase keeps relearning.
		logging.Print(ctx, fmt.Sprintf("[authn] service-JWT exchange failed (%s); calling A2A unauthenticated", err))
		return ""
	}
	return tok
}

func exchange(ctx context.Context) (string, error) {
	raw, err := os.ReadFile(SATokenPath)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, py.RStripChars(AuthnURL, "/")+"/serviceaccount/login", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+py.Strip(string(raw)))
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	if err := httpx.RaiseForStatus(resp); err != nil {
		resp.Body.Close()
		return "", err
	}
	text, err := httpx.Text(resp)
	if err != nil {
		return "", err
	}
	body, err := py.LoadsJSON(text, false)
	if err != nil {
		return "", err
	}
	if !py.IsDict(body) {
		return "", py.Errorf("AttributeError", "object has no attribute 'get'")
	}
	if t := py.Get(body, "accessToken"); py.Truthy(t) {
		return py.Str(t), nil
	}
	if t := py.Get(body, "token"); py.Truthy(t) {
		return py.Str(t), nil
	}
	return "", nil
}

// ContextID is one A2A thread PER RUN, not one continuing thread across nights — and, inside a run, one
// per `scope`: the agent-analysis stage asks once per agent, and in one shared thread each agent's
// transcripts would sit in the context of the next agent's analysis (kagent keys the session on this
// id). A continuing thread would let the agent remember what it proposed before — tempting, and wrong
// to rely on: dedup is done deterministically by fingerprint in code, so the agent gets a clean context
// every night and correctness does not depend on its memory.
func ContextID(runName, scope string) string {
	name := "nightly-review:" + runName
	if scope != "" {
		name += ":" + scope
	}
	return uuid5(namespace, name)
}

func uuid5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return formatUUID(u)
}

func uuid4() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return formatUUID(u)
}

func formatUUID(u [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

var fenceRE = pyre.MustCompile("```(?:json)?\\s*(\\{.*?\\})\\s*```", pyre.S)

// ExtractJSON accepts the contract's bare JSON — and a fenced object, because models fence it anyway —
// but never tries to repair malformed JSON. A response we had to guess at is a response we should
// refuse. Objects keep their key order (they are quoted in validation messages).
func ExtractJSON(text string) (any, error) {
	text = py.Strip(text)
	if text == "" {
		return nil, py.Errorf("ValueError", "empty response")
	}
	if m := fenceRE.Search(text); m != nil {
		return py.LoadsJSON(m.Group(1), true)
	}
	rs := []rune(text)
	start, end := -1, -1
	for i, r := range rs {
		if r == '{' {
			start = i
			break
		}
	}
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i] == '}' {
			end = i
			break
		}
	}
	if start == -1 || end <= start {
		return nil, py.Errorf("ValueError", "no JSON object in response")
	}
	return py.LoadsJSON(string(rs[start:end+1]), true)
}

// Usage is token usage as one A2A event reported it.
type Usage map[string]any

// TokenUsage is {inputTokens, outputTokens, totalTokens} from one A2A event's result, or empty if it
// carries none.
//
// THE OLD READER LOOKED FOR `result.usage`, WHICH KAGENT NEVER SENDS, so every ReviewRun on 057 recorded
// zeros — a measurement of nothing, written as if it were one. kagent's python runtime serialises the
// ADK event's usage into `metadata.kagent_usage_metadata` (promptTokenCount / candidatesTokenCount /
// totalTokenCount) on each event that has it, and again on the final status update. The last one seen
// is kept. NO MODEL NAME, because the response carries none.
func TokenUsage(result any) Usage {
	um := py.Get(py.Or(py.Get(result, "metadata"), map[string]any{}), "kagent_usage_metadata")
	if !py.IsDict(um) {
		return Usage{}
	}
	out := Usage{}
	for _, p := range [][2]string{{"promptTokenCount", "inputTokens"}, {"candidatesTokenCount", "outputTokens"},
		{"totalTokenCount", "totalTokens"}} {
		v := py.Get(um, p[0])
		if n, ok := py.AsInt(v); ok {
			out[p[1]] = n
		} else if b, ok := v.(bool); ok { // isinstance(True, int) is True in Python
			if b {
				out[p[1]] = true
			} else {
				out[p[1]] = false
			}
		}
	}
	return out
}

// Ask is one JSON-RPC message/stream turn. It returns (parsed JSON, raw text, usage) — usage is empty
// when the agent reported none, never zeros standing in for "unknown". A variable so a test can stand in
// for the reviewer.
//
// `scope` scopes the A2A thread inside the run (see ContextID); `timeout` (seconds, 0 for the default)
// overrides A2ATimeout for this one call, so a stage with many calls can give each its own share.
//
// THE INSTRUCTIONS TRAVEL IN THE MESSAGE, AS ITS FIRST PART. They used to go in the request's
// `params.metadata.systemPrompt`, which kagent 0.10.1 never reads: its request converter builds the ADK
// turn from `message.parts` alone. So every run until then was answered by a model that had seen NOT ONE
// LINE of the instructions. The contract survived only because the user message renders the schema.
var Ask = func(ctx context.Context, system, userMessage, runName, token, scope string, timeout int) (any, string, Usage, error) {
	return ask(ctx, system, userMessage, runName, token, scope, timeout)
}

func ask(ctx context.Context, system, userMessage, runName, token, scope string, timeout int) (any, string, Usage, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      uuid4(),
		"method":  "message/stream",
		"params": map[string]any{
			"message": map[string]any{
				"role": "user",
				"parts": []any{map[string]any{"kind": "text", "text": "INSTRUCTIONS\n\n" + system},
					map[string]any{"kind": "text", "text": userMessage}},
				"messageId": uuid4(),
				"contextId": ContextID(runName, scope),
			},
		},
	}
	budget := timeout
	if budget == 0 {
		budget = A2ATimeout
	}
	deadline := time.Now().Add(time.Duration(budget) * time.Second)
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, AutopilotA2A, bytes.NewReader(body))
	if err != nil {
		return nil, "", nil, err
	}
	req.Header.Set("content-type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, "", nil, err
	}
	defer resp.Body.Close()
	if err := httpx.RaiseForStatus(resp); err != nil {
		return nil, "", nil, err
	}

	// WHERE THE ANSWER ACTUALLY IS. kagent's A2A executor does not send `result.message.parts`; it sends
	// TaskStatusUpdateEvents carrying `result.status.message.parts`, artifact events carrying
	// `result.artifact.parts`, and a final task snapshot carrying `result.history[]`.
	texts := func(container any) []string {
		var out []string
		for _, p := range py.List(py.Get(py.Or(container, map[string]any{}), "parts")) {
			if py.Get(p, "kind") == "text" && py.Truthy(py.Get(p, "text")) {
				out = append(out, py.Str(py.Get(p, "text")))
			}
		}
		return out
	}

	var candidates []string
	usage := Usage{}
	lastState := ""
	events := 0
	overran := false
	lines := newLineReader(resp.Body, time.Duration(A2AReadTimeout)*time.Second)
	defer lines.stop()
	for {
		line, err := lines.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, "", nil, err
		}
		if time.Now().After(deadline) {
			// Stop READING rather than stop the agent: the task keeps running server-side and its session
			// is still inspectable, but the run gets its window back and says why.
			overran = true
			resp.Body.Close()
			break
		}
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		event, err := py.LoadsJSON(py.Strip(line[5:]), true)
		if err != nil {
			continue
		}
		events++
		if !py.IsDict(event) {
			return nil, "", nil, py.Errorf("AttributeError", "object has no attribute 'get'")
		}
		if e := py.Get(event, "error"); py.Truthy(e) {
			return nil, "", nil, py.Errorf("ValueError", "A2A error: %s", py.Trunc(py.Str(e), 200))
		}
		result := py.Or(py.Get(event, "result"), map[string]any{})
		status := py.Or(py.Get(result, "status"), map[string]any{})
		if s := py.Get(status, "state"); py.Truthy(s) {
			lastState = py.Str(s)
		}
		candidates = append(candidates, texts(py.Get(status, "message"))...)
		candidates = append(candidates, texts(py.Get(result, "artifact"))...)
		candidates = append(candidates, texts(py.Get(result, "message"))...)
		candidates = append(candidates, texts(result)...)
		for _, msg := range py.List(py.Get(result, "history")) {
			if py.Get(msg, "role") != "user" {
				candidates = append(candidates, texts(msg)...)
			}
		}
		if found := TokenUsage(result); len(found) > 0 {
			usage = found
		}
	}

	stateOrNone := lastState
	if stateOrNone == "" {
		stateOrNone = "none"
	}
	// A REFUSAL OR A CRASH MUST NOT LOOK LIKE SILENCE. If the task ended in a terminal non-success state,
	// say so with the state name, even when some text did arrive.
	switch lastState {
	case "failed", "canceled", "rejected", "unknown":
		detail := ""
		if len(candidates) > 0 {
			detail = py.Trunc(candidates[len(candidates)-1], 200)
		}
		msg := "agent task " + lastState
		if detail != "" {
			msg += ": " + detail
		}
		return nil, "", nil, py.Errorf("ValueError", "%s", msg)
	}
	if len(candidates) == 0 {
		if overran {
			return nil, "", nil, py.Errorf("ValueError", "A2A deadline exceeded after %ds with no text in %d events (last state: %s)",
				budget, events, stateOrNone)
		}
		return nil, "", nil, py.Errorf("ValueError", "no text in %d A2A events (last state: %s)", events, stateOrNone)
	}

	// Events repeat: the final snapshot echoes what the status updates already said. Concatenating would
	// splice two JSON objects into one unparseable blob, so try whole candidates — newest first, then the
	// longest — and return the first that parses.
	var ordered []string
	seen := map[string]bool{}
	reversed := make([]string, len(candidates))
	for i, c := range candidates {
		reversed[len(candidates)-1-i] = c
	}
	byLen := append([]string(nil), candidates...)
	sort.SliceStable(byLen, func(i, j int) bool { return py.Len(byLen[i]) > py.Len(byLen[j]) })
	for _, c := range append(reversed, byLen...) {
		if !seen[c] {
			seen[c] = true
			ordered = append(ordered, c)
		}
	}
	var lastErr error
	for _, c := range ordered {
		v, err := ExtractJSON(c)
		if err == nil {
			return v, c, usage, nil
		}
		lastErr = err
	}

	// LAST RESORT, for a long answer streamed as fragments. Joining in arrival order is wrong as a FIRST
	// move (the final snapshot repeats earlier text, and two spliced objects never parse) and right as a
	// last one, because a fragmented answer is otherwise unrecoverable.
	joined := strings.Join(candidates, "")
	v, err := ExtractJSON(joined)
	if err == nil {
		return v, joined, usage, nil
	}
	overrun := ""
	if overran {
		overrun = fmt.Sprintf("A2A deadline exceeded after %ds; ", budget)
	}
	_ = lastErr
	return nil, "", nil, py.Errorf("ValueError", "%sno JSON object in %d candidates nor in their concatenation (%d chars; last error: %s)",
		overrun, len(ordered), py.Len(joined), err)
}

// lineReader yields the stream's lines as requests' iter_lines(decode_unicode=True) did: the body is
// decoded as UTF-8 (invalid bytes become U+FFFD) and split with str.splitlines() semantics — so a raw
// U+2028 or U+0085 inside an event ends a line, exactly as it did in Python. It fails when the server is
// silent for longer than the read timeout, requests' per-read timeout on a streaming response.
type lineReader struct {
	timeout time.Duration
	lines   chan lineOrErr
	done    chan struct{}
}

// stop releases the reading goroutine once the caller is no longer reading.
func (lr *lineReader) stop() { close(lr.done) }

type lineOrErr struct {
	line string
	err  error
}

func newLineReader(r io.Reader, timeout time.Duration) *lineReader {
	lr := &lineReader{timeout: timeout, lines: make(chan lineOrErr), done: make(chan struct{})}
	br := bufio.NewReaderSize(r, 1<<16)
	send := func(l lineOrErr) bool {
		select {
		case lr.lines <- l:
			return true
		case <-lr.done:
			return false
		}
	}
	go func() {
		defer close(lr.lines)
		var cur strings.Builder
		for {
			c, _, err := br.ReadRune()
			if err != nil {
				if cur.Len() > 0 && !send(lineOrErr{line: cur.String()}) {
					return
				}
				send(lineOrErr{err: err})
				return
			}
			switch c {
			case '\r':
				if next, _, err := br.ReadRune(); err == nil && next != '\n' {
					_ = br.UnreadRune()
				}
				fallthrough
			case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
				if !send(lineOrErr{line: cur.String()}) {
					return
				}
				cur.Reset()
			default:
				cur.WriteRune(c)
			}
		}
	}()
	return lr
}

func (lr *lineReader) next() (string, error) {
	timer := time.NewTimer(lr.timeout)
	defer timer.Stop()
	select {
	case l, ok := <-lr.lines:
		if !ok {
			return "", io.EOF
		}
		return l.line, l.err
	case <-timer.C:
		return "", py.Errorf("ConnectionError", "Read timed out. (read timeout=%d)", int(lr.timeout.Seconds()))
	}
}
