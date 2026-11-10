package analysis_test

// The analyse stage: whole conversations, one agent at a time, and only an assessment comes out
// (tests/test_agent_analysis.py; the folding, redaction-pattern and A2A cases live with the packages
// they test).

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	AN "github.com/krateo-platformops/nightly-review/internal/analysis"
	"github.com/krateo-platformops/nightly-review/internal/autopilot"
	E "github.com/krateo-platformops/nightly-review/internal/evidence"
	"github.com/krateo-platformops/nightly-review/internal/fake"
	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/testutil"
)

var ctx = context.Background()
var window = prompt.Window{From: "2026-09-28T20:00:00+00:00", To: "2026-09-29T20:00:00+00:00"}

// FAKE CREDENTIALS, ASSEMBLED AT RUNTIME, so no literal in this file is one.
var (
	jwt        = strings.Join([]string{"eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ", "eyJzdWIiOiJzeXN0ZW06c2EifQ", "c2lnbmF0dXJlc2lnbmF0dXJl"}, ".")
	tokenValue = "abcdefgh" + "12345"
	promptKey  = "sk1234" + "5678abcdef"
	keyData    = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBd" + strings.Repeat("A", 40)
	v1, v2, v3 = "hunter2" + "hunter2", "abcdefgh" + "1234", "P@ss!w0" + "rd#9x"
)

func set[T any](t *testing.T, p *T, v T) {
	saved := *p
	*p = v
	t.Cleanup(func() { *p = saved })
}

func dumps(v map[string]any) string { b, _ := json.Marshal(v); return string(b) }

// pyEv is kagent-adk append_event: event.model_dump_json(), snake_case, None fields present.
func pyEv(author string, extra map[string]any, parts ...map[string]any) string {
	role := "model"
	if author == "user" {
		role = "user"
	}
	ps := make([]any, len(parts))
	for i, p := range parts {
		ps[i] = p
	}
	ev := map[string]any{"author": author, "content": map[string]any{"role": role, "parts": ps}, "invocation_id": "i",
		"partial": nil, "error_message": nil}
	for k, v := range extra {
		ev[k] = v
	}
	return dumps(ev)
}

// goEv is kagent go/adk AppendEvent: json.Marshal(adk-go session.Event).
func goEv(author string, extra map[string]any, parts ...map[string]any) string {
	ps := make([]any, len(parts))
	for i, p := range parts {
		ps[i] = p
	}
	ev := map[string]any{"Author": author, "Content": map[string]any{"role": "model", "parts": ps}, "ID": "e", "InvocationID": "i",
		"Partial": false}
	for k, v := range extra {
		ev[k] = v
	}
	return dumps(ev)
}

func text(s string) map[string]any { return map[string]any{"text": s} }

func kinds(entries []AN.Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Kind)
	}
	return out
}

func TestThePythonRuntimeReplyCallResultAndErrorAreAllRead(t *testing.T) {
	data := pyEv("k8s_agent", map[string]any{"error_message": "rate limited", "error_code": "429"}, text("Let me look."),
		map[string]any{"function_call": map[string]any{"id": "c1", "name": "k8s_get_resources", "args": map[string]any{"kind": "Pod"}}},
		map[string]any{"function_response": map[string]any{"id": "c1", "name": "k8s_get_resources", "response": map[string]any{"result": "ok"}}})
	author, entries, shape := AN.ReadEvent(data)
	if author != "k8s_agent" || shape != "parsed" || !reflect.DeepEqual(kinds(entries), []string{"text", "call", "result", "error"}) ||
		entries[1].Name != "k8s_get_resources" || !strings.Contains(entries[1].Payload.(string), `"kind": "Pod"`) {
		t.Fatal(author, entries, shape)
	}
}

func TestTheGoRuntimeReplyCallResultAndErrorAreAllRead(t *testing.T) {
	data := goEv("autopilot", map[string]any{"ErrorMessage": "tool timed out", "ErrorCode": "DEADLINE"}, text("Delegating."),
		map[string]any{"functionCall": map[string]any{"id": "c1", "name": "k8s_agent", "args": map[string]any{"request": "list pods"}}},
		map[string]any{"functionResponse": map[string]any{"id": "c1", "name": "k8s_agent", "response": map[string]any{"result": "3 pods"}}})
	author, entries, shape := AN.ReadEvent(data)
	if author != "autopilot" || shape != "parsed" || !reflect.DeepEqual(kinds(entries), []string{"text", "call", "result", "error"}) {
		t.Fatal(author, entries, shape)
	}
}

func TestThoughtsAndPartialsAreNotShown(t *testing.T) {
	if _, _, s := AN.ReadEvent(pyEv("a", nil, map[string]any{"text": "scratch work", "thought": true})); s != "no-content" {
		t.Error(s)
	}
	if _, _, s := AN.ReadEvent(goEv("a", map[string]any{"Partial": true}, text("frag"))); s != "partial" {
		t.Error(s)
	}
	if _, _, s := AN.ReadEvent("not json"); s != "unparseable" {
		t.Error(s)
	}
	if _, _, s := AN.ReadEvent(nil); s != "empty" {
		t.Error(s)
	}
}

// --- REDACTION: replies and tool traffic, before any cut -----------------------------------------

func rendered(author any, entries []AN.Entry) string {
	lines, _, _ := AN.Render(author, entries, false)
	return strings.Join(lines, "\n")
}

func TestAKubeconfigAndTokenInAToolResultNeverReachTheModel(t *testing.T) {
	kubeconfig := "apiVersion: v1\nkind: Config\nusers:\n- name: admin\n  user:\n    client-key-data: " + keyData + "\n    token: " + jwt + "\n"
	_, entries, _ := AN.ReadEvent(goEv("k8s_agent", nil, map[string]any{"functionResponse": map[string]any{
		"name": "k8s_get_resource_yaml", "response": map[string]any{"content": []any{map[string]any{"type": "text", "text": kubeconfig}}}}}))
	out := rendered("k8s_agent", entries)
	if strings.Contains(out, keyData[:40]) || strings.Contains(out, "eyJhbGci") || !strings.Contains(out, "<REDACTED") {
		t.Fatal(out)
	}
}

func TestAPasswordInAnAgentReplyNeverReachesTheModel(t *testing.T) {
	_, entries, _ := AN.ReadEvent(pyEv("installer_agent", nil, text("Log in with password: Sup3rS3cretValue")))
	out := rendered("installer_agent", entries)
	if strings.Contains(out, "Sup3rS3cretValue") || !strings.Contains(out, "password=<REDACTED>") {
		t.Fatal(out)
	}
}

func TestAJWTInToolArgumentsNeverReachesTheModel(t *testing.T) {
	_, entries, _ := AN.ReadEvent(pyEv("autopilot", nil, map[string]any{"function_call": map[string]any{
		"name": "http_get", "args": map[string]any{"headers": map[string]any{"Authorization": "Bearer " + jwt}}}}))
	out := rendered("autopilot", entries)
	if strings.Contains(out, "eyJhbGci") || !strings.Contains(out, "Bearer <REDACTED") {
		t.Fatal(out)
	}
}

func TestAJSONQuotedPasswordInToolArgumentsIsRedacted(t *testing.T) {
	_, entries, _ := AN.ReadEvent(goEv("helm_agent", nil, map[string]any{"functionCall": map[string]any{
		"name": "helm_install", "args": map[string]any{"values": map[string]any{"password": "hunter2hunter2", "token": tokenValue}}}}))
	out := rendered("helm_agent", entries)
	if strings.Contains(out, "hunter2hunter2") || strings.Contains(out, tokenValue) {
		t.Fatal(out)
	}
}

func TestRedactionRunsBeforeTheToolResultCap(t *testing.T) {
	set(t, &AN.MaxToolResultChars, 30)
	_, entries, _ := AN.ReadEvent(goEv("k8s_agent", nil, map[string]any{"functionResponse": map[string]any{"name": "t",
		"response": map[string]any{"result": strings.Repeat("x", 14) + jwt}}}))
	if out := rendered("k8s_agent", entries); strings.Contains(out, "eyJhbG") {
		t.Fatal(out)
	}
}

func TestAToolResultIsCutHardAndTheCutIsCounted(t *testing.T) {
	set(t, &AN.MaxToolResultChars, 50)
	_, entries, _ := AN.ReadEvent(pyEv("a", nil, map[string]any{"function_response": map[string]any{"name": "t",
		"response": map[string]any{"result": strings.Repeat("y", 5000)}}}))
	lines, dropped, _ := AN.Render("a", entries, false)
	if dropped != 4950 || !strings.Contains(lines[0], "…[cut 4950 chars]") || len([]rune(lines[0])) >= 120 {
		t.Fatal(lines, dropped)
	}
}

// --- reading the conversations ------------------------------------------------------------------

func conn(census, rows [][]any) *fake.Conn {
	return &fake.Conn{Answer: func(q string, _ map[string]any) ([][]any, error) {
		switch {
		case strings.Contains(q, "AS delegated"):
			return census, nil
		case strings.Contains(q, "dense_rank"):
			return rows, nil
		}
		return nil, errors.New("unexpected query")
	}}
}

func row(agent string, sn, n int64, data any, inSession int64, source any, length any) []any {
	if length == nil {
		if s, ok := data.(string); ok {
			length = int64(len([]rune(s)))
		} else {
			length = int64(0)
		}
	}
	return []any{agent, sn, source, inSession, n, data, length}
}

const ag = "krateo_system__NS__k8s_agent"

func readConvs(t *testing.T, rows [][]any, next int) (map[string][]*AN.Conversation, map[string]AN.Cuts, *py.OMap) {
	t.Helper()
	cuts := map[string]AN.Cuts{}
	out, shapes, err := AN.ReadConversations(ctx, conn(nil, rows), window, []string{ag}, cuts, next)
	if err != nil {
		t.Fatal(err)
	}
	return out, cuts, shapes
}

func TestConversationsAreNumberedPerRunAndCarryNoIDs(t *testing.T) {
	rows := [][]any{row(ag, 1, 1, pyEv("user", nil, text("why is pod x crashing?")), 2, nil, nil),
		row(ag, 1, 2, pyEv("k8s_agent", nil, text("It is OOMKilled.")), 2, nil, nil),
		row(ag, 2, 1, goEv("user", nil, text("list helm releases")), 1, "agent", nil)}
	out, _, _ := readConvs(t, rows, 7)
	convs := out[ag]
	if convs[0].Ordinal != 7 || convs[1].Ordinal != 8 || !strings.Contains(convs[0].Text, "USER: why is pod x crashing?") ||
		!strings.Contains(convs[1].Text, "PARENT AGENT: list helm releases") || !convs[1].Delegated ||
		convs[1].Facts["unanswered"] != true || convs[0].Facts["unanswered"] != false {
		t.Fatal(convs[0], convs[1])
	}
}

func TestTheMiddleOfALongConversationGivesWayAndSaysSo(t *testing.T) {
	rows := [][]any{row(ag, 1, 1, pyEv("user", nil, text("q")), 50, nil, nil), row(ag, 1, 50, pyEv("k8s_agent", nil, text("a")), 50, nil, nil)}
	out, cuts, _ := readConvs(t, rows, 1)
	if !strings.Contains(out[ag][0].Text, "[… 48 event(s) omitted") || cuts[ag]["messages"] != int64(2) || cuts[ag]["droppedMessages"] != int64(48) {
		t.Fatal(out[ag][0].Text, cuts)
	}
}

func TestTheAgentBudgetStopsFurtherConversationsAndCountsThem(t *testing.T) {
	set(t, &AN.MaxChars, 60)
	rows := [][]any{row(ag, 1, 1, pyEv("user", nil, text(strings.Repeat("a", 40))), 1, nil, nil),
		row(ag, 2, 1, pyEv("user", nil, text(strings.Repeat("b", 40))), 1, nil, nil),
		row(ag, 3, 1, pyEv("user", nil, text(strings.Repeat("c", 40))), 1, nil, nil)}
	out, cuts, _ := readConvs(t, rows, 1)
	if len(out[ag]) != 1 || cuts[ag]["droppedSessions"] != int64(2) || py.Int(cuts[ag]["droppedChars"]) <= 0 {
		t.Fatal(cuts)
	}
}

func TestAnOversizeEventIsNotFetchedAndItsSizeIsCounted(t *testing.T) {
	rows := [][]any{row(ag, 1, 1, pyEv("user", nil, text("q")), 2, nil, nil), row(ag, 1, 2, nil, 2, nil, int64(9_000_000))}
	out, cuts, shapes := readConvs(t, rows, 1)
	oversize, _ := shapes.Get("oversize")
	if !strings.Contains(out[ag][0].Text, "was not read: over maxEventChars") || cuts[ag]["droppedChars"] != int64(9_000_000) || oversize != int64(1) {
		t.Fatal(out[ag][0].Text, cuts)
	}
}

func TestMeasuredFactsComeFromTheEvents(t *testing.T) {
	call := map[string]any{"functionCall": map[string]any{"name": "k8s_get", "args": map[string]any{"n": int64(1)}}}
	errResp := map[string]any{"functionResponse": map[string]any{"name": "k8s_get", "response": map[string]any{
		"content": []any{map[string]any{"text": "forbidden"}}, "isError": true}}}
	var rows [][]any
	for i, d := range []string{goEv("user", nil, text("get it")), goEv("k8s_agent", nil, call), goEv("k8s_agent", nil, errResp),
		goEv("k8s_agent", nil, call), goEv("k8s_agent", nil, call)} {
		rows = append(rows, row(ag, 1, int64(i+1), d, 5, nil, nil))
	}
	out, _, _ := readConvs(t, rows, 1)
	want := map[string]any{"toolCalls": int64(3), "toolErrors": int64(1), "maxRepeatedCall": int64(3), "unanswered": true}
	if !reflect.DeepEqual(out[ag][0].Facts, want) {
		t.Fatal(out[ag][0].Facts)
	}
}

func TestTheSQLSelectsNoIdentityAndNoTask(t *testing.T) {
	final := AN.ConversationsSQL[strings.LastIndex(AN.ConversationsSQL, "SELECT"):]
	final = final[:strings.Index(final, "FROM")]
	if strings.Contains(final, "user_id") || strings.Contains(final, "session_id") {
		t.Fatal(final)
	}
	for _, q := range []string{AN.ConversationsSQL, AN.CensusSQL} {
		if strings.Contains(strings.ReplaceAll(q, "tasks", ""), "task") || !strings.Contains(q, "deleted_at IS NULL") ||
			!strings.Contains(q, ":frm") || !strings.Contains(q, ":to") {
			t.Fatal(q)
		}
	}
}

// --- the prompt the agent runs with today --------------------------------------------------------

func agent(name string, decl map[string]any, annotations map[string]any, typ string) map[string]any {
	if annotations == nil {
		annotations = map[string]any{}
	}
	if decl == nil {
		decl = map[string]any{}
	}
	return map[string]any{"metadata": map[string]any{"namespace": "krateo-system", "name": name, "annotations": annotations},
		"spec": map[string]any{"type": typ, "description": "K8s helper", "declarative": decl}}
}

func cms(m map[string]map[string]any) AN.ReadCM {
	return func(ns, name string) (map[string]any, error) {
		data, ok := m[name]
		if !ok {
			return nil, py.Errorf("RuntimeError", "configmaps %s is forbidden", py.StrRepr(name))
		}
		return map[string]any{"data": data, "metadata": map[string]any{"name": name, "annotations": map[string]any{}}}, nil
	}
}

func TestIncludesResolveFromTheNamedConfigmapAndInlineTextIsKept(t *testing.T) {
	decl := map[string]any{"systemMessage": "{{include \"prompts/k8s_agent\"}}\n\n## Extra\nI am {{ .AgentName }}.",
		"promptTemplate": map[string]any{"dataSources": []any{map[string]any{"alias": "prompts", "kind": "ConfigMap", "name": "krateo-prompts-eng"}}}}
	text, sources, notes, _ := AN.ResolvePrompt(agent("k8s-agent", decl, nil, "Declarative"),
		cms(map[string]map[string]any{"krateo-prompts-eng": {"k8s_agent": "You are the Kubernetes agent. {{ not a template }}"}}))
	if !strings.HasPrefix(text, "You are the Kubernetes agent. {{ not a template }}") || !strings.Contains(text, "I am k8s-agent.") ||
		len(notes) != 0 || !reflect.DeepEqual(sources, []string{"ConfigMap krateo-system/krateo-prompts-eng key k8s_agent",
		"spec.declarative.systemMessage (inline around the includes)"}) {
		t.Fatal(text, sources, notes)
	}
}

func TestWhatCannotBeResolvedIsMarkedAndNoted(t *testing.T) {
	decl := map[string]any{"systemMessage": "{{include \"prompts/gone\"}} tools: {{ .ToolNames }}",
		"promptTemplate": map[string]any{"dataSources": []any{map[string]any{"alias": "prompts", "name": "missing-cm"}}}}
	text, _, notes, _ := AN.ResolvePrompt(agent("k8s-agent", decl, nil, "Declarative"), cms(nil))
	joined := strings.Join(notes, "|")
	if !strings.Contains(text, "[include 'prompts/gone' not resolved]") || !strings.Contains(text, "[template action not resolved: .ToolNames]") ||
		!strings.Contains(joined, "forbidden") || !strings.Contains(joined, "2 template action") {
		t.Fatal(text, notes)
	}
}

func TestASecretBackedPromptIsNeverRead(t *testing.T) {
	called := 0
	text, _, notes, _ := AN.ResolvePrompt(agent("x", map[string]any{"systemMessageFrom": map[string]any{"type": "Secret", "name": "s", "key": "k"}},
		nil, "Declarative"), func(string, string) (map[string]any, error) { called++; return nil, nil })
	if text != "" || called != 0 || !strings.Contains(notes[0], "reads no Secrets") {
		t.Fatal(text, notes)
	}
}

func TestWithoutATemplateTheMessageIsTakenLiterally(t *testing.T) {
	text, sources, _, _ := AN.ResolvePrompt(agent("x", map[string]any{"systemMessage": "Plain {{ .AgentName }}"}, nil, "Declarative"), cms(nil))
	if text != "Plain {{ .AgentName }}" || !reflect.DeepEqual(sources, []string{"spec.declarative.systemMessage"}) {
		t.Fatal(text, sources)
	}
}

func TestADeclaredPromptRepoIsShapeChecked(t *testing.T) {
	for value, want := range map[string]string{"krateo-agentiko/k8s-agent": "krateo-agentiko/k8s-agent",
		"https://github.com/krateo-agentiko/krateo-autopilot.git": "krateo-agentiko/krateo-autopilot",
		"github.com/org/repo/": "org/repo", "../../etc/passwd": "", "https://evil.example/org/repo": "", "": ""} {
		got, _ := AN.PromptRepo(agent("x", nil, map[string]any{"krateo.io/prompt-repo": value}, "Declarative"), nil)
		if got != want {
			t.Errorf("%q -> %q", value, got)
		}
	}
}

// --- what is accepted back: the service counts, and checks every quote ---------------------------

var convs = []*AN.Conversation{
	{Ordinal: 3, Events: 2, Facts: map[string]any{}, Text: "USER: how do I roll back release foo?\nAGENT[helm_agent]: I cannot run helm rollback."},
	{Ordinal: 4, Events: 2, Facts: map[string]any{}, Text: "USER: roll back bar please\nAGENT[helm_agent]: I cannot run helm rollback, sorry."},
}

const promptText = "You are the Helm agent. Never run mutating helm commands.\nAnswer with release status only."

func assessment(over map[string]any) map[string]any {
	base := map[string]any{"summary": "s", "servedWell": "status questions",
		"failurePatterns": []any{map[string]any{"pattern": "refuses rollbacks", "category": "refusal",
			"conversations": []any{int64(3), int64(4), int64(99)}, "count": int64(57),
			"examples": []any{map[string]any{"conversation": int64(3), "excerpt": "I cannot run helm rollback."}}}},
		"promptFindings": []any{map[string]any{"finding": "forbids mutation without a route", "promptExcerpt": "Never run mutating helm commands",
			"evidence": "c3, c4", "suggestedChange": "route rollbacks to the installer", "conversations": []any{int64(3), int64(4)}}}}
	for k, v := range over {
		base[k] = v
	}
	return base
}

func firstFP(over map[string]any) map[string]any {
	fp := map[string]any{}
	for k, v := range assessment(nil)["failurePatterns"].([]any)[0].(map[string]any) {
		fp[k] = v
	}
	for k, v := range over {
		fp[k] = v
	}
	return fp
}

func TestTheCountIsTheServicesNotTheModels(t *testing.T) {
	out, _ := AN.Normalise(assessment(nil), convs, promptText)
	fp := out["failurePatterns"].([]any)[0].(map[string]any)
	if fp["count"] != int64(2) || !reflect.DeepEqual(fp["conversations"], []any{int64(3), int64(4)}) ||
		py.Has(py.GetPath(AN.AssessmentSchema, "properties", "failurePatterns", "items", "properties"), "count") {
		t.Fatal(fp)
	}
}

func TestAnExcerptTheTranscriptDoesNotContainIsDropped(t *testing.T) {
	fp := firstFP(map[string]any{"examples": []any{
		map[string]any{"conversation": int64(3), "excerpt": "The agent said it would never do rollbacks"}, // paraphrase
		map[string]any{"conversation": int64(4), "excerpt": "I cannot run helm rollback, sorry"},          // real
		map[string]any{"conversation": int64(3), "excerpt": "roll back bar please"}}})                     // real, WRONG conversation
	out, unverified := AN.Normalise(assessment(map[string]any{"failurePatterns": []any{fp}}), convs, promptText)
	want := []any{map[string]any{"conversation": int64(4), "excerpt": "I cannot run helm rollback, sorry"}}
	if !reflect.DeepEqual(out["failurePatterns"].([]any)[0].(map[string]any)["examples"], want) || unverified != 2 {
		t.Fatal(out, unverified)
	}
}

func TestAnElidedExcerptNeedsEveryPiece(t *testing.T) {
	if !AN.Found("how do I roll back ... release foo", AN.Norm(convs[0].Text)) ||
		AN.Found("how do I roll back ... release zzz-invented", AN.Norm(convs[0].Text)) {
		t.Fatal()
	}
}

func TestAPatternCitingNothingThatExistsIsDropped(t *testing.T) {
	fp := map[string]any{"pattern": "invented", "category": "loop", "conversations": []any{int64(42)}, "examples": []any{}}
	out, unverified := AN.Normalise(assessment(map[string]any{"failurePatterns": []any{fp}}), convs, promptText)
	if len(out["failurePatterns"].([]any)) != 0 || unverified != 1 {
		t.Fatal(out, unverified)
	}
}

func TestAMisquotedPromptLosesTheQuoteButKeepsTheFinding(t *testing.T) {
	pf := map[string]any{}
	for k, v := range assessment(nil)["promptFindings"].([]any)[0].(map[string]any) {
		pf[k] = v
	}
	pf["promptExcerpt"] = "Always escalate rollbacks to a human"
	out, unverified := AN.Normalise(assessment(map[string]any{"promptFindings": []any{pf}}), convs, promptText)
	f := out["promptFindings"].([]any)[0].(map[string]any)
	if _, has := f["promptExcerpt"]; has || f["count"] != int64(2) || unverified != 1 {
		t.Fatal(f, unverified)
	}
}

func TestModelOutputIsRedactedAndBounded(t *testing.T) {
	fp := firstFP(map[string]any{"pattern": "leaks token " + jwt + " " + strings.Repeat("z", 500)})
	out, _ := AN.Normalise(assessment(map[string]any{"summary": "password: hunter2hunter2 " + strings.Repeat("s", 900),
		"failurePatterns": []any{fp}}), convs, promptText)
	s := out["summary"].(string)
	p := out["failurePatterns"].([]any)[0].(map[string]any)["pattern"].(string)
	if strings.Contains(s, "hunter2hunter2") || len([]rune(s)) > 600 || strings.Contains(p, "eyJhbGci") || len([]rune(p)) > 200 {
		t.Fatal(s, p)
	}
}

func TestAnUnknownCategoryBecomesOtherInsteadOfLosingTheAssessment(t *testing.T) {
	payload := assessment(map[string]any{"failurePatterns": []any{map[string]any{"pattern": "p", "category": "Misrouting!",
		"conversations": []any{int64(3)}}}})
	AN.Lenient(payload)
	if err := jsonschema.Validate(payload, AN.AssessmentSchema); err != nil {
		t.Fatal(err)
	}
	if payload["failurePatterns"].([]any)[0].(map[string]any)["category"] != "other" {
		t.Fatal(payload)
	}
}

// --- the stage: isolation, budgets, and what it records ------------------------------------------

func deployed(names ...string) *fake.API {
	a := fake.NewAPI()
	for _, n := range names {
		a.Agents = append(a.Agents, agent(n, map[string]any{"systemMessage": "You are " + n + "."}, nil, "Declarative"))
	}
	return a
}

type asked struct {
	scope   string
	timeout int
	system  string
	message string
}

func stage(t *testing.T, census, rows [][]any, a *fake.API, ask AN.AskFunc) ([]AN.Assessment, map[string]any, []map[string]any) {
	t.Helper()
	t.Cleanup(fake.UseConn(conn(census, rows)))
	set(t, &E.KagentDBUser, "u")
	set(t, &E.KagentDBPassword, "p")
	return AN.Analyse(ctx, a, fake.ConfigMaps{}, window, "rr-test", "", ask)
}

func key(name string) string { return E.AgentKey("krateo-system/" + name) }

func convRows(name string) [][]any {
	return [][]any{row(key(name), 1, 1, goEv("user", nil, text("question for "+name)), 2, nil, nil),
		row(key(name), 1, 2, goEv(strings.ReplaceAll(name, "-", "_"), nil, text("answer from "+name)), 2, nil, nil)}
}

var good = map[string]any{"summary": "fine", "failurePatterns": []any{}, "promptFindings": []any{}}

func TestOneAgentsFailureIsThatAgentsAlone(t *testing.T) {
	names := []string{"a-agent", "b-agent", "c-agent"}
	var seen []asked
	ask := func(_ context.Context, system, message, run, token, scope string, timeout int) (any, string, autopilot.Usage, error) {
		seen = append(seen, asked{scope: scope, timeout: timeout})
		switch {
		case strings.Contains(scope, "a-agent"):
			return nil, "", nil, py.Errorf("ValueError", "A2A deadline exceeded after 300s")
		case strings.Contains(scope, "b-agent"):
			return map[string]any{"proposals": []any{}}, "{}", autopilot.Usage{}, nil // wrong shape
		}
		return good, "{}", autopilot.Usage{"inputTokens": int64(100), "outputTokens": int64(10), "totalTokens": int64(110)}, nil
	}
	var census, rows [][]any
	for _, n := range names {
		census = append(census, []any{key(n), int64(1), int64(2), int64(0)})
		rows = append(rows, convRows(n)...)
	}
	got, stats, calls := stage(t, census, rows, deployed(names...), ask)
	if len(got) != 1 || got[0]["agent"] != "krateo-system/c-agent" || stats["ok"] != true || stats["queried"] != int64(3) ||
		stats["returned"] != int64(1) {
		t.Fatal(got, stats)
	}
	errs := map[string]string{}
	for _, r := range stats["agents"].([]any) {
		m := r.(map[string]any)
		errs[m["agent"].(string)] = py.Str(py.Or(m["error"], ""))
	}
	if !strings.Contains(errs["krateo-system/a-agent"], "deadline") || !strings.Contains(errs["krateo-system/b-agent"], "ValidationError") ||
		!strings.Contains(stats["note"].(string), "2 of 3 agent(s) not analysed") {
		t.Fatal(errs, stats["note"])
	}
	scopes := map[string]bool{}
	for _, s := range seen {
		scopes[s.scope] = true
		if s.timeout > AN.Timeout {
			t.Fatal(s.timeout)
		}
	}
	if len(scopes) != 3 {
		t.Fatal("a context per agent: one shared thread would carry every transcript into the next call")
	}
	if !reflect.DeepEqual(calls[len(calls)-1], map[string]any{"step": "analyse", "agent": "krateo-system/c-agent",
		"inputTokens": int64(100), "outputTokens": int64(10), "totalTokens": int64(110)}) {
		t.Fatal(calls)
	}
}

func TestEveryAgentFailingMakesTheSourceNotOK(t *testing.T) {
	ask := func(context.Context, string, string, string, string, string, int) (any, string, autopilot.Usage, error) {
		return nil, "", nil, py.Errorf("ValueError", "boom")
	}
	got, stats, _ := stage(t, [][]any{{key("a-agent"), int64(1), int64(2), int64(0)}}, convRows("a-agent"), deployed("a-agent"), ask)
	if len(got) != 0 || stats["ok"] != false || !strings.Contains(stats["error"].(string), "no agent could be analysed") {
		t.Fatal(stats)
	}
}

func failAsk(t *testing.T, why string) AN.AskFunc {
	return func(context.Context, string, string, string, string, string, int) (any, string, autopilot.Usage, error) {
		t.Fatal(why)
		return nil, "", nil, nil
	}
}

func TestAnUnreadableConversationSetIsAFailureNotAQuietNight(t *testing.T) {
	_, stats, _ := stage(t, [][]any{{key("a-agent"), int64(1), int64(1), int64(0)}},
		[][]any{row(key("a-agent"), 1, 1, "not json", 1, nil, nil)}, deployed("a-agent"), failAsk(t, "no call without conversations"))
	if stats["ok"] != false || stats["agents"].([]any)[0].(map[string]any)["error"] != "no readable conversation in the window" {
		t.Fatal(stats)
	}
}

func TestExcludedRetiredAndOverCapAgentsAreRecordedNotRead(t *testing.T) {
	set(t, &AN.MaxAgents, 1)
	set(t, &AN.ExcludeAgents, "*-bench")
	set(t, &E.QuestionsExcludeAgents, "krateo-system/nightly-review-agent")
	census := [][]any{{key("k8s-agent-bench"), int64(9), int64(20), int64(0)}, {key("nightly-review-agent"), int64(8), int64(16), int64(0)},
		{"krateo_system__NS__retired", int64(7), int64(14), int64(0)}, {key("a-agent"), int64(2), int64(4), int64(0)},
		{key("b-agent"), int64(1), int64(2), int64(0)}}
	got, stats, _ := stage(t, census, convRows("a-agent"), deployed("k8s-agent-bench", "nightly-review-agent", "a-agent", "b-agent"),
		func(context.Context, string, string, string, string, string, int) (any, string, autopilot.Usage, error) {
			return good, "{}", autopilot.Usage{}, nil
		})
	reasons := map[string]string{}
	for _, s := range stats["skipped"].([]any) {
		m := s.(map[string]any)
		reasons[m["agent"].(string)] = m["reason"].(string)
	}
	want := map[string]string{"krateo-system/k8s-agent-bench": "excluded", "krateo-system/nightly-review-agent": "excluded",
		"krateo_system__NS__retired": "not deployed", "krateo-system/b-agent": "over maxAgents"}
	if len(got) != 1 || got[0]["agent"] != "krateo-system/a-agent" || !reflect.DeepEqual(reasons, want) ||
		stats["droppedAgents"] != int64(1) || stats["truncated"] != true {
		t.Fatal(reasons, stats)
	}
}

func TestDisabledIsSaidNotSilent(t *testing.T) {
	set(t, &AN.MaxAgents, 0)
	got, stats, calls := AN.Analyse(ctx, nil, nil, window, "rr", "", nil)
	if len(got) != 0 || len(calls) != 0 || stats["empty"] != true || !strings.Contains(stats["note"].(string), "disabled") {
		t.Fatal(stats)
	}
}

func TestNoCredentialsIsNotOK(t *testing.T) {
	set(t, &E.KagentDBUser, "")
	_, stats, _ := AN.Analyse(ctx, nil, nil, window, "rr", "", nil)
	if stats["ok"] != false || !strings.Contains(stats["error"].(string), "not configured") {
		t.Fatal(stats)
	}
}

func TestTheStageBudgetIsEnforcedAndRecorded(t *testing.T) {
	set(t, &AN.TotalSeconds, 10) // below the 30s floor for starting a call
	_, stats, _ := stage(t, [][]any{{key("a-agent"), int64(1), int64(2), int64(0)}}, convRows("a-agent"), deployed("a-agent"),
		failAsk(t, "no time left"))
	if !strings.Contains(stats["agents"].([]any)[0].(map[string]any)["error"].(string), "totalSeconds") {
		t.Fatal(stats)
	}
}

func TestThePromptAndTranscriptReachTheAnalysisCallRedacted(t *testing.T) {
	var got asked
	ask := func(_ context.Context, system, message, run, token, scope string, timeout int) (any, string, autopilot.Usage, error) {
		got = asked{system: system, message: message}
		return good, "{}", autopilot.Usage{}, nil
	}
	a := fake.NewAPI()
	a.Agents = []any{agent("a-agent", map[string]any{"systemMessage": "You are a-agent. Use api_key: " + promptKey}, nil, "Declarative")}
	stage(t, [][]any{{key("a-agent"), int64(1), int64(1), int64(0)}},
		[][]any{row(key("a-agent"), 1, 1, goEv("user", nil, text("my token is "+jwt)), 1, nil, nil)}, a, ask)
	if !strings.Contains(got.message, "You are a-agent.") || strings.Contains(got.message, "eyJhbGci") ||
		strings.Contains(got.message, promptKey) || !strings.Contains(got.system, "THE SERVICE COUNTS") {
		t.Fatal(got.message)
	}
}

// --- what the main review sees ------------------------------------------------------------------

func fullAssessment(name string, over map[string]any) AN.Assessment {
	out, _ := AN.Normalise(assessment(nil), convs, promptText)
	a := AN.Assessment{"agent": name, "conversations": int64(2), "promptSource": "ConfigMap x key y",
		"measured": map[string]any{"withToolErrors": int64(1)}}
	for k, v := range out {
		a[k] = v
	}
	for k, v := range over {
		a[k] = v
	}
	return a
}

func TestTheReviewGetsTheAssessmentNeverTheTranscript(t *testing.T) {
	body := AN.RenderForReview([]AN.Assessment{fullAssessment("krateo-system/helm-agent", nil)}, nil)
	if !strings.Contains(body, "FAILURE [refusal] in 2 conversation(s)") || !strings.Contains(body, "PROMPT FINDING backed by 2") ||
		strings.Contains(body, "roll back bar please") || strings.Contains(body, "how do I roll back") {
		t.Fatal(body)
	}
}

func TestTheReviewBlockIsBounded(t *testing.T) {
	set(t, &AN.CorpusMaxChars, 1500)
	var many []AN.Assessment
	for i := 0; i < 10; i++ {
		many = append(many, fullAssessment("krateo-system/agent-"+string(rune('0'+i)), map[string]any{"summary": strings.Repeat("w", 600)}))
	}
	stats := map[string]any{}
	body := AN.RenderForReview(many, stats)
	if len([]rune(body)) >= 1500+600 || !strings.Contains(body, "agent-analysis cut at 1500") || py.Int(stats["corpusDroppedChars"]) <= 0 {
		t.Fatal(len(body), stats)
	}
}

func TestTheRecordedCutIsExactlyWhatTheBlockLost(t *testing.T) {
	var few []AN.Assessment
	for i := 0; i < 4; i++ {
		few = append(few, fullAssessment("krateo-system/agent-"+string(rune('0'+i)), nil))
	}
	headLen := len([]rune(AN.RenderForReview(nil, nil)))
	full := AN.RenderForReview(few, nil)
	for _, part := range strings.Split(string([]rune(full)[headLen:]), "\n- AGENT") {
		if len([]rune(part)) >= 1200 {
			t.Fatal("a per-agent cut would fire")
		}
	}
	set(t, &AN.CorpusMaxChars, 1500)
	stats := map[string]any{}
	AN.RenderForReview(few, stats)
	if stats["corpusDroppedChars"] != int64(len([]rune(full))-headLen-1500) {
		t.Fatal(stats["corpusDroppedChars"], len([]rune(full))-headLen-1500)
	}
}

func TestAnUncutReviewBlockRecordsNoCut(t *testing.T) {
	stats := map[string]any{}
	AN.RenderForReview([]AN.Assessment{fullAssessment("krateo-system/helm-agent", nil)}, stats)
	if _, has := stats["corpusDroppedChars"]; has {
		t.Fatal(stats)
	}
}

func TestTheReviewIsToldHowManyOfAnAgentsConversationsWereRead(t *testing.T) {
	body := AN.RenderForReview([]AN.Assessment{fullAssessment("krateo-system/helm-agent", map[string]any{"sessions": int64(45),
		"conversations": int64(10)})}, nil)
	if !strings.Contains(body, "10 conversation(s) of 45 in the window analysed") {
		t.Fatal(body)
	}
	line := strings.Split(AN.RenderForReview([]AN.Assessment{fullAssessment("krateo-system/helm-agent",
		map[string]any{"sessions": int64(2)})}, nil), "\n")[1]
	if strings.Contains(strings.Split(line, ";")[0], " of ") {
		t.Fatal(line)
	}
}

func TestADeclaredPromptRepoIsNoLongerADestination(t *testing.T) {
	a := fullAssessment("krateo-system/helm-agent", map[string]any{"promptRepo": "krateo-agentiko/helm-agent", "promptRepoFrom": "Agent annotation x"})
	body := AN.RenderForReview([]AN.Assessment{a}, map[string]any{"ok": true})
	if strings.Contains(body, "krateo-agentiko") || strings.Contains(body, "target.repo") {
		t.Fatal(body)
	}
}

// --- declared -----------------------------------------------------------------------------------

// Every per-agent key and every stats key the stage records is declared in the ReviewRun CRD. The
// Python suite read the keys out of analysis.py's source; this drives the stage down its paths and walks
// what it actually recorded.
func TestEveryPerAgentKeyTheStageRecordsIsDeclared(t *testing.T) {
	ev := py.GetPath(testutil.YAML(t, "helm/nightly-review-crds/templates/reviewrun.crd.yaml"),
		"spec", "versions")
	evidence := py.GetPath(py.List(ev)[0], "schema", "openAPIV3Schema", "properties", "status", "properties", "evidence",
		"additionalProperties", "properties")
	item := py.GetPath(evidence, "agents", "items", "properties")
	set(t, &AN.MaxSessions, 1)
	set(t, &AN.MaxPromptChars, 5)
	names := []string{"a-agent", "b-agent", "c-agent"}
	census := [][]any{{key("a-agent"), int64(3), int64(9), int64(1)}, {key("b-agent"), int64(1), int64(2), int64(0)},
		{key("c-agent"), int64(1), int64(1), int64(0)}, {"krateo_system__NS__gone", int64(1), int64(1), int64(0)}}
	rows := append(convRows("a-agent"), convRows("b-agent")...)
	rows = append(rows, row(key("c-agent"), 1, 1, "not json", 1, nil, nil))
	a := deployed(names...)
	a.Agents[0].(map[string]any)["metadata"].(map[string]any)["annotations"] = map[string]any{"krateo.io/prompt-repo": "o/r"}
	ask := func(_ context.Context, _, _, _, _, scope string, _ int) (any, string, autopilot.Usage, error) {
		if strings.Contains(scope, "b-agent") {
			return nil, "", nil, errors.New("boom")
		}
		return good, "{}", autopilot.Usage{"inputTokens": int64(1), "totalTokens": int64(2)}, nil
	}
	_, stats, _ := stage(t, census, rows, a, ask)
	seen := map[string]bool{}
	for _, r := range stats["agents"].([]any) {
		for k := range r.(map[string]any) {
			seen[k] = true
			if !py.Has(item, k) {
				t.Errorf("per-agent key %q is not declared", k)
			}
		}
	}
	for _, k := range []string{"error", "measured", "promptChars", "promptTruncated", "promptSource", "promptRepo", "tokens",
		"patterns", "promptFindings", "unverifiedExamples", "chars"} {
		if !seen[k] {
			t.Errorf("the stage never recorded %q, so this test does not cover it", k)
		}
	}
	for k := range stats {
		if !py.Has(evidence, k) {
			t.Errorf("stats key %q is not declared", k)
		}
	}
}

// --- the whole call, redacted --------------------------------------------------------------------

func TestNoRawSecretReachesTheAnalysisCall(t *testing.T) {
	envDump := "HOME=/root\nKAGENT_DB_PASSWORD=" + v3 + "\nPGPASSWORD=" + v1 + "\nclient-key-data: " + keyData + "\n"
	var rows [][]any
	for i, d := range []string{
		goEv("user", nil, text("why does it fail? my DB_PASSWORD="+v1+" and token "+jwt)),
		goEv("a_agent", nil, map[string]any{"functionCall": map[string]any{"name": "exec", "args": map[string]any{"cmd": "env",
			"env": map[string]any{"MY_API_KEY": v2}}}}),
		goEv("a_agent", nil, map[string]any{"functionResponse": map[string]any{"name": "exec", "response": map[string]any{
			"content": []any{map[string]any{"text": envDump}}}}}),
		pyEv("a_agent", nil, text("Found it: CLICKHOUSE_PASSWORD="+v2+" is wrong; the password is "+v1+".")),
	} {
		rows = append(rows, row(key("a-agent"), 1, int64(i+1), d, 4, nil, nil))
	}
	a := fake.NewAPI()
	a.Agents = []any{agent("a-agent", map[string]any{"systemMessage": "Connect with PGPASSWORD=" + v3 + "."}, nil, "Declarative")}
	var received []string
	reviewer := func(_ context.Context, system, message, _, _, _ string, _ int) (any, string, autopilot.Usage, error) {
		received = append(received, system+message)
		return good, "{}", autopilot.Usage{}, nil
	}
	_, stats, _ := stage(t, [][]any{{key("a-agent"), int64(1), int64(4), int64(0)}}, rows, a, reviewer)
	if stats["returned"] != int64(1) || len(received) != 1 {
		t.Fatal(stats)
	}
	for _, secret := range []string{v1, v2, v3, jwt[:20], keyData[:40]} {
		if strings.Contains(received[0], secret) {
			t.Errorf("%s… reached the reviewer", secret[:6])
		}
	}
	if !strings.Contains(received[0], "KAGENT_DB_PASSWORD=<REDACTED>") || !strings.Contains(received[0], "HOME=/root") {
		t.Fatal(received[0])
	}
}

var _ kube.ConfigMaps = fake.ConfigMaps{}
