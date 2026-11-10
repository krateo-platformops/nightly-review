package proposals_test

// The trust boundary, asserted by exercising it (tests/test_trust_boundary.py, test_redact_key_names.py,
// and the redaction, fingerprint, subject and alert-kind cases of test_review_bookkeeping.py,
// test_platform_review_service.py and test_agent_analysis.py).
//
// Everything here is a control that stands between attacker-influenceable text and a pull request. A
// control nobody runs is a comment. Credential-shaped values are assembled from fragments at runtime, so
// the repository's secret scanner sees no literal credential.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/krateo-platformops/nightly-review/internal/jsonschema"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	P "github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

func p(over map[string]any) map[string]any {
	base := map[string]any{
		"kind": "Alert", "subject": "svc/some-signal", "title": "t", "rationale": "r", "confidence": "medium",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s", "observedCount": int64(9)},
			map[string]any{"source": "clickhouse", "summary": "s2", "observedCount": int64(4)}},
		"target": map[string]any{"repo": "org/allowed", "path": "p.yaml"},
		"change": map[string]any{"format": "yaml", "content": "a: 1"},
	}
	for k, v := range over {
		base[k] = v
	}
	return base
}

func noop(any) error { return nil }

func batch(t *testing.T, items []any, itemCheck P.Check) ([]map[string]any, []string) {
	t.Helper()
	kept, notes, err := P.ValidateBatch(map[string]any{"proposals": items}, noop, itemCheck)
	if err != nil {
		t.Fatal(err)
	}
	return kept, notes
}

func fp(t *testing.T, v map[string]any) string {
	t.Helper()
	f, err := P.Fingerprint(v)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func anyHas(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// --- redaction ---------------------------------------------------------------------------------

func TestSecretsAreScrubbedWhereverTheyAppear(t *testing.T) {
	for _, c := range []struct{ secret, marker string }{
		{"eyJ" + "hbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.bbb", "<REDACTED-JWT>"},
		{"AKIA" + "IOSFODNN7EXAMPLE", "<REDACTED-AWS-KEY-ID>"},
		{"ghp_" + "abcdefghijklmnopqrstuvwxyz0123", "<REDACTED-GITHUB-PAT>"},
		{"Bearer " + "abcdefghijklmnopqrstuvwxyz", "Bearer <REDACTED>"},
	} {
		out := P.Redact(map[string]any{"rationale": c.secret, "nested": []any{map[string]any{"summary": c.secret}}}).(map[string]any)
		r := out["rationale"].(string)
		if !strings.Contains(r, c.marker) || strings.Contains(r, c.secret) {
			t.Errorf("%q -> %q", c.secret, r)
		}
		if !strings.Contains(out["nested"].([]any)[0].(map[string]any)["summary"].(string), c.marker) {
			t.Errorf("nested %q not redacted", c.secret)
		}
	}
}

func TestRedactionReachesEveryFieldOfARealProposal(t *testing.T) {
	kept, notes := batch(t, []any{p(map[string]any{"rationale": "token eyJ" + "hbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaa.ccc"})}, nil)
	b, _ := json.Marshal(kept)
	if strings.Contains(string(b), "eyJ") || !anyHas(notes, "redacted") {
		t.Fatalf("kept=%s notes=%v", b, notes)
	}
}

// --- confidence --------------------------------------------------------------------------------
// These assert the OPPOSITE of the removed cap (#14): confidence passes through untouched, because the
// service does not verify it and must not appear to.

func TestConfidencePassesThroughUntouchedEvenOnOneObservation(t *testing.T) {
	kept, notes := batch(t, []any{p(map[string]any{"confidence": "high",
		"evidence": []any{map[string]any{"source": "kagent-sessions", "summary": "once", "observedCount": int64(1)}}})}, nil)
	if kept[0]["confidence"] != "high" || anyHas(notes, "capped") {
		t.Fatal(kept, notes)
	}
}

func TestAFabricatedObservedcountCannotBeWhatEarnsHigh(t *testing.T) {
	kept, notes := batch(t, []any{p(map[string]any{"confidence": "high",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s", "observedCount": int64(900)}}})}, nil)
	if kept[0]["confidence"] != "high" || anyHas(notes, "capped") {
		t.Fatal(kept, notes)
	}
}

// --- fingerprint -------------------------------------------------------------------------------

func TestRewordingTheRationaleDoesNotChangeTheFingerprint(t *testing.T) {
	if fp(t, p(map[string]any{"rationale": "because X"})) != fp(t, p(map[string]any{"rationale": "a completely different explanation"})) {
		t.Fatal("fingerprint moved with the prose")
	}
}

func TestTrailingWhitespaceAndBlankLinesDoNotChangeIt(t *testing.T) {
	a := fp(t, p(map[string]any{"change": map[string]any{"format": "yaml", "content": "a: 1\nb: 2"}}))
	b := fp(t, p(map[string]any{"change": map[string]any{"format": "yaml", "content": "a: 1  \n\n\nb: 2   "}}))
	if a != b {
		t.Fatal("whitespace changed the fingerprint")
	}
}

func TestADifferentTargetIsADifferentProposal(t *testing.T) {
	if fp(t, p(nil)) == fp(t, p(map[string]any{"target": map[string]any{"repo": "org/allowed", "path": "other.yaml"}})) {
		t.Fatal("a different target fingerprinted the same")
	}
}

// --- batch semantics ---------------------------------------------------------------------------

func TestAnEmptyProposalListIsValidAndNotAnError(t *testing.T) {
	kept, notes := batch(t, []any{}, nil)
	if len(kept) != 0 || len(notes) != 0 {
		t.Fatal(kept, notes)
	}
}

func TestANonObjectResponseIsRefusedWhole(t *testing.T) {
	_, _, err := P.ValidateBatch([]any{"not", "an", "object"}, noop, nil)
	if _, ok := err.(*P.Refused); !ok {
		t.Fatalf("want Refused, got %v", err)
	}
}

func TestAnUnexpectedTargetIsKeptVerbatimAndNeverRewritten(t *testing.T) {
	kept, _ := batch(t, []any{p(nil), p(map[string]any{"target": map[string]any{"repo": "somewhere/unexpected", "path": "x.yaml"}}), p(nil)}, nil)
	var repos []string
	for _, k := range kept {
		repos = append(repos, k["target"].(map[string]any)["repo"].(string))
	}
	if !reflect.DeepEqual(repos, []string{"org/allowed", "somewhere/unexpected", "org/allowed"}) {
		t.Fatal(repos)
	}
}

func TestTheShippedDefaultStillProducesSomethingToRead(t *testing.T) {
	kept, notes := batch(t, []any{p(nil), p(map[string]any{"title": "another"})}, nil)
	if len(kept) != 2 || anyHas(notes, "REFUSED") {
		t.Fatal(kept, notes)
	}
	for _, k := range kept {
		if k["fingerprint"] == "" {
			t.Fatal("no fingerprint")
		}
	}
}

func TestABadItemIsDroppedAndItsSiblingsSurvive(t *testing.T) {
	item := func(v any) error { return jsonschema.Validate(v, prompt.ItemSchema) }
	good, bad := p(nil), p(map[string]any{"confidence": "very high"})
	kept, notes := batch(t, []any{good, bad, p(nil)}, item)
	if len(kept) != 2 || !strings.HasPrefix(notes[0], "DROPPED") {
		t.Fatal(kept, notes)
	}
}

// --- env-style key names (test_redact_key_names.py) -----------------------------------------------

var (
	v     = "s3" + "cret" + "Val" + "ue9" // 12 chars, has a digit, no literal in the source
	punct = "s3" + "cret!" + "va" + "lue" // punctuation must not stop the redaction halfway
)

func TestAnEnvStyleKeyIsRedacted(t *testing.T) {
	for _, line := range []string{"DB_PASSWORD=" + v, "PGPASSWORD=" + v, "MY_API_KEY=" + v, "CLICKHOUSE_PASSWORD=" + v,
		"export KAGENT_DB_PASSWORD='" + v + "'", "db_password: " + v, `{"PGPASSWORD": "` + v + `"}`,
		`{"db_access_token": "` + v + `"}`, "KAGENT_DB_PASSWORD=" + punct} {
		out := P.RedactString(line)
		if strings.Contains(out, v) || strings.Contains(out, punct) || strings.Contains(out, "cret") || !strings.Contains(out, "<REDACTED>") {
			t.Errorf("%q -> %q", line, out)
		}
	}
}

func TestAnEnvDumpRedactsEverySecretAndKeepsTheRest(t *testing.T) {
	dump := strings.Join([]string{"HOME=/root", "KAGENT_DB_PASSWORD=" + v, "KAGENT_DB_HOST=kagent-postgresql",
		"CLICKHOUSE_PASSWORD=" + punct, "OPENAI_API_KEY=" + v}, "\n")
	out := P.RedactString(dump)
	if strings.Contains(out, "cret") || !strings.Contains(out, "HOME=/root") || !strings.Contains(out, "KAGENT_DB_HOST=kagent-postgresql") ||
		strings.Count(out, "<REDACTED>") != 3 {
		t.Fatal(out)
	}
}

func TestProseAboutPasswordsSurvives(t *testing.T) {
	for _, s := range []string{"How do I reset my password?", "set the password: see docs", "tokens used: 14518"} {
		if got := P.RedactString(s); got != s {
			t.Errorf("%q -> %q", s, got)
		}
	}
}

func TestATokenNamedKeyIsRedactedWhateverTheValueLooksLike(t *testing.T) {
	for _, line := range []string{"TARGET_CHECK_TOKEN=" + v, "GH_TOKEN=" + v, "export GITHUB_TOKEN='" + v + "'", "aws_secret_key: " + v} {
		out := P.RedactString(line)
		if strings.Contains(out, v) || !strings.Contains(out, "<REDACTED>") {
			t.Errorf("%q -> %q", line, out)
		}
	}
}

func TestTokenCountsAndProseSurvive(t *testing.T) {
	for _, s := range []string{"tokens used: 14518", "max_tokens=4096", `"totalTokens": 221497`, "the token is required"} {
		if got := P.RedactString(s); got != s {
			t.Errorf("%q -> %q", s, got)
		}
	}
}

// --- prose and identifiers (test_agent_analysis.py) ----------------------------------------------

var (
	prosePW, proseKey = "Qu3stion" + "Passw0rd", "AbCdEf" + "123456789"
	v1, v2, v3        = "hunter2" + "hunter2", "abcdefgh" + "1234", "P@ss!w0" + "rd#9x"
)

func TestAPasswordTypedInProseIsRedacted(t *testing.T) {
	for _, c := range []struct{ text, secret string }{
		{"install the portal; my password is " + prosePW, prosePW},
		{"The admin password was 'hunter2hunter2'.", "hunter2hunter2"},
		{"your api key is " + proseKey, proseKey},
	} {
		if strings.Contains(P.RedactString(c.text), c.secret) {
			t.Errorf("%q survived", c.text)
		}
	}
}

func TestProseRedactionLeavesOrdinarySentencesAlone(t *testing.T) {
	s := "The password is required and the token is refreshed hourly."
	if P.RedactString(s) != s {
		t.Fatal(P.RedactString(s))
	}
}

func TestAnIdentifierContainingASecretWordIsRedacted(t *testing.T) {
	for _, c := range []struct{ text, secret string }{
		{"password=" + v1, v1}, {"DB_PASSWORD=" + v1, v1}, {"PGPASSWORD=" + v1, v1}, {"MY_API_KEY=" + v2, v2},
		{"CLICKHOUSE_PASSWORD=" + v2, v2}, {"export KAGENT_DB_PASSWORD='" + v3 + "'", v3}, {`{"PGPASSWORD": "` + v1 + `"}`, v1},
		{"spec:\n  db_password: " + v2 + "\n", v2}, {"clientSecret: " + v1, v1}, {"ADMIN_PASSWORD_B64=" + v2, v2},
		{`{"apiKeyValue": "` + v1 + `"}`, v1},
	} {
		out := P.RedactString(c.text)
		if strings.Contains(out, c.secret) || !strings.Contains(out, "<REDACTED>") {
			t.Errorf("%q -> %q", c.text, out)
		}
	}
}

func TestAnEnvDumpLosesEverySecretAndKeepsEverythingElse(t *testing.T) {
	dump := strings.Join([]string{"HOME=/home/app", "KAGENT_DB_PASSWORD=" + v3, "PGPASSWORD=" + v1, "OPENAI_API_KEY=" + v2,
		"LOG_LEVEL=debug", "KAGENT_DB_HOST=kagent-postgresql"}, "\n")
	out := P.RedactString(dump)
	for _, s := range []string{v1, v2, v3} {
		if strings.Contains(out, s) {
			t.Fatal(out)
		}
	}
	for _, keep := range []string{"HOME=/home/app", "LOG_LEVEL=debug", "KAGENT_DB_HOST=kagent-postgresql", "KAGENT_DB_PASSWORD=<REDACTED>"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("%q lost: %s", keep, out)
		}
	}
}

func TestOrdinaryProseAboutPasswordsIsLeftAlone(t *testing.T) {
	for _, s := range []string{"How do I reset my password?", "The password is required and the token is refreshed hourly.",
		"Rotate the DB_PASSWORD secret, then restart the pod.", "password: see below",
		"Please update your database_password immediately afterwards."} {
		if got := P.RedactString(s); got != s {
			t.Errorf("%q -> %q", s, got)
		}
	}
}

// --- the bookkeeping (test_review_bookkeeping.py) -----------------------------------------------

func prop(content string, over map[string]any) map[string]any {
	out := map[string]any{"kind": "Documentation", "title": "t", "rationale": "r", "confidence": "low",
		"evidence": []any{}, "target": map[string]any{"repo": "krateo-platformops/installer", "path": "README.md"},
		"change": map[string]any{"format": "yaml", "content": content}}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func TestRedactionCountReportsHowManyNotMerelyWhether(t *testing.T) {
	one := map[string]any{"a": "token: " + strings.Repeat("A", 60)}
	three := map[string]any{"a": "token: " + strings.Repeat("A", 60), "b": "ghp_" + strings.Repeat("b", 30), "c": "eyJ" + strings.Repeat("c", 40)}
	if P.RedactionCount(one, P.Redact(one)) != 1 || P.RedactionCount(three, P.Redact(three)) != 3 {
		t.Fatal(P.RedactionCount(one, P.Redact(one)), P.RedactionCount(three, P.Redact(three)))
	}
}

func TestRedactionCountIsZeroWhenNothingFired(t *testing.T) {
	clean := map[string]any{"a": "nothing secret here"}
	if P.RedactionCount(clean, P.Redact(clean)) != 0 {
		t.Fatal("counted a redaction that did not fire")
	}
}

func TestRedactionCountIsAnIntNotABool(t *testing.T) {
	var n any = P.RedactionCount(map[string]any{"a": "x"}, map[string]any{"a": "x"})
	if _, ok := n.(int); !ok {
		t.Fatalf("%T", n)
	}
}

func TestARewordedCommentIsTheSameSuggestion(t *testing.T) {
	if fp(t, prop("# bump the replica count\nreplicas: 3\n", nil)) != fp(t, prop("# increase replicas to three\nreplicas: 3\n", nil)) {
		t.Fatal()
	}
}

func TestReorderedYAMLKeysAreTheSameSuggestion(t *testing.T) {
	if fp(t, prop("replicas: 3\nimage: nginx\n", nil)) != fp(t, prop("image: nginx\nreplicas: 3\n", nil)) {
		t.Fatal()
	}
}

func TestAGenuinelyDifferentChangeIsADifferentSuggestion(t *testing.T) {
	if fp(t, prop("replicas: 3\n", nil)) == fp(t, prop("replicas: 4\n", nil)) {
		t.Fatal()
	}
}

func TestTheSameBodyAimedAtADifferentFileIsADifferentSuggestion(t *testing.T) {
	a := prop("replicas: 3\n", map[string]any{"target": map[string]any{"repo": "krateo-platformops/installer", "path": "a.yaml"}})
	b := prop("replicas: 3\n", map[string]any{"target": map[string]any{"repo": "krateo-platformops/installer", "path": "b.yaml"}})
	if fp(t, a) == fp(t, b) {
		t.Fatal()
	}
}

func tk(t *testing.T, v map[string]any) string {
	k, err := P.TargetKey(v)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func classify(t *testing.T, v map[string]any, byFP map[string]string, byTarget map[string]P.Ref, bySubject map[string][]P.Ref,
	decided map[string]string) P.Classification {
	t.Helper()
	c, err := P.Classify(v, byFP, byTarget, bySubject, decided)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAChangedProposalForTheSameTargetSupersedesRatherThanDuplicates(t *testing.T) {
	old, nw := prop("replicas: 3\n", nil), prop("replicas: 5\n", nil)
	index := map[string]P.Ref{tk(t, old): {Fingerprint: fp(t, old), Name: "p-old"}}
	if c := classify(t, nw, map[string]string{}, index, nil, nil); c.Action != "supersede" || !reflect.DeepEqual(c.Priors, []string{"p-old"}) {
		t.Fatal(c)
	}
}

func TestAnIdenticalProposalIsDeduplicatedNotSuperseded(t *testing.T) {
	old := prop("replicas: 3\n", nil)
	byFP := map[string]string{fp(t, old): "p-old"}
	index := map[string]P.Ref{tk(t, old): {Fingerprint: fp(t, old), Name: "p-old"}}
	if c := classify(t, old, byFP, index, nil, nil); c.Action != "dedup" || c.Name != "p-old" {
		t.Fatal(c)
	}
}

func TestAnUnseenProposalIsNew(t *testing.T) {
	if c := classify(t, prop("replicas: 3\n", nil), map[string]string{}, map[string]P.Ref{}, nil, nil); c.Action != "new" || c.Priors != nil {
		t.Fatal(c)
	}
}

func TestASecretInAnUnusableResponseIsRedactedBeforeItIsStored(t *testing.T) {
	raw := "I suggest using token ghp_" + strings.Repeat("a", 30) + " and eyJ" + strings.Repeat("b", 40)
	out := P.RedactString(raw)
	if strings.Contains(out, "ghp_") || strings.Contains(out, "eyJ") || !strings.Contains(out, "<REDACTED-GITHUB-PAT>") ||
		!strings.Contains(out, "<REDACTED-JWT>") {
		t.Fatal(out)
	}
}

func TestTheDenylistCoversTheFamiliesItWasMissing(t *testing.T) {
	for _, c := range []struct{ raw, marker string }{
		{"gl" + "pat-" + strings.Repeat("a", 24), "<REDACTED-GITLAB-PAT>"},                        // gitleaks:allow
		{"xo" + "xb-" + strings.Repeat("1", 12) + "-" + "abcdefghijkl", "<REDACTED-SLACK-TOKEN>"}, // gitleaks:allow
		{"AI" + "za" + strings.Repeat("B", 35), "<REDACTED-GOOGLE-API-KEY>"},                      // gitleaks:allow
		{"api" + "_key=" + "abcd1234efgh", "<REDACTED>"},                                          // gitleaks:allow
		{"client" + "_secret: " + "verysecretvalue123", "<REDACTED>"},                             // gitleaks:allow
	} {
		if !strings.Contains(P.RedactString(c.raw), c.marker) {
			t.Errorf("%q survived redaction", c.raw[:20])
		}
	}
	secret := "s3cret" + "pw" // gitleaks:allow
	u := P.RedactString("postgres://user:" + secret + "@db.internal:5432/x")
	if strings.Contains(u, secret) || !strings.Contains(u, "db.internal") {
		t.Fatal(u)
	}
}

// --- subject (test_platform_review_service.py) ----------------------------------------------------

func TestOneFindingTypedManyWaysNormalisesToOneSubject(t *testing.T) {
	for raw, want := range map[string]string{
		"snowplow/subjectaccessreview-unauthorized":             "snowplow/subjectaccessreview-unauthorized",
		"Snowplow/SubjectAccessReview Unauthorized":             "snowplow/subject-access-review-unauthorized",
		"installer-chart-inspector:RBAC generation HTTP 500":    "installer-chart-inspector/rbac-generation-http-500",
		"rest-dynamic-controller/CannotObserveExternalResource": "rest-dynamic-controller/cannot-observe-external-resource",
		"  kagent / agent never used  ":                         "kagent/agent-never-used",
		"a/b/c":                                                 "a/b-c",
	} {
		if got, _ := P.NormaliseSubject(raw); got != want {
			t.Errorf("%q -> %q, want %q", raw, got, want)
		}
	}
}

func TestTheSameEventReasonMeetsItselfInCamelAndKebab(t *testing.T) {
	a, _ := P.NormaliseSubject("x/CannotObserveExternalResource")
	b, _ := P.NormaliseSubject("x/cannot-observe-external-resource")
	if a != b {
		t.Fatal(a, b)
	}
}

func TestAnUnusableSubjectIsNoneNotAGuess(t *testing.T) {
	for _, raw := range []any{nil, int64(7), "", "no-separator-at-all", "/signal-only", "component/", "!!/??"} {
		if s, ok := P.NormaliseSubject(raw); ok {
			t.Errorf("%v -> %q", raw, s)
		}
	}
}

func pp(kind, subject, content, repo, path, format string, noSubject bool) map[string]any {
	out := map[string]any{"kind": kind, "title": "t", "rationale": "r", "confidence": "low",
		"evidence": []any{map[string]any{"source": "clickhouse", "summary": "s"}},
		"target":   map[string]any{"repo": repo, "path": path}, "change": map[string]any{"format": format, "content": content}}
	if !noSubject {
		out["subject"] = subject
	}
	return out
}

func alert(content string) map[string]any {
	return pp("Alert", "snowplow/sar-unauthorized", content, "org/repo", "x.yaml", "yaml", false)
}

func TestValidateBatchKeepsAProposalWhoseSubjectFoldsToNothing(t *testing.T) {
	v := alert("a: 1\n")
	v["kind"], v["subject"] = "Alert", "nonsense"
	kept, notes := batch(t, []any{v}, nil)
	if _, has := kept[0]["subject"]; len(kept) != 1 || has || !anyHas(notes, "no usable subject") {
		t.Fatal(kept, notes)
	}
}

func TestTheSubjectIsRequiredByTheContract(t *testing.T) {
	if !py.Has(py.Get(prompt.ItemSchema, "properties"), "subject") {
		t.Fatal("subject not declared")
	}
	found := false
	for _, r := range py.List(py.Get(prompt.ItemSchema, "required")) {
		found = found || r == "subject"
	}
	if !found {
		t.Fatal("subject not required")
	}
}

func TestTheSubjectDoesNotChangeTheFingerprint(t *testing.T) {
	a, b := alert("a: 1\n"), alert("a: 1\n")
	a["subject"], b["subject"] = "a/b", "c/d"
	if fp(t, a) != fp(t, b) {
		t.Fatal()
	}
}

// --- the alert kind (#24) -----------------------------------------------------------------------

const (
	prom     = "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata: {name: x}\nspec: {groups: []}\n"
	invented = "apiVersion: monitoring.krateo.io/v1alpha1\nkind: Alert\nmetadata: {name: x}\n"
	real     = "apiVersion: observability.krateo.io/v1alpha1\nkind: Alert\nmetadata: {name: x, namespace: krateo-system}\n" +
		"spec: {interval: 15m, threshold: 1, thresholdType: above, where: \"Body LIKE '%x%'\"}\n"
)

func TestTheTwoShapesEveryAlertProposalOn057TookAreRefused(t *testing.T) {
	for name, content := range map[string]string{"PrometheusRule": prom, "monitoring.krateo.io": invented} {
		kept, notes := batch(t, []any{alert(content)}, nil)
		ok := false
		for _, n := range notes {
			ok = ok || (strings.HasPrefix(n, "DROPPED") && strings.Contains(n, "observability.krateo.io/v1alpha1"))
		}
		if len(kept) != 0 || !ok {
			t.Errorf("%s: kept=%v notes=%v", name, kept, notes)
		}
	}
}

func TestTheRealAlertKindPasses(t *testing.T) {
	kept, notes := batch(t, []any{alert(real)}, nil)
	if len(kept) != 1 || anyHas(notes, "DROPPED") {
		t.Fatal(kept, notes)
	}
}

func violation(t *testing.T, v map[string]any) string {
	s, err := P.AlertKindViolation(v)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAnAlertProposalCannotCarrySomeOtherObject(t *testing.T) {
	if violation(t, alert("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n")) == "" {
		t.Fatal()
	}
}

func TestAWidgetCalledAlertIsFineInAWidgetProposal(t *testing.T) {
	w := pp("Widget", "snowplow/sar-unauthorized", "apiVersion: widgets.templates.krateo.io/v1beta1\nkind: Alert\nmetadata: {name: x}\n",
		"org/repo", "x.yaml", "yaml", false)
	if s := violation(t, w); s != "" {
		t.Fatal(s)
	}
}

func TestAPrometheusruleIsRefusedWhateverKindCarriesIt(t *testing.T) {
	if violation(t, pp("Policy", "s/x", prom, "org/repo", "x.yaml", "yaml", false)) == "" {
		t.Fatal()
	}
}

func TestADiffAlertNamingAForbiddenKindIsRefusedByText(t *testing.T) {
	if violation(t, pp("Alert", "s/x", "+apiVersion: monitoring.coreos.com/v1\n+kind: PrometheusRule\n", "org/repo", "x.yaml", "diff", false)) == "" {
		t.Fatal()
	}
}

func TestDocumentationMayMentionPrometheusruleInProse(t *testing.T) {
	doc := "We do not use PrometheusRule here; see observability.krateo.io Alerts."
	if s := violation(t, pp("Documentation", "s/x", doc, "org/repo", "x.yaml", "markdown", false)); s != "" {
		t.Fatal(s)
	}
}

// --- subject keys -------------------------------------------------------------------------------

func TestNullSubjectsNeverAKey(t *testing.T) {
	if _, ok := P.SubjectKey(pp("Alert", "", "a: 1\n", "org/repo", "x.yaml", "yaml", true)); ok {
		t.Fatal("a missing subject made a key")
	}
}

// --- one unreadable proposal does not fail the night -----------------------------------------------

func TestAProposalWhoseContentCannotBeReadIsDroppedAndItsSiblingsSurvive(t *testing.T) {
	item := func(v any) error { return jsonschema.Validate(v, prompt.ItemSchema) }
	for name, content := range map[string]string{
		"impossible timestamp": "a: 2020-13-45\n",             // the constructor raises ValueError
		"unhashable kind":      "apiVersion: v1\nkind: [a]\n", // the alert-kind check raises TypeError
		"nesting too deep":     strings.Repeat("[", 600) + strings.Repeat("]", 600) + "\n",
	} {
		bad := p(map[string]any{"kind": "Policy", "title": "bad", "change": map[string]any{"format": "yaml", "content": content}})
		kept, notes, err := P.ValidateBatch(map[string]any{"proposals": []any{p(nil), bad, p(map[string]any{"title": "another"})}},
			noop, item)
		if err != nil {
			t.Fatalf("%s: the whole batch failed: %v", name, err)
		}
		var titles []string
		for _, k := range kept {
			titles = append(titles, k["title"].(string))
			if k["fingerprint"] == "" {
				t.Errorf("%s: a sibling lost its fingerprint", name)
			}
		}
		if !reflect.DeepEqual(titles, []string{"t", "another"}) {
			t.Errorf("%s: kept %v", name, titles)
		}
		dropped := false
		for _, n := range notes {
			if strings.HasPrefix(n, "DROPPED proposal[1] (Policy): its change.content could not be read as yaml (") {
				dropped = true
			}
		}
		if !dropped {
			t.Errorf("%s: the bad proposal was not reported: %v", name, notes)
		}
	}
}

func TestTheUnreadableNoteNamesTheErrorAndQuotesNoSecret(t *testing.T) {
	bad := p(map[string]any{"kind": "Policy", "change": map[string]any{"format": "yaml",
		"content": "a: 2020-13-45\nt: " + "ghp_" + strings.Repeat("A", 36) + "\n"}})
	_, notes := batch(t, []any{bad}, nil)
	var note string
	for _, n := range notes {
		if strings.Contains(n, "could not be read") {
			note = n
		}
	}
	if !strings.Contains(note, "ValueError") || strings.Contains(note, "ghp_") {
		t.Fatalf("%q", note)
	}
}
