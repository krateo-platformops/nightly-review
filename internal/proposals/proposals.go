// Package proposals validates, redacts and fingerprints what the model returned, before any of it is
// written anywhere.
//
// THIS PACKAGE IS THE TRUST BOUNDARY. Upstream of it, every string is model output derived from
// telemetry and from real user conversations — attacker-influenceable on both counts. Downstream of it,
// strings are written into Kubernetes objects and pull request bodies that people will read and act on.
// Nothing crosses without passing through here.
package proposals

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
	"github.com/krateo-platformops/nightly-review/internal/pyyaml"
)

// ---------------------------------------------------------------------------------------------
// 2. REDACTION
// ---------------------------------------------------------------------------------------------
// None of these are hypothetical on this platform. JWTs reached ClickHouse through OTel spans until the
// collector's redaction landed, and spans older than that mitigation are still queryable; an
// aws-access-key-id was found sitting in a PUBLIC repository this week. Evidence is summarised BY a
// model FROM that corpus, so a credential can arrive here inside a perfectly well-formed summary.
//
// The patterns are the Python service's, character for character, compiled with Python's semantics
// (see package pyre): what they match decides what a Proposal stores, and so its fingerprint.

type secretPattern struct {
	re   *pyre.Regexp
	repl string
}

// SecretPatterns is the redaction denylist, applied in order.
var SecretPatterns = []secretPattern{
	{pyre.MustCompile(`eyJ[A-Za-z0-9._-]{20,}`, 0), "<REDACTED-JWT>"},
	{pyre.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, 0), "<REDACTED-AWS-KEY-ID>"},
	{pyre.MustCompile(`(?i)\baws_secret_access_key\s*[=:]\s*\S+`, 0), "aws_secret_access_key=<REDACTED>"},
	{pyre.MustCompile(`(?i)\bghp_[A-Za-z0-9]{20,}\b`, 0), "<REDACTED-GITHUB-PAT>"},
	{pyre.MustCompile(`(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b`, 0), "<REDACTED-GITHUB-PAT>"},
	{pyre.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`, pyre.S),
		"<REDACTED-PRIVATE-KEY>"},
	{pyre.MustCompile(`(?i)\b(client-certificate-data|client-key-data|token)\s*:\s*[A-Za-z0-9+/=]{40,}`, 0), `\1: <REDACTED>`},
	{pyre.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}`, 0), "Bearer <REDACTED>"},
	// ADDED AFTER THE LIST WAS AUDITED AND FOUND THIN. A denylist is never complete — that is not a
	// reason to leave known families out of it, and each of these is a credential that would otherwise
	// survive a model's summary into a pull request body.
	{pyre.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`, 0), "<REDACTED-GITLAB-PAT>"},
	{pyre.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`, 0), "<REDACTED-SLACK-TOKEN>"},
	{pyre.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`, 0), "<REDACTED-GOOGLE-API-KEY>"},
	// user:pass@host in a URL — the password is the part that matters, so the host is left readable.
	{pyre.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@`, 0), `\1:<REDACTED>@`},
	// THE KEY MAY BE PART OF A LONGER NAME. The pattern used to open with `\b(password|…)`, and `\b` does
	// not fire between `_` and a letter or inside PGPASSWORD — so DB_PASSWORD=, PGPASSWORD=,
	// MY_API_KEY= and CLICKHOUSE_PASSWORD= all passed untouched (found on 057, 2026-09-29, where
	// KAGENT_DB_PASSWORD holds admin's password and tool output is where an `env` dump lands). Any
	// identifier CONTAINING a key word now matches, and the value runs to whitespace or a quote, so a
	// password with punctuation is not redacted halfway. `token` and `secret_key` joined 2026-09-30: the
	// review pod now holds a GitHub token as TARGET_CHECK_TOKEN, and a token whose VALUE matches no known
	// shape (ghp_, JWT…) was left in the clear by a key list that only knew access_token.
	{pyre.MustCompile(`(?i)\b([A-Za-z0-9_\-]*?(?:api[_\-]?key|client[_\-]?secret|access[_\-]?token|token|secret[_\-]?key|password|passwd)[A-Za-z0-9_\-]*)`+
		`\s*[=:]\s*[\"\']?([^\s\"\',;]{8,})[\"\']?`, 0), `\1=<REDACTED>`},
	// THE SAME KEYS, JSON-QUOTED. The pattern above needs the colon right after the key, and in JSON a
	// quote sits between them — so `"password": "hunter2hunter2"` passed through untouched. That shape
	// was rare while only people's questions were read; tool ARGUMENTS are rendered as JSON, and the
	// agent-analysis stage reads every one of them. `token` is here bare as well, because tool arguments
	// carry it bare; `secret` is not, because in Kubernetes JSON it is far more often a Secret's NAME.
	{pyre.MustCompile(`(?i)\"([A-Za-z0-9_\-]*?(?:api[_\-]?key|client[_\-]?secret|access[_\-]?token|refresh[_\-]?token|token|password|passwd)[A-Za-z0-9_\-]*)\"`+
		`\s*:\s*\"[^\"\\]{8,}\"`, 0), `"\1": "<REDACTED>"`},
	// AND IN PROSE. People type "my password is X" to an agent, and agents answer "the password is X";
	// neither has a colon, so both passed. The value must carry a digit: prose has no other way to tell
	// "the password is hunter2hunter2" from "the password is required", and redacting English would make
	// every transcript unreadable. A password of letters only still passes; that is this pattern's stated
	// limit, not an oversight.
	{pyre.MustCompile(`(?i)\b(password|passwd|api[_\- ]?key|token)(\s+(?:is|was|=)\s+)[\"\']?(?=[^\s\"\']*\d)[^\s\"\']{8,}[\"\']?`, 0),
		`\1\2<REDACTED>`},
}

// RedactString redacts one string.
func RedactString(s string) string {
	for _, p := range SecretPatterns {
		s = p.re.Sub(s, p.repl)
	}
	return s
}

// Redact recursively redacts every string in a structure. Applied to the WHOLE proposal, not just the
// fields that look risky: the model decides what goes in `rationale` and `summary`, so assuming a
// credential could only appear in `change.content` is assuming the thing being guarded against. An
// ordered map comes back as a plain one.
func Redact(v any) any {
	switch x := v.(type) {
	case string:
		return RedactString(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = Redact(e)
		}
		return out
	case *py.OMap:
		out := make(map[string]any, x.Len())
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			out[k] = Redact(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Redact(e)
		}
		return out
	}
	return v
}

// RedactionCount counts the string leaves that differ between a structure and its redaction, so a run
// that scrubbed something says so rather than quietly cleaning up and reporting a normal night.
//
// IT USED TO ZIP TWO JSON STRINGS CHARACTER BY CHARACTER, which cannot answer the question it was named
// for. Walk the two structures instead and count the string leaves that differ — which is exactly what
// "how many redactions fired" means.
func RedactionCount(before, after any) int {
	switch b := before.(type) {
	case string:
		if a, ok := after.(string); ok && a == b {
			return 0
		}
		return 1
	case map[string]any, *py.OMap:
		if !py.IsDict(after) {
			return 0
		}
		n := 0
		for _, k := range py.DictKeys(b) {
			n += RedactionCount(py.Get(b, k), py.Get(after, k))
		}
		return n
	case []any:
		a, ok := after.([]any)
		if !ok {
			return 0
		}
		n := 0
		for i := 0; i < len(b) && i < len(a); i++ {
			n += RedactionCount(b[i], a[i])
		}
		return n
	}
	return 0
}

// ---------------------------------------------------------------------------------------------
// 3. FINGERPRINT
// ---------------------------------------------------------------------------------------------

// NormaliseBody is what "the same change" means, independent of how the model happened to type it
// that night. YAML is compared as PARSED DATA with its mappings sorted, so key order and comments cannot
// affect identity; anything that is not a YAML mapping or sequence falls through to the text path:
// comment lines and blank lines dropped, internal whitespace runs collapsed. The YAML half is PyYAML's
// safe_load/safe_dump, ported byte for byte (package pyyaml) because existing Proposals are named by it.
func NormaliseBody(content, format string) (string, error) {
	return pyyaml.NormaliseBody(content, format)
}

// field reads d.get(key, "") as `"\x1f".join` needs it: absent is "", a str is itself, anything else is
// the TypeError Python's join raises.
func field(d any, key string, pos int) (string, error) {
	if !py.Has(d, key) {
		return "", nil
	}
	v := py.Get(d, key)
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", py.Errorf("TypeError", "sequence item %d: expected str instance, %s found", pos, pyTypeName(v))
}

func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int64, int:
		return "int"
	case float64:
		return "float"
	case []any:
		return "list"
	case map[string]any, *py.OMap:
		return "dict"
	}
	return "object"
}

// getOrEmpty is proposal.get(key, {}): absent gives {}; present is returned as it is.
func getOrEmpty(d any, key string) any {
	if !py.Has(d, key) {
		return map[string]any{}
	}
	return py.Get(d, key)
}

func kindOf(p any) (string, error) {
	if !py.Has(p, "kind") {
		return "", py.Errorf("KeyError", "'kind'")
	}
	return field(p, "kind", 0)
}

// TargetKey is what a proposal is ABOUT, with its body left out: one file, one kind of change. Two
// proposals sharing this but not their fingerprint are successive opinions on the same question, which
// is the distinction `superseded` was always meant to record.
func TargetKey(p any) (string, error) {
	kind, err := kindOf(p)
	if err != nil {
		return "", err
	}
	t := getOrEmpty(p, "target")
	if !py.IsDict(t) {
		return "", py.Errorf("AttributeError", "'%s' object has no attribute 'get'", pyTypeName(t))
	}
	repo, err := field(t, "repo", 1)
	if err != nil {
		return "", err
	}
	path, err := field(t, "path", 2)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{kind, repo, path}, "\x1f"), nil
}

// Fingerprint is the stable identity of "the same suggestion", so night two supersedes night one
// instead of reproposing it. Deliberately excludes rationale and confidence — the model will word its
// reasoning differently every night, and a fingerprint that changed with the prose would defeat itself.
func Fingerprint(p any) (string, error) {
	kind, err := kindOf(p)
	if err != nil {
		return "", err
	}
	t := getOrEmpty(p, "target")
	change := getOrEmpty(p, "change")
	if !py.IsDict(t) {
		return "", py.Errorf("AttributeError", "'%s' object has no attribute 'get'", pyTypeName(t))
	}
	if !py.IsDict(change) {
		return "", py.Errorf("AttributeError", "'%s' object has no attribute 'get'", pyTypeName(change))
	}
	content := ""
	if py.Has(change, "content") {
		c, ok := py.Get(change, "content").(string)
		if !ok {
			return "", py.Errorf("AttributeError", "'%s' object has no attribute 'splitlines'", pyTypeName(py.Get(change, "content")))
		}
		content = c
	}
	format, _ := py.Get(change, "format").(string)
	body, err := NormaliseBody(content, format)
	if err != nil {
		return "", err
	}
	repo, err := field(t, "repo", 1)
	if err != nil {
		return "", err
	}
	path, err := field(t, "path", 2)
	if err != nil {
		return "", err
	}
	key := strings.Join([]string{kind, repo, path, body}, "\x1f")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:32], nil
}

// MustFingerprint is Fingerprint for proposals already through ValidateBatch, whose fingerprint was
// computed once without error and whose body has not changed since.
func MustFingerprint(p any) string {
	fp, err := Fingerprint(p)
	if err != nil {
		panic(err)
	}
	return fp
}

// ---------------------------------------------------------------------------------------------
// 3b. SUBJECT — what a proposal is ABOUT, independent of where it would land
// ---------------------------------------------------------------------------------------------
// THE TARGET WAS NEVER A STABLE KEY FOR A FINDING, and the proposals on 057 are the measurement. One
// chart-inspector failure produced five Alert proposals across four repositories, four of them still
// open on 2026-09-29 — each a different target key, so each one looked new, and none superseded
// another. What stays the same is the FINDING: which component, failing how.
//
// ONE NORMALISED STRING, `component/signal`. Both halves are lowercase kebab so the model's casing and
// punctuation cannot split one finding into two: `Snowplow/SubjectAccessReview Unauthorized` and
// `snowplow:subjectaccessreview-unauthorized` are the same subject.

var (
	slugNon   = pyre.MustCompile(`[^a-z0-9]+`, 0)
	subjectRE = pyre.MustCompile(`\s*([^/:]+)[/:](.+)`, 0)
)

// SubjectMax bounds a subject.
const SubjectMax = 160

// Slug is CannotObserveExternalResource -> cannot-observe-external-resource; `HTTP 500!` -> http-500.
// CamelCase is split BEFORE lowercasing (Python's `(?<=[a-z0-9])(?=[A-Z])`), because event reasons
// arrive CamelCase from Kubernetes and kebab from the model's paraphrase of them, and the two must meet.
func Slug(text string) string {
	var b strings.Builder
	var prev rune = -1
	for _, r := range text {
		if r >= 'A' && r <= 'Z' && ((prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9')) {
			b.WriteByte('-')
		}
		b.WriteRune(r)
		prev = r
	}
	return py.StripChars(slugNon.Sub(py.Lower(b.String()), "-"), "-")
}

// NormaliseSubject returns `component/signal`, normalised, or "", false when there is nothing usable to
// normalise.
//
// REWRITES, NEVER REFUSES. A colon where a slash was asked for, capitals, spaces — all folded. Only a
// value with no separator, or with an empty half after folding, comes back empty, and that is a
// legitimate state: it is what every proposal written before this field existed carries, and
// SubjectKey guarantees it never groups.
func NormaliseSubject(value any) (string, bool) {
	s, ok := value.(string)
	if !ok {
		return "", false
	}
	m := subjectRE.Match(s)
	if m == nil {
		return "", false
	}
	component, signal := Slug(m.Group(1)), Slug(m.Group(2))
	if component == "" || signal == "" {
		return "", false
	}
	return py.Trunc(component+"/"+signal, SubjectMax), true
}

// SubjectKey is (kind, subject), or "", false — AND AN ABSENT SUBJECT MUST NEVER BE A KEY. The twenty
// proposals on 057 that predate this field all carry no subject; if a missing subject compared equal to
// another missing subject, the first new proposal of each kind would supersede every legacy one of that
// kind in one night.
//
// KIND IS PART OF THE KEY on purpose. An Alert and a Documentation proposal about the same failure are
// two halves of one answer, not successive opinions on one question, and neither should retire the
// other.
func SubjectKey(p any) (string, bool) {
	subject := py.Get(p, "subject")
	if !py.Truthy(subject) {
		return "", false
	}
	return py.Str(py.Get(p, "kind")) + "\x1f" + py.Str(subject), true
}

// Ref names an open proposal in an index.
type Ref struct {
	Fingerprint string
	Name        string
}

// Classification is classify()'s answer: Action is "dedup", "decided", "supersede" or "new"; Name is
// the matched proposal for dedup/decided; Priors the proposals a supersession replaces.
type Classification struct {
	Action string
	Name   string
	Priors []string
}

// Classify decides one proposal against the indexes. THREE OUTCOMES, WHERE THE CODE USED TO SEE TWO —
// and the missing third is why `superseded` was reported as a hardcoded 0 every night.
//
//   - Identical to something already open is a duplicate: ("dedup", name). The fingerprint wins over
//     everything, because an exact repeat is not a new opinion however it is labelled.
//   - The same FINDING (kind + subject) as a Proposed one from an earlier night, or the same FILE with a
//     different body, is a replacement: ("supersede", [names]).
//   - Exactly what a PERSON has already answered (Rejected, Merged, or a PrOpen they opened) is
//     ("decided", name) — neither a duplicate of an open question nor a new one. It is not written: the
//     object is named by its fingerprint, so writing it would reset that person's answer to Proposed.
//   - Otherwise ("new", nil).
func Classify(p any, byFingerprint map[string]string, byTarget map[string]Ref, bySubject map[string][]Ref,
	decided map[string]string) (Classification, error) {
	fp, err := Fingerprint(p)
	if err != nil {
		return Classification{}, err
	}
	if name, ok := decided[fp]; ok && len(decided) > 0 {
		return Classification{Action: "decided", Name: name}, nil
	}
	if name, ok := byFingerprint[fp]; ok {
		return Classification{Action: "dedup", Name: name}, nil
	}
	var priors []string
	if key, ok := SubjectKey(p); ok && len(bySubject) > 0 {
		for _, r := range bySubject[key] {
			if r.Fingerprint != fp {
				priors = append(priors, r.Name)
			}
		}
	}
	tk, err := TargetKey(p)
	if err != nil {
		return Classification{}, err
	}
	if prior, ok := byTarget[tk]; ok && prior.Fingerprint != fp && !contains(priors, prior.Name) {
		priors = append(priors, prior.Name)
	}
	if len(priors) > 0 {
		return Classification{Action: "supersede", Priors: priors}, nil
	}
	return Classification{Action: "new"}, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 3c. THE ALERT KIND (#24)
// ---------------------------------------------------------------------------------------------
// Kinds and groups that are alert-shaped and dead here. Every one of the thirteen Alert proposals on 057
// on 2026-09-29 was one of these; see prompt.AlertKind for why none of them can fire on this platform.
var (
	forbiddenAlertKinds  = map[string]bool{"PrometheusRule": true}
	forbiddenAlertGroups = map[string]bool{"monitoring.krateo.io": true, "monitoring.coreos.com": true}
	forbiddenText        = pyre.MustCompile(`\bPrometheusRule\b|\bmonitoring\.krateo\.io\b|\bmonitoring\.coreos\.com\b`, 0)
)

// AlertKindViolation returns a sentence saying why change.content carries an alert this platform cannot
// evaluate, or "" when it does not.
//
// TWO RULES, SCOPED DIFFERENTLY ON PURPOSE.
//   - Any proposal whose YAML declares a PrometheusRule or an object in a forbidden group is refused,
//     whatever its kind: a dead alert smuggled into a Policy proposal is as dead as one in an Alert.
//   - An ALERT proposal must declare nothing but observability.krateo.io/v1alpha1 Alert. Not applied to
//     other kinds, because `alerts.widgets.templates.krateo.io` is a real portal widget called Alert and
//     a Widget proposal may legitimately carry one.
//
// A document with neither kind nor apiVersion is not an object declaration and is left alone. Content
// that is not parseable YAML — a diff, markdown — is scanned as text for the forbidden names, but only
// for Alert proposals: documentation may mention PrometheusRule in prose, an Alert may not ship one.
func AlertKindViolation(p any) (string, error) {
	change := py.Get(p, "change")
	if !py.Truthy(change) {
		change = map[string]any{}
	}
	content := py.Get(change, "content")
	if !py.Truthy(content) {
		content = ""
	}
	text, _ := content.(string)
	var docs []*pyyaml.Mapping
	parsed := false
	if py.Get(change, "format") == "yaml" {
		values, err := pyyaml.SafeLoadAll(text)
		if err == nil {
			parsed = true
			for _, v := range values {
				if m, ok := v.(*pyyaml.Mapping); ok {
					docs = append(docs, m)
				}
			}
		} else if _, isYAMLErr := err.(*pyyaml.YAMLError); !isYAMLErr {
			return "", err // a non-YAMLError exception escapes alert_kind_violation in Python too
		}
	}
	isAlert := py.Get(p, "kind") == "Alert"
	if !parsed {
		if isAlert {
			if m := forbiddenText.Search(text); m != nil {
				return fmt.Sprintf("an Alert proposal must carry an %s Alert; its content names %s, which nothing "+
					"on this platform evaluates", prompt.AlertAPIVersion, m.Group(0)), nil
			}
		}
		return "", nil
	}
	for _, d := range docs {
		kind, hasKind := d.Get("kind")
		api, hasAPI := d.Get("apiVersion")
		if (!hasKind || kind == nil) && (!hasAPI || api == nil) {
			continue
		}
		apiStr := ""
		if pyyaml.Truthy(api) {
			apiStr = pyyaml.Str(api)
		}
		group, _, _ := strings.Cut(apiStr, "/")
		if kind != nil && !pyyaml.Hashable(kind) {
			return "", py.Errorf("TypeError", "unhashable type")
		}
		ks, kindIsStr := kind.(string)
		if (kindIsStr && forbiddenAlertKinds[ks]) || forbiddenAlertGroups[group] {
			return fmt.Sprintf("declares %s/%s, which nothing on this platform evaluates — the only alert kind is %s Alert",
				yamlStr(api), yamlStr(kind), prompt.AlertAPIVersion), nil
		}
		apiS, apiIsStr := api.(string)
		if isAlert && !(kindIsStr && ks == "Alert" && apiIsStr && apiS == prompt.AlertAPIVersion) {
			return fmt.Sprintf("an Alert proposal must carry only %s Alert objects; it declares %s/%s",
				prompt.AlertAPIVersion, yamlStr(api), yamlStr(kind)), nil
		}
	}
	return "", nil
}

// yamlStr is f"{x}" of a loaded YAML value (None for an absent one).
func yamlStr(v pyyaml.Value) string {
	if v == nil {
		return "None"
	}
	return pyyaml.Str(v)
}

// ---------------------------------------------------------------------------------------------
// 4. VALIDATION
// ---------------------------------------------------------------------------------------------
// THE ALLOWLIST IS GONE, DELIBERATELY, AND THIS COMMENT IS ITS EPITAPH so the next reader does not
// reintroduce it by accident. It bounded which repository a proposal could name, and it existed because
// this service used to hold a GitHub write credential: `target.repo` is chosen by the model from a
// corpus containing user-written chat, so an unbounded target aimed that credential wherever the corpus
// liked. Two things changed. Publishing moves to the platform's own chain, so the credential is
// git-provider's rather than the reviewer's; and every proposal now opens a pull request on a branch,
// which a human reads before anything merges. The review IS the control, and a proposal blocked before
// it becomes a pull request teaches nobody anything — not the reader, and not the next night's review.
//
// What that costs, stated plainly rather than left for someone to discover: the reviewer may now name
// any repository the install-level git credentials can write to.

// unreadable is the note for a proposal whose content cannot be read as its format says: YAML that the
// parser takes but cannot construct (a timestamp like 2020-13-45, an unhashable kind, nesting past the
// recursion limit), so neither the alert-kind check nor the fingerprint can be computed.
//
// ONE SUCH PROPOSAL USED TO FAIL THE WHOLE NIGHT. The error escaped ValidateBatch, the run was recorded
// Failed, and every other proposal was lost with it — the same single-item suppression per-item
// validation exists to prevent, reached through the content instead of the schema. Such a proposal is
// dropped and named here; its siblings are written. Checked after redaction, so the note cannot quote a
// secret, and the error text is cut like the contract's own drop notes.
func unreadable(i int, clean map[string]any, err error) string {
	return fmt.Sprintf("DROPPED proposal[%d] (%s): its change.content could not be read as %s (%s)", i,
		py.Str(clean["kind"]), py.Str(py.Get(clean["change"], "format")), py.Trunc(py.ExcString(err), 160))
}

// Refused is raised for the WHOLE batch. A partially valid response is not salvaged: deciding which
// half the model meant is exactly the guess this service exists not to make.
type Refused struct{ Msg string }

func (e *Refused) Error() string { return e.Msg }

// PyType names the Python class.
func (e *Refused) PyType() string { return "Refused" }

// Check validates one value, returning the error Python's check would raise.
type Check func(v any) error

// ValidateBatch returns (proposals, notes). It fails with *Refused only when the RESPONSE ENVELOPE is
// unusable; any other error is a schema check that raised, or an item that is not an object when no item
// check ran. A proposal whose content cannot be read is dropped with a note (see unreadable).
//
// A SINGLE BAD FIELD USED TO DISCARD THE WHOLE NIGHT. schema_check ran over the entire payload, so one
// proposal with one wrong enum raised and eleven good ones went in the bin with it — and because the
// corpus is attacker-influenceable, inducing one schema violation was the cheapest way to suppress the
// review entirely. The envelope is still validated strictly; each proposal is now validated on its own
// and a bad one is dropped WITH A NOTE while its siblings survive.
func ValidateBatch(payload any, schemaCheck, itemCheck Check) ([]map[string]any, []string, error) {
	if !py.IsDict(payload) {
		return nil, nil, &Refused{Msg: fmt.Sprintf("response was %s, expected an object", pyTypeName(payload))}
	}
	items, ok := py.Get(payload, "proposals").([]any)
	if !ok {
		return nil, nil, &Refused{Msg: "response has no `proposals` array"}
	}
	envelope := payload
	if itemCheck != nil {
		envelope = map[string]any{"proposals": []any{}} // envelope only when items are checked
	}
	if err := schemaCheck(envelope); err != nil {
		return nil, nil, err
	}

	notes := []string{}
	kept := []map[string]any{}
	for i, raw := range items {
		if itemCheck != nil {
			if err := itemCheck(raw); err != nil {
				notes = append(notes, fmt.Sprintf("DROPPED proposal[%d]: does not match the contract (%s)", i,
					py.Trunc(err.Error(), 160)))
				continue
			}
		}
		cleanAny := Redact(raw)
		clean, ok := cleanAny.(map[string]any)
		if !ok {
			// A non-object item without an item check: Python fails on clean.get below.
			return nil, nil, py.Errorf("AttributeError", "'%s' object has no attribute 'get'", pyTypeName(cleanAny))
		}
		if fired := RedactionCount(raw, clean); fired > 0 {
			notes = append(notes, fmt.Sprintf("proposal[%d] contained %d secret-shaped string(s); redacted before storage", i, fired))
		}

		// NO CONFIDENCE CAP, DELIBERATELY (#14). There used to be one here: high was demoted to medium
		// unless the proposal carried two evidence items or a summed observedCount of two or more. It read
		// as evidence verification and was arithmetic on the model's own claims — observedCount is
		// model-authored and unbounded, so a single fabricated item claiming 900 satisfied it. The cap never
		// once changed an outcome, and a check that cannot fail is worse than no check, because it is read
		// as one. So `confidence` is the MODEL's self-report and the CRD says so.

		// REFUSED WHOLE, WITH THE REASON, because a PrometheusRule is not a draft of an Alert that a
		// reviewer could fix in review — it is a different system, and merging it adds an alert that never
		// fires while looking like coverage. Checked AFTER redaction so the note cannot quote a secret.
		dead, err := AlertKindViolation(clean)
		if err != nil {
			notes = append(notes, unreadable(i, clean, err))
			continue
		}
		if dead != "" {
			notes = append(notes, fmt.Sprintf("DROPPED proposal[%d] (%s): %s", i, py.Str(clean["kind"]), dead))
			continue
		}

		// Normalised, not validated: see NormaliseSubject. A subject that folds to nothing is kept as null
		// WITH A NOTE, so the proposal survives and the run still says that one of its findings can never
		// be matched against tomorrow's.
		if subject, ok := NormaliseSubject(clean["subject"]); ok {
			clean["subject"] = subject
		} else {
			delete(clean, "subject")
			notes = append(notes, fmt.Sprintf("proposal[%d] carried no usable subject; it will not group with later nights", i))
		}

		fp, err := Fingerprint(clean)
		if err != nil {
			notes = append(notes, unreadable(i, clean, err))
			continue
		}
		clean["fingerprint"] = fp
		kept = append(kept, clean)
	}
	return kept, notes, nil
}
