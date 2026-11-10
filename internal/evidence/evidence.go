// Package evidence gathers the corpus the agent reasons over. Deterministic, bounded, and reviewable.
//
// THE QUERIES ARE CONFIGURATION, NOT CODE. They ship in the chart's values as named SQL and API reads,
// so an operator can read exactly what this service will ask for, adapt them to their own ClickHouse
// schema, and change them without a new image. A model is never asked to author the SQL: open-ended
// query generation against a store that has held live credentials is a risk with no matching benefit.
//
// EVERY SOURCE FAILS INDEPENDENTLY AND VISIBLY. A source that errors is recorded with its error and the
// run becomes PartiallyCompleted. It is never dropped silently, because a proposal built on half the
// evidence must be readable as such.
package evidence

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/krateo-platformops/nightly-review/internal/env"
	"github.com/krateo-platformops/nightly-review/internal/httpx"
	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/pg"
	"github.com/krateo-platformops/nightly-review/internal/prompt"
	"github.com/krateo-platformops/nightly-review/internal/proposals"
	"github.com/krateo-platformops/nightly-review/internal/py"
	"github.com/krateo-platformops/nightly-review/internal/pyre"
)

// Configuration, read once at start as the Python module read it at import.
var (
	ClickhouseURL      = env.Str("CLICKHOUSE_URL", "")
	ClickhouseUser     = env.Str("CLICKHOUSE_USER", "")
	ClickhousePassword = env.Str("CLICKHOUSE_PASSWORD", "")
	KagentAPI          = env.Str("KAGENT_API_URL", "http://kagent-controller.krateo-system.svc:8083")
	// kagent's Postgres, read with a role granted SELECT on `session` and `event` AND NOTHING ELSE. See
	// KagentSessions and QuestionsSQL.
	KagentDBHost     = env.Str("KAGENT_DB_HOST", "kagent-postgresql.krateo-system.svc")
	KagentDBPort     = env.Int("KAGENT_DB_PORT", "5432")
	KagentDBName     = env.Str("KAGENT_DB_NAME", "kagent")
	KagentDBUser     = env.Str("KAGENT_DB_USER", "")
	KagentDBPassword = env.Str("KAGENT_DB_PASSWORD", "")
	MaxRows          = env.Int("EVIDENCE_MAX_ROWS", "200")
	MaxChars         = env.Int("EVIDENCE_MAX_CHARS", "60000")

	QuestionsMaxSessions     = env.Int("KAGENT_QUESTIONS_MAX_SESSIONS", "40")
	QuestionsPerSession      = env.Int("KAGENT_QUESTIONS_PER_SESSION", "6")
	QuestionsCharsPerSession = env.Int("KAGENT_QUESTIONS_CHARS_PER_SESSION", "1500")
	// QuestionsExcludeAgents is the reviewer's OWN sessions. Its user turn is last night's whole
	// evidence corpus, so reading it back would feed the review its own previous input and crowd out
	// every real question. "namespace/name", comma-separated; the chart sets it to the reviewer agent it
	// creates.
	QuestionsExcludeAgents = env.Str("KAGENT_QUESTIONS_EXCLUDE_AGENTS", "")

	// MaxPages bounds the page list. 057 carries 33 page roots in krateo-system against 184 Flex widgets
	// and 553 widget CRs in all; the roots are what a proposal would duplicate, and the rest would crowd
	// out the telemetry the proposals are supposed to come from.
	MaxPages = env.Int("EVIDENCE_MAX_PAGES", "100")
)

// HTTPClient posts to ClickHouse (requests.post, timeout=120).
var HTTPClient = &http.Client{Timeout: 120 * time.Second}

// Stats is one source's record in status.evidence.
type Stats = map[string]any

// Cap bounds what reaches the prompt. An unbounded corpus is a cost problem, a context problem, and —
// because older spans predate the collector's JWT redaction — a disclosure problem.
//
// THE TRUNCATION IS RECORDED ON THE RUN, not only marked inside the corpus. Before, the marker went where
// only the model could see it while the status still read `returned: 75` and looked complete — so
// whoever wrote the most logs quietly decided what got reviewed, and nothing said so. The marker stays
// as well: the model should know its evidence was cut.
func Cap(text string, stats Stats) string {
	n := py.Len(text)
	if n <= MaxChars {
		return text
	}
	if stats != nil {
		// ADDED TO, not overwritten: kagent-sessions may already have recorded characters it cut per
		// session before the source as a whole reached this cap, and both are "what the model never saw".
		stats["truncated"] = true
		stats["truncatedAtChars"] = MaxChars
		stats["droppedChars"] = py.Int(stats["droppedChars"]) + int64(n-MaxChars)
	}
	return py.Trunc(text, MaxChars) + fmt.Sprintf("\n... [truncated at %d chars]", MaxChars)
}

// strptime regexes as Python's _strptime builds them (IGNORECASE, Unicode \d), for the four formats
// ChTime tries in order. The groups are Python's named ones (Y m d H M S f z), unnamed here and read by
// position.
var chFormats = []*pyre.Regexp{
	pyre.MustCompile(`(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)\.([0-9]{1,6})([+-]\d\d:?[0-5]\d(:?[0-5]\d(\.\d{1,6})?)?|\x5a)`, pyre.I),
	pyre.MustCompile(`(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)([+-]\d\d:?[0-5]\d(:?[0-5]\d(\.\d{1,6})?)?|\x5a)`, pyre.I),
	pyre.MustCompile(`(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)\.([0-9]{1,6})`, pyre.I),
	pyre.MustCompile(`(\d\d\d\d)-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])T(2[0-3]|[0-1]\d|\d):([0-5]\d|\d):(6[0-1]|[0-5]\d|\d)`, pyre.I),
}

// pyDigits is int() over a run of Unicode decimal digits.
func pyDigits(s string) int {
	n := 0
	for _, r := range strings.TrimSpace(s) {
		n = n*10 + digitValue(r)
	}
	return n
}

func digitValue(r rune) int {
	if r >= '0' && r <= '9' {
		return int(r - '0')
	}
	// Unicode encodes every set of decimal digits as a contiguous 0..9 run, and runs that touch (the
	// mathematical digits) are whole sets, so the value is the distance from the start of the block.
	start := r
	for unicode.Is(unicode.Nd, start-1) {
		start--
	}
	return int(r-start) % 10
}

// ChTime is a window bound ClickHouse can use its primary-key index on.
//
// THIS ONE LINE WAS THE WHOLE OF THE TIMEOUT. The run records its window as ISO-8601, which is right for
// the CR, and the same string was substituted straight into SQL — so ClickHouse compared a DateTime64
// column against '2026-09-27T14:17:43.745807+00:00' and could not prune by range, and full-scanned 13.9M
// rows every night. Measured on 057, same predicate: the ISO literal takes 167 SECONDS, past the 120s
// read timeout; 'YYYY-MM-DD HH:MM:SS' takes 15.7s, and the full grouped query 2.3s.
//
// The ReviewRun keeps the ISO form: its CRD types the window as date-time, and the record should stay
// readable. Only what goes into SQL is converted.
func ChTime(v string) string {
	for _, re := range chFormats {
		m := re.FullMatch(v)
		if m == nil {
			continue
		}
		y, mo, d := pyDigits(m.Group(1)), pyDigits(m.Group(2)), pyDigits(m.Group(3))
		h, mi, s := pyDigits(m.Group(4)), pyDigits(m.Group(5)), pyDigits(m.Group(6))
		if s > 59 || d > daysIn(y, mo) || y < 1 {
			continue // datetime() refuses it, strptime raises ValueError, the next format is tried
		}
		t := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
		// ONLY CONVERT WHAT CARRIES AN OFFSET. astimezone() on a NAIVE datetime assumes the machine's
		// local zone, which would silently slide the review window by that offset — on a box at UTC+2 the
		// first version of this shifted 14:17 to 12:17, and a window that is quietly two hours wrong is
		// worse than the slow query it was written to fix. A naive value is already UTC here.
		if z := zoneGroup(re, m); z != "" {
			off, ok := parseOffset(z)
			if !ok {
				continue
			}
			t = time.Date(y, time.Month(mo), d, h, mi, s, 0, time.FixedZone("", off)).UTC()
		}
		return py.Strftime(t, "%Y-%m-%d %H:%M:%S")
	}
	// Unparseable: hand it through untouched rather than guess. A slow query beats a wrong window.
	return v
}

func daysIn(y, m int) int { return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day() }

func zoneGroup(re *pyre.Regexp, m *pyre.Match) string {
	switch re {
	case chFormats[0]:
		return m.Group(8)
	case chFormats[1]:
		return m.Group(7)
	}
	return ""
}

// parseOffset reads %z as _strptime does: Z (only uppercase — Python writes (?-i:Z)), or
// ±HH[:]MM[[:]SS[.ffffff]] where a colon after the hours requires one after the minutes too.
func parseOffset(z string) (int, bool) {
	if z == "Z" {
		return 0, true
	}
	rs := []rune(z)
	if len(rs) > 3 && rs[3] == ':' {
		rs = append(rs[:3:3], rs[4:]...)
		if len(rs) > 5 {
			if rs[5] != ':' {
				return 0, false // "Inconsistent use of : in z"
			}
			rs = append(rs[:5:5], rs[6:]...)
		}
	}
	if len(rs) < 5 {
		return 0, false
	}
	hh, mm := pyDigits(string(rs[1:3])), pyDigits(string(rs[3:5]))
	ss := 0
	if len(rs) > 5 {
		end := 7
		if end > len(rs) {
			end = len(rs)
		}
		for _, r := range rs[5:end] {
			if !unicode.Is(unicode.Nd, r) {
				return 0, false // int() refuses it
			}
		}
		ss = pyDigits(string(rs[5:end]))
	}
	off := hh*3600 + mm*60 + ss
	if rs[0] == '-' {
		off = -off
	}
	return off, true
}

// Clickhouse runs the configured queries: {name: sql} from chart values. `{from}`/`{to}` are
// substituted, nothing else is.
func Clickhouse(ctx context.Context, queries *py.OMap, window prompt.Window) (string, Stats) {
	if ClickhouseURL == "" {
		return "", Stats{"ok": false, "error": "CLICKHOUSE_URL not configured"}
	}
	var blocks []string
	stats := Stats{"ok": true, "queried": 0, "returned": 0}
	// THE REAL SQL, KEPT BY NAME. A proposal is supposed to carry the query that produced it so a human
	// can re-run it and disagree; asking the MODEL to repeat it back produced a plausible paraphrase
	// instead — one with no window clause, matching nothing that ran. The service knows exactly what it
	// asked, so it is the service that records it.
	ran := map[string]any{}
	stats["queries"] = ran
	addErr := func(s string) {
		stats["ok"] = false
		stats["error"] = py.Str(py.Or(stats["error"], "")) + s
	}
	for _, name := range queries.Keys() {
		v, _ := queries.Get(name)
		sql := py.Str(v)
		// THE WINDOW IS A SAFETY CONTROL, NOT A COST ONE: spans older than the collector's JWT redaction
		// can still carry live credentials, so an unbounded scan is a disclosure risk. Substitution is
		// textual, so a query that simply omits the placeholders used to scan everything, silently.
		if !strings.Contains(sql, "{from}") || !strings.Contains(sql, "{to}") {
			addErr(fmt.Sprintf("%s: refused — the query does not carry both {from} and {to}, so it would not be "+
				"bounded to the review window; ", name))
			continue
		}
		bound := strings.ReplaceAll(strings.ReplaceAll(sql, "{from}", ChTime(window.From)), "{to}", ChTime(window.To))
		text, err := Post(ctx, bound+"\nFORMAT JSONCompactEachRow", MaxRows)
		if err != nil {
			addErr(fmt.Sprintf("%s: %s; ", name, err.Error()))
			continue
		}
		var rows []string
		for _, ln := range py.SplitLines(text) {
			if py.Strip(ln) != "" {
				rows = append(rows, ln)
			}
		}
		stats["queried"] = py.Int(stats["queried"]) + 1
		stats["returned"] = py.Int(stats["returned"]) + int64(len(rows))
		ran[name] = bound
		shown := rows
		if len(shown) > MaxRows {
			shown = shown[:MaxRows]
		}
		blocks = append(blocks, fmt.Sprintf("-- %s\n-- query: %s\n", name, bound)+strings.Join(shown, "\n"))
	}
	// Redact on the way IN as well as out. The agent should never be handed a credential it could
	// faithfully quote back into a proposal.
	return Cap(proposals.RedactString(strings.Join(blocks, "\n\n")), stats), stats
}

// Post sends one statement to ClickHouse with the configured credentials and returns the response
// text, as requests.post(CLICKHOUSE_URL, data=..., params={max_result_rows, result_overflow_mode:
// break}, auth=...) followed by raise_for_status() did. A variable so a test can stand in for ClickHouse.
var Post = func(ctx context.Context, body string, maxRows int) (string, error) {
	u, err := url.Parse(ClickhouseURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("max_result_rows", strconv.Itoa(maxRows))
	q.Set("result_overflow_mode", "break")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		return "", err
	}
	if ClickhouseUser != "" {
		req.SetBasicAuth(ClickhouseUser, ClickhousePassword)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	if err := httpx.RaiseForStatus(resp); err != nil {
		resp.Body.Close()
		return "", err
	}
	return httpx.Text(resp)
}

// SessionSQL is THE ONLY QUERY THIS SERVICE MAKES AGAINST kagent's session table. Three properties are
// load-bearing and each is asserted by a test:
//   - `deleted_at IS NULL`, because kagent soft-deletes and without it this returns sessions users
//     deleted, which their own API would never show them;
//   - count(DISTINCT user_id) and NEVER user_id itself, because this corpus reaches a model and from
//     there a pull request body, and aggregate counts answer the question without naming real people;
//   - `session` and no other table. Message text is read by QuestionsSQL, separately and on purpose,
//     so the agent census never depends on the content read succeeding.
const SessionSQL = `
    SELECT coalesce(agent_id, '(none)')                       AS agent,
           count(*)                                            AS all_time,
           count(*) FILTER (WHERE updated_at >= :frm
                              AND updated_at <= :to)           AS in_window,
           count(DISTINCT user_id)                             AS users,
           max(updated_at)                                     AS last_seen
      FROM session
     WHERE deleted_at IS NULL
     GROUP BY coalesce(agent_id, '(none)')
     ORDER BY last_seen DESC NULLS LAST
     LIMIT :lim
`

// WHAT PEOPLE ASKED, which is the one thing this service exists to notice and the one thing metadata
// cannot carry. Read from the SAME Postgres, as the SAME all-users role, as SessionSQL — not through
// kagent's HTTP API, which scopes /api/sessions to the caller.
//
// ONLY USER-AUTHORED EVENTS. Agent replies and tool output are left out on purpose: they are the bulk of
// the table, they are where logs, manifests and credentials pasted back by tools live. Two things decide
// "user-authored", both from kagent 0.10.1's source:
//   - event.data is the ADK Event serialised whole. The Python runtime writes `"author":"user"`; the Go
//     runtime json.Marshal's adk-go's session.Event, whose Author field carries NO json tag
//     (`"Author":"user"`). Both are matched.
//   - session.source = 'agent' marks a session a PARENT AGENT opened over A2A; its "user" turns are a
//     model's delegation prompt, not a person's question.
//
// The LIKE is a prefilter to keep agent output off the wire, never the decision — questionText re-reads
// every row, and QuestionsCensusSQL counts what the prefilter left behind.
const (
	userAuthored = `(e.data LIKE '%"author":"user"%' OR e.data LIKE '%"Author":"user"%')`
	eligible     = `
      FROM event e
      JOIN session s ON s.id = e.session_id AND s.user_id = e.user_id
     WHERE e.deleted_at IS NULL AND s.deleted_at IS NULL
       AND e.created_at >= :frm AND e.created_at <= :to
       -- Implied by the line above (an insert bumps its session's updated_at), and here because
       -- ` + "`" + `event` + "`" + ` has no index on created_at: this lets the planner start from the few sessions active
       -- in the window and reach their events through idx_event_session_id, instead of scanning a
       -- table that has filled a PVC on this platform before.
       AND s.updated_at >= :frm
       AND s.source IS DISTINCT FROM 'agent'
       AND NOT (coalesce(s.agent_id, '') = ANY(string_to_array(:excluded, ',')))
`
)

// QuestionsSQL is bounded three ways in the database: the review window, a message cap per session
// (row_number), and a session cap (LIMIT over the most recently active). No user_id is selected.
const QuestionsSQL = `
    WITH q AS (
    SELECT e.session_id,
           coalesce(s.agent_id, '(none)')                                           AS agent,
           e.created_at,
           e.data,
           row_number() OVER (PARTITION BY e.session_id ORDER BY e.created_at)      AS n,
           count(*)     OVER (PARTITION BY e.session_id)                            AS in_session,
           max(e.created_at) OVER (PARTITION BY e.session_id)                       AS last_at
    ` + eligible + `
       AND ` + userAuthored + `
    )
    SELECT session_id, agent, data, in_session
      FROM q
     WHERE n <= :per
       AND session_id IN (SELECT session_id FROM q GROUP BY session_id
                           ORDER BY max(last_at) DESC LIMIT :sessions)
     ORDER BY last_at DESC, session_id, created_at
`

// QuestionsCensusSQL is the denominator. Without it "no questions" cannot be told apart from "questions
// in a shape we no longer recognise": both return zero rows from QuestionsSQL.
const QuestionsCensusSQL = `
    SELECT count(*)                                              AS events,
           count(*) FILTER (WHERE ` + userAuthored + `)              AS user_authored,
           count(DISTINCT e.session_id) FILTER (WHERE ` + userAuthored + `) AS sessions,
           count(DISTINCT e.session_id)                          AS active
    ` + eligible + `
`

// AgentKey is kagent's agent_id: ConvertToPythonIdentifier(namespace + "/" + name).
func AgentKey(nsName string) string {
	return strings.ReplaceAll(strings.ReplaceAll(py.Strip(nsName), "-", "_"), "/", "__NS__")
}

// QuestionText is the text of one stored event IF a person wrote it, and its shape:
//
//	matched      a user-authored event with text — a question
//	unmatched    valid JSON that is not a user's text: a HITL approval, a thought, or an unknown shape
//	unparseable  not a JSON object at all
//	empty        no payload
//
// Lumping unparseable into empty would hide a decoding problem behind legitimately empty events, and
// lumping unmatched into matched-with-no-text is how a renamed field reads as a quiet night.
func QuestionText(data any) (string, string) {
	if data == nil {
		return "", "empty"
	}
	ev := data
	if s, ok := data.(string); ok {
		if py.Strip(s) == "" {
			return "", "empty"
		}
		parsed, err := py.LoadsJSON(s, false)
		if err != nil {
			return "", "unparseable"
		}
		ev = parsed
	}
	if !py.IsDict(ev) {
		return "", "unparseable"
	}
	// Python runtime: snake_case pydantic dump. Go runtime: untagged exported fields, so Author and
	// Content are capitalised while genai.Content's own tags keep `parts`/`role`/`text` lowercase.
	author := getEither(ev, "author", "Author")
	content := getEither(ev, "content", "Content")
	if author != "user" || !py.IsDict(content) {
		return "", "unmatched"
	}
	var texts []string
	for _, p := range py.List(py.Get(content, "parts")) {
		t, ok := py.Get(p, "text").(string)
		if py.IsDict(p) && ok && py.Strip(t) != "" && !py.Truthy(py.Get(p, "thought")) {
			texts = append(texts, t)
		}
	}
	if len(texts) == 0 {
		return "", "unmatched"
	}
	for i, t := range texts {
		texts[i] = py.Strip(t)
	}
	return strings.Join(texts, "\n"), "matched"
}

// getEither is ev.get(a, ev.get(b)): the first key wins whenever it is present, even holding null.
func getEither(ev any, a, b string) any {
	if py.Has(ev, a) {
		return py.Get(ev, a)
	}
	return py.Get(ev, b)
}

func toInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

// ReadQuestions returns the questions block's lines, filling the question stats as a side effect —
// before any error, so a failed read still records the shapes that explain it. It fails on a database
// error or an unreadable corpus, so the caller can degrade the source without losing the metadata half.
func ReadQuestions(ctx context.Context, conn pg.Conn, window prompt.Window, stats Stats) ([]string, error) {
	if QuestionsMaxSessions <= 0 {
		stats["note"] = "question reading disabled (maxSessions: 0)"
		return []string{}, nil
	}
	var excludedKeys []string
	for _, a := range strings.Split(QuestionsExcludeAgents, ",") {
		if py.Strip(a) != "" {
			excludedKeys = append(excludedKeys, AgentKey(a))
		}
	}
	excluded := strings.Join(excludedKeys, ",")
	census, err := conn.Run(ctx, QuestionsCensusSQL, map[string]any{"frm": window.From, "to": window.To, "excluded": excluded})
	if err != nil {
		return nil, err
	}
	if len(census) != 1 || len(census[0]) != 4 {
		return nil, py.Errorf("ValueError", "too many values to unpack (expected 1)")
	}
	events, userAuthoredN, sessions, active := toInt(census[0][0]), toInt(census[0][1]), toInt(census[0][2]), toInt(census[0][3])
	rows, err := conn.Run(ctx, QuestionsSQL, map[string]any{"per": QuestionsPerSession, "sessions": QuestionsMaxSessions,
		"frm": window.From, "to": window.To, "excluded": excluded})
	if err != nil {
		return nil, err
	}

	notUser := events - userAuthoredN
	if notUser < 0 {
		notUser = 0
	}
	shapes := py.O("matched", int64(0), "unmatched", int64(0), "unparseable", int64(0), "empty", int64(0),
		// Everything the prefilter left in the database: agent replies, tool calls and results.
		"notUserAuthored", notUser)
	type session struct {
		agent string
		texts []string
		total int64
	}
	bySession := map[any]*session{}
	var order []any
	// BENCHMARK AGENTS NEVER FEED THE REVIEW. The analyse stage already skips `*-bench`
	// (AGENT_ANALYSIS_EXCLUDE_AGENTS); this read only excluded the reviewer, so a k8s-agent-bench
	// question reached the main review through this block. Bench traffic is scripted, not a person, and
	// nothing derived from it may become product content. The patterns are the stage's own, rewritten
	// into kagent's agent_id form ("*-bench" -> "*_bench") because that is what `agent` holds.
	var bench []string
	for _, p := range strings.Split(os.Getenv("AGENT_ANALYSIS_EXCLUDE_AGENTS"), ",") {
		if py.Strip(p) != "" {
			bench = append(bench, AgentKey(p))
		}
	}
	for _, row := range rows {
		sessionID, agent, data, total := row[0], py.String(row[1]), row[2], toInt(row[3])
		if len(bench) > 0 {
			skip := false
			_, _, tail := rpartition(agent, "__NS__")
			for _, p := range bench {
				if py.Fnmatchcase(agent, p) || py.Fnmatchcase(tail, p) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
		}
		text, shape := QuestionText(data)
		cur, _ := shapes.Get(shape)
		shapes.Set(shape, cur.(int64)+1)
		key := sessionKey(sessionID)
		if _, ok := bySession[key]; !ok {
			bySession[key] = &session{agent: agent, total: total}
			order = append(order, key)
		}
		if text != "" {
			bySession[key].texts = append(bySession[key].texts, text)
		}
	}

	var lines []string
	var quoted, droppedMsgs, droppedChars int64
	for i, sid := range order {
		s := bySession[sid]
		if extra := s.total - int64(QuestionsPerSession); extra > 0 {
			droppedMsgs += extra
		}
		budget := QuestionsCharsPerSession
		var out []string
		for _, t := range s.texts {
			// REDACT BEFORE CUTTING. A token cut in half by the budget is no longer long enough to match
			// its pattern, so truncating first would hand the model the first half of a credential.
			t = proposals.RedactString(t)
			n := py.Len(t)
			if budget <= 0 {
				droppedMsgs++
				droppedChars += int64(n)
				continue
			}
			if n > budget {
				droppedChars += int64(n - budget)
				t = py.Trunc(t, budget) + " …[cut]"
			}
			budget -= py.Len(t)
			out = append(out, "    > "+strings.ReplaceAll(t, "\n", "\n      "))
		}
		if len(out) > 0 {
			quoted += int64(len(out))
			lines = append(lines, fmt.Sprintf("  - conversation %d with %s:", i+1, s.agent))
			lines = append(lines, out...)
		}
	}
	droppedSessions := sessions - int64(len(order))
	if droppedSessions < 0 {
		droppedSessions = 0
	}

	stats["questions"] = quoted
	stats["questionSessions"] = int64(len(order))
	stats["shapes"] = shapes
	if droppedMsgs > 0 || droppedChars > 0 || droppedSessions > 0 {
		// The fields every source already uses for "the model did not see all of it".
		stats["truncated"] = true
		stats["droppedChars"] = py.Int(stats["droppedChars"]) + droppedChars
		stats["droppedMessages"] = droppedMsgs
		stats["droppedSessions"] = droppedSessions
	}
	// AN UNREADABLE CORPUS MUST NOT LOOK LIKE A QUIET NIGHT. People talked to agents inside the window and
	// not one question came out: either the stored shape changed or the prefilter no longer matches it.
	matched, _ := shapes.Get("matched")
	if events != 0 && matched.(int64) == 0 {
		return nil, py.Errorf("RuntimeError", "%d event(s) in the window but no question recognised (shapes %s); "+
			"the stored event shape may have changed", events, py.Repr(shapes))
	}
	// THE PARTIAL VERSION OF THE SAME FAILURE. Two runtimes write two spellings; if one of them changes,
	// the other still matches and the total above never reaches zero — a night would quietly lose every
	// conversation with, on 057, 13 of 16 agents. A note, not an error: it is a suspicion, and the
	// questions that WERE read are real.
	if silent := active - sessions; silent != 0 && silent*2 >= active {
		stats["note"] = fmt.Sprintf("%d of %d conversation(s) active in the window had no recognisable question — "+
			"one runtime's stored event shape may have changed", silent, active)
	}
	if len(lines) == 0 {
		return []string{}, nil
	}
	return append([]string{fmt.Sprintf("- QUESTIONS PEOPLE ASKED in this window (%d quoted from %d conversation(s), "+
		"user-authored only, redacted):", quoted, len(order))}, lines...), nil
}

// sessionKey makes a row's session id usable as a map key (ids arrive as strings or numbers).
func sessionKey(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case nil, string, int64, int, float64, bool:
		return x
	}
	return fmt.Sprintf("%v", v)
}

func rpartition(s, sep string) (string, string, string) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", s
	}
	return s[:i], sep, s[i+len(sep):]
}

// SessionsBody is the kagent-sessions block, which still remembers which lines were questions and
// whose. It exists for FoldQuestions: the agent-analysis stage runs AFTER this source and reads the
// same people's messages in full, so the questions it covered are paid for twice unless they can be
// taken back out — and taking them out of the rendered text by pattern would be parsing our own output
// after the cap had already cut it.
type SessionsBody struct {
	Text      string
	Head      []string
	Questions []string
	Snapshot  map[string]any
	snapKeys  []string
}

var truncationKeys = []string{"truncated", "truncatedAtChars", "droppedChars"}

func sessionsBody(head, questions []string, stats Stats) *SessionsBody {
	snap := map[string]any{}
	for _, k := range truncationKeys {
		snap[k] = stats[k]
	}
	text := Cap(proposals.RedactString(strings.Join(append(append([]string{}, head...), questions...), "\n")), stats)
	return &SessionsBody{Text: text, Head: head, Questions: questions, Snapshot: snap, snapKeys: truncationKeys}
}

// NewSessionsBody builds a SessionsBody from its head and question lines, capped and redacted, with the
// truncation fields recorded on stats (exposed for tests and FoldQuestions).
func NewSessionsBody(head, questions []string, stats Stats) *SessionsBody {
	return sessionsBody(head, questions, stats)
}

// KagentSessions reports which agents are being USED, and — the part that matters — which are not.
//
// THE FIRST VERSION OF THIS WAS SHAPED WRONG AND THE MODEL CORRECTLY IGNORED IT. It grouped sessions
// inside the review window, so it reported four healthy agents and a total: a census, with nothing in it
// to propose. WORSE, THE WINDOW DESTROYED THE ONE REAL SIGNAL: an agent idle for three weeks does not
// appear at all. So the window no longer filters; it only marks which agents were active inside it.
//
// WHY IT READS THE DEPLOYED SET TOO. An agent that has never had a session has no row to group, so the
// only way to see it is to compare against what is deployed. kagent's agent_id is
// ConvertToPythonIdentifier(namespace + "/" + name), so the two sides can be matched.
//
// AND WHAT PEOPLE ASKED, on the same connection and after the census: see QuestionsSQL. That half fails
// on its own, so a role still revoked on `event` costs the questions and not the census.
func KagentSessions(ctx context.Context, api kube.CustomObjects, window prompt.Window, limit int) (*SessionsBody, Stats) {
	if !(KagentDBUser != "" && KagentDBPassword != "") {
		return nil, Stats{"ok": false, "error": "kagent DB credentials not configured (KAGENT_DB_USER/PASSWORD)"}
	}
	var questions []string
	questionsErr := ""
	qstats := Stats{}
	conn, err := pg.Connect(ctx, pg.Params{User: KagentDBUser, Password: KagentDBPassword, Host: KagentDBHost,
		Port: KagentDBPort, Database: KagentDBName, Timeout: 30 * time.Second})
	if err != nil {
		return nil, Stats{"ok": false, "error": py.Trunc(proposals.RedactString("session query: "+err.Error()), 300)}
	}
	rows, err := conn.Run(ctx, SessionSQL, map[string]any{"frm": window.From, "to": window.To, "lim": limit})
	if err == nil {
		// THE QUESTIONS FAIL ON THEIR OWN. A role still revoked on `event`, or a shape this reader no
		// longer recognises, must cost the questions and not the idle/never-used findings beside them.
		var qerr error
		questions, qerr = ReadQuestions(ctx, conn, window, qstats)
		if qerr != nil {
			questions = nil
			questionsErr = py.Trunc(proposals.RedactString("questions: "+qerr.Error()), 300)
		}
	}
	conn.Close()
	if err != nil {
		return nil, Stats{"ok": false, "error": py.Trunc(proposals.RedactString("session query: "+err.Error()), 300)}
	}

	// The deployed set. A failure here is NOT fatal: the session half still carries the staleness
	// signal, so degrade to "no deployed-set comparison" and say so rather than losing the whole source.
	deployed := map[string]string{}
	deployedErr := ""
	if got, err := api.ListCluster(ctx, "kagent.dev", "v1alpha1", "agents", kube.ListOpts{}); err != nil {
		deployedErr = py.Trunc(err.Error(), 160)
	} else {
		for _, a := range py.List(got["items"]) {
			md := py.Get(a, "metadata")
			if !py.Has(md, "namespace") || !py.Has(md, "name") {
				missing := "namespace"
				if py.Has(md, "namespace") {
					missing = "name"
				}
				if !py.Has(a, "metadata") {
					missing = "metadata"
				}
				deployedErr = py.Trunc(py.StrRepr(missing), 160) // str(KeyError(k))
				break
			}
			nsName := py.Str(py.Get(md, "namespace")) + "/" + py.Str(py.Get(md, "name"))
			deployed[AgentKey(nsName)] = nsName
		}
	}

	now := py.Now()
	type seenRow struct {
		allTime, inWindow, users int64
		idle                     *int64
	}
	seen := map[string]seenRow{}
	var seenOrder []string
	for _, r := range rows {
		agent := py.String(r[0])
		row := seenRow{allTime: toInt(r[1]), inWindow: toInt(r[2]), users: toInt(r[3])}
		if ts, ok := r[4].(time.Time); ok {
			d := py.TimedeltaDays(now, ts)
			row.idle = &d
		}
		if _, ok := seen[agent]; !ok {
			seenOrder = append(seenOrder, agent)
		}
		seen[agent] = row
	}

	// EVERY FINDING IS GATED ON THE AGENT STILL BEING DEPLOYED. Session rows outlive the agent that made
	// them: delete an agent and its history stays, so a source that derives staleness from sessions alone
	// reports "IDLE 21d" forever for something that no longer exists. When the deployed set could not be
	// read we cannot make that distinction, so `live` falls back to every agent seen and the note says
	// the comparison was unavailable — over-reporting with an explanation, never silently nothing.
	live := map[string]bool{}
	if len(deployed) > 0 {
		for k := range deployed {
			live[k] = true
		}
	} else {
		for k := range seen {
			live[k] = true
		}
	}
	var never []string
	if len(deployed) > 0 {
		for k, v := range deployed {
			if _, ok := seen[k]; !ok {
				never = append(never, v)
			}
		}
		sort.Strings(never)
	}
	type pair struct {
		n int64
		k string
	}
	var stale, rare, active []pair
	for _, k := range seenOrder {
		v := seen[k]
		if !live[k] {
			continue
		}
		if v.idle != nil && *v.idle >= 7 {
			stale = append(stale, pair{*v.idle, k})
		}
		if v.allTime <= 3 {
			rare = append(rare, pair{v.allTime, k})
		}
		if v.inWindow > 0 {
			active = append(active, pair{v.inWindow, k})
		}
	}
	less := func(a, b pair) bool { return a.n < b.n || (a.n == b.n && a.k < b.k) }
	sort.Slice(stale, func(i, j int) bool { return less(stale[j], stale[i]) })
	sort.Slice(rare, func(i, j int) bool { return less(rare[i], rare[j]) })
	sort.Slice(active, func(i, j int) bool { return less(active[j], active[i]) })

	// Problems first. The model reads this top-down and the interesting rows must not be buried under a
	// census of everything that is fine.
	var lines []string
	if len(never) > 0 {
		lines = append(lines, fmt.Sprintf("- DEPLOYED BUT NEVER USED (%d): %s — no session has ever existed for these; "+
			"either unreachable, undiscoverable, or no longer wanted", len(never), strings.Join(never, ", ")))
	}
	for _, s := range stale {
		v := seen[s.k]
		lines = append(lines, fmt.Sprintf("- IDLE %dd: %s — %d sessions all-time, last activity %d days ago, %d in this window",
			s.n, s.k, v.allTime, s.n, v.inWindow))
	}
	for _, r := range rare {
		lines = append(lines, fmt.Sprintf("- BARELY EVER USED: %s — %d session(s) in its entire history", r.k, r.n))
	}
	for _, a := range active {
		v := seen[a.k]
		lines = append(lines, fmt.Sprintf("- active: %s — %d sessions in window, %d all-time, %d distinct users",
			a.k, a.n, v.allTime, v.users))
	}
	if deployedErr != "" {
		lines = append(lines, fmt.Sprintf("- NOTE: the deployed-agent list could not be read (%s), so 'never used' "+
			"could not be computed; idle/active figures are unaffected", deployedErr))
	}
	head := lines
	// The questions go AFTER the agent findings: absence first, then what the present users asked.
	lines = append(append([]string{}, lines...), questions...)

	var agentsDeployed any = int64(len(deployed))
	if len(deployed) == 0 {
		agentsDeployed = nil
	}
	stats := Stats{"ok": true, "queried": 1, "returned": int64(len(rows)),
		"agentsDeployed": agentsDeployed, "agentsNeverUsed": int64(len(never)),
		"agentsIdle7d": int64(len(stale)), "agentsActiveInWindow": int64(len(active)),
		"scope": "all-users: session metadata, and the text of USER-AUTHORED messages inside the window, redacted " +
			"(SELECT on session and event; never task, never user ids)"}
	var notes []string
	if n, ok := qstats["note"]; ok {
		if py.Truthy(n) {
			notes = append(notes, py.Str(n))
		}
		delete(qstats, "note")
	}
	if deployedErr != "" {
		notes = append(notes, "deployed-agent list unreadable: "+deployedErr)
	}
	for k, v := range qstats {
		stats[k] = v
	}
	if questionsErr != "" {
		// DEGRADED, NOT BLANKED. The metadata half still answers; ok:false is what makes the run
		// PartiallyCompleted, because a review that meant to read the questions and could not is a
		// half-finished review, and the record must not read like a quiet night.
		stats["ok"] = false
		stats["error"] = questionsErr
	}
	if len(notes) > 0 {
		stats["note"] = strings.Join(notes, "; ")
	}
	if len(lines) == 0 {
		stats["empty"] = true
		stats["note"] = "no kagent agents and no sessions found at all"
		return nil, stats
	}
	return sessionsBody(head, questions, stats), stats
}

var conversationRE = pyre.MustCompile(`^  - conversation \d+ with (\S+):$`, 0)

// FoldQuestions replaces the questions of every agent in `covered` (kagent agent_ids) by one pointer
// line each, re-capped, with the truncation fields recomputed for what is now sent. The census half —
// idle, never used, active — and the questions of agents the analysis did NOT read are untouched: those
// still reach the review only here.
func FoldQuestions(body *SessionsBody, stats Stats, covered map[string]bool) *SessionsBody {
	if body == nil || len(covered) == 0 || len(body.Questions) == 0 {
		return body
	}
	header := body.Questions[0]
	type group struct {
		agent string
		lines []string
	}
	var groups []*group
	for _, line := range body.Questions[1:] {
		if m := conversationRE.Match(line); m != nil {
			groups = append(groups, &group{agent: m.Group(1), lines: []string{line}})
		} else if len(groups) > 0 {
			groups[len(groups)-1].lines = append(groups[len(groups)-1].lines, line)
		}
	}
	folded := map[string]int{}
	for _, g := range groups {
		if covered[g.agent] {
			folded[g.agent]++
		}
	}
	if len(folded) == 0 {
		return body
	}
	var kept []string
	for _, g := range groups {
		if !covered[g.agent] {
			kept = append(kept, g.lines...)
		}
	}
	var questions []string
	if len(kept) > 0 {
		questions = append([]string{header}, kept...)
	}
	total := 0
	for _, agent := range py.SortedKeys(folded) {
		questions = append(questions, fmt.Sprintf("- QUESTIONS to %s in %d conversation(s): read IN FULL by "+
			"agent-analysis, with the replies and tool calls — see that evidence; not repeated here", agent, folded[agent]))
		total += folded[agent]
	}
	for _, k := range body.snapKeys {
		if v := body.Snapshot[k]; v == nil {
			delete(stats, k)
		} else {
			stats[k] = v
		}
	}
	stats["questionsFolded"] = int64(total)
	return sessionsBody(body.Head, questions, stats)
}

// Kubernetes lists what the platform ALREADY has, so the agent proposes gaps rather than duplicates.
//
// Without this the most likely proposal every night is an alert for something already alerted on — the
// model cannot know what exists unless it is shown. The same holds for Widget proposals, which is why
// page roots are listed too.
//
// EACH READ FAILS ON ITS OWN. A cluster without one of these kinds is a normal condition, so a read that
// errors is recorded and the others still answer; the source is degraded, never blanked by it.
func Kubernetes(ctx context.Context, api kube.CustomObjects) (string, Stats) {
	ns := env.Str("NAMESPACE", "krateo-system")
	var blocks []string
	st := Stats{"ok": true, "queried": int64(0), "returned": int64(0)}
	read := func(what, group, version, plural string, render func(any) string, keep func(any) bool, limit int) {
		got, err := api.ListNamespaced(ctx, group, version, ns, plural)
		if err != nil {
			st["ok"] = false
			st["error"] = py.Str(py.Or(st["error"], "")) + what + ": " + py.Trunc(err.Error(), 160) + "; "
			return
		}
		var items []any
		for _, i := range py.List(got["items"]) {
			if keep == nil || keep(i) {
				items = append(items, i)
			}
		}
		st["queried"] = py.Int(st["queried"]) + 1
		st["returned"] = py.Int(st["returned"]) + int64(len(items))
		sort.SliceStable(items, func(a, b int) bool {
			return py.Str(py.GetPath(items[a], "metadata", "name")) < py.Str(py.GetPath(items[b], "metadata", "name"))
		})
		shown := items
		if limit > 0 && len(items) > limit {
			shown = items[:limit]
		}
		var lines []string
		for _, i := range shown {
			lines = append(lines, render(i))
		}
		if len(items) > len(shown) {
			lines = append(lines, fmt.Sprintf("- ... and %d more %s not listed", len(items)-len(shown), what))
			st["note"] = py.Str(py.Or(st["note"], "")) + fmt.Sprintf("%s: listed %d of %d; ", what, len(shown), len(items))
		}
		if len(lines) > 0 {
			blocks = append(blocks, strings.Join(lines, "\n"))
		}
	}

	read("alerts", "observability.krateo.io", "v1alpha1", "alerts", func(a any) string {
		spec := py.Or(py.Get(a, "spec"), map[string]any{})
		display := any("")
		if py.Has(spec, "displayName") {
			display = py.Get(spec, "displayName")
		}
		thresholdType := any("")
		if py.Has(spec, "thresholdType") {
			thresholdType = py.Get(spec, "thresholdType")
		}
		return fmt.Sprintf("- existing Alert %s: %s threshold=%s %s", py.Str(py.GetPath(a, "metadata", "name")),
			py.Repr(display), py.Str(py.Get(spec, "threshold")), py.Str(thresholdType))
	}, nil, 0)

	// THERE IS NO Page KIND. templates.krateo.io serves only restactions; a portal page IS a Flex widget
	// whose name begins with "page-", and its route is the krateo.io/nav-path annotation when it has one.
	// Listed in this namespace only, which is also what keeps krateo-preview's draft page roots out.
	read("pages", "widgets.templates.krateo.io", "v1beta1", "flexes", func(f any) string {
		line := "- existing Page " + py.Str(py.GetPath(f, "metadata", "name"))
		if nav := py.Get(py.GetPath(f, "metadata", "annotations"), "krateo.io/nav-path"); py.Truthy(nav) {
			line += " at " + py.Str(nav)
		}
		return line
	}, func(f any) bool {
		return strings.HasPrefix(py.String(py.GetPath(f, "metadata", "name")), "page-")
	}, MaxPages)

	if len(blocks) == 0 {
		if st["ok"] == true {
			// Read and found nothing: explained emptiness, which the run does not count as degraded.
			st["empty"] = true
			st["note"] = fmt.Sprintf("no Alerts and no page roots in %s", ns)
		}
		return "", st
	}
	return Cap(strings.Join(blocks, "\n"), st), st
}
