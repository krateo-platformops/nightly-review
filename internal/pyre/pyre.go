// Package pyre compiles the service's Python regular expressions so they match exactly what Python's
// `re` matched.
//
// WHY NOT regexp. Go's RE2 engine has no lookaround, and the service's patterns use it (the prose
// password rule's (?=…\d), the CamelCase split). It also reads \b, \w, \d and \s as ASCII, and its `$`
// only matches at the very end — where Python's str patterns are Unicode-aware and `$` also matches
// before a trailing newline. A redaction pattern that matched a different set of strings would change
// what a Proposal stores and therefore its fingerprint, so the patterns run on regexp2 (a backtracking
// engine with Python's `$`, lookaround and group semantics) after a translation of the escapes and the
// IGNORECASE flag to their exact Python meaning. The translation is checked against CPython by
// pyre_test.go and by the redaction parity fixtures.
package pyre

import (
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"
)

// Flags, as Python's re.I / re.S.
const (
	I = 1 << iota
	S
)

// Python's \s for str patterns: str.isspace() code points.
const ws = `\t\n\x0b\x0c\r\x1c-\x1f \x85\xa0  -     　`

// Python's \w for str patterns: str.isalnum() or "_" — every letter and every number category.
const word = `\p{L}\p{N}_`

// Python's \b, with Python's \w: a boundary is where word-ness changes.
const boundary = `(?:(?<=[` + word + `])(?![` + word + `])|(?<![` + word + `])(?=[` + word + `]))`

// foldExtra is what CPython's IGNORECASE adds beyond the ASCII letter pairs (sre's case equivalence
// table, measured with re.fullmatch over every code point): İ and ı match i, K (Kelvin) matches k,
// ſ (long s) matches s.
var foldExtra = map[rune]string{'i': `İı`, 'k': `K`, 's': `ſ`}

// Regexp is a compiled Python pattern.
type Regexp struct {
	src     string
	search  *regexp2.Regexp
	anchor  *regexp2.Regexp // re.match: anchored at the start
	full    *regexp2.Regexp // re.fullmatch
	ngroups int
}

// MustCompile translates and compiles a Python pattern, panicking on a pattern it cannot translate —
// every pattern is a constant, so that is a programming error caught by the tests.
func MustCompile(pattern string, flags int) *Regexp {
	r, err := Compile(pattern, flags)
	if err != nil {
		panic(err)
	}
	return r
}

// Compile translates and compiles a Python pattern.
func Compile(pattern string, flags int) (*Regexp, error) {
	t, err := translate(pattern, flags)
	if err != nil {
		return nil, fmt.Errorf("pyre: %q: %w", pattern, err)
	}
	opts := regexp2.RegexOptions(0)
	if flags&S != 0 {
		opts |= regexp2.Singleline
	}
	compile := func(p string) (*regexp2.Regexp, error) { return regexp2.Compile(p, opts) }
	out := &Regexp{src: pattern}
	if out.search, err = compile(t); err != nil {
		return nil, fmt.Errorf("pyre: %q -> %q: %w", pattern, t, err)
	}
	if out.anchor, err = compile(`\G(?:` + t + `)`); err != nil {
		return nil, err
	}
	if out.full, err = compile(`\G(?:` + t + `)\z`); err != nil {
		return nil, err
	}
	out.ngroups = len(out.search.GetGroupNumbers()) - 1
	return out, nil
}

// String returns the Python source pattern.
func (r *Regexp) String() string { return r.src }

// Match is a successful match: groups by number, positions in code points.
type Match struct {
	groups []string
	set    []bool
	Start  int
	End    int
}

// Group is m.group(i); a group that did not participate is "".
func (m *Match) Group(i int) string { return m.groups[i] }

// Matched reports whether group i participated (m.group(i) is not None).
func (m *Match) Matched(i int) bool { return m.set[i] }

func (r *Regexp) wrap(m *regexp2.Match) *Match {
	if m == nil {
		return nil
	}
	out := &Match{groups: make([]string, r.ngroups+1), set: make([]bool, r.ngroups+1), Start: m.Index,
		End: m.Index + m.Length}
	for i := 0; i <= r.ngroups; i++ {
		g := m.GroupByNumber(i)
		if g != nil && len(g.Captures) > 0 {
			out.groups[i] = g.String()
			out.set[i] = true
		}
	}
	return out
}

// Search is re.search.
func (r *Regexp) Search(s string) *Match {
	m, err := r.search.FindStringMatch(s)
	if err != nil {
		return nil
	}
	return r.wrap(m)
}

// MatchString is bool(re.search).
func (r *Regexp) MatchString(s string) bool { return r.Search(s) != nil }

// Match is re.match: a match that starts at position 0.
func (r *Regexp) Match(s string) *Match {
	m, err := r.anchor.FindStringMatch(s)
	if err != nil {
		return nil
	}
	return r.wrap(m)
}

// FullMatch is re.fullmatch.
func (r *Regexp) FullMatch(s string) *Match {
	m, err := r.full.FindStringMatch(s)
	if err != nil {
		return nil
	}
	return r.wrap(m)
}

// SubFunc is re.sub(pattern, func, s).
func (r *Regexp) SubFunc(s string, f func(*Match) string) string {
	rs := []rune(s)
	var b strings.Builder
	last := 0
	m, err := r.search.FindStringMatch(s)
	for err == nil && m != nil {
		w := r.wrap(m)
		b.WriteString(string(rs[last:w.Start]))
		b.WriteString(f(w))
		last = w.End
		m, err = r.search.FindNextMatch(m)
	}
	b.WriteString(string(rs[last:]))
	return b.String()
}

// Sub is re.sub(pattern, repl, s) with a template: \1-\99 and \g<n> refer to groups (a group that did
// not participate expands to ""), and \\ \n \t are the usual escapes.
func (r *Regexp) Sub(s, repl string) string {
	parts := parseTemplate(repl)
	return r.SubFunc(s, func(m *Match) string {
		var b strings.Builder
		for _, p := range parts {
			if p.group >= 0 {
				b.WriteString(m.Group(p.group))
			} else {
				b.WriteString(p.lit)
			}
		}
		return b.String()
	})
}

type tmplPart struct {
	lit   string
	group int
}

func parseTemplate(t string) []tmplPart {
	var out []tmplPart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, tmplPart{lit: lit.String(), group: -1})
			lit.Reset()
		}
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c != '\\' || i+1 >= len(t) {
			lit.WriteByte(c)
			continue
		}
		n := t[i+1]
		switch {
		case n >= '0' && n <= '9':
			g := int(n - '0')
			i++
			if i+1 < len(t) && t[i+1] >= '0' && t[i+1] <= '9' {
				g = g*10 + int(t[i+1]-'0')
				i++
			}
			flush()
			out = append(out, tmplPart{group: g})
		case n == 'g' && i+2 < len(t) && t[i+2] == '<':
			end := strings.IndexByte(t[i+3:], '>')
			var g int
			_, _ = fmt.Sscanf(t[i+3:i+3+end], "%d", &g)
			flush()
			out = append(out, tmplPart{group: g})
			i += 3 + end
		case n == 'n':
			lit.WriteByte('\n')
			i++
		case n == 't':
			lit.WriteByte('\t')
			i++
		case n == '\\':
			lit.WriteByte('\\')
			i++
		default:
			lit.WriteByte('\\')
		}
	}
	flush()
	return out
}

// Split is re.split(pattern, s) for a pattern without capturing groups.
func (r *Regexp) Split(s string) []string {
	rs := []rune(s)
	var out []string
	last := 0
	m, err := r.search.FindStringMatch(s)
	for err == nil && m != nil {
		out = append(out, string(rs[last:m.Index]))
		last = m.Index + m.Length
		m, err = r.search.FindNextMatch(m)
	}
	return append(out, string(rs[last:]))
}

// translate rewrites Python escapes and IGNORECASE into regexp2 syntax with Python's meaning.
func translate(p string, flags int) (string, error) {
	rs := []rune(p)
	if strings.HasPrefix(p, "(?i)") {
		flags |= I
		rs = rs[4:]
	}
	icase := flags&I != 0
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\\':
			if i+1 >= len(rs) {
				return "", fmt.Errorf("trailing backslash")
			}
			i++
			switch e := rs[i]; e {
			case 'd':
				b.WriteString(`\p{Nd}`)
			case 'D':
				b.WriteString(`\P{Nd}`)
			case 'w':
				b.WriteString(`[` + word + `]`)
			case 'W':
				b.WriteString(`[^` + word + `]`)
			case 's':
				b.WriteString(`[` + ws + `]`)
			case 'S':
				b.WriteString(`[^` + ws + `]`)
			case 'b':
				b.WriteString(boundary)
			case 'Z':
				b.WriteString(`\z`)
			case 'B', 'A':
				return "", fmt.Errorf(`\%c is not supported`, e)
			default:
				b.WriteRune('\\')
				b.WriteRune(e)
				i += copyHex(&b, rs, i, e)
			}
		case c == '[':
			j, cls, err := translateClass(rs, i, icase)
			if err != nil {
				return "", err
			}
			b.WriteString(cls)
			i = j
		case c == '(' && i+1 < len(rs) && rs[i+1] == '?':
			// group syntax passes through unchanged: (?:, (?=, (?!, (?<=, (?<!. Named groups are refused:
			// regexp2 numbers them after every unnamed group, where Python numbers all groups left to right.
			if i+2 < len(rs) && (rs[i+2] == 'P' || (rs[i+2] == '<' && i+3 < len(rs) && rs[i+3] != '=' && rs[i+3] != '!')) {
				return "", fmt.Errorf("named groups are not supported")
			}
			b.WriteString("(?")
			i++
		case icase && isASCIILetter(c):
			b.WriteString("[" + foldSet(c) + "]")
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), nil
}

func isASCIILetter(c rune) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func lowerASCII(c rune) rune {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func foldSet(c rune) string {
	l := lowerASCII(c)
	return string(l) + string(l-32) + foldExtra[l]
}

// translateClass translates the class starting at rs[i] == '[' and returns the index of its ']'.
func translateClass(rs []rune, i int, icase bool) (int, string, error) {
	var b strings.Builder
	b.WriteByte('[')
	j := i + 1
	if j < len(rs) && rs[j] == '^' {
		b.WriteByte('^')
		j++
	}
	first := true
	var letters []rune // ASCII letters the class contains, for IGNORECASE
	for ; j < len(rs); j++ {
		c := rs[j]
		if c == ']' && !first {
			if icase {
				seen := map[rune]bool{}
				for _, l := range letters {
					l = lowerASCII(l)
					if !seen[l] {
						seen[l] = true
						b.WriteString(foldSet(l))
					}
				}
			}
			b.WriteByte(']')
			return j, b.String(), nil
		}
		first = false
		if c == '\\' && j+1 < len(rs) {
			j++
			switch e := rs[j]; e {
			case 'd':
				b.WriteString(`\p{Nd}`)
			case 'w':
				b.WriteString(word)
			case 's':
				b.WriteString(ws)
			case 'D', 'W', 'S':
				return 0, "", fmt.Errorf(`\%c inside a class is not supported`, e)
			default:
				b.WriteRune('\\')
				b.WriteRune(e)
				j += copyHex(&b, rs, j, e)
			}
			continue
		}
		// a range a-z: record every ASCII letter it covers
		if j+2 < len(rs) && rs[j+1] == '-' && rs[j+2] != ']' {
			lo, hi := c, rs[j+2]
			if hi == '\\' {
				return 0, "", fmt.Errorf("escaped range end is not supported")
			}
			for x := lo; x <= hi; x++ {
				if isASCIILetter(x) {
					letters = append(letters, x)
				}
			}
			b.WriteRune(lo)
			b.WriteByte('-')
			b.WriteRune(hi)
			j += 2
			continue
		}
		if isASCIILetter(c) {
			letters = append(letters, c)
		}
		if c == '[' {
			b.WriteString(`\[`)
			continue
		}
		b.WriteRune(c)
	}
	return 0, "", fmt.Errorf("unterminated class")
}

// copyHex copies the hex digits of a \xHH or \uHHHH escape whose letter is at rs[i], untouched by the
// IGNORECASE expansion, and returns how many it copied.
func copyHex(b *strings.Builder, rs []rune, i int, e rune) int {
	n := map[rune]int{'x': 2, 'u': 4}[e]
	if i+n >= len(rs) {
		n = len(rs) - 1 - i
	}
	for k := 1; k <= n; k++ {
		b.WriteRune(rs[i+k])
	}
	return n
}
