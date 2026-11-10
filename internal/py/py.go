// Package py holds the small pieces of Python semantics the rest of the port depends on to produce
// the same bytes as the Python service did: str()/repr(), str.strip()/split()/splitlines()/lower(),
// code-point slicing, truthiness, f"{n:,}", and the exception-name convention used in messages.
//
// WHY A PACKAGE OF ITS OWN. The service writes strings that people and the next night's run compare
// against: fingerprints, subjects, condition messages, prompt text. Go's strings package disagrees with
// Python's str in small ways that matter there — strings.TrimSpace does not strip \x1c-\x1f, s[:n] cuts
// bytes rather than code points, strings.ToLower maps U+0130 to one rune where Python yields two. Each
// such difference is resolved once, here, against CPython 3.12.
package py

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsSpace is str.isspace() for one code point (Py_UNICODE_ISSPACE): the Unicode whitespace set plus
// the ASCII information separators \x1c-\x1f, which unicode.IsSpace leaves out.
func IsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680, 0x2028, 0x2029,
		0x202f, 0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// Strip is str.strip() with no argument.
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// LStripSpace is str.lstrip() with no argument.
func LStripSpace(s string) string { return strings.TrimLeftFunc(s, IsSpace) }

// RStripSpace is str.rstrip() with no argument.
func RStripSpace(s string) string { return strings.TrimRightFunc(s, IsSpace) }

// StripChars is str.strip(chars).
func StripChars(s, chars string) string { return strings.Trim(s, chars) }

// LStripChars is str.lstrip(chars).
func LStripChars(s, chars string) string { return strings.TrimLeft(s, chars) }

// RStripChars is str.rstrip(chars).
func RStripChars(s, chars string) string { return strings.TrimRight(s, chars) }

// Split is str.split() with no argument: runs of Python whitespace separate, and leading/trailing
// whitespace yields no empty fields.
func Split(s string) []string { return strings.FieldsFunc(s, IsSpace) }

// JoinFields is " ".join(s.split()), the idiom the service uses to collapse whitespace.
func JoinFields(s string) string { return strings.Join(Split(s), " ") }

// SplitLines is str.splitlines() (keepends=False). Python breaks on \n, \r, \r\n, \v, \f, \x1c, \x1d,
// \x1e, \x85,   and   — far more than "\n".
func SplitLines(s string) []string { return splitLines(s, false) }

// SplitLinesKeep is str.splitlines(True).
func SplitLinesKeep(s string) []string { return splitLines(s, true) }

func splitLines(s string, keep bool) []string {
	var out []string
	start := 0
	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		eol := 0
		switch r {
		case '\r':
			eol = 1
			if i+1 < len(s) && s[i+1] == '\n' {
				eol = 2
			}
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			eol = size
		}
		if eol == 0 {
			i += size
			continue
		}
		if keep {
			out = append(out, s[start:i+eol])
		} else {
			out = append(out, s[start:i])
		}
		i += eol
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// Lower is str.lower(): full Unicode lowercasing. The one unconditional multi-rune mapping is U+0130
// (İ -> "i̇"); Final_Sigma only chooses between two non-ASCII letters, which no caller distinguishes.
func Lower(s string) string {
	if !strings.ContainsRune(s, 0x130) {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r == 0x130 {
			b.WriteString("i̇")
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// Len is len(s) for a Python str: code points, not bytes.
func Len(s string) int { return utf8.RuneCountInString(s) }

// Trunc is s[:n] for a Python str (n >= 0).
func Trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n { // fewer bytes than n means fewer code points too
		return s
	}
	i := 0
	for count := 0; i < len(s) && count < n; count++ {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i]
}

// From is s[n:] for a Python str (n >= 0).
func From(s string, n int) string {
	i := 0
	for count := 0; i < len(s) && count < n; count++ {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[i:]
}

// Thousands is f"{n:,}".
func Thousands(n int64) string {
	neg := n < 0
	s := strconv.FormatInt(n, 10)
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// Truthy is Python truthiness for the JSON-shaped values this service handles.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case *OMap:
		return x != nil && x.Len() > 0
	}
	return true
}

// Or is Python's `a or b`.
func Or(a, b any) any {
	if Truthy(a) {
		return a
	}
	return b
}

// FloatRepr is repr(float) in CPython: the shortest string that round-trips, in fixed notation when
// the decimal exponent is in (-4, 16], scientific otherwise, and always with a '.0' or an exponent.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	neg := strings.HasPrefix(e, "-")
	if neg {
		e = e[1:]
	}
	mant, exps, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(exps)
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1
	var out string
	if decpt > -4 && decpt <= 16 {
		switch {
		case decpt <= 0:
			out = "0." + strings.Repeat("0", -decpt) + digits
		case decpt >= len(digits):
			out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		default:
			out = digits[:decpt] + "." + digits[decpt:]
		}
	} else {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		sign := "+"
		x := decpt - 1
		if x < 0 {
			sign = "-"
			x = -x
		}
		out = fmt.Sprintf("%se%s%02d", m, sign, x)
	}
	if neg {
		return "-" + out
	}
	return out
}

// IsPrintable is str.isprintable() for one code point: assigned, and not in Cc, Cf, Cs, Co, Zl, Zp or
// Zs — except the ASCII space, which is printable.
func IsPrintable(r rune) bool {
	if r == ' ' {
		return true
	}
	if r < 0x20 || r == 0x7f {
		return false
	}
	if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zl, unicode.Zp, unicode.Zs) {
		return false
	}
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// StrRepr is repr(str).
func StrRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < ' ' || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case IsPrintable(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// Repr is repr() for the JSON-shaped values this service handles. A map[string]any has no order of its
// own, so its keys are rendered sorted; an *OMap keeps the order it was decoded in, as a dict would.
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return StrRepr(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return FloatRepr(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = StrRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := SortedKeys(x)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = StrRepr(k) + ": " + Repr(x[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case *OMap:
		parts := make([]string, 0, x.Len())
		for _, k := range x.Keys() {
			val, _ := x.Get(k)
			parts = append(parts, StrRepr(k)+": "+Repr(val))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprintf("%v", v)
}

// Str is str() / format(x, "") — what an f-string interpolates.
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return Repr(v)
}

// SortedKeys returns a map's keys in Python's sorted() order (code-point order, which is UTF-8 byte
// order).
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
