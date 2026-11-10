package pyyaml

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode"
)

// Value is a Python object as SafeConstructor builds it:
//
//	nil (None), bool, int64 or *big.Int (int), float64 (float), string (str), []byte (bytes),
//	*Date (datetime.date), *DateTime (datetime.datetime), *Sequence (list), *Mapping (dict),
//	*Set (set), *Tuple (the (key, value) items of !!omap and !!pairs).
//
// Pointers carry Python object identity: an alias in the source yields the SAME object, and safe_dump writes
// an anchor for any non-scalar object it meets twice.
type Value = any

// Sequence is a Python list.
type Sequence struct{ Items []Value }

// Tuple is a Python tuple.
type Tuple struct{ Items []Value }

// Mapping is a Python dict: insertion-ordered, keys merged by Python equality (1 == 1.0 == True).
type Mapping struct {
	keys []Value
	vals []Value
}

// Set is a Python set (insertion order kept; Python's own iteration order is hash order, see SafeDump).
type Set struct{ Items []Value }

// Date is a datetime.date.
type Date struct{ Year, Month, Day int }

// DateTime is a datetime.datetime, naive or with a fixed UTC offset.
type DateTime struct {
	Year, Month, Day, Hour, Minute, Second, Microsecond int
	Aware                                               bool
	OffsetMinutes                                       int
}

// Get returns the value under a str key.
func (m *Mapping) Get(key string) (Value, bool) {
	for i, k := range m.keys {
		if s, ok := k.(string); ok && s == key {
			return m.vals[i], true
		}
	}
	return nil, false
}

// Len is len(dict).
func (m *Mapping) Len() int { return len(m.keys) }

// Keys returns the keys in insertion order.
func (m *Mapping) Keys() []Value { return append([]Value(nil), m.keys...) }

// Values returns the values in insertion order.
func (m *Mapping) Values() []Value { return append([]Value(nil), m.vals...) }

// set is dict.__setitem__: an equal key keeps its original key object and position, the value is replaced.
func (m *Mapping) set(k, v Value) {
	for i, existing := range m.keys {
		if pyEqual(existing, k) {
			m.vals[i] = v
			return
		}
	}
	m.keys = append(m.keys, k)
	m.vals = append(m.vals, v)
}

func (s *Set) add(k Value) {
	for _, existing := range s.Items {
		if pyEqual(existing, k) {
			return
		}
	}
	s.Items = append(s.Items, k)
}

// IsCollection is isinstance(v, (dict, list)).
func IsCollection(v Value) bool {
	switch v.(type) {
	case *Mapping, *Sequence:
		return true
	}
	return false
}

// Truthy is Python truthiness.
func Truthy(v Value) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []byte:
		return len(x) != 0
	case *Sequence:
		return len(x.Items) != 0
	case *Tuple:
		return len(x.Items) != 0
	case *Mapping:
		return len(x.keys) != 0
	case *Set:
		return len(x.Items) != 0
	}
	return true // date and datetime objects are always true
}

// Hashable reports whether v can be a dict key or set member (isinstance(v, collections.abc.Hashable)).
func Hashable(v Value) bool {
	switch v.(type) {
	case *Sequence, *Mapping, *Set:
		return false
	}
	return true
}

// --- numbers --------------------------------------------------------------------------------------------------

func toRat(v Value) (*big.Rat, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewRat(1, 1), true
		}
		return new(big.Rat), true
	case int64:
		return new(big.Rat).SetInt64(x), true
	case *big.Int:
		return new(big.Rat).SetInt(x), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		r := new(big.Rat)
		r.SetFloat64(x)
		return r, true
	}
	return nil, false
}

func isNumber(v Value) bool {
	switch v.(type) {
	case bool, int64, *big.Int, float64:
		return true
	}
	return false
}

// numCompare compares two Python numbers exactly; ok is false only for NaN (every comparison is False).
func numCompare(a, b Value) (int, bool) {
	fa, aIsF := a.(float64)
	fb, bIsF := b.(float64)
	if (aIsF && math.IsNaN(fa)) || (bIsF && math.IsNaN(fb)) {
		return 0, false
	}
	if aIsF && math.IsInf(fa, 0) || bIsF && math.IsInf(fb, 0) {
		ia, ib := 0, 0
		if aIsF && math.IsInf(fa, 1) {
			ia = 1
		} else if aIsF && math.IsInf(fa, -1) {
			ia = -1
		}
		if bIsF && math.IsInf(fb, 1) {
			ib = 1
		} else if bIsF && math.IsInf(fb, -1) {
			ib = -1
		}
		switch {
		case ia == ib:
			return 0, true
		case ia < ib:
			return -1, true
		}
		return 1, true
	}
	ra, _ := toRat(a)
	rb, _ := toRat(b)
	return ra.Cmp(rb), true
}

// --- dates ----------------------------------------------------------------------------------------------------

func (d *DateTime) utcKey() (int64, int) {
	days := daysFromCivil(d.Year, d.Month, d.Day)
	secs := days*86400 + int64(d.Hour*3600+d.Minute*60+d.Second)
	if d.Aware {
		secs -= int64(d.OffsetMinutes * 60)
	}
	return secs, d.Microsecond
}

func daysFromCivil(y, m, d int) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era = (y - 399) / 400
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return int64(era)*146097 + int64(doe) - 719468
}

// pyEqual is Python ==, as dict and set lookup applies it (all YAML NaNs are one object, so equal).
func pyEqual(a, b Value) bool {
	if isNumber(a) && isNumber(b) {
		fa, aIsF := a.(float64)
		fb, bIsF := b.(float64)
		if aIsF && bIsF && math.IsNaN(fa) && math.IsNaN(fb) {
			return true
		}
		c, ok := numCompare(a, b)
		return ok && c == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []byte:
		y, ok := b.([]byte)
		return ok && string(x) == string(y)
	case *Date:
		y, ok := b.(*Date)
		return ok && *x == *y
	case *DateTime:
		y, ok := b.(*DateTime)
		if !ok || x.Aware != y.Aware {
			return false
		}
		if !x.Aware {
			return *x == *y
		}
		xs, xu := x.utcKey()
		ys, yu := y.utcKey()
		return xs == ys && xu == yu
	}
	return a == b // identity for containers
}

// errUnorderable stands in for the TypeError sorted() raises on keys of incomparable types.
var errUnorderable = fmt.Errorf("unorderable")

// pyLess is Python a < b for the key types a safe-loaded mapping can hold; an error is Python's TypeError.
func pyLess(a, b Value) (bool, error) {
	if isNumber(a) && isNumber(b) {
		c, ok := numCompare(a, b)
		return ok && c < 0, nil
	}
	switch x := a.(type) {
	case string:
		if y, ok := b.(string); ok {
			return x < y, nil // UTF-8 byte order == code point order
		}
	case []byte:
		if y, ok := b.([]byte); ok {
			return string(x) < string(y), nil
		}
	case *Date:
		if y, ok := b.(*Date); ok {
			return daysFromCivil(x.Year, x.Month, x.Day) < daysFromCivil(y.Year, y.Month, y.Day), nil
		}
	case *DateTime:
		if y, ok := b.(*DateTime); ok && x.Aware == y.Aware {
			xs, xu := x.utcKey()
			ys, yu := y.utcKey()
			return xs < ys || (xs == ys && xu < yu), nil
		}
	}
	return false, errUnorderable
}

// --- str() and repr() -------------------------------------------------------------------------------------

// Str is Python str() of a loaded value.
func Str(v Value) string {
	switch x := v.(type) {
	case string:
		return x
	case *Date:
		return fmt.Sprintf("%04d-%02d-%02d", x.Year, x.Month, x.Day)
	case *DateTime:
		return x.isoformat(" ")
	}
	return pyReprValue(v)
}

func (d *DateTime) isoformat(sep string) string {
	s := fmt.Sprintf("%04d-%02d-%02d%s%02d:%02d:%02d", d.Year, d.Month, d.Day, sep, d.Hour, d.Minute, d.Second)
	if d.Microsecond != 0 {
		s += fmt.Sprintf(".%06d", d.Microsecond)
	}
	if d.Aware {
		off := d.OffsetMinutes
		sign := "+"
		if off < 0 {
			sign = "-"
			off = -off
		}
		s += fmt.Sprintf("%s%02d:%02d", sign, off/60, off%60)
	}
	return s
}

func pyReprValue(v Value) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return floatRepr(x)
	case string:
		return pyRepr(x)
	case []byte:
		return bytesRepr(x)
	case *Date:
		return fmt.Sprintf("datetime.date(%d, %d, %d)", x.Year, x.Month, x.Day)
	case *DateTime:
		args := fmt.Sprintf("%d, %d, %d, %d, %d", x.Year, x.Month, x.Day, x.Hour, x.Minute)
		if x.Second != 0 || x.Microsecond != 0 {
			args += fmt.Sprintf(", %d", x.Second)
		}
		if x.Microsecond != 0 {
			args += fmt.Sprintf(", %d", x.Microsecond)
		}
		if x.Aware {
			if x.OffsetMinutes == 0 {
				args += ", tzinfo=datetime.timezone.utc"
			} else {
				args += ", tzinfo=datetime.timezone(" + timedeltaRepr(x.OffsetMinutes) + ")"
			}
		}
		return "datetime.datetime(" + args + ")"
	case *Sequence:
		return "[" + joinRepr(x.Items) + "]"
	case *Tuple:
		if len(x.Items) == 1 {
			return "(" + pyReprValue(x.Items[0]) + ",)"
		}
		return "(" + joinRepr(x.Items) + ")"
	case *Set:
		if len(x.Items) == 0 {
			return "set()"
		}
		return "{" + joinRepr(x.Items) + "}"
	case *Mapping:
		parts := make([]string, len(x.keys))
		for i := range x.keys {
			parts[i] = pyReprValue(x.keys[i]) + ": " + pyReprValue(x.vals[i])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func timedeltaRepr(minutes int) string {
	secs := minutes * 60
	days := 0
	if secs < 0 {
		days = -1
		secs += 86400
	}
	switch {
	case days != 0 && secs != 0:
		return fmt.Sprintf("datetime.timedelta(days=%d, seconds=%d)", days, secs)
	case days != 0:
		return fmt.Sprintf("datetime.timedelta(days=%d)", days)
	}
	return fmt.Sprintf("datetime.timedelta(seconds=%d)", secs)
}

func joinRepr(items []Value) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = pyReprValue(it)
	}
	return strings.Join(parts, ", ")
}

// pyRepr is repr() of a str.
func pyRepr(s string) string {
	quote := '\''
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, r := range s {
		switch {
		case r == quote || r == '\\':
			b.WriteRune('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case isPrintable(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteRune(quote)
	return b.String()
}

// isPrintable approximates str.isprintable for one character: not Cc, Cf, Cs, Co, Cn, Zl, Zp, Zs (but ' ').
func isPrintable(r rune) bool {
	if r == ' ' {
		return true
	}
	return unicode.IsPrint(r)
}

func bytesRepr(b []byte) string {
	quote := byte('\'')
	if strings.IndexByte(string(b), '\'') >= 0 && strings.IndexByte(string(b), '"') < 0 {
		quote = '"'
	}
	var sb strings.Builder
	sb.WriteByte('b')
	sb.WriteByte(quote)
	for _, c := range b {
		switch {
		case c == quote || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&sb, `\x%02x`, c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte(quote)
	return sb.String()
}

// floatRepr is Python repr(float): the shortest round-tripping digits, positional when the decimal exponent
// is in [-4, 16), scientific otherwise.
func floatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // e.g. -1.2345e+06
	neg := strings.HasPrefix(e, "-")
	if neg {
		e = e[1:]
	}
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	var out string
	if exp >= -4 && exp < 16 {
		if exp >= 0 {
			if len(digits) <= exp+1 {
				out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
			} else {
				out = digits[:exp+1] + "." + digits[exp+1:]
			}
		} else {
			out = "0." + strings.Repeat("0", -exp-1) + digits
		}
	} else {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign = "-"
			exp = -exp
		}
		out = fmt.Sprintf("%se%s%02d", m, sign, exp)
	}
	if neg {
		out = "-" + out
	}
	return out
}
