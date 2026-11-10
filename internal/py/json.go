package py

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// OMap is a JSON object that remembers the order its keys arrived in, as a Python dict does. It is
// used where that order reaches output: a model response (validation messages quote it), the chart's
// JSON values (a later key that normalises like an earlier one wins), an A2A error object.
type OMap struct {
	keys []string
	vals map[string]any
}

// NewOMap returns an empty ordered map.
func NewOMap() *OMap { return &OMap{vals: map[string]any{}} }

// Len is len(dict).
func (m *OMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// Keys returns the keys in insertion order.
func (m *OMap) Keys() []string {
	if m == nil {
		return nil
	}
	return m.keys
}

// Get is dict.get(key).
func (m *OMap) Get(key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m.vals[key]
	return v, ok
}

// Set is dict[key] = value: a new key goes last, an existing one keeps its place.
func (m *OMap) Set(key string, v any) {
	if _, ok := m.vals[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.vals[key] = v
}

// Plain converts an ordered tree to plain map[string]any / []any values, recursively — including
// named map and slice types (a condition type, []map[string]any), via reflection.
func Plain(v any) any {
	switch x := v.(type) {
	case nil, string, bool, int64, float64, *big.Int:
		return v
	case int:
		return int64(x)
	case *OMap:
		out := make(map[string]any, x.Len())
		for _, k := range x.keys {
			out[k] = Plain(x.vals[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Plain(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = Plain(e)
		}
		return out
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() == reflect.String {
			out := make(map[string]any, rv.Len())
			for _, k := range rv.MapKeys() {
				out[k.String()] = Plain(rv.MapIndex(k).Interface())
			}
			return out
		}
	case reflect.Slice:
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = Plain(rv.Index(i).Interface())
		}
		return out
	case reflect.Ptr:
		if rv.IsNil() {
			return nil
		}
	}
	return v
}

// DictKeys returns a dict's keys in iteration order: insertion order for an *OMap, sorted for a plain
// map (whose order Go does not keep).
func DictKeys(v any) []string {
	switch x := v.(type) {
	case *OMap:
		return x.Keys()
	case map[string]any:
		return SortedKeys(x)
	}
	return nil
}

// IsDict is isinstance(v, dict).
func IsDict(v any) bool {
	switch v.(type) {
	case map[string]any, *OMap:
		return true
	}
	return false
}

// IsList is isinstance(v, list).
func IsList(v any) bool {
	_, ok := v.([]any)
	return ok
}

// Get is v.get(key) when v is a dict, else None — the `(x or {}).get(k)` idiom in one call.
func Get(v any, key string) any {
	switch x := v.(type) {
	case map[string]any:
		return x[key]
	case *OMap:
		val, _ := x.Get(key)
		return val
	}
	return nil
}

// Has is `key in v` for a dict.
func Has(v any, key string) bool {
	switch x := v.(type) {
	case map[string]any:
		_, ok := x[key]
		return ok
	case *OMap:
		_, ok := x.Get(key)
		return ok
	}
	return false
}

// GetPath walks nested dicts: GetPath(v, "a", "b") is ((v or {}).get("a") or {}).get("b").
func GetPath(v any, keys ...string) any {
	for _, k := range keys {
		v = Get(v, k)
	}
	return v
}

// List returns v as a list, or nil — the `x.get(k) or []` idiom.
func List(v any) []any {
	l, _ := v.([]any)
	return l
}

// String returns v when it is a str, else "".
func String(v any) string {
	s, _ := v.(string)
	return s
}

// IsStr is isinstance(v, str).
func IsStr(v any) bool {
	_, ok := v.(string)
	return ok
}

// AsInt returns v as an int when it is a Python int (not a bool).
func AsInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	}
	return 0, false
}

// Int is `v` read as a number for sums like sum(r.get("chars", 0)): ints only, anything else 0.
func Int(v any) int64 {
	n, _ := AsInt(v)
	return n
}

// ---------------------------------------------------------------------------------------------------
// json.loads
// ---------------------------------------------------------------------------------------------------

// JSONDecodeError is json.JSONDecodeError (a ValueError).
type JSONDecodeError struct{ Msg string }

func (e *JSONDecodeError) Error() string { return e.Msg }

// LoadsJSON is json.loads(s). Objects become *OMap (ordered) or map[string]any; integers int64 (or
// *big.Int past int64), other numbers float64; NaN, Infinity and -Infinity are accepted, as Python's
// decoder accepts them. Whitespace around the value is " \t\n\r" only, and a control character inside
// a string is an error, as with the default strict=True.
func LoadsJSON(s string, ordered bool) (any, error) {
	d := &jsonDecoder{s: s, ordered: ordered}
	d.skipWS()
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	d.skipWS()
	if d.i != len(d.s) {
		return nil, d.errf("Extra data")
	}
	return v, nil
}

type jsonDecoder struct {
	s       string
	i       int
	ordered bool
	depth   int
}

func (d *jsonDecoder) errf(msg string) error {
	pos := utf8.RuneCountInString(d.s[:d.i])
	line := 1 + strings.Count(d.s[:d.i], "\n")
	col := pos + 1
	if nl := strings.LastIndex(d.s[:d.i], "\n"); nl >= 0 {
		col = pos - utf8.RuneCountInString(d.s[:nl])
	}
	return &JSONDecodeError{Msg: fmt.Sprintf("%s: line %d column %d (char %d)", msg, line, col, pos)}
}

func (d *jsonDecoder) skipWS() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *jsonDecoder) value() (any, error) {
	if d.i >= len(d.s) {
		return nil, d.errf("Expecting value")
	}
	d.depth++
	defer func() { d.depth-- }()
	if d.depth > 900 { // CPython raises RecursionError near here; a corpus never nests this deep
		return nil, &Error{Type: "RecursionError", Msg: "maximum recursion depth exceeded while decoding a JSON document"}
	}
	switch c := d.s[d.i]; {
	case c == '{':
		return d.object()
	case c == '[':
		return d.array()
	case c == '"':
		return d.str()
	case strings.HasPrefix(d.s[d.i:], "null"):
		d.i += 4
		return nil, nil
	case strings.HasPrefix(d.s[d.i:], "true"):
		d.i += 4
		return true, nil
	case strings.HasPrefix(d.s[d.i:], "false"):
		d.i += 5
		return false, nil
	case strings.HasPrefix(d.s[d.i:], "NaN"):
		d.i += 3
		return math.NaN(), nil
	case strings.HasPrefix(d.s[d.i:], "Infinity"):
		d.i += 8
		return math.Inf(1), nil
	case strings.HasPrefix(d.s[d.i:], "-Infinity"):
		d.i += 9
		return math.Inf(-1), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	}
	return nil, d.errf("Expecting value")
}

func (d *jsonDecoder) number() (any, error) {
	start := d.i
	if d.s[d.i] == '-' {
		d.i++
	}
	if d.i >= len(d.s) || d.s[d.i] < '0' || d.s[d.i] > '9' {
		d.i = start
		return nil, d.errf("Expecting value")
	}
	if d.s[d.i] == '0' {
		d.i++
	} else {
		for d.i < len(d.s) && d.s[d.i] >= '0' && d.s[d.i] <= '9' {
			d.i++
		}
	}
	isFloat := false
	if d.i+1 < len(d.s) && d.s[d.i] == '.' && d.s[d.i+1] >= '0' && d.s[d.i+1] <= '9' {
		isFloat = true
		d.i += 2
		for d.i < len(d.s) && d.s[d.i] >= '0' && d.s[d.i] <= '9' {
			d.i++
		}
	}
	if d.i < len(d.s) && (d.s[d.i] == 'e' || d.s[d.i] == 'E') {
		j := d.i + 1
		if j < len(d.s) && (d.s[j] == '+' || d.s[j] == '-') {
			j++
		}
		if j < len(d.s) && d.s[j] >= '0' && d.s[j] <= '9' {
			for j < len(d.s) && d.s[j] >= '0' && d.s[j] <= '9' {
				j++
			}
			d.i = j
			isFloat = true
		}
	}
	lit := d.s[start:d.i]
	if isFloat {
		f, err := strconv.ParseFloat(lit, 64)
		if err != nil && !isRangeErr(err) {
			return nil, d.errf("Expecting value")
		}
		return f, nil
	}
	if n, err := strconv.ParseInt(lit, 10, 64); err == nil {
		return n, nil
	}
	b, _ := new(big.Int).SetString(lit, 10)
	return b, nil
}

func isRangeErr(err error) bool {
	ne, ok := err.(*strconv.NumError)
	return ok && ne.Err == strconv.ErrRange
}

func (d *jsonDecoder) str() (string, error) {
	d.i++ // opening quote
	var b strings.Builder
	for {
		if d.i >= len(d.s) {
			return "", d.errf("Unterminated string starting at")
		}
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return b.String(), nil
		case c == '\\':
			if d.i+1 >= len(d.s) {
				return "", d.errf("Unterminated string starting at")
			}
			esc := d.s[d.i+1]
			d.i += 2
			switch esc {
			case '"', '\\', '/':
				b.WriteByte(esc)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, ok := d.hex4()
				if !ok {
					return "", d.errf("Invalid \\uXXXX escape")
				}
				if utf16.IsSurrogate(r) && r < 0xdc00 && strings.HasPrefix(d.s[d.i:], `\u`) {
					save := d.i
					d.i += 2
					if r2, ok := d.hex4(); ok && r2 >= 0xdc00 && r2 <= 0xdfff {
						r = utf16.DecodeRune(r, r2)
					} else {
						d.i = save
					}
				}
				b.WriteRune(r) // a lone surrogate becomes U+FFFD: a Go string cannot hold one
			default:
				d.i -= 2
				return "", d.errf("Invalid \\escape")
			}
		case c < 0x20:
			return "", d.errf("Invalid control character at")
		default:
			r, size := utf8.DecodeRuneInString(d.s[d.i:])
			b.WriteRune(r)
			d.i += size
		}
	}
}

func (d *jsonDecoder) hex4() (rune, bool) {
	if d.i+4 > len(d.s) {
		return 0, false
	}
	n, err := strconv.ParseUint(d.s[d.i:d.i+4], 16, 16)
	if err != nil || n > 0xffff {
		return 0, false
	}
	d.i += 4
	return rune(n), true
}

func (d *jsonDecoder) object() (any, error) {
	d.i++
	var om *OMap
	var pm map[string]any
	if d.ordered {
		om = NewOMap()
	} else {
		pm = map[string]any{}
	}
	d.skipWS()
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		if d.ordered {
			return om, nil
		}
		return pm, nil
	}
	for {
		d.skipWS()
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return nil, d.errf("Expecting property name enclosed in double quotes")
		}
		k, err := d.str()
		if err != nil {
			return nil, err
		}
		d.skipWS()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return nil, d.errf("Expecting ':' delimiter")
		}
		d.i++
		d.skipWS()
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		if d.ordered {
			om.Set(k, v)
		} else {
			pm[k] = v
		}
		d.skipWS()
		if d.i < len(d.s) && d.s[d.i] == ',' {
			d.i++
			continue
		}
		if d.i < len(d.s) && d.s[d.i] == '}' {
			d.i++
			if d.ordered {
				return om, nil
			}
			return pm, nil
		}
		return nil, d.errf("Expecting ',' delimiter")
	}
}

func (d *jsonDecoder) array() (any, error) {
	d.i++
	out := []any{}
	d.skipWS()
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return out, nil
	}
	for {
		d.skipWS()
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		d.skipWS()
		if d.i < len(d.s) && d.s[d.i] == ',' {
			d.i++
			continue
		}
		if d.i < len(d.s) && d.s[d.i] == ']' {
			d.i++
			return out, nil
		}
		return nil, d.errf("Expecting ',' delimiter")
	}
}

// ---------------------------------------------------------------------------------------------------
// json.dumps
// ---------------------------------------------------------------------------------------------------

// DumpOpts are the json.dumps keyword arguments the service uses.
type DumpOpts struct {
	Indent      int // < 0 means indent=None
	SortKeys    bool
	EnsureASCII bool
	// DefaultStr is default=str: a value json cannot encode is written as str(value).
	DefaultStr bool
}

// DumpsJSON is json.dumps(v, ...): ", " and ": " separators when indent is None, "," and ": " with an
// indent, floats by repr, NaN/Infinity as Python writes them.
func DumpsJSON(v any, o DumpOpts) string {
	var b bytes.Buffer
	dumpValue(&b, v, o, 0)
	return b.String()
}

func dumpValue(b *bytes.Buffer, v any, o DumpOpts, level int) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSONString(b, x, o.EnsureASCII)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(FloatRepr(x))
		}
	case []any:
		dumpList(b, len(x), func(i int) any { return x[i] }, o, level)
	case []string:
		dumpList(b, len(x), func(i int) any { return x[i] }, o, level)
	case map[string]any:
		keys := SortedKeys(x) // a plain map has no order of its own
		dumpDict(b, keys, func(k string) any { return x[k] }, o, level)
	case *OMap:
		keys := append([]string(nil), x.Keys()...)
		if o.SortKeys {
			sort.Strings(keys)
		}
		dumpDict(b, keys, func(k string) any { v, _ := x.Get(k); return v }, o, level)
	default:
		switch p := Plain(v).(type) {
		case map[string]any, []any:
			dumpValue(b, p, o, level)
			return
		}
		if o.DefaultStr {
			writeJSONString(b, Str(v), o.EnsureASCII)
			return
		}
		writeJSONString(b, fmt.Sprintf("%v", v), o.EnsureASCII)
	}
}

func newline(b *bytes.Buffer, o DumpOpts, level int) {
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", o.Indent*level))
}

func dumpList(b *bytes.Buffer, n int, at func(int) any, o DumpOpts, level int) {
	if n == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			if o.Indent >= 0 {
				b.WriteByte(',')
			} else {
				b.WriteString(", ")
			}
		}
		if o.Indent >= 0 {
			newline(b, o, level+1)
		}
		dumpValue(b, at(i), o, level+1)
	}
	if o.Indent >= 0 {
		newline(b, o, level)
	}
	b.WriteByte(']')
}

func dumpDict(b *bytes.Buffer, keys []string, at func(string) any, o DumpOpts, level int) {
	if len(keys) == 0 {
		b.WriteString("{}")
		return
	}
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			if o.Indent >= 0 {
				b.WriteByte(',')
			} else {
				b.WriteString(", ")
			}
		}
		if o.Indent >= 0 {
			newline(b, o, level+1)
		}
		writeJSONString(b, k, o.EnsureASCII)
		b.WriteString(": ")
		dumpValue(b, at(k), o, level+1)
	}
	if o.Indent >= 0 {
		newline(b, o, level)
	}
	b.WriteByte('}')
}

func writeJSONString(b *bytes.Buffer, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case ascii && r > 0x7e:
				if r > 0xffff {
					r1, r2 := utf16.EncodeRune(r)
					fmt.Fprintf(b, `\u%04x\u%04x`, r1, r2)
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// O builds an *OMap from alternating keys and values, in order: py.O("a", 1, "b", 2) is {"a": 1, "b": 2}.
func O(kv ...any) *OMap {
	m := NewOMap()
	for i := 0; i+1 < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}

// MarshalJSON writes the map in insertion order, so an ordered map can sit inside a status or a body.
func (m *OMap) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range m.Keys() {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(m.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
