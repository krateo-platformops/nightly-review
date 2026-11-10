package pyyaml

import (
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// --- constructor.py: BaseConstructor + SafeConstructor ------------------------------------------------------

type constructor struct {
	constructed map[*node]Value
	recursive   map[*node]bool
	// stateGenerators: the second half of construct_yaml_seq/map/set/omap/pairs. Python runs a generator up to
	// its first `yield` (the empty container is registered) and finishes it later, in batches, from
	// construct_document; the order of those batches decides which of two errors in one document is raised.
	stateGenerators []func()
}

func newConstructor() *constructor {
	return &constructor{constructed: map[*node]Value{}, recursive: map[*node]bool{}}
}

func ctorErr(context, problem string) { raise(yamlErr(context, problem)) }

func (c *constructor) constructDocument(n *node) Value {
	data := c.constructObject(n)
	for len(c.stateGenerators) > 0 {
		gens := c.stateGenerators
		c.stateGenerators = nil
		for _, g := range gens {
			g()
		}
	}
	c.constructed = map[*node]Value{}
	c.recursive = map[*node]bool{}
	return data
}

func (c *constructor) constructObject(n *node) Value {
	if v, ok := c.constructed[n]; ok {
		return v
	}
	if c.recursive[n] {
		ctorErr("", "found unconstructable recursive node")
	}
	c.recursive[n] = true
	var data Value
	switch n.tag {
	case tagNull:
		c.constructScalar(n)
		data = nil
	case tagBool:
		data = c.constructYAMLBool(n)
	case tagInt:
		data = c.constructYAMLInt(n)
	case tagFloat:
		data = c.constructYAMLFloat(n)
	case tagBinary:
		data = c.constructYAMLBinary(n)
	case tagTimestamp:
		data = c.constructYAMLTimestamp(n)
	case tagStr:
		data = c.constructScalar(n)
	case tagOmap, tagPairs:
		items := &Sequence{}
		data = items
		what := "an ordered map"
		if n.tag == tagPairs {
			what = "pairs"
		}
		c.stateGenerators = append(c.stateGenerators, func() { c.fillPairs(n, items, what) })
	case tagSet:
		set := &Set{}
		data = set
		c.stateGenerators = append(c.stateGenerators, func() {
			m := c.constructMapping(n)
			for _, k := range m.keys {
				set.add(k)
			}
		})
	case tagSeq:
		seq := &Sequence{}
		data = seq
		c.stateGenerators = append(c.stateGenerators, func() {
			seq.Items = append(seq.Items, c.constructSequence(n)...)
		})
	case tagMap:
		m := &Mapping{}
		data = m
		c.stateGenerators = append(c.stateGenerators, func() {
			value := c.constructMapping(n)
			for i := range value.keys {
				m.set(value.keys[i], value.vals[i])
			}
		})
	default:
		ctorErr("", "could not determine a constructor for the tag "+pyRepr(n.tag))
	}
	c.constructed[n] = data
	delete(c.recursive, n)
	return data
}

// constructScalar ports SafeConstructor.construct_scalar (a mapping may carry its scalar under a `=` key).
func (c *constructor) constructScalar(n *node) string {
	if n.kind == mappingNode {
		for _, p := range n.pairs {
			if p.key.tag == tagValue {
				return c.constructScalar(p.value)
			}
		}
	}
	if n.kind != scalarNode {
		ctorErr("", "expected a scalar node, but found "+n.id())
	}
	return n.value
}

func (c *constructor) constructSequence(n *node) []Value {
	if n.kind != sequenceNode {
		ctorErr("", "expected a sequence node, but found "+n.id())
	}
	out := make([]Value, 0, len(n.items))
	for _, child := range n.items {
		out = append(out, c.constructObject(child))
	}
	return out
}

func (c *constructor) flattenMapping(n *node) {
	var merge []nodePair
	index := 0
	for index < len(n.pairs) {
		k, v := n.pairs[index].key, n.pairs[index].value
		if k.tag == tagMerge {
			n.pairs = append(n.pairs[:index:index], n.pairs[index+1:]...)
			switch v.kind {
			case mappingNode:
				c.flattenMapping(v)
				merge = append(merge, v.pairs...)
			case sequenceNode:
				var submerge [][]nodePair
				for _, sub := range v.items {
					if sub.kind != mappingNode {
						ctorErr("while constructing a mapping", "expected a mapping for merging, but found "+sub.id())
					}
					c.flattenMapping(sub)
					submerge = append(submerge, sub.pairs)
				}
				for i := len(submerge) - 1; i >= 0; i-- {
					merge = append(merge, submerge[i]...)
				}
			default:
				ctorErr("while constructing a mapping", "expected a mapping or list of mappings for merging, but found "+v.id())
			}
		} else if k.tag == tagValue {
			k.tag = tagStr
			index++
		} else {
			index++
		}
	}
	if len(merge) > 0 {
		n.pairs = append(append([]nodePair(nil), merge...), n.pairs...)
	}
}

func (c *constructor) constructMapping(n *node) *Mapping {
	if n.kind == mappingNode {
		c.flattenMapping(n)
	}
	if n.kind != mappingNode {
		ctorErr("", "expected a mapping node, but found "+n.id())
	}
	m := &Mapping{}
	for _, p := range n.pairs {
		key := c.constructObject(p.key)
		if !Hashable(key) {
			ctorErr("while constructing a mapping", "found unhashable key")
		}
		value := c.constructObject(p.value)
		m.set(key, value)
	}
	return m
}

func (c *constructor) fillPairs(n *node, out *Sequence, what string) {
	if n.kind != sequenceNode {
		ctorErr("while constructing "+what, "expected a sequence, but found "+n.id())
	}
	for _, sub := range n.items {
		if sub.kind != mappingNode {
			ctorErr("while constructing "+what, "expected a mapping of length 1, but found "+sub.id())
		}
		if len(sub.pairs) != 1 {
			ctorErr("while constructing "+what, "expected a single mapping item, but found "+strconv.Itoa(len(sub.pairs))+" items")
		}
		k := c.constructObject(sub.pairs[0].key)
		v := c.constructObject(sub.pairs[0].value)
		out.Items = append(out.Items, &Tuple{Items: []Value{k, v}})
	}
}

var boolValues = map[string]bool{"yes": true, "no": false, "true": true, "false": false, "on": true, "off": false}

func (c *constructor) constructYAMLBool(n *node) Value {
	value := c.constructScalar(n)
	b, ok := boolValues[pyLower(value)]
	if !ok {
		raise(pyErr("KeyError", "%s", pyRepr(pyLower(value))))
	}
	return b
}

func (c *constructor) constructYAMLInt(n *node) Value {
	value := strings.ReplaceAll(c.constructScalar(n), "_", "")
	if value == "" {
		raise(pyErr("IndexError", "string index out of range"))
	}
	sign := int64(1)
	if value[0] == '-' {
		sign = -1
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	var r *big.Int
	switch {
	case value == "0":
		return int64(0)
	case strings.HasPrefix(value, "0b"):
		r = pyInt(value[2:], 2)
	case strings.HasPrefix(value, "0x"):
		r = pyInt(value[2:], 16)
	case value == "":
		raise(pyErr("IndexError", "string index out of range"))
	case value[0] == '0':
		r = pyInt(value, 8)
	case strings.Contains(value, ":"):
		parts := strings.Split(value, ":")
		total, base := new(big.Int), big.NewInt(1)
		for i := len(parts) - 1; i >= 0; i-- {
			d := pyInt(parts[i], 10)
			total.Add(total, new(big.Int).Mul(d, base))
			base.Mul(base, big.NewInt(60))
		}
		r = total
	default:
		r = pyInt(value, 10)
	}
	r.Mul(r, big.NewInt(sign))
	return normInt(r)
}

func normInt(r *big.Int) Value {
	if r.IsInt64() {
		return r.Int64()
	}
	return r
}

// pyInt ports int(s, base) for the strings construct_yaml_int can hand it (underscores already removed).
func pyInt(s string, base int) *big.Int {
	orig := s
	t := pyStrip(s)
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	lt := strings.ToLower(t)
	if (base == 2 && strings.HasPrefix(lt, "0b")) || (base == 8 && strings.HasPrefix(lt, "0o")) ||
		(base == 16 && strings.HasPrefix(lt, "0x")) {
		t = t[2:]
	}
	r, ok := new(big.Int).SetString(t, base)
	if t == "" || !ok || strings.ContainsAny(t, "+-") {
		raise(pyErr("ValueError", "invalid literal for int() with base %d: %s", base, pyRepr(orig)))
	}
	if neg {
		r.Neg(r)
	}
	return r
}

func (c *constructor) constructYAMLFloat(n *node) Value {
	value := pyLower(strings.ReplaceAll(c.constructScalar(n), "_", ""))
	if value == "" {
		raise(pyErr("IndexError", "string index out of range"))
	}
	sign := 1.0
	if value[0] == '-' {
		sign = -1
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	switch {
	case value == ".inf":
		return sign * math.Inf(1)
	case value == ".nan":
		return math.NaN()
	case strings.Contains(value, ":"):
		parts := strings.Split(value, ":")
		total, base := 0.0, 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			total += pyFloat(parts[i]) * base
			base *= 60
		}
		return sign * total
	}
	return sign * pyFloat(value)
}

var floatLiteral = regexp.MustCompile(`^(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?$`)

// pyFloat ports float(str) for ASCII input: surrounding whitespace, a sign, nan/inf/infinity, decimal literals.
func pyFloat(s string) float64 {
	t := pyStrip(s)
	sign := 1.0
	body := t
	if body != "" && (body[0] == '+' || body[0] == '-') {
		if body[0] == '-' {
			sign = -1
		}
		body = body[1:]
	}
	switch strings.ToLower(body) {
	case "nan":
		return math.NaN()
	case "inf", "infinity":
		return sign * math.Inf(1)
	}
	if !floatLiteral.MatchString(body) {
		raise(pyErr("ValueError", "could not convert string to float: %s", pyRepr(s)))
	}
	f, err := strconv.ParseFloat(body, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
			raise(pyErr("ValueError", "could not convert string to float: %s", pyRepr(s)))
		}
	}
	return sign * f
}

func (c *constructor) constructYAMLBinary(n *node) Value {
	value := c.constructScalar(n)
	for _, r := range value {
		if r > 0x7f {
			ctorErr("", "failed to convert base64 data into ascii")
		}
	}
	out, err := a2bBase64(value)
	if err != "" {
		ctorErr("", "failed to decode base64 data: "+err)
	}
	return out
}

// a2bBase64 ports binascii.a2b_base64 (non-strict): characters outside the alphabet are skipped, and a
// completed pad sequence ends the input.
func a2bBase64(s string) ([]byte, string) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	quadPos, pads := 0, 0
	var left byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '=' {
			if quadPos >= 2 {
				pads++
				if quadPos+pads >= 4 {
					return out, ""
				}
			}
			continue
		}
		idx := strings.IndexByte(alphabet, ch)
		if idx < 0 {
			continue
		}
		v := byte(idx & 0x3f) // idx < 64: a position in the base64 alphabet
		pads = 0
		switch quadPos {
		case 0:
			quadPos, left = 1, v
		case 1:
			quadPos = 2
			out = append(out, left<<2|v>>4)
			left = v & 0x0f
		case 2:
			quadPos = 3
			out = append(out, left<<4|v>>2)
			left = v & 0x03
		case 3:
			quadPos = 0
			out = append(out, left<<6|v)
			left = 0
		}
	}
	if quadPos != 0 {
		if quadPos == 1 {
			n := 0
			for i := 0; i < len(s); i++ {
				if strings.IndexByte(alphabet, s[i]) >= 0 {
					n++
				}
			}
			return nil, "Invalid base64-encoded string: number of data characters (" + strconv.Itoa(n) +
				") cannot be 1 more than a multiple of 4"
		}
		return nil, "Incorrect padding"
	}
	return out, ""
}

var timestampRegexp = regexp.MustCompile(`\A([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.([0-9]*))?(?:[ \t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?)?\n?\z`)

func (c *constructor) constructYAMLTimestamp(n *node) Value {
	c.constructScalar(n)
	m := timestampRegexp.FindStringSubmatch(n.value)
	if m == nil {
		raise(pyErr("AttributeError", "'NoneType' object has no attribute 'groupdict'"))
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	checkDate(year, month, day)
	if m[4] == "" {
		return &Date{year, month, day}
	}
	hour, _ := strconv.Atoi(m[4])
	minute, _ := strconv.Atoi(m[5])
	second, _ := strconv.Atoi(m[6])
	fraction := 0
	if m[7] != "" {
		f := m[7]
		if len(f) > 6 {
			f = f[:6]
		}
		for len(f) < 6 {
			f += "0"
		}
		fraction, _ = strconv.Atoi(f)
	}
	dt := &DateTime{Year: year, Month: month, Day: day, Hour: hour, Minute: minute, Second: second, Microsecond: fraction}
	if m[9] != "" {
		tzHour, _ := strconv.Atoi(m[10])
		tzMinute := 0
		if m[11] != "" {
			tzMinute, _ = strconv.Atoi(m[11])
		}
		off := tzHour*60 + tzMinute
		if m[9] == "-" {
			off = -off
		}
		if off <= -24*60 || off >= 24*60 {
			raise(pyErr("ValueError", "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not %s.", timedeltaRepr(off)))
		}
		dt.Aware, dt.OffsetMinutes = true, off
	} else if m[8] != "" {
		dt.Aware = true
	}
	// datetime() validates hour, minute and second after the date (the date was checked above, before the
	// tzinfo was built — Python builds the tzinfo first, but both raise ValueError, so the order is moot).
	switch {
	case hour > 23:
		raise(pyErr("ValueError", "hour must be in 0..23"))
	case minute > 59:
		raise(pyErr("ValueError", "minute must be in 0..59"))
	case second > 59:
		raise(pyErr("ValueError", "second must be in 0..59"))
	}
	return dt
}

func checkDate(year, month, day int) {
	if year < 1 || year > 9999 {
		raise(pyErr("ValueError", "year %d is out of range", year))
	}
	if month < 1 || month > 12 {
		raise(pyErr("ValueError", "month must be in 1..12"))
	}
	dim := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[month-1]
	if month == 2 && (year%4 == 0 && (year%100 != 0 || year%400 == 0)) {
		dim = 29
	}
	if day < 1 || day > dim {
		raise(pyErr("ValueError", "day is out of range for month"))
	}
}

// --- Python str helpers -------------------------------------------------------------------------------------

// isPySpace is str.isspace for one character (also what re's \s and str.strip() use).
func isPySpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0d, r >= 0x1c && r <= 0x20, r == 0x85, r == 0xa0, r == 0x1680,
		r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}

func pyStrip(s string) string { return strings.TrimFunc(s, isPySpace) }

// pyLower is str.lower(); U+0130 is the one character whose full lowercase mapping is two characters.
func pyLower(s string) string {
	if !strings.ContainsRune(s, 0x130) {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r == 0x130 {
			b.WriteString("i\u0307")
		} else {
			b.WriteString(strings.ToLower(string(r)))
		}
	}
	return b.String()
}
