package pyyaml

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// --- representer.py: SafeRepresenter with sort_keys=True, default_flow_style=False ---------------------------

type representer struct {
	represented map[any]*node // id(data) -> node, for objects ignore_aliases does not exempt
	depth       int
}

// aliasKey is id(data) for the objects SafeRepresenter.ignore_aliases does NOT exempt (None, (), str, bytes,
// bool, int and float are exempt); nil means "no alias tracking".
func aliasKey(data Value) any {
	switch x := data.(type) {
	case *Sequence, *Mapping, *Set, *Date, *DateTime:
		return x
	case *Tuple:
		if len(x.Items) == 0 {
			return nil
		}
		return x
	}
	return nil
}

func (r *representer) representData(data Value) *node {
	key := aliasKey(data)
	if key != nil {
		if n, ok := r.represented[key]; ok {
			return n
		}
	}
	r.depth++
	if r.depth > representMaxDepth {
		recursionError()
	}
	defer func() { r.depth-- }()
	switch x := data.(type) {
	case nil:
		return r.representScalar(key, tagNull, "null", 0)
	case string:
		return r.representScalar(key, tagStr, x, 0)
	case []byte:
		return r.representScalar(key, tagBinary, encodeBytes(x), '|')
	case bool:
		if x {
			return r.representScalar(key, tagBool, "true", 0)
		}
		return r.representScalar(key, tagBool, "false", 0)
	case int64:
		return r.representScalar(key, tagInt, strconv.FormatInt(x, 10), 0)
	case *big.Int:
		return r.representScalar(key, tagInt, x.String(), 0)
	case float64:
		return r.representScalar(key, tagFloat, representFloat(x), 0)
	case *Sequence:
		return r.representSequence(key, x.Items)
	case *Tuple:
		return r.representSequence(key, x.Items)
	case *Mapping:
		return r.representMapping(key, tagMap, x.keys, x.vals)
	case *Set:
		vals := make([]Value, len(x.Items))
		return r.representMapping(key, tagSet, x.Items, vals)
	case *Date:
		return r.representScalar(key, tagTimestamp, fmt.Sprintf("%04d-%02d-%02d", x.Year, x.Month, x.Day), 0)
	case *DateTime:
		return r.representScalar(key, tagTimestamp, x.isoformat(" "), 0)
	}
	raise(&YAMLError{Msg: fmt.Sprintf("('cannot represent an object', %v)", data)})
	return nil
}

func (r *representer) representScalar(key any, tag, value string, style rune) *node {
	n := &node{kind: scalarNode, tag: tag, value: value, style: style}
	if key != nil {
		r.represented[key] = n
	}
	return n
}

func (r *representer) representSequence(key any, items []Value) *node {
	n := &node{kind: sequenceNode, tag: tagSeq}
	if key != nil {
		r.represented[key] = n
	}
	for _, it := range items {
		n.items = append(n.items, r.representData(it))
	}
	return n
}

func (r *representer) representMapping(key any, tag string, keys, vals []Value) *node {
	n := &node{kind: mappingNode, tag: tag}
	if key != nil {
		r.represented[key] = n
	}
	order := make([]int, len(keys))
	for i := range order {
		order[i] = i
	}
	if sorted, ok := pySortItems(keys, vals); ok {
		order = sorted
	}
	for _, i := range order {
		k := r.representData(keys[i])
		v := r.representData(vals[i])
		n.pairs = append(n.pairs, nodePair{k, v})
	}
	return n
}

// pySortItems is sorted(mapping.items()) as CPython's list.sort runs it (count_run, then binary insertion —
// what CPython does for fewer than 64 items, and an exact stand-in for more as long as the keys are totally
// ordered). ok is false when a comparison raised TypeError, which represent_mapping catches.
func pySortItems(keys, vals []Value) (order []int, ok bool) {
	less := func(a, b int) bool {
		// tuple comparison: the first unequal element decides; dict keys are never equal to each other.
		if pyEqual(keys[a], keys[b]) {
			l, err := pyLess(vals[a], vals[b])
			if err != nil {
				panic(errUnorderable)
			}
			return l
		}
		l, err := pyLess(keys[a], keys[b])
		if err != nil {
			panic(errUnorderable)
		}
		return l
	}
	defer func() {
		if rec := recover(); rec != nil {
			if rec == errUnorderable {
				order, ok = nil, false
				return
			}
			panic(rec)
		}
	}()
	n := len(keys)
	a := make([]int, n)
	for i := range a {
		a[i] = i
	}
	if n < 2 {
		return a, true
	}
	lo := 0
	for lo < n {
		// count_run
		run := 1
		descending := false
		if lo+1 < n {
			run = 2
			if less(a[lo+1], a[lo]) {
				descending = true
				for i := lo + 2; i < n && less(a[i], a[i-1]); i++ {
					run++
				}
			} else {
				for i := lo + 2; i < n && !less(a[i], a[i-1]); i++ {
					run++
				}
			}
		}
		if descending {
			for i, j := lo, lo+run-1; i < j; i, j = i+1, j-1 {
				a[i], a[j] = a[j], a[i]
			}
		}
		// binarysort the rest of the list into the run (one run covers the whole list below 64 items).
		start := lo + run
		for ; start < n; start++ {
			pivot := a[start]
			l, r := lo, start
			for l < r {
				p := l + (r-l)/2
				if less(pivot, a[p]) {
					r = p
				} else {
					l = p + 1
				}
			}
			copy(a[l+1:start+1], a[l:start])
			a[l] = pivot
		}
		lo = n
	}
	return a, true
}

func representFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return ".nan"
	case math.IsInf(f, 1):
		return ".inf"
	case math.IsInf(f, -1):
		return "-.inf"
	}
	v := strings.ToLower(floatRepr(f))
	if !strings.Contains(v, ".") && strings.Contains(v, "e") {
		v = strings.Replace(v, "e", ".0e", 1)
	}
	return v
}

// encodeBytes is base64.encodebytes(data).decode('ascii'): 76-character lines, each ending in a newline.
func encodeBytes(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 57 {
		end := min(i+57, len(b))
		sb.WriteString(base64.StdEncoding.EncodeToString(b[i:end]))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// --- serializer.py ------------------------------------------------------------------------------------------

type serializer struct {
	anchors    map[*node]*string
	anchorSeen map[*node]bool
	serialized map[*node]bool
	lastAnchor int
	events     []*event
	depth      int
}

func (s *serializer) anchorNode(n *node) {
	if s.anchorSeen[n] {
		if s.anchors[n] == nil {
			s.lastAnchor++
			a := fmt.Sprintf("id%03d", s.lastAnchor)
			s.anchors[n] = &a
		}
		return
	}
	s.anchorSeen[n] = true
	s.depth++
	switch n.kind {
	case sequenceNode:
		for _, it := range n.items {
			s.anchorNode(it)
		}
	case mappingNode:
		for _, p := range n.pairs {
			s.anchorNode(p.key)
			s.anchorNode(p.value)
		}
	}
	s.depth--
}

func (s *serializer) serializeNode(n *node) {
	alias := s.anchors[n]
	if s.serialized[n] {
		s.events = append(s.events, &event{kind: eAlias, anchor: alias})
		return
	}
	s.serialized[n] = true
	tag := n.tag
	switch n.kind {
	case scalarNode:
		detected := resolve(scalarNode, n.value, [2]bool{true, false})
		def := resolve(scalarNode, n.value, [2]bool{false, true})
		s.events = append(s.events, &event{kind: eScalar, anchor: alias, tag: &tag,
			implicit: [2]bool{n.tag == detected, n.tag == def}, value: n.value, style: n.style})
	case sequenceNode:
		s.events = append(s.events, &event{kind: eSequenceStart, anchor: alias, tag: &tag,
			implicit: [2]bool{n.tag == tagSeq}, flowStyle: n.flowStyle})
		for _, it := range n.items {
			s.serializeNode(it)
		}
		s.events = append(s.events, &event{kind: eSequenceEnd})
	case mappingNode:
		s.events = append(s.events, &event{kind: eMappingStart, anchor: alias, tag: &tag,
			implicit: [2]bool{n.tag == tagMap}, flowStyle: n.flowStyle})
		for _, p := range n.pairs {
			s.serializeNode(p.key)
			s.serializeNode(p.value)
		}
		s.events = append(s.events, &event{kind: eMappingEnd})
	}
}

// SafeDump is yaml.safe_dump(v, sort_keys=True, default_flow_style=False). Python's own set iteration order is
// hash order (randomised for str between processes), so an UNSORTABLE set has no reproducible Python output;
// it is emitted here in insertion order.
func SafeDump(v Value) (out string, err error) {
	defer catch(&err)
	r := &representer{represented: map[any]*node{}}
	root := r.representData(v)
	s := &serializer{anchors: map[*node]*string{}, anchorSeen: map[*node]bool{}, serialized: map[*node]bool{}}
	s.anchorNode(root)
	s.events = append(s.events, &event{kind: eStreamStart}, &event{kind: eDocumentStart})
	s.serializeNode(root)
	s.events = append(s.events, &event{kind: eDocumentEnd}, &event{kind: eStreamEnd})
	e := newEmitter()
	e.run(s.events)
	return e.out.String(), nil
}
