package py

import "strings"

// PFormat is pprint.pformat(v, width=width, sort_dicts=False) for the JSON-shaped values this service
// handles. jsonschema quotes it in every ValidationError, and those messages are stored on the run, so
// the layout is ported from CPython 3.12's pprint rather than approximated.
func PFormat(v any, width int) string {
	p := &pprinter{width: width}
	var b strings.Builder
	p.format(&b, v, 0, 0, 0)
	return b.String()
}

type pprinter struct{ width int }

func (p *pprinter) format(b *strings.Builder, v any, indent, allowance, level int) {
	rep := Repr(v)
	if Len(rep) > p.width-indent-allowance {
		switch x := v.(type) {
		case *OMap:
			p.dict(b, DictKeys(x), func(k string) any { val, _ := x.Get(k); return val }, indent, allowance, level+1)
			return
		case map[string]any:
			p.dict(b, DictKeys(x), func(k string) any { return x[k] }, indent, allowance, level+1)
			return
		case []any:
			p.list(b, x, indent, allowance, level+1)
			return
		case string:
			p.str(b, x, indent, allowance, level+1)
			return
		}
	}
	b.WriteString(rep)
}

// dict ports _pprint_dict + _format_dict_items.
func (p *pprinter) dict(b *strings.Builder, keys []string, at func(string) any, indent, allowance, level int) {
	b.WriteByte('{')
	if len(keys) > 0 {
		allowance++
		indent++
		delim := ",\n" + strings.Repeat(" ", indent)
		for i, k := range keys {
			last := i == len(keys)-1
			rep := StrRepr(k)
			b.WriteString(rep)
			b.WriteString(": ")
			a := 1
			if last {
				a = allowance
			}
			p.format(b, at(k), indent+Len(rep)+2, a, level)
			if !last {
				b.WriteString(delim)
			}
		}
	}
	b.WriteByte('}')
}

// list ports _pprint_list + _format_items (compact=False).
func (p *pprinter) list(b *strings.Builder, items []any, indent, allowance, level int) {
	b.WriteByte('[')
	allowance++
	indent++
	delim := ",\n" + strings.Repeat(" ", indent)
	for i, e := range items {
		last := i == len(items)-1
		if i > 0 {
			b.WriteString(delim)
		}
		a := 1
		if last {
			a = allowance
		}
		p.format(b, e, indent, a, level)
	}
	b.WriteByte(']')
}

// str ports _pprint_str: a long string is split into adjacent literals at whitespace.
func (p *pprinter) str(b *strings.Builder, s string, indent, allowance, level int) {
	if s == "" {
		b.WriteString(StrRepr(s))
		return
	}
	var chunks []string
	lines := SplitLinesKeep(s)
	if level == 1 {
		indent++
		allowance++
	}
	maxWidth1 := p.width - indent
	maxWidth := maxWidth1
	rep := ""
	for i, line := range lines {
		rep = StrRepr(line)
		if i == len(lines)-1 {
			maxWidth1 -= allowance
		}
		if Len(rep) <= maxWidth1 {
			chunks = append(chunks, rep)
			continue
		}
		parts := pyWhitespaceChunks(line)
		maxWidth2 := maxWidth
		current := ""
		for j, part := range parts {
			candidate := current + part
			if j == len(parts)-1 && i == len(lines)-1 {
				maxWidth2 -= allowance
			}
			if Len(StrRepr(candidate)) > maxWidth2 {
				if current != "" {
					chunks = append(chunks, StrRepr(current))
				}
				current = part
			} else {
				current = candidate
			}
		}
		if current != "" {
			chunks = append(chunks, StrRepr(current))
		}
	}
	if len(chunks) == 1 {
		b.WriteString(rep)
		return
	}
	if level == 1 {
		b.WriteByte('(')
	}
	for i, c := range chunks {
		if i > 0 {
			b.WriteString("\n" + strings.Repeat(" ", indent))
		}
		b.WriteString(c)
	}
	if level == 1 {
		b.WriteByte(')')
	}
}

// pyWhitespaceChunks is re.findall(r'\S*\s*', line) without its final empty match, with Python's
// Unicode notion of whitespace.
func pyWhitespaceChunks(line string) []string {
	var out []string
	rs := []rune(line)
	i := 0
	for i < len(rs) {
		j := i
		for j < len(rs) && !IsSpace(rs[j]) {
			j++
		}
		for j < len(rs) && IsSpace(rs[j]) {
			j++
		}
		out = append(out, string(rs[i:j]))
		i = j
	}
	return out
}
