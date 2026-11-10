package pyyaml

import (
	"fmt"
	"sort"
	"strings"
)

// --- emitter.py (canonical=False, allow_unicode=False, indent=2, width=80, line_break='\n') ------------------

const (
	bestIndent = 2
	bestWidth  = 80
	stylePlain = 'P' // Python's '' style; 0 is Python's None
)

type scalarAnalysis struct {
	scalar                                                         []rune
	empty, multiline                                               bool
	allowFlowPlain, allowBlockPlain, allowSingleQuoted, allowBlock bool
}

type emitter struct {
	out         strings.Builder
	events      []*event
	ev          *event
	states      []func()
	state       func()
	indents     []*int
	indent      *int
	flowLevel   int
	rootContext bool
	seqContext  bool
	mapContext  bool
	simpleKey   bool
	column      int
	whitespace  bool
	indention   bool
	openEnded   bool
	tagPrefixes map[string]string
	prepAnchor  *string
	prepTag     *string
	analysis    *scalarAnalysis
	style       rune
}

func newEmitter() *emitter {
	e := &emitter{whitespace: true, indention: true}
	e.state = e.expectStreamStart
	return e
}

func (e *emitter) run(events []*event) {
	e.events = events
	for len(e.events) > 0 {
		e.ev = e.events[0]
		e.events = e.events[1:]
		e.state()
		e.ev = nil
	}
}

func emitErr(msg string) { raise(&YAMLError{Msg: msg}) }

func (e *emitter) pushState(f func()) { e.states = append(e.states, f) }
func (e *emitter) popState() func() {
	f := e.states[len(e.states)-1]
	e.states = e.states[:len(e.states)-1]
	return f
}

func (e *emitter) increaseIndent(flow, indentless bool) {
	e.indents = append(e.indents, e.indent)
	if e.indent == nil {
		v := 0
		if flow {
			v = bestIndent
		}
		e.indent = &v
	} else if !indentless {
		v := *e.indent + bestIndent
		e.indent = &v
	}
}

func (e *emitter) popIndent() {
	e.indent = e.indents[len(e.indents)-1]
	e.indents = e.indents[:len(e.indents)-1]
}

func (e *emitter) expectStreamStart() {
	if e.ev.kind != eStreamStart {
		emitErr("expected StreamStartEvent")
	}
	e.state = e.expectFirstDocumentStart
}

func (e *emitter) expectNothing() { emitErr("expected nothing") }

func (e *emitter) expectFirstDocumentStart() { e.expectDocumentStart(true) }
func (e *emitter) expectDocumentStartNext()  { e.expectDocumentStart(false) }

func (e *emitter) expectDocumentStart(first bool) {
	switch e.ev.kind {
	case eDocumentStart:
		e.tagPrefixes = map[string]string{"!": "!", "tag:yaml.org,2002:": "!!"}
		implicit := first && !e.ev.explicit && !e.checkEmptyDocument()
		if !implicit {
			e.writeIndent()
			e.writeIndicator("---", true, false, false)
		}
		e.state = e.expectDocumentRoot
	case eStreamEnd:
		if e.openEnded {
			e.writeIndicator("...", true, false, false)
			e.writeIndent()
		}
		e.state = e.expectNothing
	default:
		emitErr("expected DocumentStartEvent")
	}
}

func (e *emitter) expectDocumentEnd() {
	if e.ev.kind != eDocumentEnd {
		emitErr("expected DocumentEndEvent")
	}
	e.writeIndent()
	if e.ev.explicit {
		e.writeIndicator("...", true, false, false)
		e.writeIndent()
	}
	e.state = e.expectDocumentStartNext
}

func (e *emitter) expectDocumentRoot() {
	e.pushState(e.expectDocumentEnd)
	e.expectNode(true, false, false, false)
}

func (e *emitter) expectNode(root, sequence, mapping, simpleKey bool) {
	e.rootContext, e.seqContext, e.mapContext, e.simpleKey = root, sequence, mapping, simpleKey
	switch e.ev.kind {
	case eAlias:
		e.expectAlias()
	case eScalar, eSequenceStart, eMappingStart:
		e.processAnchor("&")
		e.processTag()
		switch e.ev.kind {
		case eScalar:
			e.expectScalar()
		case eSequenceStart:
			if e.flowLevel > 0 || e.ev.flowStyle || e.checkEmptySequence() {
				e.expectFlowSequence()
			} else {
				e.expectBlockSequence()
			}
		case eMappingStart:
			if e.flowLevel > 0 || e.ev.flowStyle || e.checkEmptyMapping() {
				e.expectFlowMapping()
			} else {
				e.expectBlockMapping()
			}
		}
	default:
		emitErr("expected NodeEvent")
	}
}

func (e *emitter) expectAlias() {
	if e.ev.anchor == nil {
		emitErr("anchor is not specified for alias")
	}
	e.processAnchor("*")
	e.state = e.popState()
}

func (e *emitter) expectScalar() {
	e.increaseIndent(true, false)
	e.processScalar()
	e.popIndent()
	e.state = e.popState()
}

func (e *emitter) expectFlowSequence() {
	e.writeIndicator("[", true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.state = e.expectFirstFlowSequenceItem
}

func (e *emitter) expectFirstFlowSequenceItem() {
	if e.ev.kind == eSequenceEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("]", false, false, false)
		e.state = e.popState()
		return
	}
	if e.column > bestWidth {
		e.writeIndent()
	}
	e.pushState(e.expectFlowSequenceItem)
	e.expectNode(false, true, false, false)
}

func (e *emitter) expectFlowSequenceItem() {
	if e.ev.kind == eSequenceEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("]", false, false, false)
		e.state = e.popState()
		return
	}
	e.writeIndicator(",", false, false, false)
	if e.column > bestWidth {
		e.writeIndent()
	}
	e.pushState(e.expectFlowSequenceItem)
	e.expectNode(false, true, false, false)
}

func (e *emitter) expectFlowMapping() {
	e.writeIndicator("{", true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.state = e.expectFirstFlowMappingKey
}

func (e *emitter) expectFirstFlowMappingKey() {
	if e.ev.kind == eMappingEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("}", false, false, false)
		e.state = e.popState()
		return
	}
	if e.column > bestWidth {
		e.writeIndent()
	}
	if e.checkSimpleKey() {
		e.pushState(e.expectFlowMappingSimpleValue)
		e.expectNode(false, false, true, true)
	} else {
		e.writeIndicator("?", true, false, false)
		e.pushState(e.expectFlowMappingValue)
		e.expectNode(false, false, true, false)
	}
}

func (e *emitter) expectFlowMappingKey() {
	if e.ev.kind == eMappingEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("}", false, false, false)
		e.state = e.popState()
		return
	}
	e.writeIndicator(",", false, false, false)
	if e.column > bestWidth {
		e.writeIndent()
	}
	if e.checkSimpleKey() {
		e.pushState(e.expectFlowMappingSimpleValue)
		e.expectNode(false, false, true, true)
	} else {
		e.writeIndicator("?", true, false, false)
		e.pushState(e.expectFlowMappingValue)
		e.expectNode(false, false, true, false)
	}
}

func (e *emitter) expectFlowMappingSimpleValue() {
	e.writeIndicator(":", false, false, false)
	e.pushState(e.expectFlowMappingKey)
	e.expectNode(false, false, true, false)
}

func (e *emitter) expectFlowMappingValue() {
	if e.column > bestWidth {
		e.writeIndent()
	}
	e.writeIndicator(":", true, false, false)
	e.pushState(e.expectFlowMappingKey)
	e.expectNode(false, false, true, false)
}

func (e *emitter) expectBlockSequence() {
	indentless := e.mapContext && !e.indention
	e.increaseIndent(false, indentless)
	e.state = e.expectFirstBlockSequenceItem
}

func (e *emitter) expectFirstBlockSequenceItem() { e.expectBlockSequenceItem(true) }
func (e *emitter) expectNextBlockSequenceItem()  { e.expectBlockSequenceItem(false) }

func (e *emitter) expectBlockSequenceItem(first bool) {
	if !first && e.ev.kind == eSequenceEnd {
		e.popIndent()
		e.state = e.popState()
		return
	}
	e.writeIndent()
	e.writeIndicator("-", true, false, true)
	e.pushState(e.expectNextBlockSequenceItem)
	e.expectNode(false, true, false, false)
}

func (e *emitter) expectBlockMapping() {
	e.increaseIndent(false, false)
	e.state = e.expectFirstBlockMappingKey
}

func (e *emitter) expectFirstBlockMappingKey() { e.expectBlockMappingKey(true) }
func (e *emitter) expectNextBlockMappingKey()  { e.expectBlockMappingKey(false) }

func (e *emitter) expectBlockMappingKey(first bool) {
	if !first && e.ev.kind == eMappingEnd {
		e.popIndent()
		e.state = e.popState()
		return
	}
	e.writeIndent()
	if e.checkSimpleKey() {
		e.pushState(e.expectBlockMappingSimpleValue)
		e.expectNode(false, false, true, true)
	} else {
		e.writeIndicator("?", true, false, true)
		e.pushState(e.expectBlockMappingValue)
		e.expectNode(false, false, true, false)
	}
}

func (e *emitter) expectBlockMappingSimpleValue() {
	e.writeIndicator(":", false, false, false)
	e.pushState(e.expectNextBlockMappingKey)
	e.expectNode(false, false, true, false)
}

func (e *emitter) expectBlockMappingValue() {
	e.writeIndent()
	e.writeIndicator(":", true, false, true)
	e.pushState(e.expectNextBlockMappingKey)
	e.expectNode(false, false, true, false)
}

func (e *emitter) checkEmptySequence() bool {
	return e.ev.kind == eSequenceStart && len(e.events) > 0 && e.events[0].kind == eSequenceEnd
}

func (e *emitter) checkEmptyMapping() bool {
	return e.ev.kind == eMappingStart && len(e.events) > 0 && e.events[0].kind == eMappingEnd
}

func (e *emitter) checkEmptyDocument() bool {
	if e.ev.kind != eDocumentStart || len(e.events) == 0 {
		return false
	}
	n := e.events[0]
	return n.kind == eScalar && n.anchor == nil && n.tag == nil && n.implicit[0] && n.value == ""
}

func (e *emitter) checkSimpleKey() bool {
	length := 0
	isNode := e.ev.kind == eAlias || e.ev.kind == eScalar || e.ev.kind == eSequenceStart || e.ev.kind == eMappingStart
	if isNode && e.ev.anchor != nil {
		if e.prepAnchor == nil {
			a := prepareAnchor(*e.ev.anchor)
			e.prepAnchor = &a
		}
		length += len([]rune(*e.prepAnchor))
	}
	if (e.ev.kind == eScalar || e.ev.kind == eSequenceStart || e.ev.kind == eMappingStart) && e.ev.tag != nil {
		if e.prepTag == nil {
			t := e.prepareTag(*e.ev.tag)
			e.prepTag = &t
		}
		length += len([]rune(*e.prepTag))
	}
	if e.ev.kind == eScalar {
		if e.analysis == nil {
			e.analysis = analyzeScalar(e.ev.value)
		}
		length += len(e.analysis.scalar)
	}
	return length < 128 && (e.ev.kind == eAlias ||
		(e.ev.kind == eScalar && !e.analysis.empty && !e.analysis.multiline) ||
		e.checkEmptySequence() || e.checkEmptyMapping())
}

func (e *emitter) processAnchor(indicator string) {
	if e.ev.anchor == nil {
		e.prepAnchor = nil
		return
	}
	if e.prepAnchor == nil {
		a := prepareAnchor(*e.ev.anchor)
		e.prepAnchor = &a
	}
	if *e.prepAnchor != "" {
		e.writeIndicator(indicator+*e.prepAnchor, true, false, false)
	}
	e.prepAnchor = nil
}

func (e *emitter) processTag() {
	tag := e.ev.tag
	if e.ev.kind == eScalar {
		if e.style == 0 {
			e.style = e.chooseScalarStyle()
		}
		if (e.style == stylePlain && e.ev.implicit[0]) || (e.style != stylePlain && e.ev.implicit[1]) {
			e.prepTag = nil
			return
		}
		if e.ev.implicit[0] && tag == nil {
			bang := "!"
			tag = &bang
			e.prepTag = nil
		}
	} else if e.ev.implicit[0] {
		e.prepTag = nil
		return
	}
	if tag == nil {
		emitErr("tag is not specified")
	}
	if e.prepTag == nil {
		t := e.prepareTag(*tag)
		e.prepTag = &t
	}
	if *e.prepTag != "" {
		e.writeIndicator(*e.prepTag, true, false, false)
	}
	e.prepTag = nil
}

func (e *emitter) chooseScalarStyle() rune {
	if e.analysis == nil {
		e.analysis = analyzeScalar(e.ev.value)
	}
	st := e.ev.style
	if st == '"' {
		return '"'
	}
	if st == 0 && e.ev.implicit[0] {
		if !(e.simpleKey && (e.analysis.empty || e.analysis.multiline)) &&
			((e.flowLevel > 0 && e.analysis.allowFlowPlain) || (e.flowLevel == 0 && e.analysis.allowBlockPlain)) {
			return stylePlain
		}
	}
	if st == '|' || st == '>' {
		if e.flowLevel == 0 && !e.simpleKey && e.analysis.allowBlock {
			return st
		}
	}
	if st == 0 || st == '\'' {
		if e.analysis.allowSingleQuoted && !(e.simpleKey && e.analysis.multiline) {
			return '\''
		}
	}
	return '"'
}

func (e *emitter) processScalar() {
	if e.analysis == nil {
		e.analysis = analyzeScalar(e.ev.value)
	}
	if e.style == 0 {
		e.style = e.chooseScalarStyle()
	}
	split := !e.simpleKey
	switch e.style {
	case '"':
		e.writeDoubleQuoted(e.analysis.scalar, split)
	case '\'':
		e.writeSingleQuoted(e.analysis.scalar, split)
	case '>':
		emitErr("folded style is never produced by SafeRepresenter")
	case '|':
		e.writeLiteral(e.analysis.scalar)
	default:
		e.writePlain(e.analysis.scalar, split)
	}
	e.analysis = nil
	e.style = 0
}

func isTagChar(ch rune) bool {
	return ('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') ||
		strings.ContainsRune("-;/?:@&=+$,_.~*'()[]", ch)
}

func (e *emitter) prepareTag(tag string) string {
	if tag == "" {
		emitErr("tag must not be empty")
	}
	if tag == "!" {
		return tag
	}
	handle := ""
	suffix := tag
	prefixes := make([]string, 0, len(e.tagPrefixes))
	for p := range e.tagPrefixes {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		if strings.HasPrefix(tag, p) && (p == "!" || len(p) < len(tag)) {
			handle = e.tagPrefixes[p]
			suffix = tag[len(p):]
		}
	}
	var chunks strings.Builder
	for _, ch := range suffix {
		if isTagChar(ch) || (ch == '!' && handle != "!") {
			chunks.WriteRune(ch)
		} else {
			for _, b := range []byte(string(ch)) {
				fmt.Fprintf(&chunks, "%%%02X", b)
			}
		}
	}
	if handle != "" {
		return handle + chunks.String()
	}
	return "!<" + chunks.String() + ">"
}

func prepareAnchor(anchor string) string {
	if anchor == "" {
		emitErr("anchor must not be empty")
	}
	for _, ch := range anchor {
		if !isWordChar(ch) {
			emitErr("invalid character in the anchor")
		}
	}
	return anchor
}

func isSpecialSpace(ch rune) bool  { return strings.ContainsRune("\x00 \t\r\n\u0085\u2028\u2029", ch) }
func isLineBreakChar(ch rune) bool { return ch == '\n' || ch == 0x85 || ch == 0x2028 || ch == 0x2029 }

func analyzeScalar(value string) *scalarAnalysis {
	scalar := []rune(value)
	if len(scalar) == 0 {
		return &scalarAnalysis{scalar: scalar, empty: true, allowBlockPlain: true, allowSingleQuoted: true}
	}
	var blockIndicators, flowIndicators, lineBreaks, specialCharacters bool
	var leadingSpace, leadingBreak, trailingSpace, trailingBreak, breakSpace, spaceBreak bool
	if strings.HasPrefix(value, "---") || strings.HasPrefix(value, "...") {
		blockIndicators, flowIndicators = true, true
	}
	precededByWhitespace := true
	followedByWhitespace := len(scalar) == 1 || isSpecialSpace(scalar[1])
	previousSpace, previousBreak := false, false
	for index := 0; index < len(scalar); {
		ch := scalar[index]
		if index == 0 {
			if strings.ContainsRune("#,[]{}&*!|>'\"%@`", ch) {
				flowIndicators, blockIndicators = true, true
			}
			if ch == '?' || ch == ':' {
				flowIndicators = true
				if followedByWhitespace {
					blockIndicators = true
				}
			}
			if ch == '-' && followedByWhitespace {
				flowIndicators, blockIndicators = true, true
			}
		} else {
			if strings.ContainsRune(",?[]{}", ch) {
				flowIndicators = true
			}
			if ch == ':' {
				flowIndicators = true
				if followedByWhitespace {
					blockIndicators = true
				}
			}
			if ch == '#' && precededByWhitespace {
				flowIndicators, blockIndicators = true, true
			}
		}
		if isLineBreakChar(ch) {
			lineBreaks = true
		}
		if !(ch == '\n' || (0x20 <= ch && ch <= 0x7E)) {
			// allow_unicode is False: any non-ASCII character makes the scalar special.
			specialCharacters = true
		}
		if ch == ' ' {
			if index == 0 {
				leadingSpace = true
			}
			if index == len(scalar)-1 {
				trailingSpace = true
			}
			if previousBreak {
				breakSpace = true
			}
			previousSpace, previousBreak = true, false
		} else if isLineBreakChar(ch) {
			if index == 0 {
				leadingBreak = true
			}
			if index == len(scalar)-1 {
				trailingBreak = true
			}
			if previousSpace {
				spaceBreak = true
			}
			previousSpace, previousBreak = false, true
		} else {
			previousSpace, previousBreak = false, false
		}
		index++
		precededByWhitespace = isSpecialSpace(ch)
		followedByWhitespace = index+1 >= len(scalar) || isSpecialSpace(scalar[index+1])
	}
	a := &scalarAnalysis{scalar: scalar, multiline: lineBreaks,
		allowFlowPlain: true, allowBlockPlain: true, allowSingleQuoted: true, allowBlock: true}
	if leadingSpace || leadingBreak || trailingSpace || trailingBreak {
		a.allowFlowPlain, a.allowBlockPlain = false, false
	}
	if trailingSpace {
		a.allowBlock = false
	}
	if breakSpace {
		a.allowFlowPlain, a.allowBlockPlain, a.allowSingleQuoted = false, false, false
	}
	if spaceBreak || specialCharacters {
		a.allowFlowPlain, a.allowBlockPlain, a.allowSingleQuoted, a.allowBlock = false, false, false, false
	}
	if lineBreaks {
		a.allowFlowPlain, a.allowBlockPlain = false, false
	}
	if flowIndicators {
		a.allowFlowPlain = false
	}
	if blockIndicators {
		a.allowBlockPlain = false
	}
	return a
}

func (e *emitter) write(data string) { e.out.WriteString(data) }

func (e *emitter) writeIndicator(indicator string, needWhitespace, whitespace, indention bool) {
	data := indicator
	if !(e.whitespace || !needWhitespace) {
		data = " " + indicator
	}
	e.whitespace = whitespace
	e.indention = e.indention && indention
	e.column += len([]rune(data))
	e.openEnded = false
	e.write(data)
}

func (e *emitter) writeIndent() {
	indent := 0
	if e.indent != nil {
		indent = *e.indent
	}
	if !e.indention || e.column > indent || (e.column == indent && !e.whitespace) {
		e.writeLineBreak("")
	}
	if e.column < indent {
		e.whitespace = true
		e.write(strings.Repeat(" ", indent-e.column))
		e.column = indent
	}
}

func (e *emitter) writeLineBreak(data string) {
	if data == "" {
		data = "\n"
	}
	e.whitespace = true
	e.indention = true
	e.column = 0
	e.write(data)
}

func (e *emitter) writeSingleQuoted(text []rune, split bool) {
	e.writeIndicator("'", true, false, false)
	spaces, breaks := false, false
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		if spaces {
			if ch == -1 || ch != ' ' {
				if start+1 == end && e.column > bestWidth && split && start != 0 && end != len(text) {
					e.writeIndent()
				} else {
					data := string(text[start:end])
					e.column += end - start
					e.write(data)
				}
				start = end
			}
		} else if breaks {
			if ch == -1 || !isLineBreakChar(ch) {
				if text[start] == '\n' {
					e.writeLineBreak("")
				}
				for _, br := range text[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				e.writeIndent()
				start = end
			}
		} else {
			if ch == -1 || ch == ' ' || isLineBreakChar(ch) || ch == '\'' {
				if start < end {
					e.column += end - start
					e.write(string(text[start:end]))
					start = end
				}
			}
		}
		if ch == '\'' {
			e.column += 2
			e.write("''")
			start = end + 1
		}
		if ch != -1 {
			spaces = ch == ' '
			breaks = isLineBreakChar(ch)
		}
		end++
	}
	e.writeIndicator("'", false, false, false)
}

var emitEscapes = map[rune]string{
	0: "0", 0x07: "a", 0x08: "b", 0x09: "t", 0x0A: "n", 0x0B: "v", 0x0C: "f", 0x0D: "r", 0x1B: "e",
	'"': "\"", '\\': "\\", 0x85: "N", 0xA0: "_", 0x2028: "L", 0x2029: "P",
}

func (e *emitter) writeDoubleQuoted(text []rune, split bool) {
	e.writeIndicator("\"", true, false, false)
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		if ch == -1 || strings.ContainsRune("\"\\\u0085\u2028\u2029\ufeff", ch) || !(0x20 <= ch && ch <= 0x7E) {
			if start < end {
				e.column += end - start
				e.write(string(text[start:end]))
				start = end
			}
			if ch != -1 {
				var data string
				if rep, ok := emitEscapes[ch]; ok {
					data = "\\" + rep
				} else if ch <= 0xFF {
					data = fmt.Sprintf("\\x%02X", ch)
				} else if ch <= 0xFFFF {
					data = fmt.Sprintf("\\u%04X", ch)
				} else {
					data = fmt.Sprintf("\\U%08X", ch)
				}
				e.column += len([]rune(data))
				e.write(data)
				start = end + 1
			}
		}
		if 0 < end && end < len(text)-1 && (ch == ' ' || start >= end) && e.column+(end-start) > bestWidth && split {
			data := pySlice(text, start, end) + "\\"
			if start < end {
				start = end
			}
			e.column += len([]rune(data))
			e.write(data)
			e.writeIndent()
			e.whitespace = false
			e.indention = false
			if text[start] == ' ' {
				e.column++
				e.write("\\")
			}
		}
		end++
	}
	e.writeIndicator("\"", false, false, false)
}

func determineBlockHints(text []rune) string {
	hints := ""
	if len(text) > 0 {
		if text[0] == ' ' || isLineBreakChar(text[0]) {
			hints += "2"
		}
		last := text[len(text)-1]
		if !isLineBreakChar(last) {
			hints += "-"
		} else if len(text) == 1 || isLineBreakChar(text[len(text)-2]) {
			hints += "+"
		}
	}
	return hints
}

func (e *emitter) writeLiteral(text []rune) {
	hints := determineBlockHints(text)
	e.writeIndicator("|"+hints, true, false, false)
	if strings.HasSuffix(hints, "+") {
		e.openEnded = true
	}
	e.writeLineBreak("")
	breaks := true
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		if breaks {
			if ch == -1 || !isLineBreakChar(ch) {
				for _, br := range text[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				if ch != -1 {
					e.writeIndent()
				}
				start = end
			}
		} else {
			if ch == -1 || isLineBreakChar(ch) {
				e.write(string(text[start:end]))
				if ch == -1 {
					e.writeLineBreak("")
				}
				start = end
			}
		}
		if ch != -1 {
			breaks = isLineBreakChar(ch)
		}
		end++
	}
}

func (e *emitter) writePlain(text []rune, split bool) {
	if e.rootContext {
		e.openEnded = true
	}
	if len(text) == 0 {
		return
	}
	if !e.whitespace {
		e.column++
		e.write(" ")
	}
	e.whitespace = false
	e.indention = false
	spaces, breaks := false, false
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		if spaces {
			if ch != ' ' {
				if start+1 == end && e.column > bestWidth && split {
					e.writeIndent()
					e.whitespace = false
					e.indention = false
				} else {
					e.column += end - start
					e.write(string(text[start:end]))
				}
				start = end
			}
		} else if breaks {
			if ch == -1 {
				// `None not in '...'` raises TypeError in Python; unreachable, since a plain scalar carries no
				// line break.
				raise(pyErr("TypeError", "'in <string>' requires string as left operand, not NoneType"))
			}
			if !isLineBreakChar(ch) {
				if text[start] == '\n' {
					e.writeLineBreak("")
				}
				for _, br := range text[start:end] {
					if br == '\n' {
						e.writeLineBreak("")
					} else {
						e.writeLineBreak(string(br))
					}
				}
				e.writeIndent()
				e.whitespace = false
				e.indention = false
				start = end
			}
		} else {
			if ch == -1 || ch == ' ' || isLineBreakChar(ch) {
				e.column += end - start
				e.write(string(text[start:end]))
				start = end
			}
		}
		if ch != -1 {
			spaces = ch == ' '
			breaks = isLineBreakChar(ch)
		}
		end++
	}
}

// pySlice is text[start:end] with Python's leniency: an empty string when start >= end.
func pySlice(text []rune, start, end int) string {
	if start >= end {
		return ""
	}
	return string(text[start:end])
}
