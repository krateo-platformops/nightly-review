package pyyaml

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// --- reader.py ----------------------------------------------------------------------------------------------

// reader ports yaml.reader.Reader for a str stream: the whole input is checked for printability up front
// (check_printable) and a NUL is appended as the end marker.
type reader struct {
	buffer []rune
	ptr    int
	index  int
	line   int
	column int
}

func isNonPrintable(r rune) bool {
	// NON_PRINTABLE = '[^\x09\x0A\x0D\x20-\x7E\x85\xA0-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]'
	switch {
	case r == 0x09 || r == 0x0A || r == 0x0D:
		return false
	case r >= 0x20 && r <= 0x7E:
		return false
	case r == 0x85:
		return false
	case r >= 0xA0 && r <= 0xD7FF:
		return false
	case r >= 0xE000 && r <= 0xFFFD:
		return false
	case r >= 0x10000 && r <= 0x10FFFF:
		return false
	}
	return true
}

func newReader(src string) *reader {
	rs := []rune(src)
	for i, r := range rs {
		if isNonPrintable(r) {
			raise(&YAMLError{Msg: "unacceptable character #x" + strconv.FormatInt(int64(r), 16) +
				": special characters are not allowed\n  in \"<unicode string>\", position " + strconv.Itoa(i)})
		}
	}
	return &reader{buffer: append(rs, 0)}
}

func (r *reader) peek(i int) rune {
	if r.ptr+i < len(r.buffer) {
		return r.buffer[r.ptr+i]
	}
	// Python would raise IndexError; the scanner never peeks past the NUL in practice.
	return 0
}

func (r *reader) prefix(n int) string {
	end := r.ptr + n
	if end > len(r.buffer) {
		end = len(r.buffer)
	}
	return string(r.buffer[r.ptr:end])
}

func (r *reader) forward(n int) {
	for ; n > 0; n-- {
		ch := r.buffer[r.ptr]
		r.ptr++
		r.index++
		next := rune(0)
		if r.ptr < len(r.buffer) {
			next = r.buffer[r.ptr]
		}
		if ch == '\n' || ch == 0x85 || ch == 0x2028 || ch == 0x2029 || (ch == '\r' && next != '\n') {
			r.line++
			r.column = 0
		} else if ch != 0xFEFF {
			r.column++
		}
	}
}

// --- tokens.py ----------------------------------------------------------------------------------------------

type tokenKind int

const (
	tDirective tokenKind = iota
	tDocumentStart
	tDocumentEnd
	tStreamStart
	tStreamEnd
	tBlockSequenceStart
	tBlockMappingStart
	tBlockEnd
	tFlowSequenceStart
	tFlowMappingStart
	tFlowSequenceEnd
	tFlowMappingEnd
	tKey
	tValue
	tBlockEntry
	tFlowEntry
	tAlias
	tAnchor
	tTag
	tScalar
)

var tokenIDs = map[tokenKind]string{
	tDirective: "<directive>", tDocumentStart: "<document start>", tDocumentEnd: "<document end>",
	tStreamStart: "<stream start>", tStreamEnd: "<stream end>", tBlockSequenceStart: "<block sequence start>",
	tBlockMappingStart: "<block mapping start>", tBlockEnd: "<block end>", tFlowSequenceStart: "[",
	tFlowMappingStart: "{", tFlowSequenceEnd: "]", tFlowMappingEnd: "}", tKey: "?", tValue: ":",
	tBlockEntry: "-", tFlowEntry: ",", tAlias: "<alias>", tAnchor: "<anchor>", tTag: "<tag>",
	tScalar: "<scalar>",
}

type token struct {
	kind tokenKind
	// directive
	name           string
	yamlMajor      int
	yamlMinor      int
	tagHandle      string // TAG directive handle / tag token handle
	tagPrefix      string // TAG directive prefix / tag token suffix
	tagHandleIsNil bool   // a tag token with handle None
	// alias/anchor/scalar
	value string
	plain bool
	style rune // 0 (None), '|', '>', '\'', '"'
}

// --- scanner.py ---------------------------------------------------------------------------------------------

type simpleKey struct {
	tokenNumber int
	required    bool
	index       int
	line        int
	column      int
}

type scanner struct {
	*reader
	done               bool
	flowLevel          int
	tokens             []*token
	tokensTaken        int
	indent             int
	indents            []int
	allowSimpleKey     bool
	possibleSimpleKeys map[int]*simpleKey
	keyOrder           []int // insertion order of possibleSimpleKeys, as a Python dict iterates
}

func newScanner(src string) *scanner {
	s := &scanner{reader: newReader(src), indent: -1, allowSimpleKey: true,
		possibleSimpleKeys: map[int]*simpleKey{}}
	s.tokens = append(s.tokens, &token{kind: tStreamStart})
	return s
}

const breakz = "\x00 \t\r\n\u0085\u2028\u2029"

func in(ch rune, set string) bool { return strings.ContainsRune(set, ch) }

func scanErr(context, problem string) { raise(yamlErr(context, problem)) }

func (s *scanner) checkToken(kinds ...tokenKind) bool {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if s.tokens[0].kind == k {
				return true
			}
		}
	}
	return false
}

func (s *scanner) peekToken() *token {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		return s.tokens[0]
	}
	return nil
}

func (s *scanner) getToken() *token {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		s.tokensTaken++
		t := s.tokens[0]
		s.tokens = s.tokens[1:]
		return t
	}
	return nil
}

func (s *scanner) needMoreTokens() bool {
	if s.done {
		return false
	}
	if len(s.tokens) == 0 {
		return true
	}
	s.staleSimpleKeys()
	n, ok := s.nextPossibleSimpleKey()
	return ok && n == s.tokensTaken
}

func (s *scanner) fetchMoreTokens() {
	s.scanToNextToken()
	s.staleSimpleKeys()
	s.unwindIndent(s.column)
	ch := s.peek(0)
	switch {
	case ch == 0:
		s.fetchStreamEnd()
		return
	case ch == '%' && s.column == 0:
		s.fetchDirective()
		return
	case ch == '-' && s.checkDocumentIndicator("---"):
		s.fetchDocumentIndicator(tDocumentStart)
		return
	case ch == '.' && s.checkDocumentIndicator("..."):
		s.fetchDocumentIndicator(tDocumentEnd)
		return
	case ch == '[':
		s.fetchFlowCollectionStart(tFlowSequenceStart)
		return
	case ch == '{':
		s.fetchFlowCollectionStart(tFlowMappingStart)
		return
	case ch == ']':
		s.fetchFlowCollectionEnd(tFlowSequenceEnd)
		return
	case ch == '}':
		s.fetchFlowCollectionEnd(tFlowMappingEnd)
		return
	case ch == ',':
		s.fetchFlowEntry()
		return
	case ch == '-' && in(s.peek(1), breakz):
		s.fetchBlockEntry()
		return
	case ch == '?' && (s.flowLevel > 0 || in(s.peek(1), breakz)):
		s.fetchKey()
		return
	case ch == ':' && (s.flowLevel > 0 || in(s.peek(1), breakz)):
		s.fetchValue()
		return
	case ch == '*':
		s.saveSimpleKey()
		s.allowSimpleKey = false
		s.tokens = append(s.tokens, s.scanAnchor(tAlias))
		return
	case ch == '&':
		s.saveSimpleKey()
		s.allowSimpleKey = false
		s.tokens = append(s.tokens, s.scanAnchor(tAnchor))
		return
	case ch == '!':
		s.saveSimpleKey()
		s.allowSimpleKey = false
		s.tokens = append(s.tokens, s.scanTag())
		return
	case ch == '|' && s.flowLevel == 0:
		s.fetchBlockScalar('|')
		return
	case ch == '>' && s.flowLevel == 0:
		s.fetchBlockScalar('>')
		return
	case ch == '\'' || ch == '"':
		s.saveSimpleKey()
		s.allowSimpleKey = false
		s.tokens = append(s.tokens, s.scanFlowScalar(ch == '"'))
		return
	}
	if s.checkPlain() {
		s.saveSimpleKey()
		s.allowSimpleKey = false
		s.tokens = append(s.tokens, s.scanPlain())
		return
	}
	scanErr("while scanning for the next token", "found character "+strconv.QuoteRune(ch)+" that cannot start any token")
}

func (s *scanner) nextPossibleSimpleKey() (int, bool) {
	min, found := 0, false
	for _, level := range s.keyOrder {
		k := s.possibleSimpleKeys[level]
		if !found || k.tokenNumber < min {
			min, found = k.tokenNumber, true
		}
	}
	return min, found
}

func (s *scanner) delKey(level int) {
	delete(s.possibleSimpleKeys, level)
	for i, l := range s.keyOrder {
		if l == level {
			s.keyOrder = append(s.keyOrder[:i:i], s.keyOrder[i+1:]...)
			break
		}
	}
}

func (s *scanner) staleSimpleKeys() {
	for _, level := range append([]int(nil), s.keyOrder...) {
		k := s.possibleSimpleKeys[level]
		if k.line != s.line || s.index-k.index > 1024 {
			if k.required {
				scanErr("while scanning a simple key", "could not find expected ':'")
			}
			s.delKey(level)
		}
	}
}

func (s *scanner) saveSimpleKey() {
	required := s.flowLevel == 0 && s.indent == s.column
	if s.allowSimpleKey {
		s.removeSimpleKey()
		k := &simpleKey{tokenNumber: s.tokensTaken + len(s.tokens), required: required,
			index: s.index, line: s.line, column: s.column}
		s.possibleSimpleKeys[s.flowLevel] = k
		s.keyOrder = append(s.keyOrder, s.flowLevel)
	}
}

func (s *scanner) removeSimpleKey() {
	if k, ok := s.possibleSimpleKeys[s.flowLevel]; ok {
		if k.required {
			scanErr("while scanning a simple key", "could not find expected ':'")
		}
		s.delKey(s.flowLevel)
	}
}

func (s *scanner) unwindIndent(column int) {
	if s.flowLevel > 0 {
		return
	}
	for s.indent > column {
		s.indent = s.indents[len(s.indents)-1]
		s.indents = s.indents[:len(s.indents)-1]
		s.tokens = append(s.tokens, &token{kind: tBlockEnd})
	}
}

func (s *scanner) addIndent(column int) bool {
	if s.indent < column {
		s.indents = append(s.indents, s.indent)
		s.indent = column
		return true
	}
	return false
}

func (s *scanner) fetchStreamEnd() {
	s.unwindIndent(-1)
	s.removeSimpleKey()
	s.allowSimpleKey = false
	s.possibleSimpleKeys = map[int]*simpleKey{}
	s.keyOrder = nil
	s.tokens = append(s.tokens, &token{kind: tStreamEnd})
	s.done = true
}

func (s *scanner) fetchDirective() {
	s.unwindIndent(-1)
	s.removeSimpleKey()
	s.allowSimpleKey = false
	s.tokens = append(s.tokens, s.scanDirective())
}

func (s *scanner) checkDocumentIndicator(ind string) bool {
	return s.column == 0 && s.prefix(3) == ind && in(s.peek(3), breakz)
}

func (s *scanner) fetchDocumentIndicator(kind tokenKind) {
	s.unwindIndent(-1)
	s.removeSimpleKey()
	s.allowSimpleKey = false
	s.forward(3)
	s.tokens = append(s.tokens, &token{kind: kind})
}

func (s *scanner) fetchFlowCollectionStart(kind tokenKind) {
	s.saveSimpleKey()
	s.flowLevel++
	s.allowSimpleKey = true
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: kind})
}

func (s *scanner) fetchFlowCollectionEnd(kind tokenKind) {
	s.removeSimpleKey()
	s.flowLevel--
	s.allowSimpleKey = false
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: kind})
}

func (s *scanner) fetchFlowEntry() {
	s.allowSimpleKey = true
	s.removeSimpleKey()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tFlowEntry})
}

func (s *scanner) fetchBlockEntry() {
	if s.flowLevel == 0 {
		if !s.allowSimpleKey {
			scanErr("", "sequence entries are not allowed here")
		}
		if s.addIndent(s.column) {
			s.tokens = append(s.tokens, &token{kind: tBlockSequenceStart})
		}
	}
	s.allowSimpleKey = true
	s.removeSimpleKey()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tBlockEntry})
}

func (s *scanner) fetchKey() {
	if s.flowLevel == 0 {
		if !s.allowSimpleKey {
			scanErr("", "mapping keys are not allowed here")
		}
		if s.addIndent(s.column) {
			s.tokens = append(s.tokens, &token{kind: tBlockMappingStart})
		}
	}
	s.allowSimpleKey = s.flowLevel == 0
	s.removeSimpleKey()
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tKey})
}

func (s *scanner) insertToken(pos int, t *token) {
	s.tokens = append(s.tokens, nil)
	copy(s.tokens[pos+1:], s.tokens[pos:])
	s.tokens[pos] = t
}

func (s *scanner) fetchValue() {
	if k, ok := s.possibleSimpleKeys[s.flowLevel]; ok {
		s.delKey(s.flowLevel)
		s.insertToken(k.tokenNumber-s.tokensTaken, &token{kind: tKey})
		if s.flowLevel == 0 {
			if s.addIndent(k.column) {
				s.insertToken(k.tokenNumber-s.tokensTaken, &token{kind: tBlockMappingStart})
			}
		}
		s.allowSimpleKey = false
	} else {
		if s.flowLevel == 0 {
			if !s.allowSimpleKey {
				scanErr("", "mapping values are not allowed here")
			}
			if s.addIndent(s.column) {
				s.tokens = append(s.tokens, &token{kind: tBlockMappingStart})
			}
		}
		s.allowSimpleKey = s.flowLevel == 0
		s.removeSimpleKey()
	}
	s.forward(1)
	s.tokens = append(s.tokens, &token{kind: tValue})
}

func (s *scanner) fetchBlockScalar(style rune) {
	s.allowSimpleKey = true
	s.removeSimpleKey()
	s.tokens = append(s.tokens, s.scanBlockScalar(style))
}

func (s *scanner) checkPlain() bool {
	ch := s.peek(0)
	return !in(ch, "\x00 \t\r\n\u0085\u2028\u2029-?:,[]{}#&*!|>'\"%@`") ||
		(!in(s.peek(1), breakz) && (ch == '-' || (s.flowLevel == 0 && in(ch, "?:"))))
}

func (s *scanner) scanToNextToken() {
	if s.index == 0 && s.peek(0) == 0xFEFF {
		s.forward(1)
	}
	found := false
	for !found {
		for s.peek(0) == ' ' {
			s.forward(1)
		}
		if s.peek(0) == '#' {
			for !in(s.peek(0), "\x00\r\n\u0085\u2028\u2029") {
				s.forward(1)
			}
		}
		if s.scanLineBreak() != "" {
			if s.flowLevel == 0 {
				s.allowSimpleKey = true
			}
		} else {
			found = true
		}
	}
}

func isWordChar(ch rune) bool {
	return ('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') || ch == '-' || ch == '_'
}

func (s *scanner) scanDirective() *token {
	s.forward(1)
	name := s.scanDirectiveName()
	t := &token{kind: tDirective, name: name}
	switch name {
	case "YAML":
		t.yamlMajor, t.yamlMinor = s.scanYAMLDirectiveValue()
	case "TAG":
		t.tagHandle, t.tagPrefix = s.scanTagDirectiveValue()
	default:
		for !in(s.peek(0), "\x00\r\n\u0085\u2028\u2029") {
			s.forward(1)
		}
	}
	s.scanDirectiveIgnoredLine()
	return t
}

func (s *scanner) scanDirectiveName() string {
	length := 0
	for isWordChar(s.peek(length)) {
		length++
	}
	if length == 0 {
		scanErr("while scanning a directive", "expected alphabetic or numeric character")
	}
	v := s.prefix(length)
	s.forward(length)
	if !in(s.peek(0), "\x00 \r\n\u0085\u2028\u2029") {
		scanErr("while scanning a directive", "expected alphabetic or numeric character")
	}
	return v
}

func (s *scanner) scanYAMLDirectiveValue() (int, int) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	major := s.scanYAMLDirectiveNumber()
	if s.peek(0) != '.' {
		scanErr("while scanning a directive", "expected a digit or '.'")
	}
	s.forward(1)
	minor := s.scanYAMLDirectiveNumber()
	if !in(s.peek(0), "\x00 \r\n\u0085\u2028\u2029") {
		scanErr("while scanning a directive", "expected a digit or ' '")
	}
	return major, minor
}

func (s *scanner) scanYAMLDirectiveNumber() int {
	if ch := s.peek(0); !('0' <= ch && ch <= '9') {
		scanErr("while scanning a directive", "expected a digit")
	}
	length := 0
	for ch := s.peek(length); '0' <= ch && ch <= '9'; ch = s.peek(length) {
		length++
	}
	v := s.prefix(length)
	s.forward(length)
	// int() of an arbitrarily long digit string; only "== 1" is ever asked of the major version.
	n, err := strconv.Atoi(v)
	if err != nil {
		n = 1 << 30
	}
	return n
}

func (s *scanner) scanTagDirectiveValue() (string, string) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	handle := s.scanTagHandle("directive")
	if s.peek(0) != ' ' {
		scanErr("while scanning a directive", "expected ' '")
	}
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	prefix := s.scanTagURI("directive")
	if !in(s.peek(0), "\x00 \r\n\u0085\u2028\u2029") {
		scanErr("while scanning a directive", "expected ' '")
	}
	return handle, prefix
}

func (s *scanner) scanDirectiveIgnoredLine() {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	if s.peek(0) == '#' {
		for !in(s.peek(0), "\x00\r\n\u0085\u2028\u2029") {
			s.forward(1)
		}
	}
	if !in(s.peek(0), "\x00\r\n\u0085\u2028\u2029") {
		scanErr("while scanning a directive", "expected a comment or a line break")
	}
	s.scanLineBreak()
}

func (s *scanner) scanAnchor(kind tokenKind) *token {
	name := "anchor"
	if s.peek(0) == '*' {
		name = "alias"
	}
	s.forward(1)
	length := 0
	for isWordChar(s.peek(length)) {
		length++
	}
	if length == 0 {
		scanErr("while scanning an "+name, "expected alphabetic or numeric character")
	}
	v := s.prefix(length)
	s.forward(length)
	if !in(s.peek(0), "\x00 \t\r\n\u0085\u2028\u2029?:,]}%@`") {
		scanErr("while scanning an "+name, "expected alphabetic or numeric character")
	}
	return &token{kind: kind, value: v}
}

func (s *scanner) scanTag() *token {
	ch := s.peek(1)
	t := &token{kind: tTag}
	switch {
	case ch == '<':
		t.tagHandleIsNil = true
		s.forward(2)
		t.tagPrefix = s.scanTagURI("tag")
		if s.peek(0) != '>' {
			scanErr("while parsing a tag", "expected '>'")
		}
		s.forward(1)
	case in(ch, breakz):
		t.tagHandleIsNil = true
		t.tagPrefix = "!"
		s.forward(1)
	default:
		length := 1
		useHandle := false
		for !in(ch, "\x00 \r\n\u0085\u2028\u2029") {
			if ch == '!' {
				useHandle = true
				break
			}
			length++
			ch = s.peek(length)
		}
		if useHandle {
			t.tagHandle = s.scanTagHandle("tag")
		} else {
			t.tagHandle = "!"
			s.forward(1)
		}
		t.tagPrefix = s.scanTagURI("tag")
	}
	if !in(s.peek(0), "\x00 \r\n\u0085\u2028\u2029") {
		scanErr("while scanning a tag", "expected ' '")
	}
	return t
}

func (s *scanner) scanBlockScalar(style rune) *token {
	folded := style == '>'
	var chunks strings.Builder
	s.forward(1)
	chomping, increment := s.scanBlockScalarIndicators()
	s.scanBlockScalarIgnoredLine()
	minIndent := s.indent + 1
	if minIndent < 1 {
		minIndent = 1
	}
	var breaks []string
	var indent int
	if increment == 0 {
		var maxIndent int
		breaks, maxIndent = s.scanBlockScalarIndentation()
		indent = max(minIndent, maxIndent)
	} else {
		indent = minIndent + increment - 1
		breaks = s.scanBlockScalarBreaks(indent)
	}
	lineBreak := ""
	for s.column == indent && s.peek(0) != 0 {
		for _, b := range breaks {
			chunks.WriteString(b)
		}
		leadingNonSpace := !in(s.peek(0), " \t")
		length := 0
		for !in(s.peek(length), "\x00\r\n\u0085\u2028\u2029") {
			length++
		}
		chunks.WriteString(s.prefix(length))
		s.forward(length)
		lineBreak = s.scanLineBreak()
		breaks = s.scanBlockScalarBreaks(indent)
		if s.column == indent && s.peek(0) != 0 {
			if folded && lineBreak == "\n" && leadingNonSpace && !in(s.peek(0), " \t") {
				if len(breaks) == 0 {
					chunks.WriteString(" ")
				}
			} else {
				chunks.WriteString(lineBreak)
			}
		} else {
			break
		}
	}
	if chomping != chompStrip {
		chunks.WriteString(lineBreak)
	}
	if chomping == chompKeep {
		for _, b := range breaks {
			chunks.WriteString(b)
		}
	}
	return &token{kind: tScalar, value: chunks.String(), plain: false, style: style}
}

const (
	chompClip = iota
	chompKeep
	chompStrip
)

func (s *scanner) scanBlockScalarIndicators() (int, int) {
	chomping, increment := chompClip, 0
	ch := s.peek(0)
	if ch == '+' || ch == '-' {
		chomping = chompKeep
		if ch == '-' {
			chomping = chompStrip
		}
		s.forward(1)
		ch = s.peek(0)
		if '0' <= ch && ch <= '9' {
			increment = int(ch - '0')
			if increment == 0 {
				scanErr("while scanning a block scalar", "expected indentation indicator in the range 1-9, but found 0")
			}
			s.forward(1)
		}
	} else if '0' <= ch && ch <= '9' {
		increment = int(ch - '0')
		if increment == 0 {
			scanErr("while scanning a block scalar", "expected indentation indicator in the range 1-9, but found 0")
		}
		s.forward(1)
		ch = s.peek(0)
		if ch == '+' || ch == '-' {
			chomping = chompKeep
			if ch == '-' {
				chomping = chompStrip
			}
			s.forward(1)
		}
	}
	if !in(s.peek(0), "\x00 \r\n\u0085\u2028\u2029") {
		scanErr("while scanning a block scalar", "expected chomping or indentation indicators")
	}
	return chomping, increment
}

func (s *scanner) scanBlockScalarIgnoredLine() {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	if s.peek(0) == '#' {
		for !in(s.peek(0), "\x00\r\n\u0085\u2028\u2029") {
			s.forward(1)
		}
	}
	if !in(s.peek(0), "\x00\r\n\u0085\u2028\u2029") {
		scanErr("while scanning a block scalar", "expected a comment or a line break")
	}
	s.scanLineBreak()
}

func (s *scanner) scanBlockScalarIndentation() ([]string, int) {
	var chunks []string
	maxIndent := 0
	for in(s.peek(0), " \r\n\u0085\u2028\u2029") {
		if s.peek(0) != ' ' {
			chunks = append(chunks, s.scanLineBreak())
		} else {
			s.forward(1)
			if s.column > maxIndent {
				maxIndent = s.column
			}
		}
	}
	return chunks, maxIndent
}

func (s *scanner) scanBlockScalarBreaks(indent int) []string {
	var chunks []string
	for s.column < indent && s.peek(0) == ' ' {
		s.forward(1)
	}
	for in(s.peek(0), "\r\n\u0085\u2028\u2029") {
		chunks = append(chunks, s.scanLineBreak())
		for s.column < indent && s.peek(0) == ' ' {
			s.forward(1)
		}
	}
	return chunks
}

func (s *scanner) scanFlowScalar(double bool) *token {
	var chunks strings.Builder
	quote := s.peek(0)
	s.forward(1)
	s.scanFlowScalarNonSpaces(double, &chunks)
	for s.peek(0) != quote {
		s.scanFlowScalarSpaces(&chunks)
		s.scanFlowScalarNonSpaces(double, &chunks)
	}
	s.forward(1)
	style := '\''
	if double {
		style = '"'
	}
	return &token{kind: tScalar, value: chunks.String(), plain: false, style: style}
}

var escapeReplacements = map[rune]string{
	'0': "\x00", 'a': "\x07", 'b': "\x08", 't': "\x09", '\t': "\x09", 'n': "\x0A", 'v': "\x0B", 'f': "\x0C",
	'r': "\x0D", 'e': "\x1B", ' ': "\x20", '"': "\"", '\\': "\\", '/': "/", 'N': "\u0085", '_': "\u00a0",
	'L': "\u2028", 'P': "\u2029",
}

var escapeCodes = map[rune]int{'x': 2, 'u': 4, 'U': 8}

func (s *scanner) scanFlowScalarNonSpaces(double bool, chunks *strings.Builder) {
	for {
		length := 0
		for !in(s.peek(length), "'\"\\\x00 \t\r\n\u0085\u2028\u2029") {
			length++
		}
		if length > 0 {
			chunks.WriteString(s.prefix(length))
			s.forward(length)
		}
		ch := s.peek(0)
		switch {
		case !double && ch == '\'' && s.peek(1) == '\'':
			chunks.WriteString("'")
			s.forward(2)
		case (double && ch == '\'') || (!double && (ch == '"' || ch == '\\')):
			chunks.WriteRune(ch)
			s.forward(1)
		case double && ch == '\\':
			s.forward(1)
			ch = s.peek(0)
			if rep, ok := escapeReplacements[ch]; ok {
				chunks.WriteString(rep)
				s.forward(1)
			} else if n, ok := escapeCodes[ch]; ok {
				s.forward(1)
				for k := 0; k < n; k++ {
					if !in(s.peek(k), "0123456789ABCDEFabcdef") {
						scanErr("while scanning a double-quoted scalar",
							"expected escape sequence of "+strconv.Itoa(n)+" hexadecimal numbers")
					}
				}
				code, _ := strconv.ParseInt(s.prefix(n), 16, 64)
				if code > 0x10FFFF {
					// chr() raises ValueError, which is not a YAMLError.
					raise(pyErr("ValueError", "chr() arg not in range(0x110000)"))
				}
				if code >= 0xD800 && code <= 0xDFFF {
					// Python keeps a lone surrogate in the str; Go cannot. Kept as U+FFFD (documented divergence).
					chunks.WriteRune(utf8.RuneError)
				} else {
					chunks.WriteRune(rune(code))
				}
				s.forward(n)
			} else if in(ch, "\r\n\u0085\u2028\u2029") {
				s.scanLineBreak()
				for _, b := range s.scanFlowScalarBreaks() {
					chunks.WriteString(b)
				}
			} else {
				scanErr("while scanning a double-quoted scalar", "found unknown escape character "+strconv.QuoteRune(ch))
			}
		default:
			return
		}
	}
}

func (s *scanner) scanFlowScalarSpaces(chunks *strings.Builder) {
	length := 0
	for in(s.peek(length), " \t") {
		length++
	}
	whitespaces := s.prefix(length)
	s.forward(length)
	ch := s.peek(0)
	if ch == 0 {
		scanErr("while scanning a quoted scalar", "found unexpected end of stream")
	} else if in(ch, "\r\n\u0085\u2028\u2029") {
		lineBreak := s.scanLineBreak()
		breaks := s.scanFlowScalarBreaks()
		if lineBreak != "\n" {
			chunks.WriteString(lineBreak)
		} else if len(breaks) == 0 {
			chunks.WriteString(" ")
		}
		for _, b := range breaks {
			chunks.WriteString(b)
		}
	} else {
		chunks.WriteString(whitespaces)
	}
}

func (s *scanner) scanFlowScalarBreaks() []string {
	var chunks []string
	for {
		p := s.prefix(3)
		if (p == "---" || p == "...") && in(s.peek(3), breakz) {
			scanErr("while scanning a quoted scalar", "found unexpected document separator")
		}
		for in(s.peek(0), " \t") {
			s.forward(1)
		}
		if in(s.peek(0), "\r\n\u0085\u2028\u2029") {
			chunks = append(chunks, s.scanLineBreak())
		} else {
			return chunks
		}
	}
}

func (s *scanner) scanPlain() *token {
	var chunks strings.Builder
	indent := s.indent + 1
	var spaces []string
	for {
		length := 0
		if s.peek(0) == '#' {
			break
		}
		for {
			ch := s.peek(length)
			follow := breakz
			if s.flowLevel > 0 {
				follow += ",[]{}"
			}
			if in(ch, breakz) || (ch == ':' && in(s.peek(length+1), follow)) || (s.flowLevel > 0 && in(ch, ",?[]{}")) {
				break
			}
			length++
		}
		if length == 0 {
			break
		}
		s.allowSimpleKey = false
		for _, sp := range spaces {
			chunks.WriteString(sp)
		}
		chunks.WriteString(s.prefix(length))
		s.forward(length)
		var ok bool
		spaces, ok = s.scanPlainSpaces()
		if !ok || len(spaces) == 0 || s.peek(0) == '#' || (s.flowLevel == 0 && s.column < indent) {
			break
		}
	}
	return &token{kind: tScalar, value: chunks.String(), plain: true}
}

// scanPlainSpaces returns (chunks, true), or (nil, false) where Python returns None.
func (s *scanner) scanPlainSpaces() ([]string, bool) {
	var chunks []string
	length := 0
	for s.peek(length) == ' ' {
		length++
	}
	whitespaces := s.prefix(length)
	s.forward(length)
	ch := s.peek(0)
	if in(ch, "\r\n\u0085\u2028\u2029") {
		lineBreak := s.scanLineBreak()
		s.allowSimpleKey = true
		p := s.prefix(3)
		if (p == "---" || p == "...") && in(s.peek(3), breakz) {
			return nil, false
		}
		var breaks []string
		for in(s.peek(0), " \r\n\u0085\u2028\u2029") {
			if s.peek(0) == ' ' {
				s.forward(1)
			} else {
				breaks = append(breaks, s.scanLineBreak())
				p := s.prefix(3)
				if (p == "---" || p == "...") && in(s.peek(3), breakz) {
					return nil, false
				}
			}
		}
		if lineBreak != "\n" {
			chunks = append(chunks, lineBreak)
		} else if len(breaks) == 0 {
			chunks = append(chunks, " ")
		}
		chunks = append(chunks, breaks...)
	} else if whitespaces != "" {
		chunks = append(chunks, whitespaces)
	}
	return chunks, true
}

func (s *scanner) scanTagHandle(name string) string {
	if s.peek(0) != '!' {
		scanErr("while scanning a "+name, "expected '!'")
	}
	length := 1
	ch := s.peek(length)
	if ch != ' ' {
		for isWordChar(ch) {
			length++
			ch = s.peek(length)
		}
		if ch != '!' {
			s.forward(length)
			scanErr("while scanning a "+name, "expected '!'")
		}
		length++
	}
	v := s.prefix(length)
	s.forward(length)
	return v
}

func (s *scanner) scanTagURI(name string) string {
	var chunks []string
	length := 0
	ch := s.peek(length)
	for ('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') ||
		in(ch, "-;/?:@&=+$,_.!~*'()[]%") {
		if ch == '%' {
			chunks = append(chunks, s.prefix(length))
			s.forward(length)
			length = 0
			chunks = append(chunks, s.scanURIEscapes(name))
		} else {
			length++
		}
		ch = s.peek(length)
	}
	if length > 0 {
		chunks = append(chunks, s.prefix(length))
		s.forward(length)
	}
	if len(chunks) == 0 {
		scanErr("while parsing a "+name, "expected URI")
	}
	return strings.Join(chunks, "")
}

func (s *scanner) scanURIEscapes(name string) string {
	var codes []byte
	for s.peek(0) == '%' {
		s.forward(1)
		for k := 0; k < 2; k++ {
			if !in(s.peek(k), "0123456789ABCDEFabcdef") {
				scanErr("while scanning a "+name, "expected URI escape sequence of 2 hexadecimal numbers")
			}
		}
		b, _ := strconv.ParseUint(s.prefix(2), 16, 8)
		codes = append(codes, byte(b))
		s.forward(2)
	}
	if !utf8.Valid(codes) {
		scanErr("while scanning a "+name, "'utf-8' codec can't decode bytes")
	}
	return string(codes)
}

func (s *scanner) scanLineBreak() string {
	ch := s.peek(0)
	if in(ch, "\r\n\u0085") && ch != 0 {
		if s.prefix(2) == "\r\n" {
			s.forward(2)
		} else {
			s.forward(1)
		}
		return "\n"
	} else if ch == 0x2028 || ch == 0x2029 {
		s.forward(1)
		return string(ch)
	}
	return ""
}
