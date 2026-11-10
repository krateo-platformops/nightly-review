package pyyaml

// --- events.py ----------------------------------------------------------------------------------------------

type eventKind int

const (
	eStreamStart eventKind = iota
	eStreamEnd
	eDocumentStart
	eDocumentEnd
	eAlias
	eScalar
	eSequenceStart
	eSequenceEnd
	eMappingStart
	eMappingEnd
)

type event struct {
	kind      eventKind
	anchor    *string
	tag       *string
	implicit  [2]bool // scalar: (plain-implicit, quoted-implicit); collections use implicit[0]
	value     string
	style     rune // 0 = None, 'P' = '' (plain, emitter-chosen), '|', '>', '\'', '"'
	flowStyle bool
	explicit  bool
}

// --- parser.py ----------------------------------------------------------------------------------------------

var defaultTags = map[string]string{"!": "!", "!!": "tag:yaml.org,2002:"}

type parser struct {
	*scanner
	current    *event
	tagHandles map[string]string
	states     []func() *event
	state      func() *event
}

func newParser(src string) *parser {
	p := &parser{scanner: newScanner(src)}
	p.state = p.parseStreamStart
	return p
}

func (p *parser) checkEvent(kinds ...eventKind) bool {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	if p.current != nil {
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if p.current.kind == k {
				return true
			}
		}
	}
	return false
}

func (p *parser) peekEvent() *event {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	return p.current
}

func (p *parser) getEvent() *event {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	e := p.current
	p.current = nil
	return e
}

func (p *parser) popState() func() *event {
	st := p.states[len(p.states)-1]
	p.states = p.states[:len(p.states)-1]
	return st
}

func parseErr(context, problem string) { raise(yamlErr(context, problem)) }

func (p *parser) parseStreamStart() *event {
	p.getToken()
	p.state = p.parseImplicitDocumentStart
	return &event{kind: eStreamStart}
}

func (p *parser) parseImplicitDocumentStart() *event {
	if !p.checkToken(tDirective, tDocumentStart, tStreamEnd) {
		p.tagHandles = defaultTags
		p.peekToken()
		p.states = append(p.states, p.parseDocumentEnd)
		p.state = p.parseBlockNode
		return &event{kind: eDocumentStart, explicit: false}
	}
	return p.parseDocumentStart()
}

func (p *parser) parseDocumentStart() *event {
	for p.checkToken(tDocumentEnd) {
		p.getToken()
	}
	if !p.checkToken(tStreamEnd) {
		p.peekToken()
		p.processDirectives()
		if !p.checkToken(tDocumentStart) {
			parseErr("", "expected '<document start>', but found '"+tokenIDs[p.peekToken().kind]+"'")
		}
		p.getToken()
		p.states = append(p.states, p.parseDocumentEnd)
		p.state = p.parseDocumentContent
		return &event{kind: eDocumentStart, explicit: true}
	}
	p.getToken()
	p.state = nil
	return &event{kind: eStreamEnd}
}

func (p *parser) parseDocumentEnd() *event {
	p.peekToken()
	explicit := false
	if p.checkToken(tDocumentEnd) {
		p.getToken()
		explicit = true
	}
	p.state = p.parseDocumentStart
	return &event{kind: eDocumentEnd, explicit: explicit}
}

func (p *parser) parseDocumentContent() *event {
	if p.checkToken(tDirective, tDocumentStart, tDocumentEnd, tStreamEnd) {
		e := p.processEmptyScalar()
		p.state = p.popState()
		return e
	}
	return p.parseBlockNode()
}

func (p *parser) processDirectives() {
	yamlVersionSeen := false
	p.tagHandles = map[string]string{}
	for p.checkToken(tDirective) {
		t := p.getToken()
		if t.name == "YAML" {
			if yamlVersionSeen {
				parseErr("", "found duplicate YAML directive")
			}
			if t.yamlMajor != 1 {
				parseErr("", "found incompatible YAML document (version 1.* is required)")
			}
			yamlVersionSeen = true
		} else if t.name == "TAG" {
			if _, dup := p.tagHandles[t.tagHandle]; dup {
				parseErr("", "duplicate tag handle "+pyRepr(t.tagHandle))
			}
			p.tagHandles[t.tagHandle] = t.tagPrefix
		}
	}
	for k, v := range defaultTags {
		if _, ok := p.tagHandles[k]; !ok {
			p.tagHandles[k] = v
		}
	}
}

func (p *parser) parseBlockNode() *event { return p.parseNode(true, false) }
func (p *parser) parseFlowNode() *event  { return p.parseNode(false, false) }
func (p *parser) parseBlockNodeOrIndentlessSequence() *event {
	return p.parseNode(true, true)
}

func (p *parser) parseNode(block, indentlessSequence bool) *event {
	if p.checkToken(tAlias) {
		t := p.getToken()
		v := t.value
		p.state = p.popState()
		return &event{kind: eAlias, anchor: &v}
	}
	var anchor, tag *string
	var tagTok *token
	if p.checkToken(tAnchor) {
		t := p.getToken()
		v := t.value
		anchor = &v
		if p.checkToken(tTag) {
			tagTok = p.getToken()
		}
	} else if p.checkToken(tTag) {
		tagTok = p.getToken()
		if p.checkToken(tAnchor) {
			t := p.getToken()
			v := t.value
			anchor = &v
		}
	}
	if tagTok != nil {
		var full string
		if !tagTok.tagHandleIsNil {
			prefix, ok := p.tagHandles[tagTok.tagHandle]
			if !ok {
				parseErr("while parsing a node", "found undefined tag handle "+pyRepr(tagTok.tagHandle))
			}
			full = prefix + tagTok.tagPrefix
		} else {
			full = tagTok.tagPrefix
		}
		tag = &full
	}
	implicit := tag == nil || *tag == "!"
	if indentlessSequence && p.checkToken(tBlockEntry) {
		p.state = p.parseIndentlessSequenceEntry
		return &event{kind: eSequenceStart, anchor: anchor, tag: tag, implicit: [2]bool{implicit}}
	}
	switch {
	case p.checkToken(tScalar):
		t := p.getToken()
		var imp [2]bool
		if (t.plain && tag == nil) || (tag != nil && *tag == "!") {
			imp = [2]bool{true, false}
		} else if tag == nil {
			imp = [2]bool{false, true}
		}
		p.state = p.popState()
		return &event{kind: eScalar, anchor: anchor, tag: tag, implicit: imp, value: t.value, style: t.style}
	case p.checkToken(tFlowSequenceStart):
		p.state = p.parseFlowSequenceFirstEntry
		return &event{kind: eSequenceStart, anchor: anchor, tag: tag, implicit: [2]bool{implicit}, flowStyle: true}
	case p.checkToken(tFlowMappingStart):
		p.state = p.parseFlowMappingFirstKey
		return &event{kind: eMappingStart, anchor: anchor, tag: tag, implicit: [2]bool{implicit}, flowStyle: true}
	case block && p.checkToken(tBlockSequenceStart):
		p.state = p.parseBlockSequenceFirstEntry
		return &event{kind: eSequenceStart, anchor: anchor, tag: tag, implicit: [2]bool{implicit}}
	case block && p.checkToken(tBlockMappingStart):
		p.state = p.parseBlockMappingFirstKey
		return &event{kind: eMappingStart, anchor: anchor, tag: tag, implicit: [2]bool{implicit}}
	case anchor != nil || tag != nil:
		p.state = p.popState()
		return &event{kind: eScalar, anchor: anchor, tag: tag, implicit: [2]bool{implicit, false}, value: ""}
	}
	node := "flow"
	if block {
		node = "block"
	}
	parseErr("while parsing a "+node+" node", "expected the node content, but found '"+tokenIDs[p.peekToken().kind]+"'")
	return nil
}

func (p *parser) parseBlockSequenceFirstEntry() *event {
	p.getToken()
	return p.parseBlockSequenceEntry()
}

func (p *parser) parseBlockSequenceEntry() *event {
	if p.checkToken(tBlockEntry) {
		p.getToken()
		if !p.checkToken(tBlockEntry, tBlockEnd) {
			p.states = append(p.states, p.parseBlockSequenceEntry)
			return p.parseBlockNode()
		}
		p.state = p.parseBlockSequenceEntry
		return p.processEmptyScalar()
	}
	if !p.checkToken(tBlockEnd) {
		parseErr("while parsing a block collection", "expected <block end>, but found '"+tokenIDs[p.peekToken().kind]+"'")
	}
	p.getToken()
	p.state = p.popState()
	return &event{kind: eSequenceEnd}
}

func (p *parser) parseIndentlessSequenceEntry() *event {
	if p.checkToken(tBlockEntry) {
		p.getToken()
		if !p.checkToken(tBlockEntry, tKey, tValue, tBlockEnd) {
			p.states = append(p.states, p.parseIndentlessSequenceEntry)
			return p.parseBlockNode()
		}
		p.state = p.parseIndentlessSequenceEntry
		return p.processEmptyScalar()
	}
	p.peekToken()
	p.state = p.popState()
	return &event{kind: eSequenceEnd}
}

func (p *parser) parseBlockMappingFirstKey() *event {
	p.getToken()
	return p.parseBlockMappingKey()
}

func (p *parser) parseBlockMappingKey() *event {
	if p.checkToken(tKey) {
		p.getToken()
		if !p.checkToken(tKey, tValue, tBlockEnd) {
			p.states = append(p.states, p.parseBlockMappingValue)
			return p.parseBlockNodeOrIndentlessSequence()
		}
		p.state = p.parseBlockMappingValue
		return p.processEmptyScalar()
	}
	if !p.checkToken(tBlockEnd) {
		parseErr("while parsing a block mapping", "expected <block end>, but found '"+tokenIDs[p.peekToken().kind]+"'")
	}
	p.getToken()
	p.state = p.popState()
	return &event{kind: eMappingEnd}
}

func (p *parser) parseBlockMappingValue() *event {
	if p.checkToken(tValue) {
		p.getToken()
		if !p.checkToken(tKey, tValue, tBlockEnd) {
			p.states = append(p.states, p.parseBlockMappingKey)
			return p.parseBlockNodeOrIndentlessSequence()
		}
		p.state = p.parseBlockMappingKey
		return p.processEmptyScalar()
	}
	p.state = p.parseBlockMappingKey
	p.peekToken()
	return p.processEmptyScalar()
}

func (p *parser) parseFlowSequenceFirstEntry() *event {
	p.getToken()
	return p.parseFlowSequenceEntry(true)
}

func (p *parser) parseFlowSequenceEntryNotFirst() *event { return p.parseFlowSequenceEntry(false) }

func (p *parser) parseFlowSequenceEntry(first bool) *event {
	if !p.checkToken(tFlowSequenceEnd) {
		if !first {
			if p.checkToken(tFlowEntry) {
				p.getToken()
			} else {
				parseErr("while parsing a flow sequence", "expected ',' or ']', but got '"+tokenIDs[p.peekToken().kind]+"'")
			}
		}
		if p.checkToken(tKey) {
			p.peekToken()
			p.state = p.parseFlowSequenceEntryMappingKey
			return &event{kind: eMappingStart, implicit: [2]bool{true}, flowStyle: true}
		} else if !p.checkToken(tFlowSequenceEnd) {
			p.states = append(p.states, p.parseFlowSequenceEntryNotFirst)
			return p.parseFlowNode()
		}
	}
	p.getToken()
	p.state = p.popState()
	return &event{kind: eSequenceEnd}
}

func (p *parser) parseFlowSequenceEntryMappingKey() *event {
	p.getToken()
	if !p.checkToken(tValue, tFlowEntry, tFlowSequenceEnd) {
		p.states = append(p.states, p.parseFlowSequenceEntryMappingValue)
		return p.parseFlowNode()
	}
	p.state = p.parseFlowSequenceEntryMappingValue
	return p.processEmptyScalar()
}

func (p *parser) parseFlowSequenceEntryMappingValue() *event {
	if p.checkToken(tValue) {
		p.getToken()
		if !p.checkToken(tFlowEntry, tFlowSequenceEnd) {
			p.states = append(p.states, p.parseFlowSequenceEntryMappingEnd)
			return p.parseFlowNode()
		}
		p.state = p.parseFlowSequenceEntryMappingEnd
		return p.processEmptyScalar()
	}
	p.state = p.parseFlowSequenceEntryMappingEnd
	p.peekToken()
	return p.processEmptyScalar()
}

func (p *parser) parseFlowSequenceEntryMappingEnd() *event {
	p.state = p.parseFlowSequenceEntryNotFirst
	p.peekToken()
	return &event{kind: eMappingEnd}
}

func (p *parser) parseFlowMappingFirstKey() *event {
	p.getToken()
	return p.parseFlowMappingKey(true)
}

func (p *parser) parseFlowMappingKeyNotFirst() *event { return p.parseFlowMappingKey(false) }

func (p *parser) parseFlowMappingKey(first bool) *event {
	if !p.checkToken(tFlowMappingEnd) {
		if !first {
			if p.checkToken(tFlowEntry) {
				p.getToken()
			} else {
				parseErr("while parsing a flow mapping", "expected ',' or '}', but got '"+tokenIDs[p.peekToken().kind]+"'")
			}
		}
		if p.checkToken(tKey) {
			p.getToken()
			if !p.checkToken(tValue, tFlowEntry, tFlowMappingEnd) {
				p.states = append(p.states, p.parseFlowMappingValue)
				return p.parseFlowNode()
			}
			p.state = p.parseFlowMappingValue
			return p.processEmptyScalar()
		} else if !p.checkToken(tFlowMappingEnd) {
			p.states = append(p.states, p.parseFlowMappingEmptyValue)
			return p.parseFlowNode()
		}
	}
	p.getToken()
	p.state = p.popState()
	return &event{kind: eMappingEnd}
}

func (p *parser) parseFlowMappingValue() *event {
	if p.checkToken(tValue) {
		p.getToken()
		if !p.checkToken(tFlowEntry, tFlowMappingEnd) {
			p.states = append(p.states, p.parseFlowMappingKeyNotFirst)
			return p.parseFlowNode()
		}
		p.state = p.parseFlowMappingKeyNotFirst
		return p.processEmptyScalar()
	}
	p.state = p.parseFlowMappingKeyNotFirst
	p.peekToken()
	return p.processEmptyScalar()
}

func (p *parser) parseFlowMappingEmptyValue() *event {
	p.state = p.parseFlowMappingKeyNotFirst
	p.peekToken()
	return p.processEmptyScalar()
}

func (p *parser) processEmptyScalar() *event {
	return &event{kind: eScalar, implicit: [2]bool{true, false}, value: ""}
}
