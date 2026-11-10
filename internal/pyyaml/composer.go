package pyyaml

import "regexp"

// --- nodes.py -----------------------------------------------------------------------------------------------

type nodeKind int

const (
	scalarNode nodeKind = iota
	sequenceNode
	mappingNode
)

type nodePair struct{ key, value *node }

type node struct {
	kind      nodeKind
	tag       string
	value     string     // scalar
	items     []*node    // sequence
	pairs     []nodePair // mapping
	style     rune
	flowStyle bool
}

func (n *node) id() string {
	switch n.kind {
	case scalarNode:
		return "scalar"
	case sequenceNode:
		return "sequence"
	}
	return "mapping"
}

// --- resolver.py --------------------------------------------------------------------------------------------

const (
	tagStr       = "tag:yaml.org,2002:str"
	tagSeq       = "tag:yaml.org,2002:seq"
	tagMap       = "tag:yaml.org,2002:map"
	tagBool      = "tag:yaml.org,2002:bool"
	tagFloat     = "tag:yaml.org,2002:float"
	tagInt       = "tag:yaml.org,2002:int"
	tagMerge     = "tag:yaml.org,2002:merge"
	tagNull      = "tag:yaml.org,2002:null"
	tagTimestamp = "tag:yaml.org,2002:timestamp"
	tagValue     = "tag:yaml.org,2002:value"
	tagYAML      = "tag:yaml.org,2002:yaml"
	tagBinary    = "tag:yaml.org,2002:binary"
	tagOmap      = "tag:yaml.org,2002:omap"
	tagPairs     = "tag:yaml.org,2002:pairs"
	tagSet       = "tag:yaml.org,2002:set"
)

// The implicit resolvers, in the order Resolver.add_implicit_resolver registered them. Python's `$` (no
// MULTILINE) also matches just before a trailing newline, hence `\n?\z`; re.X whitespace outside character
// classes is dropped, inside them it is kept.
type implicitResolver struct {
	tag   string
	re    *regexp.Regexp
	first string // the first characters it is registered under; "" means the empty value
}

var implicitResolvers = []implicitResolver{
	{tagBool, regexp.MustCompile(`\A(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)\n?\z`), "yYnNtTfFoO"},
	{tagFloat, regexp.MustCompile(`\A(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\n?\z`), "-+0123456789."},
	{tagInt, regexp.MustCompile(`\A(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)\n?\z`), "-+0123456789"},
	{tagMerge, regexp.MustCompile(`\A(?:<<)\n?\z`), "<"},
	{tagNull, regexp.MustCompile(`\A(?:~|null|Null|NULL|)\n?\z`), "~nN\x00"},
	{tagTimestamp, regexp.MustCompile(`\A(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)\n?\z`), "0123456789"},
	{tagValue, regexp.MustCompile(`\A(?:=)\n?\z`), "="},
	{tagYAML, regexp.MustCompile(`\A(?:!|&|\*)\n?\z`), "!&*"},
}

// resolve ports BaseResolver.resolve for the default Resolver (no path resolvers are registered).
func resolve(kind nodeKind, value string, implicit [2]bool) string {
	if kind == scalarNode && implicit[0] {
		for _, r := range implicitResolvers {
			var registered bool
			if value == "" {
				registered = r.first == "~nN\x00" // only null is registered under ''
			} else {
				registered = in([]rune(value)[0], r.first) && []rune(value)[0] != 0
			}
			if registered && r.re.MatchString(value) {
				return r.tag
			}
		}
	}
	switch kind {
	case scalarNode:
		return tagStr
	case sequenceNode:
		return tagSeq
	}
	return tagMap
}

// --- composer.py --------------------------------------------------------------------------------------------

type composer struct {
	*parser
	anchors  map[string]*node
	depth    int
	maxDepth int
}

func newComposer(src string) *composer {
	return &composer{parser: newParser(src), anchors: map[string]*node{}}
}

func composeErr(context, problem string) { raise(yamlErr(context, problem)) }

func (c *composer) checkNode() bool {
	if c.checkEvent(eStreamStart) {
		c.getEvent()
	}
	return !c.checkEvent(eStreamEnd)
}

func (c *composer) getSingleNode() *node {
	c.getEvent()
	var doc *node
	if !c.checkEvent(eStreamEnd) {
		doc = c.composeDocument()
	}
	if !c.checkEvent(eStreamEnd) {
		c.getEvent()
		composeErr("expected a single document in the stream", "but found another document")
	}
	c.getEvent()
	return doc
}

func (c *composer) composeDocument() *node {
	c.getEvent()
	n := c.composeNode()
	c.getEvent()
	c.anchors = map[string]*node{}
	return n
}

func (c *composer) composeNode() *node {
	if c.checkEvent(eAlias) {
		e := c.getEvent()
		n, ok := c.anchors[*e.anchor]
		if !ok {
			composeErr("", "found undefined alias "+pyRepr(*e.anchor))
		}
		return n
	}
	e := c.peekEvent()
	if e.anchor != nil {
		if _, dup := c.anchors[*e.anchor]; dup {
			composeErr("found duplicate anchor "+pyRepr(*e.anchor)+"; first occurrence", "second occurrence")
		}
	}
	c.depth++
	if c.depth > c.maxDepth {
		recursionError()
	}
	var n *node
	switch {
	case c.checkEvent(eScalar):
		n = c.composeScalarNode(e.anchor)
	case c.checkEvent(eSequenceStart):
		n = c.composeSequenceNode(e.anchor)
	case c.checkEvent(eMappingStart):
		n = c.composeMappingNode(e.anchor)
	}
	c.depth--
	return n
}

func (c *composer) composeScalarNode(anchor *string) *node {
	e := c.getEvent()
	var tag string
	if e.tag == nil || *e.tag == "!" {
		tag = resolve(scalarNode, e.value, e.implicit)
	} else {
		tag = *e.tag
	}
	n := &node{kind: scalarNode, tag: tag, value: e.value, style: e.style}
	if anchor != nil {
		c.anchors[*anchor] = n
	}
	return n
}

func (c *composer) composeSequenceNode(anchor *string) *node {
	e := c.getEvent()
	var tag string
	if e.tag == nil || *e.tag == "!" {
		tag = resolve(sequenceNode, "", e.implicit)
	} else {
		tag = *e.tag
	}
	n := &node{kind: sequenceNode, tag: tag, flowStyle: e.flowStyle}
	if anchor != nil {
		c.anchors[*anchor] = n
	}
	for !c.checkEvent(eSequenceEnd) {
		n.items = append(n.items, c.composeNode())
	}
	c.getEvent()
	return n
}

func (c *composer) composeMappingNode(anchor *string) *node {
	e := c.getEvent()
	var tag string
	if e.tag == nil || *e.tag == "!" {
		tag = resolve(mappingNode, "", e.implicit)
	} else {
		tag = *e.tag
	}
	n := &node{kind: mappingNode, tag: tag, flowStyle: e.flowStyle}
	if anchor != nil {
		c.anchors[*anchor] = n
	}
	for !c.checkEvent(eMappingEnd) {
		k := c.composeNode()
		v := c.composeNode()
		n.pairs = append(n.pairs, nodePair{k, v})
	}
	c.getEvent()
	return n
}
