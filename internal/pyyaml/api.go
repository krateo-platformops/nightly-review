package pyyaml

import (
	"regexp"
	"strings"
)

// RECURSION. CPython's default recursion limit is 1000 frames. PyYAML's composer recurses two frames per
// level of nesting (compose_node -> compose_*_node) and SafeRepresenter three (represent_data ->
// represent_dict/list -> represent_mapping/sequence), so a document nested deeply enough raises RecursionError
// — which is NOT a YAMLError, so normalise_body propagates it. The limits are nesting depths, counting the
// innermost node, measured by the parity harness (measure_depth.py) at the stack depth the service calls from:
// normalise_body under main -> validate_batch -> fingerprint, and safe_load_all under main -> validate_batch ->
// alert_kind_violation. The composer's exact limit also depends on what the scanner is doing at the deepest
// point (a flow mapping's leaf fails one level earlier than a flow sequence's); these limits are the sequence
// ones, and the fixtures keep away from the boundary.
const (
	// composeMaxDepthLoad: yaml.safe_load inside normalise_body.
	composeMaxDepthLoad = 491
	// composeMaxDepthLoadAll: yaml.safe_load_all inside alert_kind_violation (one frame shallower).
	composeMaxDepthLoadAll = 492
	// representMaxDepth: yaml.safe_dump inside normalise_body.
	representMaxDepth = 329
)

func recursionError() { raise(pyErr("RecursionError", "maximum recursion depth exceeded")) }

// SafeLoad is yaml.safe_load: exactly one document (or none, which is None).
func SafeLoad(src string) (v Value, err error) {
	defer catch(&err)
	c := newComposer(src)
	c.maxDepth = composeMaxDepthLoad
	n := c.getSingleNode()
	if n == nil {
		return nil, nil
	}
	return newConstructor().constructDocument(n), nil
}

// SafeLoadAll is list(yaml.safe_load_all(src)). On an error it returns the documents constructed before it,
// as a generator consumer would have seen them, and the error.
func SafeLoadAll(src string) (docs []Value, err error) {
	defer catch(&err)
	c := newComposer(src)
	c.maxDepth = composeMaxDepthLoadAll
	ctor := newConstructor()
	for c.checkNode() {
		n := c.composeDocument()
		docs = append(docs, ctor.constructDocument(n))
	}
	return docs, nil
}

var pyWhitespaceRun = regexp.MustCompile(`[\t\n\v\f\r\x{1c}-\x{20}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]+`)

// NormaliseBody ports proposals.normalise_body:
//
//	if fmt == "yaml":
//	    try: data = yaml.safe_load(content)
//	    except yaml.YAMLError: data = None
//	    if isinstance(data, (dict, list)):
//	        return yaml.safe_dump(data, sort_keys=True, default_flow_style=False).strip()
//	lines = []
//	for line in content.splitlines():
//	    stripped = line.strip()
//	    if not stripped or stripped.startswith("#"): continue
//	    lines.append(re.sub(r"\s+", " ", stripped))
//	return "\n".join(lines)
//
// The error is a Python exception normalise_body would NOT catch (*PyError); a YAMLError never escapes.
func NormaliseBody(content, format string) (string, error) {
	if format == "yaml" {
		data, err := SafeLoad(content)
		if err != nil {
			if _, isYAML := err.(*YAMLError); !isYAML {
				return "", err
			}
			data = nil
		}
		if IsCollection(data) {
			out, err := SafeDump(data)
			if err != nil {
				return "", err
			}
			return pyStrip(out), nil
		}
	}
	var lines []string
	for _, line := range SplitLines(content) {
		stripped := pyStrip(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		lines = append(lines, pyWhitespaceRun.ReplaceAllString(stripped, " "))
	}
	return strings.Join(lines, "\n"), nil
}

// SplitLines is str.splitlines(): it breaks on \n, \r, \r\n, \v, \f, \x1c, \x1d, \x1e, \x85, \u2028, \u2029,
// and a trailing break does not produce an empty last line.
func SplitLines(s string) []string {
	var out []string
	rs := []rune(s)
	start := 0
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, string(rs[start:i]))
			start = i + 1
		case '\r':
			out = append(out, string(rs[start:i]))
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}
