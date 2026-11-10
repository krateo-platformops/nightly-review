package py

// Fnmatchcase is fnmatch.fnmatchcase(name, pat): `*` matches any run (slashes included, unlike
// path.Match), `?` any one character, `[seq]` / `[!seq]` a set; no case folding. On POSIX
// fnmatch.fnmatch is the same function, because os.path.normcase is the identity there.
func Fnmatchcase(name, pat string) bool {
	return fnmatch([]rune(name), compileGlob([]rune(pat)))
}

type globTok struct {
	kind   byte // 'c' literal, '?' any, '*' star, '[' set, 'n' never
	r      rune
	neg    bool
	ranges [][2]rune
}

func compileGlob(p []rune) []globTok {
	var out []globTok
	for i := 0; i < len(p); {
		c := p[i]
		i++
		switch c {
		case '*':
			if len(out) == 0 || out[len(out)-1].kind != '*' {
				out = append(out, globTok{kind: '*'})
			}
		case '?':
			out = append(out, globTok{kind: '?'})
		case '[':
			j := i
			if j < len(p) && p[j] == '!' {
				j++
			}
			if j < len(p) && p[j] == ']' {
				j++
			}
			for j < len(p) && p[j] != ']' {
				j++
			}
			if j >= len(p) {
				out = append(out, globTok{kind: 'c', r: '['})
				continue
			}
			stuff := p[i:j]
			i = j + 1
			tok := globTok{kind: '['}
			if len(stuff) == 0 {
				out = append(out, globTok{kind: 'n'})
				continue
			}
			if stuff[0] == '!' {
				tok.neg = true
				stuff = stuff[1:]
				if len(stuff) == 0 { // "[!]": any character
					out = append(out, globTok{kind: '?'})
					continue
				}
			}
			for k := 0; k < len(stuff); k++ {
				if k+2 < len(stuff) && stuff[k+1] == '-' {
					if stuff[k] <= stuff[k+2] { // a reversed range is empty, as Python drops it
						tok.ranges = append(tok.ranges, [2]rune{stuff[k], stuff[k+2]})
					}
					k += 2
					continue
				}
				tok.ranges = append(tok.ranges, [2]rune{stuff[k], stuff[k]})
			}
			if len(tok.ranges) == 0 && !tok.neg {
				out = append(out, globTok{kind: 'n'})
				continue
			}
			out = append(out, tok)
		default:
			out = append(out, globTok{kind: 'c', r: c})
		}
	}
	return out
}

func (t globTok) one(r rune) bool {
	switch t.kind {
	case 'c':
		return r == t.r
	case '?':
		return true
	case '[':
		in := false
		for _, rg := range t.ranges {
			if r >= rg[0] && r <= rg[1] {
				in = true
				break
			}
		}
		return in != t.neg
	}
	return false
}

func fnmatch(s []rune, toks []globTok) bool {
	if len(toks) == 0 {
		return len(s) == 0
	}
	if toks[0].kind == '*' {
		for i := 0; i <= len(s); i++ {
			if fnmatch(s[i:], toks[1:]) {
				return true
			}
		}
		return false
	}
	if len(s) == 0 || !toks[0].one(s[0]) {
		return false
	}
	return fnmatch(s[1:], toks[1:])
}

// Counter is collections.Counter as the service uses it: counts, and most_common() ordered by count
// with ties in first-insertion order (CPython sorts stably).
type Counter struct {
	keys   []string
	counts map[string]int
}

// NewCounter returns an empty Counter.
func NewCounter() *Counter { return &Counter{counts: map[string]int{}} }

// Add is counter[key] += n.
func (c *Counter) Add(key string, n int) {
	if _, ok := c.counts[key]; !ok {
		c.keys = append(c.keys, key)
	}
	c.counts[key] += n
}

// Get is counter[key].
func (c *Counter) Get(key string) int { return c.counts[key] }

// Len is len(counter).
func (c *Counter) Len() int { return len(c.keys) }

// Total is sum(counter.values()).
func (c *Counter) Total() int {
	t := 0
	for _, k := range c.keys {
		t += c.counts[k]
	}
	return t
}

// KV is one (key, count) pair.
type KV struct {
	Key   string
	Count int
}

// MostCommon is counter.most_common(n); n < 0 means all.
func (c *Counter) MostCommon(n int) []KV {
	out := make([]KV, len(c.keys))
	for i, k := range c.keys {
		out[i] = KV{k, c.counts[k]}
	}
	// stable insertion sort by count descending: ties keep insertion order, as sorted() does
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Count > out[j-1].Count; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if n >= 0 && n < len(out) {
		out = out[:n]
	}
	return out
}
