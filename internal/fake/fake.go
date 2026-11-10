// Package fake holds the tests' stand-ins for the apiserver, Postgres and HTTP: the Go forms of the
// Python suite's _Api, _Conn and monkeypatched `requests`.
package fake

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/krateo-platformops/nightly-review/internal/kube"
	"github.com/krateo-platformops/nightly-review/internal/pg"
	"github.com/krateo-platformops/nightly-review/internal/py"
)

// API is enough of CustomObjectsApi to drive a whole run, recording every write. Like the Python
// suite's _Api: proposals are stored by name; alerts, agents and flexes are fixed lists; cluster lists
// are served by plural; Configurations by (plural, name).
type API struct {
	mu        sync.Mutex
	Proposals map[string]map[string]any
	Order     []string
	Alerts    []any
	Agents    []any
	Flexes    []any
	Runs      []any
	Cluster   map[string][]any
	Configs   map[[2]string]map[string]any
	// Fail makes a list of that plural fail; Taken makes a create of that name answer 409.
	Fail  map[string]error
	Taken map[string]bool

	StatusWrites []Write
	Creates      []Create
	SpecPatches  []Write
	Reads        []string
	// LabelPatches applies main-resource label patches to stored proposals (spec-decision tests).
	LabelPatches bool
}

// Write is one patch: (plural, name, body).
type Write struct {
	Plural string
	Name   string
	Body   map[string]any
}

// Create is one create: (plural, body).
type Create struct {
	Plural string
	Body   map[string]any
}

// NewAPI builds an API holding these proposals.
func NewAPI(proposals ...map[string]any) *API {
	a := &API{Proposals: map[string]map[string]any{}, Cluster: map[string][]any{}, Configs: map[[2]string]map[string]any{},
		Fail: map[string]error{}, Taken: map[string]bool{}}
	for _, p := range proposals {
		a.put(p)
	}
	return a
}

func (a *API) put(p map[string]any) {
	name := py.Str(py.GetPath(p, "metadata", "name"))
	if _, ok := a.Proposals[name]; !ok {
		a.Order = append(a.Order, name)
	}
	a.Proposals[name] = p
}

// ProposalList returns the stored proposals in insertion order.
func (a *API) ProposalList() []any {
	out := make([]any, 0, len(a.Order))
	for _, n := range a.Order {
		out = append(out, a.Proposals[n])
	}
	return out
}

func items(xs []any) map[string]any {
	if xs == nil {
		xs = []any{}
	}
	return map[string]any{"items": deepCopy(xs), "metadata": map[string]any{}}
}

// ListNamespaced serves proposals, alerts, flexes and reviewruns.
func (a *API) ListNamespaced(_ context.Context, group, version, ns, plural string) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Reads = append(a.Reads, "list "+plural)
	if err := a.Fail[plural]; err != nil {
		return nil, err
	}
	switch plural {
	case "proposals":
		return map[string]any{"items": a.ProposalList()}, nil
	case "alerts":
		return items(a.Alerts), nil
	case "flexes":
		return items(a.Flexes), nil
	case "reviewruns":
		return items(a.Runs), nil
	}
	return items(nil), nil
}

// ListCluster serves agents and the cluster lists.
func (a *API) ListCluster(_ context.Context, group, version, plural string, _ kube.ListOpts) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Reads = append(a.Reads, "list "+group+" "+version+" "+plural)
	if err := a.Fail[plural]; err != nil {
		return nil, err
	}
	if plural == "agents" {
		return items(a.Agents), nil
	}
	return items(a.Cluster[plural]), nil
}

// GetNamespaced serves proposals and Configurations.
func (a *API) GetNamespaced(_ context.Context, group, version, ns, plural, name string) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Reads = append(a.Reads, "get "+plural+" "+name)
	if plural != "proposals" {
		c, ok := a.Configs[[2]string{plural, name}]
		if !ok {
			return nil, py.Errorf("KeyError", "(%s, %s)", py.StrRepr(plural), py.StrRepr(name))
		}
		return deepCopy(c).(map[string]any), nil
	}
	p, ok := a.Proposals[name]
	if !ok {
		return nil, &kube.APIError{Status: 404, Reason: "Not Found"}
	}
	return p, nil
}

// CreateNamespaced records the create and stores proposals.
func (a *API) CreateNamespaced(_ context.Context, group, version, ns, plural string, body map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	name := py.Str(py.GetPath(body, "metadata", "name"))
	if a.Taken[name] {
		return nil, &kube.APIError{Status: 409, Reason: "Conflict"}
	}
	body = deepCopy(body).(map[string]any)
	a.Creates = append(a.Creates, Create{plural, body})
	if plural == "proposals" {
		a.put(body)
	}
	return body, nil
}

// PatchNamespaced records the patch (and applies labels when LabelPatches is set).
func (a *API) PatchNamespaced(_ context.Context, group, version, ns, plural, name string, body map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	body = deepCopy(body).(map[string]any)
	a.SpecPatches = append(a.SpecPatches, Write{plural, name, body})
	if labels, ok := py.GetPath(body, "metadata", "labels").(map[string]any); ok && a.LabelPatches && plural == "proposals" {
		p := a.Proposals[name]
		md, _ := p["metadata"].(map[string]any)
		if md == nil {
			md = map[string]any{}
			p["metadata"] = md
		}
		l, _ := md["labels"].(map[string]any)
		if l == nil {
			l = map[string]any{}
			md["labels"] = l
		}
		for k, v := range labels {
			l[k] = v
		}
	}
	return body, nil
}

// PatchNamespacedStatus records the status write and applies it to a stored proposal.
func (a *API) PatchNamespacedStatus(_ context.Context, group, version, ns, plural, name string, body map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	body = deepCopy(body).(map[string]any)
	a.StatusWrites = append(a.StatusWrites, Write{plural, name, body})
	if p, ok := a.Proposals[name]; ok && plural == "proposals" {
		st, _ := p["status"].(map[string]any)
		if st == nil {
			st = map[string]any{}
			p["status"] = st
		}
		for k, v := range body["status"].(map[string]any) {
			st[k] = v
		}
	}
	return body, nil
}

// StatusesOf returns the bodies' status maps written for a plural, in order.
func (a *API) StatusesOf(plural string) []map[string]any {
	var out []map[string]any
	for _, w := range a.StatusWrites {
		if w.Plural == plural {
			out = append(out, w.Body["status"].(map[string]any))
		}
	}
	return out
}

// CreatesOf returns the created bodies of a plural, in order.
func (a *API) CreatesOf(plural string) []map[string]any {
	var out []map[string]any
	for _, c := range a.Creates {
		if c.Plural == plural {
			out = append(out, c.Body)
		}
	}
	return out
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case *py.OMap:
		return deepCopy(py.Plain(x))
	}
	return py.Plain(v)
}

// DeepCopy copies a JSON-shaped value.
func DeepCopy(v any) any { return deepCopy(v) }

// ConfigMaps serves ConfigMaps by name.
type ConfigMaps map[string]*kube.ConfigMap

// ReadNamespacedConfigMap returns the named ConfigMap or a forbidden error.
func (c ConfigMaps) ReadNamespacedConfigMap(_ context.Context, name, ns string) (*kube.ConfigMap, error) {
	if cm, ok := c[name]; ok {
		return cm, nil
	}
	return nil, py.Errorf("ApiException", "configmaps %s is forbidden", py.StrRepr(name))
}

// Conn is a pg.Conn answering each query by a function of its text, recording what it ran.
type Conn struct {
	mu     sync.Mutex
	Answer func(query string, args map[string]any) ([][]any, error)
	SQL    []Query
	Closed bool
}

// Query is one recorded statement.
type Query struct {
	SQL  string
	Args map[string]any
}

// Run records and answers.
func (c *Conn) Run(_ context.Context, query string, args map[string]any) ([][]any, error) {
	c.mu.Lock()
	c.SQL = append(c.SQL, Query{query, args})
	c.mu.Unlock()
	return c.Answer(query, args)
}

// Close records the close.
func (c *Conn) Close() error { c.Closed = true; return nil }

// UseConn makes pg.Connect return conn, and returns a function restoring the real one.
func UseConn(conn pg.Conn) func() {
	saved := pg.Connect
	pg.Connect = func(context.Context, pg.Params) (pg.Conn, error) { return conn, nil }
	return func() { pg.Connect = saved }
}

// RoundTrip answers HTTP requests with a function: the Go form of a monkeypatched `requests`.
type RoundTrip func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Response builds a response with a status and a body.
func Response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}
}

// Client is an http.Client served by f.
func Client(f RoundTrip) *http.Client { return &http.Client{Transport: f} }
