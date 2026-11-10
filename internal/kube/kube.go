// Package kube is the service's whole surface on the apiserver: the custom-object verbs the Python
// service called through kubernetes.client.CustomObjectsApi, one ConfigMap read, one CRD read, and
// discovery. Requests are plain REST over client-go's in-cluster transport (TLS and the rotating
// ServiceAccount token), with merge-patch for every patch, as the Python client sent them.
//
// Bodies are the same JSON-shaped maps the Python dicts were, and responses decode the way Python's
// json did: integers as int64, other numbers as float64 — so a threshold of 1.0 still prints "1.0".
package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"k8s.io/client-go/rest"

	"github.com/krateo-platformops/nightly-review/internal/py"
)

// APIError is kubernetes.client.ApiException: the HTTP status the apiserver answered.
type APIError struct {
	Status int
	Reason string
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("(%d)\nReason: %s\nHTTP response body: %s", e.Status, e.Reason, e.Body)
}

// PyType names the Python class.
func (e *APIError) PyType() string { return "ApiException" }

// StatusOf is getattr(exc, "status", None): the HTTP status an error carries, or 0.
func StatusOf(err error) int {
	if s, ok := err.(interface{ HTTPStatus() int }); ok {
		return s.HTTPStatus()
	}
	if e, ok := err.(*APIError); ok {
		return e.Status
	}
	return 0
}

// HTTPStatus lets StatusOf read the status through the interface.
func (e *APIError) HTTPStatus() int { return e.Status }

// ListOpts are list_cluster_custom_object's paging arguments.
type ListOpts struct {
	Limit    int
	Continue string
}

// CustomObjects is the subset of CustomObjectsApi the service uses.
type CustomObjects interface {
	ListNamespaced(ctx context.Context, group, version, ns, plural string) (map[string]any, error)
	ListCluster(ctx context.Context, group, version, plural string, opts ListOpts) (map[string]any, error)
	GetNamespaced(ctx context.Context, group, version, ns, plural, name string) (map[string]any, error)
	CreateNamespaced(ctx context.Context, group, version, ns, plural string, body map[string]any) (map[string]any, error)
	PatchNamespaced(ctx context.Context, group, version, ns, plural, name string, body map[string]any) (map[string]any, error)
	PatchNamespacedStatus(ctx context.Context, group, version, ns, plural, name string, body map[string]any) (map[string]any, error)
}

// ConfigMap is what the analyse stage reads of one: its data, name and annotations.
type ConfigMap struct {
	Name        string
	Data        map[string]string
	Annotations map[string]string
}

// ConfigMaps reads one ConfigMap (CoreV1Api.read_namespaced_config_map).
type ConfigMaps interface {
	ReadNamespacedConfigMap(ctx context.Context, name, ns string) (*ConfigMap, error)
}

// CRDVersion is one entry of a CRD's spec.versions.
type CRDVersion struct {
	Name    string
	Served  bool
	Storage bool
}

// Served is one discovered resource: (version, plural, kind, namespaced).
type Served struct {
	Version    string
	Plural     string
	Kind       string
	Namespaced bool
}

// Client talks to the apiserver over client-go's transport.
type Client struct {
	host string
	http *http.Client
}

// InCluster builds a Client from the pod's ServiceAccount (config.load_incluster_config).
func InCluster() (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{host: strings.TrimRight(cfg.Host, "/"), http: hc}, nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, contentType string) (any, error) {
	u := c.host + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &APIError{Status: resp.StatusCode, Reason: http.StatusText(resp.StatusCode), Body: string(data)}
	}
	return py.LoadsJSON(string(data), false)
}

func asMap(v any, err error) (map[string]any, error) {
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func objPath(group, version, ns, plural string) string {
	if ns == "" {
		return fmt.Sprintf("/apis/%s/%s/%s", group, version, plural)
	}
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", group, version, ns, plural)
}

const mergePatch = "application/merge-patch+json"

// ListNamespaced is list_namespaced_custom_object.
func (c *Client) ListNamespaced(ctx context.Context, group, version, ns, plural string) (map[string]any, error) {
	return asMap(c.do(ctx, http.MethodGet, objPath(group, version, ns, plural), nil, nil, ""))
}

// ListCluster is list_cluster_custom_object, with limit/_continue when given.
func (c *Client) ListCluster(ctx context.Context, group, version, plural string, o ListOpts) (map[string]any, error) {
	q := url.Values{}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Continue != "" {
		q.Set("continue", o.Continue)
	}
	return asMap(c.do(ctx, http.MethodGet, objPath(group, version, "", plural), q, nil, ""))
}

// GetNamespaced is get_namespaced_custom_object.
func (c *Client) GetNamespaced(ctx context.Context, group, version, ns, plural, name string) (map[string]any, error) {
	return asMap(c.do(ctx, http.MethodGet, objPath(group, version, ns, plural)+"/"+name, nil, nil, ""))
}

// CreateNamespaced is create_namespaced_custom_object.
func (c *Client) CreateNamespaced(ctx context.Context, group, version, ns, plural string, body map[string]any) (map[string]any, error) {
	return asMap(c.do(ctx, http.MethodPost, objPath(group, version, ns, plural), nil, body, "application/json"))
}

// PatchNamespaced is patch_namespaced_custom_object (merge patch).
func (c *Client) PatchNamespaced(ctx context.Context, group, version, ns, plural, name string, body map[string]any) (map[string]any, error) {
	return asMap(c.do(ctx, http.MethodPatch, objPath(group, version, ns, plural)+"/"+name, nil, body, mergePatch))
}

// PatchNamespacedStatus is patch_namespaced_custom_object_status (merge patch).
func (c *Client) PatchNamespacedStatus(ctx context.Context, group, version, ns, plural, name string, body map[string]any) (map[string]any, error) {
	return asMap(c.do(ctx, http.MethodPatch, objPath(group, version, ns, plural)+"/"+name+"/status", nil, body, mergePatch))
}

// ReadNamespacedConfigMap is CoreV1Api.read_namespaced_config_map.
func (c *Client) ReadNamespacedConfigMap(ctx context.Context, name, ns string) (*ConfigMap, error) {
	m, err := asMap(c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", ns, name), nil, nil, ""))
	if err != nil {
		return nil, err
	}
	cm := &ConfigMap{Name: py.String(py.GetPath(m, "metadata", "name")), Data: map[string]string{},
		Annotations: map[string]string{}}
	data := py.Get(m, "data")
	for _, k := range py.DictKeys(data) {
		cm.Data[k] = py.String(py.Get(data, k))
	}
	ann := py.GetPath(m, "metadata", "annotations")
	for _, k := range py.DictKeys(ann) {
		cm.Annotations[k] = py.String(py.Get(ann, k))
	}
	return cm, nil
}

// CRDVersions reads a CRD's spec.versions (ApiextensionsV1Api.read_custom_resource_definition).
func (c *Client) CRDVersions(ctx context.Context, name string) ([]CRDVersion, error) {
	m, err := asMap(c.do(ctx, http.MethodGet, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"+name, nil, nil, ""))
	if err != nil {
		return nil, err
	}
	var out []CRDVersion
	for _, v := range py.List(py.GetPath(m, "spec", "versions")) {
		served, _ := py.Get(v, "served").(bool)
		storage, _ := py.Get(v, "storage").(bool)
		out = append(out, CRDVersion{Name: py.String(py.Get(v, "name")), Served: served, Storage: storage})
	}
	return out, nil
}

// GetPath is ApiClient.call_api(path, "GET", response_type="object"): a raw read, used for discovery.
func (c *Client) GetPath(ctx context.Context, path string) (any, error) {
	return c.do(ctx, http.MethodGet, path, nil, nil, "")
}
