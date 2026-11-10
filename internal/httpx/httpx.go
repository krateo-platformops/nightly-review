// Package httpx carries the two pieces of `requests` behaviour the service's messages depend on:
// raise_for_status()'s error text, and reading a body as text.
package httpx

import (
	"fmt"
	"io"
	"net/http"
)

// HTTPError is requests.HTTPError, raised by RaiseForStatus.
type HTTPError struct {
	Status int
	Reason string
	URL    string
}

func (e *HTTPError) Error() string {
	kind := "Client"
	if e.Status >= 500 {
		kind = "Server"
	}
	return fmt.Sprintf("%d %s Error: %s for url: %s", e.Status, kind, e.Reason, e.URL)
}

// PyType names the Python class.
func (e *HTTPError) PyType() string { return "HTTPError" }

// HTTPStatus exposes the status, as exc.response.status_code.
func (e *HTTPError) HTTPStatus() int { return e.Status }

// RaiseForStatus is response.raise_for_status(): an error for a 4xx or 5xx answer.
func RaiseForStatus(resp *http.Response) error {
	if resp.StatusCode < 400 || resp.StatusCode >= 600 {
		return nil
	}
	reason := http.StatusText(resp.StatusCode)
	if len(resp.Status) > 4 {
		reason = resp.Status[4:]
	}
	return &HTTPError{Status: resp.StatusCode, Reason: reason, URL: resp.Request.URL.String()}
}

// Text reads the whole body as a string (response.text) and closes it.
func Text(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
