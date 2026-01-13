package ml

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// sharedTransport provides connection pooling across all ML service HTTP clients.
// This improves performance by reusing TCP connections and reducing TLS handshakes.
// All ML clients (intent, safeguard, semantic, vector, etc.) share this transport.
var sharedTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     90 * time.Second,
}

// NewHTTPClient creates an HTTP client with shared transport and specified timeout.
// All ML service clients should use this to benefit from connection pooling.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: sharedTransport,
	}
}

// APIError represents an HTTP API error with status code and response body.
// Use errors.As() to extract status code for programmatic handling.
type APIError struct {
	StatusCode int
	Body       string
	Service    string // Optional: which service returned the error
}

func (e *APIError) Error() string {
	if e.Service != "" {
		return fmt.Sprintf("%s: HTTP %d: %s", e.Service, e.StatusCode, e.Body)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
}

// CheckResponse returns an APIError if the response status is not 2xx.
// The response body is read and included in the error for debugging.
// Call this before attempting to decode the response body.
func CheckResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// Limit body read to prevent memory exhaustion from malicious responses
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &APIError{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
}

// CheckResponseWithService returns an APIError with service name context.
func CheckResponseWithService(resp *http.Response, service string) error {
	if resp := CheckResponse(resp); resp != nil {
		if apiErr, ok := resp.(*APIError); ok {
			apiErr.Service = service
			return apiErr
		}
		return resp
	}
	return nil
}
