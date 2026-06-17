// Package httpjson is a minimal JSON-over-HTTP client for the REST provider
// adapters, ported from util/http.py. Dependency-free (net/http), with bearer/
// custom-header auth, retry-with-backoff on 429/5xx for idempotent methods, and a
// safe redirect policy (refuse https->http; drop credential headers cross-origin).
package httpjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var retryStatus = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}
var idempotent = map[string]bool{"GET": true, "HEAD": true, "PUT": true, "DELETE": true}
var sensitiveHeaders = map[string]bool{"authorization": true, "x-auth-token": true, "cookie": true}

// HTTPError is a failed REST call (non-2xx, or transport error after retries).
type HTTPError struct{ Msg string }

func (e *HTTPError) Error() string { return e.Msg }

func errf(format string, a ...any) error { return &HTTPError{Msg: fmt.Sprintf(format, a...)} }

// client follows redirects but refuses an https->non-https downgrade and strips
// credential headers when a redirect crosses origin.
var client = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errf("stopped after 10 redirects")
		}
		prev := via[len(via)-1].URL
		if prev.Scheme == "https" && req.URL.Scheme != "https" {
			return errf("refusing an https -> non-https redirect")
		}
		if origin(prev) != origin(req.URL) {
			for h := range req.Header {
				if sensitiveHeaders[strings.ToLower(h)] {
					req.Header.Del(h)
				}
			}
		}
		return nil
	},
}

func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	return u.Scheme + "://" + u.Hostname() + ":" + port
}

// RequestJSON makes a JSON request and returns the parsed body (an empty map for
// 204/empty). headers carries auth (e.g. Authorization or X-Auth-Token).
func RequestJSON(method, rawURL string, headers map[string]string, body any) (any, error) {
	const retries = 4
	var data []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		data = b
	}
	method = strings.ToUpper(method)
	for attempt := 0; attempt <= retries; attempt++ {
		req, err := http.NewRequest(method, rawURL, bytesReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if data != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			if idempotent[method] && attempt < retries {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			return nil, errf("%s %s failed: %v", method, rawURL, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			if idempotent[method] && retryStatus[resp.StatusCode] && attempt < retries {
				time.Sleep(retryWait(resp, attempt))
				continue
			}
			return nil, errf("%s %s -> %d %s", method, rawURL, resp.StatusCode,
				strings.TrimSpace(truncate(string(raw), 300)))
		}
		if resp.StatusCode == 204 || len(raw) == 0 {
			return map[string]any{}, nil
		}
		var out any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, errf("%s %s -> non-JSON response: %s", method, rawURL, truncate(string(raw), 300))
		}
		return out, nil
	}
	return nil, errf("%s %s not attempted (retries=%d)", method, rawURL, retries)
}

func retryWait(resp *http.Response, attempt int) time.Duration {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil {
			if n > 30 {
				n = 30
			}
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(attempt+1) * time.Second
}

func bytesReader(data []byte) io.Reader {
	if data == nil {
		return nil
	}
	return bytes.NewReader(data)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
