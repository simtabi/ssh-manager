package httpjson

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Parity reference: python-final:src/ssh_manager/util/http.py. Same retry set
// (429/5xx), same idempotent-only retry rule, same redirect policy - refuse an
// https->non-https downgrade, and drop credential headers when a redirect
// crosses origin, because the stdlib would otherwise forward a bearer token to
// whatever host the redirect names.

// noSleep replaces the backoff for the duration of a test, and records what the
// code asked to wait so the schedule can still be asserted.
func noSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	orig := sleep
	sleep = func(d time.Duration) { waits = append(waits, d) }
	t.Cleanup(func() { sleep = orig })
	return &waits
}

func TestRequestJSONSendsHeadersAndParsesTheBody(t *testing.T) {
	var gotAuth, gotAccept, gotCT, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAccept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		gotCT, gotMethod = r.Header.Get("Content-Type"), r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"name":"key"}`))
	}))
	defer srv.Close()

	out, err := RequestJSON("post", srv.URL, map[string]string{"Authorization": "Bearer tok"},
		map[string]any{"name": "key"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q, want it upper-cased to POST", gotMethod)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccept != "application/json" || gotCT != "application/json" {
		t.Errorf("Accept=%q Content-Type=%q", gotAccept, gotCT)
	}
	if gotBody["name"] != "key" {
		t.Errorf("request body = %v", gotBody)
	}
	m, ok := out.(map[string]any)
	if !ok || m["name"] != "key" {
		t.Errorf("response = %#v", out)
	}
}

// 204 and an empty 200 both come back as an empty map rather than nil, so a
// caller can index the result without checking for nil first.
func TestEmptyResponsesBecomeAnEmptyMap(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		out, err := RequestJSON("GET", srv.URL, nil, nil)
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		m, ok := out.(map[string]any)
		if !ok || len(m) != 0 {
			t.Errorf("status %d: got %#v, want an empty map", status, out)
		}
	}
}

// A retryable status is retried for an idempotent method, and the eventual
// success is returned.
func TestRetriesIdempotentRequests(t *testing.T) {
	waits := noSleep(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	out, err := RequestJSON("GET", srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m := out.(map[string]any); m["ok"] != true {
		t.Errorf("response = %#v", out)
	}
	if calls != 3 {
		t.Errorf("server saw %d calls, want 3 (two failures then a success)", calls)
	}
	if len(*waits) != 2 {
		t.Fatalf("backed off %d times, want 2", len(*waits))
	}
	if (*waits)[0] >= (*waits)[1] {
		t.Errorf("backoff should grow: %v", *waits)
	}
}

// A POST is never retried. A 502 often means the request reached the backend and
// may have succeeded, so a retry risks creating the resource twice - which for
// these adapters means a duplicate SSH key on the account.
func TestDoesNotRetryNonIdempotentRequests(t *testing.T) {
	noSleep(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	if _, err := RequestJSON("POST", srv.URL, nil, map[string]any{"x": 1}); err == nil {
		t.Fatal("a 502 should be an error")
	}
	if calls != 1 {
		t.Errorf("server saw %d calls, want exactly 1 - a POST must not be retried", calls)
	}
}

// A 4xx that is not in the retry set fails immediately, and the message carries
// the server's explanation.
func TestClientErrorsFailImmediatelyAndReportTheBody(t *testing.T) {
	noSleep(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"bad token"}`))
	}))
	defer srv.Close()

	_, err := RequestJSON("GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("401 should be an error")
	}
	if calls != 1 {
		t.Errorf("401 is not retryable, but the server saw %d calls", calls)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "bad token") {
		t.Errorf("error should carry the status and the body: %v", err)
	}
}

// An enormous error body is truncated, so a misbehaving API cannot flood the
// terminal through an error message.
func TestErrorBodyIsTruncated(t *testing.T) {
	noSleep(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()

	_, err := RequestJSON("GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("403 should be an error")
	}
	if len(err.Error()) > 500 {
		t.Errorf("error message is %d bytes; the body should have been truncated", len(err.Error()))
	}
}

// Retry-After is honoured and capped, so a hostile or broken API cannot park the
// process for an hour.
func TestRetryAfterIsHonouredAndCapped(t *testing.T) {
	cases := map[string]time.Duration{
		"5":       5 * time.Second,
		"3600":    30 * time.Second, // capped
		"":        1 * time.Second,  // absent -> linear backoff
		"garbage": 1 * time.Second,  // unparseable -> linear backoff
	}
	for header, want := range cases {
		resp := &http.Response{Header: http.Header{}}
		if header != "" {
			resp.Header.Set("Retry-After", header)
		}
		if got := retryWait(resp, 0); got != want {
			t.Errorf("Retry-After %q -> %v, want %v", header, got, want)
		}
	}
}

func TestNonJSONResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	if _, err := RequestJSON("GET", srv.URL, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "non-JSON") {
		t.Errorf("want a non-JSON error, got %v", err)
	}
}

// The redirect policy, tested directly - it is security behaviour, and going
// over the wire would need a TLS server just to observe it.
func TestRedirectPolicyRefusesDowngradeAndStripsCredentials(t *testing.T) {
	mk := func(rawURL string, headers map[string]string) *http.Request {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		req := &http.Request{URL: u, Header: http.Header{}}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req
	}

	t.Run("https to http is refused", func(t *testing.T) {
		via := []*http.Request{mk("https://api.example.com/keys", nil)}
		err := client.CheckRedirect(mk("http://api.example.com/keys", nil), via)
		if err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("a downgrade should be refused, got %v", err)
		}
	})

	t.Run("credentials are dropped across origins", func(t *testing.T) {
		via := []*http.Request{mk("https://api.example.com/keys", nil)}
		next := mk("https://evil.example.net/keys", map[string]string{
			"Authorization": "Bearer tok",
			"X-Auth-Token":  "tok",
			"Cookie":        "session=1",
			"Accept":        "application/json",
		})
		if err := client.CheckRedirect(next, via); err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{"Authorization", "X-Auth-Token", "Cookie"} {
			if next.Header.Get(h) != "" {
				t.Errorf("%s survived a cross-origin redirect", h)
			}
		}
		if next.Header.Get("Accept") == "" {
			t.Error("a non-credential header should have been kept")
		}
	})

	t.Run("credentials survive a same-origin redirect", func(t *testing.T) {
		via := []*http.Request{mk("https://api.example.com/keys", nil)}
		// Explicit :443 is the same origin as the default port.
		next := mk("https://api.example.com:443/keys/2",
			map[string]string{"Authorization": "Bearer tok"})
		if err := client.CheckRedirect(next, via); err != nil {
			t.Fatal(err)
		}
		if next.Header.Get("Authorization") == "" {
			t.Error("a same-origin redirect should keep the token; :443 is the default port")
		}
	})

	t.Run("redirect chains are bounded", func(t *testing.T) {
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = mk("https://api.example.com/", nil)
		}
		if err := client.CheckRedirect(mk("https://api.example.com/", nil), via); err == nil {
			t.Error("an endless redirect chain should be stopped")
		}
	})
}
