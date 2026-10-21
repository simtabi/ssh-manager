package providers

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Next-page URLs come from the response body, and each one is a fresh request
// carrying the provider credential, so the redirect policy in httpjson never sees
// it. A compromised or spoofed page could otherwise name any host and receive the
// token. These tests use a fake transport, not a listening server, so they run
// where binding a port is not allowed.

type pageTripper func(*http.Request) (*http.Response, error)

func (f pageTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeAPI swaps http.DefaultTransport (the one httpjson's client falls back to)
// for a function, and records every host a request reached.
func fakeAPI(t *testing.T, serve func(*http.Request) string) *[]string {
	t.Helper()
	var hosts []string
	orig := http.DefaultTransport
	http.DefaultTransport = pageTripper(func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Host)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
			Body: io.NopCloser(strings.NewReader(serve(r)))}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = orig })
	return &hosts
}

func runCred(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func assertRefused(t *testing.T, err error, hosts []string) {
	t.Helper()
	if err == nil {
		t.Fatal("a next link to another origin should stop with an error")
	}
	if !strings.Contains(err.Error(), "collector.example.net") {
		t.Errorf("error should name the refused host: %v", err)
	}
	for _, h := range hosts {
		if h == "collector.example.net" {
			t.Error("the credential was sent to the host the next link named")
			break
		}
	}
	if len(hosts) == 0 {
		t.Error("no request was made; the test proves nothing")
	}
}

func TestDigitalOceanRefusesACrossOriginNextLink(t *testing.T) {
	old := doBase
	doBase = "https://api.example.com/v2"
	defer func() { doBase = old }()
	hosts := fakeAPI(t, func(*http.Request) string {
		return `{"ssh_keys":[],"links":{"pages":{"next":"https://collector.example.net/v2/account/keys?page=2"}}}`
	})

	_, err := doOps{}.listKeys(runCred(t))
	assertRefused(t, err, *hosts)
}

// A scheme downgrade on the same host is a different origin too.
func TestDigitalOceanRefusesAnHTTPNextLink(t *testing.T) {
	old := doBase
	doBase = "https://api.example.com/v2"
	defer func() { doBase = old }()
	hosts := fakeAPI(t, func(*http.Request) string {
		return `{"ssh_keys":[],"links":{"pages":{"next":"http://api.example.com/v2/account/keys?page=2"}}}`
	})

	if _, err := (doOps{}).listKeys(runCred(t)); err == nil {
		t.Fatal("an https -> http next link should stop with an error")
	}
	if len(*hosts) != 1 {
		t.Errorf("made %d requests, want only the first page", len(*hosts))
	}
}

// Same-origin pagination still works, explicit default port included.
func TestDigitalOceanFollowsASameOriginNextLink(t *testing.T) {
	old := doBase
	doBase = "https://api.example.com/v2"
	defer func() { doBase = old }()
	fakeAPI(t, func(r *http.Request) string {
		if r.URL.Query().Get("page") == "2" {
			return `{"ssh_keys":[{"id":2,"name":"b","public_key":"p"}],"links":{}}`
		}
		return `{"ssh_keys":[{"id":1,"name":"a","public_key":"p"}],
		         "links":{"pages":{"next":"https://api.example.com:443/v2/account/keys?page=2"}}}`
	})

	keys, err := doOps{}.listKeys(runCred(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Errorf("got %d keys, want both pages", len(keys))
	}
}

func TestGenericRestRefusesACrossOriginNextLink(t *testing.T) {
	ops := genericRestOps{spec: Spec{Rest: map[string]any{
		"base_url":         "https://api.example.com",
		"list_path":        "/keys",
		"list_field":       "keys",
		"next_field":       "links.next",
		"auth_header_name": "Auth-API-Token",
	}}}
	hosts := fakeAPI(t, func(*http.Request) string {
		return `{"keys":[],"links":{"next":"https://collector.example.net/keys?page=2"}}`
	})

	_, err := ops.listKeys(runCred(t))
	assertRefused(t, err, *hosts)
}
