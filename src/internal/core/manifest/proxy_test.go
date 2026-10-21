package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func hostFrom(t *testing.T, raw string) (*Manifest, error) {
	t.Helper()
	var m Manifest
	if err := json.Unmarshal([]byte(`{"version":1,"profiles":{"p":{"hosts":[`+raw+`]}}}`), &m); err != nil {
		return nil, err
	}
	return &m, m.Validate()
}

// A Cloudflare Access host is reached through `cloudflared access ssh`; the
// manifest names the kind, and only kinds sshmgr knows how to render.
func TestProxyKindsAreValidated(t *testing.T) {
	if _, err := hostFrom(t, `{"alias":"ssh-web-00","hostname":"ssh-web-00.simtabi.com","user":"adm-imani",
		"proxy":{"kind":"cloudflared"}}`); err != nil {
		t.Errorf("a cloudflared host was refused: %v", err)
	}
	if _, err := hostFrom(t, `{"alias":"a","hostname":"a.example","user":"u","proxy":{"kind":"socks"}}`); err == nil ||
		!strings.Contains(err.Error(), "cloudflared") {
		t.Errorf("an unknown proxy kind should be refused, naming the known one: %v", err)
	}
	if _, err := hostFrom(t, `{"alias":"a","hostname":"a","user":"u","proxy":{"kind":"cloudflared"},
		"vm":{"hypervisor":"vmpal","name":"x"}}`); err == nil {
		t.Error("a host cannot be both a VM and behind Cloudflare Access: one ProxyCommand")
	}
}

// Hosts without a proxy serialize exactly as before, so existing manifests do
// not change on the next save.
func TestNoProxyKeepsTheHostByteIdentical(t *testing.T) {
	b, err := json.Marshal(Host{Alias: "a", Hostname: "a.example", User: "u", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "proxy") {
		t.Errorf("an unset proxy was written: %s", b)
	}
	b, _ = json.Marshal(Host{Alias: "a", Hostname: "a", User: "u", Port: 22, Proxy: &ProxySpec{Kind: ProxyCloudflared}})
	if !strings.Contains(string(b), `"proxy":{"kind":"cloudflared"}`) {
		t.Errorf("proxy not written: %s", b)
	}
}
