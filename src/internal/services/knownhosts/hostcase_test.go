package knownhosts

import (
	"os"
	"path/filepath"
	"testing"
)

// ssh lowercases the host name before it consults known_hosts, so a manifest
// hostname written in mixed case names the same pin as its lowercase form. Every
// shape the store can hold has to agree: plaintext, hashed, and [host]:port.
func TestHostInKnownHostsIgnoresHostnameCase(t *testing.T) {
	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	cases := []struct {
		name, line, token string
	}{
		{"plaintext", "server.example.com ssh-ed25519 AAAA", "Server.Example.com"},
		{"plaintext stored mixed case", "Server.Example.COM ssh-ed25519 AAAA", "server.example.com"},
		{"plaintext list", "other.host,Server.Example.com ssh-ed25519 AAAA", "SERVER.example.com"},
		{"hashed", hashHost("server.example.com", salt) + " ssh-ed25519 AAAA", "Server.Example.com"},
		{"hashed port form", hashHost("[server.example.com]:2222", salt) + " ssh-ed25519 AAAA", "[Server.Example.com]:2222"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kh := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(kh, []byte(tc.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !HostInKnownHosts(kh, tc.token) {
				t.Errorf("%q should be pinned by %q", tc.token, tc.line)
			}
		})
	}
}

// A pin sshmgr writes from a mixed-case name must be found by the lowercase
// name ssh actually looks up; hashing the raw spelling would write a line ssh
// can never match.
func TestAddHashesTheLowercasedHostname(t *testing.T) {
	s := New(t.TempDir())
	if _, err := s.Add([]string{"Server.Example.com ssh-ed25519 AAAA"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := parseKHLine(string(data))
	if !ok {
		t.Fatalf("unparseable store: %q", data)
	}
	// Checked against the raw HMAC rather than through hostFieldMatches, so the
	// assertion holds even if matching itself became case-insensitive.
	if !hashedFieldMatches(parsed.field, "server.example.com") {
		t.Fatal("a pin written for Server.Example.com must hash the name ssh looks up")
	}
}

// The reported incident: the manifest says Server.Example.com, the store holds
// the lowercase pin ssh wrote, and `clean -y` pruned the live pin.
func TestPruneKeepsPinForMixedCaseManifestHost(t *testing.T) {
	s := New(t.TempDir())
	if _, err := s.Add([]string{
		"server.example.com ssh-ed25519 AAAA",
		"[server.example.com]:2222 ssh-ed25519 BBBB",
	}); err != nil {
		t.Fatal(err)
	}
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
  "work":{"key_scope":"per_service","hosts":[
    {"alias":"srv","hostname":"Server.Example.com","user":"u"},
    {"alias":"alt","hostname":"Server.Example.com","port":2222,"user":"u"}]}}}`)
	n, err := s.Prune(m)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("pruned %d live pin(s); a hostname's case must not make it look dead", n)
	}
}

// @revoked says a key must never be trusted, so a host listed only under it is
// not pinned. @cert-authority keeps counting, as it always has.
func TestHostInKnownHostsMarkers(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	body := "@revoked revoked.example.com ssh-ed25519 AAAA\n" +
		"@cert-authority ca.example.com ssh-ed25519 CCCC\n"
	if err := os.WriteFile(kh, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if HostInKnownHosts(kh, "revoked.example.com") {
		t.Error("a @revoked entry must never make a host count as trusted")
	}
	if !HostInKnownHosts(kh, "ca.example.com") {
		t.Error("@cert-authority entry should still count as trusted")
	}
}
