package knownhosts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

func addTo(t *testing.T, ssh string, lines ...string) (*Service, string) {
	t.Helper()
	s := New(ssh)
	if _, err := s.Add(lines); err != nil {
		t.Fatal(err)
	}
	return s, s.Path()
}

// A plaintext store is a readable inventory of every host the user reaches, which
// matters more once the per-profile stores collapse into one file.
func TestNamesAreHashedOnWrite(t *testing.T) {
	_, path := addTo(t, t.TempDir(),
		"github.com ssh-ed25519 AAAA",
		"[internal.example.com]:2222 ssh-rsa BBBB",
	)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"github.com", "internal.example.com"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("%q appears in the clear:\n%s", secret, body)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if !strings.HasPrefix(line, hashMagic) {
			t.Errorf("line is not hashed: %q", line)
		}
	}
}

// Hashing is pointless if the tool can no longer tell what it has pinned.
func TestHashedEntriesAreStillFound(t *testing.T) {
	_, path := addTo(t, t.TempDir(),
		"github.com ssh-ed25519 AAAA",
		"[internal.example.com]:2222 ssh-rsa BBBB",
	)
	for _, token := range []string{"github.com", "[internal.example.com]:2222"} {
		if !HostInKnownHosts(path, token) {
			t.Errorf("%q was pinned but is not found", token)
		}
	}
	for _, token := range []string{"gitlab.com", "internal.example.com"} {
		if HostInKnownHosts(path, token) {
			t.Errorf("%q was never pinned but matched", token)
		}
	}
}

// Every hashed line carries a fresh random salt, so the same host hashes to
// different bytes each time. String-equality dedup would append a duplicate on
// every single run.
func TestRepinningDoesNotAccumulate(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	for i := 0; i < 3; i++ {
		n, err := s.Add([]string{"github.com ssh-ed25519 AAAA"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && n != 1 {
			t.Fatalf("first pin should add one line, got %d", n)
		}
		if i > 0 && n != 0 {
			t.Errorf("re-pinning added %d duplicate line(s) on pass %d", n, i)
		}
	}
	body, _ := os.ReadFile(s.Path())
	if n := strings.Count(strings.TrimSpace(string(body)), "\n"); n != 0 {
		t.Errorf("expected exactly one line, got %d:\n%s", n+1, body)
	}
}

// A comma-separated plaintext field cannot be hashed as a unit, since a hash names
// exactly one host. It has to become one line per name or the ip stops matching.
func TestCommaSeparatedNamesBecomeSeparateLines(t *testing.T) {
	_, path := addTo(t, t.TempDir(), "github.com,140.82.121.4 ssh-ed25519 AAAA")

	for _, token := range []string{"github.com", "140.82.121.4"} {
		if !HostInKnownHosts(path, token) {
			t.Errorf("%q should still match after hashing", token)
		}
	}
	body, _ := os.ReadFile(path)
	if n := strings.Count(strings.TrimSpace(string(body)), "\n") + 1; n != 2 {
		t.Errorf("expected two lines, got %d:\n%s", n, body)
	}
}

// Hashing a wildcard would leave it matching nothing, so patterns and marker lines
// stay in the clear.
func TestPatternsAndMarkersAreNotHashed(t *testing.T) {
	_, path := addTo(t, t.TempDir(),
		"*.example.com ssh-ed25519 AAAA",
		"@cert-authority ca.example.com ssh-ed25519 BBBB",
	)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"*.example.com", "@cert-authority ca.example.com"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%q should be preserved verbatim:\n%s", want, body)
		}
	}
	// And they must still dedup, since they bypass the hash-aware path.
	s := New(filepath.Dir(path))
	if n, _ := s.Add([]string{"*.example.com ssh-ed25519 AAAA"}); n != 0 {
		t.Errorf("a verbatim line was duplicated (added %d)", n)
	}
}

// Plaintext entries written by the user or by ssh itself must keep matching.
func TestPlaintextEntriesStillMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte("gitlab.com ssh-ed25519 ZZZZ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !HostInKnownHosts(path, "gitlab.com") {
		t.Error("a pre-existing plaintext entry stopped matching")
	}
	// And a plaintext pin of the same key must not be re-added in hashed form.
	if n, _ := New(dir).Add([]string{"gitlab.com ssh-ed25519 ZZZZ"}); n != 0 {
		t.Errorf("an already-trusted host was pinned again (added %d)", n)
	}
}

func TestTrustStoreIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	_, path := addTo(t, t.TempDir(), "github.com ssh-ed25519 AAAA")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != perms.KnownHostsMode {
		t.Errorf("trust store is %o, want %o", fi.Mode().Perm(), perms.KnownHostsMode)
	}
}

// The hash format is only useful if OpenSSH agrees with it. ssh-keygen -F is the
// authority: it does the lookup ssh itself does.
func TestOpenSSHAcceptsOurHashes(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	_, path := addTo(t, t.TempDir(),
		"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"[internal.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	)
	for _, host := range []string{"github.com", "[internal.example.com]:2222"} {
		out, err := exec.Command("ssh-keygen", "-F", host, "-f", path).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			t.Errorf("ssh-keygen could not find %s in our hashed store: %v: %s", host, err, out)
		}
	}
	out, _ := exec.Command("ssh-keygen", "-F", "never-pinned.example.com", "-f", path).CombinedOutput()
	if strings.Contains(string(out), hashMagic) {
		t.Errorf("ssh-keygen matched a host that was never pinned: %s", out)
	}
}
