package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [
      {"alias": "gh", "hostname": "github.com", "user": "git"},
      {"alias": "box", "hostname": "10.0.0.2", "user": "deploy"}
    ]},
    "shared": {"key_scope": "shared", "key_name": "id_shared", "hosts": [
      {"alias": "a", "hostname": "a.com", "user": "u"},
      {"alias": "b", "hostname": "b.com", "user": "u"}
    ]}
  }
}`

func loadManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func keyName(t *testing.T, m *manifest.Manifest, profile, alias string) string {
	t.Helper()
	for _, h := range m.Profiles[profile].Hosts {
		if h.Alias == alias {
			k, err := m.ResolvedKeyName(profile, h)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
	}
	t.Fatalf("no alias %q in %q", alias, profile)
	return ""
}

func touch(t *testing.T, ssh, profile, key string) {
	t.Helper()
	p := filepath.Join(ssh, "profiles", profile, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("PRIV\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSharedDedupAndMissingSkip(t *testing.T) {
	m := loadManifest(t)
	ssh := t.TempDir()

	// Shared profile: one key for two hosts -> attempted once.
	touch(t, ssh, "shared", "id_shared")
	var attempts []string
	added, err := Load(m, ssh, "shared", func(p string) bool {
		attempts = append(attempts, filepath.Base(p))
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0] != "id_shared" {
		t.Errorf("shared key should be attempted once: %v", attempts)
	}
	if len(added) != 1 || added[0] != "id_shared" {
		t.Errorf("added=%v want [id_shared]", added)
	}

	// per_service: gh present, box missing -> only gh added.
	touch(t, ssh, "work", keyName(t, m, "work", "gh"))
	added, _ = Load(m, ssh, "work", func(string) bool { return true })
	if len(added) != 1 || added[0] != keyName(t, m, "work", "gh") {
		t.Errorf("work added=%v want only gh (box missing on disk)", added)
	}

	// A failing agent (add returns false) yields no added entries.
	added, _ = Load(m, ssh, "shared", func(string) bool { return false })
	if len(added) != 0 {
		t.Errorf("failed add should yield no added: %v", added)
	}
}

// --apple-use-keychain exists only on macOS. ssh-add rejects the whole
// invocation on an unknown flag, so passing it elsewhere would not degrade to
// "added without keychain storage" - the key would simply never be added, and
// Add reports that as a plain false.
func TestSSHAddArgsCarryTheKeychainFlagOnlyWhenAsked(t *testing.T) {
	const key = "/home/me/.ssh/profiles/work/work_gh-ed25519"

	plain := sshAddArgs(false, key)
	if len(plain) != 1 || plain[0] != key {
		t.Errorf("args = %v, want the key path alone", plain)
	}

	keychain := sshAddArgs(true, key)
	if len(keychain) != 2 || keychain[0] != "--apple-use-keychain" || keychain[1] != key {
		t.Errorf("args = %v, want the flag before the key path", keychain)
	}

	// A path with spaces stays one argument: it reaches exec as an argv element,
	// so quoting it would produce a path that does not exist.
	const spaced = `/Users/Imani Manyara/.ssh/profiles/work/k`
	if got := sshAddArgs(false, spaced); len(got) != 1 || got[0] != spaced {
		t.Errorf("args = %v, want the path verbatim and unquoted", got)
	}
}

// An agent holds keys for connections. A key a profile declares that no host
// uses serves no connection, so it stays out - otherwise the agent would offer
// an extra identity to every server the user subsequently talks to. This differs
// from reconcile, validate and keyaudit, which all walk KeyRefs precisely so an
// unwired key is not overlooked; the difference is deliberate and pinned here so
// it does not get "fixed" into consistency.
func TestADeclaredButUnwiredKeyIsNotLoadedIntoTheAgent(t *testing.T) {
	const j = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","keys":[{"name":"work_spare-ed25519"}],
	    "hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	dir := filepath.Join(ssh, "profiles", "work")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Both keys exist on disk, so presence is not what decides it.
	for _, name := range []string{"work_gh-ed25519", "work_spare-ed25519"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("PRIVATE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var offered []string
	added, err := Load(&m, ssh, "work", func(path string) bool {
		offered = append(offered, filepath.Base(path))
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "work_gh-ed25519" {
		t.Errorf("added = %v, want only the key a host uses", added)
	}
	for _, name := range offered {
		if name == "work_spare-ed25519" {
			t.Error("an unwired key was offered to the agent")
		}
	}
}
