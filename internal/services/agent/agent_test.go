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
