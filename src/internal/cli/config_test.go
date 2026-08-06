package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
)

func cmdWithOutput(out *bytes.Buffer) *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(out)
	return c
}

// Migrating off per-profile known_hosts has to be a no-op on a tree that
// already only has the single store, since config render calls it on every
// invocation rather than gating it behind a one-time flag.
func TestMigrateLegacyKnownHostsIsANoOpWithoutLegacyStores(t *testing.T) {
	p := fixture(t)
	var out bytes.Buffer
	if err := migrateLegacyKnownHosts(cmdWithOutput(&out), p, false); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output for a tree with nothing to migrate, got %q", out.String())
	}
}

// The actual migration: profiles/*/known_hosts merges into the single store
// and the legacy files are removed, reported to the user.
func TestMigrateLegacyKnownHostsMergesAndReports(t *testing.T) {
	p := fixture(t)
	legacy := filepath.Join(p.SSHDir, "profiles", "work", "known_hosts")
	if err := os.WriteFile(legacy, []byte("github.com ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrateLegacyKnownHosts(cmdWithOutput(&out), p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Error("the legacy per-profile file should have been removed")
	}
	if !knownhosts.HostInKnownHosts(filepath.Join(p.SSHDir, "known_hosts"), "github.com") {
		t.Error("github.com should have been merged into the single store")
	}
	if out.Len() == 0 {
		t.Error("the migration should report what it did")
	}
}

// --dry-run must not touch the filesystem, only report what would happen.
func TestMigrateLegacyKnownHostsDryRunTouchesNothing(t *testing.T) {
	p := fixture(t)
	legacy := filepath.Join(p.SSHDir, "profiles", "work", "known_hosts")
	if err := os.WriteFile(legacy, []byte("github.com ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrateLegacyKnownHosts(cmdWithOutput(&out), p, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Error("dry-run must not remove the legacy file")
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "known_hosts")); err == nil {
		t.Error("dry-run must not write the single store")
	}
	if out.Len() == 0 {
		t.Error("dry-run should still report what it would do")
	}
}
