package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/preflight"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// After `sshmgr import ~/.ssh/config` and a render, the user's original Host
// blocks sit above the managed block and win for every keyword they set. doctor
// used to call that clean; it now names the alias and the line, and fails.
func TestDoctorReportsAShadowedManagedAlias(t *testing.T) {
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"srv","hostname":"new.example","user":"deploy"}]}}}`)
	ssh := t.TempDir()
	cfg := filepath.Join(ssh, "config")
	if err := os.WriteFile(cfg, []byte("Host srv\n    HostName old.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configsvc.New(ssh, m, false).Write(false); err != nil {
		t.Fatal(err)
	}
	rep := New(paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}, m, false).Run(false)
	if len(rep.ShadowedHosts) != 1 {
		t.Fatalf("shadowed = %v, want srv", rep.ShadowedHosts)
	}
	if s := rep.ShadowedHosts[0]; !strings.Contains(s, "srv") || !strings.Contains(s, cfg+":1") {
		t.Errorf("shadow line %q should name the alias and the file:line", s)
	}
	if !rep.ConfigInSync {
		t.Error("the managed block matches the manifest; drift is a separate finding")
	}

	base := Report{ConfigInSync: true, Preflight: preflight.Report{RuntimeOK: true}}
	if !base.OK() {
		t.Fatal("the baseline report must pass, or the next check proves nothing")
	}
	base.ShadowedHosts = rep.ShadowedHosts
	if base.OK() {
		t.Error("a shadowed managed alias must fail the verdict")
	}
	f := base.Format()
	if !strings.Contains(f, "srv") || !strings.Contains(f, "sshmgr does not edit") {
		t.Errorf("the report must name the alias and say who has to fix it:\n%s", f)
	}
}

// A raw option that duplicates a managed line is reported (it is a warning: the
// rendered config already resolves the managed value).
func TestDoctorReportsRawOptionsThatDuplicateManagedLines(t *testing.T) {
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"srv","hostname":"h","user":"u",
	    "raw_options":{"UserKnownHostsFile":"~/.ssh/known_hosts_work"}}]}}}`)
	rep := New(paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}, m, false).Run(false)
	if len(rep.RawOptionOverlaps) != 1 || !strings.Contains(rep.RawOptionOverlaps[0], "UserKnownHostsFile") {
		t.Fatalf("overlaps = %v", rep.RawOptionOverlaps)
	}
	if !strings.Contains(rep.Format(), "UserKnownHostsFile") {
		t.Errorf("format omits the overlap:\n%s", rep.Format())
	}
}
