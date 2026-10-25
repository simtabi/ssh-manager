package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// `host apply` - the upsert verb for compact host specs.
func TestHostApply(t *testing.T) {
	t.Run("one positional spec adds the host and renders its block", func(t *testing.T) {
		p := editHome(t)
		run(t, "profile", "add", "adelsaiq")
		out := run(t, "host", "apply", "adelsaiq", "dani-prd-web-00", "206.189.185.129", "ploi", "web")
		if !strings.Contains(out, "added     dani-prd-web-00") || !strings.Contains(out, "1 added, 0 updated, 0 unchanged") {
			t.Fatalf("output:\n%s", out)
		}
		if cfg := configText(t, p); !strings.Contains(cfg, "dani-prd-web-00") {
			t.Errorf("block not rendered:\n%s", cfg)
		}
	})

	t.Run("repeated --host upserts, merges tags, then is idempotent", func(t *testing.T) {
		p := editHome(t)
		run(t, "profile", "add", "adelsaiq")
		run(t, "host", "add", "adelsaiq", "dani-prd-web-00", "-H", "1.2.3.4", "-u", "root")
		args := []string{"host", "apply", "adelsaiq",
			"--host", "dani-prd-web-00 206.189.185.129 ploi web",
			"--host", "dani-prd-db-00  137.184.219.1   ploi db", "--tag", "prd"}
		out := run(t, args...)
		for _, want := range []string{"updated   dani-prd-web-00", "hostname 1.2.3.4 -> 206.189.185.129",
			"user root -> ploi", "added     dani-prd-db-00", "1 added, 1 updated, 0 unchanged"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in:\n%s", want, out)
			}
		}
		m, _ := manifest.Load(p.Manifest())
		hs := m.Profiles["adelsaiq"].Hosts
		if strings.Join(hs[0].Tags, ",") != "web,prd" || strings.Join(hs[1].Tags, ",") != "db,prd" {
			t.Errorf("tags: %v %v", hs[0].Tags, hs[1].Tags)
		}
		if out := run(t, args...); !strings.Contains(out, "0 added, 0 updated, 2 unchanged") {
			t.Errorf("second run should change nothing:\n%s", out)
		}
	})

	t.Run("-f reads a file and --dry-run writes nothing", func(t *testing.T) {
		p := editHome(t)
		run(t, "profile", "add", "adelsaiq")
		f := filepath.Join(t.TempDir(), "hosts.txt")
		_ = os.WriteFile(f, []byte("# prod\na 10.0.0.1 ploi web\nb 10.0.0.2:2222 ploi\n"), 0o600)
		out := run(t, "host", "apply", "adelsaiq", "-f", f, "--dry-run")
		if !strings.Contains(out, "(dry-run)") || !strings.Contains(out, "2 added") {
			t.Fatalf("output:\n%s", out)
		}
		m, _ := manifest.Load(p.Manifest())
		if len(m.Profiles["adelsaiq"].Hosts) != 0 {
			t.Fatal("dry run wrote hosts")
		}
		run(t, "host", "apply", "adelsaiq", "-f", f)
		m, _ = manifest.Load(p.Manifest())
		if hs := m.Profiles["adelsaiq"].Hosts; len(hs) != 2 || hs[1].Port != 2222 {
			t.Fatalf("hosts: %+v", hs)
		}
	})

	t.Run("-f - reads JSON from stdin", func(t *testing.T) {
		p := editHome(t)
		run(t, "profile", "add", "adelsaiq")
		js := `[{"alias":"a","host":"10.0.0.1","user":"ploi","role":"web"},"b 10.0.0.2 ploi db"]`
		if out, err := runIn(t, js, "host", "apply", "adelsaiq", "-f", "-"); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		m, _ := manifest.Load(p.Manifest())
		if len(m.Profiles["adelsaiq"].Hosts) != 2 {
			t.Fatal("stdin specs not applied")
		}
	})

	t.Run("a missing profile is refused unless asked to create it", func(t *testing.T) {
		p := editHome(t)
		if _, err := runErr(t, "host", "apply", "newp", "a", "10.0.0.1", "ploi"); err == nil ||
			!strings.Contains(err.Error(), "--create-profile") {
			t.Fatalf("want a refusal naming --create-profile, got %v", err)
		}
		out := run(t, "host", "apply", "newp", "a", "10.0.0.1", "ploi", "--category", "clients", "-y")
		if !strings.Contains(out, "profile: created newp") {
			t.Errorf("output:\n%s", out)
		}
		m, _ := manifest.Load(p.Manifest())
		if pr, ok := m.Profiles["newp"]; !ok || len(pr.Hosts) != 1 {
			t.Fatal("profile/host not created")
		}
	})

	t.Run("bad specs are refused and change nothing", func(t *testing.T) {
		p := editHome(t)
		run(t, "profile", "add", "adelsaiq")
		for _, args := range [][]string{
			{"host", "apply", "adelsaiq"},
			{"host", "apply", "adelsaiq", "a", "h"},
			{"host", "apply", "adelsaiq", "--host", "a h:0 u"},
			{"host", "apply", "adelsaiq", "--host", "a h u", "--host", "a h2 u"},
		} {
			if _, err := runErr(t, args...); err == nil {
				t.Errorf("%v: want an error", args)
			}
		}
		m, _ := manifest.Load(p.Manifest())
		if len(m.Profiles["adelsaiq"].Hosts) != 0 {
			t.Error("a refused batch wrote hosts")
		}
	})

	t.Run("--reconcile mints the new host's key", func(t *testing.T) {
		needBin(t, "ssh-keygen")
		p := editHome(t)
		run(t, "profile", "add", "adelsaiq")
		out := run(t, "host", "apply", "adelsaiq", "web", "127.0.0.1:1", "ploi", "--reconcile", "-y", "--no-pin")
		if !strings.Contains(out, "reconcile (applied)") {
			t.Fatalf("output:\n%s", out)
		}
		found := false
		_ = filepath.WalkDir(p.SSHDir, func(path string, d os.DirEntry, _ error) error {
			if d != nil && d.Name() == "adelsaiq_web-ed25519.pub" {
				found = true
			}
			return nil
		})
		if !found {
			t.Error("--reconcile did not mint adelsaiq_web-ed25519")
		}
	})
}
