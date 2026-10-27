package reconciler

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// noSecurityKey puts an ssh-keygen first on PATH that fails every hardware
// (-sk) type, as ssh-keygen does with no FIDO2 device, and runs the real one
// for everything else - so the fallback path runs whether or not a security
// key is plugged in.
func noSecurityKey(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in ssh-keygen is a shell script")
	}
	real, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	dir := t.TempDir()
	// Only the -t value: a key whose file name ends in -sk is still read.
	script := "#!/bin/sh\nprev=\nfor a in \"$@\"; do\n  if [ \"$prev\" = -t ]; then case \"$a\" in *-sk) echo 'no FIDO authenticator' >&2; exit 1;; esac; fi\n  prev=$a\ndone\nexec '" +
		real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh-keygen"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A hardware key type with no device answering is minted as software. The key
// says so in its comment; the inventory has to record the key that exists, and
// the run has to say so, or the user believes they hold a hardware-bound key.
func TestHardwareFallbackIsRecordedAndReported(t *testing.T) {
	noSecurityKey(t)
	const js = `{"version":1,"defaults":{"key_type":"ed25519-sk","rotate_after_days":365},
	  "profiles":{"work":{"key_scope":"per_service","hosts":[
	    {"alias":"yubi","hostname":"h.example","user":"me"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	inv := inventory.New()
	res, err := New(p, &m, inv, false).Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Minted) != 1 || res.Minted[0].Fallback != "ed25519" {
		t.Fatalf("the mint should report the software fallback: %+v", res.Minted)
	}
	if out := res.Format(); !strings.Contains(out, "no security key answered") {
		t.Errorf("the summary should say the key is software:\n%s", out)
	}
	rec, ok := inv.Keys[res.Minted[0].Fingerprint]
	if !ok {
		t.Fatalf("no record for %s", res.Minted[0].Fingerprint)
	}
	if rec.Type != "ed25519" {
		t.Errorf("the record should say ed25519, the key that exists, got %q", rec.Type)
	}
	if rec.Comment == nil || !strings.HasSuffix(*rec.Comment, "(sk-fallback)") {
		t.Errorf("the record's comment should match the key's: %v", rec.Comment)
	}
}
