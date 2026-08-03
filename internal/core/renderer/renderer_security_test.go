package renderer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

func opts(t *testing.T, raw string) manifest.OrderedOptions {
	t.Helper()
	var o manifest.OrderedOptions
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func host(t *testing.T, raw string) RenderHost {
	t.Helper()
	return RenderHost{
		Alias:        "example",
		Hostname:     "example.com",
		User:         "git",
		IdentityFile: "~/.ssh/profiles/p/k-ed25519",
		KnownHosts:   "~/.ssh/known_hosts",
		RawOptions:   opts(t, raw),
	}
}

// Without IdentitiesOnly, ssh offers every identity held by the agent to each
// server it reaches, disclosing the whole key inventory. It used to be supplied
// only by defaults.global_options, so emptying that map switched the protection
// off silently; it now belongs to the host block itself.
func TestHostBlockAlwaysBindsIdentitiesOnly(t *testing.T) {
	out := RenderProfileConfig([]RenderHost{host(t, "{}")})
	if !strings.Contains(out, "    IdentitiesOnly yes\n") {
		t.Errorf("host block is missing IdentitiesOnly:\n%s", out)
	}
}

// An explicit per-host value is a deliberate choice and is preserved, but it must
// not produce two IdentitiesOnly lines: ssh takes the first and the file would
// misrepresent what is in force.
func TestExplicitIdentitiesOnlyIsNotDuplicated(t *testing.T) {
	out := RenderProfileConfig([]RenderHost{host(t, `{"IdentitiesOnly":"no"}`)})
	if n := strings.Count(out, "IdentitiesOnly"); n != 1 {
		t.Errorf("want exactly one IdentitiesOnly line, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "    IdentitiesOnly no\n") {
		t.Errorf("explicit value not honoured:\n%s", out)
	}
}

// The directive is bound to the key it constrains, so a reader can see the pair
// together.
func TestIdentitiesOnlyFollowsIdentityFile(t *testing.T) {
	out := RenderProfileConfig([]RenderHost{host(t, "{}")})
	identity := strings.Index(out, "IdentityFile ")
	only := strings.Index(out, "IdentitiesOnly ")
	if identity == -1 || only == -1 || only < identity {
		t.Errorf("IdentitiesOnly should follow IdentityFile:\n%s", out)
	}
}
