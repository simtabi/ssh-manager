package doctor

import (
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/preflight"
)

// With an empty PATH, a VM host's hypervisor CLI and git (when defaults.git is
// set) are missing, and doctor must say so and fail; a missing clipboard tool is
// reported but never fails the verdict, since `termius keys --print` works without one.
func TestManifestToolsAreReportedWhenMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	m := manifest.Starter(false)
	m.SetProfile("lab", manifest.Profile{KeyScope: "per_service", Hosts: []manifest.Host{
		{Alias: "devbox", User: "dev", Port: 22, VM: &manifest.VMSpec{Hypervisor: manifest.HypervisorParallels, Name: "devbox"}},
		{Alias: "web", Hostname: "1.2.3.4", User: "ploi", Port: 22},
	}})
	got := neededTools(m)
	if len(got) != 0 && strings.Contains(strings.Join(got, "\n"), "git") {
		t.Fatalf("git reported without defaults.git: %v", got)
	}
	if len(got) != 1 || !strings.Contains(got[0], "parallels") || !strings.Contains(got[0], "lab/devbox") {
		t.Fatalf("needed = %v, want the parallels CLI for lab/devbox", got)
	}

	m.Defaults.Git = &manifest.GitDefaults{Mode: manifest.GitModeSSH}
	got = neededTools(m)
	if len(got) != 2 || !strings.Contains(strings.Join(got, "\n"), "git (") {
		t.Fatalf("needed = %v, want git too once defaults.git is set", got)
	}

	base := Report{ConfigInSync: true, Preflight: preflight.Report{RuntimeOK: true}}
	if !base.OK() {
		t.Fatal("the baseline report must pass, or the next checks prove nothing")
	}
	adv := base
	adv.Clipboard = "none found"
	if !adv.OK() {
		t.Error("a missing clipboard tool must not fail the verdict")
	}
	if !strings.Contains(adv.Format(), "clipboard: none found") {
		t.Errorf("clipboard advice missing:\n%s", adv.Format())
	}
	base.NeededTools = got
	if base.OK() {
		t.Error("a missing tool the manifest needs must fail the verdict")
	}
	if f := base.Format(); !strings.Contains(f, "parallels") || !strings.Contains(f, "git (") {
		t.Errorf("format:\n%s", f)
	}
	if b, _ := base.JSON(); !strings.Contains(string(b), `"needed_tools"`) || !strings.Contains(string(b), `"clipboard"`) {
		t.Errorf("json:\n%s", b)
	}
}
