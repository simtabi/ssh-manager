package renderer

import (
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

// Expected output captured verbatim from the Python render_all() on the shipped
// config/manifest.json (emit_use_keychain=True).
const wantRoot = "# Managed by ssh-manager - do not edit (run: sshmgr config render)\n" +
	"Include profiles/*/config\n\nHost *\n" +
	"    AddKeysToAgent yes\n    IgnoreUnknown UseKeychain\n    UseKeychain yes\n" +
	"    IdentitiesOnly yes\n    ServerAliveInterval 60\n" +
	"# End of ssh-manager-managed block - content outside it is preserved\n"

const wantWork = "# Managed by ssh-manager - do not edit (run: sshmgr config render)\n" +
	"Host unc\n    HostName sc.its.unc.edu\n    User uncgit\n    Port 443\n" +
	"    IdentityFile ~/.ssh/profiles/work/work_unc-ed25519\n" +
	"    UserKnownHostsFile ~/.ssh/profiles/work/known_hosts\n\n"

func TestRenderAllParity(t *testing.T) {
	m, err := manifest.Load("../../../config/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderAll(m, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 5 { // root + 4 non-empty profiles (school excluded)
		t.Fatalf("rendered %d files, want 5: %v", len(out), keys(out))
	}
	if out["config"] != wantRoot {
		t.Errorf("root config mismatch:\n got %q\nwant %q", out["config"], wantRoot)
	}
	if out["profiles/work/config"] != wantWork {
		t.Errorf("work config mismatch:\n got %q\nwant %q", out["profiles/work/config"], wantWork)
	}
	if _, ok := out["profiles/school/config"]; ok {
		t.Error("empty profile should render no file")
	}
}

func TestRenderRootDropsUseKeychainOffMacOS(t *testing.T) {
	m, _ := manifest.Load("../../../config/manifest.json")
	off := RenderRootConfig(m.Defaults.GlobalOptions, false)
	if strings.Contains(off, "UseKeychain yes") {
		t.Error("UseKeychain must be dropped when emitUseKeychain is false")
	}
	if !strings.Contains(off, "IgnoreUnknown UseKeychain") {
		t.Error("IgnoreUnknown line should remain")
	}
}

func TestComposePreservesForeignAndReownsLegacy(t *testing.T) {
	managed := wantRoot

	// foreign preamble preserved; managed block replaced (not duplicated); idempotent
	existing := "# Added by OrbStack\nInclude ~/.orbstack/ssh/config\n\n" + managed
	out := ComposeRootConfig(existing, managed)
	if !strings.Contains(out, "Added by OrbStack") {
		t.Error("OrbStack preamble must be preserved")
	}
	if strings.Count(out, "Managed by ssh-manager") != 1 {
		t.Errorf("managed block must appear once (re-owned), got %d", strings.Count(out, "Managed by ssh-manager"))
	}
	if ComposeRootConfig(out, managed) != out {
		t.Error("compose must be idempotent")
	}
	if ComposeRootConfig("", managed) != managed {
		t.Error("empty existing should return the managed block")
	}

	// legacy markers recognized + replaced, foreign content kept
	legacy := "pre-line\n# Managed by sshmgr - do not edit (run: sshmgr config render)\n" +
		"old body\n# End of sshmgr-managed block - content outside it is preserved\npost-line\n"
	out2 := ComposeRootConfig(legacy, managed)
	if strings.Contains(out2, "sshmgr-managed block") {
		t.Error("legacy block should be replaced, not kept")
	}
	if !strings.Contains(out2, "pre-line") || !strings.Contains(out2, "post-line") {
		t.Error("foreign content around the legacy block must be preserved")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
