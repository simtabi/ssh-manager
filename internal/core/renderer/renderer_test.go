package renderer

import (
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

// TestRenderAllInline exercises the shipped config/manifest.json
// (emit_use_keychain=true) end to end: exactly one rendered file, every
// non-empty profile's hosts inline under its own banner in manifest order,
// the single known_hosts store referenced everywhere, and Host * last.
func TestRenderAllInline(t *testing.T) {
	m, err := manifest.Load("../../../config/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderAll(m, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("rendered %d files, want 1 (everything inline now): %v", len(out), keys(out))
	}
	got, ok := out[RootConfig]
	if !ok {
		t.Fatalf("missing %q in rendered output", RootConfig)
	}

	if !strings.HasPrefix(got, ManagedHeader+"\n\n") {
		t.Errorf("expected header first:\n%s", got)
	}
	if !strings.HasSuffix(got, ManagedEnd+"\n") {
		t.Errorf("expected footer last:\n%s", got)
	}

	// school has no hosts and must render no banner at all.
	if strings.Contains(got, "profile: school") {
		t.Error("an empty profile should not get a banner")
	}

	// Every host's UserKnownHostsFile points at the single trust store, never a
	// per-profile one.
	if strings.Contains(got, "profiles/work/known_hosts") || strings.Contains(got, "profiles/personal/known_hosts") {
		t.Errorf("a per-profile known_hosts path leaked into the rendered config:\n%s", got)
	}
	if n := strings.Count(got, "UserKnownHostsFile ~/.ssh/known_hosts\n"); n != 6 {
		t.Errorf("want 6 hosts pointing at the single known_hosts store, got %d:\n%s", n, got)
	}

	// Profile banners appear in manifest (file) order: work, personal, simtabi,
	// development.
	order := []string{"profile: work", "profile: personal", "profile: simtabi", "profile: development"}
	last := -1
	for _, marker := range order {
		idx := strings.Index(got, marker)
		if idx == -1 {
			t.Fatalf("missing banner %q:\n%s", marker, got)
		}
		if idx < last {
			t.Errorf("banner %q is out of manifest order", marker)
		}
		last = idx
	}

	// Host * must be the very last Host block: OpenSSH takes the first value it
	// sees for a keyword, so a global block above the per-host blocks would
	// silently override their more specific directives.
	allHosts := indicesOf(got, "\nHost ")
	if len(allHosts) == 0 {
		t.Fatal("no Host blocks rendered")
	}
	lastHost := allHosts[len(allHosts)-1]
	if !strings.HasPrefix(got[lastHost+1:], "Host *\n") {
		t.Errorf("Host * must be the last Host block:\n%s", got)
	}
	for _, idx := range allHosts[:len(allHosts)-1] {
		if strings.HasPrefix(got[idx+1:], "Host *\n") {
			t.Errorf("Host * appeared before a per-host block:\n%s", got)
		}
	}

	// The global block carries the manifest's global_options plus the pinned
	// HashKnownHosts default, with UseKeychain present since emitUseKeychain=true.
	tail := got[lastHost+1:]
	for _, want := range []string{
		"Host *\n", "    AddKeysToAgent yes\n", "    IgnoreUnknown UseKeychain\n",
		"    UseKeychain yes\n", "    IdentitiesOnly yes\n", "    ServerAliveInterval 60\n",
		"    HashKnownHosts yes\n",
	} {
		if !strings.Contains(tail, want) {
			t.Errorf("global block missing %q:\n%s", want, tail)
		}
	}

	// A representative host block: alias, port only when non-default, identity,
	// IdentitiesOnly bound next to it.
	if !strings.Contains(got, "Host unc\n    HostName sc.its.unc.edu\n    User uncgit\n    Port 443\n"+
		"    IdentityFile ~/.ssh/profiles/work/work_unc-ed25519\n    IdentitiesOnly yes\n"+
		"    UserKnownHostsFile ~/.ssh/known_hosts\n") {
		t.Errorf("work/unc host block did not render as expected:\n%s", got)
	}
	if strings.Contains(got, "Host github-personal\n    HostName github.com\n    User git\n    Port") {
		t.Error("default port 22 should not be rendered")
	}
}

func TestRenderRootDropsUseKeychainOffMacOS(t *testing.T) {
	m, err := manifest.Load("../../../config/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	off, err := RenderRootConfig(m, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "UseKeychain yes") {
		t.Error("UseKeychain must be dropped when emitUseKeychain is false")
	}
	if !strings.Contains(off, "IgnoreUnknown UseKeychain") {
		t.Error("IgnoreUnknown line should remain")
	}
}

func TestComposePreservesForeignAndReownsLegacy(t *testing.T) {
	m, err := manifest.Load("../../../config/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	managed, err := RenderRootConfig(m, true)
	if err != nil {
		t.Fatal(err)
	}

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

func indicesOf(s, substr string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], substr)
		if j == -1 {
			return out
		}
		out = append(out, i+j)
		i += j + 1
	}
}
