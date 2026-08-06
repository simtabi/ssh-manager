package key

import (
	"strings"
	"testing"
)

func TestNormalizeSegment(t *testing.T) {
	cases := map[string]string{
		"Work":            "work",
		"app-db-psql":     "app-db-psql",
		"hpc.example.edu": "hpc-example-edu",
		"a__b!!c":         "a-b-c",
		"--Hi--":          "hi",
		"UPPER_Snake":     "upper-snake",
		"  spaced  out  ": "spaced-out",
	}
	for in, want := range cases {
		if got := NormalizeSegment(in); got != want {
			t.Errorf("NormalizeSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildKeyName(t *testing.T) {
	cases := []struct {
		profile, service, algo, want string
	}{
		{"work", "hpc", "", "work_hpc-ed25519"},
		{"work", "hpc.example.edu", "", "work_hpc-example-edu-ed25519"},
		{"dev-team", "app web", "", "devteam_app-web-ed25519"},
		{"work", "box", "rsa", "work_box-rsa"},
	}
	for _, c := range cases {
		got, err := BuildKeyName(c.profile, c.service, c.algo)
		if err != nil {
			t.Errorf("BuildKeyName(%q,%q,%q) errored: %v", c.profile, c.service, c.algo, err)
			continue
		}
		if got != c.want {
			t.Errorf("BuildKeyName(%q,%q,%q) = %q, want %q", c.profile, c.service, c.algo, got, c.want)
		}
	}
	if _, err := BuildKeyName("", "x", ""); err == nil {
		t.Error("BuildKeyName with empty profile should error")
	}
	if _, err := BuildKeyName("p", "!!", ""); err == nil {
		t.Error("BuildKeyName with empty-normalized service should error")
	}
}

func TestSplitKeyName(t *testing.T) {
	p, r, err := SplitKeyName("work_hpc-ed25519")
	if err != nil || p != "work" || r != "hpc-ed25519" {
		t.Errorf("SplitKeyName = (%q,%q,%v), want (work, hpc-ed25519, nil)", p, r, err)
	}
	for _, bad := range []string{"nounderscore", "trailing_", ""} {
		if _, _, err := SplitKeyName(bad); err == nil {
			t.Errorf("SplitKeyName(%q) should error", bad)
		}
	}
}

func TestAlgoOf(t *testing.T) {
	cases := map[string]string{
		"work_hpc-ed25519":    "ed25519",
		"work_hpc-ed25519-sk": "ed25519-sk",
		"work_box-rsa":        "rsa",
		"work_foo":            "ed25519", // no recognized suffix -> default
	}
	for name, want := range cases {
		got, err := AlgoOf(name)
		if err != nil {
			t.Errorf("AlgoOf(%q) errored: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("AlgoOf(%q) = %q, want %q", name, got, want)
		}
	}
	if _, err := AlgoOf("nokey"); err == nil {
		t.Error("AlgoOf on a non-key-name should error")
	}
}

// DeriveKeyName is what turns a host alias into a key name, so the alias forms
// that actually appear in a manifest are the ones worth pinning.
// python-final:src/ssh_manager/core/key.py::derive_key_name.
func TestDeriveKeyNameFromRealAliases(t *testing.T) {
	cases := []struct{ profile, alias, want string }{
		{"work", "hpc.example.edu", "work_hpc-example-edu-ed25519"},
		{"development", "app-db-psql", "development_app-db-psql-ed25519"},
		{"personal", "github", "personal_github-ed25519"},
		// A profile reduces to one token: the underscore is the profile
		// separator, so a dash inside it would make the name ambiguous.
		{"ad-elsaiq", "github", "adelsaiq_github-ed25519"},
	}
	for _, c := range cases {
		got, err := DeriveKeyName(c.profile, c.alias, "ed25519")
		if err != nil {
			t.Errorf("DeriveKeyName(%q,%q): %v", c.profile, c.alias, err)
			continue
		}
		if got != c.want {
			t.Errorf("DeriveKeyName(%q,%q) = %q, want %q", c.profile, c.alias, got, c.want)
		}
	}
}

// A derived name round-trips: whatever algo went in comes back out, and the
// profile is recoverable. Rotation and expiry both read the name back.
func TestNameRoundTrips(t *testing.T) {
	for _, algo := range []string{"ed25519", "rsa", "ecdsa", "ed25519-sk", "ecdsa-sk"} {
		name, err := BuildKeyName("work", "some.host", algo)
		if err != nil {
			t.Fatal(err)
		}
		gotAlgo, err := AlgoOf(name)
		if err != nil {
			t.Errorf("AlgoOf(%q): %v", name, err)
			continue
		}
		if gotAlgo != algo {
			t.Errorf("AlgoOf(%q) = %q, want %q", name, gotAlgo, algo)
		}
		profile, _, err := SplitKeyName(name)
		if err != nil || profile != "work" {
			t.Errorf("SplitKeyName(%q) = %q, %v", name, profile, err)
		}
	}
}

// The hardware variants must not be read as their software equivalents: an
// ed25519-sk key reported as ed25519 would have reconcile mint the wrong type.
func TestHardwareKeyTypesAreNotTruncated(t *testing.T) {
	cases := map[string]string{
		"work_yubi-ed25519-sk": "ed25519-sk",
		"work_yubi-ecdsa-sk":   "ecdsa-sk",
		"work_plain-ed25519":   "ed25519",
		"work_plain-ecdsa":     "ecdsa",
	}
	for name, want := range cases {
		got, err := AlgoOf(name)
		if err != nil {
			t.Errorf("AlgoOf(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("AlgoOf(%q) = %q, want %q", name, got, want)
		}
	}
}

// IsKnownAlgo is the allowlist a declared key's `type` is validated against, so
// a typo is refused at load time rather than surfacing as a mid-mint
// ssh-keygen failure after the tree has already been touched.
func TestIsKnownAlgo(t *testing.T) {
	for _, ok := range []string{"ed25519", "ed25519-sk", "ecdsa", "ecdsa-sk", "rsa", "dsa"} {
		if !IsKnownAlgo(ok) {
			t.Errorf("%q should be a known algorithm", ok)
		}
	}
	for _, bad := range []string{"", "ED25519", "quantum", "ssh-ed25519", "ed25519 ", "sk"} {
		if IsKnownAlgo(bad) {
			t.Errorf("%q should not be accepted as an algorithm", bad)
		}
	}
}

// A key name becomes a file name under profiles/, so anything that is not
// [a-z0-9-] has to be collapsed - otherwise a host alias with an accent or a
// slash would produce a path that is awkward at best and an escape at worst.
func TestNormalizeCollapsesAnythingUnsafeForAFilename(t *testing.T) {
	cases := map[string]string{
		"Wörk":          "w-rk",
		"a/b":           "a-b",
		"../escape":     "escape",
		"host:2222":     "host-2222",
		"tabs\tand\nnl": "tabs-and-nl",
		"":              "",
		"!!!":           "",
	}
	for in, want := range cases {
		if got := NormalizeSegment(in); got != want {
			t.Errorf("NormalizeSegment(%q) = %q, want %q", in, got, want)
		}
	}
	// And a name built from one of those is still a single safe segment.
	name, err := BuildKeyName("work", "../escape", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/", "\\", "..", " "} {
		if strings.Contains(name, bad) {
			t.Errorf("derived name %q contains %q", name, bad)
		}
	}
}
