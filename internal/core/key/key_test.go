package key

import "testing"

func TestNormalizeSegment(t *testing.T) {
	cases := map[string]string{
		"Work":            "work",
		"oribi-db-psql":   "oribi-db-psql",
		"sc.its.unc.edu":  "sc-its-unc-edu",
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
		{"work", "unc", "", "work_unc-ed25519"},
		{"work", "sc.its.unc.edu", "", "work_sc-its-unc-edu-ed25519"},
		{"dev-team", "oribi web", "", "devteam_oribi-web-ed25519"},
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
	p, r, err := SplitKeyName("work_unc-ed25519")
	if err != nil || p != "work" || r != "unc-ed25519" {
		t.Errorf("SplitKeyName = (%q,%q,%v), want (work, unc-ed25519, nil)", p, r, err)
	}
	for _, bad := range []string{"nounderscore", "trailing_", ""} {
		if _, _, err := SplitKeyName(bad); err == nil {
			t.Errorf("SplitKeyName(%q) should error", bad)
		}
	}
}

func TestAlgoOf(t *testing.T) {
	cases := map[string]string{
		"work_unc-ed25519":    "ed25519",
		"work_unc-ed25519-sk": "ed25519-sk",
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
