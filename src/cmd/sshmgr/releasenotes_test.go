package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every release carries its CHANGELOG section as the body. release.yml hands
// GoReleaser that section with --release-notes, but GoReleaser reads the flag
// inside its changelog pipe, and `changelog: disable: true` skips the pipe
// whole: v3.2.0 and v3.4.0 were published with empty bodies that way, and the
// run reported success. So the config must not disable the changelog, and the
// workflow also sets the body itself after GoReleaser, so a future GoReleaser
// change cannot silently drop it again.
func TestReleasesCarryTheirChangelogSection(t *testing.T) {
	cfg, err := os.ReadFile(filepath.Join(filepath.Dir(repoRoot(t)), "src", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^changelog:\s*\n(?:[ \t]+#.*\n)*[ \t]+disable:\s*(true|"true")`).Match(cfg) {
		t.Error("src/.goreleaser.yaml sets changelog.disable: true, which makes GoReleaser ignore --release-notes")
	}
	wf, err := os.ReadFile(filepath.Join(filepath.Dir(repoRoot(t)), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--release-notes=", "gh release edit", "--notes-file"} {
		if !strings.Contains(string(wf), want) {
			t.Errorf("release.yml lacks %q: the release body must be set from the CHANGELOG section", want)
		}
	}
}
