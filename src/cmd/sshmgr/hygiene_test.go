package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// File hygiene, in the language the repository is written in.
//
// These checks used to come from pre-commit, which is a Python program - the
// last thing in the repo that needed a Python runtime, and a second CI job with
// its own toolchain setup to run four rules about whitespace. The rules are
// worth keeping; the runtime was not.
//
// Two of pre-commit's hooks are not reimplemented here because they were already
// covered twice over: gitleaks runs as its own CI job against the full history
// (which the hook could not do), and gofmt/go vet are in `make ci`. What is left
// is what this file does, and it now runs in `make check` as well as in CI,
// where before it only ran for people who had installed pre-commit.
//
// Not covered: YAML and TOML parse checks. There is no TOML left in the tree,
// and validating YAML would mean adding a dependency to a binary whose single
// direct dependency is asserted by TestTheBinaryHasExactlyOneDirectDependency.
// The YAML that matters is checked anyway - GitHub rejects a malformed workflow,
// and `goreleaser check` parses the release config.

// maxTrackedFileSize matches pre-commit's check-added-large-files default. The
// repository ships no binaries, so anything approaching this is a mistake.
const maxTrackedFileSize = 500 * 1024

// trackedFiles lists what git tracks, so generated and ignored files are out of
// scope by construction rather than by an exclusion list that drifts.
func trackedFiles(t *testing.T) (root string, files []string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Dir(moduleRoot)

	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		t.Fatal("git tracks no files; this test would pass vacuously")
	}
	return root, files
}

// isBinary follows .gitattributes: those extensions are the only ones exempt
// from the text rules below.
func isBinary(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".age", ".gz", ".zip", ".ico":
		return true
	}
	return false
}

func TestTrackedFilesAreHygienic(t *testing.T) {
	root, files := trackedFiles(t)
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(body) > maxTrackedFileSize {
			t.Errorf("%s is %d bytes, over the %d-byte limit for a tracked file",
				name, len(body), maxTrackedFileSize)
		}
		if isBinary(name) || len(body) == 0 {
			continue
		}
		text := string(body)

		// .gitattributes says `* text=auto eol=lf`, so a CR in the working tree
		// is a file that escaped normalization.
		if strings.Contains(text, "\r") {
			t.Errorf("%s contains a carriage return; .gitattributes normalizes to LF", name)
		}
		// Exactly one trailing newline: none makes a diff noisy the next time the
		// last line changes, several are accidental.
		if !strings.HasSuffix(text, "\n") {
			t.Errorf("%s does not end with a newline", name)
		} else if strings.HasSuffix(text, "\n\n") {
			t.Errorf("%s ends with a blank line", name)
		}
		for i, line := range strings.Split(text, "\n") {
			if line != strings.TrimRight(line, " \t") {
				t.Errorf("%s:%d ends in whitespace", name, i+1)
			}
		}
	}
}

// A merge marker committed to a tracked file is a broken file that still parses
// often enough to be missed.
func TestNoTrackedFileHasMergeMarkers(t *testing.T) {
	root, files := trackedFiles(t)
	// Split so this file does not match its own check.
	markers := []string{"<<<<<<" + "<", "=======" + "\n>>>>>>" + ">", ">>>>>>" + ">"}
	for _, name := range files {
		if isBinary(name) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		for _, m := range markers {
			if strings.Contains(string(body), m) {
				t.Errorf("%s contains a merge conflict marker", name)
				break
			}
		}
	}
}

// Every tracked JSON file parses. Several are shipped as data - the example
// manifest, the provider catalog, the schemas - and a malformed one is a runtime
// failure for a user rather than a build failure for us.
func TestEveryTrackedJSONFileParses(t *testing.T) {
	root, files := trackedFiles(t)
	var checked int
	for _, name := range files {
		if filepath.Ext(name) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var any interface{}
		if err := json.Unmarshal(body, &any); err != nil {
			t.Errorf("%s is not valid JSON: %v", name, err)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no JSON files were checked; this test has stopped measuring anything")
	}
}
