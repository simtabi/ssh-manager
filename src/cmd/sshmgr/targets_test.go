//go:build e2e

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// X3 - packaging. Four things independently reconstruct the release matrix and
// the `sshmgr_{os}_{arch}` artifact names: build/targets.txt,
// scripts/build-all.sh, .goreleaser.yaml, and the two installers. Nothing tied
// them together, so a target could be declared and not compile, or compile and
// never be built.
//
// This closes the first half: every declared target actually builds from this
// tree. Behind the e2e tag because it is one link step per target.
func TestEveryDeclaredReleaseTargetCompiles(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain")
	}
	// Two roots, and they are not the same directory. The module root is src/,
	// which is where `go build` has to run from; the target list is a repo-level
	// input under build/, one level above it. Conflating them silently reads a
	// file that does not exist.
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Dir(moduleRoot)
	body, err := os.ReadFile(filepath.Join(repoRoot, "build", "targets.txt"))
	if err != nil {
		t.Fatalf("the release target list is missing: %v", err)
	}

	var checked int
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Errorf("targets.txt line %q is not GOOS GOARCH [GOARM]", line)
			continue
		}
		goos, goarch := fields[0], fields[1]
		name := goos + "/" + goarch
		if len(fields) > 2 {
			name += "v" + fields[2]
		}
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("go", "build", "-o", os.DevNull, "./cmd/sshmgr")
			cmd.Dir = moduleRoot
			cmd.Env = append(os.Environ(),
				"GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
			if len(fields) > 2 {
				cmd.Env = append(cmd.Env, "GOARM="+fields[2])
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s is a declared release target and does not build:\n%s", name, out)
			}
		})
		checked++
	}
	if checked == 0 {
		t.Fatal("targets.txt declared no targets; the release matrix is empty")
	}
}

// The Makefile's `clean` empties build/ except for a KEEP list, and that list is
// hand-written. If a tracked file is ever added to build/ without being added to
// KEEP, `make clean` deletes it and the next build silently loses an input - so
// the two are pinned to each other here.
func TestBuildDirKeepListMatchesGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Dir(moduleRoot)

	cmd := exec.Command("git", "ls-files", "build/")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	var tracked []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			tracked = append(tracked, filepath.Base(line))
		}
	}

	mk, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	for _, line := range strings.Split(string(mk), "\n") {
		if strings.HasPrefix(line, "KEEP :=") {
			keep = strings.Fields(strings.TrimPrefix(line, "KEEP :="))
		}
	}
	if len(keep) == 0 {
		t.Fatal("the Makefile no longer declares KEEP; `make clean` would empty build/ completely")
	}

	sort.Strings(tracked)
	sort.Strings(keep)
	if strings.Join(tracked, ",") != strings.Join(keep, ",") {
		t.Errorf("git tracks %v in build/, but the Makefile keeps %v.\n"+
			"`make clean` deletes anything not in KEEP, so the difference is a file it silently removes.",
			tracked, keep)
	}
}
