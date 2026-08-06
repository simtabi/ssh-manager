//go:build e2e

package main

import (
	"os"
	"os/exec"
	"path/filepath"
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
