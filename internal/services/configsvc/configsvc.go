// Package configsvc renders, checks, and shows the SSH config, ported from
// src/ssh_manager/services/configsvc.py. All three modes drive the ONE renderer,
// so the verifier and the writer can never disagree; check changes nothing.
package configsvc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/core/renderer"
	"github.com/simtabi/ssh-manager/internal/util/fs"
)

const (
	dirMode    = 0o700
	configMode = 0o600
)

// Service renders/checks/writes the managed config under an ~/.ssh dir.
type Service struct {
	sshDir          string
	manifest        *manifest.Manifest
	emitUseKeychain bool
}

// New builds a Service. emitUseKeychain is true only on macOS.
func New(sshDir string, m *manifest.Manifest, emitUseKeychain bool) *Service {
	return &Service{sshDir: sshDir, manifest: m, emitUseKeychain: emitUseKeychain}
}

// Rendered returns {relpath -> content} for every managed file.
func (s *Service) Rendered() (map[string]string, error) {
	return renderer.RenderAll(s.manifest, s.emitUseKeychain)
}

// CheckResult reports config drift. InSync is the gate (ssh_errors don't count).
type CheckResult struct {
	FileDiffs map[string]string
	Missing   []string
	Orphan    []string
	SSHErrors map[string]string
}

// InSync reports whether the on-disk config matches the manifest.
func (r *CheckResult) InSync() bool {
	return len(r.FileDiffs) == 0 && len(r.Missing) == 0 && len(r.Orphan) == 0
}

// Format renders a human report.
func (r *CheckResult) Format() string {
	if r.InSync() && len(r.SSHErrors) == 0 {
		return "config: in sync with the manifest"
	}
	var b strings.Builder
	for _, rel := range r.Missing {
		fmt.Fprintf(&b, "MISSING  %s (manifest renders it; not on disk)\n", rel)
	}
	for _, rel := range r.Orphan {
		fmt.Fprintf(&b, "ORPHAN   %s (managed file on disk; manifest renders none)\n", rel)
	}
	for _, rel := range sortedKeys(r.FileDiffs) {
		fmt.Fprintf(&b, "DRIFT    %s\n%s", rel, r.FileDiffs[rel])
	}
	for _, a := range sortedKeys(r.SSHErrors) {
		fmt.Fprintf(&b, "SSH -G   %s: %s\n", a, r.SSHErrors[a])
	}
	b.WriteString("config: DRIFT detected - run: sshmgr config render")
	return b.String()
}

// WriteResult reports what render wrote.
type WriteResult struct {
	Written   []string
	Pruned    []string
	Unchanged []string
	DryRun    bool
}

// Write renders the config to disk (or previews with dryRun), preserving foreign
// content in the root config and pruning managed files the manifest no longer
// renders.
func (s *Service) Write(dryRun bool) (*WriteResult, error) {
	rendered, err := s.Rendered()
	if err != nil {
		return nil, err
	}
	res := &WriteResult{DryRun: dryRun}
	for _, rel := range sortedKeys(rendered) {
		content := rendered[rel]
		dest := filepath.Join(s.sshDir, filepath.FromSlash(rel))
		current, exists := readFile(dest)
		target := content
		if rel == renderer.RootConfig {
			if exists {
				target = renderer.ComposeRootConfig(current, content)
			} else {
				target = renderer.ComposeRootConfig("", content)
			}
		}
		if exists && current == target {
			res.Unchanged = append(res.Unchanged, rel)
			continue
		}
		res.Written = append(res.Written, rel)
		if !dryRun {
			if rel != renderer.RootConfig {
				if err := fs.EnsureDir(filepath.Dir(dest), dirMode); err != nil {
					return nil, err
				}
			}
			if err := fs.WriteTextAtomic(dest, target, configMode); err != nil {
				return nil, err
			}
		}
	}
	for _, rel := range s.configFilesOnDisk() {
		if _, ok := rendered[rel]; !ok {
			res.Pruned = append(res.Pruned, rel)
			if !dryRun {
				_ = os.Remove(filepath.Join(s.sshDir, filepath.FromSlash(rel)))
			}
		}
	}
	return res, nil
}

// Check verifies the on-disk config against the manifest (read-only).
func (s *Service) Check(validateSSH bool) (*CheckResult, error) {
	rendered, err := s.Rendered()
	if err != nil {
		return nil, err
	}
	res := &CheckResult{FileDiffs: map[string]string{}, SSHErrors: map[string]string{}}
	for _, rel := range sortedKeys(rendered) {
		content := rendered[rel]
		dest := filepath.Join(s.sshDir, filepath.FromSlash(rel))
		current, exists := readFile(dest)
		if !exists {
			res.Missing = append(res.Missing, rel)
			continue
		}
		target := content
		if rel == renderer.RootConfig {
			target = renderer.ComposeRootConfig(current, content)
		}
		if current != target {
			res.FileDiffs[rel] = unifiedDiff(current, target, rel)
		}
	}
	for _, rel := range s.configFilesOnDisk() {
		if _, ok := rendered[rel]; !ok {
			res.Orphan = append(res.Orphan, rel)
		}
	}
	if validateSSH {
		if _, err := exec.LookPath("ssh"); err == nil {
			res.SSHErrors = s.validateAliases()
		}
	}
	return res, nil
}

// Show returns the rendered config (no alias) or `ssh -G` for one alias.
func (s *Service) Show(alias string) (string, error) {
	if alias == "" {
		rendered, err := s.Rendered()
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, rel := range sortedKeys(rendered) {
			fmt.Fprintf(&b, "# === %s ===\n%s", rel, rendered[rel])
		}
		return b.String(), nil
	}
	cfg := filepath.Join(s.sshDir, renderer.RootConfig)
	out, err := exec.Command("ssh", "-G", "-F", cfg, alias).CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

// configFilesOnDisk lists managed config files present under ~/.ssh, by location
// (root config + profiles/*/config), as forward-slash relpaths.
func (s *Service) configFilesOnDisk() []string {
	var found []string
	if _, ok := readFile(filepath.Join(s.sshDir, renderer.RootConfig)); ok {
		found = append(found, renderer.RootConfig)
	}
	matches, _ := filepath.Glob(filepath.Join(s.sshDir, "profiles", "*", "config"))
	sort.Strings(matches)
	for _, m := range matches {
		rel, err := filepath.Rel(s.sshDir, m)
		if err == nil {
			found = append(found, filepath.ToSlash(rel))
		}
	}
	return found
}

func (s *Service) validateAliases() map[string]string {
	cfg := filepath.Join(s.sshDir, renderer.RootConfig)
	if _, ok := readFile(cfg); !ok {
		return map[string]string{}
	}
	errs := map[string]string{}
	resolved, err := s.manifest.IterResolved()
	if err != nil {
		return errs
	}
	for _, rk := range resolved {
		out, err := exec.Command("ssh", "-G", "-F", cfg, rk.Host.Alias).CombinedOutput()
		if err != nil {
			errs[rk.Host.Alias] = strings.TrimSpace(string(out))
		}
	}
	return errs
}

func readFile(path string) (content string, exists bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unifiedDiff is a compact line diff (an LCS, so insertions/deletions align). Not
// byte-identical to Python's difflib, but the drift gate is the exact string
// compare above; this is the human-readable report.
func unifiedDiff(current, expected, rel string) string {
	a := strings.SplitAfter(current, "\n")
	b := strings.SplitAfter(expected, "\n")
	// LCS table
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s (on disk)\n+++ %s (manifest)\n", rel, rel)
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out.WriteString(" " + a[i])
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out.WriteString("-" + a[i])
			i++
		default:
			out.WriteString("+" + b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		out.WriteString("-" + a[i])
	}
	for ; j < len(b); j++ {
		out.WriteString("+" + b[j])
	}
	if !strings.HasSuffix(out.String(), "\n") {
		out.WriteString("\n")
	}
	return out.String()
}
