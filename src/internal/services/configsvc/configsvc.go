// Package configsvc renders, checks, and shows the SSH config. All three modes
// drive the ONE renderer,
// so the verifier and the writer can never disagree; check changes nothing.
package configsvc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
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

// CheckResult reports config drift. InSync is the gate.
type CheckResult struct {
	FileDiffs map[string]string
	Missing   []string
	Orphan    []string
	// SSHErrors is filled only when Check ran with validateSSH; callers that
	// skip the ssh leg get an empty map and an InSync that ignores it.
	SSHErrors map[string]string
	// Shadowed lists managed aliases that foreign content above the managed
	// block takes over, so ssh does not do what the manifest says for them.
	Shadowed []Shadow
}

// BlockInSync reports whether every managed file on disk matches the manifest
// byte for byte - the part `config render` can fix.
func (r *CheckResult) BlockInSync() bool {
	return len(r.FileDiffs) == 0 && len(r.Missing) == 0 && len(r.Orphan) == 0
}

// InSync reports whether the on-disk config matches the manifest and, when it
// was asked, whether ssh can parse it. A config ssh refuses breaks every host,
// so it is never in sync even when every managed byte matches. Nor is one where
// a foreign block ssh reads first overrides a managed alias: the bytes match,
// but ssh resolves something else.
func (r *CheckResult) InSync() bool {
	return r.BlockInSync() && len(r.SSHErrors) == 0 && len(r.Shadowed) == 0
}

// Format renders a human report.
func (r *CheckResult) Format() string {
	if r.InSync() {
		return "config: in sync with the manifest ✓"
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
	for _, sh := range r.Shadowed {
		fmt.Fprintf(&b, "SHADOWED %s\n", sh)
	}
	if r.BlockInSync() {
		// The managed block already matches, so rendering again would not
		// help - the fault is in content sshmgr does not own.
		if len(r.SSHErrors) > 0 {
			b.WriteString("config: ssh cannot parse the config - fix the lines reported above")
		} else {
			b.WriteString("config: managed block in sync, but ssh reads the blocks above first - " + ShadowFix)
		}
		return b.String()
	}
	if len(r.Shadowed) > 0 {
		b.WriteString("config: shadowed aliases need fixing by hand - " + ShadowFix + "\n")
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
	// Iterate in the manifest's render order (root config, then profiles in file
	// order) - the same order v1 yielded them in - so the Missing
	// list matches v1 byte-for-byte, not a sorted reordering.
	for _, rel := range s.renderedOrder(rendered) {
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
			// Read from what is on disk: foreign content above the block stays
			// above it through a render, so the verdict holds either way.
			res.Shadowed = findShadows(dest, current, rendered)
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

// configFilesOnDisk lists managed config files present under ~/.ssh as
// forward-slash relpaths: the root config, plus each profiles/*/config sshmgr
// owns (see ownsConfigFile). Anything listed here and not rendered is pruned.
func (s *Service) configFilesOnDisk() []string {
	var found []string
	if _, ok := readFile(filepath.Join(s.sshDir, renderer.RootConfig)); ok {
		found = append(found, renderer.RootConfig)
	}
	matches, _ := filepath.Glob(filepath.Join(s.sshDir, "profiles", "*", "config"))
	sort.Strings(matches)
	for _, m := range matches {
		if !ownsConfigFile(m) {
			continue
		}
		rel, err := filepath.Rel(s.sshDir, m)
		if err == nil {
			found = append(found, filepath.ToSlash(rel))
		}
	}
	return found
}

// ownsConfigFile decides whether a profiles/<x>/config is sshmgr's to prune.
// Two shapes are:
//
//   - one carrying the managed header: a category file sshmgr rendered;
//   - one in a flat profile directory - keys, old/ and dot directories only -
//     which is where v1 wrote its per-profile files, without a header.
//
// A headerless file beside profile directories is neither. It is a category
// file someone wrote by hand before sshmgr knew about categories, and it is
// the only thing routing those hosts until the manifest catches up, so
// deleting it would take every host in the category offline.
func ownsConfigFile(path string) bool {
	if content, ok := readFile(path); ok && renderer.IsManagedFile(content) {
		return true
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != "old" && !strings.HasPrefix(e.Name(), ".") {
			return false // a subdirectory that is a profile: this is a category
		}
	}
	return true
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

// renderedOrder returns the rendered relpaths in manifest render order: the root
// config first, then each category's config in first-seen manifest order.
func (s *Service) renderedOrder(rendered map[string]string) []string {
	order := make([]string, 0, len(rendered))
	if _, ok := rendered[renderer.RootConfig]; ok {
		order = append(order, renderer.RootConfig)
	}
	for _, c := range s.manifest.Categories() {
		rel := manifest.CategoryConfigRel(c)
		if _, ok := rendered[rel]; ok {
			order = append(order, rel)
		}
	}
	return order
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
// byte-identical to v1's diff output, but the drift gate is the exact string
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
