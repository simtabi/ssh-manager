// Package initsvc creates and converges the per-user home, ported from
// facade.init: it (re)creates the directory scaffolding, seeds the starter files
// (manifest, inventory, .env) when missing, and re-asserts secret perms. --force
// overwrites the seed files (optionally backing the old ones up first).
package initsvc

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/homeperms"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// defaultEnv is the starter .env, kept byte-identical to the shipped
// data/.env-example (a test enforces it).
//
//go:embed env_example.txt
var defaultEnv []byte

// Result summarizes an init run.
type Result struct {
	ConfigDir string
	Created   []string
	Existed   []string
	Backup    string
}

// Format renders the human-readable init summary (mirrors InitResult.format).
func (r Result) Format() string {
	lines := []string{"init: home " + r.ConfigDir}
	for _, c := range r.Created {
		lines = append(lines, "  created  "+c)
	}
	for _, e := range r.Existed {
		lines = append(lines, "  exists   "+e+" (left as-is)")
	}
	if r.Backup != "" {
		lines = append(lines, "  backup   previous files saved to "+r.Backup)
	}
	lines = append(lines, "Next: edit "+filepath.Join(r.ConfigDir, "manifest.json")+", then `sshmgr reconcile`.")
	return strings.Join(lines, "\n")
}

// Service scaffolds the home.
type Service struct {
	p               paths.Paths
	emitUseKeychain bool
}

// New builds an init service. emitUseKeychain matches the platform (macOS only).
func New(p paths.Paths, emitUseKeychain bool) *Service {
	return &Service{p: p, emitUseKeychain: emitUseKeychain}
}

// Run creates/converges the home. stamp is the timestamp for a --force --backup
// dir (pass "" when not backing up). force overwrites seed files; backup copies
// the old ones into <home>/.state/init-backup-<stamp>/ first.
func (s *Service) Run(force, backup bool, stamp string) (Result, error) {
	res := Result{ConfigDir: s.p.ConfigDir}
	for _, d := range []string{s.p.ConfigDir, s.p.LogDir(), s.p.SnapshotsDir(), s.p.DistDir(), s.p.StateDir()} {
		if err := fs.EnsureDir(d, homeperms.DirMode); err != nil {
			return Result{}, err
		}
	}
	backupDir := ""
	if force && backup {
		backupDir = filepath.Join(s.p.StateDir(), "init-backup-"+stamp)
	}

	if s.shouldWrite(s.p.Manifest(), &res, force, backupDir) {
		if err := manifest.Starter(s.emitUseKeychain).Save(s.p.Manifest()); err != nil {
			return Result{}, err
		}
	}
	if s.shouldWrite(s.p.Inventory(), &res, force, backupDir) {
		if err := inventory.New().Save(s.p.Inventory()); err != nil {
			return Result{}, err
		}
	}
	// providers.json is NOT seeded - the full catalog ships with the binary; a
	// user file only exists to customize it (see `providers --export`).
	if s.shouldWrite(s.p.EnvFile(), &res, force, backupDir) {
		if err := fs.WriteTextAtomic(s.p.EnvFile(), string(defaultEnv), homeperms.FileMode); err != nil {
			return Result{}, err
		}
	}

	// Re-assert perms on whatever now exists.
	for _, sp := range homeperms.SecretPerms(s.p) {
		if fs.Exists(sp.Path) && !perms.PermsOK(sp.Path, sp.Mode) {
			_ = perms.SetPerms(sp.Path, sp.Mode)
		}
	}
	if backupDir != "" && fs.Exists(backupDir) {
		res.Backup = backupDir
	}
	return res, nil
}

// shouldWrite decides whether to (over)write a seed file; records it and backs up.
// Mirrors facade._should_write.
func (s *Service) shouldWrite(path string, res *Result, force bool, backupDir string) bool {
	name := filepath.Base(path)
	if fs.Exists(path) {
		if !force {
			res.Existed = append(res.Existed, name)
			return false
		}
		s.backupFile(path, backupDir)
		note := "reset (no backup)"
		if backupDir != "" {
			note = "reset; backup saved"
		}
		res.Created = append(res.Created, fmt.Sprintf("%s (%s)", name, note))
		return true
	}
	res.Created = append(res.Created, name)
	return true
}

func (s *Service) backupFile(path, backupDir string) {
	if backupDir == "" || !fs.Exists(path) {
		return
	}
	if err := fs.EnsureDir(backupDir, homeperms.DirMode); err != nil {
		return
	}
	in, err := os.Open(path)
	if err != nil {
		return
	}
	defer in.Close()
	dst := filepath.Join(backupDir, filepath.Base(path))
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, homeperms.FileMode)
	if err != nil {
		return
	}
	_, _ = io.Copy(out, in)
	_ = out.Close()
}
