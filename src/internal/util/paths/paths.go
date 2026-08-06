// Package paths resolves the per-user home and the on-disk layout, ported from
// src/ssh_manager/util/paths.py + the platform config_dir logic. Resolution:
// $SSH_MANAGER_HOME (alias $SSH_MANAGER_CONFIG_DIR), else the OS-standard config
// dir + the "ssh-manager" folder ($XDG_CONFIG_HOME or ~/.config on Unix/macOS,
// %APPDATA% on Windows).
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
)

// Getenv is an env lookup, injectable for tests. nil means os.Getenv.
type Getenv func(string) string

func resolve(get Getenv) Getenv {
	if get == nil {
		return os.Getenv
	}
	return get
}

func home(get Getenv) string {
	if platform.IsWindows() {
		if v := get("USERPROFILE"); v != "" {
			return v
		}
	} else if v := get("HOME"); v != "" {
		return v
	}
	h, _ := os.UserHomeDir()
	return h
}

func expandUser(p string, get Getenv) string {
	if p == "~" {
		return home(get)
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home(get), p[2:])
	}
	return p
}

// ConfigDir resolves the per-user home directory. cwd is used to absolutize a
// relative $SSH_MANAGER_HOME override (pass "" to use the process cwd).
func ConfigDir(get Getenv, cwd string) string {
	get = resolve(get)
	if override := firstNonEmpty(get("SSH_MANAGER_HOME"), get("SSH_MANAGER_CONFIG_DIR")); override != "" {
		p := expandUser(override, get)
		if !filepath.IsAbs(p) {
			if cwd == "" {
				cwd, _ = os.Getwd()
			}
			p = filepath.Join(cwd, p)
		}
		return p
	}
	if platform.IsWindows() {
		base := get("APPDATA")
		if base == "" {
			base = filepath.Join(home(get), "AppData", "Roaming")
		}
		return filepath.Join(base, "ssh-manager")
	}
	base := get("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home(get), ".config")
	}
	return filepath.Join(base, "ssh-manager")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Paths is the resolved on-disk layout for one invocation.
type Paths struct {
	SSHDir    string
	ConfigDir string
	// DevRoot is the sandbox root when this layout came from --dev-root, and
	// empty otherwise. Its presence is what every "am I sandboxed" check reads,
	// so there is one answer rather than a comparison rebuilt per call site.
	DevRoot string
}

// Resolve builds the Paths bundle. sshDir "" defaults to ~/.ssh.
func Resolve(get Getenv, cwd, sshDir string) Paths {
	get = resolve(get)
	if sshDir == "" {
		sshDir = filepath.Join(home(get), ".ssh")
	}
	return Paths{SSHDir: sshDir, ConfigDir: ConfigDir(get, cwd)}
}

func (p Paths) Home() string         { return p.ConfigDir }
func (p Paths) Manifest() string     { return filepath.Join(p.ConfigDir, "manifest.json") }
func (p Paths) Inventory() string    { return filepath.Join(p.ConfigDir, "inventory.json") }
func (p Paths) Providers() string    { return filepath.Join(p.ConfigDir, "providers.json") }
func (p Paths) EnvFile() string      { return filepath.Join(p.ConfigDir, ".env") }
func (p Paths) AgeIdentity() string  { return filepath.Join(p.ConfigDir, "age-identity.txt") }
func (p Paths) LogDir() string       { return filepath.Join(p.ConfigDir, "log") }
func (p Paths) AuditLog() string     { return filepath.Join(p.LogDir(), "audit.log") }
func (p Paths) SnapshotsDir() string { return filepath.Join(p.ConfigDir, "snapshots") }
func (p Paths) DistDir() string      { return filepath.Join(p.ConfigDir, "dist") }
func (p Paths) StateDir() string     { return filepath.Join(p.ConfigDir, ".state") }
func (p Paths) LockFile() string     { return filepath.Join(p.StateDir(), ".lock") }
func (p Paths) ExpiryCache() string  { return filepath.Join(p.StateDir(), "expiry-cache.json") }
func (p Paths) NotifyCache() string  { return filepath.Join(p.StateDir(), "notify-cache.json") }

// LegacyHomes are pre-rename / pre-XDG home locations in priority order: the
// "sshmgr" sibling of the standard home (pre-rename OS-standard dir) and the
// original dot-home ~/.sshmgr. Mirrors facade._legacy_homes.
func (p Paths) LegacyHomes() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(filepath.Dir(p.ConfigDir), "sshmgr"),
		filepath.Join(home, ".sshmgr"),
	}
}

// FirstLegacyHome returns the first real legacy dir worth migrating (a directory,
// not a symlink, not the standard home), or "". Mirrors facade._first_legacy_home.
func (p Paths) FirstLegacyHome() string {
	for _, cand := range p.LegacyHomes() {
		if cand == p.ConfigDir {
			continue
		}
		if fi, err := os.Lstat(cand); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			return cand
		}
	}
	return ""
}

// --- dev mode ---------------------------------------------------------------

// DevRootEnv is the environment variable form of --dev-root.
const DevRootEnv = "SSHMGR_DEV_ROOT"

// DevSSHDir and DevConfigDir are the fixed subdirectories a dev root is split
// into.
const (
	DevSSHDir    = "ssh"
	DevConfigDir = "config"
)

// ResolveDev builds the layout for a sandboxed run: one root, holding both the
// sandbox's ~/.ssh and its config home.
//
// It is deliberately ONE root rather than two independent overrides. The config
// home already had an override ($SSH_MANAGER_HOME) and ~/.ssh had none, so the
// only way to test against a scratch tree was to move $HOME - which also moves
// the ssh-agent socket, the launchd session and everything else that reads it.
// Two knobs would allow the worse failure: a run with its config redirected and
// its keys still going to the real ~/.ssh, which looks sandboxed right up until
// it overwrites a key you use.
//
// The root is created on demand by the caller; this only computes and checks it.
func ResolveDev(get Getenv, cwd, devRoot string) (Paths, error) {
	get = resolve(get)
	root := expandUser(devRoot, get)
	if !filepath.IsAbs(root) {
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		// On Windows `\scratch` is rooted but not absolute - Go wants a volume
		// too - and it means "that location on the current drive". Joining it to
		// the working directory instead silently turns it into a relative path,
		// so someone who typed `\` for the drive root would sandbox their
		// current directory and be told nothing.
		if vol := filepath.VolumeName(cwd); vol != "" && isRooted(root) {
			root = vol + root
		} else {
			root = filepath.Join(cwd, root)
		}
	}
	root = filepath.Clean(root)

	real := Resolve(get, cwd, "")
	if err := checkDevRoot(root, real); err != nil {
		return Paths{}, err
	}
	return Paths{
		SSHDir:    filepath.Join(root, DevSSHDir),
		ConfigDir: filepath.Join(root, DevConfigDir),
		DevRoot:   root,
	}, nil
}

// checkDevRoot refuses a sandbox that is not one.
//
// Both directions matter. A root inside the real ~/.ssh would have the tool
// write keys into the tree it is supposed to be avoiding; a root that CONTAINS
// the real ~/.ssh (the home directory, or /) means a later snapshot, clean or
// restore walks the real tree while believing it is scratch.
func checkDevRoot(root string, real Paths) error {
	// A filesystem root, checked after the path has been absolutized rather than
	// by comparing the input to a separator. On Windows the input never looks
	// like the root it resolves to: `\` has no volume, so the literal
	// comparison matched nothing and the whole guard was dead there.
	// Dir(root) == root is true at "/" and at "C:\" alike.
	if root == "" || filepath.Dir(root) == root {
		return fmt.Errorf("--dev-root %q is not a usable sandbox: it is a filesystem root", root)
	}
	for _, danger := range []struct{ path, what string }{
		{real.SSHDir, "your real ~/.ssh"},
		{real.ConfigDir, "your real config home"},
	} {
		if danger.path == "" {
			continue
		}
		if within(danger.path, root) {
			return fmt.Errorf("--dev-root %s is inside %s (%s); "+
				"a sandbox there would write to the tree it exists to avoid",
				root, danger.what, danger.path)
		}
		if within(root, danger.path) {
			return fmt.Errorf("--dev-root %s contains %s (%s); "+
				"a snapshot or restore under it would walk the real tree",
				root, danger.what, danger.path)
		}
	}
	return nil
}

// within reports whether dest is at or below root. It is the same rule as
// util/fs.Within, repeated here because util/fs imports nothing from paths and
// this package must not start a cycle by importing it.
func within(root, dest string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dest))
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

// isRooted reports whether p begins at a path separator without naming a
// volume - the Windows "\somewhere" form.
func isRooted(p string) bool {
	return p != "" && (p[0] == '\\' || p[0] == '/') && filepath.VolumeName(p) == ""
}

// IsDev reports whether this layout is a sandbox.
func (p Paths) IsDev() bool { return p.DevRoot != "" }
