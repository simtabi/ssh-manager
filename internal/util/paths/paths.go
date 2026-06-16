// Package paths resolves the per-user home and the on-disk layout, ported from
// src/ssh_manager/util/paths.py + the platform config_dir logic. Resolution:
// $SSH_MANAGER_HOME (alias $SSH_MANAGER_CONFIG_DIR), else the OS-standard config
// dir + the "ssh-manager" folder ($XDG_CONFIG_HOME or ~/.config on Unix/macOS,
// %APPDATA% on Windows).
package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	if runtime.GOOS == "windows" {
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
	if runtime.GOOS == "windows" {
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
