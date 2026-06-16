package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func env(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func TestConfigDirDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		want := filepath.Join(`C:\AppData`, "ssh-manager")
		if got := ConfigDir(env(map[string]string{"APPDATA": `C:\AppData`}), ""); got != want {
			t.Fatalf("windows default = %q, want %q", got, want)
		}
		return
	}
	// Unix/macOS: XDG_CONFIG_HOME or ~/.config, + ssh-manager.
	if got := ConfigDir(env(map[string]string{"HOME": "/tmp/h"}), "/cwd"); got != "/tmp/h/.config/ssh-manager" {
		t.Fatalf("default = %q, want /tmp/h/.config/ssh-manager", got)
	}
	if got := ConfigDir(env(map[string]string{"HOME": "/tmp/h", "XDG_CONFIG_HOME": "/tmp/xdg"}), "/cwd"); got != "/tmp/xdg/ssh-manager" {
		t.Fatalf("XDG = %q, want /tmp/xdg/ssh-manager", got)
	}
}

// absPath builds an OS-absolute path (drive-letter rooted on Windows).
func absPath(parts ...string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(append([]string{`C:\`}, parts...)...)
	}
	return filepath.Join(append([]string{"/"}, parts...)...)
}

func TestConfigDirOverride(t *testing.T) {
	abs := absPath("abs", "home")
	cwd := absPath("cwd")
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"SSH_MANAGER_HOME": abs}, abs},
		{map[string]string{"SSH_MANAGER_CONFIG_DIR": abs}, abs}, // alias
		{map[string]string{"SSH_MANAGER_HOME": "rel"}, filepath.Join(cwd, "rel")}, // relative absolutized
	}
	for _, c := range cases {
		if got := ConfigDir(env(c.env), cwd); got != c.want {
			t.Errorf("ConfigDir(%v) = %q, want %q", c.env, got, c.want)
		}
	}
	// An empty override falls through to the OS default (not treated as set).
	got := ConfigDir(env(map[string]string{"SSH_MANAGER_HOME": "", "HOME": "/tmp/h", "APPDATA": `C:\A`}), cwd)
	if filepath.Base(got) != "ssh-manager" {
		t.Errorf("empty override should fall through to default, got %q", got)
	}
}

func TestPathsLayout(t *testing.T) {
	h := absPath("home", "x")
	ssh := absPath("ssh")
	p := Resolve(env(map[string]string{"SSH_MANAGER_HOME": h}), absPath("cwd"), ssh)
	checks := map[string]string{
		"home":        p.Home(),
		"manifest":    p.Manifest(),
		"env":         p.EnvFile(),
		"auditLog":    p.AuditLog(),
		"lockFile":    p.LockFile(),
		"distDir":     p.DistDir(),
		"expiryCache": p.ExpiryCache(),
	}
	want := map[string]string{
		"home":        h,
		"manifest":    filepath.Join(h, "manifest.json"),
		"env":         filepath.Join(h, ".env"),
		"auditLog":    filepath.Join(h, "log", "audit.log"),
		"lockFile":    filepath.Join(h, ".state", ".lock"),
		"distDir":     filepath.Join(h, "dist"),
		"expiryCache": filepath.Join(h, ".state", "expiry-cache.json"),
	}
	for k := range want {
		if checks[k] != want[k] {
			t.Errorf("%s = %q, want %q", k, checks[k], want[k])
		}
	}
	if p.SSHDir != ssh {
		t.Errorf("SSHDir = %q, want %q", p.SSHDir, ssh)
	}
}
