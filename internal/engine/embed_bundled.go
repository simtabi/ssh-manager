//go:build bundled

package engine

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// engineBytes is the frozen Python engine, embedded at build time. The file is
// produced per-OS by .build/freeze-engine.sh (PyInstaller) before a `-tags
// bundled` build; it is not committed.
//
//go:embed embed/engine
var engineBytes []byte

var (
	extractOnce sync.Once
	enginePath  string
)

// bundledEngine extracts the embedded engine to a per-user cache dir once and
// returns its path. The cache file name carries a content hash, so a binary
// built with a newer engine extracts fresh instead of reusing a stale copy.
func bundledEngine() string {
	extractOnce.Do(func() { enginePath = extractEngine() })
	return enginePath
}

func extractEngine() string {
	if len(engineBytes) == 0 {
		return ""
	}
	sum := sha256.Sum256(engineBytes)
	name := "ssh-manager-engine-" + hex.EncodeToString(sum[:8])
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "ssh-manager")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(dir, name)
	if fi, err := os.Stat(path); err == nil && fi.Size() == int64(len(engineBytes)) {
		return path // already extracted by a prior run
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, engineBytes, 0o755); err != nil {
		return ""
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return ""
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return ""
	}
	return path
}
