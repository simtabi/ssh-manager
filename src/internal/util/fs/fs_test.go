package fs

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Parity reference: python-final:src/ssh_manager/util/fs.py::write_text_atomic
// and ::ensure_dir. The Python wrote through tempfile.mkstemp in the target's
// own directory, fsynced, chmodded the temp, then os.replace'd it - so a reader
// never saw a half file and a crash never left one. Same contract here.

func TestWriteTextAtomicWritesContentAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	const body = "Host gh\n    HostName github.com\n"
	if err := WriteTextAtomic(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("content = %q, want %q", got, body)
	}
	if runtime.GOOS != "windows" { // chmod only carries the read-only bit there
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o, want 600", fi.Mode().Perm())
		}
	}
}

// Bytes go to disk as given. The Python passed newline="" for exactly this: an
// ssh config and a private key must be LF, and a CRLF translation on Windows
// would corrupt both.
func TestWriteTextAtomicDoesNotTranslateNewlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	const body = "line one\nline two\n"
	if err := WriteTextAtomic(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "\r") {
		t.Errorf("newlines were translated: %q", got)
	}
	if string(got) != body {
		t.Errorf("content = %q, want %q", got, body)
	}
}

// Overwriting replaces the file rather than truncating and rewriting it, and
// leaves no temp file behind either way.
func TestWriteTextAtomicReplacesAndLeavesNoResidue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := WriteTextAtomic(path, "first\n", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextAtomic(path, "second\n", 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second\n" {
		t.Errorf("content = %q, want the second write", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the target file", names)
	}
}

// A mode is re-asserted on every write. A state file that had drifted to
// group-readable must not stay that way just because it already existed.
func TestWriteTextAtomicReassertsModeOnAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := WriteTextAtomic(path, "{}\n", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteTextAtomic(path, "{}\n", 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o after rewrite, want 600", fi.Mode().Perm())
	}
}

// The parent directory is created, matching the Python's
// path.parent.mkdir(parents=True).
func TestWriteTextAtomicCreatesTheParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "config")
	if err := WriteTextAtomic(path, "x\n", 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written into a fresh tree: %v", err)
	}
}

// A cross-package contract, and a silent one if it breaks: the temp file this
// writes has to be recognisable to the crash-residue sweep. snapshots
// (tmpArtifact) matches a leading "." and a trailing ".tmp"; if the naming here
// drifted, a temp file left by an interrupted write would never be swept - and
// under profiles/ it can hold key material.
func TestTempFileNameIsSweepable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config")

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(tmp.Name())
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".tmp") {
		t.Errorf("temp name %q does not match the sweep's pattern (leading dot, trailing .tmp)", name)
	}
	if !strings.Contains(name, "config") {
		t.Errorf("temp name %q does not name its target, making residue hard to attribute", name)
	}
}

// EnsureDir forces the mode rather than trusting mkdir, which the umask masks.
func TestEnsureDirForcesModeOnANewAndAnExistingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	base := t.TempDir()
	nested := filepath.Join(base, "profiles", "work")
	if err := EnsureDir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("new dir mode = %o, want 700", fi.Mode().Perm())
	}

	// Already there, and wrong: the mode is corrected, not left alone.
	if err := os.Chmod(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("existing dir mode = %o, want 700", fi.Mode().Perm())
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if Exists(path) {
		t.Error("a missing file should not exist")
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Exists(path) {
		t.Error("a written file should exist")
	}
	if !Exists(dir) {
		t.Error("a directory should exist")
	}
}

// The traversal guard, with the shapes a crafted archive actually uses. Both
// tar extractors call this, so a hole here is a hole in `snapshots restore` and
// `restore <bundle>` at once.
func TestWithinRefusesEveryShapeThatEscapesTheRoot(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "home", "user", ".ssh")

	inside := []string{
		root, // the archive's own root entry
		filepath.Join(root, "config"),
		filepath.Join(root, "profiles", "work", "k"),
		filepath.Join(root, "a", "..", "b"), // resolves back inside
	}
	for _, p := range inside {
		if !Within(root, p) {
			t.Errorf("Within(%q, %q) = false, want true", root, p)
		}
	}

	outside := []string{
		filepath.Join(root, ".."),                        // the parent itself
		filepath.Join(root, "..", ".bashrc"),             // straight out
		filepath.Join(root, "..", "..", "etc", "passwd"), // further out
		filepath.Join(root, "x", "..", "..", "escaped"),  // out via a plausible prefix
		// The sibling case a naive string-prefix check gets wrong: "/home/user/.ssh"
		// is a prefix of "/home/user/.ssh-evil" as a string, but not as a path.
		filepath.Join(string(filepath.Separator), "home", "user", ".ssh-evil", "k"),
		filepath.Join(string(filepath.Separator), "tmp", "elsewhere"),
	}
	for _, p := range outside {
		if Within(root, p) {
			t.Errorf("Within(%q, %q) = true; that path is outside the root", root, p)
		}
	}
}
