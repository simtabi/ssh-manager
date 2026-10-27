package bundler

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
)

// writeArchiveWith builds an unencrypted bundle (fakeCipher passes it through)
// with the given member bodies, in the order given.
func writeArchiveWith(t *testing.T, members [][2]string) string {
	t.Helper()
	agePath := filepath.Join(t.TempDir(), "ssh-manager-crafted.age")
	f, err := os.Create(agePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{Name: m[0], Mode: 0o600, Size: int64(len(m[1])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m[1])); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []io.Closer{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return agePath
}

// privKeyBody is a key restore accepts in a rendered slot: looksLikeKey parses
// it, so it has to be well formed.
var privKeyBody = testOpenSSHKey("none")

// A bundle carries keys and the manifest, not files sshmgr renders from the
// manifest: a rendered category config is rebuilt on restore, and carrying it
// let a forged bundle plant a config the root config Includes. A key that
// happens to be named config is still a key, and is still bundled.
func TestBundleLeavesOutRenderedFiles(t *testing.T) {
	ssh, cfg := writeSrc(t)
	put := func(rel, body string) {
		p := filepath.Join(ssh, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("profiles/clients/config", renderer.ManagedHeader+"\nHost a\n")
	put("profiles/legacy/known_hosts", "github.com ssh-ed25519 AAAA\n")
	put("profiles/flat/config", privKeyBody)

	res, err := New(ssh, cfg, fakeCipher{}).Bundle("age1fake", t.TempDir(), "20260101")
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{"ssh/profiles/clients/config", "ssh/profiles/legacy/known_hosts"} {
		if slices.Contains(res.Contents, rendered) {
			t.Errorf("%s is rendered from the manifest and must not be bundled: %v", rendered, res.Contents)
		}
	}
	if !slices.Contains(res.Contents, "ssh/profiles/flat/config") {
		t.Errorf("a key named config must still be bundled: %v", res.Contents)
	}
}

// A bundle made before this change, or a forged one, may still carry those
// members. Restore lays none of them down - the config is re-rendered from the
// restored manifest afterwards - and says which it skipped; a key named config
// is restored as before.
func TestRestoreSkipsRenderedMembersOfAnOlderBundle(t *testing.T) {
	base := t.TempDir()
	ssh, cfg := filepath.Join(base, ".ssh"), filepath.Join(base, "cfg")
	crafted := writeArchiveWith(t, [][2]string{
		{"ssh/profiles/clients/config", "Host *\n    ProxyCommand touch /tmp/owned\n"},
		{"ssh/profiles/legacy/known_hosts", "evil.example ssh-ed25519 AAAA\n"},
		{"ssh/profiles/flat/config", privKeyBody},
		{"ssh/profiles/work/work_a-ed25519", privKeyBody},
	})
	rr, err := New(ssh, cfg, fakeCipher{}).Restore(crafted, "", fakeFP)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"profiles/clients/config", "profiles/legacy/known_hosts"} {
		if _, err := os.Stat(filepath.Join(ssh, filepath.FromSlash(rel))); err == nil {
			t.Errorf("%s was laid down; restore must re-render it, not trust the bundle", rel)
		}
		if !slices.Contains(rr.Skipped, rel) {
			t.Errorf("%s should be reported as skipped: %v", rel, rr.Skipped)
		}
	}
	for _, rel := range []string{"profiles/flat/config", "profiles/work/work_a-ed25519"} {
		if _, err := os.Stat(filepath.Join(ssh, filepath.FromSlash(rel))); err != nil {
			t.Errorf("key %s was not restored: %v", rel, err)
		}
	}
	if !strings.Contains(rr.Format(), "skipped") {
		t.Errorf("the summary should say what was skipped:\n%s", rr.Format())
	}
}
