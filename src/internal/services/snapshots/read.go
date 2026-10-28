package snapshots

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrHoldsKeyMaterial refuses to open a snapshot written before private keys
// were excluded. Reading it to show a diff would put a private key on a page.
var ErrHoldsKeyMaterial = errors.New("this snapshot predates key exclusion and holds private keys, so it is not opened; " +
	"remove it once you no longer need it: sshmgr snapshots prune --keep 0")

// maxReadBytes caps what Files reads from one member. Everything a snapshot
// holds is config text; a member larger than this is not something to diff.
const maxReadBytes = 4 << 20

// Files returns the text of every file a snapshot holds, keyed by its path
// below the ssh directory ("config", "profiles/work/config"). It refuses a
// snapshot that holds key material, and reads only the names a snapshot may
// hold, so a member it was never meant to contain is skipped, not shown.
func Files(tarball string) (map[string]string, error) {
	if HoldsKeyMaterial(tarball) {
		return nil, ErrHoldsKeyMaterial
	}
	f, err := os.Open(tarball)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || !archivable(path.Base(hdr.Name)) {
			continue
		}
		// Members are "<base>/<rel>"; the base is the ssh directory's own name.
		_, rel, ok := strings.Cut(hdr.Name, "/")
		if !ok || rel == "" || strings.Contains(rel, "..") {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxReadBytes))
		if err != nil {
			return nil, err
		}
		out[rel] = string(body)
	}
}

// CurrentFiles returns what a snapshot of sshDir would hold now, in the same
// form as Files, so the two can be compared file by file.
func CurrentFiles(sshDir string) (map[string]string, error) {
	root := filepath.Clean(sshDir)
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == root {
				return filepath.SkipDir
			}
			return err
		}
		if fi.IsDir() || !fi.Mode().IsRegular() || !archivable(fi.Name()) || fi.Size() > maxReadBytes {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	return out, err
}
