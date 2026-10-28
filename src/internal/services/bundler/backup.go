package bundler

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// BackupBeforeDestroying writes an age-encrypted bundle so an operation that
// destroys key material stays recoverable.
//
// This used to be free: the pre-mutation snapshot tarred every private key, so
// anything destroyed could be dug back out of it. Snapshots no longer carry keys
// - deliberately, they were a rolling plaintext archive - which means the
// destructive paths need a real backup of their own. An encrypted bundle is the
// replacement, and no configured recipient is a hard stop rather than a shrug,
// because the alternative is losing a key with no way back.
func BackupBeforeDestroying(p paths.Paths, out io.Writer, skip bool) error {
	recipient := os.Getenv("SSH_MANAGER_AGE_RECIPIENT")
	if skip {
		if recipient == "" {
			_, _ = fmt.Fprintln(out, "WARNING: proceeding without a key backup - anything this "+
				"destroys is unrecoverable.")
		}
		return nil
	}
	if recipient == "" {
		return errors.New("this destroys key material and there is no encrypted backup to fall " +
			"back on; set SSH_MANAGER_AGE_RECIPIENT to an age recipient (age-keygen -o " +
			"<identity>) so a bundle can be written first, or pass --no-key-backup to accept " +
			"that the replaced key is gone for good")
	}
	res, err := New(p.SSHDir, p.ConfigDir, AgeCipher{}).
		Bundle(recipient, p.DistDir(), time.Now().Format("20060102-150405"))
	if err != nil {
		return fmt.Errorf("could not back up keys before proceeding: %w", err)
	}
	_, _ = fmt.Fprintf(out, "key backup: %s\n", res.AgePath)
	return nil
}

// Prune removes all but the newest keep bundles in dir, taking their
// sidecars with them so no orphaned .sha256 is left to verify a missing file.
// Returns the base names removed.
func Prune(dir string, keep int) []string {
	matches := Sorted(dir)
	if len(matches) <= keep {
		return nil
	}
	var removed []string
	for _, m := range matches[:len(matches)-keep] {
		if os.Remove(m) != nil {
			continue
		}
		_ = os.Remove(m + ".sha256")
		_ = os.Remove(m + ".contents")
		removed = append(removed, filepath.Base(m))
	}
	return removed
}

// Sorted lists the bundles in dir, oldest first: the order Prune removes them in.
func Sorted(dir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "ssh-manager-*.age"))
	sort.Slice(matches, func(i, j int) bool {
		fi, errI := os.Stat(matches[i])
		fj, errJ := os.Stat(matches[j])
		if errI != nil || errJ != nil || fi.ModTime().Equal(fj.ModTime()) {
			return matches[i] < matches[j]
		}
		return fi.ModTime().Before(fj.ModTime())
	})
	return matches
}
