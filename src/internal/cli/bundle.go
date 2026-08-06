package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/bundler"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/homeperms"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

func newBundleCmd() *cobra.Command {
	var recipient, output string
	var keep int
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Encrypted backup of keys + state",
		Long: "Encrypted backup of keys + state.\n\n" +
			"Old bundles are kept, not pruned: they are encrypted, and silently deleting the\n" +
			"only copy of a key would be worse than letting them accumulate. Pass --keep to\n" +
			"trim the destination once the new bundle is written.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			recip := recipient
			if recip == "" {
				recip = os.Getenv("SSH_MANAGER_AGE_RECIPIENT")
			}
			dest := output
			if dest == "" {
				dest = p.DistDir()
			}
			stamp := time.Now().Format("20060102-150405")
			res, err := bundler.New(p.SSHDir, p.ConfigDir, bundler.AgeCipher{}).Bundle(recip, dest, stamp)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			_, _ = fmt.Fprintln(out, res.Format())
			if keep > 0 {
				for _, pruned := range pruneBundles(dest, keep) {
					_, _ = fmt.Fprintf(out, "pruned %s\n", pruned)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&recipient, "recipient", "r", "", "age recipient (else $SSH_MANAGER_AGE_RECIPIENT)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "destination dir (else config-dir/dist)")
	cmd.Flags().IntVar(&keep, "keep", 0, "after bundling, keep only the newest N bundles (0 keeps all)")
	return cmd
}

// backupKeysBeforeDestroying writes an age-encrypted bundle so an operation that
// destroys key material stays recoverable.
//
// This used to be free: the pre-mutation snapshot tarred every private key, so
// anything destroyed could be dug back out of it. Snapshots no longer carry keys
// - deliberately, they were a rolling plaintext archive - which means the
// destructive paths need a real backup of their own. An encrypted bundle is the
// replacement, and no configured recipient is a hard stop rather than a shrug,
// because the alternative is losing a key with no way back.
func backupKeysBeforeDestroying(p paths.Paths, out io.Writer, skip bool) error {
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
	res, err := bundler.New(p.SSHDir, p.ConfigDir, bundler.AgeCipher{}).
		Bundle(recipient, p.DistDir(), time.Now().Format("20060102-150405"))
	if err != nil {
		return fmt.Errorf("could not back up keys before proceeding: %w", err)
	}
	_, _ = fmt.Fprintf(out, "key backup: %s\n", res.AgePath)
	return nil
}

// pruneBundles removes all but the newest keep bundles in dir, taking their
// sidecars with them so no orphaned .sha256 is left to verify a missing file.
// Returns the base names removed.
func pruneBundles(dir string, keep int) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "ssh-manager-*.age"))
	if len(matches) <= keep {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool {
		fi, errI := os.Stat(matches[i])
		fj, errJ := os.Stat(matches[j])
		if errI != nil || errJ != nil || fi.ModTime().Equal(fj.ModTime()) {
			return matches[i] < matches[j]
		}
		return fi.ModTime().Before(fj.ModTime())
	})
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

func newRestoreCmd() *cobra.Command {
	var identity string
	var yes bool
	cmd := &cobra.Command{
		Use:   "restore <bundle.age>",
		Short: "Decrypt and lay keys back",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := confirmOrAbort(c, "Restore ~/.ssh from this bundle? (current tree is snapshotted first)", yes); err != nil {
				return err
			}
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			ident := identity
			if ident == "" {
				if env := os.Getenv("SSH_MANAGER_AGE_IDENTITY_FILE"); env != "" {
					ident = env
				}
			}
			snapshotBeforeMutation(p)
			ks := keystore.New()
			res, err := bundler.New(p.SSHDir, p.ConfigDir, bundler.AgeCipher{}).Restore(args[0], ident, ks.Fingerprint)
			if err != nil {
				return err
			}
			// Re-assert perms on the restored tree + config-home secrets, then
			// re-render the config so ~/.ssh is usable.
			for _, mp := range perms.IterManagedPaths(p.SSHDir) {
				_ = perms.SetPerms(mp.Path, mp.Mode)
			}
			for _, sp := range homeperms.SecretPerms(p) {
				if _, e := os.Stat(sp.Path); e == nil {
					_ = perms.SetPerms(sp.Path, sp.Mode)
				}
			}
			if m, e := manifest.Load(p.Manifest()); e == nil {
				_, _ = configsvc.New(p.SSHDir, m, platform.EmitUseKeychain()).Write(false)
			}
			_, _ = fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	cmd.Flags().StringVarP(&identity, "identity", "i", "", "age identity file (else $SSH_MANAGER_AGE_IDENTITY_FILE)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}
