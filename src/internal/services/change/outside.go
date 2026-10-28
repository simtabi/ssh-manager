package change

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/bundler"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/cleaner"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/dockerctx"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/lifecycle"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/notifier"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// The changes below reach past the files a preview copies. Some touch files
// the copy holds only as placeholders - private keys a purge deletes or a
// category move carries along - and the preview names those in Plan.Hidden.
// The rest act outside the home altogether, in OnApply, and say what they will
// do in Effects, which the confirmation is bound to.

// HostApply is `sshmgr host apply <profile> --host <spec>... --yes`, with
// --create-profile or --category for a profile that does not exist yet.
// Each spec is `<alias> <host>[:port] <user> [role]`.
func HostApply(profile string, specs []editor.HostSpec, create bool, category string) Change {
	args := []string{profile}
	for _, s := range specs {
		line := s.Alias + " " + s.Hostname
		if s.Port != 0 {
			line += fmt.Sprintf(":%d", s.Port)
		}
		line += " " + s.User
		if s.Role != "" {
			line += " " + s.Role
		}
		args = append(args, "--host="+line)
	}
	if category != "" {
		create = true
		args = append(args, "--category="+category)
	} else if create {
		args = append(args, "--create-profile")
	}
	args = append(args, "--yes")
	return Change{
		Command: "host apply", Args: args,
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: profile}},
		Run: func(p paths.Paths, out io.Writer) error {
			if len(specs) == 0 {
				return errors.New("no host specs given")
			}
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			_, exists := m.Profiles[profile]
			if !exists && !create {
				return fmt.Errorf("unknown profile: %q (create it with the profile, or tick create)", profile)
			}
			res, err := editor.New(p).ApplyCreatingProfile(profile, category, !exists, specs)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, editor.FormatApply(profile, !exists, res, false))
			if err := ApplyManifestEdit(out, p); err != nil {
				return err
			}
			if editor.AnyAdded(res) {
				_, _ = fmt.Fprintln(out, "run reconcile to mint new hosts' keys")
			}
			return nil
		},
	}
}

// ProfileCategory is `sshmgr profile edit <name> --category <category>`: it
// moves the profile's key directory, private keys and all, and the inventory
// records follow. "" returns it to the flat layout.
func ProfileCategory(name, category string) Change {
	return Change{
		Command: "profile edit", Args: []string{name, "--category=" + category},
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: name}},
		Run: func(p paths.Paths, out io.Writer) error {
			res, err := editor.New(p).SetCategory(name, category)
			if err != nil {
				return err
			}
			if res.From != res.To {
				verb := "keys expected at"
				if res.Moved {
					verb = "moved keys to"
				}
				_, _ = fmt.Fprintf(out, "%s: %s %s (was %s); %d inventory record(s) updated\n",
					name, verb, res.To, res.From, res.RecordsUpdated)
			}
			_, _ = fmt.Fprintf(out, "edited profile %s (run `sshmgr reconcile` to mint any key "+
				"this now points at)\n", name)
			if err := ApplyManifestEdit(out, p); err != nil {
				return err
			}
			if m, err := manifest.Load(p.Manifest()); err == nil {
				WarnDangling(out, p, m)
			}
			return nil
		},
	}
}

// ProfilePurge is `sshmgr profile delete <name> --purge --yes`: everything
// ProfileDelete removes, and the profile's key files too. It never runs
// without the encrypted backup the CLI writes first; the web has no
// --no-key-backup.
func ProfilePurge(name string) Change {
	return Change{
		Command: "profile delete", Args: []string{name, "--purge", "--yes"},
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: name}},
		Effects: func(p paths.Paths) ([]string, error) {
			if err := backupReady(); err != nil {
				return nil, err
			}
			return []string{"writes an encrypted backup of ~/.ssh and the config to " + p.DistDir() +
				" first, so the deleted keys can be restored"}, nil
		},
		OnApply: func(p paths.Paths, out io.Writer) error {
			return bundler.BackupBeforeDestroying(p, out, false)
		},
		Run: func(p paths.Paths, out io.Writer) error {
			res, err := lifecycle.New(p, platform.EmitUseKeychain()).
				DeleteProfile(name, lifecycle.Options{Purge: true})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
			return nil
		},
	}
}

// backupReady reports why an encrypted bundle cannot be written now, before
// anything is shown as if it could be.
func backupReady() error {
	if os.Getenv("SSH_MANAGER_AGE_RECIPIENT") == "" {
		return errors.New("this needs an encrypted backup first, and SSH_MANAGER_AGE_RECIPIENT is not set: " +
			"set it to an age recipient (age-keygen -o <identity>) and restart sshmgr serve")
	}
	if _, err := exec.LookPath("age"); err != nil {
		return errors.New("this needs an encrypted backup first, and age is not installed")
	}
	return nil
}

// Clean is `sshmgr clean --yes [--adopt]`: stale pins, stale inventory
// records and write residue. The residue is swept by the snapshot apply takes
// first, as the CLI's is.
func Clean(adopt bool) Change {
	args := []string{"--yes"}
	if adopt {
		args = append(args, "--adopt")
	}
	return Change{
		Command: "clean", Args: args,
		Effects: func(p paths.Paths) ([]string, error) {
			var out []string
			for _, r := range snapshots.FindTempArtifacts(p.SSHDir) {
				out = append(out, "removes write residue "+r)
			}
			return out, nil
		},
		Run: func(p paths.Paths, out io.Writer) error {
			return cleaner.Run(p, out, adopt, false, func() {})
		},
	}
}

// Bundle is `sshmgr bundle [--keep N]`: an age-encrypted backup of ~/.ssh
// and the config, written to the config home's dist/. It takes no snapshot,
// as the CLI's does not: it changes nothing a snapshot would hold.
func Bundle(keep int) Change {
	var args []string
	if keep > 0 {
		args = append(args, fmt.Sprintf("--keep=%d", keep))
	}
	return Change{
		Command: "bundle", Args: args, NoSnapshot: true,
		Effects: func(p paths.Paths) ([]string, error) {
			if err := backupReady(); err != nil {
				return nil, errors.New(strings.Replace(err.Error(), "this needs an encrypted backup first, and ", "", 1))
			}
			out := []string{"writes an encrypted bundle of ~/.ssh and the config to " + p.DistDir()}
			if keep > 0 {
				// The new bundle is the newest, so it counts towards keep.
				old := bundler.Sorted(p.DistDir())
				for i := 0; i < len(old)+1-keep && i < len(old); i++ {
					out = append(out, "removes bundle "+filepath.Base(old[i]))
				}
			}
			return out, nil
		},
		OnApply: func(p paths.Paths, out io.Writer) error {
			stamp := time.Now().Format("20060102-150405")
			res, err := bundler.New(p.SSHDir, p.ConfigDir, bundler.AgeCipher{}).
				Bundle(os.Getenv("SSH_MANAGER_AGE_RECIPIENT"), p.DistDir(), stamp)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
			if keep > 0 {
				for _, pruned := range bundler.Prune(p.DistDir(), keep) {
					_, _ = fmt.Fprintf(out, "pruned %s\n", pruned)
				}
			}
			return nil
		},
		Run: func(paths.Paths, io.Writer) error { return nil },
	}
}

// VMDockerContext is `sshmgr vm docker-context <alias>`: create, or update,
// the Docker context ssh://<alias> for a VM host.
func VMDockerContext(alias string) Change {
	return Change{
		Command: "vm docker-context", Args: []string{alias}, NoSnapshot: true,
		Subjects: []history.Subject{{Kind: history.KindHost, Name: alias}},
		Effects: func(p paths.Paths) ([]string, error) {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return nil, err
			}
			if _, err := manifest.VMHost(m, alias); err != nil {
				return nil, err
			}
			if err := dockerctx.Available(); err != nil {
				return nil, err
			}
			return []string{fmt.Sprintf("%ss the Docker context %s -> ssh://%s", dockerctx.Verb(alias), alias, alias)}, nil
		},
		OnApply: func(_ paths.Paths, out io.Writer) error {
			line, err := dockerctx.Apply(alias)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, line)
			return nil
		},
		Run: func(paths.Paths, io.Writer) error { return nil },
	}
}

// NotifyTest is `sshmgr notify test`: one test desktop notification.
func NotifyTest() Change {
	return Change{
		Command: "notify test", NoSnapshot: true,
		Effects: func(paths.Paths) ([]string, error) {
			return []string{"sends a test desktop notification"}, nil
		},
		OnApply: func(p paths.Paths, out io.Writer) error {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if notifier.New(p, m).Test() {
				_, _ = fmt.Fprintln(out, "sent a test desktop notification.")
			} else {
				_, _ = fmt.Fprintln(out, "no notification backend found (install notify-send / terminal-notifier).")
			}
			return nil
		},
		Run: func(paths.Paths, io.Writer) error { return nil },
	}
}

// AuditNotify is the --notify half of `sshmgr audit --notify`: the desktop
// alert for keys that need attention, if one is due. It is gated by the same
// daily or weekly cadence, so asking twice in a day sends one.
func AuditNotify() Change {
	return Change{
		Command: "audit", Args: []string{"--notify"}, NoSnapshot: true,
		Effects: func(paths.Paths) ([]string, error) {
			return []string{"sends the desktop alert for keys that need attention, if one is due " +
				"(at most daily while a key is close to expiry, weekly otherwise)"}, nil
		},
		OnApply: func(p paths.Paths, out io.Writer) error {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			status := "not sent (not due, disabled, or no notifier backend)"
			if notifier.New(p, m).Notify(time.Now(), false) {
				status = "sent"
			}
			_, _ = fmt.Fprintln(out, "desktop notification: "+status)
			return nil
		},
		Run: func(paths.Paths, io.Writer) error { return nil },
	}
}
