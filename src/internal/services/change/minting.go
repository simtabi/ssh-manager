package change

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/providers"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/doctor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/homeperms"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

// The changes that make keys. A preview mints throwaway keys in its copy -
// real ones, from ssh-keygen, deleted with the copy - so it shows exactly the
// files and records the change writes; apply then mints the keys that stay.
// They never take a passphrase (the web takes none, D7), never overwrite a
// key that exists, and never pin hosts, which needs the network.

// errOnePassword refuses a change that would mint in 1Password: a preview
// mints for real, and in a vault that is an item a person would have to
// delete by hand.
var errOnePassword = errors.New("keys kept in 1Password are minted from the terminal: run the command shown above with sshmgr")

func refuseOnePassword(m *manifest.Manifest, profiles ...string) error {
	if len(profiles) == 0 {
		profiles = m.ProfileNames()
	}
	for _, name := range profiles {
		if prof, ok := m.Profiles[name]; ok && prof.InOnePassword() {
			return errOnePassword
		}
	}
	return nil
}

// Reconcile is `sshmgr reconcile --yes --no-pin`: mint every missing key,
// record keys already on disk, render the config, fix modes.
func Reconcile() Change {
	return Change{
		Command: "reconcile", Args: []string{"--yes", "--no-pin"}, Mints: true,
		Run: func(p paths.Paths, out io.Writer) error {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if err := refuseOnePassword(m); err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			res, err := reconciler.New(p, m, inv, platform.EmitUseKeychain()).Reconcile(false, "")
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
			WarnDangling(out, p, m)
			return nil
		},
	}
}

// Keygen is `sshmgr keygen <profile|alias> --no-pin --yes`, without --force:
// it mints the target's missing keys and leaves every existing one alone.
func Keygen(target string) Change {
	return Change{
		Command: "keygen", Args: []string{target, "--no-pin", "--yes"}, Mints: true,
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: target}},
		Run: func(p paths.Paths, out io.Writer) error {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			profile, ok := ownerOf(m, target)
			if !ok {
				return fmt.Errorf("unknown profile or host: %q", target)
			}
			if err := refuseOnePassword(m, profile); err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			r := reconciler.New(p, m, inv, platform.EmitUseKeychain())
			existing, err := r.ExistingKeys(target)
			if err != nil {
				return err
			}
			if len(existing) > 0 {
				names := make([]string, 0, len(existing))
				for _, ref := range existing {
					names = append(names, ref.String())
				}
				_, _ = fmt.Fprintf(out, "%d key(s) already exist in %q: %s\n", len(existing), target, strings.Join(names, ", "))
				_, _ = fmt.Fprintln(out, "  existing keys will be SKIPPED - re-run with --force to "+
					"overwrite (the replaced key is kept in the profile's old/ dir).")
			}
			minted, err := r.Mint(target, "", map[manifest.KeyRef]bool{})
			if err != nil {
				return err
			}
			if len(minted) == 0 {
				_, _ = fmt.Fprintf(out, "no keys minted for %q (all present; --force to overwrite)\n", target)
				return nil
			}
			for _, mk := range minted {
				_, _ = fmt.Fprintf(out, "minted %s  %s  (needs-redeploy)\n", mk.KeyName, mk.Fingerprint)
			}
			return nil
		},
	}
}

// ownerOf is the profile a keygen target names: the profile itself, or the
// profile holding the host alias.
func ownerOf(m *manifest.Manifest, target string) (string, bool) {
	if _, ok := m.Profiles[target]; ok {
		return target, true
	}
	for _, name := range m.ProfileNames() {
		for _, h := range m.Profiles[name].Hosts {
			if h.Alias == target {
				return name, true
			}
		}
	}
	return "", false
}

// KeyAdd is `sshmgr key add <profile> <name> [--type] [--host]`: declare the
// key, mint it, and wire it to a host when one is named.
func KeyAdd(profile, name, keyType, host string) Change {
	args := []string{profile, name}
	var kt *string
	if keyType != "" {
		kt = &keyType
		args = append(args, "--type="+keyType)
	}
	if host != "" {
		args = append(args, "--host="+host)
	}
	return Change{
		Command: "key add", Args: args, Mints: true,
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: profile}, {Kind: history.KindKey, Name: name}},
		Run: func(p paths.Paths, out io.Writer) error {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if err := refuseOnePassword(m, profile); err != nil {
				return err
			}
			if err := editor.New(p).AddKey(profile, name, kt, nil, host); err != nil {
				return err
			}
			if m, err = manifest.Load(p.Manifest()); err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			ref := manifest.KeyRef{Profile: profile, KeyName: name}
			minted, err := reconciler.New(p, m, inv, platform.EmitUseKeychain()).MintRef(ref, "")
			if err != nil {
				return err
			}
			switch {
			case minted != nil:
				_, _ = fmt.Fprintf(out, "minted %s  %s  (needs-redeploy)\n", ref, minted.Fingerprint)
			default:
				_, _ = fmt.Fprintf(out, "declared %s (a key already exists at that path; left untouched)\n", ref)
			}
			if host != "" {
				_, _ = fmt.Fprintf(out, "wired to host %s\n", host)
			} else {
				_, _ = fmt.Fprintf(out, "UNWIRED: no host uses %s yet. Wire it with:\n"+
					"  sshmgr host edit %s <alias> --key-name %s\n", ref, profile, name)
			}
			return ApplyManifestEdit(out, p)
		},
	}
}

// ProvidersExport is `sshmgr providers --export`, without --force: write the
// shipped provider catalog into the home to customize, unless one is there.
func ProvidersExport() Change {
	return Change{
		Command: "providers", Args: []string{"--export"},
		Run: func(p paths.Paths, out io.Writer) error {
			dest := p.Providers()
			if fs.Exists(dest) {
				return fmt.Errorf("%s already exists - use --force to overwrite it", dest)
			}
			if err := fs.EnsureDir(p.ConfigDir, perms.DirMode); err != nil {
				return err
			}
			if err := fs.WriteTextAtomic(dest, string(providers.DefaultCatalog()), homeperms.FileMode); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "wrote provider catalog to %s - edit it to customize "+
				"(delete it to track the shipped default again)\n", dest)
			return nil
		},
	}
}

// SnapshotsPrune is `sshmgr snapshots prune --keep <n>`. It takes no
// snapshot of its own first, which would push one more out.
func SnapshotsPrune(keep int) Change {
	return Change{
		Command: "snapshots prune", Args: []string{fmt.Sprintf("--keep=%d", keep)}, NoSnapshot: true,
		Effects: func(p paths.Paths) ([]string, error) {
			if keep < 0 {
				return nil, fmt.Errorf("--keep %d: want 0 or more", keep)
			}
			list := snapshots.List(p.SnapshotsDir())
			var out []string
			for i := 0; i < len(list)-keep; i++ {
				out = append(out, "removes snapshot "+filepath.Base(list[i]))
			}
			if len(out) == 0 {
				out = append(out, fmt.Sprintf("removes nothing: %d snapshot(s), keeping %d", len(list), keep))
			}
			return out, nil
		},
		Run: func(p paths.Paths, out io.Writer) error {
			// The preview's copy holds no snapshots; only the real run says anything.
			if removed := snapshots.Prune(p.SnapshotsDir(), keep); removed > 0 {
				_, _ = fmt.Fprintf(out, "pruned %d snapshot(s)\n", removed)
			}
			return nil
		},
	}
}

// DoctorFix is the --fix half of `sshmgr doctor --fix`: set every config-home
// and ~/.ssh path back to its canonical mode.
func DoctorFix() Change {
	return Change{
		Command: "doctor", Args: []string{"--fix"},
		Effects: func(p paths.Paths) ([]string, error) {
			m, _ := manifest.Load(p.Manifest())
			rep := doctor.New(p, m, platform.EmitUseKeychain()).Run(false)
			var out []string
			for _, issue := range rep.PermIssues {
				out = append(out, "fixes the mode of "+issue)
			}
			if len(out) == 0 {
				out = append(out, "fixes nothing: every mode is already right")
			}
			return out, nil
		},
		Run: func(p paths.Paths, out io.Writer) error {
			m, _ := manifest.Load(p.Manifest())
			for _, change := range doctor.New(p, m, platform.EmitUseKeychain()).FixPerms() {
				_, _ = fmt.Fprintln(out, "fixed perms:", change)
			}
			return nil
		},
	}
}
