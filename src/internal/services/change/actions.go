package change

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/lifecycle"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// The changes below are the ones a preview can show exactly: each writes
// only the manifest, the inventory and files a snapshot holds. Each runs the
// steps of its CLI command after the guard, in the same order, and the parity
// test in internal/cli holds them to that.
//
// The changes that mint keys are in minting.go, and the ones that act
// outside the copy - a purge, a category move, clean, bundles, Docker
// contexts, notifications - are in outside.go.

// ProfileAdd is `sshmgr profile add <name> [--key-scope] [--key-name] [--key-comment]`.
func ProfileAdd(name, keyScope, keyName, keyComment string) Change {
	if keyScope == "" {
		keyScope = "per_service"
	}
	args := []string{name, "--key-scope=" + keyScope}
	var kn *string
	if keyName != "" {
		kn = &keyName
		args = append(args, "--key-name="+keyName)
	}
	if keyComment != "" {
		args = append(args, "--key-comment=<set>")
	}
	return Change{
		Command: "profile add", Args: args,
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: name}},
		Run: func(p paths.Paths, out io.Writer) error {
			ed := editor.New(p)
			if err := ed.AddProfile(name, keyScope, kn); err != nil {
				return err
			}
			if keyComment != "" {
				if err := ed.SetKeyComment(name, keyComment); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(out, "added profile %s (no hosts yet - add one with "+
				"`sshmgr host add %s <alias>`)\n", name, name)
			return ApplyManifestEdit(out, p)
		},
	}
}

// ProfileEdit is `sshmgr profile edit <name> [--key-scope] [--key-name]`. A
// nil field is left as it is.
func ProfileEdit(name string, keyScope, keyName *string) Change {
	args := []string{name}
	if keyScope != nil {
		args = append(args, "--key-scope="+*keyScope)
	}
	if keyName != nil {
		args = append(args, "--key-name="+*keyName)
	}
	return Change{
		Command: "profile edit", Args: args,
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: name}},
		Run: func(p paths.Paths, out io.Writer) error {
			if err := editor.New(p).EditProfile(name, keyScope, keyName); err != nil {
				return err
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

// ProfileDelete is `sshmgr profile delete <name> --yes`: the manifest, the
// inventory records, the rendered blocks and the pins go; key files stay.
func ProfileDelete(name string) Change {
	return Change{
		Command: "profile delete", Args: []string{name, "--yes"},
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: name}},
		Run: func(p paths.Paths, out io.Writer) error {
			res, err := lifecycle.New(p, platform.EmitUseKeychain()).DeleteProfile(name, lifecycle.Options{})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
			return nil
		},
	}
}

// HostInput is what a person can set on a host from the web. Pointer fields
// are left unchanged when nil, as an unset CLI flag is.
type HostInput struct {
	Hostname, User *string
	Port           *int
	Tags           *[]string
	KeyName        *string
}

func (h HostInput) args() []string {
	var a []string
	if h.Hostname != nil {
		a = append(a, "--hostname="+*h.Hostname)
	}
	if h.User != nil {
		a = append(a, "--user="+*h.User)
	}
	if h.Port != nil {
		a = append(a, fmt.Sprintf("--port=%d", *h.Port))
	}
	if h.KeyName != nil {
		a = append(a, "--key-name="+*h.KeyName)
	}
	if h.Tags != nil {
		for _, t := range *h.Tags {
			a = append(a, "--tag="+t)
		}
		if len(*h.Tags) == 0 {
			a = append(a, "--tag=")
		}
	}
	return a
}

// HostAdd is `sshmgr host add <profile> <alias> -H <hostname> -u <user> [-p] [--tag]...`.
func HostAdd(profile, alias string, in HostInput) Change {
	return Change{
		Command: "host add", Args: append([]string{profile, alias}, in.args()...),
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: profile}, {Kind: history.KindHost, Name: alias}},
		Run: func(p paths.Paths, out io.Writer) error {
			port := 22
			if in.Port != nil {
				port = *in.Port
			}
			f := editor.HostFields{Hostname: in.Hostname, User: in.User, Port: &port, KeyName: in.KeyName}
			if in.Tags != nil {
				f.Tags = *in.Tags
			}
			if err := editor.New(p).AddHost(profile, alias, f); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "added host %s to %s (run `sshmgr reconcile` to mint its "+
				"key)\n", alias, profile)
			return ApplyManifestEdit(out, p)
		},
	}
}

// HostEdit is `sshmgr host edit <profile> <alias> [...]`.
func HostEdit(profile, alias string, in HostInput) Change {
	return Change{
		Command: "host edit", Args: append([]string{profile, alias}, in.args()...),
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: profile}, {Kind: history.KindHost, Name: alias}},
		Run: func(p paths.Paths, out io.Writer) error {
			f := editor.HostFields{Hostname: in.Hostname, User: in.User, Port: in.Port, KeyName: in.KeyName, SetTags: in.Tags}
			if err := editor.New(p).EditHost(profile, alias, f); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "edited host %s\n", alias)
			if in.KeyName != nil {
				_, _ = fmt.Fprintln(out, "  the key it now names may not exist yet - "+
					"run `sshmgr reconcile` to mint it")
			}
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

// HostDelete is `sshmgr host delete <profile> <alias> --yes`: the host, its
// block and its pins go; its key files stay.
func HostDelete(profile, alias string) Change {
	return Change{
		Command: "host delete", Args: []string{profile, alias, "--yes"},
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: profile}, {Kind: history.KindHost, Name: alias}},
		Run: func(p paths.Paths, out io.Writer) error {
			res, err := lifecycle.New(p, platform.EmitUseKeychain()).DeleteHost(profile, alias, lifecycle.Options{})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
			return nil
		},
	}
}

// KeyDelete is `sshmgr key delete <profile/key> --yes`: the declaration and
// the record go; the files stay.
func KeyDelete(ref manifest.KeyRef) Change {
	return Change{
		Command: "key delete", Args: []string{ref.String(), "--yes"},
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: ref.Profile}, {Kind: history.KindKey, Name: ref.KeyName}},
		Run: func(p paths.Paths, out io.Writer) error {
			res, err := lifecycle.New(p, platform.EmitUseKeychain()).DeleteKey(ref, lifecycle.Options{})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
			return nil
		},
	}
}

// VMAdd is `sshmgr vm add <profile> <alias> --hypervisor --vm -u <user> --yes`.
func VMAdd(profile, alias, hypervisor, vmName, user string) Change {
	return Change{
		Command:  "vm add",
		Args:     []string{profile, alias, "--hypervisor=" + hypervisor, "--vm=" + vmName, "--user=" + user, "--yes"},
		Subjects: []history.Subject{{Kind: history.KindProfile, Name: profile}, {Kind: history.KindHost, Name: alias}},
		Run: func(p paths.Paths, out io.Writer) error {
			if hypervisor == manifest.HypervisorOrbStack || hypervisor == manifest.HypervisorPodman {
				return fmt.Errorf("%s manages its own SSH access and keys; use `sshmgr vm docker-context` instead of a host", hypervisor)
			}
			name := alias
			f := editor.HostFields{Hostname: &name, User: &user,
				VM: &manifest.VMSpec{Hypervisor: hypervisor, Name: vmName}}
			if err := editor.New(p).AddHost(profile, alias, f); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "added VM host %s to %s (%s %q); run `sshmgr reconcile` to mint its key, "+
				"then install the public key in the guest\n", alias, profile, hypervisor, vmName)
			return ApplyManifestEdit(out, p)
		},
	}
}

// ConfigRender is `sshmgr config render --yes`: migrate any legacy
// per-profile known_hosts into the single store, then write the config.
func ConfigRender() Change {
	return Change{
		Command: "config render", Args: []string{"--yes"},
		Run: func(p paths.Paths, out io.Writer) error {
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if legacy, _ := filepath.Glob(filepath.Join(p.SSHDir, "profiles", "*", "known_hosts")); len(legacy) > 0 {
				rep, err := knownhosts.New(p.SSHDir).MigrateLegacyStores()
				if err != nil {
					return err
				}
				if len(rep.Removed) > 0 {
					_, _ = fmt.Fprintf(out, "migrated %d known_hosts line(s) from %s into the single store\n",
						rep.Merged, strings.Join(rep.Removed, ", "))
				}
			}
			res, err := configsvc.New(p.SSHDir, m, platform.EmitUseKeychain()).Write(false)
			if err != nil {
				return err
			}
			if len(res.Written) > 0 {
				_, _ = fmt.Fprintf(out, "wrote: %s\n", strings.Join(res.Written, ", "))
			}
			if len(res.Pruned) > 0 {
				_, _ = fmt.Fprintf(out, "pruned: %s\n", strings.Join(res.Pruned, ", "))
			}
			if len(res.Written) == 0 && len(res.Pruned) == 0 {
				_, _ = fmt.Fprintln(out, "config: already in sync")
			}
			return nil
		},
	}
}
