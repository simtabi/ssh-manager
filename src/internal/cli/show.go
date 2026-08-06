package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
)

// newShowCmd is the "what is actually going on with this thing" verb. `view`
// answers it host-first from the manifest; `show` answers it across all four
// places the truth is spread - the manifest, the key files, the rendered config
// and the trust store - because a host that fails to authenticate is usually a
// disagreement between them.
//
// It never prints key material: files are reported as paths, modes and
// fingerprints.
func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <profile|alias|profile/key>",
		Short: "Everything about a profile, host or key: files, config, pins",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			selector := args[0]
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			keys := keysvc.New(m, inv, p.SSHDir)
			kh := knownhosts.New(p.SSHDir)
			out := c.OutOrStdout()

			// Profile, then host alias, then key: the same precedence `view` uses,
			// so one selector never means different things to different verbs.
			if prof, ok := m.Profiles[selector]; ok {
				return showProfile(out, m, keys, kh, selector, prof)
			}
			for _, pname := range m.ProfileNames() {
				for _, host := range m.Profiles[pname].Hosts {
					if host.Alias == selector {
						return showHost(out, m, keys, kh, pname, host)
					}
				}
			}
			ref, err := m.ResolveKeySelector(selector)
			if err != nil {
				return fmt.Errorf("no profile, host or key matches %q", selector)
			}
			return showKey(out, keys, ref, "")
		},
	}
}

func showProfile(out io.Writer, m *manifest.Manifest, keys *keysvc.Service, kh *knownhosts.Service,
	name string, prof manifest.Profile) error {
	_, _ = fmt.Fprintf(out, "profile %s  (key_scope: %s", name, prof.KeyScope)
	if prof.KeyName != nil && *prof.KeyName != "" {
		_, _ = fmt.Fprintf(out, ", key_name: %s", *prof.KeyName)
	}
	_, _ = fmt.Fprintln(out, ")")

	rows, err := keys.Rows("")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "\nkeys:")
	found := 0
	for _, row := range rows {
		if row.Ref.Profile != name {
			continue
		}
		found++
		if err := showKey(out, keys, row.Ref, "  "); err != nil {
			return err
		}
	}
	if found == 0 {
		_, _ = fmt.Fprintln(out, "  (none)")
	}

	_, _ = fmt.Fprintln(out, "\nhosts:")
	if len(prof.Hosts) == 0 {
		_, _ = fmt.Fprintln(out, "  (none)")
		return nil
	}
	for _, host := range prof.Hosts {
		kname, err := m.ResolvedKeyName(name, host)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "  %s  ->  %s  (%s)\n", host.Alias, hostPort(host), kname)
		writePins(out, kh, "    ", host)
	}
	return nil
}

func showHost(out io.Writer, m *manifest.Manifest, keys *keysvc.Service, kh *knownhosts.Service,
	profile string, host manifest.Host) error {
	_, _ = fmt.Fprintf(out, "host %s  (profile %s)\n", host.Alias, profile)

	block, err := renderer.RenderHostBlockFor(m, profile, host)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "\nconfig (as rendered from the manifest; `sshmgr diff` compares it to the file):")
	for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		_, _ = fmt.Fprintln(out, "  "+line)
	}

	kname, err := m.ResolvedKeyName(profile, host)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "\nkey:")
	if err := showKey(out, keys, manifest.KeyRef{Profile: profile, KeyName: kname}, "  "); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(out, "\nknown_hosts:")
	writePins(out, kh, "  ", host)
	return nil
}

// showKey prints one key: what it is, the files that hold it (paths, modes and
// fingerprints - never contents), the hosts using it, and where it is deployed.
func showKey(out io.Writer, keys *keysvc.Service, ref manifest.KeyRef, indent string) error {
	d, err := keys.Detail(ref)
	if err != nil {
		return err
	}
	line := func(format string, a ...any) {
		_, _ = fmt.Fprintf(out, indent+format+"\n", a...)
	}
	state := d.Status
	if notes := keyaudit.Notes(d.Row); len(notes) > 0 {
		state += "  " + strings.Join(notes, ",")
	}
	line("%s  (%s)  %s", ref, d.Type, state)
	line("  rotate after: %d days", d.RotateAfterDays)
	if d.ExpiresOn != "" {
		line("  expires on:   %s", d.ExpiresOn)
	}
	if d.Fingerprint != "" {
		line("  recorded:     %s", d.Fingerprint)
	}
	switch {
	case d.FingerprintErr != "":
		line("  on disk:      unreadable (%s)", d.FingerprintErr)
	case d.DiskFingerprint != "":
		line("  on disk:      %s", d.DiskFingerprint)
	}
	if d.Mismatched() {
		line("  MISMATCH: the key on disk is not the one the inventory recorded - deployments")
		line("            and expiry describe a key that is no longer there.")
	}
	line("  files:")
	for _, f := range []struct {
		path   string
		onDisk bool
		mode   uint32
	}{
		{d.PrivatePath, d.PrivateOnDisk, uint32(d.PrivateMode)},
		{d.PublicPath, d.PublicOnDisk, uint32(d.PublicMode)},
	} {
		if !f.onDisk {
			line("    %s  (absent)", f.path)
			continue
		}
		line("    %s  (%04o)", f.path, f.mode)
	}
	if d.Wired() {
		line("  hosts: %s", strings.Join(d.Hosts, ", "))
	} else {
		line("  hosts: none - this key is UNWIRED and nothing uses it")
	}
	if len(d.Deployments) > 0 {
		line("  deployments:")
		for _, dep := range d.Deployments {
			flag := "unverified"
			if dep.Verified {
				flag = "verified"
			}
			line("    - %s via %s (%s)", dep.Target, dep.Method, flag)
		}
	}
	return nil
}

// writePins reports the trust-store lines pinning a host. The store is hashed,
// so this is the only way to see what is actually pinned for a host.
func writePins(out io.Writer, kh *knownhosts.Service, indent string, host manifest.Host) {
	entries := kh.EntriesFor(knownHostsToken(host))
	if len(entries) == 0 {
		_, _ = fmt.Fprintf(out, "%snot pinned (run `sshmgr knownhosts pin %s`)\n", indent, host.Alias)
		return
	}
	for _, e := range entries {
		owner := "user-owned"
		if e.Tagged {
			owner = "sshmgr"
		}
		form := "plaintext"
		if e.Hashed {
			form = "hashed"
		}
		marker := ""
		if e.Marker != "" {
			marker = e.Marker + " "
		}
		_, _ = fmt.Fprintf(out, "%s%s%s  %s  %s  [%s, %s]\n", indent, marker, e.Token, e.Keytype, e.Fingerprint, form, owner)
	}
}

// knownHostsToken is how ssh writes a host in known_hosts: bare for port 22,
// [host]:port otherwise.
func knownHostsToken(host manifest.Host) string {
	if host.Port == 0 || host.Port == 22 {
		return host.Hostname
	}
	return fmt.Sprintf("[%s]:%d", host.Hostname, host.Port)
}

func hostPort(host manifest.Host) string {
	if host.Port == 0 || host.Port == 22 {
		return host.Hostname
	}
	return fmt.Sprintf("%s:%d", host.Hostname, host.Port)
}
