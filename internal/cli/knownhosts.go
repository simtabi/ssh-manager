package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/lock"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// heldLock keeps the acquired advisory lock alive for the rest of the process so
// the OS doesn't release it (and GC doesn't close the fd) before the mutation
// finishes; a short-lived CLI command releases it on exit.
var heldLock func()

// snapshotBeforeMutation is the native mutation guard (mirrors the Facade's
// _mutating): take the advisory lock so concurrent commands serialize, sweep crash
// residue, then snapshot ~/.ssh so the change is reversible. The lock is best-
// effort - a failure to acquire doesn't block the operation. Returns the snapshot
// path ("" if none was made).
func snapshotBeforeMutation(p paths.Paths) string {
	if rel, err := lock.Acquire(p.LockFile()); err == nil {
		heldLock = rel
	}
	snapshots.CleanTempArtifacts(p.SSHDir)
	snap, _ := snapshots.Snapshot(p.SSHDir, p.SnapshotsDir(), snapshotRetain, "")
	return snap
}

func newKnownHostsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "knownhosts",
		Short: "Initialize/pin per-profile known_hosts",
	}

	var allInit, user, force bool
	initCmd := &cobra.Command{
		Use:   "init [profile]",
		Short: "Initialize known_hosts and pin reachable hosts (TOFU; fingerprints reported)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			profile := ""
			if len(args) > 0 {
				profile = args[0]
			}
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			snapshotBeforeMutation(p)
			report, err := knownhosts.New(p.SSHDir).Init(m, profile, allInit, user, force)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), report.Format())
			return nil
		},
	}
	initCmd.Flags().BoolVar(&allInit, "all", false, "initialize every profile's store")
	initCmd.Flags().BoolVar(&user, "user", false, "also initialize the per-user ~/.ssh/known_hosts")
	initCmd.Flags().BoolVar(&force, "force", false, "re-scan already-trusted hosts and add any new keys")
	cmd.AddCommand(initCmd)

	var allPin, yes bool
	var port int
	pin := &cobra.Command{
		Use:   "pin [host]",
		Short: "Seed each host's per-profile known_hosts via ssh-keyscan, with confirmation",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			host := ""
			if len(args) > 0 {
				host = args[0]
			}
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			svc := knownhosts.New(p.SSHDir)
			all, err := knownhosts.Targets(m)
			if err != nil {
				return err
			}
			var targets []knownhosts.Target
			switch {
			case allPin:
				targets = all
			case host != "":
				var match *knownhosts.Target
				for i := range all {
					if all[i].Alias == host {
						match = &all[i]
						break
					}
				}
				if match != nil {
					targets = []knownhosts.Target{*match}
				} else {
					// A host not in the manifest is scanned verbatim with --port.
					targets = []knownhosts.Target{{Profile: knownhosts.ProfileOfAlias(m, host), Alias: host, Hostname: host, Port: port}}
				}
			}
			out := c.OutOrStdout()
			if len(targets) == 0 {
				fmt.Fprintln(out, "give a HOST or use --all")
				return fmt.Errorf("no target")
			}
			byProfile := map[string][]string{}
			for _, t := range targets {
				for _, sk := range svc.Scan(t.Hostname, t.Port) {
					label := t.Profile
					if label == "" {
						label = "global"
					}
					fmt.Fprintf(out, "[%s] %s  %s  %s\n", label, sk.Host, sk.Keytype, sk.Fingerprint)
					if yes || confirm(c, fmt.Sprintf("  trust this %s key for %s?", sk.Keytype, sk.Host)) {
						byProfile[t.Profile] = append(byProfile[t.Profile], sk.Line)
					}
				}
			}
			if len(byProfile) > 0 {
				snapshotBeforeMutation(p)
			}
			total := 0
			for prof, lines := range byProfile {
				n, err := svc.Add(lines, prof)
				if err != nil {
					return err
				}
				total += n
			}
			fmt.Fprintf(out, "pinned %d host key(s) into per-profile known_hosts\n", total)
			return nil
		},
	}
	pin.Flags().BoolVar(&allPin, "all", false, "pin every host in the manifest")
	pin.Flags().IntVarP(&port, "port", "p", 22, "port for an unmanaged host")
	pin.Flags().BoolVarP(&yes, "yes", "y", false, "trust scanned keys without prompting")
	cmd.AddCommand(pin)

	return cmd
}
