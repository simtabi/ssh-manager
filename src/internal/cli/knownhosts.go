package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

func newKnownHostsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "knownhosts",
		Short: "Pin host keys into the single ~/.ssh/known_hosts trust store",
	}

	var allInit, force, initYes bool
	initCmd := &cobra.Command{
		Use:   "init [profile]",
		Short: "Pin reachable hosts into known_hosts (TOFU; fingerprints reported)",
		Long: "Pin reachable hosts into known_hosts (TOFU; fingerprints reported).\n\n" +
			"PROFILE and --all select which manifest hosts to scan, not a separate\n" +
			"file: every host is pinned into the one ~/.ssh/known_hosts store.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := confirmChange(c,
				"knownhosts init scans the hosts it can reach and pins their keys "+
					"into ~/.ssh/known_hosts (trust on first use).", initYes); err != nil {
				return err
			}
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
			report, err := knownhosts.New(p.SSHDir).Init(m, profile, allInit, force)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(c.OutOrStdout(), report.Format())
			return nil
		},
	}
	initCmd.Flags().BoolVar(&allInit, "all", false, "scan every profile's hosts")
	initCmd.Flags().BoolVarP(&initYes, "yes", "y", false, "pin without confirming (implied when there is no terminal)")
	initCmd.Flags().BoolVar(&force, "force", false, "re-scan already-trusted hosts and add any new keys")
	cmd.AddCommand(initCmd)

	var allPin, yes bool
	var port int
	pin := &cobra.Command{
		Use:   "pin [host]",
		Short: "Seed known_hosts via ssh-keyscan, with confirmation",
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
				_, _ = fmt.Fprintln(out, "give a HOST or use --all")
				return fmt.Errorf("no target")
			}
			byProfile := map[string][]string{}
			for _, t := range targets {
				for _, sk := range svc.Scan(t.Hostname, t.Port) {
					label := t.Profile
					if label == "" {
						label = "global"
					}
					_, _ = fmt.Fprintf(out, "[%s] %s  %s  %s\n", label, sk.Host, sk.Keytype, sk.Fingerprint)
					if yes || confirm(c, fmt.Sprintf("  trust this %s key for %s?", sk.Keytype, sk.Host)) {
						byProfile[t.Profile] = append(byProfile[t.Profile], sk.Line)
					}
				}
			}
			if len(byProfile) > 0 {
				snapshotBeforeMutation(p)
			}
			var all2 []string
			for _, lines := range byProfile {
				all2 = append(all2, lines...)
			}
			total, err := svc.Add(all2)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "pinned %d host key(s) into known_hosts\n", total)
			return nil
		},
	}
	pin.Flags().BoolVar(&allPin, "all", false, "pin every host in the manifest")
	pin.Flags().IntVarP(&port, "port", "p", 22, "port for an unmanaged host")
	pin.Flags().BoolVarP(&yes, "yes", "y", false, "trust scanned keys without prompting")
	cmd.AddCommand(pin)

	return cmd
}
