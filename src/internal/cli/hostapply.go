package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
)

const hostApplyLong = `Add or update hosts from compact specs:

    <alias> <host>[:port] <user> [role]

A host that is not in the profile is added (as ` + "`host add`" + `); one that is has
its hostname, user and port (when given) set (as ` + "`host edit`" + `). The role, and
any --tag, are merged into the host's tags; existing tags are never removed.
Re-running the same specs is a no-op that reports every host unchanged.

Specs come from any mix of:
  - one spec as positional arguments after the profile
  - --host "<spec>", repeatable
  - -f FILE (- for stdin): one spec per line, blank lines and # comments
    skipped; or a JSON array of spec strings or
    {"alias","host","user","port","role","tags"} objects

The batch is checked by the manifest's own validation and saved at once, so one
bad spec changes nothing. --reconcile mints the new hosts' keys afterwards.`

const hostApplyExample = `  sshmgr host apply adelsaiq dani-prd-web-00 206.189.185.129 ploi web
  sshmgr host apply adelsaiq \
      --host "dani-prd-web-00 206.189.185.129 ploi web" \
      --host "dani-prd-db-00  137.184.219.1   ploi db" --tag prd --reconcile
  sshmgr host apply adelsaiq -f hosts.txt --create-profile --category clients
  printf 'bastion 10.0.0.5:2222 admin\n' | sshmgr host apply adelsaiq -f - --dry-run`

func newHostApplyCmd() *cobra.Command {
	var specLines, extraTags []string
	var file, category string
	var createProfile, doReconcile, dryRun, yes, noPin bool
	cmd := &cobra.Command{
		Use:     "apply <profile> [<alias> <host>[:port] <user> [role]]",
		Short:   "Add or update hosts from compact specs (one, many, or a file)",
		Long:    hostApplyLong,
		Example: hostApplyExample,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("a profile is required")
			}
			if n := len(args) - 1; n != 0 && (n < 3 || n > 4) {
				return fmt.Errorf("a positional spec is `<alias> <host>[:port] <user> [role]` "+
					"(3 or 4 values after the profile, got %d)", n)
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			profile := args[0]
			specs, err := collectHostSpecs(c.InOrStdin(), args[1:], specLines, file)
			if err != nil {
				return err
			}
			if len(specs) == 0 {
				return fmt.Errorf("no host specs given: pass `<alias> <host> <user> [role]`, --host or -f")
			}
			for i := range specs {
				specs[i].Tags = append(specs[i].Tags, extraTags...)
			}
			if category != "" {
				createProfile = true
			}
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			willAsk := !dryRun && asks(yes)
			if !willAsk {
				lockForMutation(p)
			}
			out := c.OutOrStdout()
			ed := editor.New(p)
			var exists bool
			// summarize reads the profile and previews the batch against it. A
			// missing profile cannot be previewed against, so every spec is an add.
			summarize := func() (string, error) {
				m, err := manifest.Load(p.Manifest())
				if err != nil {
					return "", err
				}
				_, exists = m.Profiles[profile]
				if !exists && !createProfile {
					return "", fmt.Errorf("unknown profile: %q (add it with `sshmgr profile add %s`, "+
						"or pass --create-profile / --category)", profile, profile)
				}
				var preview []editor.ApplyResult
				if exists {
					if preview, err = ed.ApplyHosts(profile, specs, true); err != nil {
						return "", err
					}
				} else {
					for _, s := range specs {
						preview = append(preview, editor.ApplyResult{Alias: s.Alias, Action: editor.HostAdded})
					}
				}
				return formatApply(profile, !exists, preview, true), nil
			}
			summary, err := summarize()
			if err != nil {
				return err
			}
			if dryRun {
				_, _ = fmt.Fprintln(out, summary)
				return nil
			}
			// Every batch asks now, an existing profile's too (W15): it used to
			// apply with no confirmation where every other manifest edit asks.
			if err := confirmChange(c, summary, yes); err != nil {
				return err
			}
			if willAsk {
				if err := recheck(p, summary, summarize); err != nil {
					return err
				}
			}

			snapshotBeforeMutation(p)
			res, err := applyCreatingProfile(ed, p.Manifest(), profile, category, !exists, specs)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, formatApply(profile, !exists, res, false))
			if err := applyManifestEdit(c, p); err != nil {
				return err
			}
			if !doReconcile {
				if anyAdded(res) {
					_, _ = fmt.Fprintln(out, "run `sshmgr reconcile` (or pass --reconcile) to mint new hosts' keys")
				}
				return nil
			}
			return reconcileApply(c, p, yes, false, noPin)
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&specLines, "host", nil, `a spec "<alias> <host>[:port] <user> [role]" (repeatable)`)
	f.StringVarP(&file, "file", "f", "", "read specs from a file, one per line or a JSON array (- for stdin)")
	f.StringArrayVar(&extraTags, "tag", nil, "extra tag for every host in the batch (repeatable)")
	f.BoolVar(&createProfile, "create-profile", false, "create the profile if it does not exist")
	f.StringVar(&category, "category", "", "category for a profile this creates (implies --create-profile)")
	f.BoolVar(&doReconcile, "reconcile", false, "run reconcile afterwards to mint keys and re-render")
	f.BoolVar(&noPin, "no-pin", false, "with --reconcile: don't auto-pin reachable hosts' known_hosts")
	f.BoolVar(&dryRun, "dry-run", false, "report what would change without writing")
	f.BoolVarP(&yes, "yes", "y", false, "apply without confirming (implied when there is no terminal)")
	return cmd
}

// applyCreatingProfile runs the batch, first creating the profile when asked.
// Creating it is a separate save, so if the batch then fails validation the
// manifest is put back exactly as it was - otherwise a refused batch left an
// empty profile behind. A new profile has no key directory yet, so restoring
// the manifest is the whole of the undo.
func applyCreatingProfile(ed *editor.Editor, manifestPath, profile, category string, create bool,
	specs []editor.HostSpec) ([]editor.ApplyResult, error) {
	if !create {
		return ed.ApplyHosts(profile, specs, false)
	}
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	undo := func(cause error) error {
		if werr := os.WriteFile(manifestPath, before, 0o600); werr != nil {
			return fmt.Errorf("%w (and restoring the manifest failed: %v)", cause, werr)
		}
		return cause
	}
	if err := ed.AddProfile(profile, "per_service", nil); err != nil {
		return nil, undo(err)
	}
	if category != "" {
		if _, err := ed.SetCategory(profile, category); err != nil {
			return nil, undo(err)
		}
	}
	res, err := ed.ApplyHosts(profile, specs, false)
	if err != nil {
		return nil, undo(err)
	}
	return res, nil
}

// collectHostSpecs merges the positional spec, --host values and -f input, in
// that order.
func collectHostSpecs(stdin io.Reader, positional, lines []string, file string) ([]editor.HostSpec, error) {
	var specs []editor.HostSpec
	if len(positional) > 0 {
		s, err := editor.ParseHostSpec(positional)
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	for _, l := range lines {
		s, err := editor.ParseHostSpecLine(l)
		if err != nil {
			return nil, fmt.Errorf("--host: %w", err)
		}
		specs = append(specs, s)
	}
	if file != "" {
		r := stdin
		if file != "-" {
			fh, err := os.Open(file)
			if err != nil {
				return nil, err
			}
			defer func() { _ = fh.Close() }()
			r = fh
		}
		more, err := editor.ParseHostSpecs(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		specs = append(specs, more...)
	}
	return specs, nil
}

func formatApply(profile string, newProfile bool, res []editor.ApplyResult, preview bool) string {
	var b strings.Builder
	mode := "applied"
	if preview {
		mode = "dry-run"
	}
	fmt.Fprintf(&b, "host apply %s (%s):", profile, mode)
	if newProfile {
		verb := "created"
		if preview {
			verb = "would create"
		}
		fmt.Fprintf(&b, "\n  profile: %s %s", verb, profile)
	}
	counts := map[editor.ApplyAction]int{}
	for _, r := range res {
		counts[r.Action]++
		fmt.Fprintf(&b, "\n  %-9s %s", r.Action, r.Alias)
		if len(r.Changes) > 0 {
			fmt.Fprintf(&b, "  (%s)", strings.Join(r.Changes, "; "))
		}
	}
	fmt.Fprintf(&b, "\n  %d added, %d updated, %d unchanged",
		counts[editor.HostAdded], counts[editor.HostUpdated], counts[editor.HostUnchanged])
	return b.String()
}

func anyAdded(res []editor.ApplyResult) bool {
	for _, r := range res {
		if r.Action == editor.HostAdded {
			return true
		}
	}
	return false
}
