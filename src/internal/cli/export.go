package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// Exports are copies for other tools. They are written under the config home,
// never into ~/.ssh, and the split config `config render` maintains is not
// read, rewritten or replaced by either of them.
const (
	flatExportName    = "ssh_config"
	termiusExportName = "termius-hosts.csv"
	stdoutTarget      = "-"
)

func exportDir(p paths.Paths) string { return filepath.Join(p.ConfigDir, "exports") }

func exportPaths(p paths.Paths) renderer.ExportPaths {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = filepath.Dir(p.SSHDir)
	}
	return renderer.ExportPaths{SSHDir: p.SSHDir, Home: home}
}

// exportTarget resolves --out and refuses any target inside the SSH
// directory. An export is a copy for another tool; written into ~/.ssh it
// could replace the split config it was asked to leave alone, the trust
// store, or a key. Containment is decided by inode (os.SameFile) on each
// existing ancestor, not by comparing strings, so neither another spelling on
// a case-insensitive filesystem (~/.SSH/Config on APFS) nor a symlinked
// directory gets past it.
func exportTarget(p paths.Paths, out, defaultName string) (string, error) {
	if out == "" {
		return filepath.Join(exportDir(p), defaultName), nil
	}
	target, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	if insideDir(target, p.SSHDir) {
		return "", fmt.Errorf("refusing to write %s: it is inside %s, which `sshmgr config render` and "+
			"the key store own; an export must leave it as it is. Choose an --out outside it", target, p.SSHDir)
	}
	return target, nil
}

// insideDir reports whether path is dir or lies under it, judged by inode:
// each existing ancestor of path is compared with dir by os.SameFile.
func insideDir(path, dir string) bool {
	want, err := os.Stat(dir)
	if err != nil {
		return false // no SSH directory yet: nothing there to overwrite
	}
	for cur := filepath.Clean(path); ; {
		if fi, err := os.Stat(cur); err == nil && os.SameFile(fi, want) {
			return true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}

// writeExport writes an export (0600: it names every host and key path) or
// prints it for --out -. It reports where it wrote.
func writeExport(c *cobra.Command, target, text string) error {
	if target == stdoutTarget {
		_, err := fmt.Fprint(c.OutOrStdout(), text)
		return err
	}
	if err := fs.WriteTextAtomic(target, text, 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.OutOrStdout(), "wrote: %s\n", target)
	return nil
}

func loadExport(c *cobra.Command) (paths.Paths, *manifest.Manifest, *configsvc.Service, error) {
	return loadConfigService(c)
}

func newConfigExportCmd() *cobra.Command {
	var flat bool
	var out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the config as one file for another tool (never touches ~/.ssh)",
		Long: "Write a copy of the managed config for a tool that cannot read the split layout.\n\n" +
			"--flat puts every host inline, with absolute key paths and no Include or Match, in\n" +
			"~/.config/ssh-manager/exports/ssh_config (or --out, or - for stdout). The files\n" +
			"`config render` writes under ~/.ssh are left exactly as they are: no target inside ~/.ssh is accepted.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if !flat {
				return errors.New("choose a format: --flat (every host inline in one file)")
			}
			p, m, _, err := loadExport(c)
			if err != nil {
				return err
			}
			target := out
			if out != stdoutTarget {
				if target, err = exportTarget(p, out, flatExportName); err != nil {
					return err
				}
			}
			text, err := renderer.RenderFlatConfig(m, exportPaths(p), platform.EmitUseKeychain())
			if err != nil {
				return err
			}
			return writeExport(c, target, text)
		},
	}
	cmd.Flags().BoolVar(&flat, "flat", false, "every host inline in one file, absolute paths, no Include")
	cmd.Flags().StringVarP(&out, "out", "o", "", "where to write (default ~/.config/ssh-manager/exports/ssh_config; - for stdout)")
	return cmd
}

// openFile is how --open reaches Termius on macOS; tests swap it.
var openFile = func(args ...string) error {
	return exec.Command("open", args...).Run()
}

func stubOpener(f func(args ...string) error) (restore func()) {
	prev := openFile
	openFile = f
	return func() { openFile = prev }
}

func onMacOS() bool { return platform.IsMacOS() }

func newTermiusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "termius",
		Short: "Export hosts for the Termius app",
		Long: "Termius keeps its hosts in its own encrypted vault and offers no command line or\n" +
			"API to add them, and its SSH-config importer does not follow Include, so it cannot\n" +
			"see the split config. `termius export` writes the CSV its importer reads instead.",
	}
	var out string
	var includeGit, open bool
	var skip []string
	export := &cobra.Command{
		Use:   "export",
		Short: "Write a Termius CSV import of every host, and list the key to attach to each",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if open && !onMacOS() {
				return errors.New("--open needs macOS; import the file in Termius by hand")
			}
			p, m, _, err := loadExport(c)
			if err != nil {
				return err
			}
			target := out
			if out != stdoutTarget {
				if target, err = exportTarget(p, out, termiusExportName); err != nil {
					return err
				}
			}
			exp, err := renderer.RenderTermiusCSV(m, exportPaths(p),
				renderer.TermiusOptions{IncludeGit: includeGit, Skip: skip})
			if err != nil {
				return err
			}
			if err := writeExport(c, target, exp.CSV); err != nil {
				return err
			}
			// The CSV owns stdout under --out -, so the report goes to stderr
			// there: piping the export still yields a clean file.
			report := c.OutOrStdout()
			if target == stdoutTarget {
				report = c.ErrOrStderr()
			}
			reportTermius(report, exp, target == stdoutTarget)
			if open {
				if err := openFile("-a", "Termius"); err != nil {
					return fmt.Errorf("could not open Termius: %w", err)
				}
				if err := openFile("-R", target); err != nil {
					return fmt.Errorf("could not show %s in Finder: %w", target, err)
				}
			}
			return nil
		},
	}
	export.Flags().StringVarP(&out, "out", "o", "", "where to write (default ~/.config/ssh-manager/exports/termius-hosts.csv; - for stdout)")
	export.Flags().BoolVar(&includeGit, "include-git", false, "also export git hosts (user git, or a github or gitlab provider), which are not shells")
	export.Flags().StringArrayVar(&skip, "skip", nil, "leave out this alias (repeatable)")
	export.Flags().BoolVar(&open, "open", false, "macOS: open Termius and show the file in Finder")
	cmd.AddCommand(export, newTermiusKeysCmd())
	return cmd
}

// reportTermius says what was left out and what the user still does in
// Termius: the CSV carries no keys, and the importer is a menu, not a command.
func reportTermius(w io.Writer, exp *renderer.TermiusExport, toStdout bool) {
	_, _ = fmt.Fprintf(w, "hosts: %d\n", len(exp.Keys))
	for _, s := range exp.Skipped {
		_, _ = fmt.Fprintf(w, "skipped: %s\n", s)
	}
	file := "the file above"
	if toStdout {
		file = "the file you saved"
	}
	_, _ = fmt.Fprintln(w, "\nIn Termius: Hosts > New Host (arrow) > Import > CSV, and choose "+file+".")
	if len(exp.Keys) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "The CSV carries no keys (Termius's importer has no key column). For each host below:")
	_, _ = fmt.Fprintln(w, "  sshmgr termius keys <HOST>   copies its private key and prints the Termius label;")
	_, _ = fmt.Fprintln(w, "  then Keychain > New Key: Label + paste into Private key > Save, pick it on the host, Continue & Save.")
	width := 0
	for _, k := range exp.Keys {
		width = max(width, len(k.Label))
	}
	for _, k := range exp.Keys {
		where := k.KeyFile
		if k.Agent != "" {
			where = "in 1Password (" + strings.TrimSuffix(filepath.Base(k.KeyFile), ".pub") + "): add it from 1Password, not from disk"
		}
		_, _ = fmt.Fprintf(w, "  %-*s  %s\n", width, k.Label, where)
	}
}
