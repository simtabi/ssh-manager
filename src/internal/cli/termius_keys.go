package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
)

// Termius's CSV import has no key column (docs.termius.com, "Import existing
// hosts"): keys go into its Keychain (New Key: Label + Private key paste, or
// Import from key file) and are then picked on each host. `termius keys`
// prepares exactly those two values: the label to type and the private key on
// the clipboard, never on the screen unless --print asks for it.

// clipboardWrite puts text on the system clipboard; tests swap it so they
// never touch the real one.
var clipboardWrite = systemClipboardWrite

// clipboardSleep waits before --clear-after clears; tests swap it.
var clipboardSleep = time.Sleep

func stubClipboard(f func(string) error) (restore func()) {
	prev, prevSleep := clipboardWrite, clipboardSleep
	clipboardWrite = f
	clipboardSleep = func(time.Duration) {}
	return func() { clipboardWrite, clipboardSleep = prev, prevSleep }
}

// clipboardCommand picks the platform's clipboard writer: pbcopy on macOS,
// clip on Windows, and wl-copy, xclip or xsel on Linux and the BSDs.
func clipboardCommand() (string, []string, error) {
	switch {
	case platform.IsMacOS():
		return "pbcopy", nil, nil
	case platform.IsWindows():
		return "clip", nil, nil
	}
	cands := [][]string{
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
	}
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		cands = append([][]string{{"wl-copy"}}, cands...)
	}
	for _, c := range cands {
		if _, err := exec.LookPath(c[0]); err == nil {
			return c[0], c[1:], nil
		}
	}
	return "", nil, errors.New("no clipboard tool found (install wl-clipboard, xclip or xsel), or use --print")
}

func systemClipboardWrite(text string) error {
	name, args, err := clipboardCommand()
	if err != nil {
		return err
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// termiusKeyLabel is the label to give the key in Termius: the key file's
// basename (adelsaiq_dani-prd-db-00-ed25519), so the keychain entry says which
// file it came from.
func termiusKeyLabel(k renderer.TermiusKey) string {
	return strings.TrimSuffix(filepath.Base(k.KeyFile), ".pub")
}

func privateKeyPath(k renderer.TermiusKey) string { return strings.TrimSuffix(k.KeyFile, ".pub") }

func newTermiusKeysCmd() *cobra.Command {
	var includeGit, printKey, clear bool
	var clearAfter time.Duration
	cmd := &cobra.Command{
		Use:   "keys [ALIAS]",
		Short: "List the Termius key label for each host, or copy one host's private key to the clipboard",
		Long: "The Termius CSV carries no keys: each one is added in Termius under Keychain > New Key\n" +
			"(Label + Private key) and then chosen on the host. With no ALIAS this lists every\n" +
			"exported host with the label to use and the key file. With an ALIAS it copies that\n" +
			"host's private key to the clipboard (pbcopy, wl-copy/xclip/xsel, or clip) and prints\n" +
			"the label; the key itself is never printed unless --print is given.",
		Example: "  sshmgr termius keys\n" +
			"  sshmgr termius keys dani-prd-db-00 --clear-after 60s\n" +
			"  sshmgr termius keys --clear",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			if clear {
				if len(args) > 0 || printKey {
					return errors.New("--clear takes no ALIAS and no --print")
				}
				if err := clipboardWrite(""); err != nil {
					return err
				}
				_, _ = fmt.Fprintln(out, "clipboard cleared")
				return nil
			}
			p, m, _, err := loadExport(c)
			if err != nil {
				return err
			}
			exp, err := renderer.RenderTermiusCSV(m, exportPaths(p), renderer.TermiusOptions{IncludeGit: includeGit})
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if printKey || clearAfter > 0 {
					return errors.New("--print and --clear-after need an ALIAS")
				}
				listTermiusKeys(out, exp.Keys)
				return nil
			}
			var key *renderer.TermiusKey
			for i := range exp.Keys {
				if exp.Keys[i].Label == args[0] {
					key = &exp.Keys[i]
				}
			}
			if key == nil {
				return fmt.Errorf("no exported host %q (git hosts need --include-git; see `sshmgr termius keys`)", args[0])
			}
			if key.Agent != "" {
				return fmt.Errorf("%s uses a key in 1Password; add it to Termius from 1Password, there is no file to copy", args[0])
			}
			path := privateKeyPath(*key)
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read private key: %w", err)
			}
			if !strings.Contains(string(b), "PRIVATE KEY") {
				return fmt.Errorf("%s does not look like a private key", path)
			}
			label := termiusKeyLabel(*key)
			if printKey {
				_, _ = fmt.Fprintln(c.ErrOrStderr(), "warning: printing a PRIVATE key; it may stay in your terminal scrollback and history")
				_, err := fmt.Fprint(out, string(b))
				return err
			}
			if err := clipboardWrite(string(b)); err != nil {
				return fmt.Errorf("copy to clipboard: %w", err)
			}
			_, _ = fmt.Fprintf(out, "host:  %s\nlabel: %s\nkey:   %s\n\n", key.Label, label, path)
			_, _ = fmt.Fprintln(out, "The private key is on your clipboard (not shown). In Termius: Keychain > New Key,\n"+
				"Label = the label above, click Private key and paste, leave Certificate empty, Save.\n"+
				"Then on the host's SSH key selection pick that key and click Continue & Save.")
			if clearAfter > 0 {
				_, _ = fmt.Fprintf(out, "\nclearing the clipboard in %s (Ctrl-C keeps it; then run `sshmgr termius keys --clear`)...\n", clearAfter)
				clipboardSleep(clearAfter)
				if err := clipboardWrite(""); err != nil {
					return err
				}
				_, _ = fmt.Fprintln(out, "clipboard cleared")
			} else {
				_, _ = fmt.Fprintln(out, "\nWhen done: sshmgr termius keys --clear")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&includeGit, "include-git", false, "also list git hosts, as `termius export --include-git` does")
	cmd.Flags().BoolVar(&printKey, "print", false, "print the private key to stdout instead of copying it (warns on stderr)")
	cmd.Flags().BoolVar(&clear, "clear", false, "empty the clipboard and exit")
	cmd.Flags().DurationVar(&clearAfter, "clear-after", 0, "after copying, wait this long (e.g. 60s) and empty the clipboard")
	return cmd
}

func listTermiusKeys(w io.Writer, keys []renderer.TermiusKey) {
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(w, "no hosts to export")
		return
	}
	aw, lw := len("HOST"), len("TERMIUS LABEL")
	for _, k := range keys {
		aw, lw = max(aw, len(k.Label)), max(lw, len(termiusKeyLabel(k)))
	}
	_, _ = fmt.Fprintf(w, "%-*s  %-*s  %s\n", aw, "HOST", lw, "TERMIUS LABEL", "PRIVATE KEY")
	for _, k := range keys {
		where := privateKeyPath(k)
		if k.Agent != "" {
			where = "in 1Password: add it from 1Password"
		}
		_, _ = fmt.Fprintf(w, "%-*s  %-*s  %s\n", aw, k.Label, lw, termiusKeyLabel(k), where)
	}
	_, _ = fmt.Fprintln(w, "\nCopy one host's key and label: sshmgr termius keys <HOST>")
}
