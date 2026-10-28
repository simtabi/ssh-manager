package renderer

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// ExportPaths is what an export needs to turn the ~ form paths the managed
// config uses into absolute ones: the SSH directory ~/.ssh stands for, and the
// home directory any other ~/ path is relative to. They differ under
// --ssh-dir, which is why the home is not derived from the SSH directory.
type ExportPaths struct {
	SSHDir string
	Home   string
}

// ExportPathsFor is the ExportPaths for sshDir: the user's home, or the SSH
// directory's parent when there is no home to read.
func ExportPathsFor(sshDir string) ExportPaths {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = filepath.Dir(sshDir)
	}
	return ExportPaths{SSHDir: sshDir, Home: home}
}

// expand makes a ~ form path absolute. Anything else is returned unchanged.
func (p ExportPaths) expand(v string) string {
	switch {
	case v == "~/.ssh" || strings.HasPrefix(v, "~/.ssh/"):
		return p.SSHDir + strings.TrimPrefix(v, "~/.ssh")
	case strings.HasPrefix(v, "~/"):
		return p.Home + strings.TrimPrefix(v, "~")
	}
	return v
}

func (p ExportPaths) expandHost(h RenderHost) RenderHost {
	h.IdentityFile = p.expand(h.IdentityFile)
	h.IdentityAgent = p.expand(h.IdentityAgent)
	h.KnownHosts = p.expand(h.KnownHosts)
	if h.RawOptions.Len() > 0 {
		pairs := make([][2]string, 0, h.RawOptions.Len())
		for _, k := range h.RawOptions.Keys() {
			pairs = append(pairs, [2]string{k, p.expand(h.RawOptions.Get(k))})
		}
		h.RawOptions = manifest.NewOrderedOptions(pairs)
	}
	return h
}

// FlatHeader opens a flat export. It is deliberately not the managed header:
// sshmgr owns the files it renders under ~/.ssh, and a copy of an export
// carrying that header would be treated as one of them.
const FlatHeader = "# ssh-manager flat export - every host inline, absolute paths, no Include.\n" +
	"# Generated from the manifest by `sshmgr config export --flat`; ssh does not read this file\n" +
	"# unless you point it here. Edit the manifest, not this copy, and export again.\n"

// RenderFlatConfig renders the whole managed config as one self-contained
// file, for tools that read a single ssh_config and do not follow Include or
// Match (Termius's importer is one). Every profile's hosts are inline in
// manifest order, whatever their category, followed by the git ssh-mode block
// and Host * last, exactly as the split render orders them. Every ~ path is
// made absolute, so the file means the same wherever it is copied.
//
// It is an export, never written over a file `config render` owns.
func RenderFlatConfig(m *manifest.Manifest, p ExportPaths, emitUseKeychain bool) (string, error) {
	byProfile, err := hostsByProfile(m)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(FlatHeader + "\n")
	for _, pname := range m.ProfileNames() {
		hosts := byProfile[pname]
		for i := range hosts {
			hosts[i] = p.expandHost(hosts[i])
		}
		writeProfile(&b, pname, hosts)
	}
	gh, err := gitHubBlock(m)
	if err != nil {
		return "", err
	}
	if gh != nil {
		b.WriteString(gitBanner(m.Defaults.Git.Profile) + "\n")
		writeHostBlock(&b, p.expandHost(*gh))
	}
	writeGlobalBlock(&b, m.Defaults.GlobalOptions, emitUseKeychain)
	return b.String(), nil
}

// TermiusColumns is the header of Termius's CSV import template, as the
// third-party exporters written against it reproduce it (Termius 9.x). Termius
// publishes the template only as a download inside the app, so this is the
// one place to change if it moves.
var TermiusColumns = []string{"Groups", "Label", "Tags", "Hostname/IP", "Protocol", "Port", "Username", "Password"}

// TermiusKey is one key the user attaches in Termius by hand: the CSV carries
// no keys, and Termius imports them into its own keychain, not by path.
type TermiusKey struct {
	Label   string // the host's alias, its Termius label
	KeyFile string // absolute path of the key ssh would use
	Agent   string // non-empty when the key lives in 1Password, not on disk
}

// TermiusExport is a rendered Termius import: the CSV, the keys to attach, and
// the hosts left out with the reason for each.
type TermiusExport struct {
	CSV     string
	Keys    []TermiusKey
	Skipped []string
}

// RenderTermiusCSV renders the manifest's hosts as a Termius CSV import, one
// row per host Termius can reach: group = profile, label = alias, tags = the
// host's tags. Two kinds are left out and reported:
//
//   - VM hosts, which are reached only through sshmgr's ProxyCommand, which
//     Termius ignores (its docs say so), so a row would be a dead host;
//   - git hosts (user git, or a github or gitlab provider), which are not
//     shells, unless IncludeGit is set;
//   - any alias named in Skip.
//
// No password is ever written: the column is part of the template and stays
// empty.
func RenderTermiusCSV(m *manifest.Manifest, p ExportPaths, opts TermiusOptions) (*TermiusExport, error) {
	resolved, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(TermiusColumns); err != nil {
		return nil, err
	}
	exp := &TermiusExport{}
	skip := map[string]bool{}
	for _, a := range opts.Skip {
		skip[a] = true
	}
	for _, rk := range resolved {
		h := rk.Host
		switch {
		case skip[h.Alias]:
			exp.Skipped = append(exp.Skipped, h.Alias+": --skip")
			delete(skip, h.Alias)
			continue
		case h.VM != nil:
			exp.Skipped = append(exp.Skipped, h.Alias+": a VM host is reached through a ProxyCommand, which Termius ignores")
			continue
		case h.Proxy != nil:
			exp.Skipped = append(exp.Skipped, h.Alias+": reached through "+h.Proxy.Kind+
				" (a ProxyCommand), which Termius ignores; connect with ssh instead")
			continue
		case isGitHost(h) && !opts.IncludeGit:
			exp.Skipped = append(exp.Skipped, h.Alias+": a git host, not a shell (export it with --include-git)")
			continue
		}
		port := h.Port
		if port == 0 {
			port = 22
		}
		row := []string{
			cell(rk.Profile), cell(h.Alias), termiusTags(h.Tags),
			cell(h.Hostname), "ssh", strconv.Itoa(port), cell(h.User), "",
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
		file, agent := identityFor(m, rk.Profile, rk.KeyName)
		exp.Keys = append(exp.Keys, TermiusKey{Label: h.Alias, KeyFile: p.expand(file), Agent: p.expand(agent)})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	if len(skip) > 0 {
		var unknown []string
		for a := range skip {
			unknown = append(unknown, a)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("--skip names no host: %s", strings.Join(unknown, ", "))
	}
	exp.CSV = buf.String()
	return exp, nil
}

// TermiusOptions narrows a Termius export.
type TermiusOptions struct {
	IncludeGit bool     // also export git hosts
	Skip       []string // aliases to leave out
}

// gitProviders are the providers whose hosts are git endpoints, not shells.
var gitProviders = map[string]bool{"github": true, "gitlab": true}

// isGitHost reports a host that serves git rather than a shell: the git user
// every forge uses, or a forge provider whatever user it sets.
func isGitHost(h manifest.Host) bool {
	return h.User == "git" || (h.Provider != nil && gitProviders[*h.Provider])
}

// termiusTags joins a host's tags into one field. A comma inside a tag would
// read back as two tags, so it becomes a space.
func termiusTags(tags []string) string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, cell(strings.ReplaceAll(t, ",", " ")))
	}
	return strings.Join(out, ",")
}

// cell neutralises a value a spreadsheet would evaluate as a formula. The CSV
// is meant for Termius, but a CSV is opened in a spreadsheet often enough that
// one free-text field starting with = must not become a live formula there.
func cell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
