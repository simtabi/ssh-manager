package renderer

import (
	"encoding/csv"
	"strings"
	"testing"
)

var testExportPaths = ExportPaths{SSHDir: "/home/u/.ssh", Home: "/home/u"}

const exportJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "git": {"mode": "ssh", "profile": "personal"}},
  "profiles": {
    "personal": {"category": "internal", "hosts": [
      {"alias": "github-imani", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]},
    "legacy": {"hosts": [
      {"alias": "box", "hostname": "box.example", "user": "me", "port": 2222, "key_name": "legacy-ed25519", "tags": ["prod", "eu,west"]}]},
    "simtabi": {"category": "orgs", "hosts": [
      {"alias": "oribi-web", "hostname": "143.198.186.131", "user": "ploi", "key_name": "simtabi_oribi-web-ed25519"},
      {"alias": "devbox", "hostname": "devbox", "user": "imani", "key_name": "simtabi_devbox-ed25519",
       "vm": {"hypervisor": "vmpal", "name": "Ubuntu"}}]}
  }
}`

// The flat export is the whole managed config in one file: every host inline,
// whatever its category, with no Include or Match for a reader that does not
// follow them, and every path absolute so it means the same thing wherever the
// file is copied.
func TestFlatConfigInlinesEveryHostWithAbsolutePaths(t *testing.T) {
	m := mustManifest(t, exportJSON)
	out, err := RenderFlatConfig(m, testExportPaths, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"github-imani", "box", "oribi-web", "devbox"} {
		if !strings.Contains(out, "Host "+alias+"\n") {
			t.Errorf("flat export lacks Host %s:\n%s", alias, out)
		}
	}
	for _, banned := range []string{"Include ", "Match ", "~/"} {
		if strings.Contains(out, banned) {
			t.Errorf("flat export contains %q:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "IdentityFile /home/u/.ssh/profiles/orgs/simtabi/simtabi_oribi-web-ed25519\n") {
		t.Errorf("IdentityFile is not the absolute key path:\n%s", out)
	}
	if !strings.Contains(out, "UserKnownHostsFile /home/u/.ssh/known_hosts\n") {
		t.Errorf("UserKnownHostsFile is not absolute:\n%s", out)
	}
	if !strings.Contains(out, "Host github.com\n") {
		t.Errorf("the git ssh-mode block is part of the config and belongs in the export:\n%s", out)
	}
	if i, j := strings.LastIndex(out, "Host oribi-web"), strings.Index(out, "Host *"); j < 0 || j < i {
		t.Errorf("Host * must come last, or its values override every host's:\n%s", out)
	}
	if IsManagedFile(out) {
		t.Error("the export must not carry the managed header: sshmgr would then treat a copy as a file it owns")
	}
}

// The export renders from the manifest, the same source as `config render`, so
// it must agree with what render puts in the split files host for host.
func TestFlatConfigAgreesWithTheSplitRender(t *testing.T) {
	m := mustManifest(t, exportJSON)
	flat, err := RenderFlatConfig(m, testExportPaths, false)
	if err != nil {
		t.Fatal(err)
	}
	split, err := RenderAll(m, false)
	if err != nil {
		t.Fatal(err)
	}
	for rel, text := range split {
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(line, "Host ") {
				continue
			}
			if !strings.Contains(flat, line+"\n") {
				t.Errorf("%s renders %q, which the flat export lacks", rel, line)
			}
		}
	}
}

// A manifest with no hosts still exports a valid file: the header and Host *.
func TestFlatConfigOfAnEmptyManifest(t *testing.T) {
	m := mustManifest(t, `{"version":1,"profiles":{}}`)
	out, err := RenderFlatConfig(m, testExportPaths, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Host *\n") || strings.Contains(out, "Host github") {
		t.Errorf("unexpected empty export:\n%s", out)
	}
}

func parseCSV(t *testing.T, text string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(text)).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v\n%s", err, text)
	}
	return rows
}

// The Termius CSV: the column layout of Termius's import template, one row per
// host it can use, group = profile, label = alias.
func TestTermiusCSVRowsAndSkips(t *testing.T) {
	m := mustManifest(t, exportJSON)
	exp, err := RenderTermiusCSV(m, testExportPaths, TermiusOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rows := parseCSV(t, exp.CSV)
	if got := strings.Join(rows[0], ","); got != strings.Join(TermiusColumns, ",") {
		t.Fatalf("header = %q", got)
	}
	byLabel := map[string][]string{}
	for _, r := range rows[1:] {
		byLabel[r[1]] = r
	}
	if len(byLabel) != 2 {
		t.Fatalf("want box and oribi-web only, got %v", rows[1:])
	}
	box := byLabel["box"]
	if box[0] != "legacy" || box[3] != "box.example" || box[4] != "ssh" || box[5] != "2222" || box[6] != "me" || box[7] != "" {
		t.Errorf("box row = %q", box)
	}
	if box[2] != "prod,eu west" {
		t.Errorf("tags = %q: a comma inside one tag must not split it into two", box[2])
	}
	if web := byLabel["oribi-web"]; web[0] != "simtabi" || web[5] != "22" || web[6] != "ploi" {
		t.Errorf("oribi-web row = %q", web)
	}

	skipped := strings.Join(exp.Skipped, "\n")
	if !strings.Contains(skipped, "github-imani") || !strings.Contains(skipped, "devbox") {
		t.Errorf("git and VM hosts should be reported as skipped: %v", exp.Skipped)
	}
	if len(exp.Keys) != 2 || exp.Keys[0].Label != "box" ||
		exp.Keys[0].KeyFile != "/home/u/.ssh/profiles/legacy/legacy-ed25519" {
		t.Errorf("keys to attach = %+v", exp.Keys)
	}
}

// --include-git adds the git hosts; a VM host stays out, because Termius drops
// the ProxyCommand that is its only route.
func TestTermiusCSVIncludeGit(t *testing.T) {
	m := mustManifest(t, exportJSON)
	exp, err := RenderTermiusCSV(m, testExportPaths, TermiusOptions{IncludeGit: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exp.CSV, "github-imani") {
		t.Errorf("--include-git should export the git host:\n%s", exp.CSV)
	}
	if strings.Contains(exp.CSV, "devbox") {
		t.Errorf("a VM host has no route in Termius and must stay out:\n%s", exp.CSV)
	}
}

// A field that a spreadsheet would run as a formula is neutralised: hostnames
// and aliases are validated, but tags are free text.
func TestTermiusCSVNeutralisesFormulaCells(t *testing.T) {
	m := mustManifest(t, `{"version":1,"profiles":{"p":{"hosts":[
		{"alias":"a","hostname":"a.example","user":"u","tags":["=HYPERLINK(1)","@x","+1","-2"]}]}}}`)
	exp, err := RenderTermiusCSV(m, testExportPaths, TermiusOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tags := parseCSV(t, exp.CSV)[1][2]
	for _, part := range strings.Split(tags, ",") {
		if strings.ContainsAny(part[:1], "=@+-") {
			t.Errorf("tag %q would be evaluated as a formula", part)
		}
	}
}

// A forge provider marks a git host even when its user is not git, and --skip
// leaves out a named host; a --skip that names nothing is an error rather than
// a silently ignored typo.
func TestTermiusCSVGitProviderAndSkip(t *testing.T) {
	m := mustManifest(t, `{"version":1,"profiles":{"p":{"hosts":[
		{"alias":"forge","hostname":"git.example","user":"gl","provider":"gitlab"},
		{"alias":"keep","hostname":"keep.example","user":"u"},
		{"alias":"drop","hostname":"drop.example","user":"u"}]}}}`)
	exp, err := RenderTermiusCSV(m, testExportPaths, TermiusOptions{Skip: []string{"drop"}})
	if err != nil {
		t.Fatal(err)
	}
	rows := parseCSV(t, exp.CSV)
	if len(rows) != 2 || rows[1][1] != "keep" {
		t.Errorf("want only keep, got %v", rows[1:])
	}
	if _, err := RenderTermiusCSV(m, testExportPaths, TermiusOptions{Skip: []string{"nope"}}); err == nil ||
		!strings.Contains(err.Error(), "nope") {
		t.Errorf("an unknown --skip alias should be an error naming it: %v", err)
	}
}
