package renderer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A raw_option for a keyword the managed lines already set used to be written
// after them, where ssh - which keeps the first value it obtains - ignored it.
// The config then carried two values for one keyword and the reader could not
// tell which applied. Now the block carries exactly one: the managed one.
func TestRawOptionsNeverDuplicateAManagedLine(t *testing.T) {
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[
	    {"alias":"srv","hostname":"srv.example","user":"deploy","port":2222,
	     "raw_options":{"UserKnownHostsFile":"~/.ssh/known_hosts_work","HostName":"old.example",
	       "user":"root","Port":"2200","IdentityFile":"~/.ssh/other","ForwardAgent":"no"}}]}}}`)
	got, err := RenderRootConfig(m, false)
	if err != nil {
		t.Fatal(err)
	}
	for kw, want := range map[string]string{
		"HostName":           "srv.example",
		"User":               "deploy",
		"Port":               "2222",
		"IdentityFile":       "~/.ssh/profiles/work/work_srv-ed25519",
		"UserKnownHostsFile": "~/.ssh/known_hosts",
	} {
		if n := countKeyword(got, kw); n != 1 {
			t.Errorf("%s appears %d times in the host block, want 1:\n%s", kw, n, got)
		}
		if !strings.Contains(got, "    "+kw+" "+want+"\n") {
			t.Errorf("%s should be the managed value %q:\n%s", kw, want, got)
		}
	}
	if !strings.Contains(got, "    ForwardAgent no\n") {
		t.Errorf("an option sshmgr does not manage must still render:\n%s", got)
	}
	assertSSHResolves(t, got, "srv", map[string][]string{
		"hostname":           {"srv.example"},
		"user":               {"deploy"},
		"port":               {"2222"},
		"identityfile":       {"~/.ssh/profiles/work/work_srv-ed25519"},
		"userknownhostsfile": {"~/.ssh/known_hosts"},
	})
}

// The renderer writes no Port line for the default port, so a raw Port is the
// only value ssh sees and has always applied. Dropping it would move the host
// to port 22 without a word; it stays (doctor asks for it to move to "port").
func TestARawPortStillAppliesWhenThePortFieldIsUnset(t *testing.T) {
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[
	    {"alias":"srv","hostname":"srv.example","user":"deploy","raw_options":{"Port":"2200"}}]}}}`)
	got, err := RenderRootConfig(m, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := countKeyword(got, "Port"); n != 1 {
		t.Errorf("Port appears %d times, want 1:\n%s", n, got)
	}
	assertSSHResolves(t, got, "srv", map[string][]string{"port": {"2200"}})
}

// countKeyword counts the indented option lines for kw (case-insensitive, as
// ssh reads keywords) across the whole rendered text.
func countKeyword(cfg, kw string) int {
	n := 0
	for _, ln := range strings.Split(cfg, "\n") {
		if !strings.HasPrefix(ln, "    ") {
			continue
		}
		k, _, _ := strings.Cut(strings.TrimSpace(ln), " ")
		if strings.EqualFold(k, kw) {
			n++
		}
	}
	return n
}

// assertSSHResolves runs the real `ssh -G` over cfg and checks every value it
// resolves for each keyword - all of them, so a list keyword like IdentityFile
// carrying a stray second entry fails too.
func assertSSHResolves(t *testing.T, cfg, alias string, want map[string][]string) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not on PATH")
	}
	f := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(f, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh", "-G", "-F", f, alias).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G: %v\n%s", err, out)
	}
	got := map[string][]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(ln, " ")
		if ok {
			got[k] = append(got[k], v)
		}
	}
	// ssh -G prints some paths with ~ expanded and others as written.
	home, _ := os.UserHomeDir()
	norm := func(vs []string) string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = strings.Replace(v, "~/", home+"/", 1)
		}
		return strings.Join(out, "|")
	}
	for kw, vals := range want {
		if norm(got[kw]) != norm(vals) {
			t.Errorf("ssh -G %s resolves %s = %q, want %q", alias, kw, got[kw], vals)
		}
	}
}
