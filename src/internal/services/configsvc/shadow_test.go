package configsvc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const shadowManifest = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
  "work":{"key_scope":"per_service","hosts":[
    {"alias":"srv","hostname":"new.example","user":"deploy"},
    {"alias":"db","hostname":"db.example","user":"deploy"}]}}}`

// writeWithPreamble puts foreign content in ~/.ssh/config, then renders the
// managed block under it, as `sshmgr import ~/.ssh/config` and a render leave it.
func writeWithPreamble(t *testing.T, foreign string) (*Service, string) {
	t.Helper()
	ssh := t.TempDir()
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(ssh, load(t, shadowManifest), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	return svc, ssh
}

// The onboarding path keeps the user's own Host blocks above the managed block.
// ssh keeps the first value it finds, so those blocks win for every keyword they
// set: the manifest says new.example, ssh connects to old.example, and check
// used to call that in sync because every managed byte matched.
func TestCheckReportsAForeignBlockShadowingAManagedAlias(t *testing.T) {
	const foreign = "# my old config\nHost srv\n    HostName old.example\n    User deploy\n\n"
	svc, ssh := writeWithPreamble(t, foreign)

	if _, err := exec.LookPath("ssh"); err == nil {
		out, err := exec.Command("ssh", "-G", "-F", filepath.Join(ssh, "config"), "srv").CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "\nhostname old.example\n") {
			t.Fatalf("premise: ssh should resolve the foreign block's hostname:\n%s", out)
		}
	}

	res := mustCheck(t, svc)
	if res.InSync() {
		t.Fatal("a shadowed managed alias must not be reported in sync")
	}
	if !res.BlockInSync() {
		t.Error("the managed block itself matches the manifest; only the shadowing is wrong")
	}
	if len(res.Shadowed) != 1 {
		t.Fatalf("shadowed = %+v, want exactly srv", res.Shadowed)
	}
	sh := res.Shadowed[0]
	if sh.Alias != "srv" || sh.Line != 2 {
		t.Errorf("shadow = %+v, want alias srv at line 2", sh)
	}
	f := res.Format()
	for _, want := range []string{"SHADOWED", "srv", "config:2 (Host srv)", "HostName", "User"} {
		if !strings.Contains(f, want) {
			t.Errorf("report lacks %q:\n%s", want, f)
		}
	}
	// Rendering again cannot fix content sshmgr does not own, so the report
	// must not send the user there.
	if strings.Contains(f, "run: sshmgr config render") {
		t.Errorf("report points at render, which would not help:\n%s", f)
	}
	// And check never touches the user's content.
	body, _ := os.ReadFile(filepath.Join(ssh, "config"))
	if !strings.HasPrefix(string(body), foreign) {
		t.Errorf("the foreign block moved or changed:\n%s", body)
	}
}

func TestShadowMatchingFollowsSSHPatternRules(t *testing.T) {
	cases := []struct {
		name    string
		foreign string
		want    []string // shadowed aliases, sorted within a block
	}{
		{"wildcard", "Host s?v d*\n    HostName x\n", []string{"db", "srv"}},
		{"negation excludes", "Host * !srv\n    User root\n", []string{"db"}},
		{"case and equals", "host=SRV srv\n    hostname x\n", []string{"srv"}},
		{"top-level option applies to every host", "User root\n\nHost other\n    HostName y\n", []string{"db", "srv"}},
		// A block that sets nothing the managed block sets overrides nothing.
		{"no shared keyword", "Host *\n    ServerAliveInterval 30\n", nil},
		{"other alias", "Host srv2 legacy\n    HostName x\n", nil},
		// A Match condition sshmgr does not evaluate is left alone rather than guessed at.
		{"match block", "Match host srv\n    HostName x\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := writeWithPreamble(t, tc.foreign+"\n")
			var got []string
			for _, s := range mustCheck(t, svc).Shadowed {
				got = append(got, s.Alias)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("shadowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// Content below the managed block is read after it, so the managed values win
// there and nothing is shadowed.
func TestForeignBlocksBelowTheManagedBlockShadowNothing(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, shadowManifest), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(ssh, "config")
	body, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, append(body, []byte("\nHost srv\n    HostName old.example\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	res := mustCheck(t, svc)
	if len(res.Shadowed) != 0 || !res.InSync() {
		t.Errorf("trailer content cannot shadow: shadowed=%+v in sync=%v", res.Shadowed, res.InSync())
	}
}
