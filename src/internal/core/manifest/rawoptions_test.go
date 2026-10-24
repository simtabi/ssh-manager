package manifest

import (
	"strings"
	"testing"
)

// The importer carries every option it does not parse into raw_options, so a
// manifest imported before this check existed can hold UserKnownHostsFile (and
// a hand-edited one HostName, User or Port). Such a manifest
// loads today, and refusing it now would lock the user out of every command
// until they edited JSON by hand. It still loads; the overlap is reported.
func TestRawOptionsThatDuplicateAManagedFieldStillLoadAndAreReported(t *testing.T) {
	m, err := loadJSON(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[
	    {"alias":"srv","hostname":"srv.example","user":"deploy",
	     "raw_options":{"UserKnownHostsFile":"~/.ssh/known_hosts_work","ForwardAgent":"no",
	       "hostname":"old.example","Port":"2200"}},
	    {"alias":"clean","hostname":"c.example","user":"u","raw_options":{"ForwardAgent":"no"}}]}}}`)
	if err != nil {
		t.Fatalf("a manifest that loaded before must still load: %v", err)
	}
	got := RawOptionOverlaps(m)
	if len(got) != 3 {
		t.Fatalf("overlaps = %q, want one per duplicated keyword (3)", got)
	}
	for _, want := range []string{
		`work/srv: raw_options "UserKnownHostsFile"`,
		`work/srv: raw_options "hostname"`,
		`work/srv: raw_options "Port"`,
	} {
		found := false
		for _, g := range got {
			found = found || strings.HasPrefix(g, want)
		}
		if !found {
			t.Errorf("no overlap reported starting %q in %q", want, got)
		}
	}
	// Each message names what to set instead, so the fix needs no lookup.
	for _, g := range got {
		if !strings.Contains(g, "instead") {
			t.Errorf("overlap %q does not say what to use instead", g)
		}
	}
}

func TestManagedHostOptionIsCaseInsensitiveAndLeavesOthersAlone(t *testing.T) {
	for _, k := range []string{"HostName", "hostname", "USER", "Port", "UserKnownHostsFile"} {
		if _, ok := ManagedHostOption(k); !ok {
			t.Errorf("%s is set by the managed lines of every host block", k)
		}
	}
	// IdentitiesOnly and IdentityAgent are deliberate per-host overrides, and
	// ProxyJump/ForwardAgent are never emitted by the renderer.
	// IdentityFile is a list ssh tries in order, so a raw one adds a key rather
	// than being ignored.
	for _, k := range []string{"IdentitiesOnly", "IdentityAgent", "IdentityFile", "ProxyJump", "ForwardAgent"} {
		if _, ok := ManagedHostOption(k); ok {
			t.Errorf("%s is not a managed line; raw_options may set it", k)
		}
	}
}
