package netstat

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

// Parity reference: python-final:src/ssh_manager/services/facade.py:1066-1078
// (network_status). One row per manifest host, filtered by selector, each
// carrying the profile that owns it.
//
// Probes go to loopback so they resolve immediately: an open port for
// reachable, a closed one for refused. Pointing at an unroutable address would
// make every row wait out the 4s timeout.

// openPort returns a port with something listening on it, closed at test end.
func openPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port nothing is listening on, so a connection is refused
// rather than timing out.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// fixture builds a manifest with two profiles: work has two hosts sharing one
// key name, personal has one whose key name repeats work's - the case a bare
// key selector has to handle.
func fixture(t *testing.T, up, down int) *manifest.Manifest {
	t.Helper()
	raw := fmt.Sprintf(`{
	  "version": 1,
	  "defaults": {"key_type": "ed25519"},
	  "profiles": {
	    "work": {"key_scope": "per_service", "hosts": [
	      {"alias": "up", "hostname": "127.0.0.1", "user": "u", "port": %d, "key_name": "shared-ed25519"},
	      {"alias": "down", "hostname": "127.0.0.1", "user": "u", "port": %d, "key_name": "work_only-ed25519"}
	    ]},
	    "personal": {"key_scope": "per_service", "hosts": [
	      {"alias": "mine", "hostname": "127.0.0.1", "user": "u", "port": %d, "key_name": "shared-ed25519"}
	    ]}
	  }
	}`, up, down, up)
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func aliases(rows []HostNet) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Alias)
	}
	return out
}

func TestStatusProbesEveryHostAndReportsItsProfile(t *testing.T) {
	up, down := openPort(t), closedPort(t)
	rows, err := Status(fixture(t, up, down), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want one per host: %v", len(rows), aliases(rows))
	}

	byAlias := map[string]HostNet{}
	for _, r := range rows {
		byAlias[r.Alias] = r
	}
	if !byAlias["up"].Status.Reachable {
		t.Error("a port with a listener should be reachable")
	}
	if byAlias["down"].Status.Reachable {
		t.Error("a closed port should not be reachable")
	}
	if byAlias["up"].Profile != "work" || byAlias["mine"].Profile != "personal" {
		t.Errorf("rows must carry their owning profile: %+v", rows)
	}
	if byAlias["up"].Status.Host != "127.0.0.1" || byAlias["up"].Status.Port != up {
		t.Errorf("status should record what was probed: %+v", byAlias["up"].Status)
	}
}

func TestSelectorFilters(t *testing.T) {
	up, down := openPort(t), closedPort(t)
	m := fixture(t, up, down)

	cases := map[string][]string{
		"":                       {"up", "down", "mine"}, // manifest order
		"up":                     {"up"},                 // host alias
		"work":                   {"up", "down"},         // profile
		"work_only-ed25519":      {"down"},               // key name, unique
		"work/work_only-ed25519": {"down"},               // composite
		"nosuchthing":            nil,                    // no match is empty, not an error
	}
	for selector, want := range cases {
		rows, err := Status(m, selector)
		if err != nil {
			t.Errorf("selector %q: %v", selector, err)
			continue
		}
		got := aliases(rows)
		if len(got) != len(want) {
			t.Errorf("selector %q -> %v, want %v", selector, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("selector %q -> %v, want %v", selector, got, want)
				break
			}
		}
	}
}

// A bare key name is only unique inside a profile. "shared-ed25519" exists in
// both, so it matches both - and each row names its profile, which is the only
// thing that makes the output readable. The composite form is how you mean one.
func TestBareKeyNameMatchesEveryProfileThatHasIt(t *testing.T) {
	up, down := openPort(t), closedPort(t)
	m := fixture(t, up, down)

	rows, err := Status(m, "shared-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("bare name matched %v, want both profiles' hosts", aliases(rows))
	}
	profiles := map[string]bool{}
	for _, r := range rows {
		profiles[r.Profile] = true
	}
	if !profiles["work"] || !profiles["personal"] {
		t.Errorf("both owning profiles should appear: %+v", rows)
	}

	// The composite form narrows it to exactly one.
	rows, err = Status(m, "personal/shared-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Alias != "mine" {
		t.Errorf("composite selector -> %v, want just personal's host", aliases(rows))
	}
}

// A host flagged requires_vpn carries that through to the status, so the caller
// can explain an unreachable host rather than just reporting it down.
func TestVPNMetadataIsCarriedThrough(t *testing.T) {
	raw := fmt.Sprintf(`{
	  "version": 1, "defaults": {"key_type": "ed25519"},
	  "profiles": {"work": {"key_scope": "per_service", "hosts": [
	    {"alias": "gated", "hostname": "127.0.0.1", "user": "u", "port": %d,
	     "requires_vpn": true, "vpn_name": "UNC VPN", "vpn_url": "https://vpn.unc.edu"}
	  ]}}
	}`, closedPort(t))
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	rows, err := Status(&m, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	st := rows[0].Status
	if !st.RequiresVPN || st.VPNName != "UNC VPN" || st.VPNURL != "https://vpn.unc.edu" {
		t.Errorf("VPN metadata lost: %+v", st)
	}
	if msg := st.Message(); msg == "" {
		t.Error("a gated host should produce an explanatory message")
	}
}

// A manifest that cannot resolve its keys is an error, not a partial list -
// silently probing the hosts it could resolve would under-report.
func TestUnresolvableManifestIsAnError(t *testing.T) {
	// shared scope with no key_name: ResolvedKeyName cannot answer.
	const raw = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "broken":{"key_scope":"shared","hosts":[{"alias":"h","hostname":"127.0.0.1","user":"u"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(&m, ""); err == nil {
		t.Error("an unresolvable manifest should error rather than return a partial list")
	}
}
