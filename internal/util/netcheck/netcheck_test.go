package netcheck

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

func TestMessageAndIcon(t *testing.T) {
	cases := []struct {
		name     string
		s        NetStatus
		wantIcon string
		wantMsg  string
	}{
		{
			"reachable",
			NetStatus{Host: "h", Port: 22, Reachable: true},
			"online", "h:22 reachable",
		},
		{
			"vpn-required, named+url, no tunnel",
			NetStatus{Host: "h", Port: 443, RequiresVPN: true, VPNName: "Corp", VPNURL: "https://vpn", VPN: nil},
			"offline",
			"h:443 unreachable - this host requires a VPN (Corp); connect it at https://vpn and retry; no active VPN/tunnel detected",
		},
		{
			"vpn-required, tunnel up -> no tail",
			NetStatus{Host: "h", Port: 443, RequiresVPN: true, VPN: boolp(true)},
			"offline",
			"h:443 unreachable - this host requires a VPN; connect it and retry",
		},
		{
			"plain unreachable, undeterminable vpn -> hint",
			NetStatus{Host: "h", Port: 80, VPN: nil},
			"offline",
			"h:80 unreachable - check your network connection (or a VPN, if this host needs one)",
		},
		{
			"plain unreachable, tunnel up -> no hint",
			NetStatus{Host: "h", Port: 80, VPN: boolp(true)},
			"offline",
			"h:80 unreachable - check your network connection",
		},
	}
	for _, c := range cases {
		if got := c.s.Icon(); got != c.wantIcon {
			t.Errorf("%s: icon=%q want %q", c.name, got, c.wantIcon)
		}
		if got := c.s.Message(); got != c.wantMsg {
			t.Errorf("%s: message=\n  %q\nwant\n  %q", c.name, got, c.wantMsg)
		}
	}
}

func TestVPNInterfaceFilter(t *testing.T) {
	names := []string{"en0", "lo0", "wg0", "tun3", "tap0", "utun1", "utun4", "tailscale0", "ts0", "ppp0", "utun"}
	want := []string{"ppp0", "tailscale0", "tap0", "ts0", "tun3", "utun4", "wg0"}
	if got := vpnInterfacesFrom(names); !reflect.DeepEqual(got, want) {
		t.Errorf("vpnInterfacesFrom=%v want %v", got, want)
	}
}

func TestTCPReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback")
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	if !TCPReachable("127.0.0.1", port, 2*time.Second) {
		t.Error("open listener should be reachable")
	}
	_ = ln.Close()
	if TCPReachable("127.0.0.1", port, 500*time.Millisecond) {
		t.Error("closed port should be unreachable")
	}
}

// stubSSH puts a fake ssh first on PATH that writes body to stderr and exits
// with code. SSHReachable's whole decision is made by reading that stderr, and
// it is the check that gates deploy and rotate.
func stubSSH(t *testing.T, body string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub is a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' " + shQuote(body) + " >&2\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// The probe is deliberately asymmetric: only a recognised failure counts as
// unreachable, and anything else - including an auth rejection - counts as
// reachable, because a server that refuses your key is a server that is there.
// Reading it the other way round would block deploys against every host whose
// error text is not in the list.
func TestSSHReachableTreatsOnlyKnownFailuresAsUnreachable(t *testing.T) {
	unreachable := []string{
		"ssh: connect to host box port 22: Connection refused",
		"ssh: connect to host box port 22: Operation timed out",
		"ssh: Could not resolve hostname box: nodename nor servname provided",
		"ssh: connect to host box port 22: No route to host",
		"ssh: connect to host box port 22: Network is unreachable",
		"Connection closed by 10.0.0.2 port 22",
		"kex_exchange_identification: read: Connection reset by peer",
		"ssh: connect to host box port 22: Host is down",
	}
	for _, msg := range unreachable {
		t.Run(msg[:20], func(t *testing.T) {
			stubSSH(t, msg, 255)
			if SSHReachable("box", 22, time.Second) {
				t.Errorf("%q should read as unreachable", msg)
			}
		})
	}

	// A live server that rejects the key is reachable: the point of the probe is
	// "can I get there", not "am I allowed in".
	t.Run("permission denied", func(t *testing.T) {
		stubSSH(t, "git@github.com: Permission denied (publickey).", 255)
		if !SSHReachable("github.com", 22, time.Second) {
			t.Error("an auth rejection means the server answered; that is reachable")
		}
	})
	// So is a clean success.
	t.Run("success", func(t *testing.T) {
		stubSSH(t, "", 0)
		if !SSHReachable("box", 22, time.Second) {
			t.Error("a successful connection should be reachable")
		}
	})
	// An error nobody has seen before is treated as reachable, so an unfamiliar
	// message degrades to "try the deploy and let it report", not "refuse".
	t.Run("unrecognised", func(t *testing.T) {
		stubSSH(t, "ssh: something entirely new went wrong", 255)
		if !SSHReachable("box", 22, time.Second) {
			t.Error("an unrecognised failure should not block the operation")
		}
	})
	// Matching is case-insensitive: the same condition is capitalised
	// differently across OpenSSH versions and platforms.
	t.Run("case", func(t *testing.T) {
		stubSSH(t, "SSH: CONNECT TO HOST BOX PORT 22: CONNECTION REFUSED", 255)
		if SSHReachable("box", 22, time.Second) {
			t.Error("marker matching should not depend on case")
		}
	})
}

// Windows OpenSSH is optional and a minimal container may have no client at all.
// With no ssh on PATH the probe falls back to a plain TCP connect rather than
// reporting every host unreachable.
func TestSSHReachableFallsBackToTCPWithNoSSHClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH emptying is not enough to hide ssh.exe reliably")
	}
	t.Setenv("PATH", t.TempDir()) // nothing on PATH at all

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	if !SSHReachable(host, port, time.Second) {
		t.Error("with no ssh client, a listening port should still read as reachable")
	}

	// And a closed port is still unreachable rather than reachable-by-default.
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if SSHReachable(host, port, 200*time.Millisecond) {
		t.Error("a closed port should be unreachable even on the fallback path")
	}
}
