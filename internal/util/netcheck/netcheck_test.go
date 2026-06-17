package netcheck

import (
	"net"
	"reflect"
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
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if !TCPReachable("127.0.0.1", port, 2*time.Second) {
		t.Error("open listener should be reachable")
	}
	ln.Close()
	if TCPReachable("127.0.0.1", port, 500*time.Millisecond) {
		t.Error("closed port should be unreachable")
	}
}
