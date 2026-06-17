// Package netcheck is the network reachability + VPN status probe, ported from
// util/net.py. Network actions can hang when a host sits behind a VPN that isn't
// connected; this gives a fast bounded reachability check and a best-effort VPN
// indicator so commands fail fast with an actionable message. stdlib only.
package netcheck

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// vpnPrefixes mark a tunnel/VPN interface. Heuristic; reachability to the host is
// the real signal.
var vpnPrefixes = []string{"wg", "tun", "tap", "ppp", "ipsec", "nordlynx", "proton",
	"tailscale", "ts", "gpd", "ovpn"}

var unreachableMarkers = []string{
	"connection refused", "connection timed out", "operation timed out",
	"could not resolve", "no route to host", "network is unreachable",
	"timed out after", "host is down", "connection reset",
	"connection closed by", "no address associated with hostname",
}

// TCPReachable is true if a TCP connection to host:port opens within timeout.
func TCPReachable(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// SSHReachable is true if the SSH layer on host:port responds within timeout - a
// stronger check than TCPReachable for VPN-gated hosts on HTTPS-style ports that
// accept TCP but never complete the SSH banner. A live server (even one that
// rejects auth) counts as reachable; a hang/refusal does not.
func SSHReachable(host string, port int, timeout time.Duration) bool {
	if _, err := exec.LookPath("ssh"); err != nil {
		return TCPReachable(host, port, timeout)
	}
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes",
		"-o", "ConnectTimeout="+strconv.Itoa(secs), "-o", "StrictHostKeyChecking=no",
		"-p", strconv.Itoa(port), "--", host, "true")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	_ = cmd.Run()
	errText := strings.ToLower(stderr.String())
	for _, m := range unreachableMarkers {
		if strings.Contains(errText, m) {
			return false
		}
	}
	return true
}

// vpnInterfacesFrom filters interface names to the tunnel/VPN-like ones. Pure, so
// it is unit-testable independent of the host's live interfaces.
func vpnInterfacesFrom(names []string) []string {
	set := map[string]bool{}
	for _, n := range names {
		for _, p := range vpnPrefixes {
			if strings.HasPrefix(n, p) {
				set[n] = true
				break
			}
		}
	}
	// macOS uses utunN for VPNs; utun0-2 are usually system services, so only a
	// higher-numbered utun is a meaningful hint.
	for _, n := range names {
		if strings.HasPrefix(n, "utun") {
			if suf := n[4:]; suf != "" && allDigits(suf) {
				if v, _ := strconv.Atoi(suf); v >= 3 {
					set[n] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func interfaceNames() ([]string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	return names, true
}

// VPNInterfaces is the live list of tunnel/VPN-like interfaces present.
func VPNInterfaces() []string {
	names, ok := interfaceNames()
	if !ok {
		return nil
	}
	return vpnInterfacesFrom(names)
}

// VPNActive is a heuristic: is a VPN/tunnel interface present? nil when
// undeterminable (mirrors Python's bool | None).
func VPNActive() *bool {
	names, ok := interfaceNames()
	if !ok {
		return nil
	}
	v := len(vpnInterfacesFrom(names)) > 0
	return &v
}

// NetStatus is the reachability of one host:port with a VPN-aware message.
type NetStatus struct {
	Host        string
	Port        int
	Reachable   bool
	RequiresVPN bool
	VPNName     string // "" == none
	VPNURL      string // "" == none
	VPN         *bool  // nil == undeterminable
}

// Icon is "online"/"offline".
func (s NetStatus) Icon() string {
	if s.Reachable {
		return "online"
	}
	return "offline"
}

// Message is the VPN-aware human message (mirrors NetStatus.message).
func (s NetStatus) Message() string {
	where := fmt.Sprintf("%s:%d", s.Host, s.Port)
	if s.Reachable {
		return where + " reachable"
	}
	vpnUp := s.VPN != nil && *s.VPN
	if s.RequiresVPN {
		named := ""
		if s.VPNName != "" {
			named = " (" + s.VPNName + ")"
		}
		at := ""
		if s.VPNURL != "" {
			at = " at " + s.VPNURL
		}
		tail := ""
		if !vpnUp {
			tail = "; no active VPN/tunnel detected"
		}
		return fmt.Sprintf("%s unreachable - this host requires a VPN%s; connect it%s and retry%s",
			where, named, at, tail)
	}
	hint := ""
	if !vpnUp {
		hint = " (or a VPN, if this host needs one)"
	}
	return fmt.Sprintf("%s unreachable - check your network connection%s", where, hint)
}

// Check returns reachability + VPN status for one host:port. ssh=true uses the
// bounded SSH-banner probe (deploy/rotate); the default TCP probe is faster.
func Check(host string, port int, requiresVPN bool, vpnName, vpnURL string, timeout time.Duration, ssh bool) NetStatus {
	reach := TCPReachable(host, port, timeout)
	if ssh {
		reach = SSHReachable(host, port, timeout)
	}
	return NetStatus{
		Host: host, Port: port, Reachable: reach, RequiresVPN: requiresVPN,
		VPNName: vpnName, VPNURL: vpnURL, VPN: VPNActive(),
	}
}
