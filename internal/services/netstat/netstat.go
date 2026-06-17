// Package netstat reports per-host network reachability for the `net` verb,
// ported from facade.network_status. Read-only: a fast TCP probe per manifest
// host, with a VPN-aware status message.
package netstat

import (
	"time"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/netcheck"
)

const probeTimeout = 4 * time.Second

// HostNet is one host's reachability (mirrors facade.HostNet).
type HostNet struct {
	Profile string
	Alias   string
	Status  netcheck.NetStatus
}

// Status returns reachability for every manifest host, filtered by selector
// (alias, profile, or key name; empty for all). Mirrors facade.network_status.
func Status(m *manifest.Manifest, selector string) ([]HostNet, error) {
	rks, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	var out []HostNet
	for _, rk := range rks {
		h := rk.Host
		if selector != "" && selector != h.Alias && selector != rk.Profile && selector != rk.KeyName {
			continue
		}
		st := netcheck.Check(h.Hostname, h.Port, h.RequiresVPN, deref(h.VPNName), deref(h.VPNURL), probeTimeout, false)
		out = append(out, HostNet{Profile: rk.Profile, Alias: h.Alias, Status: st})
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
