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

// Status returns reachability for every manifest host, filtered by selector: an
// alias, a profile, a "profile/key" reference, or a bare key name.
//
// A bare key name matches in every profile that has one, and says so by
// reporting the profile on each row. Key names are unique per profile, not
// globally, so "imani_github-ed25519" is a legitimate name in several of them -
// the composite form is there for when you mean exactly one.
func Status(m *manifest.Manifest, selector string) ([]HostNet, error) {
	rks, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	var out []HostNet
	for _, rk := range rks {
		h := rk.Host
		ref := manifest.KeyRef{Profile: rk.Profile, KeyName: rk.KeyName}
		if selector != "" && selector != h.Alias && selector != rk.Profile &&
			selector != rk.KeyName && selector != ref.String() {
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
