// Package deployer installs a key's public half on its target(s) and records the
// deployment, ported from services/deployer.py. A key name maps to the host(s)
// that reference it (one per_service, many shared); each host's provider does the
// install (named adapter -> generic ssh -> manual) and the result is recorded in
// the inventory keyed by fingerprint.
package deployer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/core/providers"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/util/netcheck"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// DeployRecord is one target's deploy outcome.
type DeployRecord struct {
	Target   string
	Provider string
	Method   string
	Verified bool
	Detail   string
	Error    bool
}

// DeployReport summarizes a deploy run.
type DeployReport struct {
	KeyName     string
	Fingerprint string
	Records     []DeployRecord
}

// Format renders the deploy summary (mirrors DeployReport.format).
func (r DeployReport) Format() string {
	lines := []string{fmt.Sprintf("deploy %s  (%s)", r.KeyName, r.Fingerprint)}
	for _, rec := range r.Records {
		flag := "MANUAL/needs-redeploy"
		if rec.Verified {
			flag = "verified"
		}
		lines = append(lines, fmt.Sprintf("  -> %s via %s/%s: %s", rec.Target, rec.Provider, rec.Method, flag))
		if rec.Detail != "" {
			lines = append(lines, "     "+rec.Detail)
		}
	}
	return strings.Join(lines, "\n")
}

// AnyError reports whether any target's deploy was attempted and failed.
func (r DeployReport) AnyError() bool {
	for _, rec := range r.Records {
		if rec.Error {
			return true
		}
	}
	return false
}

// Deployer deploys keys to their targets.
type Deployer struct {
	p   paths.Paths
	m   *manifest.Manifest
	inv *inventory.Inventory
	ks  *keystore.KeyStore
}

// New builds a Deployer.
func New(p paths.Paths, m *manifest.Manifest, inv *inventory.Inventory) *Deployer {
	return &Deployer{p: p, m: m, inv: inv, ks: keystore.New()}
}

// Deploy installs key keyName on its target(s) (all hosts using it, or just
// targetAlias) and records each deployment. Mirrors Deployer.deploy.
func (d *Deployer) Deploy(keyName, targetAlias string) (DeployReport, error) {
	hosts, profile, err := d.targets(keyName, targetAlias)
	if err != nil {
		return DeployReport{}, err
	}
	pub := filepath.Join(d.p.SSHDir, "profiles", profile, keyName+".pub")
	if _, err := os.Stat(pub); err != nil {
		return DeployReport{}, fmt.Errorf("public key not found: %s - run `sshmgr reconcile` first", pub)
	}
	fp, err := d.ks.Fingerprint(pub)
	if err != nil {
		return DeployReport{}, err
	}
	pubText := ""
	if b, err := os.ReadFile(pub); err == nil {
		pubText = string(b)
	}
	fpKey := d.ensureRecord(fp, profile, keyName)
	rec := d.inv.Keys[fpKey]

	report := DeployReport{KeyName: keyName, Fingerprint: fp}
	knownHosts := filepath.Join(d.p.SSHDir, "profiles", profile, "known_hosts")
	for _, host := range hosts {
		provider := providers.Resolve(deref(host.Provider), d.p.Providers())
		if provider.Category() == "server" {
			st := netcheck.Check(host.Hostname, host.Port, host.RequiresVPN, deref(host.VPNName), deref(host.VPNURL), 4*time.Second, true)
			if !st.Reachable {
				recordDeployment(&rec, host.Alias, "unreachable", false)
				report.Records = append(report.Records, DeployRecord{
					Target: host.Alias, Provider: provider.Name(), Method: "unreachable",
					Verified: false, Detail: st.Message(), Error: true,
				})
				continue
			}
		}
		tgt := providers.Target{
			Alias: host.Alias, Hostname: host.Hostname, User: host.User, Port: host.Port,
			PubkeyPath: pub, PubkeyText: pubText, TokenEnv: deref(host.TokenEnv),
			KnownHosts: knownHosts,
		}
		outcome := provider.Deploy(tgt)
		recordDeployment(&rec, host.Alias, outcome.Method, outcome.Verified)
		report.Records = append(report.Records, DeployRecord{
			Target: host.Alias, Provider: provider.Name(), Method: outcome.Method,
			Verified: outcome.Verified, Detail: outcome.Detail, Error: outcome.Error,
		})
	}
	d.inv.Keys[fpKey] = rec
	return report, nil
}

func (d *Deployer) targets(keyName, targetAlias string) ([]manifest.Host, string, error) {
	rks, err := d.m.IterResolved()
	if err != nil {
		return nil, "", err
	}
	var using []manifest.Host
	profile := ""
	for _, rk := range rks {
		if rk.KeyName == keyName {
			using = append(using, rk.Host)
			if profile == "" {
				profile = rk.Profile
			}
		}
	}
	if len(using) == 0 {
		return nil, "", fmt.Errorf("no host in the manifest uses key %q", keyName)
	}
	if targetAlias == "" {
		return using, profile, nil
	}
	var chosen []manifest.Host
	var aliases []string
	for _, h := range using {
		aliases = append(aliases, h.Alias)
		if h.Alias == targetAlias {
			chosen = append(chosen, h)
		}
	}
	if len(chosen) == 0 {
		return nil, "", fmt.Errorf("host %q does not use key %q (it's used by: %s)", targetAlias, keyName, strings.Join(aliases, ", "))
	}
	return chosen, profile, nil
}

// ensureRecord makes sure an inventory record exists for fp, with pydantic
// defaults (type ed25519, rotate 365), and returns the fingerprint key.
func (d *Deployer) ensureRecord(fp, profile, keyName string) string {
	if _, ok := d.inv.Keys[fp]; !ok {
		d.inv.Record(fp, inventory.KeyRecord{
			Profile: profile, Path: d.m.IdentityFile(profile, keyName),
			Type: "ed25519", RotateAfterDays: 365,
		})
	}
	return fp
}

// recordDeployment replaces any existing entry for target with a fresh one.
func recordDeployment(rec *inventory.KeyRecord, target, method string, verified bool) {
	kept := rec.Deployments[:0:0]
	for _, dep := range rec.Deployments {
		if dep.Target != target {
			kept = append(kept, dep)
		}
	}
	date := inventory.Today()
	kept = append(kept, inventory.Deployment{Target: target, Method: method, Date: &date, Verified: verified})
	rec.Deployments = kept
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
