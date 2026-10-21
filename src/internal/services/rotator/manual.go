package rotator

import (
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/providers"
)

// ManualStep is asked, for each target whose provider can only take a pasted key (a web panel such
// as Ploi), to show the staged public key and where it goes, and to report whether it is now in
// place. The CLI sets one only when there is a terminal to ask at; without one, rotate behaves as it
// always has.
type ManualStep func(alias, where, pubkey string) bool

// WithManualStep sets the manual step and returns the Rotator.
func (r *Rotator) WithManualStep(step ManualStep) *Rotator {
	r.manual = step
	return r
}

// panelProof reports whether a provider category's hosts are servers a staged key can be proven on
// by logging in. A git host refuses a shell even for a valid key, so an SSH login proves nothing
// there; only panel providers (Ploi and the like, whose targets are servers) qualify.
func panelProof(category string) bool { return category == "panel" }

// proveManual turns a manual deploy into a verified one: the key is pasted while sshmgr waits, then
// proven by logging in with the staged key itself. It returns verified unchanged when the provider
// verified on its own, when the deploy was not manual, when no manual step is set, or when the
// provider is not a panel.
func (r *Rotator) proveManual(h manifest.Host, prov providers.Provider, out providers.DeployOutcome,
	tgt providers.Target, verified bool) bool {
	if verified || out.Method != "manual" || r.manual == nil || !panelProof(prov.Category()) {
		return verified
	}
	if !r.manual(h.Alias, out.Detail, tgt.PubkeyText) {
		return false
	}
	return r.sshVerify(tgt)
}

// defaultSSHVerify logs in with the target's identity and runs `true`, as the generic SSH provider
// verifies its own deploys.
func defaultSSHVerify(t providers.Target) bool { return providers.GenericSSH{}.Verify(t) }
