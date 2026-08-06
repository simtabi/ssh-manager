// Package agent adds keys to the ssh-agent (macOS keychain), ported from
// services/agent.py + facade.load. ssh-add runs interactively so a passphrase
// prompt can be answered.
package agent

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// Agent adds private keys to the running ssh-agent.
type Agent struct {
	useKeychain bool
}

// New builds an Agent. useKeychain adds --apple-use-keychain (macOS).
func New(useKeychain bool) *Agent { return &Agent{useKeychain: useKeychain} }

// Add adds one private key to the agent, interactively (so a passphrase prompt is
// answerable). Returns true on success. Mirrors agent.Agent.add.
func (a *Agent) Add(keyPath string) bool {
	if _, err := exec.LookPath("ssh-add"); err != nil {
		return false
	}
	cmd := exec.Command("ssh-add", sshAddArgs(a.useKeychain, keyPath)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run() == nil
}

// sshAddArgs is the ssh-add argv, kept out of Add so it can be tested without a
// running agent. --apple-use-keychain stores the passphrase in the login
// keychain and exists only on macOS; passing it elsewhere makes ssh-add reject
// the whole invocation, so the key would silently never be added.
func sshAddArgs(useKeychain bool, keyPath string) []string {
	args := []string{}
	if useKeychain {
		args = append(args, "--apple-use-keychain")
	}
	// The path goes last and unquoted: it is an argv element, never a shell word.
	return append(args, keyPath)
}

// Load adds a profile's keys to the agent and returns the key names added. A
// shared key mapped to many hosts is added once. add is the per-key action
// (Agent.Add in production; injectable for tests). Mirrors facade.load.
//
// Resolved hosts, not KeyRefs - deliberately, and unlike reconcile/validate/
// keyaudit, which all walk KeyRefs so a declared-but-unwired key is not
// overlooked. An agent holds keys for connections; a key no host uses serves no
// connection, so loading it would put an identity in the agent that is offered
// to every server the user then talks to.
func Load(m *manifest.Manifest, sshDir, profile string, add func(string) bool) ([]string, error) {
	rks, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	var added []string
	seen := map[string]bool{}
	for _, rk := range rks {
		if rk.Profile != profile {
			continue
		}
		priv := filepath.Join(sshDir, "profiles", rk.Profile, rk.KeyName)
		if seen[priv] {
			continue
		}
		seen[priv] = true
		if fileExists(priv) && add(priv) {
			added = append(added, rk.KeyName)
		}
	}
	return added, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
