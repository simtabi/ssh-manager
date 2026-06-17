// Package agent adds keys to the ssh-agent (macOS keychain), ported from
// services/agent.py + facade.load. ssh-add runs interactively so a passphrase
// prompt can be answered.
package agent

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
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
	args := []string{}
	if a.useKeychain {
		args = append(args, "--apple-use-keychain")
	}
	args = append(args, keyPath)
	cmd := exec.Command("ssh-add", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run() == nil
}

// Load adds a profile's keys to the agent and returns the key names added. A
// shared key mapped to many hosts is added once. add is the per-key action
// (Agent.Add in production; injectable for tests). Mirrors facade.load.
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
