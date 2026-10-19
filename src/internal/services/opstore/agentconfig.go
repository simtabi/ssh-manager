package opstore

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The vaults the 1Password SSH agent serves when there is no agent.toml
// (checked against 1password.dev/ssh/agent/config, 2026-10-19).
var defaultAgentVaults = map[string]bool{"personal": true, "private": true, "employee": true}

// AgentConfigPath is where the 1Password SSH agent reads agent.toml:
// $XDG_CONFIG_HOME/1Password/ssh/agent.toml when XDG_CONFIG_HOME is set, else
// ~/.config/1Password/ssh/agent.toml (on Windows,
// %LOCALAPPDATA%/1Password/config/ssh/agent.toml).
func AgentConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "1Password", "config", "ssh", "agent.toml")
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "1Password", "ssh", "agent.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "1Password", "ssh", "agent.toml")
}

// AgentServesVault reports whether the 1Password SSH agent offers every key in
// vault, and if not, what to change. Every key in the vault matters, not just
// today's: a rotation's .staged item has to be served to be verified.
//
// With no agent.toml the agent serves only the default vaults. Once the file
// exists it serves only what the file lists - even an empty file overrides the
// default - so the vault then needs its own whole-vault entry.
func AgentServesVault(vault, configPath string) (bool, string) {
	entry := fmt.Sprintf("[[ssh-keys]]\nvault = %q", vault)
	f, err := os.Open(configPath)
	if err != nil {
		if defaultAgentVaults[strings.ToLower(vault)] {
			return true, ""
		}
		return false, fmt.Sprintf("the 1Password SSH agent serves only the Personal, Private and "+
			"Employee vaults by default, so keys in vault %q are never offered to ssh; add\n%s\nto %s",
			vault, indent(entry), configPath)
	}
	defer func() { _ = f.Close() }()
	itemsOnly := false
	for _, e := range parseAgentConfig(f) {
		if !strings.EqualFold(e["vault"], vault) {
			continue
		}
		if e["item"] == "" {
			return true, ""
		}
		itemsOnly = true
	}
	if itemsOnly {
		return false, fmt.Sprintf("%s lists single items from vault %q but not the whole vault, so a "+
			"rotation's staged key is never offered and cannot be verified; add\n%s", configPath, vault, indent(entry))
	}
	return false, fmt.Sprintf("%s exists, so the agent serves only what it lists, and vault %q is not "+
		"listed; add\n%s", configPath, vault, indent(entry))
}

func indent(s string) string { return "    " + strings.ReplaceAll(s, "\n", "\n    ") }

// parseAgentConfig reads the [[ssh-keys]] entries of an agent.toml as key/value
// maps. It understands only what the file uses - array-of-tables headers,
// key = "string" pairs, and comments - which is all the agent accepts.
func parseAgentConfig(f *os.File) []map[string]string {
	var entries []map[string]string
	var cur map[string]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			cur = nil
			if strings.TrimSpace(strings.Trim(line, "[]")) == "ssh-keys" {
				cur = map[string]string{}
				entries = append(entries, cur)
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || cur == nil {
			continue
		}
		val = strings.TrimSpace(val)
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		cur[strings.TrimSpace(key)] = strings.Trim(val, `"'`)
	}
	return entries
}
