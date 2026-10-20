// Package gitremote reads and switches a checkout's GitHub origin between the three transport
// modes: profile (git@github-<profile>:owner/repo.git), ssh (git@github.com:owner/repo.git) and
// https (https://github.com/owner/repo.git).
package gitremote

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// Git is the slice of git this package needs, so tests can stand in for the network.
type Git interface {
	Origin(dir string) (string, error)
	LsRemote(dir, url string) error
	SetOrigin(dir, url string) error
}

// Remote is a parsed GitHub origin.
type Remote struct {
	URL     string
	Mode    string // profile, ssh or https
	Owner   string
	Repo    string
	Profile string // profile mode: the profile whose alias it uses
}

var (
	httpsRe  = regexp.MustCompile(`^https?://(?:[^@/]+@)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)
	sshURLRe = regexp.MustCompile(`^ssh://git@([^/:]+)(?::\d+)?/([^/]+)/([^/]+?)(?:\.git)?/?$`)
	scpRe    = regexp.MustCompile(`^git@([^:]+):([^/]+)/([^/]+?)(?:\.git)?/?$`)
)

// Parse recognises a GitHub origin. ok is false for anything else, which callers leave alone.
func Parse(m *manifest.Manifest, url string) (Remote, bool) {
	if g := httpsRe.FindStringSubmatch(url); g != nil {
		return Remote{URL: url, Mode: manifest.GitModeHTTPS, Owner: g[1], Repo: g[2]}, true
	}
	host, owner, repo := "", "", ""
	if g := sshURLRe.FindStringSubmatch(url); g != nil {
		host, owner, repo = g[1], g[2], g[3]
	} else if g := scpRe.FindStringSubmatch(url); g != nil {
		host, owner, repo = g[1], g[2], g[3]
	} else {
		return Remote{}, false
	}
	if strings.EqualFold(host, "github.com") {
		return Remote{URL: url, Mode: manifest.GitModeSSH, Owner: owner, Repo: repo}, true
	}
	for _, name := range m.ProfileNames() {
		for _, h := range m.Profiles[name].Hosts {
			if h.Alias == host && strings.EqualFold(h.Hostname, "github.com") {
				return Remote{URL: url, Mode: manifest.GitModeProfile, Owner: owner, Repo: repo, Profile: name}, true
			}
		}
	}
	return Remote{}, false
}

// URLFor builds the origin URL for owner/repo in mode. Profile mode needs a profile with a
// github.com host; ssh mode needs defaults.git.profile, whose key `Host github.com` uses.
func URLFor(m *manifest.Manifest, mode, owner, repo, profile string) (string, error) {
	switch mode {
	case manifest.GitModeHTTPS:
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo), nil
	case manifest.GitModeSSH:
		if m.Defaults.Git == nil || m.Defaults.Git.Profile == "" {
			return "", fmt.Errorf("ssh mode needs defaults.git.profile: its key is what Host github.com uses")
		}
		return fmt.Sprintf("git@github.com:%s/%s.git", owner, repo), nil
	case manifest.GitModeProfile:
		h, ok := manifest.GitHubHostOf(m, profile)
		if !ok {
			return "", fmt.Errorf("profile %q has no github.com host to use as an alias", profile)
		}
		return fmt.Sprintf("git@%s:%s/%s.git", h.Alias, owner, repo), nil
	}
	return "", fmt.Errorf("unknown mode %q (want one of %s)", mode, strings.Join(manifest.GitModes, ", "))
}

// Change is what `use` did, or would do, to one checkout.
type Change struct {
	Dir, From, To string
	Applied       bool
	Skipped       string // why nothing changed; empty when it changed or would
}

// Use points dir's origin at mode. The new URL is proven with ls-remote before origin is
// rewritten, so a checkout never ends up with a remote it cannot authenticate to.
func Use(g Git, m *manifest.Manifest, dir, mode, profile string, dryRun bool) (Change, error) {
	ch := Change{Dir: dir}
	url, err := g.Origin(dir)
	if err != nil {
		ch.Skipped = "no origin (not a git checkout, or no remote named origin)"
		return ch, nil
	}
	ch.From = url
	r, ok := Parse(m, url)
	if !ok {
		ch.Skipped = "origin is not a GitHub remote sshmgr manages"
		return ch, nil
	}
	if profile == "" {
		if profile, err = manifest.ProfileForOwner(m, r.Owner); err != nil && mode == manifest.GitModeProfile {
			return ch, err
		}
	}
	to, err := URLFor(m, mode, r.Owner, r.Repo, profile)
	if err != nil {
		return ch, err
	}
	ch.To = to
	if to == url {
		ch.Skipped = "already " + mode
		return ch, nil
	}
	if dryRun {
		return ch, nil
	}
	if err := g.LsRemote(dir, to); err != nil {
		return ch, fmt.Errorf("%s: %s does not authenticate, origin left as %s: %v", dir, to, url, err)
	}
	if err := g.SetOrigin(dir, to); err != nil {
		return ch, err
	}
	ch.Applied = true
	return ch, nil
}

// Exec is Git through the git binary.
type Exec struct{}

func (Exec) run(dir string, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	// Never stop to ask: a prompt in a batch over many checkouts would hang it. A user's own
	// GIT_SSH_COMMAND is respected.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if os.Getenv("GIT_SSH_COMMAND") == "" {
		cmd.Env = append(cmd.Env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, lastLine(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (e Exec) Origin(dir string) (string, error) {
	return e.run(dir, 10*time.Second, "remote", "get-url", "origin")
}

func (e Exec) LsRemote(dir, url string) error {
	_, err := e.run(dir, 45*time.Second, "ls-remote", "--heads", "--", url)
	return err
}

func (e Exec) SetOrigin(dir, url string) error {
	_, err := e.run(dir, 10*time.Second, "remote", "set-url", "origin", url)
	return err
}
