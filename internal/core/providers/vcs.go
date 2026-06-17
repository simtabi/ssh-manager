package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/internal/util/secrets"
)

// runEnv runs argv with an overlaid env (nil = inherit), returning stdout, stderr,
// and the exit code (-1 on a non-exit failure).
func runEnv(timeout time.Duration, env []string, argv ...string) (string, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return stdout.String(), stderr.String(), code
}

func mergedEnv(overlay map[string]string) []string {
	env := os.Environ()
	for k, v := range overlay {
		env = append(env, k+"="+v)
	}
	return env
}

// parseKeyRows parses a JSON array of {id,key,title}-shaped objects.
func parseKeyRows(out string) []map[string]any {
	if strings.TrimSpace(out) == "" {
		out = "[]"
	}
	var rows []map[string]any
	if json.Unmarshal([]byte(out), &rows) != nil {
		return nil
	}
	return rows
}

func rowStr(row map[string]any, key string) string {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// --- GitHub (gh CLI) -------------------------------------------------------

// GitHub manages account keys via the gh CLI (github.com and GHES). Ports
// providers.github.GitHub.
type GitHub struct{ spec Spec }

func (g GitHub) Name() string {
	if g.spec.Name != "" {
		return g.spec.Name
	}
	return "github"
}
func (g GitHub) Category() string {
	if g.spec.Category != "" {
		return g.spec.Category
	}
	return "vcs"
}

func (g GitHub) host() string {
	if g.spec.Host != "" {
		return g.spec.Host
	}
	return "github.com"
}
func (g GitHub) isEnterprise() bool { return g.host() != "github.com" }

func (g GitHub) token(t Target) string {
	v := firstNonEmpty(t.TokenEnv, g.spec.TokenEnv, "GH_TOKEN")
	return secrets.Resolve(os.Getenv(v))
}

func (g GitHub) env(t Target) []string {
	token := g.token(t)
	if token == "" {
		return nil
	}
	overlay := map[string]string{"GH_HOST": g.host()}
	if g.isEnterprise() {
		overlay["GH_ENTERPRISE_TOKEN"] = token
	} else {
		overlay["GH_TOKEN"] = token
	}
	return mergedEnv(overlay)
}

func (g GitHub) canAPI(t Target) bool {
	if _, err := exec.LookPath("gh"); err != nil {
		return false
	}
	return g.token(t) != ""
}

func (g GitHub) listRemote(t Target) []map[string]any {
	out, _, code := runEnv(30*time.Second, g.env(t), "gh", "api", "--paginate", "user/keys")
	if code != 0 {
		return nil
	}
	return parseKeyRows(out)
}

func (g GitHub) Deploy(t Target) DeployOutcome {
	if !g.canAPI(t) {
		return manual(g.ManageURL(t), t)
	}
	want := authkeys.KeyBody(t.PubkeyText)
	rows := g.listRemote(t)
	if rows != nil && want != "" && hasKeyBody(rows, want) {
		return DeployOutcome{Method: "github-gh", Verified: true, Detail: "already present"}
	}
	title := "ssh-manager " + baseName(t.PubkeyPath)
	_, stderr, code := runEnv(30*time.Second, g.env(t), "gh", "ssh-key", "add", t.PubkeyPath, "--title", title)
	if code != 0 {
		return DeployOutcome{Method: "github-gh", Detail: strings.TrimSpace(stderr), Error: true}
	}
	return DeployOutcome{Method: "github-gh", Verified: true, Detail: "added as '" + title + "'"}
}

func (g GitHub) Verify(t Target) bool {
	if g.canAPI(t) {
		want := authkeys.KeyBody(t.PubkeyText)
		rows := g.listRemote(t)
		return rows != nil && want != "" && hasKeyBody(rows, want)
	}
	if t.IdentityPath == "" {
		return false
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return false
	}
	args := []string{"ssh", "-T", "-i", t.IdentityPath, "-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	if t.KnownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+t.KnownHosts)
	}
	args = append(args, "git@"+g.host())
	out, stderr, _ := runEnv(20*time.Second, nil, args...)
	return strings.Contains(strings.ToLower(stderr+out), "successfully authenticated")
}

func (g GitHub) ListDeployed(t Target) []string {
	if !g.canAPI(t) {
		return nil
	}
	return titles(g.listRemote(t))
}

func (g GitHub) Remove(t Target) bool {
	if !g.canAPI(t) {
		return false
	}
	return removeByBody(g.listRemote(t), authkeys.KeyBody(t.PubkeyText), func(id string) bool {
		_, _, code := runEnv(30*time.Second, g.env(t), "gh", "api", "--method", "DELETE", "user/keys/"+id)
		return code == 0
	})
}

func (GitHub) Rename(Target, string) bool { return false }

func (g GitHub) ManageURL(Target) string {
	if u := g.spec.ResolvedKeysURL(); u != "" {
		return u
	}
	return "https://" + g.host() + "/settings/keys"
}

// --- GitLab (glab CLI) -----------------------------------------------------

// GitLab manages account keys via the glab CLI. Ports providers.gitlab.GitLab.
type GitLab struct{ spec Spec }

func (g GitLab) Name() string {
	if g.spec.Name != "" {
		return g.spec.Name
	}
	return "gitlab"
}
func (g GitLab) Category() string {
	if g.spec.Category != "" {
		return g.spec.Category
	}
	return "vcs"
}

func (g GitLab) host() string {
	if g.spec.Host != "" {
		return g.spec.Host
	}
	return "gitlab.com"
}

func (g GitLab) token(t Target) string {
	v := firstNonEmpty(t.TokenEnv, g.spec.TokenEnv, "GLAB_TOKEN")
	return secrets.Resolve(os.Getenv(v))
}

func (g GitLab) env(t Target) []string {
	token := g.token(t)
	if token == "" {
		return nil
	}
	return mergedEnv(map[string]string{"GITLAB_TOKEN": token, "GITLAB_HOST": g.host()})
}

func (g GitLab) canAPI(t Target) bool {
	if _, err := exec.LookPath("glab"); err != nil {
		return false
	}
	return g.token(t) != ""
}

func (g GitLab) listRemote(t Target) []map[string]any {
	out, _, code := runEnv(30*time.Second, g.env(t), "glab", "api", "--paginate", "user/keys")
	if code != 0 {
		return nil
	}
	return parseKeyRows(out)
}

func (g GitLab) Deploy(t Target) DeployOutcome {
	if !g.canAPI(t) {
		return manual(g.ManageURL(t), t)
	}
	want := authkeys.KeyBody(t.PubkeyText)
	rows := g.listRemote(t)
	if rows != nil && want != "" && hasKeyBody(rows, want) {
		return DeployOutcome{Method: "gitlab-glab", Verified: true, Detail: "already present"}
	}
	title := "ssh-manager " + baseName(t.PubkeyPath)
	_, stderr, code := runEnv(30*time.Second, g.env(t), "glab", "ssh-key", "add", t.PubkeyPath, "--title", title)
	if code != 0 {
		return DeployOutcome{Method: "gitlab-glab", Detail: strings.TrimSpace(stderr), Error: true}
	}
	return DeployOutcome{Method: "gitlab-glab", Verified: true, Detail: "added as '" + title + "'"}
}

func (g GitLab) Verify(t Target) bool {
	if !g.canAPI(t) {
		return false
	}
	want := authkeys.KeyBody(t.PubkeyText)
	rows := g.listRemote(t)
	return rows != nil && want != "" && hasKeyBody(rows, want)
}

func (g GitLab) ListDeployed(t Target) []string {
	if !g.canAPI(t) {
		return nil
	}
	return titles(g.listRemote(t))
}

func (g GitLab) Remove(t Target) bool {
	if !g.canAPI(t) {
		return false
	}
	return removeByBody(g.listRemote(t), authkeys.KeyBody(t.PubkeyText), func(id string) bool {
		_, _, code := runEnv(30*time.Second, g.env(t), "glab", "api", "--method", "DELETE", "user/keys/"+id)
		return code == 0
	})
}

func (GitLab) Rename(Target, string) bool { return false }

func (g GitLab) ManageURL(Target) string {
	if u := g.spec.ResolvedKeysURL(); u != "" {
		return u
	}
	return "https://" + g.host() + "/-/user_settings/ssh_keys"
}

// --- shared VCS helpers ----------------------------------------------------

func hasKeyBody(rows []map[string]any, want string) bool {
	for _, r := range rows {
		if authkeys.KeyBody(rowStr(r, "key")) == want {
			return true
		}
	}
	return false
}

func titles(rows []map[string]any) []string {
	if len(rows) == 0 {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowStr(r, "title"))
	}
	return out
}

// removeByBody deletes every row whose key body matches want, via del(id).
// Returns true if any delete succeeded. id comes from the row's "id" field.
func removeByBody(rows []map[string]any, want string, del func(id string) bool) bool {
	if rows == nil || want == "" {
		return false
	}
	ok := false
	for _, r := range rows {
		if authkeys.KeyBody(rowStr(r, "key")) != want {
			continue
		}
		id := jsonID(r["id"])
		if id == "" {
			continue
		}
		if del(id) {
			ok = true
		}
	}
	return ok
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
