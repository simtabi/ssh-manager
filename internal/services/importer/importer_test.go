package importer

import "testing"

func find(hosts []*ParsedHost, alias string) *ParsedHost {
	for _, h := range hosts {
		if h.Alias == alias {
			return h
		}
	}
	return nil
}

func TestParseSSHConfig(t *testing.T) {
	cfg := `# a comment
Host gh
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    ProxyCommand /bin/danger
    ServerAliveInterval 60
Host db web
    HostName 10.0.0.9
    Port 2200
    IdentityFile ~/.ssh/profiles/work/work_db-ed25519
Host *
    Compression yes
Match host foo
    User nobody
`
	hosts := parseSSHConfig(cfg, "", map[string]bool{})

	// Wildcard "*" is skipped; gh, db, web remain (3).
	if len(hosts) != 3 {
		t.Fatalf("parsed %d hosts want 3 (wildcard skipped): %v", len(hosts), hosts)
	}
	gh := find(hosts, "gh")
	if gh == nil || gh.Hostname != "github.com" || gh.User != "git" || gh.Port != 22 {
		t.Fatalf("gh = %+v", gh)
	}
	if gh.IdentityFile != "~/.ssh/id_ed25519" || gh.Profile != "imported" {
		t.Errorf("gh identity/profile = %q / %q", gh.IdentityFile, gh.Profile)
	}
	// ProxyCommand dropped (dangerous); ServerAliveInterval carried as a raw option.
	if len(gh.Extra) != 1 || gh.Extra[0].Key != "serveraliveinterval" || gh.Extra[0].Val != "60" {
		t.Errorf("gh extra = %+v (ProxyCommand should be dropped)", gh.Extra)
	}
	// Multi-alias "Host db web": both get the block's options + the profiles/ profile.
	db, web := find(hosts, "db"), find(hosts, "web")
	if db == nil || web == nil || db.Port != 2200 || web.Port != 2200 {
		t.Fatalf("db/web = %+v / %+v", db, web)
	}
	if db.Profile != "work" || web.Profile != "work" {
		t.Errorf("profile from IdentityFile = %q / %q want work", db.Profile, web.Profile)
	}
}

func TestInferProviderAndProfileFromIdentity(t *testing.T) {
	if p := inferProvider("github.com"); p == nil || *p != "github" {
		t.Errorf("github.com -> %v want github", p)
	}
	if p := inferProvider("GitLab.com"); p == nil || *p != "gitlab" {
		t.Errorf("case-insensitive gitlab failed: %v", p)
	}
	if p := inferProvider("example.com"); p != nil {
		t.Errorf("unknown host should infer no provider, got %v", *p)
	}
	if got := profileFromIdentity("~/.ssh/profiles/simtabi/k"); got != "simtabi" {
		t.Errorf("profileFromIdentity = %q want simtabi", got)
	}
	if got := profileFromIdentity("~/.ssh/id_ed25519"); got != "imported" {
		t.Errorf("profileFromIdentity = %q want imported", got)
	}
}
