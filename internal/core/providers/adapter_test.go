package providers

import "testing"

func TestResolveRouting(t *testing.T) {
	cases := []struct {
		name         string
		wantName     string
		wantCategory string
		wantManage   string
	}{
		{"github", "github", "vcs", "https://github.com/settings/keys"},
		{"gitlab", "gitlab", "vcs", "https://gitlab.com/-/user_settings/ssh_keys"},
		{"generic-ssh", "generic-ssh", "server", ""},
		{"digitalocean", "digitalocean", "vps", "https://cloud.digitalocean.com/account/security"},
		{"ploi", "ploi", "panel", "https://ploi.io/servers"},
		{"bitbucket", "bitbucket", "vcs", "https://bitbucket.org/account/settings/ssh-keys/"}, // catalog kind, no adapter -> base
		{"", "generic-ssh", "server", ""},                                                     // none -> generic ssh
		{"zzz-unknown", "generic-ssh", "server", ""},                                          // unknown -> generic ssh
	}
	for _, c := range cases {
		p := Resolve(c.name, "")
		if p.Name() != c.wantName {
			t.Errorf("%q: Name=%q want %q", c.name, p.Name(), c.wantName)
		}
		if p.Category() != c.wantCategory {
			t.Errorf("%q: Category=%q want %q", c.name, p.Category(), c.wantCategory)
		}
		if got := p.ManageURL(Target{}); got != c.wantManage {
			t.Errorf("%q: ManageURL=%q want %q", c.name, got, c.wantManage)
		}
	}
}

func TestManualDeploy(t *testing.T) {
	// A web-panel provider degrades to a manual paste with the keys URL.
	p := Resolve("ploi", "")
	out := p.Deploy(Target{PubkeyPath: "/h/.ssh/profiles/w/k.pub", Hostname: "h", User: "u"})
	if out.Method != "manual" || out.Verified {
		t.Fatalf("ploi deploy = %+v want manual/unverified", out)
	}
	if out.Detail != "paste k.pub at https://ploi.io/servers" {
		t.Errorf("manual detail = %q", out.Detail)
	}

	// No manage URL -> fall back to the ssh dest.
	out = base{spec: Spec{Name: "x"}}.Deploy(Target{PubkeyPath: "/p/id.pub", Hostname: "host", User: "me"})
	if out.Detail != "paste id.pub at me@host (authorized_keys)" {
		t.Errorf("fallback detail = %q", out.Detail)
	}
}

func TestKeyTitle(t *testing.T) {
	if got := keyTitle("k.pub", "ABCDEFGHIJKLMNOPQRST"); got != "ssh-manager k.pub ABCDEFGHIJKL" {
		t.Errorf("keyTitle = %q (want 12-char body fragment)", got)
	}
	if got := keyTitle("k.pub", ""); got != "ssh-manager k.pub" {
		t.Errorf("keyTitle no-body = %q", got)
	}
}

func TestRemoveByBody(t *testing.T) {
	// A real ed25519 body (KeyBody validates the line, so fakes won't match).
	body := "AAAAC3NzaC1lZDI1NTE5AAAAIKBhbiwvJigPhtwCSedPrebJ6NRC27KYLY3l/okYRnNA"
	rows := []map[string]any{
		{"id": float64(1), "key": "ssh-rsa NOTAKEY x", "title": "a"}, // KeyBody "" -> never matches
		{"id": "kp-2", "key": "ssh-ed25519 " + body + " two", "title": "b"},
	}
	var deleted []string
	ok := removeByBody(rows, body, func(id string) bool { deleted = append(deleted, id); return true })
	if !ok || len(deleted) != 1 || deleted[0] != "kp-2" {
		t.Errorf("removeByBody deleted=%v ok=%v (want [kp-2])", deleted, ok)
	}
	// No match -> no delete.
	if removeByBody(rows, "AAAAsomeotherbody", func(string) bool { return true }) {
		t.Error("no body match should not delete")
	}
}
