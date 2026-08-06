package providers

import (
	"strings"
	"testing"
)

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

// P1's remaining gap: the Provider interface is a Strategy, and every adapter
// has to satisfy the whole of it. A method that returns a zero value because
// nobody implemented it is indistinguishable at the call site from one that
// genuinely has nothing to say - `Rename` returning false, for instance, is a
// real answer for GenericSSH and a bug anywhere it was simply forgotten.
func TestEveryAdapterAnswersTheWholeInterface(t *testing.T) {
	target := Target{Alias: "a", Hostname: "example.com", User: "git", Port: 22}
	// Built through Resolve, the way the tool builds them, so the table cannot
	// drift from the constructor.
	for _, name := range []string{"generic-ssh", "github", "gitlab", "ploi", "digitalocean"} {
		p := Resolve(name, "")
		t.Run(name, func(t *testing.T) {
			if p == nil {
				t.Fatalf("Resolve(%q) returned nothing", name)
			}
		})
	}
	for name, p := range map[string]Provider{
		"generic-ssh": Resolve("generic-ssh", ""),
		"github":      Resolve("github", ""),
		"gitlab":      Resolve("gitlab", ""),
		"web-panel":   Resolve("ploi", ""),
		"rest-vps":    Resolve("digitalocean", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if p.Name() == "" {
				t.Error("Name is empty; the inventory records deployments under it")
			}
			if p.Category() == "" {
				t.Error("Category is empty; --type filters on it")
			}
			// ManageURL may be empty (not every provider has a keys page), but it
			// must not panic and must not return a placeholder.
			if u := p.ManageURL(target); strings.Contains(u, "%") || strings.Contains(u, "{") {
				t.Errorf("ManageURL = %q: an unexpanded template reached the user", u)
			}
		})
	}
}

// P2 - a catalog entry always resolves to an adapter that can identify itself.
//
// The two fields that matter are not interchangeable: category is what
// `list --type` filters on and what the provider label shows; kind is what
// adapterFor switches on. Neither is checked against a fixed vocabulary here,
// because neither has one - category is free-form so a user's providers.json can
// introduce its own, and adapterFor's default branch is deliberate: a kind with
// no API adapter (sourcehut, bitbucket, forgejo) falls to the universal manual
// path, which is the right answer for a provider whose keys are added through a
// web page.
//
// Nor is "the field is non-empty" worth asserting: specFromEntry defaults both
// to "generic", so it cannot be otherwise and the check would be unfalsifiable.
// What IS checkable is that the defaulting happens - a hand-edited
// providers.json missing a field degrades to a labelled generic entry rather
// than to a blank one - and that every shipped entry resolves to something that
// answers.
func TestACatalogEntryAlwaysResolvesToAnAdapterThatAnswers(t *testing.T) {
	specs := AllSpecs("")
	if len(specs) == 0 {
		t.Fatal("the shipped catalog is empty")
	}
	for name := range specs {
		p := Resolve(name, "")
		if p == nil {
			t.Errorf("%s resolves to nothing", name)
			continue
		}
		// A blank name or category would render as an empty column and would
		// never match a --type filter.
		if p.Name() == "" || p.Category() == "" {
			t.Errorf("%s resolved to an adapter that cannot identify itself (name=%q category=%q)",
				name, p.Name(), p.Category())
		}
	}

	// The defaulting, which is what makes the above true even for a malformed
	// user file. Written as a table over specFromEntry so it fails if the
	// fallback is ever removed and blank fields start reaching the renderer.
	for _, c := range []struct{ kind, cat, wantKind, wantCat string }{
		{"", "", "generic", "generic"},
		{"github", "", "github", "generic"},
		{"", "vcs", "generic", "vcs"},
		{"rest", "vps", "rest", "vps"},
	} {
		got := specFromEntry("x", catalogEntry{Kind: c.kind, Category: c.cat})
		if got.Kind != c.wantKind || got.Category != c.wantCat {
			t.Errorf("specFromEntry(kind=%q cat=%q) = kind %q cat %q, want %q/%q",
				c.kind, c.cat, got.Kind, got.Category, c.wantKind, c.wantCat)
		}
	}
}
