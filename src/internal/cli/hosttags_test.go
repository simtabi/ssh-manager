package cli

import (
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// `host edit --tag/--untag` - the only CLI way to take a tag off a host.
func TestHostEditTags(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "web", "-H", "1.2.3.4", "-u", "ploi", "--tag", "web", "--tag", "prd", "--tag", "eu")
	tags := func() string {
		m, err := manifest.Load(p.Manifest())
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(m.Profiles["work"].Hosts[0].Tags, ",")
	}

	run(t, "host", "edit", "work", "web", "-u", "deploy")
	if got := tags(); got != "web,prd,eu" {
		t.Fatalf("edit without tag flags changed tags: %q", got)
	}
	run(t, "host", "edit", "work", "web", "--untag", "eu")
	if got := tags(); got != "web,prd" {
		t.Fatalf("--untag: %q", got)
	}
	run(t, "host", "edit", "work", "web", "--tag", "db", "--tag", "stg")
	if got := tags(); got != "db,stg" {
		t.Fatalf("--tag replaces: %q", got)
	}
	run(t, "host", "edit", "work", "web", "--tag", "")
	if got := tags(); got != "" {
		t.Fatalf("--tag '' clears: %q", got)
	}
}
