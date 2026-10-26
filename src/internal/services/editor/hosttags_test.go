package editor

import (
	"strings"
	"testing"
)

func TestEditHostReplacesAndRemovesTags(t *testing.T) {
	ed, p := setup(t)
	if err := ed.AddHost("work", "web", HostFields{Hostname: str("1.2.3.4"), User: str("ploi"),
		Tags: []string{"web", "prd", "eu"}}); err != nil {
		t.Fatal(err)
	}
	tags := func() string {
		_, h, err := findHost(reload(t, p), "work", "web")
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(h.Tags, ",")
	}

	// No tag fields: tags are left alone, as before.
	if err := ed.EditHost("work", "web", HostFields{Hostname: str("5.6.7.8")}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); got != "web,prd,eu" {
		t.Fatalf("edit without tag fields changed tags: %q", got)
	}

	// Untag removes only the named tags; one the host lacks is a no-op.
	if err := ed.EditHost("work", "web", HostFields{Untag: []string{"eu", "missing"}}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); got != "web,prd" {
		t.Fatalf("after untag = %q, want web,prd", got)
	}

	// Replace sets the whole list, de-duplicated, in order.
	set := []string{"db", "stg", "db"}
	if err := ed.EditHost("work", "web", HostFields{SetTags: &set}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); got != "db,stg" {
		t.Fatalf("after replace = %q, want db,stg", got)
	}

	// Replace then untag in one edit.
	set = []string{"a", "b"}
	if err := ed.EditHost("work", "web", HostFields{SetTags: &set, Untag: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); got != "b" {
		t.Fatalf("replace+untag = %q, want b", got)
	}

	// An empty replacement clears every tag.
	empty := []string{}
	if err := ed.EditHost("work", "web", HostFields{SetTags: &empty}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); got != "" {
		t.Fatalf("after clear = %q, want none", got)
	}
}
