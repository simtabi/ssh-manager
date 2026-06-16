package cli

import (
	"bytes"
	"testing"

	"github.com/simtabi/ssh-manager/internal/version"
)

func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version command errored: %v", err)
	}
	want := "sshmgr " + version.Version + "\n"
	if out.String() != want {
		t.Fatalf("version output = %q, want %q", out.String(), want)
	}
}

func TestRootHasVersionFlag(t *testing.T) {
	root := newRootCmd()
	if root.Version != version.Version {
		t.Fatalf("root.Version = %q, want %q", root.Version, version.Version)
	}
}
