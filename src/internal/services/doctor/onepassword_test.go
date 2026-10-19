package doctor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

func TestOnePasswordIssuesOnlyWhenAProfileUsesIt(t *testing.T) {
	var none, uses manifest.Manifest
	_ = json.Unmarshal([]byte(`{"version":1,"profiles":{"p":{"hosts":[]}}}`), &none)
	if got := onePasswordIssues(&none); got != nil {
		t.Errorf("no 1Password profile: issues = %v, want none", got)
	}
	_ = json.Unmarshal([]byte(`{"version":1,"defaults":{"onepassword_agent":"~/.no-such-dir-9f2/agent.sock"},
	  "profiles":{"bot":{"key_store":"1password","op_vault":"V","hosts":[]}}}`), &uses)
	t.Setenv("PATH", t.TempDir()) // no op
	got := strings.Join(onePasswordIssues(&uses), "|")
	if !strings.Contains(got, "op") || !strings.Contains(got, "socket") {
		t.Errorf("issues = %q, want both the missing op and the missing socket", got)
	}
}
