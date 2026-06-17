package secrets

import (
	"reflect"
	"testing"
)

func TestResolvePlainAndEmpty(t *testing.T) {
	if got := Resolve("ghp_token123"); got != "ghp_token123" {
		t.Errorf("plain value should pass through, got %q", got)
	}
	if got := Resolve(""); got != "" {
		t.Errorf("empty -> empty, got %q", got)
	}
}

func TestResolveCmd(t *testing.T) {
	// echo is portable enough for the test; trimmed stdout is the secret.
	if got := Resolve("cmd:echo  hunter2 "); got != "hunter2" {
		t.Errorf("cmd: secret = %q want hunter2", got)
	}
	// A failing command -> "" (degrade to manual).
	if got := Resolve("cmd:false"); got != "" {
		t.Errorf("failing cmd -> empty, got %q", got)
	}
}

func TestShlexSplit(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`op read op://Private/GitHub/token`, []string{"op", "read", "op://Private/GitHub/token"}},
		{`sh -c 'echo hi there'`, []string{"sh", "-c", "echo hi there"}},
		{`a "b c" d`, []string{"a", "b c", "d"}},
		{``, nil},
	}
	for _, c := range cases {
		if got := shlexSplit(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("shlexSplit(%q)=%v want %v", c.in, got, c.want)
		}
	}
}
