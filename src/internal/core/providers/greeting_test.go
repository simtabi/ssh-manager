package providers

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGreetedLogin(t *testing.T) {
	cases := map[string]string{
		"Hi simtabi-bot! You've successfully authenticated, but GitHub does not provide shell access.":  "simtabi-bot",
		"Hi imanimanyara! You've successfully authenticated, but GitHub does not provide shell access.": "imanimanyara",
		"git@github.com: Permission denied (publickey).":                                                "",
		"": "",
	}
	for banner, want := range cases {
		if got := greetedLogin(banner); got != want {
			t.Errorf("greetedLogin(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestVerifyLoginUsesTheAgentForAPublicKey(t *testing.T) {
	file := Target{IdentityPath: "/k"}.identityOpts()
	agent := Target{IdentityPath: "/k.pub", IdentityAgent: "~/.1password/agent.sock"}.identityOpts()
	if len(file) != 4 || len(agent) != 6 || agent[5] != "IdentityAgent=~/.1password/agent.sock" {
		t.Errorf("file opts %v, agent opts %v", file, agent)
	}
}

// A token for the wrong account (a personal one left in GH_TOKEN_SIMTABI) lists
// the key on that account, so "the key is listed" passes; GitHub then greets the
// key as someone else. Verify must refuse that, or rotation commits a key the
// machine-user alias cannot push with.
func TestGitHubVerifyRejectsAKeyThatAuthenticatesAsAnotherAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stubs are shell scripts")
	}
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBUS2DuYRWw/OWok0ZTrm7v2vmro3+jJ+/n36DZDuitx simtabi-bot" // throwaway, generated for this test
	bin := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("gh", `case "$*" in
*user/keys*) echo '[{"id":1,"key":"`+pub+`","title":"t"}]' ;;
*"api user"*) echo "$FAKE_LOGIN" ;;
esac
`)
	write("ssh", `echo "Hi $FAKE_GREETING! You've successfully authenticated, but GitHub does not provide shell access." >&2; exit 1`+"\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN_TEST", "tok")
	tgt := Target{PubkeyText: pub, TokenEnv: "GH_TOKEN_TEST", IdentityPath: "/k.pub"}

	t.Setenv("FAKE_LOGIN", "simtabi-bot")
	t.Setenv("FAKE_GREETING", "simtabi-bot")
	if !(GitHub{}).Verify(tgt) {
		t.Fatal("matching account: Verify = false, want true")
	}
	t.Setenv("FAKE_GREETING", "imanimanyara")
	if (GitHub{}).Verify(tgt) {
		t.Fatal("key authenticates as another account: Verify = true, want false")
	}
}
