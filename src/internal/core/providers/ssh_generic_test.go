package providers

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Ports v1's ssh_generic tests, which ran the generated remote
// script for real rather than mocking it. The script is the part that edits a
// live server's authorized_keys; asserting that Remove "calls ssh" would check
// nothing that matters. So the tests below put a stand-in ssh first on PATH that
// executes the script's text locally against a temp $HOME - the same thing the
// v1's test achieved by stubbing its subprocess wrapper.

// keyBody builds a plausible OpenSSH key body: the wire format the base64 in a
// public key line actually encodes, so authkeys parses it as a real key.
func keyBody(tag, keyType string) string {
	payload := strings.Repeat(tag, 64)[:32]
	var blob []byte
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(keyType)))
	blob = append(blob, keyType...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	blob = append(blob, payload...)
	return base64.StdEncoding.EncodeToString(blob)
}

// stubSSHRunsScriptLocally installs an "ssh" on PATH that runs its last argument
// - the remote script - under sh with HOME pointed at the given directory, and
// returns nothing else. Everything before the script is the argv Remove built,
// which the stub ignores exactly as a real ssh would ignore it for our purposes.
func stubSSHRunsScriptLocally(t *testing.T, home string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the remote script is POSIX sh")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\nHOME=" + home + " exec sh -c \"$last\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// removeFixture seeds a temp HOME with an authorized_keys and returns the target
// whose key Remove will be asked to take out, plus the file's path.
func removeFixture(t *testing.T, initial string) (Target, string) {
	t.Helper()
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(ak, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	stubSSHRunsScriptLocally(t, home)

	pubPath := filepath.Join(t.TempDir(), "k.pub")
	pubText := "ssh-ed25519 " + targetBody + " me@host\n"
	if err := os.WriteFile(pubPath, []byte(pubText), 0o644); err != nil {
		t.Fatal(err)
	}
	return Target{
		Alias: "a", Hostname: "h", User: "u", Port: 22,
		PubkeyPath: pubPath, PubkeyText: pubText,
	}, ak
}

var (
	targetBody = keyBody("target", "ssh-ed25519")
	otherBody  = keyBody("other", "ssh-rsa")
)

func TestRemoveTakesOneKeyAndLeavesTheRest(t *testing.T) {
	tgt, ak := removeFixture(t,
		"ssh-ed25519 "+targetBody+" me@host\nssh-rsa "+otherBody+" you\n")

	if !(GenericSSH{}).Remove(tgt) {
		t.Fatal("removing one of two keys should succeed")
	}
	body, err := os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), targetBody) {
		t.Error("the key that was removed is still in authorized_keys")
	}
	if !strings.Contains(string(body), otherBody) {
		t.Fatal("removing one key took another with it")
	}
	// The rewrite is preceded by a timestamped backup, so a bad removal is
	// recoverable from the server itself - which may be the only way back in.
	backups, err := filepath.Glob(ak + ".ssh-manager.bak.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) == 0 {
		t.Error("no backup was taken before rewriting authorized_keys")
	}
}

// The lockout guard. Removing the last key would leave a server nobody can log
// in to, and there is no undo for that from this side - so the script refuses
// and leaves the file exactly as it was.
func TestRemoveRefusesToEmptyAuthorizedKeys(t *testing.T) {
	tgt, ak := removeFixture(t, "ssh-ed25519 "+targetBody+" only\n")

	if (GenericSSH{}).Remove(tgt) {
		t.Error("removing the only key should be refused")
	}
	body, err := os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), targetBody) {
		t.Fatal("the only key was removed; the server is now unreachable")
	}
}

// A comment line is not a key, so a file left with nothing but comments still
// trips the guard rather than counting as "something is left".
func TestRemoveRefusesWhenOnlyCommentsWouldRemain(t *testing.T) {
	tgt, ak := removeFixture(t,
		"# my keys\n\nssh-ed25519 "+targetBody+" only\n")

	if (GenericSSH{}).Remove(tgt) {
		t.Error("a file of comments is not a set of keys; the removal should be refused")
	}
	body, err := os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), targetBody) {
		t.Fatal("the only key was removed behind a comment line")
	}
}

func TestRemoveReportsFalseWhenTheKeyIsNotThere(t *testing.T) {
	tgt, ak := removeFixture(t, "ssh-rsa "+otherBody+" you\n")

	if (GenericSSH{}).Remove(tgt) {
		t.Error("removing a key that is not deployed should report false")
	}
	body, err := os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), otherBody) {
		t.Error("a no-op removal rewrote the file anyway")
	}
	if backups, _ := filepath.Glob(ak + ".ssh-manager.bak.*"); len(backups) != 0 {
		t.Error("a no-op removal should not leave a backup behind")
	}
}

// A key with no parseable body cannot be matched against anything on the remote,
// and substituting an empty body into the script would make grep match every
// line - emptying authorized_keys instead of editing it.
func TestRemoveWithNoParseableKeyNeverReachesTheRemote(t *testing.T) {
	tgt, ak := removeFixture(t, "ssh-rsa "+otherBody+" you\n")
	tgt.PubkeyText = "this is not a public key"

	if (GenericSSH{}).Remove(tgt) {
		t.Error("an unparseable public key should not report a successful removal")
	}
	body, err := os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), otherBody) {
		t.Fatal("an unparseable key emptied authorized_keys")
	}
}

// The ssh fallback (D6). Microsoft's OpenSSH port does not ship ssh-copy-id, so
// on Windows this is the normal path rather than a fallback, and it has to do
// what ssh-copy-id does: create ~/.ssh restrictively, append the key once, and
// leave authorized_keys owner-only.
func TestDeployOverSSHAppendsOnceAndTightensPermissions(t *testing.T) {
	home := t.TempDir()
	stubSSHRunsScriptLocally(t, home)
	pubText := "ssh-ed25519 " + targetBody + " me@host"
	tgt := Target{Alias: "a", Hostname: "h", User: "u", Port: 22, PubkeyText: pubText}

	out := (GenericSSH{}).deployOverSSH(tgt)
	if out.Error || !out.Verified {
		t.Fatalf("deploy = %+v, want a verified install", out)
	}
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	body, err := os.ReadFile(ak)
	if err != nil {
		t.Fatalf("authorized_keys was not created: %v", err)
	}
	if !strings.Contains(string(body), targetBody) {
		t.Errorf("authorized_keys = %q, want the key appended", body)
	}

	// Re-deploying is normal - a rotation, a re-run after a failure - and must
	// not accumulate duplicate lines.
	if out := (GenericSSH{}).deployOverSSH(tgt); out.Error {
		t.Fatalf("second deploy = %+v", out)
	}
	body, err = os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(body), targetBody); n != 1 {
		t.Errorf("the key appears %d times after two deploys, want 1", n)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(ak)
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("authorized_keys is %04o, want 0600 - sshd ignores a loose one", mode)
		}
		di, err := os.Stat(filepath.Dir(ak))
		if err != nil {
			t.Fatal(err)
		}
		if mode := di.Mode().Perm(); mode != 0o700 {
			t.Errorf("~/.ssh is %04o, want 0700", mode)
		}
	}
}

// The key goes over stdin, not in the command line, so it never appears in the
// remote host's process list - where any local user could read it.
func TestDeployOverSSHKeepsTheKeyOutOfTheCommandLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the remote script is POSIX sh")
	}
	if strings.Contains(appendKeyScript, targetBody) {
		t.Fatal("the script template should not contain key material at all")
	}
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "argv.txt")
	// This stub records the argv instead of running the script.
	stub := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argvLog + "; done\ncat > /dev/null\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pubText := "ssh-ed25519 " + targetBody + " me@host"
	(GenericSSH{}).deployOverSSH(Target{Alias: "a", Hostname: "h", User: "u", Port: 22, PubkeyText: pubText})

	argv, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("the stub was not invoked: %v", err)
	}
	if strings.Contains(string(argv), targetBody) {
		t.Errorf("the public key reached the remote command line:\n%s", argv)
	}
}
