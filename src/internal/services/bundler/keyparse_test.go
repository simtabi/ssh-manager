package bundler

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func wireString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// ed25519Blob is a wire-format public key; crypto/rand does not fail.
func ed25519Blob() []byte {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return append(wireString([]byte("ssh-ed25519")), wireString(pub)...)
}

func testPublicLine() string {
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(ed25519Blob()) + " work/a 2026-10-27\n"
}

// testOpenSSHKey builds an unencrypted "OPENSSH PRIVATE KEY" the way
// PROTOCOL.key lays it out; only the header and public key are checked.
func testOpenSSHKey(cipher string) string {
	b := []byte(opensshMagic)
	b = append(b, wireString([]byte(cipher))...)
	b = append(b, wireString([]byte("none"))...)
	b = append(b, wireString(nil)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, wireString(ed25519Blob())...)
	b = append(b, wireString([]byte("private section"))...)
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b}))
}

func pemOf(t *testing.T, typ string, der []byte, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func TestLooksLikeKeyAcceptsRealKeys(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8, err8 := x509.MarshalPKCS8PrivateKey(edPriv)
	ecDER, errEC := x509.MarshalECPrivateKey(ecPriv)
	cases := map[string]string{
		"public line":            testPublicLine(),
		"public line no comment": "ssh-ed25519 " + base64.StdEncoding.EncodeToString(ed25519Blob()),
		"openssh":                testOpenSSHKey("none"),
		"openssh, passphrase":    testOpenSSHKey("aes256-ctr"),
		"pkcs8":                  pemOf(t, "PRIVATE KEY", pkcs8, err8),
		"ec":                     pemOf(t, "EC PRIVATE KEY", ecDER, errEC),
		"rsa":                    pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaPriv), nil),
	}
	for name, body := range cases {
		if !looksLikeKey([]byte(body)) {
			t.Errorf("%s: a real key was refused", name)
		}
	}
}

// G12: the prefix check laid down anything that started "ssh-". Each of these
// does, or opens like a PEM key, and none is a key.
func TestLooksLikeKeyRefusesLookalikes(t *testing.T) {
	cases := map[string]string{
		"forged config":         "ssh-ed25519 AAAA\nHost *\n    ProxyCommand touch /tmp/owned\n",
		"bad base64":            "ssh-ed25519 not*base64 c\n",
		"type mismatch":         "ssh-rsa " + base64.StdEncoding.EncodeToString(ed25519Blob()) + "\n",
		"type only":             "ssh-ed25519\n",
		"empty blob":            "ssh-ed25519 AAAA\n",
		"pem with trailer":      testOpenSSHKey("none") + "Host *\n    ProxyCommand x\n",
		"pem without magic":     "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
		"pem not a key":         pemOf(t, "CERTIFICATE", []byte("x"), nil),
		"pkcs8 garbage":         pemOf(t, "PRIVATE KEY", []byte("garbage"), nil),
		"truncated length":      "-----BEGIN ",
		"known_hosts line":      "github.com " + testPublicLine(),
		"sk prefix, plain text": "sk-ssh-ed25519@openssh.com hello\n",
	}
	for name, body := range cases {
		if looksLikeKey([]byte(body)) {
			t.Errorf("%s: accepted as a key", name)
		}
	}
}

// Keys ssh-keygen itself writes, where it is installed, including one with a
// passphrase: the case a parse of the private half alone would refuse.
func TestLooksLikeKeyAcceptsSSHKeygenOutput(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	for _, tc := range []struct{ typ, pass string }{{"ed25519", ""}, {"ed25519", "pw-for-test"}, {"ecdsa", ""}, {"rsa", ""}} {
		path := filepath.Join(dir, tc.typ+tc.pass)
		if out, err := exec.Command("ssh-keygen", "-q", "-t", tc.typ, "-N", tc.pass, "-C", "c", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %s: %v %s", tc.typ, err, out)
		}
		for _, p := range []string{path, path + ".pub"} {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !looksLikeKey(b) {
				t.Errorf("%s: ssh-keygen output refused", filepath.Base(p))
			}
		}
	}
}
