package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func hasAge() bool {
	if _, err := exec.LookPath("age"); err != nil {
		return false
	}
	_, err := exec.LookPath("age-keygen")
	return err == nil
}

// ageIdentity mints a throwaway keypair and returns (recipient, identity path).
func ageIdentity(t *testing.T) (string, string) {
	t.Helper()
	identity := filepath.Join(t.TempDir(), "id.age")
	out, err := exec.Command("age-keygen", "-o", identity).CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen: %v: %s", err, out)
	}
	for _, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(f, "age1") {
			return f, identity
		}
	}
	t.Fatalf("no recipient in age-keygen output: %s", out)
	return "", ""
}
