package configsvc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Host pattern defined twice across the managed files is reported - the case
// a git ssh mode block rendered into both the root and a category file made.
func TestCheckFlagsDuplicateHostBlocks(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, manifestJSON), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	if res := mustCheck(t, svc); len(res.Duplicates) != 0 {
		t.Fatalf("a fresh render has duplicates: %v", res.Duplicates)
	}
	root := filepath.Join(ssh, "config")
	b, _ := os.ReadFile(root)
	dup := strings.Replace(string(b), "Host *\n", "Host github.com\n    User git\n\nHost github.com\n    User other\n\nHost *\n", 1)
	if err := os.WriteFile(root, []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}
	res := mustCheck(t, svc)
	if len(res.Duplicates) != 1 || res.Duplicates[0].Pattern != "github.com" || res.InSync() {
		t.Fatalf("want one github.com duplicate, got %+v", res.Duplicates)
	}
	if !strings.Contains(res.Format(), "DUPLICATE Host github.com is defined 2 times") {
		t.Errorf("format:\n%s", res.Format())
	}
}
