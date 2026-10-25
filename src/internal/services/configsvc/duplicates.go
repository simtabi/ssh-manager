package configsvc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
)

// Duplicate is a Host pattern that sshmgr's managed files define more than once.
// ssh uses only the first, so the later blocks are dead weight that reads as
// if it applied.
type Duplicate struct {
	Pattern string
	Files   []string // in the order ssh reads them
}

func (d Duplicate) String() string {
	return fmt.Sprintf("Host %s is defined %d times (%s); ssh uses only the first",
		d.Pattern, len(d.Files), strings.Join(d.Files, ", "))
}

// findDuplicates reads the managed files on disk in ssh's read order (the root
// managed block, whose Includes expand first, then each category file) and
// reports every Host pattern that appears in more than one block.
func (s *Service) findDuplicates(rendered map[string]string) []Duplicate {
	order := s.renderedOrder(rendered)
	// Root's Includes expand before its own blocks: read categories first.
	var files []string
	for _, rel := range order {
		if rel != renderer.RootConfig {
			files = append(files, rel)
		}
	}
	files = append(files, renderer.RootConfig)
	seen := map[string]*Duplicate{}
	var keys []string
	for _, rel := range files {
		content, ok := readFile(filepath.Join(s.sshDir, filepath.FromSlash(rel)))
		if !ok {
			continue
		}
		if rel == renderer.RootConfig {
			content = managedRegion(content)
		}
		for _, ln := range strings.Split(content, "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 || !strings.EqualFold(f[0], "Host") {
				continue
			}
			for _, pat := range f[1:] {
				k := strings.ToLower(pat)
				if seen[k] == nil {
					seen[k] = &Duplicate{Pattern: pat}
					keys = append(keys, k)
				}
				seen[k].Files = append(seen[k].Files, rel)
			}
		}
	}
	var out []Duplicate
	for _, k := range keys {
		if len(seen[k].Files) > 1 {
			out = append(out, *seen[k])
		}
	}
	return out
}

// managedRegion is the part of the root config between the managed markers.
func managedRegion(content string) string {
	var b strings.Builder
	in := false
	for _, ln := range strings.Split(content, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case renderer.IsManagedHeaderLine(t):
			in = true
		case renderer.IsManagedEndLine(t):
			in = false
		case in:
			b.WriteString(ln + "\n")
		}
	}
	return b.String()
}
