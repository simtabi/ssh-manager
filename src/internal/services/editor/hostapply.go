package editor

import (
	"fmt"
	"os"
	"strings"
)

// ApplyCreatingProfile runs the batch, first creating the profile when asked.
// Creating it is a separate save, so if the batch then fails validation the
// manifest is put back exactly as it was - otherwise a refused batch left an
// empty profile behind. A new profile has no key directory yet, so restoring
// the manifest is the whole of the undo.
func (e *Editor) ApplyCreatingProfile(profile, category string, create bool, specs []HostSpec) ([]ApplyResult, error) {
	ed, manifestPath := e, e.p.Manifest()
	if !create {
		return ed.ApplyHosts(profile, specs, false)
	}
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	undo := func(cause error) error {
		if werr := os.WriteFile(manifestPath, before, 0o600); werr != nil {
			return fmt.Errorf("%w (and restoring the manifest failed: %v)", cause, werr)
		}
		return cause
	}
	if err := ed.AddProfile(profile, "per_service", nil); err != nil {
		return nil, undo(err)
	}
	if category != "" {
		if _, err := ed.SetCategory(profile, category); err != nil {
			return nil, undo(err)
		}
	}
	res, err := ed.ApplyHosts(profile, specs, false)
	if err != nil {
		return nil, undo(err)
	}
	return res, nil
}

// FormatApply is the report `host apply` prints, for a dry run or a real one.
func FormatApply(profile string, newProfile bool, res []ApplyResult, preview bool) string {
	var b strings.Builder
	mode := "applied"
	if preview {
		mode = "dry-run"
	}
	fmt.Fprintf(&b, "host apply %s (%s):", profile, mode)
	if newProfile {
		verb := "created"
		if preview {
			verb = "would create"
		}
		fmt.Fprintf(&b, "\n  profile: %s %s", verb, profile)
	}
	counts := map[ApplyAction]int{}
	for _, r := range res {
		counts[r.Action]++
		fmt.Fprintf(&b, "\n  %-9s %s", r.Action, r.Alias)
		if len(r.Changes) > 0 {
			fmt.Fprintf(&b, "  (%s)", strings.Join(r.Changes, "; "))
		}
	}
	fmt.Fprintf(&b, "\n  %d added, %d updated, %d unchanged",
		counts[HostAdded], counts[HostUpdated], counts[HostUnchanged])
	return b.String()
}

// AnyAdded reports whether the batch added a host.
func AnyAdded(res []ApplyResult) bool {
	for _, r := range res {
		if r.Action == HostAdded {
			return true
		}
	}
	return false
}
