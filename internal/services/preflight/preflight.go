// Package preflight detects the OS and verifies the SSH tooling doctor needs,
// ported from services/preflight.py. The Python version also gates on a minimum
// CPython; the Go binary is self-contained, so that check becomes a runtime note
// and the actionable part - the hard/optional binary scan - is unchanged.
package preflight

import (
	"os/exec"
	"runtime"
	"strings"
)

// HardBins must be present; OptionalBins degrade gracefully. Same lists as v1.
var (
	HardBins     = []string{"ssh-keygen", "ssh-add", "ssh-copy-id", "ssh-keyscan"}
	OptionalBins = []string{"age", "sops", "gitleaks", "gh", "glab", "age-plugin-yubikey"}
)

// Report is the preflight result.
type Report struct {
	OSName          string
	RuntimeOK       bool // a built Go binary carries its runtime; always true
	OSFirstClass    bool
	MissingHard     []string
	MissingOptional []string
}

// OK is true when the runtime is fine and no hard dep is missing.
func (r Report) OK() bool { return r.RuntimeOK && len(r.MissingHard) == 0 }

// Check runs the preflight scan over the current PATH.
func Check() Report {
	return Report{
		OSName:          osName(),
		RuntimeOK:       true,
		OSFirstClass:    firstClass(),
		MissingHard:     missing(HardBins),
		MissingOptional: missing(OptionalBins),
	}
}

func missing(bins []string) []string {
	var out []string
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			out = append(out, b)
		}
	}
	return out
}

func firstClass() bool {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return true
	default:
		return false
	}
}

func osName() string {
	pretty := map[string]string{"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
	n := pretty[runtime.GOOS]
	if n == "" {
		n = runtime.GOOS
	}
	return runtime.GOOS + " (" + n + ")"
}

// Format renders the human-readable preflight block.
func Format(r Report) string {
	lines := []string{
		"os: " + r.OSName,
		"runtime: native binary (no interpreter required)",
	}
	if !r.OSFirstClass {
		lines = append(lines, "note: this OS is not yet first-class - support is in progress")
	}
	if len(r.MissingHard) == 0 {
		lines = append(lines, "hard deps: ok")
	} else {
		lines = append(lines, "hard deps: MISSING "+strings.Join(r.MissingHard, ", "))
	}
	if len(r.MissingOptional) > 0 {
		lines = append(lines, "optional (degrade gracefully): "+strings.Join(r.MissingOptional, ", "))
	}
	if r.OK() {
		lines = append(lines, "RESULT: ready")
	} else {
		lines = append(lines, "RESULT: blocked - install the missing hard deps")
	}
	return strings.Join(lines, "\n")
}
