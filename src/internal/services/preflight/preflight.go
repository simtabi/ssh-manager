// Package preflight detects the OS and verifies the SSH tooling doctor needs.
// The implementation this replaced also gated on a minimum CPython; the Go binary
// is self-contained, so that check becomes a runtime note
// and the actionable part - the hard/optional binary scan - is unchanged.
package preflight

import (
	"os/exec"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
)

// HardBins must be present; OptionalBins degrade gracefully.
//
// ssh-copy-id is hard on Unix and optional on Windows: Microsoft's OpenSSH port
// does not ship it, so requiring it there made preflight fail - and doctor with
// it - on every stock Windows machine, for a tool the generic ssh provider only
// uses as one deployment path among several. It is still listed there, so a
// user who has it installed keeps the better path and one who does not is told
// what they are missing rather than that their install is broken.
var (
	HardBins     = hardBins()
	OptionalBins = optionalBins()
)

const copyID = "ssh-copy-id"

func hardBins() []string {
	bins := []string{"ssh-keygen", "ssh-add", "ssh-keyscan"}
	if !platform.IsWindows() {
		bins = append(bins, copyID)
	}
	return bins
}

func optionalBins() []string {
	bins := []string{"age", "sops", "gitleaks", "gh", "glab", "age-plugin-yubikey"}
	if platform.IsWindows() {
		bins = append([]string{copyID}, bins...)
	}
	return bins
}

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

func firstClass() bool { return platform.FirstClass() }

func osName() string { return platform.OSName() }

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
