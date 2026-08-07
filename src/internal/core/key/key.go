// Package key implements the ssh-manager key-naming convention. Name grammar:
// <profile>_<service>-<algo> with
// exactly one underscore (the profile prefix); the rest is kebab-case.
package key

import (
	"fmt"
	"regexp"
	"strings"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// NormalizeSegment lowercases and collapses any non-alphanumeric run to a single
// dash, trimming leading/trailing dashes.
func NormalizeSegment(value string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(value), "-"), "-")
}

// BuildKeyName builds a canonical key name. The profile must reduce to a single
// token (dashes are removed). An empty algo defaults to ed25519.
func BuildKeyName(profile, service, algo string) (string, error) {
	if algo == "" {
		algo = "ed25519"
	}
	prof := strings.ReplaceAll(NormalizeSegment(profile), "-", "")
	svc := NormalizeSegment(service)
	if prof == "" || svc == "" {
		return "", fmt.Errorf("cannot build key name from profile=%q service=%q", profile, service)
	}
	return prof + "_" + svc + "-" + algo, nil
}

// SplitKeyName splits a name into (profile, remainder) on the first underscore.
func SplitKeyName(name string) (profile, remainder string, err error) {
	profile, remainder, found := strings.Cut(name, "_")
	if !found || remainder == "" {
		return "", "", fmt.Errorf("not a ssh-manager key name: %q", name)
	}
	return profile, remainder, nil
}

// Known algo suffixes, longest first so -ed25519-sk wins over -sk. The same set
// is what ssh-keygen -t accepts, so it doubles as the type allowlist.
var algoSuffixes = []string{"ed25519-sk", "ecdsa-sk", "ed25519", "ecdsa", "rsa", "dsa"}

// IsKnownAlgo reports whether algo is a key type ssh-keygen -t understands.
// Callers validate a declared type up front rather than letting a typo surface
// as a mid-mint ssh-keygen failure, after the snapshot and directory work.
func IsKnownAlgo(algo string) bool {
	for _, a := range algoSuffixes {
		if algo == a {
			return true
		}
	}
	return false
}

// AlgoOf returns the trailing -<algo> token of a key name (default ed25519).
func AlgoOf(name string) (string, error) {
	_, remainder, err := SplitKeyName(name)
	if err != nil {
		return "", err
	}
	for _, algo := range algoSuffixes {
		if remainder == algo || strings.HasSuffix(remainder, "-"+algo) {
			return algo, nil
		}
	}
	return "ed25519", nil
}

// DeriveKeyName derives a canonical key name from a profile + host alias. The
// alias is the service token (e.g. "hpc.example.edu" -> "sc-its-hpc-edu").
func DeriveKeyName(profile, alias, algo string) (string, error) {
	return BuildKeyName(profile, alias, algo)
}
