// Package version carries the build version.
package version

// Version is the ssh-manager version. Release builds override it through
// -ldflags "-X .../internal/version.Version=..."; this default is for dev builds.
var Version = "2.0.0-dev"

// Commit is the short git commit the binary was built from. Release builds
// stamp it via -ldflags "-X .../internal/version.Commit=..."; empty in dev builds.
var Commit = ""

// Date is the build/commit date (RFC 3339). Release builds stamp it via
// -ldflags "-X .../internal/version.Date=..."; empty in dev builds.
var Date = ""
