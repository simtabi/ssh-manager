// Package version carries the build version.
package version

// Version is the ssh-manager version. Release builds override it through
// -ldflags "-X .../internal/version.Version=..."; this default is for dev builds.
var Version = "2.0.0-dev"
