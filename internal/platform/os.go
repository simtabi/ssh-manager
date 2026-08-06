package platform

import "runtime"

// The OS predicates. These exist so a question like "should the config emit
// UseKeychain?" is asked once, in a package whose job is knowing the answer,
// rather than as a runtime.GOOS comparison repeated at every call site - which
// is how the same string literal ended up in sixteen places, each free to get it
// wrong on its own.

// IsMacOS reports whether this is macOS.
func IsMacOS() bool { return runtime.GOOS == "darwin" }

// IsWindows reports whether this is Windows.
func IsWindows() bool { return runtime.GOOS == "windows" }

// IsLinux reports whether this is Linux.
func IsLinux() bool { return runtime.GOOS == "linux" }

// FirstClass reports whether this OS is one sshmgr is tested on. Elsewhere it
// still builds and mostly works, but the platform layer falls back to generic
// behaviour and preflight says so.
func FirstClass() bool { return IsMacOS() || IsLinux() || IsWindows() }

// OSName is the GOOS token plus its human name, for display.
func OSName() string {
	pretty := map[string]string{"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
	name := pretty[runtime.GOOS]
	if name == "" {
		name = runtime.GOOS
	}
	return runtime.GOOS + " (" + name + ")"
}

// EmitUseKeychain reports whether the rendered ssh config should carry
// UseKeychain.
//
// It is an Apple extension: ssh on macOS reads a key's passphrase from the login
// keychain instead of prompting. OpenSSH elsewhere does not know the keyword,
// and an unknown keyword is a hard parse error for the whole file - which is why
// the renderer also pins `IgnoreUnknown UseKeychain`, and why this has to be
// decided per machine rather than baked into the manifest.
func EmitUseKeychain() bool { return IsMacOS() }
