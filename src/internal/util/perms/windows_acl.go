package perms

import (
	"os"
	"os/user"
)

// The Windows ACL rules, kept out of the build-tagged file that runs them.
//
// perms_windows.go can only be compiled - and therefore only be tested - on
// Windows, which put the whole of this logic beyond reach of every developer
// machine and two of the three CI legs. What is actually worth checking is not
// that exec.Command works: it is which commands get built, in what order, and
// who they name. That is all decidable without Windows, so it lives here and
// perms_windows.go is left as the thin part that runs them.

// broadPrincipals are the over-broad ACEs stripped from keys, directories and
// configs so no other principal keeps access. Mirrors
// v1's windows layer (_BROAD_PRINCIPALS).
var broadPrincipals = []string{"Everyone", "Authenticated Users", "Users", `BUILTIN\Users`}

// aclOwner is the account an ACL is granted to: %USERNAME% when set, else the
// current user. getenv and current are injected so the fallback is testable.
func aclOwner(getenv func(string) string, current func() (*user.User, error)) string {
	if u := getenv("USERNAME"); u != "" {
		return u
	}
	if cu, err := current(); err == nil {
		return cu.Username
	}
	return ""
}

// icaclsCommands is the argv of every icacls call that restricts path to owner,
// in the order they must run.
//
// Order is the whole point. Dropping inheritance first means the explicit grant
// that follows is the only thing left; granting first would leave a window where
// the file carries both the inherited ACEs and the new one. The broad-principal
// removals come last and are individually optional - removing an ACE that is not
// there is a no-op - so they are separated from the two that must succeed.
func icaclsCommands(path, owner string) (required [][]string, optional [][]string) {
	required = [][]string{
		{"icacls", path, "/inheritance:r"},
		{"icacls", path, "/grant:r", owner + ":F"},
	}
	for _, p := range broadPrincipals {
		optional = append(optional, []string{"icacls", path, "/remove:g", p})
	}
	return required, optional
}

// windowsPermsOK treats any existing file as correct. Windows permissions are
// ACLs, not mode bits: a synthetic st_mode would flag every file as wrong, and
// the actual enforcement happens through icacls on write. Mirrors
// v1's windows layer (perms_ok).
func windowsPermsOK(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
