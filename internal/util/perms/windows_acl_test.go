package perms

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

// Parity reference: python-final:src/ssh_manager/platforms/windows.py, which
// Python covered in tests/test_windows.py. These run on every platform: what is
// worth checking is which commands get built and who they name, and that is
// decidable without Windows. The exec wiring itself is exercised by the Windows
// leg of CI - see MIGRATION_PLAN.md's coverage limits.

func TestACLOwnerPrefersUSERNAMEThenTheCurrentUser(t *testing.T) {
	current := func() (*user.User, error) { return &user.User{Username: `DOMAIN\fallback`}, nil }

	if got := aclOwner(func(string) string { return "envuser" }, current); got != "envuser" {
		t.Errorf("owner = %q, want the USERNAME value", got)
	}
	if got := aclOwner(func(string) string { return "" }, current); got != `DOMAIN\fallback` {
		t.Errorf("owner = %q, want the current user when USERNAME is unset", got)
	}

	// Neither available: empty, so the caller can refuse rather than build an
	// icacls grant to nobody - which would strip inheritance and grant nothing.
	broken := func() (*user.User, error) { return nil, errors.New("no user") }
	if got := aclOwner(func(string) string { return "" }, broken); got != "" {
		t.Errorf("owner = %q, want empty when the user cannot be determined", got)
	}
}

// Order is the property: inheritance is dropped before the explicit grant, so
// there is no window where the file carries both the inherited ACEs and ours.
func TestICACLSDropsInheritanceBeforeGranting(t *testing.T) {
	required, optional := icaclsCommands(`C:\Users\me\.ssh\id`, "me")

	if len(required) != 2 {
		t.Fatalf("required = %v, want inheritance then grant", required)
	}
	if !contains(required[0], "/inheritance:r") {
		t.Errorf("first command should drop inheritance: %v", required[0])
	}
	if !contains(required[1], "/grant:r") || !contains(required[1], "me:F") {
		t.Errorf("second command should grant full control to the owner: %v", required[1])
	}
	for _, argv := range append(required, optional...) {
		if argv[0] != "icacls" {
			t.Errorf("argv[0] = %q, want icacls", argv[0])
		}
		if argv[1] != `C:\Users\me\.ssh\id` {
			t.Errorf("path argument = %q, want it passed through unmodified", argv[1])
		}
	}
}

// Every over-broad principal the Python listed is stripped, and each removal is
// optional - an ACE that is not present is a no-op, so a missing one must not
// fail the whole operation.
func TestICACLSStripsEveryBroadPrincipal(t *testing.T) {
	_, optional := icaclsCommands("p", "me")

	if len(optional) != len(broadPrincipals) {
		t.Fatalf("got %d removals for %d principals", len(optional), len(broadPrincipals))
	}
	for i, principal := range broadPrincipals {
		if !contains(optional[i], "/remove:g") || !contains(optional[i], principal) {
			t.Errorf("removal %d = %v, want /remove:g %s", i, optional[i], principal)
		}
	}
	for _, want := range []string{"Everyone", "Authenticated Users", "Users", `BUILTIN\Users`} {
		found := false
		for _, argv := range optional {
			if contains(argv, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not stripped; it would keep access to a private key", want)
		}
	}
}

// A path with spaces goes through as one argument. It is passed to exec as an
// argv element, never through a shell, so no quoting is applied or needed - and
// applying some would create a path that does not exist.
func TestPathsWithSpacesArePassedAsOneArgument(t *testing.T) {
	const path = `C:\Users\Imani Manyara\.ssh\profiles\work\key`
	required, _ := icaclsCommands(path, "Imani Manyara")

	if required[0][1] != path {
		t.Errorf("path = %q, want it verbatim", required[0][1])
	}
	if strings.Contains(required[0][1], `"`) {
		t.Error("the path should not be quoted; it is an argv element, not a shell word")
	}
	if !contains(required[1], "Imani Manyara:F") {
		t.Errorf("grant = %v, want the owner name unquoted", required[1])
	}
}

// Windows permissions are ACLs; a mode check would flag every file. Enforcement
// is the icacls call on write, so the check only asks whether the file is there.
func TestWindowsPermsOKOnlyChecksExistence(t *testing.T) {
	dir := t.TempDir()
	if !windowsPermsOK(dir) {
		t.Error("an existing directory should pass")
	}
	if windowsPermsOK(dir + "/definitely-not-here") {
		t.Error("a missing path should not pass")
	}
}

func contains(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}
