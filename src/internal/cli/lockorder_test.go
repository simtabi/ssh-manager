package cli

import (
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/lock"
)

// The advisory lock only serializes commands if it is taken before they read
// state. keygen (like rotate, deploy, reconcile and clean) loaded the inventory
// first and only then blocked on the lock, so it saved a copy from before the
// other command's change and silently dropped that change. Here the test holds
// the lock, starts keygen, writes a record while keygen waits, then releases:
// the record must survive keygen's save.
func TestAMutatingCommandReadsStateOnlyAfterTakingTheLock(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "w")
	run(t, "host", "add", "w", "a", "-H", "a.example", "-u", "u")
	run(t, "reconcile", "--yes", "--no-pin")
	run(t, "host", "add", "w", "b", "-H", "b.example", "-u", "u")
	mutation.Release() // the setup commands took it; release it for the test to hold

	release, err := lock.Acquire(p.LockFile())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := runErr(t, "keygen", "w", "--yes", "--no-pin")
		done <- err
	}()
	time.Sleep(400 * time.Millisecond) // keygen is now waiting on the lock

	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	var some inventory.KeyRecord
	for _, r := range inv.Keys {
		some = r
	}
	inv.Keys["SHA256:written-while-keygen-waited"] = some
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
	release()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("keygen never finished")
	}
	after, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Keys["SHA256:written-while-keygen-waited"]; !ok {
		t.Error("keygen saved an inventory read before it held the lock, dropping a concurrent change")
	}
}

// `rotate <profile>` and `rotate <alias>` are in the usage line and work under
// --dry-run, but one argument went to the single-key path, which only accepts
// a key name, so the real run failed with "no such key". And a rollback that
// did not complete exited 0, so a script could not tell it had not happened.
func TestRotateTakesAProfileOrAliasAndRollbackFailsWhenIncomplete(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "w")
	run(t, "host", "add", "w", "panel", "-H", "panel.example", "-u", "u", "--provider", "ploi")
	run(t, "reconcile", "--yes", "--no-pin")
	for _, sel := range []string{"w", "panel"} {
		if out, err := runErr(t, "rotate", sel, "--yes", "--no-key-backup", "--allow-unverified"); err != nil {
			t.Errorf("rotate %s: %v\n%s", sel, err, out)
		}
	}
	// A server the rollback cannot reach: nothing changes, and it must fail.
	run(t, "host", "add", "w", "box", "-H", "nohost.invalid", "-u", "u", "--key-name", "w_panel-ed25519")
	if _, err := runErr(t, "rollback", "w/w_panel-ed25519", "--yes"); err == nil {
		t.Error("a rollback that reached no server exited 0")
	}
}
