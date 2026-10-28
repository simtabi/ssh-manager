package change

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// SnapshotRestore is `sshmgr snapshots restore <id> --yes`: put back the
// config, known_hosts and public keys a snapshot holds, after snapshotting
// ~/.ssh as it is now. snapshotsDir is the real home's: a preview restores from
// it into the copy, where it has no snapshot of its own to take, and apply
// restores into the home through the same function the CLI uses.
//
// A snapshot written before private keys were left out is refused, as the
// snapshot page refuses to open one: restoring it would put plaintext private
// keys back on disk from an archive nobody can see into here.
func SnapshotRestore(snapshotsDir, id string, retain int) Change {
	return Change{
		Command: "snapshots restore", Args: []string{id, "--yes"}, NoSnapshot: true,
		Effects: func(p paths.Paths) ([]string, error) {
			if id == "" {
				return nil, errors.New("name the snapshot to restore")
			}
			path, err := snapshots.Find(snapshotsDir, id)
			if err != nil {
				return nil, err
			}
			name := filepath.Base(path)
			if snapshots.HoldsKeyMaterial(path) {
				return nil, fmt.Errorf("%s holds private keys from before snapshots left them out; restore it "+
					"from a terminal with `sshmgr snapshots restore %s`, or remove it with `sshmgr snapshots prune`", name, name)
			}
			// Naming the file binds the confirmation to it: a partial id that
			// would pick a newer snapshot by apply time shows as a change.
			return []string{"restores " + name,
				"snapshots ~/.ssh as it is now first, so the restore itself can be undone"}, nil
		},
		Run: func(p paths.Paths, out io.Writer) error {
			var res snapshots.Result
			var err error
			if p.SnapshotsDir() == snapshotsDir {
				res, err = snapshots.RestoreByIDIn(p, retain, id)
			} else {
				res, err = snapshots.RestoreInto(p.SSHDir, snapshotsDir, p.DevRoot, id)
			}
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(out, "restored from %s\n", filepath.Base(res.Snapshot))
			for _, s := range res.Skipped {
				_, _ = fmt.Fprintf(out, "kept %s: the snapshot's copy does not match the private key on disk\n", s)
			}
			return nil
		},
	}
}
