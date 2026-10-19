// Package pubkeys regenerates public keys from the key they belong to: the
// private key file for a key on disk (ssh-keygen -y), or the vault item for a
// key kept in 1Password. It repairs a missing or wrong .pub; it never creates
// or changes a private key - that is reconcile's and rotate's job.
package pubkeys

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/opstore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

// What happened to one key's .pub.
const (
	Unchanged = "unchanged" // already matched its key
	Created   = "created"   // was missing
	Rewritten = "rewritten" // did not match its key
	Skipped   = "skipped"   // nothing to derive it from, or needs a passphrase
	Failed    = "failed"
)

// Result is the outcome for one key.
type Result struct {
	Ref    manifest.KeyRef
	Action string
	Detail string
}

// Service regenerates public keys under one ~/.ssh.
type Service struct {
	m   *manifest.Manifest
	inv *inventory.Inventory
	ks  *keystore.KeyStore
	op  *opstore.Client
}

// New builds a Service.
func New(m *manifest.Manifest, inv *inventory.Inventory) *Service {
	return &Service{m: m, inv: inv, ks: keystore.New(), op: opstore.New()}
}

// Regenerate rebuilds the .pub of each row. With dryRun nothing is written and
// the inventory is left alone; the actions are what a real run would do.
func (s *Service) Regenerate(rows []keysvc.Row, dryRun bool) []Result {
	out := make([]Result, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.one(row, dryRun))
	}
	return out
}

func (s *Service) one(row keysvc.Row, dryRun bool) Result {
	res := Result{Ref: row.Ref}
	source, skip, err := s.source(row)
	switch {
	case err != nil:
		res.Action, res.Detail = Failed, err.Error()
		return res
	case skip != "":
		res.Action, res.Detail = Skipped, skip
		return res
	}

	current := ""
	if b, err := os.ReadFile(row.PublicPath); err == nil {
		current = strings.TrimSpace(string(b))
	}
	if current != "" && authkeys.KeyBody(current) == authkeys.KeyBody(source) {
		res.Action = Unchanged
		return res
	}
	res.Action = Created
	if current != "" {
		res.Action = Rewritten
		res.Detail = "the .pub on disk was a different key; anything deployed from it " +
			"needs `sshmgr deploy " + row.Ref.String() + "`"
	}
	if dryRun {
		return res
	}
	if err := fs.WriteTextAtomic(row.PublicPath, withComment(source, current, row)+"\n", perms.PublicKeyMode); err != nil {
		res.Action, res.Detail = Failed, err.Error()
		return res
	}
	s.rekey(row)
	return res
}

// source is the public key the row's key really has, or why there is none.
func (s *Service) source(row keysvc.Row) (pub, skip string, err error) {
	if row.InOnePassword() {
		it, err := s.op.Get(row.Vault, row.Ref.KeyName)
		switch {
		case errors.Is(err, opstore.ErrNotFound):
			return "", fmt.Sprintf("no item %q in 1Password vault %q (`sshmgr reconcile` creates it)",
				row.Ref.KeyName, row.Vault), nil
		case err != nil:
			return "", "", err
		case it.PublicKey == "":
			return "", "", fmt.Errorf("1Password item %q has no public key", row.Ref.KeyName)
		}
		return it.PublicKey, "", nil
	}
	if !row.PrivateOnDisk {
		return "", "the private key is missing, so there is nothing to derive from " +
			"(`sshmgr reconcile` mints a new pair)", nil
	}
	derived, encrypted, err := s.ks.PublicFromPrivate(row.PrivatePath)
	switch {
	case err != nil:
		return "", "", err
	case encrypted:
		return "", "the private key has a passphrase; derive it by hand: ssh-keygen -y -f " +
			row.PrivatePath + " > " + row.PublicPath, nil
	case derived == "":
		return "", "", fmt.Errorf("%s is not a readable private key", row.PrivatePath)
	}
	return derived, "", nil
}

// withComment keeps the comment the old .pub carried (it names the profile and
// host), falling back to the source's own, then to the key reference.
func withComment(source, current string, row keysvc.Row) string {
	fields := strings.Fields(source)
	if len(fields) < 2 {
		return source
	}
	comment := ""
	if old := strings.Fields(current); len(old) > 2 {
		comment = strings.Join(old[2:], " ")
	} else if len(fields) > 2 {
		comment = strings.Join(fields[2:], " ")
	} else {
		comment = row.Ref.String()
	}
	return fields[0] + " " + fields[1] + " " + comment
}

// rekey moves the key's inventory record to the fingerprint of the regenerated
// .pub. The record is keyed by fingerprint, and a wrong .pub had recorded the
// wrong one - which made expiry and deployments describe a key that is not the
// one in use.
func (s *Service) rekey(row keysvc.Row) {
	fp, err := s.ks.Fingerprint(row.PublicPath)
	if err != nil || fp == "" {
		return
	}
	for old, rec := range s.inv.Keys {
		if rec.Path == row.IdentityFile && old != fp {
			delete(s.inv.Keys, old)
			s.inv.Keys[fp] = rec
			return
		}
	}
}

// Format renders results, one line per key, then a tally.
func Format(results []Result, dryRun bool) string {
	var b strings.Builder
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Action]++
		fmt.Fprintf(&b, "%-9s %s", r.Action, r.Ref)
		if r.Detail != "" {
			fmt.Fprintf(&b, " - %s", r.Detail)
		}
		b.WriteString("\n")
	}
	prefix := ""
	if dryRun {
		prefix = "(dry run) "
	}
	fmt.Fprintf(&b, "%s%d key(s): %d unchanged, %d created, %d rewritten, %d skipped, %d failed",
		prefix, len(results), counts[Unchanged], counts[Created], counts[Rewritten], counts[Skipped], counts[Failed])
	return b.String()
}
