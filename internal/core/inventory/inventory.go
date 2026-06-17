// Package inventory is the deployment-tracking model, ported from
// src/ssh_manager/core/inventory.py. Keyed by SHA256 fingerprint, it turns
// rotation into a checklist and is persisted atomically.
package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const schemaVersion = 1

const dateLayout = "2006-01-02"

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Deployment records a key installed on one target.
type Deployment struct {
	Target   string  `json:"target"`
	Method   string  `json:"method"` // ssh-copy-id | web-panel | manual | <adapter>
	Date     *string `json:"date"`
	Verified bool    `json:"verified"` // false == needs-redeploy
}

func (d *Deployment) UnmarshalJSON(b []byte) error {
	type alias Deployment
	var aux alias
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*d = Deployment(aux)
	return nil
}

// KeyRecord is one managed key and where it is deployed. All fields serialize
// unconditionally (null for an unset pointer, [] for no deployments) to match
// pydantic's model_dump(mode="json") byte-for-byte.
type KeyRecord struct {
	Profile         string       `json:"profile"`
	Path            string       `json:"path"`
	Type            string       `json:"type"`
	Comment         *string      `json:"comment"`
	Created         *string      `json:"created"`
	RotateAfterDays int          `json:"rotate_after_days"`
	ExpiresOn       *string      `json:"expires_on"`
	Deployments     []Deployment `json:"deployments"`
}

func (r *KeyRecord) UnmarshalJSON(b []byte) error {
	type alias KeyRecord
	aux := alias{Type: "ed25519", RotateAfterDays: 365}
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*r = KeyRecord(aux)
	return nil
}

// MarshalJSON emits a nil Deployments slice as [] (not null), matching pydantic's
// default_factory=list. The pointer fields already emit null when unset.
func (r KeyRecord) MarshalJSON() ([]byte, error) {
	type alias KeyRecord
	a := alias(r)
	if a.Deployments == nil {
		a.Deployments = []Deployment{}
	}
	return json.Marshal(a)
}

// NeedsRedeploy is true when no deployment is verified (e.g. a fresh key).
func (r KeyRecord) NeedsRedeploy() bool {
	for _, d := range r.Deployments {
		if d.Verified {
			return false
		}
	}
	return true
}

// Inventory is the whole inventory, keyed by fingerprint.
type Inventory struct {
	Version int                  `json:"version"`
	Keys    map[string]KeyRecord `json:"keys"`
}

func (inv *Inventory) UnmarshalJSON(b []byte) error {
	type alias Inventory
	aux := alias{Version: schemaVersion, Keys: map[string]KeyRecord{}}
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*inv = Inventory(aux)
	return nil
}

// New returns an empty inventory.
func New() *Inventory { return &Inventory{Version: schemaVersion, Keys: map[string]KeyRecord{}} }

// Load reads an inventory; a missing file yields an empty inventory (matching v1).
func Load(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, fmt.Errorf("inventory could not be read: %s: %w", path, err)
	}
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("inventory failed validation: %s: %w", path, err)
	}
	if inv.Keys == nil {
		inv.Keys = map[string]KeyRecord{}
	}
	return &inv, nil
}

// Save writes the inventory as indented JSON.
func (inv *Inventory) Save(path string) error {
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Record stores a key record under its fingerprint.
func (inv *Inventory) Record(fingerprint string, rec KeyRecord) {
	if inv.Keys == nil {
		inv.Keys = map[string]KeyRecord{}
	}
	inv.Keys[fingerprint] = rec
}

// IsArchivedPath reports whether path is a rotation's /old/ predecessor slot,
// i.e. .../profiles/<profile>/old/<key_name> (by structure, so a profile literally
// named "old" is not mistaken for an archived key).
func IsArchivedPath(path string) bool {
	parts := strings.Split(path, "/")
	n := len(parts)
	return n >= 4 && parts[n-2] == "old" && parts[n-4] == "profiles"
}

// ComputeExpiry returns created (YYYY-MM-DD) + rotateAfterDays as YYYY-MM-DD.
func ComputeExpiry(created string, rotateAfterDays int) (string, error) {
	base, err := time.Parse(dateLayout, created)
	if err != nil {
		return "", err
	}
	return base.AddDate(0, 0, rotateAfterDays).Format(dateLayout), nil
}

// Today returns today's date as YYYY-MM-DD.
func Today() string { return time.Now().Format(dateLayout) }
