// Package opstore keeps SSH keys as items in 1Password, through the op CLI.
//
// The private key is generated inside 1Password and never written to disk:
// sshmgr only ever reads an item's public key back. Items are found by title
// (the key name) and then addressed by ID, so an edit or an archive cannot land
// on a different item that happens to share a title.
package opstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Item is the part of a 1Password SSH Key item sshmgr uses.
type Item struct {
	ID          string
	Title       string
	Vault       string
	PublicKey   string // OpenSSH one-line form
	Fingerprint string // as 1Password reports it; may be empty
}

// ErrNotFound means no item in the vault has the title.
var ErrNotFound = errors.New("not found in 1Password")

// Client runs the op CLI. Bin is "op" unless a test points it elsewhere.
type Client struct {
	Bin     string
	Timeout time.Duration
}

// New returns a client for the op on PATH.
func New() *Client { return &Client{Bin: "op", Timeout: 60 * time.Second} }

// Available reports why op cannot be used, or nil.
func (c *Client) Available() error {
	if _, err := exec.LookPath(c.Bin); err != nil {
		return fmt.Errorf("the 1Password CLI (op) is not on PATH: install it and sign in " +
			"(https://developer.1password.com/docs/cli/get-started/)")
	}
	return nil
}

// Create generates a new Ed25519 SSH key item titled title in vault and
// returns it. The private key stays in 1Password.
func (c *Client) Create(vault, title string) (Item, error) {
	if err := c.Available(); err != nil {
		return Item{}, err
	}
	// No --ssh-generate-key: Ed25519 is op's default, and the flag's documented
	// form is only shown for RSA.
	out, err := c.run("item", "create", "--category", "ssh", "--title", title,
		"--vault", vault, "--format", "json")
	if err != nil {
		return Item{}, fmt.Errorf("op item create %q in vault %q: %w", title, vault, err)
	}
	it, err := parseItem(out)
	if err != nil {
		return Item{}, err
	}
	if it.PublicKey == "" {
		return Item{}, fmt.Errorf("op created %q but returned no public key", title)
	}
	return it, nil
}

// Get returns the item titled title in vault, or ErrNotFound.
func (c *Client) Get(vault, title string) (Item, error) {
	if err := c.Available(); err != nil {
		return Item{}, err
	}
	out, err := c.run("item", "get", title, "--vault", vault, "--format", "json")
	if err != nil {
		if isNotFound(err) {
			return Item{}, fmt.Errorf("%q in vault %q: %w", title, vault, ErrNotFound)
		}
		return Item{}, fmt.Errorf("op item get %q in vault %q: %w", title, vault, err)
	}
	return parseItem(out)
}

// Rename retitles the item with id.
func (c *Client) Rename(vault, id, title string) error {
	if _, err := c.run("item", "edit", id, "--vault", vault, "--title", title); err != nil {
		return fmt.Errorf("op item edit %s --title %q: %w", id, title, err)
	}
	return nil
}

// Archive moves the item with id to 1Password's Archive, where it can still be
// restored. sshmgr never deletes an item outright.
func (c *Client) Archive(vault, id string) error {
	if _, err := c.run("item", "delete", id, "--vault", vault, "--archive"); err != nil {
		return fmt.Errorf("op item delete %s --archive: %w", id, err)
	}
	return nil
}

func (c *Client) run(args ...string) ([]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return stdout.Bytes(), nil
}

// isNotFound reports op's own wording for a missing item ("\"x\" isn't an item
// in the \"V\" vault"), and nothing broader. A looser match also caught a
// missing vault ("isn't a vault"), a missing account and similar failures, which
// reconcile then answered by trying to create the item.
func isNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "isn't an item")
}

// parseItem reads the fields sshmgr needs from `op item ... --format json`.
// The public key field is matched by id or by label, because 1Password
// documents neither, and both have been seen as "public_key" / "public key".
func parseItem(raw []byte) (Item, error) {
	var doc struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Vault struct {
			Name string `json:"name"`
		} `json:"vault"`
		Fields []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Item{}, fmt.Errorf("unexpected op output: %w", err)
	}
	it := Item{ID: doc.ID, Title: doc.Title, Vault: doc.Vault.Name}
	for _, f := range doc.Fields {
		switch norm(f.ID, f.Label) {
		case "publickey":
			it.PublicKey = strings.TrimSpace(f.Value)
		case "fingerprint":
			it.Fingerprint = strings.TrimSpace(f.Value)
		}
	}
	return it, nil
}

func norm(id, label string) string {
	for _, s := range []string{id, label} {
		k := strings.NewReplacer("_", "", " ", "", "-", "").Replace(strings.ToLower(s))
		if k == "publickey" || k == "fingerprint" {
			return k
		}
	}
	return ""
}
