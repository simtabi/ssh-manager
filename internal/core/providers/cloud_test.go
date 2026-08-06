package providers

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Parity reference: python-final:tests/test_cloud_providers.py. That file pinned
// the orchestration rules these adapters share - idempotent deploy, rename our
// own stale title but never a user's label, find-by-body for verify and remove -
// by faking the HTTP layer. The Go design makes that cleaner: restProvider holds
// a restOps interface, so the rules can be tested with no HTTP at all, and HTTP
// is tested separately against a real server.

// pubKey builds a valid public key line; the body is the identity these adapters
// match on, so it has to parse as a real wire blob.
func pubKey(tag string) string {
	payload := []byte(strings.Repeat(tag, 32))[:32]
	blob := binary.BigEndian.AppendUint32(nil, uint32(len("ssh-ed25519")))
	blob = append(blob, "ssh-ed25519"...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	blob = append(blob, payload...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " me@host"
}

// fakeOps records what the orchestration asked for, so a test can assert what
// did *not* happen as easily as what did.
type fakeOps struct {
	keys     []RemoteKey
	added    []string // titles
	deleted  []string // ids
	renamed  map[string]string
	listErr  error
	addErr   error
	renameOK bool
}

func newFakeOps(keys ...RemoteKey) *fakeOps {
	return &fakeOps{keys: keys, renamed: map[string]string{}, renameOK: true}
}

func (f *fakeOps) listKeys(string) ([]RemoteKey, error) { return f.keys, f.listErr }
func (f *fakeOps) addKey(_, name, _ string) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, name)
	return nil
}
func (f *fakeOps) deleteKey(_, id string) error { f.deleted = append(f.deleted, id); return nil }
func (f *fakeOps) renameKey(_, id, name string) (bool, error) {
	f.renamed[id] = name
	return f.renameOK, nil
}

func testTarget(t *testing.T, pub string) Target {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(path, []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Target{Alias: "droplet", Hostname: "1.2.3.4", User: "root",
		PubkeyPath: path, PubkeyText: pub}
}

func testProvider(ops restOps) restProvider {
	return restProvider{className: "digitalocean", defaultEnv: "DIGITALOCEAN_TOKEN",
		dashboard: "https://example.invalid/keys", ops: ops}
}

func TestDeployAddsAKeyThatIsNotThere(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "tok")
	ops := newFakeOps()
	out := testProvider(ops).Deploy(testTarget(t, pubKey("a")))

	if !out.Verified || out.Error {
		t.Fatalf("deploy should succeed: %+v", out)
	}
	if out.Method != "digitalocean-api" {
		t.Errorf("method = %q, want the adapter's own name", out.Method)
	}
	if len(ops.added) != 1 || !strings.HasPrefix(ops.added[0], "ssh-manager ") {
		t.Errorf("added %v, want one key titled by us", ops.added)
	}
}

// Deploying a key the account already has is a no-op, however it is labelled.
func TestDeployIsIdempotent(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "tok")
	pub := pubKey("b")
	ops := newFakeOps(RemoteKey{ID: "9", Name: "ssh-manager k.pub", Body: pub})

	out := testProvider(ops).Deploy(testTarget(t, pub))
	if !out.Verified {
		t.Fatalf("an already-present key is a success: %+v", out)
	}
	if len(ops.added) != 0 {
		t.Errorf("added %v; a key already on the account must not be duplicated", ops.added)
	}
}

// The two title rules, which are the ones a user would notice going wrong.
func TestDeployRenamesOurStaleTitleButNeverAUserLabel(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "tok")
	pub := pubKey("c")

	t.Run("a title the old sshmgr wrote is ours to fix", func(t *testing.T) {
		ops := newFakeOps(RemoteKey{ID: "9", Name: "sshmgr old.pub", Body: pub})
		out := testProvider(ops).Deploy(testTarget(t, pub))

		if !out.Verified || !strings.Contains(out.Detail, "renamed") {
			t.Fatalf("we should recognise and re-title our own key: %+v", out)
		}
		if got := ops.renamed["9"]; !strings.HasPrefix(got, "ssh-manager ") {
			t.Errorf("renamed to %q, want the current title format", got)
		}
		if len(ops.added) != 0 {
			t.Error("renaming must not also add a duplicate")
		}
	})

	t.Run("a label the user chose is left alone", func(t *testing.T) {
		ops := newFakeOps(RemoteKey{ID: "9", Name: "my-laptop-key", Body: pub})
		out := testProvider(ops).Deploy(testTarget(t, pub))

		if !out.Verified || !strings.Contains(out.Detail, "already present") {
			t.Fatalf("an existing key is still a success: %+v", out)
		}
		if len(ops.renamed) != 0 {
			t.Errorf("renamed %v; a label the user chose is not ours to overwrite", ops.renamed)
		}
		if len(ops.added) != 0 {
			t.Error("must not add a duplicate")
		}
	})
}

// Matching is by key body, so a different comment or label is still the same key
// - which is what makes deploy idempotent and remove reliable.
func TestVerifyAndRemoveMatchOnBodyNotLabel(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "tok")
	pub := pubKey("d")
	body := strings.Fields(pub)[1]
	// Same body, different comment and a label of the user's choosing.
	remote := "ssh-ed25519 " + body + " someone-else@elsewhere"
	ops := newFakeOps(RemoteKey{ID: "42", Name: "unrelated label", Body: remote})
	p := testProvider(ops)
	target := testTarget(t, pub)

	if !p.Verify(target) {
		t.Error("a key present under another label should still verify")
	}
	if !p.Remove(target) {
		t.Error("remove should find the key by body")
	}
	if len(ops.deleted) != 1 || ops.deleted[0] != "42" {
		t.Errorf("deleted %v, want the matching key's id", ops.deleted)
	}

	// A key that is not on the account verifies false and removes nothing.
	empty := newFakeOps()
	p2 := testProvider(empty)
	if p2.Verify(target) {
		t.Error("an absent key should not verify")
	}
	if len(empty.deleted) != 0 {
		t.Errorf("deleted %v from an empty account", empty.deleted)
	}
}

// With no token there is nothing to authenticate with, so the adapter degrades
// to telling the user where to paste it rather than failing.
func TestNoTokenFallsBackToManual(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	ops := newFakeOps()
	out := testProvider(ops).Deploy(testTarget(t, pubKey("e")))

	if out.Method != "manual" {
		t.Errorf("method = %q, want a manual fallback", out.Method)
	}
	if out.Error {
		t.Error("a missing token is not an error; it is a different route")
	}
	if len(ops.added) != 0 {
		t.Error("nothing should have been sent without a token")
	}
}

// A failing API is reported, not swallowed into a false success.
func TestAPIFailuresSurface(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "tok")
	target := testTarget(t, pubKey("f"))

	listBroken := newFakeOps()
	listBroken.listErr = &HTTPStub{"401 unauthorized"}
	if out := testProvider(listBroken).Deploy(target); !out.Error {
		t.Errorf("a failed list should be an error: %+v", out)
	}
	addBroken := newFakeOps()
	addBroken.addErr = &HTTPStub{"422 already exists"}
	if out := testProvider(addBroken).Deploy(target); !out.Error {
		t.Errorf("a failed add should be an error: %+v", out)
	}
	// Verify cannot distinguish "absent" from "API down", and answers false -
	// the safe direction, since a false true would skip a needed deploy.
	if testProvider(listBroken).Verify(target) {
		t.Error("verify should be false when the account cannot be listed")
	}
}

// HTTPStub is a minimal error for the fake ops.
type HTTPStub struct{ msg string }

func (e *HTTPStub) Error() string { return e.msg }

// The field names each provider uses. This is the mapping most likely to be
// wrong in a port nobody has run against a live API, and it is invisible until
// a real account returns keys the adapter then fails to see.
func TestPerProviderResponseShapes(t *testing.T) {
	cases := []struct {
		provider          string
		listField         string
		idF, nameF, bodyF string
		payload           string
	}{
		{"digitalocean", "ssh_keys", "id", "name", "public_key",
			`{"ssh_keys":[{"id":7,"name":"laptop","public_key":"ssh-ed25519 AAAA x"}]}`},
		{"vultr", "ssh_keys", "id", "name", "ssh_key",
			`{"ssh_keys":[{"id":"abc","name":"laptop","ssh_key":"ssh-ed25519 AAAA x"}]}`},
		{"hetzner", "ssh_keys", "id", "name", "public_key",
			`{"ssh_keys":[{"id":12,"name":"laptop","public_key":"ssh-ed25519 AAAA x"}]}`},
		{"linode", "data", "id", "label", "ssh_key",
			`{"data":[{"id":3,"label":"laptop","ssh_key":"ssh-ed25519 AAAA x"}]}`},
	}
	for _, c := range cases {
		t.Run(c.provider, func(t *testing.T) {
			var data map[string]any
			if err := json.Unmarshal([]byte(c.payload), &data); err != nil {
				t.Fatal(err)
			}
			keys := remoteKeys(arr(data[c.listField]), c.idF, c.nameF, c.bodyF)
			if len(keys) != 1 {
				t.Fatalf("parsed %d keys from a one-key response: %+v", len(keys), keys)
			}
			if keys[0].ID == "" {
				t.Error("id did not map; deleting and renaming both need it")
			}
			if keys[0].Name != "laptop" {
				t.Errorf("name = %q", keys[0].Name)
			}
			if !strings.HasPrefix(keys[0].Body, "ssh-ed25519 ") {
				t.Errorf("body = %q; without it nothing matches by key", keys[0].Body)
			}
		})
	}
}

// A numeric id must survive as a string. JSON numbers decode to float64, so a
// large id rendered through %v would become scientific notation and produce a
// URL like /account/keys/1.234568e+08.
func TestNumericIDsDoNotBecomeScientificNotation(t *testing.T) {
	var data map[string]any
	if err := json.Unmarshal([]byte(`{"ssh_keys":[{"id":123456789,"name":"n","public_key":"p"}]}`), &data); err != nil {
		t.Fatal(err)
	}
	keys := remoteKeys(arr(data["ssh_keys"]), "id", "name", "public_key")
	if len(keys) != 1 || keys[0].ID != "123456789" {
		t.Fatalf("id = %q, want the exact digits", keys[0].ID)
	}
}

// The whole request path for one adapter, over a real server: URL, method, auth
// header, pagination, and the JSON round trip. The other adapters share this
// code; what differs between them is the field mapping, covered above.
func TestDigitalOceanOverHTTP(t *testing.T) {
	page2 := "" // filled once the server is up
	var gotAuth, gotPath, gotMethod string
	var posted map[string]any

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/v2/account/keys", func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotMethod = r.Header.Get("Authorization"), r.Method
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// First page points at a second, to prove pagination is followed.
		_, _ = w.Write([]byte(`{"ssh_keys":[{"id":1,"name":"first","public_key":"ssh-ed25519 AAAA a"}],
		                       "links":{"pages":{"next":"` + page2 + `"}}}`))
	})
	mux.HandleFunc("/v2/page2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ssh_keys":[{"id":2,"name":"second","public_key":"ssh-ed25519 AAAA b"}],"links":{}}`))
	})
	page2 = srv.URL + "/v2/page2"

	old := doBase
	doBase = srv.URL + "/v2"
	defer func() { doBase = old }()

	keys, err := doOps{}.listKeys("tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want both pages: %+v", len(keys), keys)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotMethod != http.MethodGet || !strings.Contains(gotPath, "per_page=200") {
		t.Errorf("listed with %s %s", gotMethod, gotPath)
	}

	if err := (doOps{}).addKey("tok", "ssh-manager k.pub", "ssh-ed25519 AAAA x"); err != nil {
		t.Fatal(err)
	}
	if posted["name"] != "ssh-manager k.pub" || posted["public_key"] != "ssh-ed25519 AAAA x" {
		t.Errorf("POST body = %v; DigitalOcean expects name + public_key", posted)
	}
}

// Pagination that never terminates is an error rather than an endless loop
// against someone's account.
func TestPaginationIsBounded(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ssh_keys":[],"links":{"pages":{"next":"` + srv.URL + `/v2/loop"}}}`))
	}))
	defer srv.Close()

	old := doBase
	doBase = srv.URL + "/v2"
	defer func() { doBase = old }()

	if _, err := (doOps{}).listKeys("tok"); err == nil {
		t.Error("a self-referential next link should stop with an error")
	} else if !strings.Contains(err.Error(), "pagination") {
		t.Errorf("error should name the cause: %v", err)
	}
}
