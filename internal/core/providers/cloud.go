package providers

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/internal/util/httpjson"
	"github.com/simtabi/ssh-manager/internal/util/secrets"
)

const maxPages = 50

// restOps is the per-provider key API (list/add/delete/rename). Mirrors the
// RestVpsProvider subclass interface.
type restOps interface {
	listKeys(token string) ([]RemoteKey, error)
	addKey(token, name, publicKey string) error
	deleteKey(token, id string) error
	renameKey(token, id, name string) (bool, error)
}

// restProvider manages account keys over a provider REST API (category vps).
// Ports cloud.RestVpsProvider's shared deploy/verify/remove/rename orchestration.
type restProvider struct {
	spec       Spec
	className  string // default name when the spec doesn't set one
	defaultEnv string
	dashboard  string
	ops        restOps
}

func (r restProvider) Name() string {
	if r.spec.Name != "" {
		return r.spec.Name
	}
	return r.className
}
func (r restProvider) Category() string {
	if r.spec.Category != "" {
		return r.spec.Category
	}
	return "vps"
}

func (r restProvider) token(t Target) string {
	v := firstNonEmpty(t.TokenEnv, r.spec.TokenEnv, r.defaultEnv)
	if v == "" {
		return ""
	}
	return secrets.Resolve(os.Getenv(v))
}

func (r restProvider) ManageURL(Target) string {
	if u := r.spec.ResolvedKeysURL(); u != "" {
		return u
	}
	return r.dashboard
}

func keyTitle(filename, body string) string {
	if body == "" {
		return "ssh-manager " + filename
	}
	frag := body
	if len(frag) > 12 {
		frag = frag[:12]
	}
	return "ssh-manager " + filename + " " + frag
}

func (r restProvider) Deploy(t Target) DeployOutcome {
	token := r.token(t)
	if token == "" {
		return manual(r.ManageURL(t), t)
	}
	want := authkeys.KeyBody(t.PubkeyText)
	title := keyTitle(baseName(t.PubkeyPath), want)
	method := r.Name() + "-api"
	keys, err := r.ops.listKeys(token)
	if err != nil {
		return DeployOutcome{Method: method, Detail: err.Error(), Error: true}
	}
	for _, k := range keys {
		if k.Body == "" || authkeys.KeyBody(k.Body) != want {
			continue
		}
		owned := strings.HasPrefix(k.Name, "ssh-manager ") || strings.HasPrefix(k.Name, "sshmgr ")
		if k.Name != title && owned {
			if ok, _ := r.ops.renameKey(token, k.ID, title); ok {
				return DeployOutcome{Method: method, Verified: true, Detail: "already present; renamed to '" + title + "'"}
			}
		}
		return DeployOutcome{Method: method, Verified: true, Detail: "already present (as '" + k.Name + "')"}
	}
	if err := r.ops.addKey(token, title, strings.TrimSpace(t.PubkeyText)); err != nil {
		return DeployOutcome{Method: method, Detail: err.Error(), Error: true}
	}
	return DeployOutcome{Method: method, Verified: true, Detail: "added to " + r.Name() + " account as '" + title + "'"}
}

func (r restProvider) Verify(t Target) bool {
	token := r.token(t)
	if token == "" {
		return false
	}
	want := authkeys.KeyBody(t.PubkeyText)
	keys, err := r.ops.listKeys(token)
	if err != nil {
		return false
	}
	for _, k := range keys {
		if k.Body != "" && authkeys.KeyBody(k.Body) == want {
			return true
		}
	}
	return false
}

func (r restProvider) ListDeployed(t Target) []string {
	token := r.token(t)
	if token == "" {
		return nil
	}
	keys, err := r.ops.listKeys(token)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Name)
	}
	return out
}

func (r restProvider) Remove(t Target) bool {
	token := r.token(t)
	if token == "" {
		return false
	}
	want := authkeys.KeyBody(t.PubkeyText)
	keys, err := r.ops.listKeys(token)
	if err != nil {
		return false
	}
	for _, k := range keys {
		if k.Body != "" && authkeys.KeyBody(k.Body) == want {
			return r.ops.deleteKey(token, k.ID) == nil
		}
	}
	return false
}

func (r restProvider) Rename(t Target, newTitle string) bool {
	token := r.token(t)
	if token == "" {
		return false
	}
	want := authkeys.KeyBody(t.PubkeyText)
	keys, err := r.ops.listKeys(token)
	if err != nil {
		return false
	}
	for _, k := range keys {
		if k.Body != "" && authkeys.KeyBody(k.Body) == want {
			ok, _ := r.ops.renameKey(token, k.ID, newTitle)
			return ok
		}
	}
	return false
}

// --- HTTP + JSON helpers ---------------------------------------------------

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func get(headers map[string]string, u string) (map[string]any, error) {
	data, err := httpjson.RequestJSON("GET", u, headers, nil)
	if err != nil {
		return nil, err
	}
	m, _ := data.(map[string]any)
	return m, nil
}

func paginationError() error {
	return fmt.Errorf("pagination did not terminate after %d pages", maxPages)
}

func arr(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// jsonID stringifies an id that may be a JSON number or string.
func jsonID(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}

// dig walks a dotted path into nested maps. Mirrors cloud._dig.
func dig(m any, parts ...string) any {
	cur := m
	for _, p := range parts {
		cm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = cm[p]
	}
	return cur
}

func remoteKeys(items []any, idF, nameF, bodyF string) []RemoteKey {
	out := make([]RemoteKey, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, RemoteKey{ID: jsonID(m[idF]), Name: str(m[nameF]), Body: str(m[bodyF])})
	}
	return out
}

// --- DigitalOcean ----------------------------------------------------------

const doBase = "https://api.digitalocean.com/v2"

type doOps struct{}

func newDigitalOcean(spec Spec) Provider {
	return restProvider{spec: spec, className: "digitalocean", defaultEnv: "DIGITALOCEAN_TOKEN",
		dashboard: "https://cloud.digitalocean.com/account/security", ops: doOps{}}
}
func (doOps) listKeys(token string) ([]RemoteKey, error) {
	var out []RemoteKey
	u := doBase + "/account/keys?per_page=200"
	for i := 0; i < maxPages && u != ""; i++ {
		data, err := get(bearer(token), u)
		if err != nil {
			return nil, err
		}
		out = append(out, remoteKeys(arr(data["ssh_keys"]), "id", "name", "public_key")...)
		u = str(dig(data, "links", "pages", "next"))
	}
	if u != "" {
		return nil, paginationError()
	}
	return out, nil
}
func (doOps) addKey(token, name, pub string) error {
	_, err := httpjson.RequestJSON("POST", doBase+"/account/keys", bearer(token), map[string]any{"name": name, "public_key": pub})
	return err
}
func (doOps) deleteKey(token, id string) error {
	_, err := httpjson.RequestJSON("DELETE", doBase+"/account/keys/"+id, bearer(token), nil)
	return err
}
func (doOps) renameKey(token, id, name string) (bool, error) {
	_, err := httpjson.RequestJSON("PUT", doBase+"/account/keys/"+id, bearer(token), map[string]any{"name": name})
	return err == nil, err
}

// --- Vultr -----------------------------------------------------------------

const vultrBase = "https://api.vultr.com/v2"

type vultrOps struct{}

func newVultr(spec Spec) Provider {
	return restProvider{spec: spec, className: "vultr", defaultEnv: "VULTR_API_KEY",
		dashboard: "https://my.vultr.com/settings/#settingssshkeys", ops: vultrOps{}}
}
func (vultrOps) listKeys(token string) ([]RemoteKey, error) {
	var out []RemoteKey
	u := vultrBase + "/ssh-keys?per_page=500"
	for i := 0; i < maxPages && u != ""; i++ {
		data, err := get(bearer(token), u)
		if err != nil {
			return nil, err
		}
		out = append(out, remoteKeys(arr(data["ssh_keys"]), "id", "name", "ssh_key")...)
		nxt := str(dig(data, "meta", "links", "next"))
		if nxt != "" {
			u = vultrBase + "/ssh-keys?per_page=500&cursor=" + url.QueryEscape(nxt)
		} else {
			u = ""
		}
	}
	if u != "" {
		return nil, paginationError()
	}
	return out, nil
}
func (vultrOps) addKey(token, name, pub string) error {
	_, err := httpjson.RequestJSON("POST", vultrBase+"/ssh-keys", bearer(token), map[string]any{"name": name, "ssh_key": pub})
	return err
}
func (vultrOps) deleteKey(token, id string) error {
	_, err := httpjson.RequestJSON("DELETE", vultrBase+"/ssh-keys/"+id, bearer(token), nil)
	return err
}
func (vultrOps) renameKey(token, id, name string) (bool, error) {
	_, err := httpjson.RequestJSON("PATCH", vultrBase+"/ssh-keys/"+id, bearer(token), map[string]any{"name": name})
	return err == nil, err
}

// --- Hetzner ---------------------------------------------------------------

const hetznerBase = "https://api.hetzner.cloud/v1"

type hetznerOps struct{}

func newHetzner(spec Spec) Provider {
	return restProvider{spec: spec, className: "hetzner", defaultEnv: "HCLOUD_TOKEN",
		dashboard: "https://console.hetzner.cloud/", ops: hetznerOps{}}
}
func (hetznerOps) listKeys(token string) ([]RemoteKey, error) {
	var out []RemoteKey
	u := hetznerBase + "/ssh_keys?per_page=50"
	for i := 0; i < maxPages && u != ""; i++ {
		data, err := get(bearer(token), u)
		if err != nil {
			return nil, err
		}
		out = append(out, remoteKeys(arr(data["ssh_keys"]), "id", "name", "public_key")...)
		nxt := dig(data, "meta", "pagination", "next_page")
		if n := jsonID(nxt); n != "" && nxt != nil {
			u = hetznerBase + "/ssh_keys?per_page=50&page=" + n
		} else {
			u = ""
		}
	}
	if u != "" {
		return nil, paginationError()
	}
	return out, nil
}
func (hetznerOps) addKey(token, name, pub string) error {
	_, err := httpjson.RequestJSON("POST", hetznerBase+"/ssh_keys", bearer(token), map[string]any{"name": name, "public_key": pub})
	return err
}
func (hetznerOps) deleteKey(token, id string) error {
	_, err := httpjson.RequestJSON("DELETE", hetznerBase+"/ssh_keys/"+id, bearer(token), nil)
	return err
}
func (hetznerOps) renameKey(token, id, name string) (bool, error) {
	_, err := httpjson.RequestJSON("PUT", hetznerBase+"/ssh_keys/"+id, bearer(token), map[string]any{"name": name})
	return err == nil, err
}

// --- Linode ----------------------------------------------------------------

const linodeBase = "https://api.linode.com/v4"

type linodeOps struct{}

func newLinode(spec Spec) Provider {
	return restProvider{spec: spec, className: "linode", defaultEnv: "LINODE_TOKEN",
		dashboard: "https://cloud.linode.com/profile/keys", ops: linodeOps{}}
}
func (linodeOps) listKeys(token string) ([]RemoteKey, error) {
	var out []RemoteKey
	page, done := 1, false
	for i := 0; i < maxPages; i++ {
		data, err := get(bearer(token), fmt.Sprintf("%s/profile/sshkeys?page=%d&page_size=100", linodeBase, page))
		if err != nil {
			return nil, err
		}
		out = append(out, remoteKeys(arr(data["data"]), "id", "label", "ssh_key")...)
		pages := 1
		if p, ok := data["pages"].(float64); ok {
			pages = int(p)
		}
		if page >= pages {
			done = true
			break
		}
		page++
	}
	if !done {
		return nil, paginationError()
	}
	return out, nil
}
func (linodeOps) addKey(token, name, pub string) error {
	_, err := httpjson.RequestJSON("POST", linodeBase+"/profile/sshkeys", bearer(token), map[string]any{"label": name, "ssh_key": pub})
	return err
}
func (linodeOps) deleteKey(token, id string) error {
	_, err := httpjson.RequestJSON("DELETE", linodeBase+"/profile/sshkeys/"+id, bearer(token), nil)
	return err
}
func (linodeOps) renameKey(token, id, name string) (bool, error) {
	_, err := httpjson.RequestJSON("PUT", linodeBase+"/profile/sshkeys/"+id, bearer(token), map[string]any{"label": name})
	return err == nil, err
}

// --- Scaleway (project-scoped, X-Auth-Token) -------------------------------

const scwBase = "https://api.scaleway.com/iam/v1alpha1"

type scwOps struct{}

func newScaleway(spec Spec) Provider {
	return restProvider{spec: spec, className: "scaleway", defaultEnv: "SCW_SECRET_KEY",
		dashboard: "https://console.scaleway.com/project/credentials", ops: scwOps{}}
}
func scwHeaders(token string) map[string]string { return map[string]string{"X-Auth-Token": token} }
func scwProject() string                        { return os.Getenv("SCW_PROJECT_ID") }

func (scwOps) listKeys(token string) ([]RemoteKey, error) {
	project := scwProject()
	if project == "" {
		return nil, fmt.Errorf("Scaleway requires SCW_PROJECT_ID (the project the keys belong to) - set it alongside SCW_SECRET_KEY")
	}
	var out []RemoteKey
	page, done := 1, false
	for i := 0; i < maxPages; i++ {
		data, err := get(scwHeaders(token), fmt.Sprintf("%s/ssh-keys?project_id=%s&page=%d&page_size=100", scwBase, url.QueryEscape(project), page))
		if err != nil {
			return nil, err
		}
		batch := arr(data["ssh_keys"])
		out = append(out, remoteKeys(batch, "id", "name", "public_key")...)
		if len(batch) < 100 {
			done = true
			break
		}
		page++
	}
	if !done {
		return nil, paginationError()
	}
	return out, nil
}
func (scwOps) addKey(token, name, pub string) error {
	_, err := httpjson.RequestJSON("POST", scwBase+"/ssh-keys", scwHeaders(token),
		map[string]any{"name": name, "public_key": pub, "project_id": scwProject()})
	return err
}
func (scwOps) deleteKey(token, id string) error {
	_, err := httpjson.RequestJSON("DELETE", scwBase+"/ssh-keys/"+id, scwHeaders(token), nil)
	return err
}
func (scwOps) renameKey(token, id, name string) (bool, error) {
	_, err := httpjson.RequestJSON("PATCH", scwBase+"/ssh-keys/"+id, scwHeaders(token), map[string]any{"name": name})
	return err == nil, err
}

// --- GenericRest (config-driven via providers.json `rest`) -----------------

type genericRestOps struct{ spec Spec }

func newGenericRest(spec Spec) Provider {
	return restProvider{spec: spec, className: "rest", ops: genericRestOps{spec: spec}}
}
func (o genericRestOps) cfg() map[string]any {
	if o.spec.Rest != nil {
		return o.spec.Rest
	}
	return map[string]any{}
}
func (o genericRestOps) headers(token string) map[string]string {
	c := o.cfg()
	h := map[string]string{}
	if eh, ok := c["extra_headers"].(map[string]any); ok {
		for k, v := range eh {
			h[k] = str(v)
		}
	}
	name := strOr(c["auth_header_name"], "Authorization")
	prefix := strOr(c["auth_header_prefix"], "Bearer ")
	h[name] = prefix + token
	return h
}
func (o genericRestOps) listKeys(token string) ([]RemoteKey, error) {
	c := o.cfg()
	base := strOr(c["base_url"], "")
	listField := strOr(c["list_field"], "")
	if base == "" || listField == "" {
		return nil, fmt.Errorf("generic 'rest' provider needs a `rest` config with at least base_url + list_field in providers.json")
	}
	if !strings.HasPrefix(strings.ToLower(base), "https://") {
		return nil, fmt.Errorf("generic 'rest' base_url must be https:// (got %q)", base)
	}
	idF := strOr(c["id_field"], "id")
	nmF := strOr(c["name_field"], "name")
	pkF := strOr(c["public_key_field"], "public_key")
	nextField := strOr(c["next_field"], "")
	var out []RemoteKey
	u := base + strOr(c["list_path"], "")
	for i := 0; i < maxPages && u != ""; i++ {
		data, err := get(o.headers(token), u)
		if err != nil {
			return nil, err
		}
		out = append(out, remoteKeys(arr(data[listField]), idF, nmF, pkF)...)
		u = ""
		if nextField != "" {
			u = str(dig(data, strings.Split(nextField, ".")...))
		}
	}
	if u != "" {
		return nil, paginationError()
	}
	return out, nil
}
func (o genericRestOps) addKey(token, name, pub string) error {
	c := o.cfg()
	base := strOr(c["base_url"], "")
	path := strOr(c["create_path"], strOr(c["list_path"], ""))
	body := map[string]any{
		strOr(c["create_name_field"], "name"):      name,
		strOr(c["create_key_field"], "public_key"): pub,
	}
	_, err := httpjson.RequestJSON("POST", base+path, o.headers(token), body)
	return err
}
func (o genericRestOps) deleteKey(token, id string) error {
	c := o.cfg()
	dp := strOr(c["delete_path"], "")
	if dp == "" {
		return fmt.Errorf("generic 'rest' provider has no `delete_path` configured - revoke the key manually in the provider dashboard")
	}
	_, err := httpjson.RequestJSON("DELETE", strOr(c["base_url"], "")+strings.ReplaceAll(dp, "{id}", id), o.headers(token), nil)
	return err
}
func (o genericRestOps) renameKey(token, id, name string) (bool, error) {
	c := o.cfg()
	rp := strOr(c["rename_path"], "")
	if rp == "" {
		return false, nil
	}
	u := strOr(c["base_url"], "") + strings.ReplaceAll(rp, "{id}", id)
	body := map[string]any{strOr(c["rename_field"], "name"): name}
	method := strings.ToUpper(strOr(c["rename_method"], "PUT"))
	if method != "PATCH" {
		method = "PUT"
	}
	_, err := httpjson.RequestJSON(method, u, o.headers(token), body)
	return err == nil, err
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
