// Package tabler vendors the Tabler assets the web UI embeds: it resolves and
// pins versions, downloads and integrity-checks the npm tarballs, cuts the
// icon subset, and writes the licence texts, the hash manifest and the
// repository's THIRD_PARTY_NOTICES.md. The tablervendor command drives it; the
// web package's tests use it to check the committed files still agree.
package tabler

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Package names, as TABLER_VERSION records them.
const (
	PkgCore      = "@tabler/core"
	PkgIcons     = "@tabler/icons-sprite"
	PkgBootstrap = "bootstrap"
	PkgPopper    = "@popperjs/core"
)

// Registry is the npm registry. A var so a test can point it elsewhere.
var Registry = "https://registry.npmjs.org"

// coreFiles are the three files the UI loads, from @tabler/core's dist/.
var coreFiles = []string{"css/tabler.min.css", "js/tabler.min.js", "js/tabler-theme.min.js"}

// Fetcher retrieves a URL's body.
type Fetcher interface {
	Get(url string) ([]byte, error)
}

// HTTPFetcher fetches over the network.
type HTTPFetcher struct{}

func (HTTPFetcher) Get(u string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute, Transport: transport()}
	resp, err := c.Get(u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// transport honours SSL_CERT_FILE on every platform. Go reads it only off
// macOS, where it uses the system verifier instead -- which rejects the
// certificate of a TLS-intercepting proxy that a CA bundle would accept.
func transport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		if pem, err := os.ReadFile(file); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
			}
		}
	}
	return t
}

// Vendor writes the vendored tree.
type Vendor struct {
	Root     string // repository root
	AssetDir string // src/internal/web/assets/vendor
	Fetch    Fetcher
	Log      func(format string, a ...any)
}

// Versions is the parsed TABLER_VERSION file.
type Versions map[string]string

// VersionFile is the single place the vendored versions are pinned.
const VersionFile = "TABLER_VERSION"

// ParseVersions reads "<package> <version>" lines; '#' starts a comment.
func ParseVersions(data []byte) (Versions, error) {
	out := Versions{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s: want \"<package> <version>\", got %q", VersionFile, sc.Text())
		}
		out[fields[0]] = fields[1]
	}
	for _, p := range []string{PkgCore, PkgIcons, PkgBootstrap, PkgPopper} {
		if out[p] == "" {
			return nil, fmt.Errorf("%s: no version for %s", VersionFile, p)
		}
	}
	return out, sc.Err()
}

// Format renders the file. Order is fixed so a diff shows only what moved.
func (v Versions) Format() []byte {
	var b bytes.Buffer
	b.WriteString("# The vendored Tabler assets the web UI embeds. This is the one place their\n")
	b.WriteString("# versions are pinned. Change them with `make tabler-update` (newest releases)\n")
	b.WriteString("# or edit and run `make tabler-vendor`; never by hand-editing vendored files.\n")
	b.WriteString("# bootstrap and @popperjs/core are bundled inside tabler.min.js; they are\n")
	b.WriteString("# listed so their licence texts are fetched at the matching versions.\n")
	for _, p := range []string{PkgCore, PkgIcons, PkgBootstrap, PkgPopper} {
		fmt.Fprintf(&b, "%s %s\n", p, v[p])
	}
	return b.Bytes()
}

type packument struct {
	DistTags map[string]string `json:"dist-tags"`
}

type manifest struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	Dist         struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
}

func escape(pkg string) string { return strings.Replace(url.PathEscape(pkg), "%40", "@", 1) }

func (v *Vendor) latest(pkg string) (string, error) {
	body, err := v.Fetch.Get(Registry + "/" + escape(pkg))
	if err != nil {
		return "", err
	}
	var p packument
	if err := json.Unmarshal(body, &p); err != nil {
		return "", fmt.Errorf("%s: %w", pkg, err)
	}
	if p.DistTags["latest"] == "" {
		return "", fmt.Errorf("%s: no latest dist-tag", pkg)
	}
	return p.DistTags["latest"], nil
}

func (v *Vendor) manifest(pkg, version string) (manifest, error) {
	var m manifest
	body, err := v.Fetch.Get(Registry + "/" + escape(pkg) + "/" + version)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("%s@%s: %w", pkg, version, err)
	}
	return m, nil
}

// tarball downloads a package and returns its files, keyed by path inside
// package/, after checking the registry's sha512 integrity. Nothing is
// extracted to disk: the archive is read in memory, so a hostile entry name
// cannot write anywhere.
func (v *Vendor) tarball(pkg, version string) (map[string][]byte, manifest, error) {
	m, err := v.manifest(pkg, version)
	if err != nil {
		return nil, m, err
	}
	data, err := v.Fetch.Get(m.Dist.Tarball)
	if err != nil {
		return nil, m, err
	}
	if err := VerifyIntegrity(data, m.Dist.Integrity); err != nil {
		return nil, m, fmt.Errorf("%s@%s: %w", pkg, version, err)
	}
	files, err := ReadTarball(data)
	if err != nil {
		return nil, m, fmt.Errorf("%s@%s: %w", pkg, version, err)
	}
	v.Log("fetched %s@%s (%d files, integrity ok)", pkg, version, len(files))
	return files, m, nil
}

// VerifyIntegrity checks data against an npm "sha512-<base64>" string.
func VerifyIntegrity(data []byte, integrity string) error {
	want, ok := strings.CutPrefix(integrity, "sha512-")
	if !ok {
		return fmt.Errorf("integrity %q is not sha512", integrity)
	}
	sum := sha512.Sum512(data)
	if base64.StdEncoding.EncodeToString(sum[:]) != want {
		return errors.New("tarball does not match the registry's sha512 integrity")
	}
	return nil
}

// ReadTarball returns the regular files of a gzipped npm tarball, keyed by
// their path below the leading package/ directory.
func ReadTarball(data []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		_, rest, ok := strings.Cut(name, "/")
		if !ok || strings.HasPrefix(rest, "..") {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, 32<<20))
		if err != nil {
			return nil, err
		}
		out[rest] = body
	}
}

var bootstrapVersion = regexp.MustCompile(`static get VERSION\(\)\{return"(\d+\.\d+\.\d+)"\}`)

// BundledBootstrap reads the Bootstrap version compiled into tabler.min.js.
func BundledBootstrap(js []byte) (string, error) {
	m := bootstrapVersion.FindSubmatch(js)
	if m == nil {
		return "", errors.New("tabler.min.js: no Bootstrap VERSION marker found")
	}
	return string(m[1]), nil
}

var symbolRE = regexp.MustCompile(`(?s)<symbol id="tabler-([a-z0-9-]+)"[^>]*>.*?</symbol>`)

// SubsetSprite returns an SVG holding only the named symbols, in the order
// asked. A missing name is an error: the UI would render a blank icon.
func SubsetSprite(sprite []byte, names []string) ([]byte, error) {
	found := map[string][]byte{}
	for _, m := range symbolRE.FindAllSubmatch(sprite, -1) {
		found[string(m[1])] = m[0]
	}
	var b bytes.Buffer
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" class="d-none" aria-hidden="true"><defs>`)
	var missing []string
	for _, n := range names {
		sym, ok := found[n]
		if !ok {
			missing = append(missing, n)
			continue
		}
		b.Write(sym)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("icons not in the sprite: %s", strings.Join(missing, ", "))
	}
	b.WriteString("</defs></svg>\n")
	return b.Bytes(), nil
}

// ReadIconList reads icons.txt: one name per line, '#' comments.
func ReadIconList(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Licence is one notice to carry.
type Licence struct {
	File, Package, Version, What string
	Text                         []byte
}

// Check compares what TABLER_VERSION pins with the newest releases on npm and
// returns one line per package that is behind. It changes nothing: the weekly
// CI run prints the lines as warnings rather than opening a pull request.
func (v *Vendor) Check() ([]string, error) {
	data, err := os.ReadFile(filepath.Join(v.AssetDir, VersionFile))
	if err != nil {
		return nil, err
	}
	vers, err := ParseVersions(data)
	if err != nil {
		return nil, err
	}
	var behind []string
	for _, p := range []string{PkgCore, PkgIcons} {
		latest, err := v.latest(p)
		if err != nil {
			return nil, err
		}
		if latest != vers[p] {
			behind = append(behind, fmt.Sprintf("%s is pinned at %s; %s is out. Run make tabler-update.", p, vers[p], latest))
		}
	}
	return behind, nil
}

// Run vendors everything. With latest, it first resolves the newest releases
// and rewrites TABLER_VERSION.
func (v *Vendor) Run(latest bool) error {
	versionPath := filepath.Join(v.AssetDir, VersionFile)
	var vers Versions
	if latest {
		vers = Versions{}
		for _, p := range []string{PkgCore, PkgIcons} {
			l, err := v.latest(p)
			if err != nil {
				return err
			}
			vers[p] = l
		}
	} else {
		data, err := os.ReadFile(versionPath)
		if err != nil {
			return err
		}
		if vers, err = ParseVersions(data); err != nil {
			return err
		}
	}

	core, coreManifest, err := v.tarball(PkgCore, vers[PkgCore])
	if err != nil {
		return err
	}
	vendored := map[string][]byte{}
	for _, f := range coreFiles {
		body, ok := core["dist/"+f]
		if !ok {
			return fmt.Errorf("%s@%s ships no dist/%s", PkgCore, vers[PkgCore], f)
		}
		vendored["tabler/"+path.Base(f)] = body
	}

	bs, err := BundledBootstrap(vendored["tabler/tabler.min.js"])
	if err != nil {
		return err
	}
	if latest {
		vers[PkgBootstrap] = bs
		popper, err := v.latest(PkgPopper)
		if err != nil {
			return err
		}
		if want := coreManifest.Dependencies[PkgPopper]; !sameMajor(want, popper) {
			return fmt.Errorf("%s latest %s does not satisfy %s's range %q", PkgPopper, popper, PkgCore, want)
		}
		vers[PkgPopper] = popper
	} else if bs != vers[PkgBootstrap] {
		return fmt.Errorf("tabler.min.js bundles Bootstrap %s but %s pins %s", bs, VersionFile, vers[PkgBootstrap])
	}

	icons, _, err := v.tarball(PkgIcons, vers[PkgIcons])
	if err != nil {
		return err
	}
	list, err := os.ReadFile(filepath.Join(v.AssetDir, "icons.txt"))
	if err != nil {
		return err
	}
	subset, err := SubsetSprite(icons["dist/tabler-sprite.svg"], ReadIconList(list))
	if err != nil {
		return err
	}
	vendored["tabler-icons.svg"] = subset

	coreLicence, err := v.Fetch.Get(CoreLicenceURL(vers[PkgCore]))
	if err != nil {
		return fmt.Errorf("the npm tarball ships no LICENSE, and the tagged one could not be fetched: %w", err)
	}
	bsFiles, _, err := v.tarball(PkgBootstrap, vers[PkgBootstrap])
	if err != nil {
		return err
	}
	popperFiles, _, err := v.tarball(PkgPopper, vers[PkgPopper])
	if err != nil {
		return err
	}
	licences := Licences(vers, map[string][]byte{
		"tabler.txt":       coreLicence,
		"tabler-icons.txt": icons["LICENSE"],
		"bootstrap.txt":    firstOf(bsFiles, "LICENSE", "LICENSE.md"),
		"popper.txt":       firstOf(popperFiles, "LICENSE.md", "LICENSE"),
	})
	for _, l := range licences {
		if len(l.Text) == 0 {
			return fmt.Errorf("%s@%s: no licence text found", l.Package, l.Version)
		}
		vendored["LICENSES/"+l.File] = l.Text
	}

	// Write: the files, then the version pin, then the hashes over all of it.
	for name, body := range vendored {
		if err := writeFile(filepath.Join(v.AssetDir, filepath.FromSlash(name)), body); err != nil {
			return err
		}
	}
	if err := writeFile(versionPath, vers.Format()); err != nil {
		return err
	}
	vendored[VersionFile] = vers.Format()
	vendored["icons.txt"] = list
	if err := writeFile(filepath.Join(v.AssetDir, "MANIFEST.sha256"), Manifest(vendored)); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(v.Root, "THIRD_PARTY_NOTICES.md"), Notices(licences)); err != nil {
		return err
	}
	v.Log("vendored %s %s, %s %s (%d icons); notices and hashes rewritten",
		PkgCore, vers[PkgCore], PkgIcons, vers[PkgIcons], len(ReadIconList(list)))
	return nil
}

// CoreLicenceURL is @tabler/core's LICENSE at the release tag. The npm tarball
// ships none, so it comes from the repository; since 1.3 the tags are named
// "@tabler/core@<version>", which is what this escapes.
func CoreLicenceURL(version string) string {
	return "https://raw.githubusercontent.com/tabler/tabler/" + url.PathEscape(PkgCore+"@"+version) + "/LICENSE"
}

// Licences pairs each vendored package with its licence text, keyed by the
// file name under LICENSES/. The order is the order THIRD_PARTY_NOTICES.md
// lists them in.
func Licences(vers Versions, texts map[string][]byte) []Licence {
	return []Licence{
		{"tabler.txt", PkgCore, vers[PkgCore], "tabler.min.css, tabler.min.js, tabler-theme.min.js", texts["tabler.txt"]},
		{"tabler-icons.txt", PkgIcons, vers[PkgIcons], "the icon subset in tabler-icons.svg", texts["tabler-icons.txt"]},
		{"bootstrap.txt", PkgBootstrap, vers[PkgBootstrap], "bundled inside tabler.min.js", texts["bootstrap.txt"]},
		{"popper.txt", PkgPopper, vers[PkgPopper], "bundled inside tabler.min.js", texts["popper.txt"]},
	}
}

func firstOf(files map[string][]byte, names ...string) []byte {
	for _, n := range names {
		if b, ok := files[n]; ok {
			return b
		}
	}
	return nil
}

// sameMajor reports whether version satisfies a caret range's major.
func sameMajor(caret, version string) bool {
	want := strings.SplitN(strings.TrimLeft(caret, "^~>=v "), ".", 2)[0]
	got := strings.SplitN(version, ".", 2)[0]
	return want != "" && want == got
}

// Manifest renders "sha256  path" lines, sorted, in sha256sum's format.
func Manifest(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	return b.Bytes()
}

// Notices renders THIRD_PARTY_NOTICES.md from the licence texts.
func Notices(ls []Licence) []byte {
	var b bytes.Buffer
	b.WriteString("# Third-party notices\n\n")
	b.WriteString("The `serve` web UI embeds the following third-party software in every\n")
	b.WriteString("sshmgr binary. Each is MIT-licensed; its full notice follows.\n")
	b.WriteString("This file is generated by `make tabler-update` / `make tabler-vendor`;\n")
	b.WriteString("do not edit it by hand.\n")
	for _, l := range ls {
		fmt.Fprintf(&b, "\n## %s %s\n\nUsed for: %s.\n\n```text\n%s\n```\n",
			l.Package, l.Version, l.What, strings.TrimRight(string(l.Text), "\n"))
	}
	return b.Bytes()
}

func writeFile(p string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, body, 0o644)
}
