# Release

Tag-driven. A `v*` tag builds a static binary per OS/arch and attaches them,
with checksums, to a GitHub Release. Install the binary, or build from source
with `go install github.com/simtabi/ssh-manager/src/v3/cmd/sshmgr@latest`.

## Two tags per release

Each release is tagged twice on the same commit, and they are not
interchangeable:

| Tag | Read by | Why |
|---|---|---|
| `vX.Y.Z` | GoReleaser, the installers, `git describe` | the release proper, and the only one a human writes |
| `src/vX.Y.Z` | the Go module proxy, and nothing else | Go resolves a subdirectory module through a tag prefixed with that subdirectory, so `go install .../src/v3@vX.Y.Z` finds nothing without it |

They cannot be collapsed into one. OSS GoReleaser rejects `src/vX.Y.Z` outright
("current tag is not semver"), and `monorepo.tag_prefix`, which exists for this,
is a Pro feature. So the release runs off `vX.Y.Z` and the workflow mirrors
`src/vX.Y.Z` onto the same commit before publishing anything - you tag once.
`src/...` does not match the workflow's own `v[0-9]*` trigger, so pushing the
alias starts no second run.

## How a release is built

Each binary is pure Go with no runtime dependency of any kind - there is no
embedded interpreter and no `-tags bundled` build any more, so every target
cross-compiles from one Linux runner (`CGO_ENABLED=0`) instead of needing a
matching native one per OS. The binary version comes from the tag via ldflags
(`internal/version.Version`).

## Cut a release

1. Update `CHANGELOG.md` (move Unreleased into a dated, semver-tagged section).
2. Tag and push: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
   A tag with a pre-release suffix (`-rc.1`, `-beta`) is published as a GitHub
   pre-release. The workflow adds the second tag itself - see below.
3. The `Release` workflow builds every target and publishes the per-OS/arch
   binaries and archives, the deb/rpm/apk packages, per-archive SBOMs,
   `checksums.txt`, and a signed build-provenance attestation. Verify any
   downloaded artifact with
   `gh attestation verify <file> --repo simtabi/ssh-manager`.

> There is no cosign signature. Provenance attestation is the org default and is
> what `release.yml` produces; a `signs:` block would be added against a named
> downstream need, not speculatively.

## First release (one-time setup)

1. Make the repo public and enable Issues.
2. Set the metadata:
   `gh repo edit simtabi/ssh-manager --homepage "https://opensource.simtabi.com/products/simtabi/ssh-manager"`,
   topics `oss ssh ssh-keys ssh-config key-rotation cli go`.
3. Create the `release` GitHub Environment (`release.yml` runs in it).
4. Green on macOS, Linux and Windows: `make check`, `make e2e`, `make feature-check`.
5. After the tag lands, confirm the published artifact installs:
   `curl -fsSL https://raw.githubusercontent.com/simtabi/ssh-manager/main/src/scripts/install.sh | bash -s vX.Y.Z && sshmgr version`.

## Channels still to wire (need external setup)

Homebrew cask, Scoop manifest, and Linux packages (deb/rpm/apk) are not yet in
`release.yml`. They need the `simtabi/homebrew-tap` and `simtabi/scoop-bucket`
repos plus a `TAP_GITHUB_TOKEN` secret; add them once those exist.

## GitHub Actions hygiene

Keep action versions current via Dependabot (weekly); re-pin on every merged
dependency PR.

For the org-wide OIDC reference across channels, see
`/opensource/package-publishing-guide.md`.

---

[← Docs index](../README.md#documentation)
