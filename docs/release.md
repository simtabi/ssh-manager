# Release

Tag-driven. A `v*` tag builds a static binary per OS/arch and attaches them,
with checksums, to a GitHub Release. Install the binary, or build from source
with `go install github.com/simtabi/ssh-manager/cmd/sshmgr@latest`.

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
   pre-release.
3. The `Release` workflow builds all targets and publishes the binaries,
   `SHA256SUMS`, and the cosign signature/cert.

## Channels still to wire (need external setup)

Homebrew cask, Scoop manifest, and Linux packages (deb/rpm/apk) are not yet in
`release.yml`. They need the `simtabi/homebrew-tap` and `simtabi/scoop-bucket`
repos plus a `TAP_GITHUB_TOKEN` secret; add them once those exist.

## GitHub Actions hygiene

Keep action versions current via Dependabot (weekly); re-pin on every merged
dependency PR.

For the org-wide OIDC reference across channels, see
`/opensource/package-publishing-guide.md`.
