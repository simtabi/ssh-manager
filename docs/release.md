# Release

Tag-driven. A `v*` tag builds a self-contained binary per OS/arch and attaches
them, with checksums and a cosign signature, to a GitHub Release. Not published
to PyPI; install the binary, or from the repo
(`pip install git+https://github.com/simtabi/ssh-manager.git`) for the engine.

## How a release is built (v2)

Each binary is the Go front-end with the Python engine frozen and embedded
(`-tags bundled`). CPython cannot cross-compile, so `release.yml` builds every
target on a matching native runner: macOS arm64 (`macos-14`) and amd64
(`macos-13`), Linux amd64 (`ubuntu-24.04`) and arm64 (`ubuntu-24.04-arm`), and
Windows amd64. A final job combines checksums, cosign-signs them keylessly
(OIDC), and creates the GitHub Release. The binary version comes from the tag via
ldflags (`internal/version.Version`).

Note: macOS Intel (`macos-13`) runners are scarce, so `darwin/amd64` can sit
queued well after the others finish; that is runner latency, not a failure.

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
