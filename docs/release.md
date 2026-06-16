# Release

Tag-driven, single source of version truth (`src/ssh_manager/__init__.py::__version__`,
read by hatchling's dynamic version). A `v*` tag builds the wheel + sdist and
attaches them, with checksums, to a GitHub Release.

This project is not published to PyPI. Install it from the repo:
`pip install git+https://github.com/simtabi/ssh-manager.git` (or `pipx`). The v2
line will wrap the tool in Go for a portable, single-binary executable.

## Cut a release

1. Bump `__version__` in `src/ssh_manager/__init__.py` and update `CHANGELOG.md` (move
   Unreleased into a dated, semver-tagged section).
2. Commit, then tag: `git tag vX.Y.Z && git push --tags`. The `Release` workflow
   verifies the tag matches `__version__` before building.
3. The `Release` workflow builds `dist/*` and creates the GitHub Release with the
   wheel, sdist, and `SHA256SUMS` attached. No registry credentials are used.

## GitHub Actions hygiene

Keep action versions current via Dependabot (weekly); re-pin on every merged
dependency PR.

For the org-wide OIDC reference across channels, see
`/opensource/package-publishing-guide.md`.
