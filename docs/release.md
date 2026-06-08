# Release

Tag-driven, single source of version truth (`src/ssh_manager/__init__.py::__version__`,
read by hatchling's dynamic version), OIDC trusted publishing to PyPI.

## Cut a release

1. Bump `__version__` in `src/ssh_manager/__init__.py` and update `CHANGELOG.md` (move
   Unreleased into a dated, semver-tagged section).
2. Commit, then tag: `git tag vX.Y.Z && git push --tags`. The `Release` workflow
   verifies the tag matches `__version__` before publishing.
3. The `Release` workflow builds and publishes to PyPI via the `pypi` GitHub
   Environment (trusted publisher - no API token stored).

## GitHub Actions hygiene

Keep action versions current via Dependabot (weekly); re-pin on every merged
dependency PR.

For the org-wide OIDC reference across channels, see
`/opensource/package-publishing-guide.md`.
