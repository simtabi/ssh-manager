# Shipping checklist

One-time setup to publish the first release, then the recurring per-release steps.
For the recurring tag-cut flow and version-source details, see
[release.md](release.md).

## First release (one-time)

1. **Make the repo public** on GitHub (`gh repo edit simtabi/ssh-manager --visibility public`).
2. **Set repo metadata**:
   ```sh
   gh repo edit simtabi/ssh-manager \
     --homepage "https://opensource.simtabi.com/products/ssh-manager" \
     --description "Profile-based SSH key & config lifecycle manager." \
     --add-topic oss --add-topic python --add-topic ssh --add-topic ssh-keys \
     --add-topic ssh-config --add-topic key-rotation --add-topic cli
   ```
   Enable Issues (and Discussions if you expect a user base).
3. **Create the `pypi` GitHub Environment** (Settings -> Environments -> `pypi`).
   The `Release` workflow publishes from this environment.
4. **Configure PyPI trusted publishing** (OIDC, no stored token) for the project:
   PyPI -> the project -> Publishing -> add a GitHub publisher with
   owner `simtabi`, repo `ssh-manager`, workflow `release.yml`, environment `pypi`.
5. **Confirm the green gates** locally and in CI:
   `make test e2e feature-check` (ruff + mypy --strict + pytest + smoke + feature
   check). CI must be green on macOS / Linux (3.11-3.13) and the Windows job.
6. **Cut `v0.1.0`** (see the recurring steps below).

No extra secrets are needed for PyPI (OIDC). A Homebrew tap, if added later,
would need a `TAP_GITHUB_TOKEN` secret.

## Every release (recurring)

1. Bump `__version__` in `src/ssh_manager/__init__.py` (the single source of version
   truth; hatchling reads it) and move `CHANGELOG.md`'s `[Unreleased]` into a
   dated, semver-tagged section.
2. Commit, then tag and push: `git tag vX.Y.Z && git push --tags`.
3. The `Release` workflow verifies the tag matches `__version__`, builds, and
   publishes to PyPI via the `pypi` environment (trusted publishing).
4. Verify the new version installs: `pipx install ssh-manager==X.Y.Z` then
   `sshmgr --version`.
