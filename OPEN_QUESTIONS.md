# Open questions

Ambiguities found during the migration. Each has a recommended default, which
has been **taken** so work continues; reverse any of them by saying so.

---

### Q1 — The Python tree was deleted before the matrix existed

**Ambiguity.** The protocol requires that no Python file is touched until
Phase 4, and that Phase 4 is gated on every matrix row being `VERIFIED` or
`DROPPED`. The tree was deleted in `fe8cef1`, before any matrix existed. Do we
restore it to `go-v2` and re-run the protocol literally?

**Default taken: no restore.** The tree is fully preserved at tag
`python-final` and is both readable (`git show python-final:<path>`) and
runnable (`git worktree add /tmp/py python-final`), so nothing needed for
verification or characterisation is lost. Restoring it into the branch only to
delete it again produces two no-op commits and changes nothing that can be
proven. Phase 4's forward drift check is replaced by a **backward** one:
confirm the deletion commit removed exactly the 88 files the matrix accounts
for, and nothing else.

**Cost of the default.** If a Python file had been modified between the real
Phase 1 baseline and the deletion, the forward drift check would have caught it
and the backward one is weaker. Mitigated by the fact that `python-final` is
the deletion's immediate parent — there is no window.

---

### Q2 — Branch name

**Ambiguity.** The instruction says to work on `go-v2`. All 40 commits of
migration work are on `sshmgr-v2`.

**Default taken: create `go-v2` at the current commit and continue there.**
Costs nothing, loses no history, complies literally. `sshmgr-v2` is left
pointing where it was, so nothing that references it breaks.

---

### Q3 — What "parity" means when the on-disk layout changed on purpose

**Ambiguity.** The protocol defines parity as "same serialized formats and
field names". But v2 deliberately redesigned the `~/.ssh` layout (deviation D4:
one inline `config` instead of per-profile files plus `Include`; one hashed
`known_hosts` instead of one per profile). Rendering output cannot match Python
and should not.

**Default taken: parity is asserted against the v2 contract, not Python, for
exactly the three rows the layout change touches (K3 renderer, S6 knownhosts,
S13 configsvc).** Every other row is held to strict Python parity. When those
three are verified, their Evidence column must say which contract they were
verified against — otherwise a future reader cannot tell a deliberate deviation
from an unnoticed regression.

---

### Q4 — Are the Go-only features in scope?

**Ambiguity.** `key add/list/delete`, `show`, `clean`, and the `keyaudit` /
`keysvc` / `lifecycle` services have no Python counterpart (deviation D1). A
strict reading of "port Python to Go" would exclude them; a strict reading of
"never mark a feature migrated without evidence" would demand they be verified
like everything else.

**Default taken: in scope for verification, out of scope for parity.** They get
matrix rows and must reach `VERIFIED` on their own tests, but no Python
behaviour is compared against.

---

### Q5 — Nine Python test files have no Go counterpart

**Ambiguity.** `test_deploy`, `test_cloud_providers`, `test_ssh_generic`,
`test_windows`, `test_cli_yes`, `test_smoke`, `test_packaging`, plus netstat
and PTY-TUI coverage. Do we port those tests, or accept the gap?

**Default taken: port them, in Phase 3, before verifying the rows they cover.**
The protocol says to port tests first; these rows (S4, P3–P5, L4, E3, C9, C11,
C19) are exactly the ones currently unproven, and they include the
provider-integration and Windows-platform paths that nothing else exercises.

---

### Q6 — `.venv/` is still on disk

**Ambiguity.** The working copy holds an untracked `.venv/` (Python 3.14
site-packages), plus `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`. They are
gitignored, so they do not affect the repo, but Phase 4's verification says
`find . -name "*.py"` must return nothing.

**Default taken: exclude them from the Phase 4 check but delete them at Phase 4
as local cleanup**, and say so in the report rather than silently scoping them
out. They are not repository content; they are residue from a toolchain that no
longer applies.

---

### Q7 — Docs are wrong *now*, and Phase 5 is far away

**Ambiguity.** `README.md` and `docs/installation.md` currently tell users to
`pip install` an implementation that does not exist. Phase 5 fixes docs, but
that is several phases out, and the repo's front page is wrong in the meantime.

**Default taken: leave them until Phase 5, as the protocol orders.** Flagged
here because it is a live user-facing defect, not a cosmetic one — if the repo
is public or shared before Phase 5, fix `README.md` first.

---

### Q8 — No cloud adapter has ever been run against a live API

**Ambiguity.** `internal/core/providers/cloud.go` talks to DigitalOcean, Vultr,
Hetzner, Linode and Scaleway. Nothing in this repo's history shows any of them
being exercised against a real account, in Go or in Python -
`tests/test_cloud_providers.py` stubbed the HTTP layer entirely. So the response
shapes and endpoint paths are assumptions, and the Go port may faithfully
reproduce a Python assumption that was never right.

**Default taken: pin the shapes both implementations agree on, and say so.**
The tests assert what Python's tests asserted plus what the Go code expects;
where those agree the behaviour is at least consistent, which is what a port can
prove. DigitalOcean is additionally exercised over a real local server so the
request path itself is covered for one adapter.

**What would close it.** A sandbox token for any one provider, used once, to
confirm the list-response shape. Even one would raise confidence in the four
that share the code path. Not blocking - the adapters degrade to a manual
fallback when no token is set, which is the common case.
