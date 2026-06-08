# ssh-manager - dev front door. Run from the repo root:  make <target>
# Logic lives in Python / POSIX-sh; Make just dispatches. Dev scripts live in
# .build/; perms/groups are fixed intelligently (OS-aware) by `make perms`.
BIN := .venv/bin

.PHONY: help bootstrap init perms doctor reconcile check render rotate bundle test e2e feature-check lint fmt sync-data

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

sync-data: ## copy config/providers.json + .env-example into the shipped package data
	.build/sync-data.sh

bootstrap: ## install deps + venv + hooks, then fix perms/groups
	.build/bootstrap.sh

init: perms ## first-run: create config-dir + starter manifest/.env (secrets 0600)
	$(BIN)/sshmgr init

perms: ## OS-aware fix of file perms + groups (scripts +x, secrets 600, dirs 700, ~/.ssh)
	.build/bootstrap.sh --perms-only

doctor: ## verify environment (FIX=1 to auto-fix perms first)
	$(BIN)/sshmgr doctor $(if $(FIX),--fix,)

reconcile: ## make ~/.ssh match the manifest, then re-assert perms
	$(BIN)/sshmgr reconcile
	@$(MAKE) -s perms

check: ## verify config matches manifest (read-only)
	$(BIN)/sshmgr config check

render: ## re-render config from manifest
	$(BIN)/sshmgr config render

rotate: ## rotate a key:  make rotate KEY=<name>
	$(BIN)/sshmgr rotate $(KEY)

bundle: ## encrypted backup
	$(BIN)/sshmgr bundle

test: ## run the unit suite
	$(BIN)/pytest -q

e2e: ## end-to-end smoke in a throwaway sandbox
	.build/e2e.sh

feature-check: ## exercise EVERY command/feature with assertions (per-feature checklist)
	.build/feature-check.sh

lint: ## ruff + mypy --strict
	$(BIN)/ruff check src tests && $(BIN)/mypy src

fmt: ## ruff format
	$(BIN)/ruff format src tests
