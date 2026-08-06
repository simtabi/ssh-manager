# sshmgr - dev front door. Run from the repo root:  make <target>
#
# Pure Go: no venv, no interpreter, no bootstrap step. `make build` is enough to
# get a working binary, and every other target works off the toolchain already
# needed to compile it.
#
# Two roots, and the distinction is load-bearing. The Go module is src/ - that is
# where go.mod lives and where every `go` invocation has to run, which is what
# `go -C` below is for. Build output is a property of the repository, not of the
# module, so it lands in build/ at the root: that is where you look for the
# binary, and it stays one directory rather than one per module.
MODULE  := src
BIN     := build/sshmgr
PKG     := ./cmd/sshmgr
# A release carries two tags on the same commit, and this matches the first:
#
#   v3.0.1      the release. GoReleaser, the installers and `git describe` use
#               it, and it is what a human reads.
#   src/v3.0.1  the module alias. Go requires a subdirectory module's tags to be
#               prefixed with the subdirectory, so `go install .../src/v3@v3.0.1`
#               resolves through this one and nothing else reads it.
#
# The split exists because OSS GoReleaser rejects a prefixed tag outright
# ("current tag is not semver"), and monorepo.tag_prefix is a Pro feature. The
# release workflow creates the alias so it cannot be forgotten.
#
# --match 'v[0-9]*' so no non-release tag can become the version. 'v*' was not
# enough: it excludes python-final but admits anything else beginning with v,
# and a tag like v2-migration-record would then be stamped into the binary.
VERSION := $(shell git describe --tags --match 'v[0-9]*' --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/simtabi/ssh-manager/src/v3/internal/version.Version=$(VERSION)
GO      := go -C $(MODULE)

.PHONY: help build build-all test vet fmt fmt-check lint lint-all ci check e2e feature-check \
        cross dist clean doctor reconcile render rotate bundle

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

# -o is resolved relative to $(MODULE) because of `go -C`, hence the ../.
build: ## compile the binary into build/
	@mkdir -p build
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o ../$(BIN) $(PKG)

build-all: ## compile every package (what CI gated on before `ci` existed)
	$(GO) build ./...

test: ## run the unit suite
	$(GO) test ./...

vet: ## go vet
	$(GO) vet ./...

fmt: ## gofmt every file in place
	gofmt -w $(MODULE)/cmd $(MODULE)/internal

fmt-check: ## fail if anything is unformatted (what CI gates on)
	@test -z "$$(gofmt -l $(MODULE)/cmd $(MODULE)/internal)" || { gofmt -l $(MODULE)/cmd $(MODULE)/internal; exit 1; }

lint: ## golangci-lint (install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed. Install it with:"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		exit 1; }
	cd $(MODULE) && golangci-lint run ./...

lint-all: ## lint every GOOS - one run only sees one, so build-tagged files hide
	@for os in darwin linux windows; do \
		echo "--- GOOS=$$os ---"; \
		( cd $(MODULE) && GOOS=$$os golangci-lint run ./... ) || exit 1; \
	done

# `ci` is the gate the workflow runs, so there is one definition of it rather
# than a copy in ci.yml that drifts from this one. Lint is deliberately NOT in
# it: CI gets golangci-lint from a pinned action that also annotates the diff,
# and folding it in here would silently drop both the pin and the cache.
ci: fmt-check build-all vet test ## the gate CI runs (lint runs there as its own step)

check: ci lint ## everything: the CI gate plus lint, for humans

# Tagged out of the ordinary suite: it mints six real keypairs and does an age
# round trip. It builds its own binary, so it does not depend on `build`.
e2e: ## end-to-end smoke in a throwaway sandbox
	$(GO) test -tags e2e -count=1 -timeout 300s ./cmd/sshmgr/

# The per-command assertions live in internal/cli/commands_test.go now, so they
# run in the ordinary suite. Kept as a target because the docs and the shipping
# checklist name it.
feature-check: ## exercise every command with assertions
	$(GO) test -count=1 -run 'TestCommandSurface|TestVerbs' ./internal/cli/

# GoReleaser is configured in src/.goreleaser.yaml but runs from the repo root:
# its archives bundle LICENSE/README/CHANGELOG, and GoReleaser's file globbing
# will not climb out of its working directory to reach them. builds[].dir points
# the compile step back into the module. CI passes the same --config.
GORELEASER := goreleaser --config $(MODULE)/.goreleaser.yaml

cross: ## build every release target into build/dist/ (needs goreleaser)
	$(GORELEASER) build --clean --snapshot

dist: ## full release artifacts into build/dist/ (needs goreleaser)
	$(GORELEASER) release --clean --snapshot

# Everything generated lives under build/, so this is the whole of it. It used
# to remove `bin dist`, and GoReleaser has written to build/dist since the
# single-folder layout was adopted - so `make clean` left every release artifact
# behind while reporting success.
clean: ## remove build output (keeps build/targets.txt, which is tracked)
	rm -rf $(BIN) build/dist

# --- running the tool against your own config -------------------------------
# These build first and run the binary you just built, never an installed one,
# so what you exercise is what you changed.

doctor: build ## verify environment (FIX=1 to auto-fix perms first)
	$(BIN) doctor $(if $(FIX),--fix,)

reconcile: build ## make ~/.ssh match the manifest
	$(BIN) reconcile

render: build ## re-render config from the manifest
	$(BIN) config render

rotate: build ## rotate a key:  make rotate KEY=<profile/key>
	$(BIN) rotate $(KEY)

bundle: build ## encrypted backup
	$(BIN) bundle
