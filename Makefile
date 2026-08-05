# sshmgr - dev front door. Run from the repo root:  make <target>
#
# Pure Go: no venv, no interpreter, no bootstrap step. `make build` is enough to
# get a working binary, and every other target works off the toolchain already
# needed to compile it.
BIN     := bin/sshmgr
PKG     := ./cmd/sshmgr
# --match 'v*' so a non-release tag (e.g. python-final) never becomes the version.
VERSION := $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/simtabi/ssh-manager/internal/version.Version=$(VERSION)

.PHONY: help build build-all test vet fmt fmt-check lint lint-all ci check e2e feature-check \
        cross dist clean doctor reconcile render rotate bundle

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

build: ## compile the binary into bin/
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

build-all: ## compile every package (what CI gated on before `ci` existed)
	go build ./...

test: ## run the unit suite
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt every file in place
	gofmt -w cmd internal

fmt-check: ## fail if anything is unformatted (what CI gates on)
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

lint: ## golangci-lint (install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed. Install it with:"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		exit 1; }
	golangci-lint run ./...

lint-all: ## lint every GOOS - one run only sees one, so build-tagged files hide
	@for os in darwin linux windows; do \
		echo "--- GOOS=$$os ---"; \
		GOOS=$$os golangci-lint run ./... || exit 1; \
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
	go test -tags e2e -count=1 -timeout 300s ./cmd/sshmgr/

# The per-command assertions live in internal/cli/commands_test.go now, so they
# run in the ordinary suite. Kept as a target because the docs and the shipping
# checklist name it.
feature-check: ## exercise every command with assertions
	go test -count=1 -run 'TestCommandSurface|TestVerbs' ./internal/cli/

cross: ## build every release target into dist/ (needs goreleaser)
	goreleaser build --clean --snapshot

dist: ## full release artifacts into dist/ (needs goreleaser)
	goreleaser release --clean --snapshot

clean: ## remove build output
	rm -rf bin dist

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
