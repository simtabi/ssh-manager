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
# enough: it excludes v1-final but admits anything else beginning with v,
# and a tag like v2-migration-record would then be stamped into the binary.
VERSION := $(shell git describe --tags --match 'v[0-9]*' --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/simtabi/ssh-manager/src/v3/internal/version.Version=$(VERSION)
GO      := go -C $(MODULE)

.PHONY: help build build-all test vet fmt fmt-check lint lint-all ci check ci-linux e2e feature-check \
        cross dist clean doctor reconcile render rotate bundle

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

# Always from an empty build/. A stale binary is not a hypothetical here: a bug
# was reported against this tool from a binary built one minute before the fix
# landed, and it looked exactly like the fix not working. Wiping the output first
# means the file on disk is always one this invocation wrote.
#
# What it does NOT do is discard Go's build cache. That cache is keyed by a hash
# of the actual inputs, so a cached object is only reused when recompiling would
# produce the same bytes - "rebuild everything" buys no correctness there, it
# just adds minutes. FORCE=1 passes -a for the rare case of suspecting the
# toolchain itself.
#
# -o is resolved relative to $(MODULE) because of `go -C`, hence the ../.
build: clean ## compile the binary into a freshly emptied build/ (FORCE=1 to rebuild deps too)
	@mkdir -p build
	$(GO) build $(if $(FORCE),-a,) -trimpath -ldflags '$(LDFLAGS)' -o ../$(BIN) $(PKG)
	@echo "built $(BIN)  ->  $$(./$(BIN) version)"

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

# The ubuntu-latest leg, runnable without GitHub. `make ci` only ever tests the
# machine you are on, and `lint-all` cross-compiles for other systems without
# running anything on them - so a Linux-only failure is invisible here until CI
# says so. When CI cannot say so (a runner outage, a fork without Actions, a
# flight), this is the same gate on the same Go version the module asks for.
#
# It reads the version from go.mod rather than pinning one, so it cannot drift
# from what setup-go installs in the workflow.
GOVERSION = $(shell awk '/^go /{print $$2}' $(MODULE)/go.mod)

ci-linux: ## run the CI gate inside a linux container (needs docker)
	@command -v docker >/dev/null 2>&1 || { echo "docker is not installed"; exit 1; }
	docker run --rm -v "$(CURDIR)":/w -w /w golang:$(GOVERSION) \
		sh -c 'apt-get -qq update >/dev/null && apt-get -qq install -y openssh-client >/dev/null && \
		       go -C $(MODULE) build ./... && go -C $(MODULE) vet ./... && go -C $(MODULE) test ./...'

# Tagged out of the ordinary suite: it mints six real keypairs and does an age
# round trip. It builds its own binary, so it does not depend on `build`.
e2e: ## end-to-end smoke in a throwaway sandbox
	$(GO) test -tags e2e -count=1 -timeout 300s ./cmd/sshmgr/

# The per-command assertions live in internal/cli/commands_test.go now, so they
# run in the ordinary suite. Kept as a target because the docs and the shipping
# checklist name it.
#
# It runs the whole package rather than a -run regex. The regex was
# 'TestCommandSurface|TestVerbs', which selected 9 tests and silently excluded
# TestTheCommandSurfaceMatchesTheOneItReplaced - the one test that pins the
# command surface against the implementation it replaced, and the thing a target
# called "feature-check" most obviously promises. A pattern that has to be kept
# in step with test names drifts the moment one is renamed, and says nothing when
# it does.
feature-check: ## exercise every command with assertions
	$(GO) test -count=1 ./internal/cli/

# GoReleaser is configured in src/.goreleaser.yaml but runs from the repo root:
# its archives bundle LICENSE/README/CHANGELOG, and GoReleaser's file globbing
# will not climb out of its working directory to reach them. builds[].dir points
# the compile step back into the module. CI passes the same --config.
GORELEASER := goreleaser --config $(MODULE)/.goreleaser.yaml

cross: ## build every release target into build/dist/ (needs goreleaser)
	$(GORELEASER) build --clean --snapshot

dist: ## full release artifacts into build/dist/ (needs goreleaser)
	$(GORELEASER) release --clean --snapshot

# Everything generated lives under build/, so this empties it. It used to remove
# `bin dist`, and GoReleaser has written to build/dist since the single-folder
# layout was adopted - so `make clean` left every release artifact behind while
# reporting success. Then it named $(BIN) and build/dist explicitly, which left
# anything else that had found its way in - a renamed artifact, a file from an
# older layout, output from a tool run by hand.
#
# So it removes everything except what git tracks. KEEP is that list, and
# TestBuildDirKeepListMatchesGit fails if the two ever disagree.
KEEP := targets.txt

clean: ## empty build/, keeping only the files git tracks there
	@if [ -d build ]; then \
		find build -mindepth 1 -maxdepth 1 $(foreach k,$(KEEP),! -name '$(k)') -exec rm -rf {} + ; \
	fi

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
