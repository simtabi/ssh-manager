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

.PHONY: help build test vet fmt fmt-check lint check e2e feature-check \
        cross dist clean doctor reconcile render rotate bundle

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

build: ## compile the binary into bin/
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

test: ## run the unit suite
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt every file in place
	gofmt -w cmd internal

fmt-check: ## fail if anything is unformatted (what CI gates on)
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

lint: ## golangci-lint, if installed
	@command -v golangci-lint >/dev/null 2>&1 \
		&& golangci-lint run \
		|| echo "golangci-lint not installed - skipping (go vet still runs in 'make check')"

check: fmt-check vet test ## everything CI gates on

e2e: build ## end-to-end smoke in a throwaway sandbox
	SSHMGR=$(CURDIR)/$(BIN) .build/e2e.sh

feature-check: build ## exercise every command with assertions
	SSHMGR=$(CURDIR)/$(BIN) .build/feature-check.sh

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
