# See https://tech.davis-hansson.com/p/make/
SHELL := bash
.DELETE_ON_ERROR:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-print-directory
BIN := .tmp/bin
export PATH := $(abspath $(BIN)):$(PATH)
export GOBIN := $(abspath $(BIN))
COPYRIGHT_YEARS := 2023-2026
LICENSE_IGNORE := --ignore testdata/

# https://github.com/bufbuild/buf/releases
BUF_VERSION := v1.68.4
GOLANGCI_LINT_VERSION := v2.11.4
# This version is the go toolchain version (which may be more specific than the module
# version) to ensure the build handles specific language features in newer toolchains.
GOLANGCILINT_GOTOOLCHAIN_VERSION := $(shell go env GOVERSION | sed 's/^go//')

.PHONY: help
help: ## Describe useful make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-30s %s\n", $$1, $$2}'

.PHONY: all
all: ## Build, test, and lint (default)
	$(MAKE) test
	$(MAKE) lint

.PHONY: clean
clean: ## Delete intermediate build artifacts
	@# -X only removes untracked files, -d recurses into directories, -f actually removes files/dirs
	git clean -Xdf

.PHONY: test
test: build ## Run unit tests
	go test -vet=off -race -cover ./...

.PHONY: build
build: generate ## Build all packages
	go build ./...

.PHONY: lint
lint: $(BIN)/golangci-lint $(BIN)/buf ## Lint
	go vet ./...
	GOTOOLCHAIN=go$(GOLANGCILINT_GOTOOLCHAIN_VERSION) $(BIN)/golangci-lint fmt --diff
	GOTOOLCHAIN=go$(GOLANGCILINT_GOTOOLCHAIN_VERSION) $(BIN)/golangci-lint run --modules-download-mode=readonly --timeout=3m0s
	buf lint
	buf format -d --exit-code

.PHONY: lintfix
lintfix: $(BIN)/golangci-lint ## Automatically fix some lint errors
	GOTOOLCHAIN=go$(GOLANGCILINT_GOTOOLCHAIN_VERSION) $(BIN)/golangci-lint fmt
	GOTOOLCHAIN=go$(GOLANGCILINT_GOTOOLCHAIN_VERSION) $(BIN)/golangci-lint run --fix --modules-download-mode=readonly --timeout=3m0s
	buf format -w

.PHONY: install
install: ## Install all binaries
	go install ./...

.PHONY: generate
generate: $(BIN)/license-header $(BIN)/buf ## Regenerate code and licenses
	rm -rf internal/gen
	buf generate
	license-header \
		--license-type apache \
		--copyright-holder "Buf Technologies, Inc." \
		--year-range "$(COPYRIGHT_YEARS)" $(LICENSE_IGNORE)

.PHONY: golden
golden:
	find internal/testdata -name "*.txt" -type f -delete
	go run internal/cmd/generate-txt-testdata/main.go internal/testdata

.PHONY: upgrade
upgrade: ## Upgrade dependencies
	go get -u -t ./...
	go mod tidy -v
	buf mod update internal/proto

.PHONY: checkgenerate
checkgenerate:
	@# Used in CI to verify that `make generate` doesn't produce a diff.
	test -z "$$(git status --porcelain | tee /dev/stderr)"

$(BIN)/buf: Makefile
	@mkdir -p $(@D)
	go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

$(BIN)/license-header: Makefile
	@mkdir -p $(@D)
	go install \
		  github.com/bufbuild/buf/private/pkg/licenseheader/cmd/license-header@$(BUF_VERSION)

$(BIN)/golangci-lint: Makefile
	@mkdir -p $(@D)
	GOTOOLCHAIN=go$(GOLANGCILINT_GOTOOLCHAIN_VERSION) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
