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
COPYRIGHT_YEARS := 2025
LICENSE_IGNORE := --ignore testdata/

BUF_VERSION := v1.53.0
GO_MOD_GOTOOLCHAIN := go1.24.3
GOLANGCI_LINT_VERSION := v1.64.8
# https://github.com/golangci/golangci-lint/issues/4837
GOLANGCI_LINT_GOTOOLCHAIN := $(GO_MOD_GOTOOLCHAIN)
#GO_GET_PKGS :=

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

.PHONY: install
install: ## Install all binaries
	go install ./...

.PHONY: lint
lint: $(BIN)/golangci-lint ## Lint
	go vet ./...
	GOTOOLCHAIN=$(GOLANGCI_LINT_GOTOOLCHAIN) golangci-lint run --modules-download-mode=readonly --timeout=3m0s

.PHONY: lintfix
lintfix: $(BIN)/golangci-lint ## Automatically fix some lint errors
	GOTOOLCHAIN=$(GOLANGCI_LINT_GOTOOLCHAIN) golangci-lint run --fix --modules-download-mode=readonly --timeout=3m0s

.PHONY: generate
generate: $(BIN)/license-header ## Regenerate code and licenses
	license-header \
		--license-type apache \
		--copyright-holder "Buf Technologies, Inc." \
		--year-range "$(COPYRIGHT_YEARS)" $(LICENSE_IGNORE)

.PHONY: upgrade
upgrade: ## Upgrade dependencies
	go mod edit -toolchain=$(GO_MOD_GOTOOLCHAIN)
	go get -u -t ./... $(GO_GET_PKGS)
	go mod tidy -v

.PHONY: checkgenerate
checkgenerate:
	@# Used in CI to verify that `make generate` doesn't produce a diff.
	test -z "$$(git status --porcelain | tee /dev/stderr)"

$(BIN)/license-header: Makefile
	@mkdir -p $(@D)
	go install github.com/bufbuild/buf/private/pkg/licenseheader/cmd/license-header@$(BUF_VERSION)

$(BIN)/golangci-lint: Makefile
	@mkdir -p $(@D)
	GOTOOLCHAIN=$(GOLANGCI_LINT_GOTOOLCHAIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
