# See https://tech.davis-hansson.com/p/make/
SHELL := bash
.DELETE_ON_ERROR:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --no-print-directory
BIN := .tmp/bin
export PATH := $(BIN):$(PATH)
export GOBIN := $(abspath $(BIN))
COPYRIGHT_YEARS := 2023-2024
LICENSE_IGNORE := --ignore testdata/

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
	$(BIN)/golangci-lint fmt --diff
	$(BIN)/golangci-lint run
	buf lint
	buf format -d --exit-code

.PHONY: lintfix
lintfix: $(BIN)/golangci-lint ## Automatically fix some lint errors
	$(BIN)/golangci-lint fmt
	$(BIN)/golangci-lint run --fix
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

$(BIN):
	@mkdir -p $(BIN)

$(BIN)/buf: $(BIN) Makefile
	go install github.com/bufbuild/buf/cmd/buf@v1.51.0

$(BIN)/license-header: $(BIN) Makefile
	go install \
		  github.com/bufbuild/buf/private/pkg/licenseheader/cmd/license-header@v1.51.0

$(BIN)/golangci-lint: $(BIN) Makefile
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.0.2
