SHELL := /bin/sh

GO ?= go
BUF ?= buf
SUDO ?= sudo

export GOCACHE ?= $(CURDIR)/.gocache

BIN_DIR := bin
DIST_DIR := dist
RULE_BUNDLE ?= $(DIST_DIR)/baseline-rules.yaml
INTEGRATION_TEST_BIN ?= /tmp/cicd-sensor-kerneltracker-it.test

LINUX_BINS := cicd-sensor cicd-sensor-manager cicd-sensorctl
LINUX_ARCHES := amd64 arm64

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf '%s\n' 'Common targets:'
	@printf '  %-24s %s\n' 'make generate' 'regenerate proto and BPF artifacts'
	@printf '  %-24s %s\n' 'make test' 'run the normal Go test suite'
	@printf '  %-24s %s\n' 'make check' 'run generation, tests, rule validation, and diff checks'
	@printf '  %-24s %s\n' 'make build' 'build Linux amd64/arm64 release binaries into ./dist'
	@printf '  %-24s %s\n' 'make build-local-ctl' 'build cicd-sensorctl for the local host into ./bin'
	@printf '  %-24s %s\n' 'make bench-cel' 'run CEL evaluation benchmark once'
	@printf '  %-24s %s\n' 'make rules-bundle' 'bundle rules/ into $(RULE_BUNDLE)'
	@printf '  %-24s %s\n' 'make test-integration' 'run privileged Linux integration tests'
	@printf '  %-24s %s\n' 'make clean' 'remove local build outputs'

.PHONY: generate
generate: generate-proto generate-bpf

.PHONY: generate-proto
generate-proto:
	$(BUF) generate

.PHONY: generate-bpf
generate-bpf:
	$(GO) generate ./internal/agent/bpf

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: build-local-ctl
build-local-ctl:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/cicd-sensorctl ./cmd/cicd-sensorctl

.PHONY: build
build: build-linux

.PHONY: build-linux
build-linux:
	mkdir -p $(DIST_DIR)
	@set -eu; \
	for arch in $(LINUX_ARCHES); do \
		for bin in $(LINUX_BINS); do \
			echo "building $$bin linux/$$arch"; \
			GOOS=linux GOARCH=$$arch $(GO) build -o "$(DIST_DIR)/$${bin}_linux_$${arch}" "./cmd/$$bin"; \
		done; \
	done

.PHONY: test
test:
	$(GO) test -count=1 ./...

.PHONY: bench-cel
bench-cel:
	$(GO) test -bench='BenchmarkEvaluate' -run='^$$' -benchmem ./internal/agent/evaluation

.PHONY: test-abi
test-abi:
	$(GO) test -tags kernel_sample_abi -count=1 ./internal/agent/kerneltracker/...

.PHONY: test-integration-compile
test-integration-compile:
	GOOS=linux GOARCH=amd64 $(GO) test -c -tags integration -o $(INTEGRATION_TEST_BIN) ./internal/agent/kerneltracker

.PHONY: test-integration
test-integration:
	$(SUDO) -n env GOCACHE=$(GOCACHE) $(GO) test -tags integration -count=1 ./internal/agent/kerneltracker ./internal/agent/kerneltracker/kernelio

.PHONY: rules-validate
rules-validate:
	$(GO) run ./cmd/cicd-sensorctl rule validate rules/

.PHONY: rules-bundle
rules-bundle:
	mkdir -p $(DIST_DIR)
	rm -f $(RULE_BUNDLE)
	$(GO) run ./cmd/cicd-sensorctl rule bundle --input-dir rules --output $(RULE_BUNDLE)

.PHONY: rules-bundle-validate
rules-bundle-validate: rules-bundle
	$(GO) run ./cmd/cicd-sensorctl rule validate $(RULE_BUNDLE)

.PHONY: diff-check
diff-check:
	git diff --check
	git diff --exit-code

.PHONY: check
check: generate test test-abi rules-validate rules-bundle-validate test-integration-compile diff-check

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -rf $(DIST_DIR)
	rm -f $(INTEGRATION_TEST_BIN)

.PHONY: clean-cache
clean-cache: clean
	rm -rf $(GOCACHE)
