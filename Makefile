SHELL := /bin/sh

GO ?= go
GO_MOD_FLAG ?= -mod=vendor
BUF ?= buf
SUDO ?= sudo
VERSION ?= dev

export GOCACHE ?= $(CURDIR)/.gocache

BIN_DIR := bin
DIST_DIR := dist
RULE_BUNDLE ?= $(DIST_DIR)/baseline-rules.yaml
RULE_ARTIFACT_REF ?=
RULE_ARTIFACT_DIR ?= $(DIST_DIR)/rules-artifact
INTEGRATION_TEST_BIN ?= /tmp/cicd-sensor-kerneltracker-it.test

LINUX_BINS := cicd-sensor cicd-sensor-manager cicd-sensorctl
LINUX_ARCHES := amd64 arm64
CTL_CROSS_TARGETS := darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf '%s\n' 'Common targets:'
	@printf '  %-29s %s\n' 'make generate' 'regenerate proto and BPF artifacts'
	@printf '  %-29s %s\n' 'make test' 'run the normal Go test suite'
	@printf '  %-29s %s\n' 'make check' 'run generation, tests, rule validation, and diff checks'
	@printf '  %-29s %s\n' 'make build' 'build Linux amd64/arm64 release binaries into ./dist'
	@printf '  %-29s %s\n' 'make build-ctl-cross' 'build cicd-sensorctl for macOS/Windows into ./dist'
	@printf '  %-29s %s\n' 'make build-local-ctl' 'build cicd-sensorctl for the local host into ./bin'
	@printf '  %-29s %s\n' 'make bench-cel' 'run CEL evaluation benchmark once'
	@printf '  %-29s %s\n' 'make rules-bundle' 'bundle rules/ into $(RULE_BUNDLE)'
	@printf '  %-29s %s\n' 'make rules-artifact-validate' 'pull and validate an OCI rules artifact'
	@printf '  %-29s %s\n' 'make test-integration' 'run privileged Linux integration tests'
	@printf '  %-29s %s\n' 'make vendor' 'refresh vendor/ from go.mod'
	@printf '  %-29s %s\n' 'make clean' 'remove local build outputs'

.PHONY: generate
generate: generate-proto generate-bpf

.PHONY: generate-proto
generate-proto:
	$(BUF) generate

.PHONY: generate-bpf
generate-bpf:
	$(GO) generate $(GO_MOD_FLAG) ./internal/agent/bpf

.PHONY: tidy
tidy:
	$(GO) mod tidy
	$(GO) mod vendor

.PHONY: vendor
vendor:
	$(GO) mod vendor

.PHONY: build-local-ctl
build-local-ctl:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GO_MOD_FLAG) -o $(BIN_DIR)/cicd-sensorctl ./cmd/cicd-sensorctl

.PHONY: build
build: build-linux

.PHONY: build-linux
build-linux:
	mkdir -p $(DIST_DIR)
	@set -eu; \
	for arch in $(LINUX_ARCHES); do \
		for bin in $(LINUX_BINS); do \
			echo "building $$bin linux/$$arch"; \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build $(GO_MOD_FLAG) \
				-trimpath \
				-buildvcs=false \
				-ldflags "-s -w -X main.version=$(VERSION)" \
				-o "$(DIST_DIR)/$${bin}_linux_$${arch}" \
				"./cmd/$$bin"; \
		done; \
	done

.PHONY: build-ctl-cross
build-ctl-cross:
	mkdir -p $(DIST_DIR)
	@set -eu; \
	for target in $(CTL_CROSS_TARGETS); do \
		os="$${target%/*}"; arch="$${target#*/}"; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "building cicd-sensorctl $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build $(GO_MOD_FLAG) \
			-trimpath \
			-buildvcs=false \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o "$(DIST_DIR)/cicd-sensorctl_$${os}_$${arch}$${ext}" \
			./cmd/cicd-sensorctl; \
	done

.PHONY: test
test:
	$(GO) test $(GO_MOD_FLAG) -count=1 ./...

.PHONY: bench-cel
bench-cel:
	$(GO) test $(GO_MOD_FLAG) -bench='BenchmarkEvaluate' -run='^$$' -benchmem ./internal/agent/evaluation

.PHONY: test-abi
test-abi:
	$(GO) test $(GO_MOD_FLAG) -tags kernel_sample_abi -count=1 ./internal/agent/kerneltracker/...

.PHONY: test-integration-compile
test-integration-compile:
	GOOS=linux GOARCH=amd64 $(GO) test $(GO_MOD_FLAG) -c -tags integration -o $(INTEGRATION_TEST_BIN) ./internal/agent/kerneltracker

.PHONY: test-integration
test-integration:
	$(SUDO) -n env GOCACHE=$(GOCACHE) $(GO) test $(GO_MOD_FLAG) -tags integration -count=1 ./internal/agent/kerneltracker ./internal/agent/kerneltracker/kernelio

.PHONY: rules-validate
rules-validate:
	$(GO) run $(GO_MOD_FLAG) ./cmd/cicd-sensorctl rule validate rules/

.PHONY: rules-bundle
rules-bundle:
	mkdir -p $(DIST_DIR)
	rm -f $(RULE_BUNDLE)
	$(GO) run $(GO_MOD_FLAG) ./cmd/cicd-sensorctl rule bundle --input-dir rules --output-file $(RULE_BUNDLE)

.PHONY: rules-bundle-validate
rules-bundle-validate: rules-bundle
	$(GO) run $(GO_MOD_FLAG) ./cmd/cicd-sensorctl rule validate $(RULE_BUNDLE)

.PHONY: rules-artifact-validate
rules-artifact-validate:
	@test -n "$(RULE_ARTIFACT_REF)" || { echo "RULE_ARTIFACT_REF is required"; exit 1; }
	rm -rf $(RULE_ARTIFACT_DIR)
	mkdir -p $(RULE_ARTIFACT_DIR)
	oras pull -o $(RULE_ARTIFACT_DIR) $(RULE_ARTIFACT_REF)
	test -f $(RULE_ARTIFACT_DIR)/baseline-rules.yaml.gz
	gzip -dc $(RULE_ARTIFACT_DIR)/baseline-rules.yaml.gz > $(RULE_ARTIFACT_DIR)/baseline-rules.yaml
	$(GO) run $(GO_MOD_FLAG) ./cmd/cicd-sensorctl rule validate $(RULE_ARTIFACT_DIR)/baseline-rules.yaml

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
