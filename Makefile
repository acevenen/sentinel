SHELL := /bin/sh

GOLANGCI_LINT_VERSION := v2.1.6
GITLEAKS_VERSION := v8.24.2
GO_BIN := $(shell go env GOPATH)/bin

.PHONY: bootstrap dev build run test test-integration fetch-knowledge lint fmt clean

bootstrap:
	go mod download
	@if [ ! -x "$(GO_BIN)/golangci-lint" ]; then \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi
	@if [ ! -x "$(GO_BIN)/gitleaks" ]; then \
		go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION); \
	fi
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit

dev:
	@command -v devcontainer >/dev/null 2>&1 || { \
		echo "Install the Dev Container CLI: npm install -g @devcontainers/cli"; \
		exit 1; \
	}
	devcontainer up --workspace-folder .

build:
	go build -trimpath -o sentinel .

run:
	go run . $(ARGS)

test:
	go test ./... -race

test-integration:
	go test -tags=integration ./... -count=1

fetch-knowledge:
	@echo "Knowledge sources are introduced in Phase 6; nothing to fetch yet."

lint:
	"$(GO_BIN)/golangci-lint" run
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

clean:
	go clean
