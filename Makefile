SHELL := /bin/sh

GOLANGCI_LINT_VERSION := v2.1.6
GITLEAKS_VERSION := v8.24.2
GO_BIN := $(shell go env GOPATH)/bin
LAB_HOST := $(shell if [ -f /.dockerenv ]; then echo host.docker.internal; else echo 127.0.0.1; fi)

.PHONY: bootstrap dev build run test test-integration lab-up lab-down fetch-knowledge lint fmt clean

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
	docker compose -f deploy/compose.yaml up -d --build llm-echo
	@trap 'docker compose -f deploy/compose.yaml down --volumes' EXIT; \
		i=0; \
		until curl --fail --silent "http://$(LAB_HOST):4010/healthz" >/dev/null; do \
			i=$$((i + 1)); \
			if [ "$$i" -ge 30 ]; then echo "local lab did not become ready"; exit 1; fi; \
			sleep 1; \
		done; \
		SENTINEL_INTEGRATION_LLM_URL="http://$(LAB_HOST):4010/v1/chat" \
		SENTINEL_INTEGRATION_NMAP_TARGET="$(LAB_HOST)" \
		SENTINEL_INTEGRATION_NMAP_PORT=4010 \
		go test -tags=integration ./... -count=1

lab-up:
	docker compose -f deploy/compose.yaml --profile web up -d --build llm-echo juice-shop

lab-down:
	docker compose -f deploy/compose.yaml --profile web down --volumes

fetch-knowledge:
	./scripts/fetch-knowledge.sh

lint:
	"$(GO_BIN)/golangci-lint" run
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

clean:
	go clean
