SHELL := /bin/sh

GOLANGCI_LINT_VERSION := v2.1.6
GO_BIN := $(shell go env GOPATH)/bin

.PHONY: bootstrap build run test test-race cover lint fmt vet clean

bootstrap:
	go mod download
	@if [ ! -x "$(GO_BIN)/golangci-lint" ]; then \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi

build:
	go build -trimpath -o reverso .

run:
	go run . $(ARGS)

test:
	go test ./...

test-race:
	go test ./... -race

cover:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out | tail -1

lint:
	"$(GO_BIN)/golangci-lint" run
	go vet ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go')

clean:
	go clean
	rm -f reverso coverage.out
