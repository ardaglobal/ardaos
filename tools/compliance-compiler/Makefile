# ArdaOS Compliance Compiler Makefile

# Variables
BINARY_NAME=compliance-compiler
VERSION?=dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)"

# Go related variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOBUILD=$(GOBASE)/build
GOFILES=$(wildcard *.go)

# Build targets
.PHONY: help build install clean test test-unit test-race test-cover lint fmt fmt-check vet deps example-policies docs

## help: Show this help message
help: Makefile
	@echo "Available targets:"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'

## build: Build the compliance-compiler binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(GOBUILD)
	go build $(LDFLAGS) -o $(GOBUILD)/$(BINARY_NAME) .
	@echo "Binary built: $(GOBUILD)/$(BINARY_NAME)"

## install: Install the compliance-compiler binary to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) .
	@echo "$(BINARY_NAME) installed to $(shell go env GOPATH)/bin"

## clean: Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(GOBUILD)
	rm -rf $(GOBIN)
	go clean -cache
	go clean -testcache

## test: Run all tests
test: test-unit vet lint

## test-unit: Run unit tests
test-unit:
	@echo "Running unit tests..."
	go test -v ./...

## test-race: Run tests with race condition detection
test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

## test-cover: Run tests with coverage report
test-cover:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## bench: Run benchmark tests
bench:
	@echo "Running benchmark tests..."
	go test -bench=. -benchmem ./...

## lint: Run golangci-lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.61.0"; \
	fi

## fmt: Format Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

## fmt-check: Check if code is formatted
fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(go fmt ./...)" ]; then \
		echo "Code is not formatted. Run 'make fmt' to fix."; \
		exit 1; \
	fi
	@echo "Code is properly formatted."

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## deps: Download and tidy dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

## example-policies: Generate example policies
example-policies:
	@echo "Generating example policies..."
	@mkdir -p examples/generated
	$(GOBUILD)/$(BINARY_NAME) generate --type basic --output examples/generated/basic_example.yaml
	$(GOBUILD)/$(BINARY_NAME) generate --type regional --region US --output examples/generated/us_regional_example.yaml
	$(GOBUILD)/$(BINARY_NAME) generate --type asset --asset-type loan --output examples/generated/loan_asset_example.yaml

## validate-examples: Validate all example policies
validate-examples: build
	@echo "Validating example policies..."
	$(GOBUILD)/$(BINARY_NAME) validate -r examples/policies

## compile-examples: Compile all example policies
compile-examples: build
	@echo "Compiling example policies..."
	@mkdir -p examples/compiled
	@for policy in examples/policies/*.yaml; do \
		echo "Compiling $$policy..."; \
		$(GOBUILD)/$(BINARY_NAME) compile --format json --overwrite -d examples/compiled $$policy; \
	done

## test-examples: Test example policies
test-examples: build
	@echo "Testing example policies..."
	@for policy in examples/policies/*.yaml; do \
		echo "Testing $$policy..."; \
		$(GOBUILD)/$(BINARY_NAME) test -t examples/test-data/sample_transactions.json $$policy || true; \
	done

## docs: Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs/generated
	$(GOBUILD)/$(BINARY_NAME) --help > docs/generated/cli-help.txt
	$(GOBUILD)/$(BINARY_NAME) compile --help > docs/generated/compile-help.txt
	$(GOBUILD)/$(BINARY_NAME) validate --help > docs/generated/validate-help.txt
	$(GOBUILD)/$(BINARY_NAME) test --help > docs/generated/test-help.txt
	$(GOBUILD)/$(BINARY_NAME) generate --help > docs/generated/generate-help.txt
	$(GOBUILD)/$(BINARY_NAME) generate --list-types > docs/generated/template-types.txt

## dev-setup: Set up development environment
dev-setup: deps
	@echo "Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.61.0; \
	fi
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi

## release-build: Build binaries for multiple platforms
release-build: clean
	@echo "Building release binaries..."
	@mkdir -p $(GOBUILD)/release

	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(GOBUILD)/release/$(BINARY_NAME)-linux-amd64 .

	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(GOBUILD)/release/$(BINARY_NAME)-linux-arm64 .

	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(GOBUILD)/release/$(BINARY_NAME)-darwin-amd64 .

	# macOS ARM64
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(GOBUILD)/release/$(BINARY_NAME)-darwin-arm64 .

	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(GOBUILD)/release/$(BINARY_NAME)-windows-amd64.exe .

	@echo "Release binaries built in $(GOBUILD)/release/"

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t arda-os/compliance-compiler:$(VERSION) .
	docker tag arda-os/compliance-compiler:$(VERSION) arda-os/compliance-compiler:latest

## docker-run: Run compliance-compiler in Docker
docker-run:
	docker run --rm -v $(PWD)/examples:/examples arda-os/compliance-compiler:latest --help

## integration-test: Run integration tests
integration-test: build validate-examples compile-examples
	@echo "Running integration tests..."
	@echo "✓ Build completed successfully"
	@echo "✓ Example validation completed"
	@echo "✓ Example compilation completed"
	@echo "Integration tests passed!"

## ci: Run continuous integration checks
ci: deps fmt-check vet lint test test-race
	@echo "All CI checks passed!"

## security-scan: Run security scanning
security-scan:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

## performance-test: Run performance tests
performance-test: build
	@echo "Running performance tests..."
	@mkdir -p examples/performance
	@echo "Testing compilation performance..."
	time $(GOBUILD)/$(BINARY_NAME) compile examples/policies/us_regional.yaml -o examples/performance/perf_test.pb
	@echo "Testing validation performance..."
	time $(GOBUILD)/$(BINARY_NAME) validate -r examples/policies
	@echo "Performance tests completed"

## all: Run all common development tasks
all: clean dev-setup build test lint integration-test docs
	@echo "All development tasks completed successfully!"

# Default target
.DEFAULT_GOAL := help

# Variables for tracking build info
BUILD_INFO_FILE := build_info.txt

## build-info: Display build information
build-info:
	@echo "Compliance Compiler Build Information"
	@echo "====================================="
	@echo "Binary Name: $(BINARY_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Go Version: $(shell go version | cut -d' ' -f3-)"
	@echo "Platform: $(shell go env GOOS)/$(shell go env GOARCH)"

## version: Display version information
version: build
	$(GOBUILD)/$(BINARY_NAME) --version
