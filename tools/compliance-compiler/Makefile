# ArdaOS Compliance Compiler Build System
# Build, test, and distribution automation for the compliance compiler tool

.DEFAULT_GOAL := help
.PHONY: help build test clean install proto deps build-all release docker lint fmt vet bench integration-test validate-examples update-schemas

# Build configuration
BINARY_NAME := compliance-compiler
MAIN_PACKAGE := ./cmd/compliance-compiler
BUILD_DIR := bin
COVERAGE_FILE := coverage.out
COVERAGE_HTML := coverage.html

# Version and build information
VERSION ?= $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

# Build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT) -X main.gitBranch=$(GIT_BRANCH)"

# Go configuration
GO := go
GOFMT := gofmt
GOLINT := golangci-lint
GOVET := go vet
GOTEST := go test

# External tools
BUF := buf
PROTOC_GEN_GO := protoc-gen-go

# Docker configuration
DOCKER_IMAGE := ardaos/compliance-compiler
DOCKER_TAG := $(VERSION)

# Platform targets for cross-compilation
PLATFORMS := linux/amd64 darwin/amd64 darwin/arm64 windows/amd64

help: ## Display this help message
	@echo "ArdaOS Compliance Compiler Build System"
	@echo "======================================="
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Build flags:"
	@echo "  VERSION=$(VERSION)"
	@echo "  BUILD_TIME=$(BUILD_TIME)"
	@echo "  GIT_COMMIT=$(GIT_COMMIT)"
	@echo "  GIT_BRANCH=$(GIT_BRANCH)"

# =============================================================================
# Build Targets
# =============================================================================

build: deps ## Build the compliance compiler binary
	@echo "Building compliance compiler..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-all: deps ## Build cross-platform binaries for all supported platforms
	@echo "Building cross-platform binaries..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d'/' -f1); \
		ARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT_NAME=$(BINARY_NAME)-$$OS-$$ARCH; \
		if [ "$$OS" = "windows" ]; then OUTPUT_NAME=$$OUTPUT_NAME.exe; fi; \
		echo "Building for $$OS/$$ARCH..."; \
		GOOS=$$OS GOARCH=$$ARCH $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$$OUTPUT_NAME $(MAIN_PACKAGE); \
	done
	@echo "Cross-platform build complete"
	@ls -la $(BUILD_DIR)/

build-release: clean deps ## Build optimized release binaries
	@echo "Building optimized release binaries..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d'/' -f1); \
		ARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT_NAME=$(BINARY_NAME)-$$OS-$$ARCH; \
		if [ "$$OS" = "windows" ]; then OUTPUT_NAME=$$OUTPUT_NAME.exe; fi; \
		echo "Building optimized binary for $$OS/$$ARCH..."; \
		CGO_ENABLED=0 GOOS=$$OS GOARCH=$$ARCH $(GO) build \
			-a -installsuffix cgo \
			-ldflags "-s -w $(LDFLAGS)" \
			-o $(BUILD_DIR)/$$OUTPUT_NAME $(MAIN_PACKAGE); \
	done
	@echo "Release build complete"

install: build ## Install the binary to $GOPATH/bin
	@echo "Installing compliance compiler to $(GOPATH)/bin..."
	$(GO) install $(LDFLAGS) $(MAIN_PACKAGE)
	@echo "Installation complete"

# =============================================================================
# Testing Targets
# =============================================================================

test: deps ## Run unit tests with coverage
	@echo "Running unit tests..."
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) ./...
	@if [ -f $(COVERAGE_FILE) ]; then \
		$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML); \
		echo "Coverage report generated: $(COVERAGE_HTML)"; \
		$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1; \
	fi

test-unit: deps ## Run unit tests only (no coverage)
	@echo "Running unit tests..."
	$(GOTEST) -v ./...

test-race: deps ## Run tests with race condition detection
	@echo "Running tests with race detection..."
	$(GOTEST) -race ./...

test-coverage: deps ## Generate detailed coverage report
	@echo "Generating detailed coverage report..."
	$(GOTEST) -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo "Coverage report: $(COVERAGE_HTML)"

bench: deps ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	$(GOTEST) -bench=. -benchmem -run=^$$ ./internal/compiler
	$(GOTEST) -bench=. -benchmem -run=^$$ ./internal/parser
	@echo "Benchmark complete"

integration-test: build ## Run integration tests
	@echo "Running integration tests..."
	@if [ -f ./scripts/run-integration-tests.sh ]; then \
		chmod +x ./scripts/run-integration-tests.sh; \
		./scripts/run-integration-tests.sh; \
	else \
		echo "Integration test script not found, creating..."; \
		mkdir -p scripts; \
		echo "#!/bin/bash" > ./scripts/run-integration-tests.sh; \
		echo "# Integration tests for compliance compiler" >> ./scripts/run-integration-tests.sh; \
		echo "echo 'Running integration tests...'" >> ./scripts/run-integration-tests.sh; \
		echo "./$(BUILD_DIR)/$(BINARY_NAME) validate ./examples/" >> ./scripts/run-integration-tests.sh; \
		echo "./$(BUILD_DIR)/$(BINARY_NAME) test ./examples/test-data/" >> ./scripts/run-integration-tests.sh; \
		chmod +x ./scripts/run-integration-tests.sh; \
		./scripts/run-integration-tests.sh; \
	fi

validate-examples: build ## Validate all example policies
	@echo "Validating example policies..."
	@if [ -d ./examples ]; then \
		./$(BUILD_DIR)/$(BINARY_NAME) validate ./examples/ --recursive --format=detailed; \
	else \
		echo "Examples directory not found"; \
	fi

# =============================================================================
# Code Quality Targets
# =============================================================================

fmt: ## Format Go source code
	@echo "Formatting Go code..."
	$(GOFMT) -s -w .
	@echo "Code formatting complete"

fmt-check: ## Check if code is properly formatted
	@echo "Checking code formatting..."
	@if [ -n "$$($(GOFMT) -l .)" ]; then \
		echo "Code is not properly formatted:"; \
		$(GOFMT) -l .; \
		exit 1; \
	fi
	@echo "Code formatting is correct"

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "Vet analysis complete"

lint: deps ## Run golangci-lint
	@echo "Running linter..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not found, installing..."; \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		$(GOLINT) run ./...; \
	fi
	@echo "Linting complete"

lint-fix: deps ## Run golangci-lint with auto-fix
	@echo "Running linter with auto-fix..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run --fix ./...; \
	else \
		echo "golangci-lint not found, installing..."; \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		$(GOLINT) run --fix ./...; \
	fi
	@echo "Linting with fixes complete"

check: fmt-check vet lint test ## Run all code quality checks

# =============================================================================
# Protocol Buffer Targets
# =============================================================================

proto: proto-deps ## Generate Go code from protocol buffer definitions
	@echo "Generating protobuf code..."
	@if [ -d ../../proto ]; then \
		cd ../../proto && $(BUF) generate; \
	else \
		echo "Proto directory not found at ../../proto"; \
	fi
	@echo "Protobuf generation complete"

proto-deps: ## Install protobuf dependencies
	@echo "Installing protobuf dependencies..."
	@if ! command -v $(BUF) >/dev/null 2>&1; then \
		echo "Installing buf..."; \
		$(GO) install github.com/bufbuild/buf/cmd/buf@latest; \
	fi
	@if ! command -v $(PROTOC_GEN_GO) >/dev/null 2>&1; then \
		echo "Installing protoc-gen-go..."; \
		$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
	fi
	@echo "Protobuf dependencies installed"

proto-lint: proto-deps ## Lint protocol buffer files
	@echo "Linting protobuf files..."
	@if [ -d ../../proto ]; then \
		cd ../../proto && $(BUF) lint; \
	else \
		echo "Proto directory not found at ../../proto"; \
	fi

# =============================================================================
# Dependency Management
# =============================================================================

deps: ## Download and verify dependencies
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod verify
	@echo "Dependencies ready"

deps-update: ## Update all dependencies
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "Dependencies updated"

deps-clean: ## Clean module cache
	@echo "Cleaning module cache..."
	$(GO) clean -modcache
	@echo "Module cache cleaned"

# =============================================================================
# Docker Targets
# =============================================================================

docker: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

docker-push: docker ## Build and push Docker image
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest
	@echo "Docker image pushed"

docker-run: docker ## Run Docker container
	@echo "Running Docker container..."
	docker run --rm -v $(PWD)/examples:/examples $(DOCKER_IMAGE):$(DOCKER_TAG) validate /examples

# =============================================================================
# Release Targets
# =============================================================================

release: clean build-release ## Create release artifacts
	@echo "Creating release artifacts..."
	@mkdir -p dist
	@for file in $(BUILD_DIR)/$(BINARY_NAME)-*; do \
		if [ -f "$$file" ]; then \
			basename=$$(basename $$file); \
			echo "Creating archive for $$basename..."; \
			if echo "$$basename" | grep -q "windows"; then \
				zip "dist/$${basename%.exe}.zip" -j "$$file" README.md LICENSE; \
			else \
				tar -czf "dist/$$basename.tar.gz" -C $(BUILD_DIR) "$$(basename $$file)" -C .. README.md LICENSE; \
			fi; \
		fi; \
	done
	@echo "Release artifacts created in dist/"
	@ls -la dist/

checksums: release ## Generate checksums for release artifacts
	@echo "Generating checksums..."
	@cd dist && sha256sum * > SHA256SUMS
	@echo "Checksums generated: dist/SHA256SUMS"

# =============================================================================
# Utility Targets
# =============================================================================

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf dist
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@echo "Clean complete"

version: ## Display version information
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Git Branch: $(GIT_BRANCH)"

env: ## Display build environment
	@echo "Build Environment:"
	@echo "=================="
	@echo "GO: $(shell $(GO) version)"
	@echo "GOPATH: $(GOPATH)"
	@echo "GOROOT: $(GOROOT)"
	@echo "PWD: $(PWD)"
	@echo "BUILD_DIR: $(BUILD_DIR)"
	@echo "BINARY_NAME: $(BINARY_NAME)"

update-schemas: ## Update policy schemas from regulatory sources
	@echo "Updating policy schemas..."
	@if [ -f ./scripts/update-schemas.sh ]; then \
		chmod +x ./scripts/update-schemas.sh; \
		./scripts/update-schemas.sh; \
	else \
		echo "Schema update script not found, creating placeholder..."; \
		mkdir -p scripts; \
		echo "#!/bin/bash" > ./scripts/update-schemas.sh; \
		echo "# Update policy schemas from regulatory sources" >> ./scripts/update-schemas.sh; \
		echo "echo 'Schema update placeholder - implement regulatory source updates'" >> ./scripts/update-schemas.sh; \
		chmod +x ./scripts/update-schemas.sh; \
	fi

# =============================================================================
# Development Targets
# =============================================================================

dev-setup: deps proto-deps ## Set up development environment
	@echo "Setting up development environment..."
	@if ! command -v $(GOLINT) >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "Development environment ready"

dev-watch: ## Watch for changes and rebuild (requires fswatch)
	@echo "Watching for changes..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | while read f; do make build; done; \
	else \
		echo "fswatch not found. Install with: brew install fswatch"; \
	fi

# =============================================================================
# CI/CD Integration
# =============================================================================

ci-test: deps ## Run tests suitable for CI environment
	@echo "Running CI tests..."
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@if [ -f $(COVERAGE_FILE) ]; then \
		$(GO) tool cover -func=$(COVERAGE_FILE); \
	fi

ci-build: clean deps ## Build for CI environment
	@echo "Running CI build..."
	@make build-release
	@make checksums

ci-security: deps ## Run security checks for CI
	@echo "Running security checks..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "Installing govulncheck..."; \
		$(GO) install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./...; \
	fi

# =============================================================================
# Performance and Monitoring
# =============================================================================

profile-cpu: build ## Run CPU profiling
	@echo "Running CPU profile..."
	@mkdir -p profiles
	./$(BUILD_DIR)/$(BINARY_NAME) compile ./examples/ --cpuprofile=profiles/cpu.prof
	$(GO) tool pprof profiles/cpu.prof

profile-mem: build ## Run memory profiling
	@echo "Running memory profile..."
	@mkdir -p profiles
	./$(BUILD_DIR)/$(BINARY_NAME) compile ./examples/ --memprofile=profiles/mem.prof
	$(GO) tool pprof profiles/mem.prof

benchmark-regression: ## Run benchmark regression tests
	@echo "Running benchmark regression tests..."
	@if [ -f ./scripts/benchmark.sh ]; then \
		chmod +x ./scripts/benchmark.sh; \
		./scripts/benchmark.sh; \
	else \
		echo "Benchmark script not found, running basic benchmarks..."; \
		make bench; \
	fi
