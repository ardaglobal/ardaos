# ArdaOS Compliance Compiler Build System
# Build, test, and distribution automation for the compliance compiler tool

.DEFAULT_GOAL := help
.PHONY: help build test clean install proto deps build-all release docker lint fmt vet bench integration-test validate-examples update-schemas

# Build configuration
BINARY_NAME := compliance-compiler
MAIN_PACKAGE := .
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

## help: Get more info on make commands.
help: Makefile
	@echo " Choose a command run in "$(APPNAME)":"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
.PHONY: help

# =============================================================================
# Build Targets
# =============================================================================

## build: Build the compliance compiler binary.
build: deps ## Build the compliance compiler binary
	@echo "Building compliance compiler..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

## build-all: Build cross-platform binaries for all supported platforms.
build-all: deps
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

## build-release: Build optimized release binaries.
build-release: clean deps
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

## install: Install the binary to $GOPATH/bin.
install: build
	@echo "Installing compliance compiler to $(GOPATH)/bin..."
	$(GO) install $(LDFLAGS) $(MAIN_PACKAGE)
	@echo "Installation complete"

# =============================================================================
# Testing Targets
# =============================================================================

## test: Run unit tests with coverage.
test: deps
	@echo "Running unit tests..."
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) ./...
	@if [ -f $(COVERAGE_FILE) ]; then \
		$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML); \
		echo "Coverage report generated: $(COVERAGE_HTML)"; \
		$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1; \
	fi

## test-unit: Run unit tests only (no coverage).
test-unit: deps
	@echo "Running unit tests..."
	$(GOTEST) -v ./...

## test-race: Run tests with race condition detection.
test-race: deps
	@echo "Running tests with race detection..."
	$(GOTEST) -race ./...

## test-coverage: Generate detailed coverage report.
test-coverage: deps
	@echo "Generating detailed coverage report..."
	$(GOTEST) -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo "Coverage report: $(COVERAGE_HTML)"

## bench: Run performance benchmarks.
bench: deps
	@echo "Running performance benchmarks..."
	$(GOTEST) -bench=. -benchmem -run=^$$ ./internal/compiler
	$(GOTEST) -bench=. -benchmem -run=^$$ ./internal/parser
	@echo "Benchmark complete"

## integration-test: Run integration tests.
integration-test: build
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

## validate-examples: Validate all example policies.
validate-examples: build
	@echo "Validating example policies..."
	@if [ -d ./examples ]; then \
		./$(BUILD_DIR)/$(BINARY_NAME) validate ./examples/ --recursive --format=detailed; \
	else \
		echo "Examples directory not found"; \
	fi

# =============================================================================
# Code Quality Targets
# =============================================================================

## fmt: Format Go source code.
fmt:
	@echo "Formatting Go code..."
	$(GOFMT) -s -w .
	@echo "Code formatting complete"

## fmt-check: Check if code is properly formatted.
fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$($(GOFMT) -l .)" ]; then \
		echo "Code is not properly formatted:"; \
		$(GOFMT) -l .; \
		exit 1; \
	fi
	@echo "Code formatting is correct"

## vet: Run go vet.
vet:
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "Vet analysis complete"

## lint: Run golangci-lint.
lint: deps
	@echo "Running linter..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not found, installing..."; \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		$(GOLINT) run ./...; \
	fi
	@echo "Linting complete"

## lint-fix: Run golangci-lint with auto-fix.
lint-fix: deps
	@echo "Running linter with auto-fix..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run --fix ./...; \
	else \
		echo "golangci-lint not found, installing..."; \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		$(GOLINT) run --fix ./...; \
	fi
	@echo "Linting with fixes complete"

## check: Run all code quality checks.
check: fmt-check vet lint test

# =============================================================================
# Protocol Buffer Targets
# =============================================================================

## proto: Generate Go code from protocol buffer definitions.
proto: proto-deps
	@echo "Generating protobuf code..."
	@if [ -f buf.yaml ]; then \
		$(BUF) generate; \
	else \
		echo "buf.yaml not found - ensure you're in the compliance-compiler directory"; \
		exit 1; \
	fi
	@echo "Protobuf generation complete"

## proto-deps: Install protobuf dependencies.
proto-deps:
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

## proto-lint: Lint protocol buffer files.
proto-lint: proto-deps
	@echo "Linting protobuf files..."
	@if [ -f buf.yaml ]; then \
		$(BUF) lint; \
	else \
		echo "buf.yaml not found - ensure you're in the compliance-compiler directory"; \
		exit 1; \
	fi

# =============================================================================
# Dependency Management
# =============================================================================

## deps: Download and verify dependencies.
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod verify
	@echo "Dependencies ready"

## deps-update: Update all dependencies.
deps-update:
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "Dependencies updated"

## deps-clean: Clean module cache.
deps-clean:
	@echo "Cleaning module cache..."
	$(GO) clean -modcache
	@echo "Module cache cleaned"

# =============================================================================
# Docker Targets
# =============================================================================

## docker: Build Docker image.
docker:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

## docker-push: Build and push Docker image.
docker-push: docker
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest
	@echo "Docker image pushed"

## docker-run: Run Docker container.
docker-run: docker
	@echo "Running Docker container..."
	docker run --rm -v $(PWD)/examples:/examples $(DOCKER_IMAGE):$(DOCKER_TAG) validate /examples

# =============================================================================
# Release Targets
# =============================================================================

## release: Create release artifacts.
release: clean build-release
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

## checksums: Generate checksums for release artifacts.
checksums: release
	@echo "Generating checksums..."
	@cd dist && sha256sum * > SHA256SUMS
	@echo "Checksums generated: dist/SHA256SUMS"

# =============================================================================
# Utility Targets
# =============================================================================

## clean: Clean build artifacts.
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf dist
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@echo "Clean complete"

## version: Display version information.
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Git Branch: $(GIT_BRANCH)"

## env: Display build environment.
env:
	@echo "Build Environment:"
	@echo "=================="
	@echo "GO: $(shell $(GO) version)"
	@echo "GOPATH: $(GOPATH)"
	@echo "GOROOT: $(GOROOT)"
	@echo "PWD: $(PWD)"
	@echo "BUILD_DIR: $(BUILD_DIR)"
	@echo "BINARY_NAME: $(BINARY_NAME)"

## update-schemas: Update policy schemas from regulatory sources.
update-schemas:
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

## dev-setup: Set up development environment.
dev-setup: deps proto-deps
	@echo "Setting up development environment..."
	@if ! command -v $(GOLINT) >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "Development environment ready"

## dev-watch: Watch for changes and rebuild (requires fswatch).
dev-watch:
	@echo "Watching for changes..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | while read f; do make build; done; \
	else \
		echo "fswatch not found. Install with: brew install fswatch"; \
	fi

# =============================================================================
# CI/CD Integration
# =============================================================================

## ci-test: Run tests suitable for CI environment.
ci-test: deps proto
	@echo "Running CI tests..."
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@if [ -f $(COVERAGE_FILE) ]; then \
		$(GO) tool cover -func=$(COVERAGE_FILE); \
	fi

## ci-build: Build for CI environment.
ci-build: clean deps
	@echo "Running CI build..."
	@make build-release
	@make checksums

## ci-security: Run security checks for CI.
ci-security: deps
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

## profile-cpu: Run CPU profiling.
profile-cpu: build
	@echo "Running CPU profile..."
	@mkdir -p profiles
	./$(BUILD_DIR)/$(BINARY_NAME) compile ./examples/ --cpuprofile=profiles/cpu.prof
	$(GO) tool pprof profiles/cpu.prof

## profile-mem: Run memory profiling.
profile-mem: build
	@echo "Running memory profile..."
	@mkdir -p profiles
	./$(BUILD_DIR)/$(BINARY_NAME) compile ./examples/ --memprofile=profiles/mem.prof
	$(GO) tool pprof profiles/mem.prof

## benchmark-regression: Run benchmark regression tests.
benchmark-regression:
	@echo "Running benchmark regression tests..."
	@if [ -f ./scripts/benchmark.sh ]; then \
		chmod +x ./scripts/benchmark.sh; \
		./scripts/benchmark.sh; \
	else \
		echo "Benchmark script not found, running basic benchmarks..."; \
		make bench; \
	fi
