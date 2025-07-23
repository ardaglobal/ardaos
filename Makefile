BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT := $(shell git log -1 --format='%H')
APPNAME := arda-os

# don't override user values
ifeq (,$(VERSION))
  VERSION := $(shell git describe --exact-match 2>/dev/null)
  # if VERSION is empty, then populate it with branch's name and raw commit hash
  ifeq (,$(VERSION))
    VERSION := $(BRANCH)-$(COMMIT)
  endif
endif

## help: Get more info on make commands.
help: Makefile
	@echo " Choose a command run in "$(APPNAME)":"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
.PHONY: help

# Update the ldflags with the app, client & server names
ldflags = -X github.com/cosmos/cosmos-sdk/version.Name=$(APPNAME) \
	-X github.com/cosmos/cosmos-sdk/version.AppName=$(APPNAME)d \
	-X github.com/cosmos/cosmos-sdk/version.Version=$(VERSION) \
	-X github.com/cosmos/cosmos-sdk/version.Commit=$(COMMIT)

BUILD_FLAGS := -ldflags '$(ldflags)'

##############
###  Test  ###
##############

## test-unit: Run unit tests.
test-unit:
	@echo Running unit tests...
	@go test -mod=readonly -v -timeout 30m ./...

## test-race: Run unit tests with race condition reporting.
test-race:
	@echo Running unit tests with race condition reporting...
	@go test -mod=readonly -v -race -timeout 30m ./...

## test-cover: Run unit tests and create coverage report.
test-cover:
	@echo Running unit tests and creating coverage report...
	@go test -mod=readonly -v -timeout 30m -coverprofile=$(COVER_FILE) -covermode=atomic ./...
	@go tool cover -html=$(COVER_FILE) -o $(COVER_HTML_FILE)
	@rm $(COVER_FILE)

## bench: Run unit tests with benchmarking.
bench:
	@echo Running unit tests with benchmarking...
	@go test -mod=readonly -v -timeout 30m -bench=. ./...

## test: Run tests.
test: govet test-unit

.PHONY: test test-unit test-race test-cover bench

#################
###  Install  ###
#################

## all: Install the application.
all: install

## install: Install the application.
install:
	@echo "--> ensure dependencies have not been modified"
	@go mod verify
	@echo "--> installing $(APPNAME)d"
	@go install $(BUILD_FLAGS) -mod=readonly ./cmd/$(APPNAME)d

.PHONY: all install

##################
###  Protobuf  ###
##################

# Use this target if you do not want to use Ignite for generating proto files
GOLANG_PROTOBUF_VERSION=1.28.1
GRPC_GATEWAY_VERSION=1.16.0
GRPC_GATEWAY_PROTOC_GEN_OPENAPIV2_VERSION=2.20.0

## proto-deps: Install protobuf dependencies.
proto-deps:
	@echo "Installing proto deps"
	@go install github.com/bufbuild/buf/cmd/buf@v1.50.0
	@go install github.com/cosmos/gogoproto/protoc-gen-gogo@latest
	@go install github.com/cosmos/cosmos-proto/cmd/protoc-gen-go-pulsar@latest
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@v$(GOLANG_PROTOBUF_VERSION)
	@go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway@v$(GRPC_GATEWAY_VERSION)
	@go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v$(GRPC_GATEWAY_PROTOC_GEN_OPENAPIV2_VERSION)
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## proto-gen: Generate protobuf files.
proto-gen:
	@echo "Generating protobuf files..."
	@ignite generate proto-go --yes

.PHONY: proto-deps proto-gen

#################
###  Linting  ###
#################

golangci_lint_cmd=golangci-lint
golangci_version=v1.62.2

## lint: Run linter.
lint:
	@echo "--> Running linter (excluding app directory)"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_version)
	@$(golangci_lint_cmd) run ./cmd/tx-sidecar --timeout 15m

## lint-fix: Run linter and fix issues.
lint-fix:
	@echo "--> Running linter and fixing issues"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_version)
	@$(golangci_lint_cmd) run ./... --fix --timeout 15m

## lint-source: Run linter on source code only.
lint-source:
	@echo "--> Running linter on source code only"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_version)
	@$(golangci_lint_cmd) run ./cmd/... ./x/... --timeout 15m --skip-files '.*\.pb\.go$$,.*\.pulsar\.go$$'

## fmt: Run gofmt.
fmt:
	@echo "--> Running gofmt"
	@find . -name '*.go' -type f -not -path "*/vendor/*" -not -path "*/.*" | xargs gofmt -s -w

## fmt-imports: Run goimports.
fmt-imports:
	@echo "--> Running goimports"
	@go install golang.org/x/tools/cmd/goimports@latest
	@find . -name '*.go' -type f -not -path "*/vendor/*" -not -path "*/.*" | xargs goimports -local arda-os -w

## fmt-check: Check gofmt.
fmt-check:
	@echo "--> Checking gofmt"
	@files=$$(find . -name '*.go' -type f -not -path "*/vendor/*" -not -path "*/.*" | xargs gofmt -s -l); \
	if [ -n "$$files" ]; then \
		echo "The following files are not properly formatted:"; \
		echo "$$files"; \
		exit 1; \
	fi

.PHONY: fmt fmt-imports fmt-check lint lint-fix lint-source

###################
### Development ###
###################

## setup-dev: Setup development environment.
setup-dev:
	@echo "--> Setting up development environment"
	@./scripts/setup-dev.sh

## govet: Run go vet.
govet:
	@echo Running go vet...
	@go vet ./app/... ./cmd/... ./x/...

## govulncheck: Run govulncheck.
govulncheck:
	@echo Running govulncheck...
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@govulncheck ./...

.PHONY: setup-dev govet govulncheck
