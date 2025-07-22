#!/bin/bash

set -e

echo "Setting up development environment..."

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo "Installing pre-commit..."
    if command -v pip &> /dev/null; then
        pip install pre-commit
    elif command -v pip3 &> /dev/null; then
        pip3 install pre-commit
    elif command -v brew &> /dev/null; then
        brew install pre-commit
    else
        echo "Please install pre-commit manually: https://pre-commit.com/#installation"
        exit 1
    fi
fi

# Install pre-commit hooks
echo "Installing pre-commit hooks..."
pre-commit install

# Install Go tools
echo "Installing Go development tools..."
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
go install golang.org/x/vuln/cmd/govulncheck@latest

echo "Development environment setup complete!"
echo ""
echo "Available make commands:"
echo "  make fmt          - Format Go code"
echo "  make fmt-imports  - Fix imports"
echo "  make fmt-check    - Check formatting"
echo "  make lint         - Run linter"
echo "  make lint-fix     - Run linter with fixes"
echo "  make test         - Run all tests"
echo "  make govet        - Run go vet"
echo "  make govulncheck  - Check vulnerabilities"
echo ""
echo "Pre-commit hooks are now installed and will run automatically on git commit."
