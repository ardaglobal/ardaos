# Development Setup

This document provides instructions for setting up the development environment for ArdaOS.

## Quick Start

1. **Initial Setup**
   ```bash
   make setup-dev
   ```
   This installs pre-commit hooks and required Go development tools.

2. **Build the Project**
   ```bash
   ignite chain build
   ```

3. **Run Tests**
   ```bash
   make test
   ```

## Development Workflow

### Code Formatting
- Code formatting is handled automatically by pre-commit hooks
- Manual formatting: `make fmt` and `make fmt-imports`
- Check formatting: `make fmt-check`

### Linting
- Pre-commit hooks run `make lint-source` automatically
- Manual linting: `make lint` (all files) or `make lint-source` (source only)
- Fix issues automatically: `make lint-fix`

### Testing
- `make test` - Full test suite with linting and security checks
- `make test-unit` - Unit tests only
- `make test-race` - Tests with race condition detection
- `make test-cover` - Tests with coverage report

### Pre-commit Hooks

Pre-commit hooks are automatically installed and will run:
- Go formatting checks
- Import organization
- Linting (source code only)
- Go vet
- Module verification and tidying
- YAML validation
- Basic file checks (trailing whitespace, merge conflicts, etc.)

If any hook fails, the commit will be rejected. Fix the issues and try again.

### Generated Files

The project contains auto-generated protobuf files in `api/` directory that may have linting issues. The development setup is configured to:
- Exclude generated files from pre-commit hooks
- Use `make lint-source` for linting source code only
- Skip generated files in formatting checks

### IDE Setup

VS Code settings are provided in `.vscode/settings.json` with:
- Go language server configuration
- Automatic formatting on save
- Import organization
- golangci-lint integration

## Troubleshooting

### Pre-commit Installation Issues
If pre-commit installation fails, install manually:
```bash
# macOS
brew install pre-commit

# Python
pip install pre-commit

# Then install hooks
pre-commit install
```

### Linting Issues in Generated Files
Use `make lint-source` instead of `make lint` to avoid issues with generated protobuf files.

### Test Failures
Ensure you have the latest dependencies:
```bash
go mod tidy
go mod verify
```
