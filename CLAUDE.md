# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ArdaOS** is a Private Markets Operating System - a sovereign blockchain built with Cosmos SDK and Ignite CLI designed to standardize and modernize private market asset workflows. It enables compliant, automated small business finance applications while maintaining regional sovereignty.

### Mission
Transform private markets from offline, fragmented, and manual processes into on-chain, compliant, and automated workflows while maintaining regional sovereignty and regulatory compliance.

## Architecture

ArdaOS implements Arda's region-first architecture:
- **Regional Sovereignty**: Each chain enforces local regulations, validator sets, and compliance rules
- **Asset-Centric Design**: Protocol-native modules for loan origination, syndication, escrow, and transfers
- **Compliance by Design**: KYC, AML, and regulatory requirements embedded at the state machine level
- **Global Interoperability**: Native IBC support and bridging to external networks via Arda Bridge

### Core Structure
- **app/**: Main application setup with dependency injection using depinject
- **x/**: Custom Cosmos SDK modules for private markets:
  - `tokenfactory/`: Loan token issuance and management
  - `syndication/`: Multi-lender workflows
  - `escrow/`: Trust-minimized escrow
  - `compliance/`: Regulatory enforcement
- **cmd/ardaosd/**: CLI daemon binary entry point
- **proto/**: Protocol buffer definitions for custom modules
- **api/**: Generated Go code from protobuf definitions (Pulsar API)

### Small Business Finance Applications
ArdaOS supports five core verticals:
1. **Credit Card Receivables**: Revolving credit lines with forward flow agreements
2. **Installment Loans**: Fixed principal with predictable cashflow streams
3. **Merchant Cash Advances**: Upfront cash against future revenue streams
4. **Small Ticket Equipment Leasing**: Equipment financing with physical asset backing
5. **Working Capital Loans**: Short-term financing for cash flow management

## Development Setup

### Initial Setup
```bash
make setup-dev      # Install pre-commit hooks and development tools
```

This will:
- Install pre-commit hooks that run automatically on git commits
- Install required Go tools (goimports, golangci-lint, govulncheck)
- Configure the development environment

### Build & Install
```bash
make install          # Build and install the ardaosd binary
ignite chain build    # Alternative build via Ignite CLI
go build -o build/ ./cmd/ardaosd  # Manual build
```

### Development Server
```bash
ignite chain serve    # Start development blockchain with automatic rebuild
```

### Testing
```bash
make test            # Run full test suite (includes govet, govulncheck, unit tests)
make test-unit       # Unit tests only
make test-race       # Unit tests with race condition detection
make test-cover      # Unit tests with coverage report
make bench           # Benchmark tests
ignite chain test    # Run all tests via Ignite CLI
go test ./...        # Direct Go test execution
```

### Code Quality & Formatting
```bash
make fmt            # Format Go code with gofmt
make fmt-imports    # Fix imports with goimports
make fmt-check      # Check if code is properly formatted
make lint           # Run golangci-lint v1.61.0 on all files
make lint-fix       # Run linter with automatic fixes
make lint-source    # Run linter on source code only (excludes generated files)
make govet          # Run go vet
make govulncheck    # Check for security vulnerabilities
```

**Note:** The project includes auto-generated protobuf files that may have linting issues. Use `make lint-source` to lint only the source code, or the pre-commit hooks will automatically run this for you.

### Protocol Buffers
```bash
make proto-deps     # Install protobuf generation dependencies
make proto-gen      # Generate Go code from .proto files (uses ignite)
ignite generate proto-go --yes  # Direct proto generation
```

## Configuration

- **config.yml**: Ignite chain configuration with validator setup and test accounts
- **buf.yaml**: Protocol buffer linting and generation config
- **go.mod**: Uses Go 1.21+ with Cosmos SDK v0.50.14
- **genesis.json**: Genesis state configuration for private markets modules

## Key Development Notes

- Use `ignite` CLI for most development tasks rather than direct Go commands
- The blockchain runs with 4 validators (alice, validator1, validator2, validator3) in development
- Test accounts: alice (20000token, 200000000stake), bob (10000token, 100000000stake)
- Private markets modules should be implemented in `x/` directory following Cosmos SDK patterns
- Core modules: tokenfactory, syndication, escrow, compliance
- Always run `make test` before committing to ensure code quality standards
- Focus on regulatory compliance and asset-centric design patterns
- Maintain regional sovereignty while enabling global interoperability

## Security & Compliance

- **Consensus Model**: Proof of Authority (PoA) with permissioned validator sets
- **Identity Verification**: KYC-verified institutional validators required
- **Regional Governance**: Local regulatory authority control
- **Privacy Features**: Selective disclosure with ZK proofs for compliance
- **Data Residency**: Regional data sovereignty guarantees

## Interoperability

- **IBC Protocol**: Native Cosmos ecosystem connectivity
- **Arda Bridge**: Cross-chain asset transfers via Hyperlane
- **Zero-Knowledge Proofs**: Privacy-preserving bridging options
- **Global Coordination**: Settlement through Arda Core layer
