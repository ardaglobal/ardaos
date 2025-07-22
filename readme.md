# ArdaOS - Private Markets Operating System

A sovereign blockchain built with Cosmos SDK and [Ignite CLI](https://ignite.com), designed to standardize and modernize private market asset workflows. ArdaOS enables compliant, automated small business finance applications while maintaining regional sovereignty.

## 🎯 Mission

Transform private markets from offline, fragmented, and manual processes into on-chain, compliant, and automated workflows while maintaining regional sovereignty and regulatory compliance.

## 🏗️ Architecture Overview

ArdaOS implements Arda's region-first architecture:

- **Regional Sovereignty**: Each chain enforces local regulations, validator sets, and compliance rules
- **Asset-Centric Design**: Protocol-native modules for loan origination, syndication, escrow, and transfers
- **Compliance by Design**: KYC, AML, and regulatory requirements embedded at the state machine level
- **Global Interoperability**: Native IBC support and bridging to external networks via Arda Bridge

## 🚀 Quick Start

### Prerequisites

- **Go**: 1.21+
- **Ignite CLI**: v28.0.0+ ([installation guide](https://docs.ignite.com/welcome/install))
- **Docker**: Latest (optional, for containerized development)

### Development Tools

The following tools are required for development and will be automatically installed when you run `make setup-dev`:

- **goimports**: Automatic import organization and formatting
- **golangci-lint v1.61.0**: Comprehensive Go linter with strict quality checks
- **govulncheck**: Security vulnerability scanner for Go dependencies
- **pre-commit**: Git hooks for automated code quality checks

#### Manual Installation (if needed)

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0

# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Install goimports
go install golang.org/x/tools/cmd/goimports@latest

# Install pre-commit (requires Python/pip)
pip install pre-commit
```

### Installation

```bash
# Clone the repository
git clone https://github.com/arda-global/ardaos.git
cd ardaos

# Setup development environment (installs tools and pre-commit hooks)
make setup-dev

# Install dependencies
go mod tidy
```

### Development Server

```bash
# Start the development server with hot reload
ignite chain serve

# This will:
# - Build and start your blockchain in development
# - Rebuild and restart on file changes
# - Initialize with test accounts and configuration
# - Start API server at localhost:1317
# - Start RPC server at localhost:26657
# - Start gRPC server at localhost:9090
```

### Manual Build & Run

```bash
# Build the binary
ignite chain build

# Or build manually
go build -o build/ ./cmd/ardaosd

# Initialize the chain
./build/ardaosd init mynode --chain-id ardaos-testnet-1

# Add test account (pre-configured with ignite chain serve)
./build/ardaosd keys add alice

# Start the blockchain
./build/ardaosd start
```

### Interact with your chain

```bash
# Query chain status
ardaosd status

# Send tokens
ardaosd tx bank send alice $(ardaosd keys show bob -a) 1000stake --from alice --chain-id ardaos-testnet-1

# Query account balance
ardaosd q bank balances $(ardaosd keys show alice -a)
```

## 🏦 Small Business Finance Applications

ArdaOS supports five core small business finance verticals:

### 1. Credit Card Receivables
- **Product**: Revolving credit lines for business expenses
- **Receivable**: Outstanding card balances with accrued interest
- **Capital Flow**: Forward flow agreements, warehouse lines, ABS securitization

### 2. Installment Loans
- **Product**: Fixed principal with scheduled repayments
- **Receivable**: Predictable cashflow streams from borrowers
- **Capital Flow**: Post-origination purchases, warehouse facilities, loan pooling

### 3. Merchant Cash Advances (MCA)
- **Product**: Upfront cash against future revenue streams
- **Receivable**: Percentage of daily card sales until repayment
- **Capital Flow**: Daily collection mechanisms, participation interests

### 4. Small Ticket Equipment Leasing
- **Product**: Equipment financing with fixed payment schedules
- **Receivable**: Lease contracts backed by physical assets
- **Capital Flow**: Equipment purchases, sale-leaseback arrangements

### 5. Working Capital Loans
- **Product**: Short-term financing for cash flow management
- **Receivable**: AR/inventory-backed loan obligations
- **Capital Flow**: Invoice factoring, inventory finance, borrowing base facilities

## 🔧 Core Modules

### Token Factory Module
Issues and manages programmable loan tokens with embedded:
- Transfer restrictions and jurisdiction compliance
- Amortization schedules and payment automation
- Dynamic rights evolution (PIK toggles, conversions)
- Multi-tranche waterfall distributions

### Syndication Module
Automates loan syndication workflows:
- Book-building and allocation logic
- Multi-lender compliance verification
- Automated settlement and distribution

### Escrow Module
Trust-minimized escrow with:
- Programmable milestone releases
- Multi-signature governance
- Dispute resolution mechanisms
- Automated covenant monitoring

### Compliance Module
Protocol-embedded regulatory enforcement:
- Real-time KYC/AML verification
- Jurisdiction-specific rule engines
- Sanctions screening integration
- Continuous covenant monitoring

## 📁 Project Structure (Ignite-Generated)

```
├── app/                    # Blockchain application setup
├── cmd/                    # CLI commands and daemon
├── docs/                   # Documentation
├── proto/                  # Protocol buffer definitions
├── testutil/               # Test utilities and helpers
├── x/                      # Custom Cosmos SDK modules
│   ├── tokenfactory/       # Loan token issuance and management
│   ├── syndication/        # Multi-lender workflows
│   ├── escrow/            # Trust-minimized escrow
│   └── compliance/        # Regulatory enforcement
├── config.yml             # Ignite chain configuration
└── genesis.json           # Genesis state configuration
```

## 🔗 Interoperability

ArdaOS connects to the broader blockchain ecosystem through:

- **IBC Protocol**: Native Cosmos ecosystem connectivity
- **Arda Bridge**: Cross-chain asset transfers via Hyperlane
- **Zero-Knowledge Proofs**: Privacy-preserving bridging options
- **Global Coordination**: Settlement through Arda Core layer

## 📊 Data Standards

All assets follow the Arda Taxonomy with:
- ISO 20022 financial messaging alignment
- ISDA derivatives definitions
- LMA syndicated lending standards
- Regional compliance extensions

## 🛡️ Security & Compliance

### Consensus Model
- **Proof of Authority (PoA)**: Permissioned validator sets
- **Identity Verification**: KYC-verified institutional validators
- **Regional Governance**: Local regulatory authority control

### Privacy Features
- **Arda Vault**: Encrypted off-chain document storage
- **Selective Disclosure**: ZK proofs for compliance verification
- **Data Residency**: Regional data sovereignty guarantees

## 🧪 Testing & Code Quality

```bash
# Run all tests with quality checks
make test

# Run unit tests only
make test-unit

# Run with coverage
make test-cover

# Run integration tests
ignite chain simulate

# Code quality and formatting
make fmt              # Format Go code
make fmt-imports      # Fix imports with goimports
make lint             # Run golangci-lint on all files
make lint-source      # Run linter on source code only (excludes generated files)
make govet            # Run go vet
make govulncheck      # Check for security vulnerabilities

# Check if code is properly formatted
make fmt-check

# Run linter with automatic fixes
make lint-fix
```

## 🚧 Development Roadmap

### Phase 1: Core Infrastructure ✅
- [x] Ignite CLI project scaffolding
- [x] Token Factory module (in development)
- [x] Basic escrow functionality
- [x] Compliance rule framework

### Phase 2: Advanced Features 🚧
- [ ] Syndication module with book-building
- [ ] AI agent integration framework
- [ ] IBC cross-chain connectivity
- [ ] Advanced privacy features (FHE, MPC)

### Phase 3: Market Integration 📋
- [ ] KYC provider integrations
- [ ] Credit bureau data feeds
- [ ] Regulatory reporting automation
- [ ] Secondary market trading

## 🔧 Development Commands

```bash
# Generate new module
ignite scaffold module [module-name]

# Generate message types
ignite scaffold message [message-name] [field1] [field2] --module [module-name]

# Generate queries
ignite scaffold query [query-name] [field1] [field2] --module [module-name]

# Generate types
ignite scaffold type [type-name] [field1] [field2] --module [module-name]

# Add new chain dependency
ignite chain init
ignite chain serve --reset-once  # Reset chain data
```

## 📖 Documentation

- [Ignite CLI Documentation](https://docs.ignite.com)
- [Cosmos SDK Documentation](https://docs.cosmos.network)
- [Technical Architecture](./docs/architecture.md)
- [Module Development Guide](./docs/modules.md)
- [Compliance Integration](./docs/compliance.md)

## 🤝 Contributing

We welcome contributions from the private markets and blockchain communities:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow Go best practices and Cosmos SDK conventions
- Use Ignite CLI for scaffolding new modules and types
- Write comprehensive tests for new functionality
- Update protobuf definitions for API changes
- Ensure compliance with regional regulatory requirements

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Website**: [arda.xyz](https://arda.xyz)
- **Documentation**: [docs.arda.xyz](https://docs.arda.xyz)
- **Discord**: [discord.gg/arda](https://discord.gg/arda)
- **Twitter**: [@ArdaGlobal](https://twitter.com/ArdaGlobal)

## ⚠️ Disclaimer

This is experimental software for private markets infrastructure. Use in production environments requires thorough security audits and regulatory approval in your jurisdiction.

---

**Built with ❤️ by the Arda team using [Ignite CLI](https://ignite.com) to reprogram private markets globally, delivered locally.**
