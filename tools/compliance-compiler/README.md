# ArdaOS Compliance Compiler

A comprehensive policy compilation and validation tool for ArdaOS blockchain compliance engine, supporting all major small business finance verticals with multi-jurisdictional regulatory compliance.

[![CI/CD](https://github.com/ardaos/arda-os/workflows/Compliance%20Compiler%20CI/CD/badge.svg)](https://github.com/ardaos/arda-os/actions)
[![Docker](https://img.shields.io/docker/pulls/ardaos/compliance-compiler)](https://hub.docker.com/r/ardaos/compliance-compiler)
[![Go Report Card](https://goreportcard.com/badge/github.com/ardaos/arda-os/tools/compliance-compiler)](https://goreportcard.com/report/github.com/ardaos/arda-os/tools/compliance-compiler)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Features

### 🏦 **Comprehensive Finance Verticals**
- **Credit Card Receivables**: CFPB/CARD Act, EU PSD2, risk-based underwriting
- **Installment Loans**: TILA compliance, state-specific requirements, ability-to-repay
- **Merchant Cash Advances**: Revenue-based qualification, daily collection, state regulations
- **Equipment Leasing**: UCC Article 9 compliance, collateral valuation, lease classification
- **Working Capital**: Asset-based lending, receivables factoring, inventory financing

### 🌍 **Multi-Jurisdictional Compliance**
- **US Federal**: CFPB, FDCPA, TILA, UCC, CARD Act
- **State-Specific**: New York, California, Texas, and other state regulations
- **International**: EU PSD2, other regional frameworks
- **Automated Updates**: Regulatory changes tracked and updated automatically

### 🛠️ **Powerful CLI Tool**
- **Policy Compilation**: YAML to optimized protobuf conversion
- **Comprehensive Validation**: Schema validation, regulatory compliance checks
- **Template Generation**: Auto-generate compliant policy templates
- **Testing Framework**: Comprehensive test data and validation

### 🚀 **Developer Experience**
- **Cross-Platform**: Linux, macOS, Windows support
- **Docker Ready**: Containerized for CI/CD integration
- **Performance Optimized**: Sub-second compilation times
- **Comprehensive Documentation**: Examples, guides, and API references

## Quick Start

### Installation

#### One-Line Install (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/ardaos/arda-os/main/tools/compliance-compiler/scripts/install.sh | bash
```

#### Manual Installation
```bash
# Download latest release
wget https://github.com/ardaos/arda-os/releases/latest/download/compliance-compiler-linux-amd64.tar.gz
tar -xzf compliance-compiler-linux-amd64.tar.gz
sudo mv compliance-compiler /usr/local/bin/
```

#### Docker
```bash
docker pull ardaos/compliance-compiler:latest
docker run --rm ardaos/compliance-compiler --help
```

#### From Source
```bash
git clone https://github.com/ardaos/arda-os.git
cd arda-os/tools/compliance-compiler
make build
```

### Basic Usage

#### Validate a Policy
```bash
compliance-compiler validate policy.yaml
```

#### Compile Policy to Protobuf
```bash
compliance-compiler compile policy.yaml -o policy.pb
```

#### Generate Policy Template
```bash
compliance-compiler generate --type credit-card --jurisdiction US --output template.yaml
```

#### Run Tests
```bash
compliance-compiler test policy.yaml --test-data tests/
```

## Policy Templates

The compliance compiler includes comprehensive policy templates for all supported finance verticals:

### Credit Card Receivables
- **US CFPB/CARD Act**: Ability-to-pay assessment, rate increase protections
- **EU PSD2**: Consumer protection, strong customer authentication
- **Risk-Based Underwriting**: Credit scoring, debt-to-income analysis
- **Forward Flow Agreements**: Portfolio sale compliance

### Installment Loans
- **US TILA Compliance**: APR calculation, disclosure requirements
- **Ability-to-Repay**: QM standards, DTI verification
- **State-Specific (CA)**: California CFL requirements
- **Small Business**: SBA compliance, commercial lending standards

### Merchant Cash Advances
- **Revenue-Based Qualification**: Cash flow analysis, industry risk assessment
- **Daily Collection**: ACH compliance, NACHA rules, FDCPA compliance
- **NY State Regulatory**: Commercial financing disclosure law

### Equipment Leasing
- **UCC Article 9**: Security interest creation, perfection, priority
- **Collateral Valuation**: Asset appraisal, depreciation schedules
- **Lease Classification**: Operating vs finance lease determination

### Working Capital Loans
- **Asset-Based Lending**: Collateral monitoring, advance rates
- **Receivables Factoring**: Account debtor verification, collection rights
- **Inventory Financing**: Commodity pricing, storage requirements
- **SBA Compliance**: Government guarantee requirements

## Examples

### Credit Card Policy Validation
```bash
# Validate CFPB CARD Act compliance
compliance-compiler validate examples/templates/credit-card/us-cfpb-card-act.yaml

# Test with sample data
compliance-compiler test examples/templates/credit-card/us-cfpb-card-act.yaml \
  --test-data examples/test-data/credit-card/positive-test-cases.json
```

### MCA Policy Compilation
```bash
# Compile NY state MCA policy
compliance-compiler compile examples/templates/mca/state-regulatory-ny.yaml \
  --format protobuf \
  --output mca-ny-policy.pb \
  --optimize
```

### Equipment Lease Template Generation
```bash
# Generate UCC Article 9 compliant template
compliance-compiler generate \
  --type equipment-lease \
  --jurisdiction US \
  --regulatory-framework "UCC Article 9" \
  --output custom-equipment-lease.yaml
```

## Configuration

The compliance compiler uses a configuration file located at `~/.config/compliance-compiler/config.yaml`:

```yaml
# Default compilation settings
compilation:
  output_format: "protobuf"
  validation_strict: true
  optimization_level: "standard"

# Template settings
templates:
  auto_update: true
  repository: "https://github.com/ardaos/arda-os/tree/main/tools/compliance-compiler/examples/templates"

# Logging configuration
logging:
  level: "info"
  format: "text"
  output: "stdout"
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/ardaos/arda-os.git
cd arda-os/tools/compliance-compiler

# Set up development environment
make dev-setup

# Build binary
make build

# Run tests
make test

# Run benchmarks
make bench
```

### Available Make Targets

```bash
make help                 # Show all available targets
```

### Adding New Templates

1. Create template in appropriate directory under `examples/templates/`
2. Follow the template schema structure
3. Add test data in `examples/test-data/`
4. Validate with `make validate-examples`
5. Update documentation

### Schema Structure

Policy templates follow this structure:

```yaml
# Template metadata
template:
  name: "Policy Name"
  version: "1.0.0"
  jurisdiction: "USA"
  asset_class: "AssetType"
  regulatory_framework: ["Framework1", "Framework2"]

# Configurable parameters
parameters:
  param_name:
    type: "float"
    default: 100.0
    min: 0.0
    max: 1000.0
    description: "Parameter description"

# Policy implementation
policy:
  metadata:
    version: "1.0.0"
    name: "policy-name"

  rules:
    - id: "rule_id"
      name: "Rule Name"
      type: "validation"
      priority: "high"
      conditions:
        - "condition_expression"
      actions:
        - "action_to_take"

  attestations:
    - id: "attestation_id"
      name: "Attestation Name"
      required: true
      fields:
        - "field_name"
```

## API Reference

### CLI Commands

#### `validate`
Validate policy files for correctness and compliance.

```bash
compliance-compiler validate [OPTIONS] <files...>

Options:
  -r, --recursive          Validate directory recursively
  -f, --format FORMAT      Output format (text, json, detailed)
  -s, --strict             Enable strict validation mode
  --fail-on-warnings       Fail on validation warnings
```

#### `compile`
Compile policy files to optimized protobuf format.

```bash
compliance-compiler compile [OPTIONS] <file>

Options:
  -o, --output FILE        Output file path
  -f, --format FORMAT      Output format (protobuf, json)
  -O, --optimize           Enable optimization
  --overwrite              Overwrite existing output file
```

#### `test`
Test policies against sample data.

```bash
compliance-compiler test [OPTIONS] <policy> --test-data <data>

Options:
  -t, --test-data FILE     Test data file (JSON)
  -c, --coverage           Generate coverage report
  -v, --verbose            Verbose output
```

#### `generate`
Generate policy templates from specifications.

```bash
compliance-compiler generate [OPTIONS]

Options:
  --type TYPE              Template type (credit-card, installment-loan, etc.)
  --jurisdiction JURISDICTION  Target jurisdiction (US, EU, etc.)
  --regulatory-framework FRAMEWORK  Regulatory framework
  -o, --output FILE        Output file path
```

## Performance

The compliance compiler is optimized for performance:

- **Sub-second compilation** for most policies
- **Memory efficient** processing of large policy sets
- **Concurrent validation** support
- **Incremental compilation** for development workflows

### Benchmarks

Run performance benchmarks:

```bash
make benchmark-regression
```

Typical performance on modern hardware:
- Small policies (< 10 rules): < 100ms
- Medium policies (10-50 rules): < 500ms
- Large policies (> 50 rules): < 1000ms

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Run `make test lint`
6. Submit a pull request

### Reporting Issues

Please report issues on our [GitHub Issues](https://github.com/ardaos/arda-os/issues) page.

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [Policy Template Reference](docs/template-reference.md)
- [Integration Guide](docs/integration.md)
- [API Documentation](docs/api.md)
- [Examples](examples/)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- 📧 Email: support@ardaos.com
- 💬 Discord: [ArdaOS Community](https://discord.gg/ardaos)
- 📖 Documentation: [docs.ardaos.com](https://docs.ardaos.com/compliance-compiler)
- 🐛 Issues: [GitHub Issues](https://github.com/ardaos/arda-os/issues)

## Acknowledgments

- CFPB for regulatory guidance and API access
- Truth in Lending Act (TILA) implementation guidance
- UCC Article 9 working group contributions
- Open source community for tools and libraries

---

Built with ❤️ by the ArdaOS team for compliant blockchain finance.
