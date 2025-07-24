# ArdaOS Compliance Compiler

A comprehensive policy compilation and validation tool for ArdaOS blockchain compliance engine, supporting all major small business finance verticals with multi-jurisdictional regulatory compliance.

[![CI/CD](https://github.com/ardaos/arda-os/workflows/Compliance%20Compiler%20CI/CD/badge.svg)](https://github.com/ardaos/arda-os/actions)
[![Docker](https://img.shields.io/docker/pulls/ardaos/compliance-compiler)](https://hub.docker.com/r/ardaos/compliance-compiler)
[![Go Report Card](https://goreportcard.com/badge/github.com/ardaos/arda-os/tools/compliance-compiler)](https://goreportcard.com/report/github.com/ardaos/arda-os/tools/compliance-compiler)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## How It Works

The ArdaOS Compliance Compiler transforms YAML compliance policies into blockchain-ready protobuf format through a modern, multi-stage architecture:

### 🔄 **Processing Pipeline**

```
YAML Policy → JSON Schema Validation → Protobuf Conversion → Blockchain Output
     ↓              ↓                         ↓                    ↓
  Parse YAML    Validate Fields       Convert to Proto     Binary/JSON/Text
  Structure     Check Rules           Use Generated        Ready for ArdaOS
                Suggest Fixes         Types (Buf CLI)
```

### 🏗️ **Architecture Components**

1. **📋 JSON Schema Validation**
   - Comprehensive validation against `schemas/compliance-policy.json`
   - Intelligent error messages with actionable suggestions
   - Jurisdiction-specific and asset-class-specific warnings
   - Best practices recommendations (e.g., missing metadata, enforcement config)

2. **🔧 Buf CLI Integration**
   - Modern protobuf management with `buf.yaml` configuration
   - Generated Go types in `gen/compliance/v1/` package
   - Linting, breaking change detection, and dependency management
   - Clean separation between schema definition and code generation

3. **⚙️ Multi-Stage Parser**
   - YAML parsing with syntax validation
   - JSON Schema validation with detailed error reporting
   - Protobuf conversion using generated types
   - Multiple output formats (binary, JSON, text)

### 🏦 **Finance Verticals Supported**
- **Credit Card Receivables**: CFPB/CARD Act, EU PSD2, risk-based underwriting
- **Installment Loans**: TILA compliance, state-specific requirements, ability-to-repay
- **Merchant Cash Advances**: Revenue-based qualification, daily collection, state regulations
- **Equipment Leasing**: UCC Article 9 compliance, collateral valuation, lease classification
- **Working Capital**: Asset-based lending, receivables factoring, inventory financing

### 🌍 **Multi-Jurisdictional Compliance**
- **US Federal**: CFPB, FDCPA, TILA, UCC, CARD Act
- **State-Specific**: New York, California, Texas, and other state regulations
- **International**: EU PSD2, other regional frameworks
- **Smart Validation**: Jurisdiction-aware validation with targeted suggestions

### 🚀 **Developer Experience**
- **Rich CLI Interface**: Colored output, progress bars, intelligent error messages
- **Multiple Output Formats**: Binary protobuf, JSON (debugging), text (human-readable)
- **Comprehensive Validation**: Schema validation with suggestions and warnings
- **Performance Optimized**: Sub-second compilation times with efficient parsing

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

The compliance compiler currently supports the `compile` command with comprehensive JSON Schema validation:

#### Compile Policy to Different Formats
```bash
# Compile to JSON format (for debugging and inspection)
compliance-compiler compile policy.yaml --format json

# Compile to binary protobuf (for ArdaOS blockchain)
compliance-compiler compile policy.yaml --format binary -o policy.pb

# Compile to text format (human-readable)
compliance-compiler compile policy.yaml --format text

# Quiet mode for CI/CD pipelines
compliance-compiler compile policy.yaml --quiet
```

#### Example Policy Structure
```yaml
# Minimal credit card policy example
policy_id: "credit_card_policy"
version: "1.0.0"
jurisdiction: "US"
asset_class: "credit-card"

rules:
  - name: "Credit Score Check"
    description: "Borrower must have minimum credit score"
    predicate:
      field: "borrower.credit_score"
      op: "gte"
      value: 620
    required: true

metadata:
  title: "Credit Card Compliance Policy"
  description: "Basic credit card receivables policy"
  author: "Compliance Team"
```

#### Validation Output
The tool provides intelligent validation with suggestions:
```bash
$ compliance-compiler compile policy.yaml --format json

🚀 Starting compilation of: policy.yaml
📖 Parsing and validating YAML policy file...
  ⚠️  3 warnings found:
    • metadata: Missing metadata section (Suggestion: Add metadata section...)
    • enforcement: Missing enforcement configuration (Suggestion: Add enforcement section...)
    • rules: Consider adding ability-to-pay assessment rules for US credit card compliance
  ✅ Policy parsed and validated successfully
```

## Policy Templates

The compliance compiler includes comprehensive policy templates for all supported finance verticals:

### Credit Card Receivables
- **US CFPB/CARD Act**: Ability-to-pay assessment, rate increase protections
- **EU PSD2**: Consumer protection, strong customer authentication
- **Risk-Based Underwriting**: Credit scoring, debt-to-income analysis
- **Forward Flow Agreements**: Portfolio sale compliance

## Examples

### Credit Card Policy Validation
```bash
# Validate CFPB CARD Act compliance
compliance-compiler validate examples/templates/credit-card/us-cfpb-card-act.yaml

# Test with sample data
compliance-compiler test examples/templates/credit-card/us-cfpb-card-act.yaml \
  --test-data examples/test-data/credit-card/positive-test-cases.json
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

The compliance compiler uses a comprehensive JSON Schema for validation. Policies follow this structure:

```yaml
# Required fields
policy_id: "unique_policy_identifier"
version: "1.0.0"                    # Semantic versioning
jurisdiction: "US"                   # US, EU, CA, UK, etc.
asset_class: "credit-card"          # credit-card, installment-loan, mca, etc.

# Rules define compliance conditions
rules:
  - name: "Rule Name"
    description: "Detailed rule description"
    predicate:
      # Comparison predicate
      field: "borrower.credit_score"
      op: "gte"                     # eq, ne, gt, gte, lt, lte, contains
      value: 620
    required: true                  # true for required rules
    priority: 10                    # 1-100 (1=highest priority)
    tags: ["credit", "underwriting"] # Optional categorization

  # Logical predicates (AND, OR, NOT)
  - name: "Complex Logic Rule"
    predicate:
      and:
        - field: "borrower.income"
          op: "gt"
          value: 50000
        - field: "borrower.employment_status"
          op: "eq"
          value: "employed"

  # Existence predicates
  - name: "Required Field Check"
    predicate:
      exists: "borrower.ssn"
      should_exist: true

  # Range predicates
  - name: "Debt to Income Range"
    predicate:
      range:
        field: "borrower.debt_to_income_ratio"
        max: 0.43
        max_inclusive: true

# Optional sections
attestations:
  - name: "Credit Bureau Check"
    type: "credit_check"           # Predefined attestation types
    required: true

enforcement:
  level: "blocking"                # advisory, warning, blocking, quarantine, reject
  actions:
    - "log"
    - "block_transaction"

metadata:
  title: "Human-readable policy title"
  description: "Detailed policy description"
  author: "Policy author"
  tags: ["compliance", "credit-card"]
```

### JSON Schema Validation

The tool validates policies against `schemas/compliance-policy.json` and provides:

- **Field Validation**: Required fields, data types, format validation
- **Enum Validation**: Jurisdiction codes, asset classes, operators, etc.
- **Pattern Validation**: Policy IDs, version numbers, field paths
- **Business Logic**: Cross-field validation and consistency checks
- **Best Practices**: Warnings for missing recommended sections
- **Jurisdiction-Specific**: Smart suggestions based on jurisdiction and asset class

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
