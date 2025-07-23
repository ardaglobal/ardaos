# ArdaOS Compliance Compiler

A standalone Go tool for compiling YAML compliance policies into protobuf format for use with the ArdaOS blockchain compliance modules.

## Overview

The compliance-compiler is an off-chain tool that enables ArdaOS users to:

- **Compile** YAML compliance policies into protobuf format
- **Validate** policy syntax and business logic
- **Test** policies against sample transaction data
- **Generate** policy templates for different regions and asset types

This tool bridges the gap between human-readable compliance policies and the binary format required by ArdaOS blockchain modules.

## Features

### 🔧 Compilation
- Convert YAML policies to protobuf binary, text, or JSON formats
- Optimize policies for runtime execution
- Generate metadata and dependency information

### ✅ Validation
- Syntax validation for YAML structure
- Business logic consistency checks
- Cross-reference validation between rules, conditions, and actions
- Regional compliance requirement verification

### 🧪 Testing
- Execute policies against sample transaction data
- Support for multiple test scenarios
- Performance testing and benchmarking
- Parallel test execution

### 📋 Template Generation
- Generate templates for different regions (US, EU, APAC, etc.)
- Asset-specific templates (loans, equity, bonds, derivatives)
- Interactive template creation wizard
- Customizable business rule templates

## Installation

### Prerequisites
- Go 1.21 or later
- Git

### Build from Source

```bash
# Clone the ArdaOS repository
git clone https://github.com/arda-org/arda-os.git
cd arda-os/tools/compliance-compiler

# Build the tool
go build -o compliance-compiler .

# Install globally (optional)
go install .
```

### Using Make

```bash
cd tools/compliance-compiler
make build
make install
```

## Quick Start

### 1. Generate a Basic Policy Template

```bash
compliance-compiler generate --type basic --output my_policy.yaml
```

### 2. Validate Your Policy

```bash
compliance-compiler validate my_policy.yaml
```

### 3. Compile the Policy

```bash
compliance-compiler compile my_policy.yaml
```

### 4. Test the Policy

```bash
compliance-compiler test -t sample_data.json my_policy.yaml
```

## Commands

### `compile` - Compile YAML to Protobuf

Converts YAML compliance policies into protobuf format for blockchain deployment.

```bash
compliance-compiler compile [flags] <input-file>

Flags:
  -o, --output string      Output file path (default: <input>.pb)
  -d, --output-dir string  Output directory (default: same as input)
  -f, --format string      Output format (binary, text, json) (default: binary)
      --validate           Validate policy before compilation (default: true)
      --overwrite          Overwrite existing output files
```

**Examples:**

```bash
# Basic compilation
compliance-compiler compile policy.yaml

# Compile with custom output
compliance-compiler compile -o compiled_policy.pb policy.yaml

# Compile to JSON format
compliance-compiler compile -f json policy.yaml

# Compile without validation
compliance-compiler compile --no-validate policy.yaml
```

### `validate` - Validate Policies

Validates YAML compliance policies for syntax and semantic correctness.

```bash
compliance-compiler validate [flags] <file-or-directory>

Flags:
  -r, --recursive         Validate files recursively
  -p, --pattern string    File pattern to match (default: "*.yaml")
      --strict            Fail on warnings (strict mode)
      --output string     Output format (text, json) (default: "text")
```

**Examples:**

```bash
# Validate single policy
compliance-compiler validate policy.yaml

# Validate directory recursively
compliance-compiler validate -r ./policies

# Strict validation (fail on warnings)
compliance-compiler validate --strict policy.yaml

# JSON output
compliance-compiler validate --output json policy.yaml
```

### `test` - Test Policies

Tests compliance policies against sample transaction data.

```bash
compliance-compiler test [flags] <policy-file>

Flags:
  -t, --test-data string  Test data file (JSON format) [required]
  -o, --output string     Output file for test results
  -v, --verbose           Verbose test output
      --parallel          Run tests in parallel
```

**Examples:**

```bash
# Test policy with sample data
compliance-compiler test -t sample_data.json policy.yaml

# Verbose testing with results output
compliance-compiler test -v -t sample_data.json -o results.json policy.yaml

# Parallel test execution
compliance-compiler test --parallel -t sample_data.json policy.yaml
```

### `generate` - Generate Templates

Generates compliance policy templates for different use cases.

```bash
compliance-compiler generate [flags]

Flags:
  -t, --type string         Template type (basic, regional, asset, custom)
  -o, --output string       Output file path
      --region string       Region code for regional templates (US, EU, APAC)
      --asset-type string   Asset type for asset templates (loan, equity, bond)
  -i, --interactive         Interactive template generation
      --overwrite           Overwrite existing files
      --list-types          List available template types
```

**Examples:**

```bash
# Generate basic template
compliance-compiler generate --type basic

# Generate US regional template
compliance-compiler generate --type regional --region US -o us_policy.yaml

# Generate loan-specific template
compliance-compiler generate --type asset --asset-type loan

# Interactive generation
compliance-compiler generate --interactive

# List available templates
compliance-compiler generate --list-types
```

## Policy Structure

### Basic Policy Format

```yaml
metadata:
  name: "policy_name"
  version: "1.0.0"
  description: "Policy description"
  region: "US"
  asset_type: "loan"

spec:
  rules:
    - id: "rule_1"
      name: "Rule Name"
      type: "validation"
      condition: "amount > 0"
      action: "allow"
      priority: 100
      enabled: true

  limits:
    daily_amount:
      type: "amount"
      value: 100000
      period: "1d"
      currency: "USD"

  settings:
    default_action: "deny"
    strict_mode: true
```

### Rule Types

- **`validation`** - Data validation rules
- **`limit`** - Quantity/amount limits
- **`restriction`** - Access restrictions
- **`requirement`** - Required conditions
- **`notification`** - Alert/notification triggers

### Action Types

- **`allow`** - Permit the transaction
- **`deny`** - Block the transaction
- **`require`** - Require additional information
- **`notify`** - Send notification
- **`log`** - Log the event
- **`escalate`** - Escalate for manual review

## Regional Compliance

The tool supports region-specific compliance templates:

### United States
- Bank Secrecy Act (BSA) reporting
- OFAC sanctions screening
- USA PATRIOT Act CIP requirements
- Suspicious Activity Reporting (SAR)

### European Union
- GDPR data protection
- MiFID II suitability assessment
- 4th AML Directive compliance
- PSD2 payment limits

### Asia-Pacific
- FATF recommendations
- Local AML requirements
- Cross-border transaction rules

## Asset-Specific Policies

### Loan Assets
- Loan-to-Value (LTV) ratio checks
- Credit score requirements
- Debt-to-Income (DTI) ratio validation
- TILA disclosure compliance

### Equity Assets
- Accredited investor verification
- Portfolio concentration limits
- Suitability assessments

### Bond Assets
- Credit rating requirements
- Maturity restrictions
- Interest rate validations

## Configuration

### Global Configuration

Create `~/.compliance-compiler.yaml`:

```yaml
log:
  level: "info"
  format: "text"

defaults:
  region: "US"
  currency: "USD"
  strict_mode: true

templates:
  output_dir: "./generated"

validation:
  strict_warnings: false
  max_rule_priority: 1000
```

### Environment Variables

```bash
COMPLIANCE_COMPILER_LOG_LEVEL=debug
COMPLIANCE_COMPILER_CONFIG_FILE=/path/to/config.yaml
COMPLIANCE_COMPILER_TEMPLATES_DIR=/path/to/templates
```

## Testing Framework

### Test Data Format

```json
{
  "test_cases": [
    {
      "name": "valid_transaction",
      "description": "Transaction that should pass",
      "input": {
        "amount": 1000.00,
        "sender": "alice",
        "recipient": "bob"
      },
      "expected": {
        "pass": true,
        "reason": "Valid transaction"
      }
    }
  ]
}
```

### Writing Tests

1. Create test data JSON files
2. Define input transaction data
3. Specify expected outcomes
4. Run tests with detailed reporting

## Integration with ArdaOS

### Blockchain Deployment

1. Compile policies using the compiler
2. Deploy compiled policies to ArdaOS blockchain
3. Reference policies in transaction validation
4. Monitor compliance execution

### API Integration

```go
import "github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"

// Parse policy
parser := parser.NewYAMLParser()
policy, err := parser.ParseFile("policy.yaml")

// Compile policy
compiler := compiler.NewCompiler()
compiled, err := compiler.CompilePolicy(policy)

// Use in blockchain module
result := blockchainModule.ValidateTransaction(compiled, transaction)
```

## Development

### Building

```bash
# Build the tool
make build

# Run tests
make test

# Run linting
make lint

# Generate documentation
make docs
```

### Project Structure

```
tools/compliance-compiler/
├── main.go                 # CLI entry point
├── cmd/                    # Command implementations
├── internal/               # Internal packages
│   ├── parser/             # YAML parsing
│   ├── compiler/           # Policy compilation
│   ├── validator/          # Policy validation
│   └── templates/          # Template generation
├── pkg/types/              # Shared types
├── examples/               # Example policies
├── docs/                   # Documentation
└── Makefile               # Build commands
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests and documentation
5. Submit a pull request

## Troubleshooting

### Common Issues

**Policy Validation Errors**
```bash
# Check syntax
compliance-compiler validate --strict policy.yaml

# Debug with verbose output
compliance-compiler validate -v policy.yaml
```

**Compilation Failures**
```bash
# Validate before compiling
compliance-compiler compile --validate policy.yaml

# Check dependencies
compliance-compiler compile --debug policy.yaml
```

**Test Failures**
```bash
# Run with verbose output
compliance-compiler test -v -t test_data.json policy.yaml

# Check individual test cases
compliance-compiler test --test-case "specific_test" policy.yaml
```

### Debug Mode

Enable debug logging:

```bash
compliance-compiler --log-level debug <command>
```

### Getting Help

```bash
# General help
compliance-compiler --help

# Command-specific help
compliance-compiler <command> --help

# List available options
compliance-compiler <command> --help
```

## License

This tool is part of the ArdaOS project and is licensed under the same terms as the main repository.

## Support

For support, please:
1. Check this documentation
2. Review example policies in `examples/`
3. Open an issue on the ArdaOS GitHub repository
4. Contact the ArdaOS development team

---

**Note**: This tool is designed specifically for ArdaOS blockchain compliance modules. For other blockchain platforms, modifications may be required.
