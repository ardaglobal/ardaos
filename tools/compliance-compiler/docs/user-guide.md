# ArdaOS Compliance Compiler - User Guide

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Policy Development Workflow](#policy-development-workflow)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- **Go 1.21+** - Required for building from source
- **Git** - For cloning the repository
- **Make** - For using the provided Makefile

### Installing from Source

1. **Clone the ArdaOS repository:**
   ```bash
   git clone https://github.com/ardaos/arda-os.git
   cd arda-os/tools/compliance-compiler
   ```

2. **Build the compiler:**
   ```bash
   make build
   ```

3. **Install globally (optional):**
   ```bash
   make install
   ```

4. **Verify installation:**
   ```bash
   compliance-compiler --version
   ```

### Installing via Go

```bash
go install github.com/ardaos/arda-os/tools/compliance-compiler@latest
```

### Docker Installation

```bash
docker pull ardaos/compliance-compiler:latest
docker run -v $(pwd):/workspace ardaos/compliance-compiler:latest --help
```

## Quick Start

### Your First Policy

Let's create a simple installment loan policy:

1. **Create a policy file** (`my-policy.yaml`):
   ```yaml
   template:
     name: "Simple Installment Loan Policy"
     version: "1.0.0"
     asset_class: "InstallmentLoan"
     jurisdiction: "USA"
     regulatory_framework:
       - "CFPB"
       - "TILA"
     description: "Basic installment loan compliance policy"
     author: "Your Name"
     last_updated: "2024-01-15"

   parameters:
     min_credit_score:
       type: "int"
       default: 650
       description: "Minimum credit score required"
       min: 300
       max: 850

     max_loan_amount:
       type: "float"
       default: 50000.0
       description: "Maximum loan amount"
       min: 1000.0
       max: 100000.0

   policy:
     metadata:
       version: "1.0.0"
       name: "installment-loan-basic"
       description: "Basic installment loan policy"
       tags: ["credit", "installment", "consumer"]

     rules:
       - id: "credit_score_check"
         name: "Credit Score Validation"
         description: "Ensure applicant meets minimum credit score"
         type: "validation"
         priority: "critical"
         enabled: true
         conditions:
           - "credit_score >= params.min_credit_score"
         actions:
           - "validate_credit_score"
           - "log_decision"

       - id: "loan_amount_check"
         name: "Loan Amount Validation"
         description: "Validate loan amount is within limits"
         type: "validation"
         priority: "high"
         enabled: true
         conditions:
           - "amount <= params.max_loan_amount"
           - "amount >= 1000"
         actions:
           - "validate_amount"
           - "log_decision"

     attestations:
       - id: "compliance_officer_review"
         name: "Compliance Officer Review"
         description: "Manual review by compliance officer"
         type: "legal"
         required: true
         fields:
           - "officer_signature"
           - "review_date"
           - "approval_status"
   ```

2. **Compile the policy:**
   ```bash
   compliance-compiler compile --input my-policy.yaml --output compiled-policy.json
   ```

3. **Validate the policy:**
   ```bash
   compliance-compiler validate --input my-policy.yaml
   ```

4. **Test the policy:**
   ```bash
   # Create test transaction data
   echo '{
     "id": "test-001",
     "asset_class": "InstallmentLoan",
     "amount": 25000,
     "applicant": {
       "credit_score": 720,
       "annual_income": 60000
     }
   }' > test-data.json

   # Evaluate policy against test data
   compliance-compiler evaluate --policy compiled-policy.json --data test-data.json
   ```

### Expected Output

```bash
✅ Policy Compilation Successful
📊 Compilation Results:
  - Rules compiled: 2
  - Attestations: 1
  - Parameters: 2
  - Output format: JSON
  - Build time: 45ms

🔍 Policy Validation Results:
✅ Template validation passed
✅ Rule validation passed
✅ Parameter validation passed
✅ Attestation validation passed

📋 Policy Evaluation Results:
✅ Evaluation successful
  - Credit Score Check: PASS (720 >= 650)
  - Loan Amount Check: PASS (25000 <= 50000)
  - Overall Status: APPROVED
  - Compliance Score: 100%
```

## CLI Reference

### Global Options

```bash
compliance-compiler [command] [flags]
```

**Global Flags:**
- `--config, -c`: Configuration file path
- `--verbose, -v`: Enable verbose output
- `--quiet, -q`: Suppress non-error output
- `--help, -h`: Show help information
- `--version`: Show version information

### Commands

#### `compile` - Compile Policy

Compiles a YAML policy into executable format.

```bash
compliance-compiler compile [flags]
```

**Flags:**
- `--input, -i`: Input policy file (YAML)
- `--output, -o`: Output file path
- `--format, -f`: Output format (json, protobuf, go) [default: json]
- `--optimize`: Enable optimization passes
- `--validate`: Validate before compilation
- `--watch, -w`: Watch for file changes and recompile

**Examples:**
```bash
# Basic compilation
compliance-compiler compile -i policy.yaml -o policy.json

# Compile with optimization
compliance-compiler compile -i policy.yaml -o policy.json --optimize

# Compile and watch for changes
compliance-compiler compile -i policy.yaml -o policy.json --watch

# Compile to Go code
compliance-compiler compile -i policy.yaml -o policy.go --format go
```

#### `validate` - Validate Policy

Validates policy syntax and compliance.

```bash
compliance-compiler validate [flags]
```

**Flags:**
- `--input, -i`: Input policy file(s) or directory
- `--schema, -s`: Custom validation schema
- `--strict`: Enable strict validation mode
- `--format, -f`: Output format (text, json, yaml)
- `--output, -o`: Output file for results

**Examples:**
```bash
# Validate single policy
compliance-compiler validate -i policy.yaml

# Validate directory of policies
compliance-compiler validate -i ./policies/

# Strict validation with JSON output
compliance-compiler validate -i policy.yaml --strict --format json
```

#### `evaluate` - Evaluate Policy

Evaluates compiled policy against transaction data.

```bash
compliance-compiler evaluate [flags]
```

**Flags:**
- `--policy, -p`: Compiled policy file
- `--data, -d`: Transaction data file (JSON)
- `--output, -o`: Output file for results
- `--format, -f`: Output format (json, yaml, text)
- `--trace`: Enable execution tracing

**Examples:**
```bash
# Basic evaluation
compliance-compiler evaluate -p policy.json -d transaction.json

# Evaluation with tracing
compliance-compiler evaluate -p policy.json -d transaction.json --trace

# Batch evaluation
compliance-compiler evaluate -p policy.json -d ./test-data/ --format json
```

#### `test` - Test Policy

Runs policy tests and benchmarks.

```bash
compliance-compiler test [flags]
```

**Flags:**
- `--input, -i`: Policy file or directory
- `--test-data, -d`: Test data directory
- `--coverage`: Generate coverage report
- `--benchmark`: Run performance benchmarks
- `--iterations, -n`: Number of test iterations

**Examples:**
```bash
# Run policy tests
compliance-compiler test -i policy.yaml -d ./test-data/

# Run with coverage
compliance-compiler test -i policy.yaml -d ./test-data/ --coverage

# Performance benchmarks
compliance-compiler test -i policy.yaml --benchmark --iterations 1000
```

#### `generate` - Generate Templates

Generates policy templates and boilerplate code.

```bash
compliance-compiler generate [type] [flags]
```

**Types:**
- `policy`: Generate policy template
- `test`: Generate test data template
- `schema`: Generate validation schema
- `docs`: Generate documentation

**Flags:**
- `--asset-class, -a`: Asset class for template
- `--jurisdiction, -j`: Jurisdiction for template
- `--output, -o`: Output file or directory
- `--interactive, -i`: Interactive template generation

**Examples:**
```bash
# Generate policy template
compliance-compiler generate policy -a InstallmentLoan -j USA -o template.yaml

# Interactive generation
compliance-compiler generate policy --interactive

# Generate test data
compliance-compiler generate test -a CreditCard -o test-data.json
```

#### `serve` - Start Development Server

Starts development server with live reload.

```bash
compliance-compiler serve [flags]
```

**Flags:**
- `--port, -p`: Server port [default: 3000]
- `--host`: Server host [default: localhost]
- `--watch-dir, -w`: Additional directories to watch
- `--debug`: Enable debug mode

**Examples:**
```bash
# Start development server
compliance-compiler serve

# Custom port and debug mode
compliance-compiler serve --port 8080 --debug
```

#### `format` - Format Policy Files

Formats and standardizes policy files.

```bash
compliance-compiler format [flags]
```

**Flags:**
- `--input, -i`: Input file or directory
- `--output, -o`: Output file or directory
- `--in-place`: Format files in place
- `--check`: Check if files are formatted

**Examples:**
```bash
# Format single file
compliance-compiler format -i policy.yaml -o formatted-policy.yaml

# Format in place
compliance-compiler format -i policy.yaml --in-place

# Check formatting
compliance-compiler format -i ./policies/ --check
```

## Policy Development Workflow

### 1. Planning Phase

1. **Identify Requirements:**
   - Asset class (InstallmentLoan, CreditCard, etc.)
   - Jurisdiction (USA, USA-NY, EU, etc.)
   - Regulatory frameworks (CFPB, TILA, GDPR, etc.)
   - Business rules and constraints

2. **Generate Template:**
   ```bash
   compliance-compiler generate policy \
     --asset-class InstallmentLoan \
     --jurisdiction USA \
     --interactive \
     --output my-policy.yaml
   ```

### 2. Development Phase

1. **Edit Policy:**
   - Use your preferred YAML editor
   - Start development server for live feedback:
     ```bash
     compliance-compiler serve --debug
     ```

2. **Validate Continuously:**
   ```bash
   compliance-compiler validate -i my-policy.yaml --watch
   ```

3. **Generate Test Data:**
   ```bash
   compliance-compiler generate test \
     --asset-class InstallmentLoan \
     --output test-data/
   ```

### 3. Testing Phase

1. **Unit Testing:**
   ```bash
   compliance-compiler test -i my-policy.yaml -d test-data/
   ```

2. **Integration Testing:**
   ```bash
   compliance-compiler test -i ./policies/ -d ./integration-tests/ --coverage
   ```

3. **Performance Testing:**
   ```bash
   compliance-compiler test -i my-policy.yaml --benchmark --iterations 1000
   ```

### 4. Deployment Phase

1. **Final Validation:**
   ```bash
   compliance-compiler validate -i my-policy.yaml --strict
   ```

2. **Compile for Production:**
   ```bash
   compliance-compiler compile \
     -i my-policy.yaml \
     -o my-policy.json \
     --optimize \
     --format json
   ```

3. **Generate Documentation:**
   ```bash
   compliance-compiler generate docs -i my-policy.yaml -o docs/
   ```

## Best Practices

### Policy Structure

1. **Use Descriptive Names:**
   ```yaml
   template:
     name: "Consumer Installment Loan Policy v2.1"
     description: "Comprehensive installment loan policy for consumer lending"
   ```

2. **Version Your Policies:**
   ```yaml
   template:
     version: "2.1.0"  # Use semantic versioning
   policy:
     metadata:
       version: "2.1.0"  # Keep in sync
   ```

3. **Document Everything:**
   ```yaml
   rules:
     - id: "credit_score_check"
       name: "Credit Score Validation"
       description: "Ensures applicant meets minimum credit score requirements per CFPB guidelines"
   ```

### Rule Design

1. **Keep Rules Atomic:**
   ```yaml
   # Good: Single responsibility
   - id: "age_check"
     conditions: ["age >= 18"]

   # Bad: Multiple responsibilities
   - id: "eligibility_check"
     conditions: ["age >= 18", "income >= 30000", "credit_score >= 650"]
   ```

2. **Use Meaningful Conditions:**
   ```yaml
   # Good: Clear and readable
   conditions:
     - "applicant.credit_score >= params.min_credit_score"
     - "application.amount <= risk_metrics.max_approved_amount"

   # Bad: Unclear and hard to maintain
   conditions:
     - "cs >= mcs"
     - "amt <= max"
   ```

3. **Order Rules by Priority:**
   ```yaml
   rules:
     - id: "kyc_verification"     # Critical security checks first
       priority: "critical"
     - id: "credit_assessment"    # Core business rules
       priority: "high"
     - id: "documentation_check"  # Process requirements last
       priority: "medium"
   ```

### Parameter Management

1. **Use Typed Parameters:**
   ```yaml
   parameters:
     max_loan_amount:
       type: "float"
       default: 50000.0
       min: 1000.0
       max: 100000.0
       description: "Maximum loan amount in USD"
   ```

2. **Provide Sensible Defaults:**
   ```yaml
   parameters:
     credit_score_threshold:
       type: "int"
       default: 650        # Industry standard
       min: 300
       max: 850
   ```

3. **Document Parameter Impact:**
   ```yaml
   parameters:
     debt_to_income_ratio:
       type: "float"
       default: 0.43
       description: "Maximum debt-to-income ratio (43% per CFPB QM rule)"
   ```

### Performance Optimization

1. **Order Conditions by Selectivity:**
   ```yaml
   # Put most selective conditions first
   conditions:
     - "jurisdiction == 'USA'"          # Most selective
     - "asset_class == 'InstallmentLoan'"
     - "amount >= 1000"                 # Less selective
   ```

2. **Use Early Returns:**
   ```yaml
   rules:
     - id: "quick_reject"
       conditions: ["credit_score < 500"]
       actions: ["reject_application"]

     - id: "detailed_analysis"         # Only runs if above passes
       conditions: ["credit_score >= 500"]
   ```

3. **Cache Expensive Operations:**
   ```yaml
   # Reference pre-calculated values
   conditions:
     - "risk_metrics.calculated_score >= params.min_risk_score"
   ```

### Error Handling

1. **Validate Input Data:**
   ```yaml
   rules:
     - id: "data_validation"
       conditions:
         - "applicant != null"
         - "applicant.ssn != null && applicant.ssn != ''"
       actions: ["validate_required_fields"]
   ```

2. **Handle Missing Fields Gracefully:**
   ```yaml
   conditions:
     - "coalesce(applicant.credit_score, 0) >= params.min_credit_score"
   ```

3. **Provide Clear Error Messages:**
   ```yaml
   actions:
     - "log_error('Credit score {credit_score} below minimum {min_credit_score}')"
   ```

## Troubleshooting

### Common Issues

#### 1. Compilation Errors

**Error:** `Template validation failed: missing required field 'name'`

**Solution:**
```yaml
template:
  name: "Your Policy Name"  # Add missing required field
  version: "1.0.0"
  # ... other required fields
```

**Error:** `Rule condition parsing failed: unknown field 'creditscore'`

**Solution:**
```yaml
conditions:
  - "applicant.credit_score >= 650"  # Use correct field path (snake_case)
```

#### 2. Validation Issues

**Error:** `Parameter type mismatch: expected int, got string`

**Solution:**
```yaml
parameters:
  min_age:
    type: "int"      # Ensure type matches usage
    default: 18      # Use appropriate type for default
```

**Error:** `Unknown asset class 'PersonalLoan'`

**Solution:**
```yaml
template:
  asset_class: "InstallmentLoan"  # Use supported asset class
```

Supported asset classes:
- `CreditCard`
- `InstallmentLoan`
- `MerchantCashAdvance`
- `EquipmentLease`
- `WorkingCapital`

#### 3. Runtime Evaluation Errors

**Error:** `Field path 'applicant.income' not found in transaction data`

**Solution:**
Ensure your transaction data includes all referenced fields:
```json
{
  "applicant": {
    "annual_income": 50000,  // Use 'annual_income' not 'income'
    "credit_score": 720
  }
}
```

**Error:** `Division by zero in expression`

**Solution:**
Add null checks:
```yaml
conditions:
  - "applicant.annual_income > 0 && (monthly_debt / (applicant.annual_income / 12)) <= 0.43"
```

#### 4. Performance Issues

**Issue:** Slow policy compilation

**Solutions:**
1. **Reduce rule complexity:**
   ```yaml
   # Instead of complex nested conditions
   conditions:
     - "applicant.credit_score >= 650 && applicant.income >= 30000 && applicant.employment_status == 'employed'"

   # Split into multiple rules
   - id: "credit_check"
     conditions: ["applicant.credit_score >= 650"]
   - id: "income_check"
     conditions: ["applicant.income >= 30000"]
   ```

2. **Use rule priorities to fail fast:**
   ```yaml
   - id: "basic_eligibility"
     priority: "critical"
     conditions: ["applicant.age >= 18"]
   ```

3. **Enable optimization:**
   ```bash
   compliance-compiler compile -i policy.yaml --optimize
   ```

#### 5. Development Server Issues

**Issue:** Server not detecting file changes

**Solution:**
```bash
# Ensure you're watching the correct directory
compliance-compiler serve --watch-dir ./policies/ --debug
```

**Issue:** Port already in use

**Solution:**
```bash
compliance-compiler serve --port 3001
```

### Debugging Techniques

#### 1. Enable Verbose Output

```bash
compliance-compiler compile -i policy.yaml --verbose
```

#### 2. Use Trace Mode

```bash
compliance-compiler evaluate -p policy.json -d data.json --trace
```

#### 3. Validate Individual Components

```bash
# Validate just the template
compliance-compiler validate -i policy.yaml --section template

# Validate just the rules
compliance-compiler validate -i policy.yaml --section rules
```

#### 4. Check Generated Code

```bash
# Compile to Go to see generated code
compliance-compiler compile -i policy.yaml -o policy.go --format go
```

#### 5. Use the Interactive Debugger

```bash
# Start policy debugger
go run tools/policy-debugger.go --policy policy.yaml --data test-data.json --interactive
```

### Getting Help

1. **Check the logs:**
   ```bash
   compliance-compiler compile -i policy.yaml --verbose 2>&1 | tee compile.log
   ```

2. **Use the built-in help:**
   ```bash
   compliance-compiler help compile
   compliance-compiler compile --help
   ```

3. **Run diagnostics:**
   ```bash
   compliance-compiler version --full
   ```

4. **Community support:**
   - GitHub Issues: https://github.com/ardaos/arda-os/issues
   - Discord: https://discord.gg/ardaos
   - Documentation: https://docs.ardaos.com/compliance-compiler

### Performance Monitoring

Monitor your policies in production:

```bash
# Profile compilation performance
go run tools/perf-profiler.go --file policy.yaml --benchmark

# Monitor memory usage
go run tools/perf-profiler.go --file policy.yaml --mem-profile

# Generate performance report
go run tools/perf-profiler.go --dir ./policies/ --output-dir ./performance-reports/
```

This completes the comprehensive user guide for the ArdaOS Compliance Compiler. The guide covers everything from installation to advanced troubleshooting, providing users with all the information they need to effectively use the tool.
