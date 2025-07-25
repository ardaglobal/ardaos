#!/bin/bash
# Validate all example policies and templates
# Comprehensive validation script for the compliance compiler examples

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_DIR/bin/compliance-compiler"
EXAMPLES_DIR="$PROJECT_DIR/examples"
REPORT_DIR="$PROJECT_DIR/validation-reports"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Counters
TOTAL_FILES=0
VALID_FILES=0
INVALID_FILES=0
WARNING_FILES=0

# Arrays to track results
VALID_LIST=()
INVALID_LIST=()
WARNING_LIST=()

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo -e "${PURPLE}[SECTION]${NC} $1"
}

# Check if compliance compiler is built
check_binary() {
    if [ ! -f "$BINARY" ]; then
        log_error "Compliance compiler binary not found at $BINARY"
        log_info "Run 'make build' to build the compliance compiler"
        exit 1
    fi

    if [ ! -x "$BINARY" ]; then
        log_error "Compliance compiler binary is not executable"
        exit 1
    fi

    # Test binary
    if ! "$BINARY" --version >/dev/null 2>&1; then
        log_error "Compliance compiler binary failed to execute"
        exit 1
    fi

    local version
    version=$("$BINARY" --version 2>/dev/null | head -1 | awk '{print $NF}')
    log_success "Using compliance compiler version: $version"
}

# Create report directory
setup_reporting() {
    mkdir -p "$REPORT_DIR"

    # Create timestamp for this validation run
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    REPORT_FILE="$REPORT_DIR/validation_report_$TIMESTAMP.md"
    DETAILED_LOG="$REPORT_DIR/validation_detailed_$TIMESTAMP.log"

    log_info "Validation reports will be saved to:"
    log_info "  Summary: $REPORT_FILE"
    log_info "  Detailed: $DETAILED_LOG"
}

# Validate a single file
validate_file() {
    local file="$1"
    local relative_path="${file#$PROJECT_DIR/}"

    log_info "Validating: $relative_path"

    local temp_log=$(mktemp)
    local exit_code=0

    # Run validation and capture output
    "$BINARY" validate "$file" --format=detailed > "$temp_log" 2>&1 || exit_code=$?

    # Analyze results
    case $exit_code in
        0)
            log_success "✓ $relative_path"
            VALID_FILES=$((VALID_FILES + 1))
            VALID_LIST+=("$relative_path")

            # Check for warnings in successful validation
            if grep -q "WARNING" "$temp_log"; then
                log_warning "  Contains warnings - see detailed log"
                WARNING_FILES=$((WARNING_FILES + 1))
                WARNING_LIST+=("$relative_path")
            fi
            ;;
        1)
            log_error "✗ $relative_path"
            INVALID_FILES=$((INVALID_FILES + 1))
            INVALID_LIST+=("$relative_path")

            # Show first few error lines
            echo "  Error details:"
            head -3 "$temp_log" | sed 's/^/    /'
            ;;
        *)
            log_error "✗ $relative_path (unexpected error code: $exit_code)"
            INVALID_FILES=$((INVALID_FILES + 1))
            INVALID_LIST+=("$relative_path")
            ;;
    esac

    # Append to detailed log
    {
        echo "=== $relative_path ==="
        echo "Exit code: $exit_code"
        echo "Timestamp: $(date)"
        echo ""
        cat "$temp_log"
        echo ""
        echo ""
    } >> "$DETAILED_LOG"

    rm -f "$temp_log"
    TOTAL_FILES=$((TOTAL_FILES + 1))
}

# Validate templates directory
validate_templates() {
    log_section "Validating Policy Templates"

    local templates_dir="$EXAMPLES_DIR/templates"

    if [ ! -d "$templates_dir" ]; then
        log_warning "Templates directory not found: $templates_dir"
        return
    fi

    # Find all YAML template files
    local template_files
    mapfile -t template_files < <(find "$templates_dir" -name "*.yaml" -o -name "*.yml" | sort)

    if [ ${#template_files[@]} -eq 0 ]; then
        log_warning "No template files found in $templates_dir"
        return
    fi

    log_info "Found ${#template_files[@]} template files"

    for template in "${template_files[@]}"; do
        validate_file "$template"
    done
}

# Validate test policies
validate_test_policies() {
    log_section "Validating Test Policies"

    local policies_dir="$EXAMPLES_DIR/policies"

    if [ ! -d "$policies_dir" ]; then
        log_warning "Policies directory not found: $policies_dir"
        return
    fi

    # Find all YAML policy files
    local policy_files
    mapfile -t policy_files < <(find "$policies_dir" -name "*.yaml" -o -name "*.yml" | sort)

    if [ ${#policy_files[@]} -eq 0 ]; then
        log_warning "No policy files found in $policies_dir"
        return
    fi

    log_info "Found ${#policy_files[@]} policy files"

    for policy in "${policy_files[@]}"; do
        validate_file "$policy"
    done
}

# Validate example policies in test-policies directory
validate_example_policies() {
    log_section "Validating Example Policies"

    local test_policies_dir="$EXAMPLES_DIR/test-policies"

    if [ ! -d "$test_policies_dir" ]; then
        log_warning "Test policies directory not found: $test_policies_dir"
        return
    fi

    # Find all YAML files
    local example_files
    mapfile -t example_files < <(find "$test_policies_dir" -name "*.yaml" -o -name "*.yml" | sort)

    if [ ${#example_files[@]} -eq 0 ]; then
        log_warning "No example policy files found in $test_policies_dir"
        return
    fi

    log_info "Found ${#example_files[@]} example policy files"

    for example in "${example_files[@]}"; do
        validate_file "$example"
    done
}

# Test compilation of valid policies
test_compilation() {
    log_section "Testing Policy Compilation"

    if [ ${#VALID_LIST[@]} -eq 0 ]; then
        log_warning "No valid policies to test compilation"
        return
    fi

    local compile_dir="$PROJECT_DIR/validation-compile-test"
    mkdir -p "$compile_dir"

    local compiled_count=0
    local compile_errors=0

    for file_path in "${VALID_LIST[@]}"; do
        local full_path="$PROJECT_DIR/$file_path"
        local basename=$(basename "$full_path" .yaml)
        local output_file="$compile_dir/${basename}.pb"

        log_info "Compiling: $file_path"

        if "$BINARY" compile "$full_path" -o "$output_file" >/dev/null 2>&1; then
            log_success "✓ Compiled: $file_path"
            compiled_count=$((compiled_count + 1))
        else
            log_error "✗ Compilation failed: $file_path"
            compile_errors=$((compile_errors + 1))
        fi
    done

    log_info "Compilation results: $compiled_count successful, $compile_errors failed"

    # Cleanup
    rm -rf "$compile_dir"
}

# Generate validation report
generate_report() {
    log_section "Generating Validation Report"

    local success_rate=0
    if [ $TOTAL_FILES -gt 0 ]; then
        success_rate=$(( (VALID_FILES * 100) / TOTAL_FILES ))
    fi

    # Generate markdown report
    cat > "$REPORT_FILE" << EOF
# Compliance Compiler Validation Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Compiler Version:** $("$BINARY" --version 2>/dev/null | head -1 | awk '{print $NF}')
**Validation Script:** validate-examples.sh

## Summary

| Metric | Count | Percentage |
|--------|-------|------------|
| Total Files | $TOTAL_FILES | 100% |
| Valid Files | $VALID_FILES | ${success_rate}% |
| Invalid Files | $INVALID_FILES | $(( (INVALID_FILES * 100) / TOTAL_FILES ))% |
| Files with Warnings | $WARNING_FILES | $(( (WARNING_FILES * 100) / TOTAL_FILES ))% |

## Validation Results

### ✅ Valid Files ($VALID_FILES)

EOF

    for file in "${VALID_LIST[@]}"; do
        echo "- \`$file\`" >> "$REPORT_FILE"
    done

    if [ ${#INVALID_LIST[@]} -gt 0 ]; then
        cat >> "$REPORT_FILE" << EOF

### ❌ Invalid Files ($INVALID_FILES)

EOF
        for file in "${INVALID_LIST[@]}"; do
            echo "- \`$file\`" >> "$REPORT_FILE"
        done
    fi

    if [ ${#WARNING_LIST[@]} -gt 0 ]; then
        cat >> "$REPORT_FILE" << EOF

### ⚠️ Files with Warnings ($WARNING_FILES)

EOF
        for file in "${WARNING_LIST[@]}"; do
            echo "- \`$file\`" >> "$REPORT_FILE"
        done
    fi

    cat >> "$REPORT_FILE" << EOF

## Detailed Results

For detailed validation output, see: \`$(basename "$DETAILED_LOG")\`

## Recommendations

EOF

    if [ $INVALID_FILES -gt 0 ]; then
        cat >> "$REPORT_FILE" << EOF
1. **Fix Invalid Files:** Review and correct the $INVALID_FILES files that failed validation
EOF
    fi

    if [ $WARNING_FILES -gt 0 ]; then
        cat >> "$REPORT_FILE" << EOF
2. **Address Warnings:** Review the $WARNING_FILES files with warnings for potential improvements
EOF
    fi

    if [ $success_rate -lt 100 ]; then
        cat >> "$REPORT_FILE" << EOF
3. **Quality Gate:** Current success rate is ${success_rate}%. Consider establishing a minimum threshold.
EOF
    fi

    cat >> "$REPORT_FILE" << EOF

## Next Steps

1. Review detailed validation logs for specific error messages
2. Update invalid policies to comply with schema requirements
3. Address warnings to improve policy quality
4. Run integration tests with corrected policies
5. Update documentation if schema changes are needed

---
*Generated by ArdaOS Compliance Compiler validation system*
EOF

    log_success "Validation report generated: $REPORT_FILE"
}

# Display summary
display_summary() {
    echo ""
    echo "====================================="
    echo "       VALIDATION SUMMARY"
    echo "====================================="
    echo ""
    echo "Total files validated: $TOTAL_FILES"
    echo -e "Valid files:          ${GREEN}$VALID_FILES${NC}"
    echo -e "Invalid files:        ${RED}$INVALID_FILES${NC}"
    echo -e "Files with warnings:  ${YELLOW}$WARNING_FILES${NC}"
    echo ""

    if [ $TOTAL_FILES -gt 0 ]; then
        local success_rate=$(( (VALID_FILES * 100) / TOTAL_FILES ))
        echo "Success rate: ${success_rate}%"
    fi

    echo ""

    if [ $INVALID_FILES -eq 0 ]; then
        log_success "All files passed validation! 🎉"
    else
        log_error "$INVALID_FILES files failed validation"
        echo "Review the detailed report for specific issues."
    fi

    echo ""
    echo "Reports saved to:"
    echo "  📊 Summary: $REPORT_FILE"
    echo "  📝 Detailed: $DETAILED_LOG"
}

# Main function
main() {
    echo "ArdaOS Compliance Compiler Example Validator"
    echo "============================================"
    echo ""

    # Setup
    check_binary
    setup_reporting

    # Start detailed logging
    {
        echo "ArdaOS Compliance Compiler Validation Log"
        echo "Started: $(date)"
        echo "Compiler: $("$BINARY" --version 2>/dev/null | head -1)"
        echo ""
    } > "$DETAILED_LOG"

    # Run validations
    validate_templates
    validate_test_policies
    validate_example_policies

    # Test compilation if requested
    if [ "${TEST_COMPILATION:-}" = "true" ]; then
        test_compilation
    fi

    # Generate report and summary
    generate_report
    display_summary

    # Exit with appropriate code
    if [ $INVALID_FILES -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        cat << 'EOF'
ArdaOS Compliance Compiler Example Validator

Validates all example policies and templates for correctness and compliance.

Usage: validate-examples.sh [OPTIONS]

Options:
  --help, -h              Show this help message
  --compile               Also test compilation of valid policies
  --templates-only        Only validate templates directory
  --policies-only         Only validate policies directory
  --examples-only         Only validate example policies directory
  --report-dir DIR        Specify custom report directory
  --verbose               Enable verbose output

Examples:
  ./validate-examples.sh                    # Validate all examples
  ./validate-examples.sh --compile          # Validate and test compilation
  ./validate-examples.sh --templates-only   # Only validate templates

EOF
        exit 0
        ;;
    --compile)
        TEST_COMPILATION=true
        ;;
    --templates-only)
        TEMPLATES_ONLY=true
        ;;
    --policies-only)
        POLICIES_ONLY=true
        ;;
    --examples-only)
        EXAMPLES_ONLY=true
        ;;
    --report-dir)
        if [ -n "${2:-}" ]; then
            REPORT_DIR="$2"
            shift
        else
            log_error "Report directory not specified"
            exit 1
        fi
        ;;
    --verbose)
        set -x
        ;;
esac

# Override main function for specific validation modes
if [ "${TEMPLATES_ONLY:-}" = "true" ]; then
    main() {
        check_binary
        setup_reporting
        validate_templates
        generate_report
        display_summary
        [ $INVALID_FILES -eq 0 ]
    }
elif [ "${POLICIES_ONLY:-}" = "true" ]; then
    main() {
        check_binary
        setup_reporting
        validate_test_policies
        generate_report
        display_summary
        [ $INVALID_FILES -eq 0 ]
    }
elif [ "${EXAMPLES_ONLY:-}" = "true" ]; then
    main() {
        check_binary
        setup_reporting
        validate_example_policies
        generate_report
        display_summary
        [ $INVALID_FILES -eq 0 ]
    }
fi

# Run main function
main "$@"
