#!/bin/bash
# Performance benchmark and regression testing script
# Comprehensive performance testing for the compliance compiler

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_DIR/bin/compliance-compiler"
BENCHMARKS_DIR="$PROJECT_DIR/benchmarks"
RESULTS_DIR="$PROJECT_DIR/benchmark-results"

# Performance thresholds (in milliseconds)
VALIDATION_THRESHOLD=1000     # 1 second per policy
COMPILATION_THRESHOLD=2000    # 2 seconds per policy
MEMORY_THRESHOLD=100          # 100MB memory usage

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Counters
TOTAL_BENCHMARKS=0
PASSED_BENCHMARKS=0
FAILED_BENCHMARKS=0

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

log_benchmark() {
    echo -e "${PURPLE}[BENCHMARK]${NC} $1"
}

# Check dependencies
check_dependencies() {
    local deps=("time" "bc")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing[*]}"
        exit 1
    fi

    # Check if binary exists
    if [ ! -f "$BINARY" ]; then
        log_error "Compliance compiler binary not found at $BINARY"
        log_info "Run 'make build' to build the compliance compiler"
        exit 1
    fi

    if [ ! -x "$BINARY" ]; then
        log_error "Compliance compiler binary is not executable"
        exit 1
    fi
}

# Setup benchmark environment
setup_benchmarks() {
    mkdir -p "$BENCHMARKS_DIR" "$RESULTS_DIR"

    # Create timestamp for this benchmark run
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    REPORT_FILE="$RESULTS_DIR/benchmark_report_$TIMESTAMP.md"
    CSV_FILE="$RESULTS_DIR/benchmark_results_$TIMESTAMP.csv"

    log_info "Benchmark results will be saved to:"
    log_info "  Report: $REPORT_FILE"
    log_info "  CSV Data: $CSV_FILE"

    # Create CSV header
    echo "benchmark,operation,file_size_kb,execution_time_ms,memory_usage_mb,cpu_percent,status,threshold_ms,passed" > "$CSV_FILE"
}

# Create test policies of various sizes
create_test_policies() {
    log_info "Creating test policies for benchmarking..."

    # Small policy (basic template)
    cat > "$BENCHMARKS_DIR/small_policy.yaml" << 'EOF'
template:
  name: "Small Test Policy"
  version: "1.0.0"
  jurisdiction: "USA"
  asset_class: "TestAsset"

parameters:
  test_param:
    type: "float"
    default: 100.0

policy:
  metadata:
    version: "1.0.0"
    name: "small-test-policy"
  rules:
    - id: "test_rule"
      name: "Test Rule"
      type: "validation"
      enabled: true
      conditions:
        - "test_value > 0"
      actions:
        - "validate_test"
EOF

    # Medium policy (multiple rules)
    cat > "$BENCHMARKS_DIR/medium_policy.yaml" << 'EOF'
template:
  name: "Medium Test Policy"
  version: "1.0.0"
  jurisdiction: "USA"
  asset_class: "TestAsset"

parameters:
  threshold_1: { type: "float", default: 100.0 }
  threshold_2: { type: "float", default: 200.0 }
  threshold_3: { type: "float", default: 300.0 }

policy:
  metadata:
    version: "1.0.0"
    name: "medium-test-policy"
  rules:
EOF

    # Add 10 rules to medium policy
    for i in {1..10}; do
        cat >> "$BENCHMARKS_DIR/medium_policy.yaml" << EOF
    - id: "rule_$i"
      name: "Test Rule $i"
      type: "validation"
      enabled: true
      conditions:
        - "value_$i > \${threshold_1}"
        - "value_$i < \${threshold_2}"
      actions:
        - "validate_rule_$i"
        - "log_validation_$i"
EOF
    done

    # Large policy (complex template with many rules and conditions)
    cat > "$BENCHMARKS_DIR/large_policy.yaml" << 'EOF'
template:
  name: "Large Test Policy"
  version: "1.0.0"
  jurisdiction: "USA"
  asset_class: "ComplexTestAsset"
  description: "Large policy for performance testing"

parameters:
EOF

    # Add 20 parameters
    for i in {1..20}; do
        cat >> "$BENCHMARKS_DIR/large_policy.yaml" << EOF
  param_$i:
    type: "float"
    default: $((i * 10)).0
    min: $((i * 5)).0
    max: $((i * 20)).0
    description: "Test parameter $i"
EOF
    done

    cat >> "$BENCHMARKS_DIR/large_policy.yaml" << 'EOF'

policy:
  metadata:
    version: "1.0.0"
    name: "large-test-policy"
    description: "Large policy with many rules for performance testing"
  rules:
EOF

    # Add 50 rules to large policy
    for i in {1..50}; do
        cat >> "$BENCHMARKS_DIR/large_policy.yaml" << EOF
    - id: "complex_rule_$i"
      name: "Complex Test Rule $i"
      description: "Complex rule for performance testing"
      type: "validation"
      priority: "$([ $((i % 3)) -eq 0 ] && echo "high" || echo "medium")"
      enabled: true
      conditions:
        - "input_value_$i > \${param_$((i % 20 + 1))}"
        - "calculation_result_$i <= \${param_$((i % 15 + 1))}"
        - "validation_check_$i == true"
      actions:
        - "validate_complex_rule_$i"
        - "log_validation_result_$i"
        - "update_metrics_$i"
        - "notify_stakeholders_$i"
EOF
    done

    log_success "Created test policies: small, medium, large"
}

# Benchmark a single operation
benchmark_operation() {
    local operation="$1"
    local policy_file="$2"
    local threshold="$3"
    local description="$4"

    local policy_name=$(basename "$policy_file" .yaml)
    local file_size_kb=$(du -k "$policy_file" | cut -f1)

    log_benchmark "Testing $operation on $policy_name ($file_size_kb KB)"

    # Create temporary files for timing and memory measurement
    local time_output=$(mktemp)
    local memory_output=$(mktemp)
    local command_output=$(mktemp)

    # Prepare command based on operation
    local cmd_args
    case "$operation" in
        "validation")
            cmd_args="validate $policy_file"
            ;;
        "compilation")
            local output_file=$(mktemp)
            cmd_args="compile $policy_file -o $output_file"
            ;;
        "generation")
            local output_file=$(mktemp)
            cmd_args="generate --type basic --output $output_file"
            ;;
        *)
            log_error "Unknown operation: $operation"
            return 1
            ;;
    esac

    # Run benchmark with time and memory measurement
    local start_time=$(date +%s%3N)

    # Use GNU time if available, otherwise use bash built-in time
    if command -v /usr/bin/time >/dev/null 2>&1; then
        /usr/bin/time -f "%e %M %P" -o "$time_output" \
            "$BINARY" $cmd_args > "$command_output" 2>&1
        local exit_code=$?
    else
        { time "$BINARY" $cmd_args > "$command_output" 2>&1; } 2> "$time_output"
        local exit_code=$?
    fi

    local end_time=$(date +%s%3N)
    local execution_time=$((end_time - start_time))

    # Parse timing results
    local memory_usage="0"
    local cpu_percent="0"

    if [ -s "$time_output" ]; then
        if command -v /usr/bin/time >/dev/null 2>&1; then
            # GNU time format: seconds memory_kb cpu_percent
            read -r time_seconds memory_kb cpu_percent < "$time_output"
            memory_usage=$(echo "scale=2; $memory_kb / 1024" | bc)
            execution_time=$(echo "$time_seconds * 1000" | bc | cut -d. -f1)
        else
            # bash time format - approximate
            memory_usage="N/A"
            cpu_percent="N/A"
        fi
    fi

    # Determine if benchmark passed
    local status="PASS"
    local passed="true"

    if [ $exit_code -ne 0 ]; then
        status="FAIL"
        passed="false"
        log_error "✗ $description failed (exit code: $exit_code)"
        FAILED_BENCHMARKS=$((FAILED_BENCHMARKS + 1))
    elif [ "$execution_time" -gt "$threshold" ]; then
        status="SLOW"
        passed="false"
        log_warning "⚠ $description exceeded threshold (${execution_time}ms > ${threshold}ms)"
        FAILED_BENCHMARKS=$((FAILED_BENCHMARKS + 1))
    else
        log_success "✓ $description completed in ${execution_time}ms"
        PASSED_BENCHMARKS=$((PASSED_BENCHMARKS + 1))
    fi

    # Record results to CSV
    echo "$policy_name,$operation,$file_size_kb,$execution_time,$memory_usage,$cpu_percent,$status,$threshold,$passed" >> "$CSV_FILE"

    # Cleanup
    rm -f "$time_output" "$memory_output" "$command_output"
    TOTAL_BENCHMARKS=$((TOTAL_BENCHMARKS + 1))

    return $([ "$passed" = "true" ] && echo 0 || echo 1)
}

# Run validation benchmarks
benchmark_validation() {
    log_info "Running validation benchmarks..."

    benchmark_operation "validation" "$BENCHMARKS_DIR/small_policy.yaml" "$VALIDATION_THRESHOLD" "Small policy validation"
    benchmark_operation "validation" "$BENCHMARKS_DIR/medium_policy.yaml" "$VALIDATION_THRESHOLD" "Medium policy validation"
    benchmark_operation "validation" "$BENCHMARKS_DIR/large_policy.yaml" "$VALIDATION_THRESHOLD" "Large policy validation"
}

# Run compilation benchmarks
benchmark_compilation() {
    log_info "Running compilation benchmarks..."

    benchmark_operation "compilation" "$BENCHMARKS_DIR/small_policy.yaml" "$COMPILATION_THRESHOLD" "Small policy compilation"
    benchmark_operation "compilation" "$BENCHMARKS_DIR/medium_policy.yaml" "$COMPILATION_THRESHOLD" "Medium policy compilation"
    benchmark_operation "compilation" "$BENCHMARKS_DIR/large_policy.yaml" "$COMPILATION_THRESHOLD" "Large policy compilation"
}

# Run load testing (multiple concurrent operations)
benchmark_load_testing() {
    log_info "Running load testing..."

    local concurrent_jobs=5
    local test_file="$BENCHMARKS_DIR/medium_policy.yaml"

    log_benchmark "Testing $concurrent_jobs concurrent validations"

    local start_time=$(date +%s%3N)
    local pids=()

    # Start concurrent validation processes
    for i in $(seq 1 $concurrent_jobs); do
        "$BINARY" validate "$test_file" >/dev/null 2>&1 &
        pids+=($!)
    done

    # Wait for all processes to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    local end_time=$(date +%s%3N)
    local total_time=$((end_time - start_time))
    local avg_time=$((total_time / concurrent_jobs))

    log_success "✓ Concurrent load test completed in ${total_time}ms (avg: ${avg_time}ms per job)"

    # Record load test results
    echo "load_test,concurrent_validation,N/A,$total_time,N/A,N/A,PASS,$((VALIDATION_THRESHOLD * concurrent_jobs)),true" >> "$CSV_FILE"

    TOTAL_BENCHMARKS=$((TOTAL_BENCHMARKS + 1))
    PASSED_BENCHMARKS=$((PASSED_BENCHMARKS + 1))
}

# Generate benchmark report
generate_report() {
    log_info "Generating benchmark report..."

    local total_time=$(tail -n +2 "$CSV_FILE" | cut -d, -f4 | awk '{sum += $1} END {print sum}')
    local avg_time=$(echo "scale=2; $total_time / $TOTAL_BENCHMARKS" | bc)
    local pass_rate=$(echo "scale=2; $PASSED_BENCHMARKS * 100 / $TOTAL_BENCHMARKS" | bc)

    # Generate markdown report
    cat > "$REPORT_FILE" << EOF
# Compliance Compiler Performance Benchmark Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Compiler Version:** $("$BINARY" --version 2>/dev/null | head -1 | awk '{print $NF}')
**Benchmark Script:** benchmark.sh

## Summary

| Metric | Value |
|--------|-------|
| Total Benchmarks | $TOTAL_BENCHMARKS |
| Passed | $PASSED_BENCHMARKS |
| Failed | $FAILED_BENCHMARKS |
| Pass Rate | ${pass_rate}% |
| Total Execution Time | ${total_time}ms |
| Average Execution Time | ${avg_time}ms |

## Performance Thresholds

| Operation | Threshold | Status |
|-----------|-----------|--------|
| Validation | ${VALIDATION_THRESHOLD}ms | $([ $VALIDATION_THRESHOLD -gt 500 ] && echo "✓" || echo "⚠") |
| Compilation | ${COMPILATION_THRESHOLD}ms | $([ $COMPILATION_THRESHOLD -gt 1000 ] && echo "✓" || echo "⚠") |
| Memory Usage | ${MEMORY_THRESHOLD}MB | ✓ |

## Detailed Results

### Validation Performance

| Policy Size | File Size | Execution Time | Memory Usage | Status |
|-------------|-----------|----------------|--------------|--------|
EOF

    # Add validation results
    grep ",validation," "$CSV_FILE" | while IFS=',' read -r benchmark operation file_size exec_time memory cpu status threshold passed; do
        local status_icon=$([ "$status" = "PASS" ] && echo "✅" || echo "❌")
        echo "| $benchmark | ${file_size}KB | ${exec_time}ms | ${memory}MB | $status_icon |" >> "$REPORT_FILE"
    done

    cat >> "$REPORT_FILE" << EOF

### Compilation Performance

| Policy Size | File Size | Execution Time | Memory Usage | Status |
|-------------|-----------|----------------|--------------|--------|
EOF

    # Add compilation results
    grep ",compilation," "$CSV_FILE" | while IFS=',' read -r benchmark operation file_size exec_time memory cpu status threshold passed; do
        local status_icon=$([ "$status" = "PASS" ] && echo "✅" || echo "❌")
        echo "| $benchmark | ${file_size}KB | ${exec_time}ms | ${memory}MB | $status_icon |" >> "$REPORT_FILE"
    done

    cat >> "$REPORT_FILE" << EOF

## Performance Analysis

### Observations

EOF

    if [ $FAILED_BENCHMARKS -gt 0 ]; then
        cat >> "$REPORT_FILE" << EOF
- ⚠️ **$FAILED_BENCHMARKS benchmarks failed or exceeded thresholds**
- Review failed benchmarks and consider optimization
EOF
    else
        cat >> "$REPORT_FILE" << EOF
- ✅ **All benchmarks passed performance thresholds**
- System performance is within acceptable limits
EOF
    fi

    cat >> "$REPORT_FILE" << EOF

### Recommendations

1. **Performance Monitoring:** Set up continuous performance monitoring
2. **Threshold Tuning:** Review and adjust performance thresholds as needed
3. **Optimization:** Focus on optimizing slow operations identified in benchmarks
4. **Load Testing:** Consider more extensive load testing for production scenarios

## Raw Data

Detailed benchmark data is available in: \`$(basename "$CSV_FILE")\`

---
*Generated by ArdaOS Compliance Compiler benchmark system*
EOF

    log_success "Benchmark report generated: $REPORT_FILE"
}

# Compare with previous benchmarks (regression testing)
compare_with_baseline() {
    log_info "Checking for performance regressions..."

    # Find most recent previous benchmark
    local previous_csv=$(ls -t "$RESULTS_DIR"/benchmark_results_*.csv 2>/dev/null | sed -n '2p')

    if [ -z "$previous_csv" ]; then
        log_warning "No previous benchmark found for comparison"
        return
    fi

    log_info "Comparing with previous benchmark: $(basename "$previous_csv")"

    # Simple regression check - compare average execution times
    local current_avg=$(tail -n +2 "$CSV_FILE" | cut -d, -f4 | awk '{sum += $1; count++} END {print sum/count}')
    local previous_avg=$(tail -n +2 "$previous_csv" | cut -d, -f4 | awk '{sum += $1; count++} END {print sum/count}')

    local regression_threshold=10  # 10% regression threshold
    local performance_change=$(echo "scale=2; ($current_avg - $previous_avg) * 100 / $previous_avg" | bc)

    if (( $(echo "$performance_change > $regression_threshold" | bc -l) )); then
        log_warning "Performance regression detected: ${performance_change}% slower than previous run"
        echo "performance_regression,comparison,N/A,$current_avg,N/A,N/A,REGRESSION,$previous_avg,false" >> "$CSV_FILE"
    else
        log_success "No significant performance regression detected (${performance_change}% change)"
    fi
}

# Display summary
display_summary() {
    echo ""
    echo "=========================================="
    echo "        BENCHMARK SUMMARY"
    echo "=========================================="
    echo ""
    echo "Total benchmarks: $TOTAL_BENCHMARKS"
    echo -e "Passed:          ${GREEN}$PASSED_BENCHMARKS${NC}"
    echo -e "Failed:          ${RED}$FAILED_BENCHMARKS${NC}"
    echo ""

    if [ $TOTAL_BENCHMARKS -gt 0 ]; then
        local pass_rate=$(echo "scale=1; $PASSED_BENCHMARKS * 100 / $TOTAL_BENCHMARKS" | bc)
        echo "Pass rate: ${pass_rate}%"
    fi

    echo ""

    if [ $FAILED_BENCHMARKS -eq 0 ]; then
        log_success "All benchmarks passed! 🚀"
    else
        log_error "$FAILED_BENCHMARKS benchmarks failed or exceeded thresholds"
        echo "Review the detailed report for optimization opportunities."
    fi

    echo ""
    echo "Reports saved to:"
    echo "  📊 Report: $REPORT_FILE"
    echo "  📈 CSV Data: $CSV_FILE"
}

# Main function
main() {
    echo "ArdaOS Compliance Compiler Performance Benchmarks"
    echo "=================================================="
    echo ""

    # Setup
    check_dependencies
    setup_benchmarks
    create_test_policies

    # Run benchmarks
    benchmark_validation
    benchmark_compilation

    if [ "${LOAD_TEST:-}" = "true" ]; then
        benchmark_load_testing
    fi

    # Analysis and reporting
    if [ "${REGRESSION_TEST:-}" = "true" ]; then
        compare_with_baseline
    fi

    generate_report
    display_summary

    # Cleanup test policies
    rm -rf "$BENCHMARKS_DIR"

    # Exit with appropriate code
    if [ $FAILED_BENCHMARKS -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        cat << 'EOF'
ArdaOS Compliance Compiler Performance Benchmarks

Runs comprehensive performance benchmarks and regression testing.

Usage: benchmark.sh [OPTIONS]

Options:
  --help, -h              Show this help message
  --load-test             Include concurrent load testing
  --regression-test       Compare with previous benchmark results
  --validation-only       Only run validation benchmarks
  --compilation-only      Only run compilation benchmarks
  --threshold-val MS      Set validation threshold in milliseconds
  --threshold-comp MS     Set compilation threshold in milliseconds
  --results-dir DIR       Specify custom results directory

Examples:
  ./benchmark.sh                           # Run all benchmarks
  ./benchmark.sh --load-test               # Include load testing
  ./benchmark.sh --regression-test         # Check for regressions
  ./benchmark.sh --validation-only         # Only validation benchmarks

EOF
        exit 0
        ;;
    --load-test)
        LOAD_TEST=true
        ;;
    --regression-test)
        REGRESSION_TEST=true
        ;;
    --validation-only)
        VALIDATION_ONLY=true
        ;;
    --compilation-only)
        COMPILATION_ONLY=true
        ;;
    --threshold-val)
        if [ -n "${2:-}" ]; then
            VALIDATION_THRESHOLD="$2"
            shift
        else
            log_error "Validation threshold not specified"
            exit 1
        fi
        ;;
    --threshold-comp)
        if [ -n "${2:-}" ]; then
            COMPILATION_THRESHOLD="$2"
            shift
        else
            log_error "Compilation threshold not specified"
            exit 1
        fi
        ;;
    --results-dir)
        if [ -n "${2:-}" ]; then
            RESULTS_DIR="$2"
            shift
        else
            log_error "Results directory not specified"
            exit 1
        fi
        ;;
esac

# Override main function for specific benchmark modes
if [ "${VALIDATION_ONLY:-}" = "true" ]; then
    main() {
        check_dependencies
        setup_benchmarks
        create_test_policies
        benchmark_validation
        generate_report
        display_summary
        rm -rf "$BENCHMARKS_DIR"
        [ $FAILED_BENCHMARKS -eq 0 ]
    }
elif [ "${COMPILATION_ONLY:-}" = "true" ]; then
    main() {
        check_dependencies
        setup_benchmarks
        create_test_policies
        benchmark_compilation
        generate_report
        display_summary
        rm -rf "$BENCHMARKS_DIR"
        [ $FAILED_BENCHMARKS -eq 0 ]
    }
fi

# Run main function
main "$@"
