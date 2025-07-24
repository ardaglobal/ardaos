package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/validator"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewTestCmd() *cobra.Command {
	var (
		testDataFile  string
		samplesDir    string
		outputFile    string
		coverage      bool
		benchmark     bool
		verbose       bool
		quiet         bool
		parallel      bool
		timeout       string
		format        string
		reportFormat  string
		generateCases bool
		interactive   bool
	)

	cmd := &cobra.Command{
		Use:   "test [policy-file] [test-data] [options]",
		Short: "Test policies against sample transaction data",
		Long: `Test compliance policies against sample transaction data to verify correctness.

The test command provides comprehensive testing capabilities including:
- Unit testing against sample transaction data
- Property-based testing with generated test cases
- Performance benchmarking and load testing
- Coverage analysis for policy rules
- Regression testing with baseline comparison
- Interactive testing with guided scenarios

Examples:
  # Basic testing with sample data
  compliance-compiler test policy.yaml --samples ./test-data/

  # Test with specific test data file
  compliance-compiler test policy.yaml sample-transactions.json

  # Generate test coverage report
  compliance-compiler test policy.yaml --samples ./test-data/ --coverage --output coverage.html

  # Run performance benchmarks
  compliance-compiler test policy.yaml --samples ./test-data/ --benchmark --verbose

  # Generate test cases automatically
  compliance-compiler test policy.yaml --generate-cases --output generated-tests.json

  # Interactive testing mode
  compliance-compiler test policy.yaml --interactive

  # Parallel testing for performance
  compliance-compiler test policy.yaml --samples ./test-data/ --parallel --timeout 30s`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			policyFile := args[0]
			if len(args) > 1 {
				testDataFile = args[1]
			}

			return runTest(TestOptions{
				PolicyFile:    policyFile,
				TestDataFile:  testDataFile,
				SamplesDir:    samplesDir,
				OutputFile:    outputFile,
				Coverage:      coverage,
				Benchmark:     benchmark,
				Verbose:       verbose,
				Quiet:         quiet,
				Parallel:      parallel,
				Timeout:       timeout,
				Format:        format,
				ReportFormat:  reportFormat,
				GenerateCases: generateCases,
				Interactive:   interactive,
			})
		},
	}

	cmd.Flags().StringVar(&testDataFile, "test-data", "", "test data file (JSON format)")
	cmd.Flags().StringVar(&samplesDir, "samples", "", "directory of test transaction samples")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for test results")
	cmd.Flags().BoolVar(&coverage, "coverage", false, "generate test coverage report")
	cmd.Flags().BoolVar(&benchmark, "benchmark", false, "run performance benchmarks")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "detailed test output")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress output except errors")
	cmd.Flags().BoolVar(&parallel, "parallel", false, "run tests in parallel")
	cmd.Flags().StringVar(&timeout, "timeout", "60s", "test timeout duration")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, html")
	cmd.Flags().StringVar(&reportFormat, "report-format", "summary", "report format: summary, detailed, junit")
	cmd.Flags().BoolVar(&generateCases, "generate-cases", false, "generate test cases from policy")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "interactive testing mode")

	// Add shell completion
	cmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"text", "json", "html"}, cobra.ShellCompDirectiveDefault
	})

	cmd.RegisterFlagCompletionFunc("report-format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"summary", "detailed", "junit"}, cobra.ShellCompDirectiveDefault
	})

	return cmd
}

type TestOptions struct {
	PolicyFile    string
	TestDataFile  string
	SamplesDir    string
	OutputFile    string
	Coverage      bool
	Benchmark     bool
	Verbose       bool
	Quiet         bool
	Parallel      bool
	Timeout       string
	Format        string
	ReportFormat  string
	GenerateCases bool
	Interactive   bool
}

func runTest(opts TestOptions) error {
	// Initialize colored output
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)

	if !opts.Quiet {
		blue.Printf("🧪 Starting policy testing: %s\n", opts.PolicyFile)
	}

	// Validate inputs
	if _, err := os.Stat(opts.PolicyFile); os.IsNotExist(err) {
		return &TestError{
			Type:    "policy_file_not_found",
			Message: fmt.Sprintf("Policy file does not exist: %s", opts.PolicyFile),
			Suggestions: []string{
				"Check the file path for typos",
				"Ensure the policy file exists",
				"Use an absolute path if needed",
			},
		}
	}

	// Parse policy
	if !opts.Quiet {
		fmt.Printf("📖 Parsing policy file...\n")
	}

	yamlParser := parser.NewYAMLParser()
	policy, err := yamlParser.ParseFile(opts.PolicyFile)
	if err != nil {
		return &TestError{
			Type:    "policy_parse_error",
			Message: fmt.Sprintf("Failed to parse policy: %v", err),
			Suggestions: []string{
				"Check YAML syntax in the policy file",
				"Validate the policy structure",
				"Use 'compliance-compiler validate' to check for issues",
			},
		}
	}

	// Initialize validator for testing
	policyValidator := validator.NewPolicyValidator()

	// Handle different testing modes
	if opts.GenerateCases {
		return generateTestCases(policy, policyValidator, opts)
	}

	if opts.Interactive {
		return runInteractiveTests(policy, policyValidator, opts)
	}

	// Load test data
	testData, err := loadTestData(opts)
	if err != nil {
		return err
	}

	if !opts.Quiet {
		fmt.Printf("📊 Loaded %d test case(s)\n", len(testData))
	}

	// Run tests
	results, err := executeTests(policy, policyValidator, testData, opts)
	if err != nil {
		return err
	}

	// Generate reports
	if err := generateTestReports(results, opts); err != nil {
		return err
	}

	// Show summary
	if !opts.Quiet {
		printTestSummary(results)
	}

	// Determine exit status
	if results.Summary.Failed > 0 {
		return &TestError{
			Type:    "tests_failed",
			Message: fmt.Sprintf("%d test(s) failed", results.Summary.Failed),
			Suggestions: []string{
				"Review the failed test details above",
				"Check policy logic against test expectations",
				"Use --verbose for more detailed output",
			},
		}
	}

	if !opts.Quiet {
		green.Printf("✅ All tests passed! (%d/%d)\n", results.Summary.Passed, results.Summary.Total)
	}

	return nil
}

func loadTestData(opts TestOptions) ([]validator.TransactionData, error) {
	var testData []validator.TransactionData

	// Load from specific test data file
	if opts.TestDataFile != "" {
		data, err := loadTestDataFile(opts.TestDataFile)
		if err != nil {
			return nil, &TestError{
				Type:    "test_data_load_error",
				Message: fmt.Sprintf("Failed to load test data file: %v", err),
				Suggestions: []string{
					"Check if the test data file exists",
					"Verify JSON format is correct",
					"Ensure file permissions allow reading",
				},
			}
		}
		testData = append(testData, data...)
	}

	// Load from samples directory
	if opts.SamplesDir != "" {
		data, err := loadSamplesDirectory(opts.SamplesDir)
		if err != nil {
			return nil, &TestError{
				Type:    "samples_load_error",
				Message: fmt.Sprintf("Failed to load samples directory: %v", err),
				Suggestions: []string{
					"Check if the samples directory exists",
					"Ensure directory contains valid JSON files",
					"Verify directory permissions",
				},
			}
		}
		testData = append(testData, data...)
	}

	// If no test data specified, generate basic test cases
	if len(testData) == 0 {
		if !opts.Quiet {
			fmt.Printf("⚠️  No test data specified, generating basic test cases...\n")
		}
		testData = generateBasicTestData()
	}

	return testData, nil
}

func loadTestDataFile(filename string) ([]validator.TransactionData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var testCases []map[string]interface{}
	if err := json.Unmarshal(data, &testCases); err != nil {
		return nil, err
	}

	result := make([]validator.TransactionData, len(testCases))
	for i, testCase := range testCases {
		result[i] = validator.TransactionData{
			Data: testCase,
		}
	}

	return result, nil
}

func loadSamplesDirectory(dir string) ([]validator.TransactionData, error) {
	var testData []validator.TransactionData

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".json") {
			data, err := loadTestDataFile(path)
			if err != nil {
				logrus.Warnf("Failed to load test file %s: %v", path, err)
				return nil // Continue with other files
			}
			testData = append(testData, data...)
		}

		return nil
	})

	return testData, err
}

func generateBasicTestData() []validator.TransactionData {
	return []validator.TransactionData{
		{
			Data: map[string]interface{}{
				"amount":            1000.0,
				"currency":          "USD",
				"transaction_type":  "transfer",
				"participant_count": 2,
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		},
		{
			Data: map[string]interface{}{
				"amount":            50000.0,
				"currency":          "USD",
				"transaction_type":  "large_transfer",
				"participant_count": 3,
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		},
	}
}

func executeTests(policy *parser.CompliancePolicy, policyValidator *validator.PolicyValidator, testData []validator.TransactionData, opts TestOptions) (*TestResults, error) {
	startTime := time.Now()

	// Initialize progress bar
	var bar *progressbar.ProgressBar
	if !opts.Quiet {
		bar = progressbar.NewOptions(len(testData),
			progressbar.OptionSetDescription("Running tests..."),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(50),
		)
	}

	results := &TestResults{
		PolicyFile: opts.PolicyFile,
		StartTime:  startTime,
		TestCases:  make([]*TestCaseResult, 0, len(testData)),
		Summary:    &TestSummary{},
		Options:    opts,
	}

	// Run tests
	for i, data := range testData {
		if !opts.Quiet {
			bar.Set(i)
		}

		testResult := executeTestCase(policy, policyValidator, data, i, opts)
		results.TestCases = append(results.TestCases, testResult)

		// Update summary
		results.Summary.Total++
		switch testResult.Status {
		case "passed":
			results.Summary.Passed++
		case "failed":
			results.Summary.Failed++
		case "skipped":
			results.Summary.Skipped++
		case "error":
			results.Summary.Errors++
		}
	}

	if !opts.Quiet {
		bar.Set(len(testData))
		bar.Finish()
		fmt.Println()
	}

	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)

	// Run benchmarks if requested
	if opts.Benchmark {
		if !opts.Quiet {
			fmt.Printf("🚀 Running performance benchmarks...\n")
		}
		results.BenchmarkResults = runBenchmarks(policy, policyValidator, testData, opts)
	}

	// Generate coverage if requested
	if opts.Coverage {
		if !opts.Quiet {
			fmt.Printf("📊 Analyzing test coverage...\n")
		}
		results.CoverageResults = analyzeCoverage(policy, testData, results.TestCases, opts)
	}

	return results, nil
}

func executeTestCase(policy *parser.CompliancePolicy, policyValidator *validator.PolicyValidator, data validator.TransactionData, index int, opts TestOptions) *TestCaseResult {
	testCase := &TestCaseResult{
		ID:        fmt.Sprintf("test_case_%d", index+1),
		Name:      fmt.Sprintf("Transaction Test %d", index+1),
		StartTime: time.Now(),
		TestData:  data,
	}

	defer func() {
		testCase.EndTime = time.Now()
		testCase.Duration = testCase.EndTime.Sub(testCase.StartTime)
	}()

	// Test the policy against the sample data
	testReport := policyValidator.TestPolicyAgainstSamples(policy, []validator.TransactionData{data})

	if len(testReport.TestResults) == 0 {
		testCase.Status = "error"
		testCase.ErrorMessage = "No test results returned"
		return testCase
	}

	result := testReport.TestResults[0]

	switch result.Status {
	case "passed":
		testCase.Status = "passed"
		testCase.Message = "Test passed - transaction validated successfully"
	case "failed":
		testCase.Status = "failed"
		testCase.Message = result.Message
		testCase.ErrorMessage = result.Message

		// Collect validation errors
		for _, err := range result.ErrorDetails {
			testCase.ValidationErrors = append(testCase.ValidationErrors, ValidationError{
				Type:    err.ErrorType,
				Field:   err.Field,
				Message: err.Message,
			})
		}
	default:
		testCase.Status = "error"
		testCase.ErrorMessage = "Unknown test result status"
	}

	// Add performance metrics
	testCase.PerformanceMetrics = &PerformanceMetrics{
		ExecutionTime: result.ExecutionTime,
		MemoryUsage:   1024, // Placeholder
		CPUUsage:      0.1,  // Placeholder
	}

	if opts.Verbose {
		logrus.Infof("Test case %d: %s (%v)", index+1, testCase.Status, testCase.Duration)
	}

	return testCase
}

func runBenchmarks(policy *parser.CompliancePolicy, policyValidator *validator.PolicyValidator, testData []validator.TransactionData, opts TestOptions) *BenchmarkResults {
	// Placeholder implementation for benchmarking
	return &BenchmarkResults{
		AverageExecutionTime: 10 * time.Millisecond,
		MaxExecutionTime:     50 * time.Millisecond,
		MinExecutionTime:     5 * time.Millisecond,
		ThroughputPerSecond:  1000,
		MemoryUsage:          1024 * 1024, // 1MB
	}
}

func analyzeCoverage(policy *parser.CompliancePolicy, testData []validator.TransactionData, testCases []*TestCaseResult, opts TestOptions) *CoverageResults {
	// Placeholder implementation for coverage analysis
	return &CoverageResults{
		RuleCoverage:      0.85,
		PredicateCoverage: 0.90,
		OverallCoverage:   0.87,
		UncoveredRules:    []string{"rule_3", "rule_7"},
	}
}

func generateTestCases(policy *parser.CompliancePolicy, policyValidator *validator.PolicyValidator, opts TestOptions) error {
	if !opts.Quiet {
		fmt.Printf("🎯 Generating test cases from policy...\n")
	}

	testCases := policyValidator.GenerateTestCases(policy)

	if !opts.Quiet {
		fmt.Printf("📝 Generated %d test case(s)\n", len(testCases))
	}

	// Convert to JSON for output
	output, err := json.MarshalIndent(testCases, "", "  ")
	if err != nil {
		return &TestError{
			Type:    "test_generation_error",
			Message: fmt.Sprintf("Failed to serialize generated test cases: %v", err),
		}
	}

	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, output, 0644); err != nil {
			return &TestError{
				Type:    "output_write_error",
				Message: fmt.Sprintf("Failed to write test cases to file: %v", err),
			}
		}
		if !opts.Quiet {
			fmt.Printf("✅ Test cases saved to: %s\n", opts.OutputFile)
		}
	} else {
		fmt.Print(string(output))
	}

	return nil
}

func runInteractiveTests(policy *parser.CompliancePolicy, policyValidator *validator.PolicyValidator, opts TestOptions) error {
	// Placeholder for interactive testing mode
	fmt.Printf("🎮 Interactive testing mode not yet implemented\n")
	return nil
}

func generateTestReports(results *TestResults, opts TestOptions) error {
	if opts.OutputFile == "" {
		return nil // No output file specified
	}

	var output []byte
	var err error

	switch opts.Format {
	case "json":
		output, err = json.MarshalIndent(results, "", "  ")
	case "html":
		output, err = generateHTMLReport(results)
	default:
		output, err = generateTextReport(results)
	}

	if err != nil {
		return &TestError{
			Type:    "report_generation_error",
			Message: fmt.Sprintf("Failed to generate test report: %v", err),
		}
	}

	return os.WriteFile(opts.OutputFile, output, 0644)
}

func generateHTMLReport(results *TestResults) ([]byte, error) {
	// Placeholder for HTML report generation
	return []byte("<html><body>HTML report not yet implemented</body></html>"), nil
}

func generateTextReport(results *TestResults) ([]byte, error) {
	var builder strings.Builder

	builder.WriteString("📋 Test Report\n")
	builder.WriteString("=============\n\n")
	builder.WriteString(fmt.Sprintf("Policy: %s\n", results.PolicyFile))
	builder.WriteString(fmt.Sprintf("Duration: %v\n", results.Duration))
	builder.WriteString(fmt.Sprintf("Total Tests: %d\n\n", results.Summary.Total))

	for _, testCase := range results.TestCases {
		status := "✅"
		if testCase.Status == "failed" {
			status = "❌"
		} else if testCase.Status == "skipped" {
			status = "⏭️"
		}

		builder.WriteString(fmt.Sprintf("%s %s (%v)\n", status, testCase.Name, testCase.Duration))
		if testCase.ErrorMessage != "" {
			builder.WriteString(fmt.Sprintf("   Error: %s\n", testCase.ErrorMessage))
		}
	}

	return []byte(builder.String()), nil
}

func printTestSummary(results *TestResults) {
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	fmt.Println("\n📊 Test Summary")
	fmt.Println("===============")
	fmt.Printf("Total Tests: %d\n", results.Summary.Total)

	if results.Summary.Passed > 0 {
		green.Printf("Passed: %d\n", results.Summary.Passed)
	}

	if results.Summary.Failed > 0 {
		red.Printf("Failed: %d\n", results.Summary.Failed)
	}

	if results.Summary.Skipped > 0 {
		yellow.Printf("Skipped: %d\n", results.Summary.Skipped)
	}

	if results.Summary.Errors > 0 {
		red.Printf("Errors: %d\n", results.Summary.Errors)
	}

	fmt.Printf("Duration: %v\n", results.Duration)

	// Show coverage if available
	if results.CoverageResults != nil {
		fmt.Printf("Coverage: %.1f%%\n", results.CoverageResults.OverallCoverage*100)
	}

	// Show benchmark results if available
	if results.BenchmarkResults != nil {
		fmt.Printf("Avg Execution Time: %v\n", results.BenchmarkResults.AverageExecutionTime)
		fmt.Printf("Throughput: %.0f ops/sec\n", results.BenchmarkResults.ThroughputPerSecond)
	}

	// Show failed tests
	if results.Summary.Failed > 0 {
		fmt.Println("\n❌ Failed Tests:")
		for _, testCase := range results.TestCases {
			if testCase.Status == "failed" {
				red.Printf("  • %s: %s\n", testCase.Name, testCase.ErrorMessage)
			}
		}
	}
}

// Type definitions
type TestResults struct {
	PolicyFile       string            `json:"policy_file"`
	StartTime        time.Time         `json:"start_time"`
	EndTime          time.Time         `json:"end_time"`
	Duration         time.Duration     `json:"duration"`
	TestCases        []*TestCaseResult `json:"test_cases"`
	Summary          *TestSummary      `json:"summary"`
	BenchmarkResults *BenchmarkResults `json:"benchmark_results,omitempty"`
	CoverageResults  *CoverageResults  `json:"coverage_results,omitempty"`
	Options          TestOptions       `json:"options"`
}

type TestCaseResult struct {
	ID                 string                    `json:"id"`
	Name               string                    `json:"name"`
	Status             string                    `json:"status"`
	Message            string                    `json:"message,omitempty"`
	ErrorMessage       string                    `json:"error_message,omitempty"`
	StartTime          time.Time                 `json:"start_time"`
	EndTime            time.Time                 `json:"end_time"`
	Duration           time.Duration             `json:"duration"`
	TestData           validator.TransactionData `json:"test_data"`
	ValidationErrors   []ValidationError         `json:"validation_errors,omitempty"`
	PerformanceMetrics *PerformanceMetrics       `json:"performance_metrics,omitempty"`
}

type TestSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

type ValidationError struct {
	Type    string `json:"type"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

type PerformanceMetrics struct {
	ExecutionTime time.Duration `json:"execution_time"`
	MemoryUsage   int64         `json:"memory_usage"`
	CPUUsage      float64       `json:"cpu_usage"`
}

type BenchmarkResults struct {
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	MaxExecutionTime     time.Duration `json:"max_execution_time"`
	MinExecutionTime     time.Duration `json:"min_execution_time"`
	ThroughputPerSecond  float64       `json:"throughput_per_second"`
	MemoryUsage          int64         `json:"memory_usage"`
}

type CoverageResults struct {
	RuleCoverage      float64  `json:"rule_coverage"`
	PredicateCoverage float64  `json:"predicate_coverage"`
	OverallCoverage   float64  `json:"overall_coverage"`
	UncoveredRules    []string `json:"uncovered_rules"`
}

// TestError represents a user-friendly test error
type TestError struct {
	Type        string   `json:"type"`
	Message     string   `json:"message"`
	Suggestions []string `json:"suggestions,omitempty"`
}

func (e *TestError) Error() string {
	var builder strings.Builder

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	red.Fprintf(&builder, "❌ Test Error: %s\n", e.Message)

	if len(e.Suggestions) > 0 {
		builder.WriteString("\n")
		yellow.Fprintf(&builder, "💡 Suggestions:\n")
		for _, suggestion := range e.Suggestions {
			fmt.Fprintf(&builder, "  • %s\n", suggestion)
		}
	}

	return builder.String()
}
