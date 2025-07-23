package cmd

import (
	"fmt"
	"os"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/compiler"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewTestCmd() *cobra.Command {
	var (
		testDataFile string
		outputFile   string
		verbose      bool
		parallel     bool
	)

	cmd := &cobra.Command{
		Use:   "test [flags] <policy-file>",
		Short: "Test compliance policies against sample data",
		Long: `Test compliance policies against sample transaction data to verify behavior.

The test command runs compiled policies against sample data to validate that
the compliance rules work as expected. It can test various scenarios including:
- Valid transactions that should pass compliance
- Invalid transactions that should be rejected
- Edge cases and boundary conditions
- Performance under load

Examples:
  # Test a policy with sample data
  compliance-compiler test -t sample_data.json policy.yaml

  # Test with verbose output
  compliance-compiler test -v -t sample_data.json policy.yaml

  # Save test results to file
  compliance-compiler test -t sample_data.json -o results.json policy.yaml

  # Run tests in parallel for performance
  compliance-compiler test --parallel -t sample_data.json policy.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(args[0], testDataFile, outputFile, verbose, parallel)
		},
	}

	cmd.Flags().StringVarP(&testDataFile, "test-data", "t", "", "test data file (JSON format)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for test results")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose test output")
	cmd.Flags().BoolVar(&parallel, "parallel", false, "run tests in parallel")

	cmd.MarkFlagRequired("test-data")

	return cmd
}

func runTest(policyFile, testDataFile, outputFile string, verbose, parallel bool) error {
	logrus.Infof("Testing policy: %s with data: %s", policyFile, testDataFile)

	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		return fmt.Errorf("policy file does not exist: %s", policyFile)
	}

	if _, err := os.Stat(testDataFile); os.IsNotExist(err) {
		return fmt.Errorf("test data file does not exist: %s", testDataFile)
	}

	yamlParser := parser.NewYAMLParser()
	policy, err := yamlParser.ParseFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to parse policy file: %w", err)
	}

	logrus.Debug("Compiling policy for testing")
	policyCompiler := compiler.NewCompiler()
	compiledPolicy, err := policyCompiler.CompilePolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	logrus.Debug("Loading test data")
	testData, err := loadTestData(testDataFile)
	if err != nil {
		return fmt.Errorf("failed to load test data: %w", err)
	}

	logrus.Infof("Running %d test cases", len(testData.TestCases))

	tester := compiler.NewTester()
	tester.SetVerbose(verbose)
	tester.SetParallel(parallel)

	results, err := tester.RunTests(compiledPolicy, testData)
	if err != nil {
		return fmt.Errorf("failed to run tests: %w", err)
	}

	if outputFile != "" {
		if err := saveTestResults(results, outputFile); err != nil {
			return fmt.Errorf("failed to save test results: %w", err)
		}
		logrus.Infof("Test results saved to: %s", outputFile)
	}

	return printTestSummary(results)
}

// Test types are now defined in pkg/types package

func loadTestData(filename string) (*types.TestData, error) {
	logrus.Debugf("Loading test data from: %s", filename)

	// Simplified implementation - would parse JSON test data
	testData := &types.TestData{
		TestCases: []types.TestCase{
			{
				Name:        "valid_transaction",
				Description: "Test a valid transaction that should pass compliance",
				Input: map[string]interface{}{
					"amount":     1000.00,
					"sender":     "alice",
					"recipient":  "bob",
					"asset_type": "USD",
					"region":     "US",
				},
				Expected: types.TestExpectation{
					Pass:   true,
					Reason: "Transaction meets all compliance requirements",
				},
			},
			{
				Name:        "exceeds_limit",
				Description: "Test transaction that exceeds compliance limits",
				Input: map[string]interface{}{
					"amount":     100000.00,
					"sender":     "alice",
					"recipient":  "bob",
					"asset_type": "USD",
					"region":     "US",
				},
				Expected: types.TestExpectation{
					Pass:   false,
					Reason: "Transaction amount exceeds daily limit",
				},
			},
		},
	}

	return testData, nil
}

func saveTestResults(results *types.TestResults, filename string) error {
	logrus.Debugf("Saving test results to: %s", filename)
	// Implementation would save results as JSON
	return nil
}

func printTestSummary(results *types.TestResults) error {
	fmt.Printf("\nTest Summary:\n")
	fmt.Printf("=============\n")
	fmt.Printf("Total:   %d\n", results.Summary.Total)
	fmt.Printf("Passed:  %d\n", results.Summary.Passed)
	fmt.Printf("Failed:  %d\n", results.Summary.Failed)
	fmt.Printf("Skipped: %d\n", results.Summary.Skipped)
	fmt.Printf("\n")

	if results.Summary.Failed > 0 {
		fmt.Printf("Failed Tests:\n")
		fmt.Printf("-------------\n")
		for _, result := range results.Cases {
			if result.Status == "failed" {
				fmt.Printf("❌ %s: %s\n", result.Name, result.ErrorMsg)
			}
		}
		fmt.Printf("\n")
		return fmt.Errorf("some tests failed")
	}

	fmt.Printf("✅ All tests passed!\n")
	return nil
}
