package compiler

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

type Writer struct {
	format string
}

func NewWriter(format string) *Writer {
	return &Writer{
		format: format,
	}
}

func (w *Writer) Write(policy *types.CompiledPolicy) ([]byte, error) {
	logrus.Debugf("Writing compiled policy in %s format", w.format)

	switch w.format {
	case "binary":
		return w.writeBinary(policy)
	case "text":
		return w.writeText(policy)
	case "json":
		return w.writeJSON(policy)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", w.format)
	}
}

func (w *Writer) WriteToFile(policy *types.CompiledPolicy, filename string) error {
	logrus.Debugf("Writing compiled policy to file: %s", filename)

	data, err := w.Write(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	logrus.Debugf("Successfully wrote %d bytes to %s", len(data), filename)
	return nil
}

func (w *Writer) WriteToWriter(policy *types.CompiledPolicy, writer io.Writer) error {
	logrus.Debug("Writing compiled policy to writer")

	data, err := w.Write(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	n, err := writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to writer: %w", err)
	}

	logrus.Debugf("Successfully wrote %d bytes to writer", n)
	return nil
}

func (w *Writer) writeBinary(policy *types.CompiledPolicy) ([]byte, error) {
	// Convert to protobuf message and serialize
	protoPolicy, err := w.toProtoMessage(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to proto message: %w", err)
	}

	data, err := proto.Marshal(protoPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto message: %w", err)
	}

	return data, nil
}

func (w *Writer) writeText(policy *types.CompiledPolicy) ([]byte, error) {
	// Convert to protobuf message and serialize as text
	protoPolicy, err := w.toProtoMessage(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to proto message: %w", err)
	}

	data, err := prototext.Marshal(protoPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto text: %w", err)
	}

	return data, nil
}

func (w *Writer) writeJSON(policy *types.CompiledPolicy) ([]byte, error) {
	// For JSON format, we can serialize directly or via protobuf JSON
	// For now, using direct JSON serialization
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return data, nil
}

func (w *Writer) writeProtobufJSON(policy *types.CompiledPolicy) ([]byte, error) {
	// Convert to protobuf message and serialize as JSON
	protoPolicy, err := w.toProtoMessage(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to proto message: %w", err)
	}

	marshaler := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}

	data, err := marshaler.Marshal(protoPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto JSON: %w", err)
	}

	return data, nil
}

// toProtoMessage converts a CompiledPolicy to a protobuf message
// Note: This would normally use generated protobuf types, but for this
// example, we'll return an error as this is a mock implementation
func (w *Writer) toProtoMessage(policy *types.CompiledPolicy) (proto.Message, error) {
	// In a real implementation, this would convert to actual protobuf types
	// For now, we'll return an error since this is just a demonstration
	return nil, fmt.Errorf("protobuf conversion not implemented in this demo version")
}

// Note: In a real implementation, actual protobuf types would be used here

// Tester provides functionality for testing compiled policies
type Tester struct {
	verbose  bool
	parallel bool
}

func NewTester() *Tester {
	return &Tester{
		verbose:  false,
		parallel: false,
	}
}

func (t *Tester) SetVerbose(verbose bool) {
	t.verbose = verbose
}

func (t *Tester) SetParallel(parallel bool) {
	t.parallel = parallel
}

func (t *Tester) RunTests(policy *types.CompiledPolicy, testData *types.TestData) (*types.TestResults, error) {
	logrus.Infof("Running %d test cases against compiled policy", len(testData.TestCases))

	results := &types.TestResults{
		Summary: types.TestSummary{
			Total: len(testData.TestCases),
		},
		Cases: make([]types.TestResult, 0, len(testData.TestCases)),
	}

	for _, testCase := range testData.TestCases {
		result, err := t.RunSingleTest(policy, &testCase)
		if err != nil {
			result = &types.TestResult{
				Name:     testCase.Name,
				Status:   "failed",
				ErrorMsg: err.Error(),
			}
		}

		results.Cases = append(results.Cases, *result)

		switch result.Status {
		case "passed":
			results.Summary.Passed++
		case "failed":
			results.Summary.Failed++
		case "skipped":
			results.Summary.Skipped++
		}
	}

	logrus.Infof("Test execution completed: %d passed, %d failed, %d skipped",
		results.Summary.Passed, results.Summary.Failed, results.Summary.Skipped)

	return results, nil
}

func (t *Tester) RunSingleTest(policy *types.CompiledPolicy, testCase *types.TestCase) (*types.TestResult, error) {
	logrus.Debugf("Running test case: %s", testCase.Name)

	// This is a simplified test execution - real implementation would
	// evaluate the compiled policy against the test input

	result := &types.TestResult{
		Name:     testCase.Name,
		Expected: testCase.Expected.Pass,
		Status:   "passed",
	}

	// Mock evaluation - in real implementation, this would execute the policy
	actual := t.evaluatePolicy(policy, testCase.Input)
	result.Actual = actual

	if actual != testCase.Expected.Pass {
		result.Status = "failed"
		result.ErrorMsg = fmt.Sprintf("Expected %t, got %t", testCase.Expected.Pass, actual)
		if testCase.Expected.Reason != "" {
			result.Reason = testCase.Expected.Reason
		}
	}

	if t.verbose {
		logrus.Infof("Test %s: %s (expected: %t, actual: %t)",
			testCase.Name, result.Status, result.Expected, result.Actual)
	}

	return result, nil
}

func (t *Tester) evaluatePolicy(policy *types.CompiledPolicy, input map[string]interface{}) bool {
	// Mock policy evaluation - real implementation would execute compiled rules
	// For demonstration, we'll use simple heuristics

	if amount, ok := input["amount"].(float64); ok {
		// Simple rule: amounts over 50000 fail compliance
		if amount > 50000 {
			return false
		}
	}

	if region, ok := input["region"].(string); ok {
		// Simple rule: certain regions might have restrictions
		if region == "RESTRICTED" {
			return false
		}
	}

	return true
}

// Testing support is now provided by types in pkg/types package
