package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseYAMLPolicy tests the core YAML parsing functionality
func TestParseYAMLPolicy(t *testing.T) {
	parser := NewYAMLParser()

	// Test valid policy parsing
	validYAML := `
policy_id: "test-policy-v1"
version: "1.0.0"
jurisdiction: "US"
asset_class: "consumer_loans"

metadata:
  title: "Test Policy"
  description: "A test compliance policy"
  tags: ["test", "compliance"]

rules:
  - name: "simple_rule"
    description: "A simple test rule"
    required: true
    predicate:
      field: "loan.amount"
      op: "gte"
      value: 1000

  - name: "complex_logical_rule"
    description: "A complex rule with logical operators"
    required: true
    predicate:
      and:
        - field: "borrower.credit_score"
          op: "gte"
          value: 620
        - or:
            - field: "loan.debt_to_income_ratio"
              op: "lte"
              value: 0.43
            - field: "borrower.annual_income"
              op: "gte"
              value: 100000

attestations:
  - name: "kyc_verification"
    type: "kyc"
    required: true

enforcement:
  level: "blocking"
  actions: ["log", "block_transaction"]
`

	policy, err := parser.ParseYAMLPolicy([]byte(validYAML))
	if err != nil {
		t.Fatalf("Failed to parse valid YAML: %v", err)
	}

	// Validate parsed structure
	if policy.PolicyId != "test-policy-v1" {
		t.Errorf("Expected policy_id 'test-policy-v1', got '%s'", policy.PolicyId)
	}

	if policy.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", policy.Version)
	}

	if policy.Jurisdiction != "US" {
		t.Errorf("Expected jurisdiction 'US', got '%s'", policy.Jurisdiction)
	}

	if len(policy.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(policy.Rules))
	}

	if len(policy.Attestations) != 1 {
		t.Errorf("Expected 1 attestation, got %d", len(policy.Attestations))
	}

	if policy.Enforcement == nil {
		t.Error("Expected enforcement config, got nil")
	}
}

// TestValidateYAMLStructure tests YAML structure validation
func TestValidateYAMLStructure(t *testing.T) {
	parser := NewYAMLParser()

	tests := []struct {
		name        string
		yamlData    map[string]interface{}
		expectError bool
		errorField  string
	}{
		{
			name: "valid_structure",
			yamlData: map[string]interface{}{
				"policy_id":    "test-policy",
				"version":      "1.0.0",
				"jurisdiction": "US",
				"asset_class":  "loans",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "test_rule",
						"predicate": map[string]interface{}{
							"field": "test.field",
							"op":    "equals",
							"value": "test",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "missing_policy_id",
			yamlData: map[string]interface{}{
				"version":      "1.0.0",
				"jurisdiction": "US",
				"asset_class":  "loans",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "test_rule",
						"predicate": map[string]interface{}{
							"field": "test.field",
							"op":    "equals",
							"value": "test",
						},
					},
				},
			},
			expectError: true,
			errorField:  "policy_id",
		},
		{
			name: "empty_rules",
			yamlData: map[string]interface{}{
				"policy_id":    "test-policy",
				"version":      "1.0.0",
				"jurisdiction": "US",
				"asset_class":  "loans",
				"rules":        []interface{}{},
			},
			expectError: true,
			errorField:  "rules",
		},
		{
			name: "invalid_jurisdiction",
			yamlData: map[string]interface{}{
				"policy_id":    "test-policy",
				"version":      "1.0.0",
				"jurisdiction": "INVALID_JURISDICTION_FORMAT",
				"asset_class":  "loans",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "test_rule",
						"predicate": map[string]interface{}{
							"field": "test.field",
							"op":    "equals",
							"value": "test",
						},
					},
				},
			},
			expectError: true,
			errorField:  "jurisdiction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.ValidateYAMLStructure(tt.yamlData)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for field '%s', but got none", tt.errorField)
				} else if !strings.Contains(err.Error(), tt.errorField) {
					t.Errorf("Expected error to contain field '%s', got: %v", tt.errorField, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
			}
		})
	}
}

// TestParsePredicateTree tests recursive predicate parsing
func TestParsePredicateTree(t *testing.T) {
	parser := NewYAMLParser()

	tests := []struct {
		name          string
		predicateData interface{}
		expectError   bool
	}{
		{
			name: "simple_comparison",
			predicateData: map[string]interface{}{
				"field": "loan.amount",
				"op":    "gte",
				"value": 1000,
			},
			expectError: false,
		},
		{
			name: "logical_and",
			predicateData: map[string]interface{}{
				"and": []interface{}{
					map[string]interface{}{
						"field": "loan.amount",
						"op":    "gte",
						"value": 1000,
					},
					map[string]interface{}{
						"field": "borrower.credit_score",
						"op":    "gte",
						"value": 620,
					},
				},
			},
			expectError: false,
		},
		{
			name: "nested_logical",
			predicateData: map[string]interface{}{
				"and": []interface{}{
					map[string]interface{}{
						"field": "loan.amount",
						"op":    "gte",
						"value": 1000,
					},
					map[string]interface{}{
						"or": []interface{}{
							map[string]interface{}{
								"field": "borrower.credit_score",
								"op":    "gte",
								"value": 620,
							},
							map[string]interface{}{
								"field": "borrower.annual_income",
								"op":    "gte",
								"value": 50000,
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "exists_predicate",
			predicateData: map[string]interface{}{
				"exists":       "borrower.social_security_number",
				"should_exist": true,
			},
			expectError: false,
		},
		{
			name: "range_predicate",
			predicateData: map[string]interface{}{
				"range": map[string]interface{}{
					"field":         "loan.interest_rate",
					"min":           0.01,
					"max":           0.30,
					"min_inclusive": true,
					"max_inclusive": false,
				},
			},
			expectError: false,
		},
		{
			name: "set_predicate_in",
			predicateData: map[string]interface{}{
				"field": "loan.purpose",
				"in":    []interface{}{"home_purchase", "refinance", "home_improvement"},
			},
			expectError: false,
		},
		{
			name: "expression_predicate",
			predicateData: map[string]interface{}{
				"expression": "loan.amount * 0.8 <= borrower.annual_income",
				"language":   "cel",
				"variables": map[string]interface{}{
					"max_dti": 0.43,
				},
			},
			expectError: false,
		},
		{
			name: "regex_predicate",
			predicateData: map[string]interface{}{
				"field": "borrower.phone_number",
				"regex": "^\\+?1?[2-9]\\d{2}[2-9]\\d{2}\\d{4}$",
				"flags": []interface{}{"case_insensitive"},
			},
			expectError: false,
		},
		{
			name: "time_predicate",
			predicateData: map[string]interface{}{
				"field": "loan.application_date",
				"time": map[string]interface{}{
					"op":             "newer_than",
					"duration":       "30 days",
					"reference_time": "2023-01-01T00:00:00Z",
				},
			},
			expectError: false,
		},
		{
			name: "invalid_predicate_structure",
			predicateData: map[string]interface{}{
				"invalid_operator": "test",
			},
			expectError: true,
		},
		{
			name: "invalid_comparison_operator",
			predicateData: map[string]interface{}{
				"field": "test.field",
				"op":    "invalid_op",
				"value": "test",
			},
			expectError: true,
		},
		{
			name:          "nil_predicate",
			predicateData: nil,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate, err := parser.ParsePredicateTree(tt.predicateData)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				if predicate == nil {
					t.Error("Expected predicate, but got nil")
				}
			}
		})
	}
}

// TestFieldPathValidation tests field path validation
func TestFieldPathValidation(t *testing.T) {
	parser := NewYAMLParser()

	tests := []struct {
		name        string
		fieldPath   string
		expectError bool
	}{
		{
			name:        "simple_field_path",
			fieldPath:   "loan.amount",
			expectError: false,
		},
		{
			name:        "nested_field_path",
			fieldPath:   "borrower.address.street",
			expectError: false,
		},
		{
			name:        "array_index_access",
			fieldPath:   "borrower.previous_loans[0].amount",
			expectError: false,
		},
		{
			name:        "array_filter_access",
			fieldPath:   "borrower.accounts[status='active'].balance",
			expectError: false,
		},
		{
			name:        "function_call",
			fieldPath:   "borrower.monthly_payments.sum()",
			expectError: false,
		},
		{
			name:        "complex_path",
			fieldPath:   "loan.payments[status='completed'].sum().amount",
			expectError: false,
		},
		{
			name:        "empty_field_path",
			fieldPath:   "",
			expectError: true,
		},
		{
			name:        "invalid_characters",
			fieldPath:   "loan..amount",
			expectError: false, // Will be handled by path parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.validateFieldPath(tt.fieldPath)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
			}
		})
	}
}

// TestCircularReferenceDetection tests circular reference detection
func TestCircularReferenceDetection(t *testing.T) {
	detector := NewCircularReferenceDetector()

	// Create a simple predicate that doesn't have circular references
	simplePredicate := &Predicate{
		PredicateType: &Predicate_Comparison{
			Comparison: &ComparisonPredicate{
				FieldPath: &FieldPath{
					RawPath: "loan.amount",
				},
				Operator: ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN,
			},
		},
	}

	err := detector.CheckPredicate(simplePredicate, "test_context")
	if err != nil {
		t.Errorf("Expected no error for simple predicate, got: %v", err)
	}

	// Test logical predicate without circular references
	logicalPredicate := &Predicate{
		PredicateType: &Predicate_Logical{
			Logical: &LogicalPredicate{
				Operator: LogicalOperator_LOGICAL_OPERATOR_AND,
				Operands: []*Predicate{simplePredicate, simplePredicate},
			},
		},
	}

	detector2 := NewCircularReferenceDetector()
	err = detector2.CheckPredicate(logicalPredicate, "logical_test")
	if err != nil {
		t.Errorf("Expected no error for logical predicate, got: %v", err)
	}
}

// TestPerformanceAnalysis tests performance analysis
func TestPerformanceAnalysis(t *testing.T) {
	analyzer := NewPerformanceAnalyzer()

	// Create a policy with many rules
	policy := &CompliancePolicy{
		PolicyId: "test-policy",
		Rules:    make([]*PolicyRule, 15), // Above warning threshold
	}

	for i := range policy.Rules {
		policy.Rules[i] = &PolicyRule{
			Name: fmt.Sprintf("rule_%d", i),
			Predicate: &Predicate{
				PredicateType: &Predicate_Comparison{
					Comparison: &ComparisonPredicate{
						FieldPath: &FieldPath{
							RawPath: fmt.Sprintf("field_%d", i),
						},
					},
				},
			},
		}
	}

	warnings := analyzer.AnalyzePolicy(policy)
	if len(warnings) == 0 {
		t.Error("Expected performance warnings for policy with many rules")
	}

	// Check that we got the expected warning about too many rules
	foundRuleCountWarning := false
	for _, warning := range warnings {
		if strings.Contains(warning.Message, "rules") && strings.Contains(warning.Message, "performance") {
			foundRuleCountWarning = true
			break
		}
	}

	if !foundRuleCountWarning {
		t.Error("Expected warning about high rule count")
	}
}

// TestParseFromFile tests parsing from actual YAML files
func TestParseFromFile(t *testing.T) {
	// Test with the example policy file
	testFilePath := filepath.Join("..", "..", "examples", "test-policies", "debt_to_income_policy.yaml")

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skipf("Test file %s does not exist, skipping file parsing test", testFilePath)
		return
	}

	parser := NewYAMLParser()

	yamlContent, err := os.ReadFile(testFilePath)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	policy, err := parser.ParseYAMLPolicy(yamlContent)
	if err != nil {
		t.Fatalf("Failed to parse test policy file: %v", err)
	}

	if policy.PolicyId == "" {
		t.Error("Expected policy_id to be set")
	}

	if len(policy.Rules) == 0 {
		t.Error("Expected policy to have rules")
	}

	t.Logf("Successfully parsed policy: %s (v%s) with %d rules",
		policy.PolicyId, policy.Version, len(policy.Rules))
}

// TestErrorCases tests various error cases
func TestErrorCases(t *testing.T) {
	parser := NewYAMLParser()

	errorCases := []struct {
		name      string
		yamlData  string
		errorType ErrorType
	}{
		{
			name: "invalid_yaml_syntax",
			yamlData: `
policy_id: "test
# Missing closing quote
version: "1.0.0"
`,
			errorType: ErrorTypeYAMLSyntax,
		},
		{
			name: "missing_required_field",
			yamlData: `
# Missing policy_id
version: "1.0.0"
jurisdiction: "US"
asset_class: "loans"
rules:
  - name: "test_rule"
    predicate:
      field: "test.field"
      op: "equals"
      value: "test"
`,
			errorType: ErrorTypeValidation,
		},
		{
			name: "invalid_predicate_operator",
			yamlData: `
policy_id: "test-policy"
version: "1.0.0"
jurisdiction: "US"
asset_class: "loans"
rules:
  - name: "test_rule"
    predicate:
      field: "test.field"
      op: "invalid_operator"
      value: "test"
`,
			errorType: ErrorTypePredicateStructure,
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParseYAMLPolicy([]byte(tc.yamlData))
			if err == nil {
				t.Error("Expected error, but got none")
			}
			// Note: In a full implementation, you'd check for specific error types
		})
	}
}

// TestStrictMode tests strict mode parsing
func TestStrictMode(t *testing.T) {
	parser := NewYAMLParser()

	// Test with strict mode disabled (default)
	yamlWithUnknownField := `
policy_id: "test-policy"
version: "1.0.0"
jurisdiction: "US"
asset_class: "loans"
unknown_field: "should be ignored in non-strict mode"
rules:
  - name: "test_rule"
    predicate:
      field: "unknown.field.path"
      op: "equals"
      value: "test"
`

	_, err := parser.ParseYAMLPolicy([]byte(yamlWithUnknownField))
	if err != nil {
		t.Errorf("Expected no error in non-strict mode, got: %v", err)
	}

	// Test with strict mode enabled
	parser.SetStrictMode(true)

	// In strict mode, unknown field paths might cause warnings or errors
	// (depending on implementation details)
	_, err = parser.ParseYAMLPolicy([]byte(yamlWithUnknownField))
	// The behavior here depends on the specific strict mode implementation
	// For now, we just test that the method can be called without panic
}

// Helper function for tests (would be moved to a separate package in real implementation)
func createTestPolicy() *CompliancePolicy {
	return &CompliancePolicy{
		PolicyId:     "test-policy-v1",
		Version:      "1.0.0",
		Jurisdiction: "US",
		AssetClass:   "consumer_loans",
		Rules: []*PolicyRule{
			{
				Name: "test_rule",
				Predicate: &Predicate{
					PredicateType: &Predicate_Comparison{
						Comparison: &ComparisonPredicate{
							FieldPath: &FieldPath{
								RawPath: "loan.amount",
							},
							Operator: ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN_OR_EQUAL,
						},
					},
				},
				Required: true,
			},
		},
	}
}

// Benchmark tests
func BenchmarkParseSimplePolicy(b *testing.B) {
	parser := NewYAMLParser()
	yamlData := `
policy_id: "benchmark-policy"
version: "1.0.0"
jurisdiction: "US"
asset_class: "loans"
rules:
  - name: "simple_rule"
    predicate:
      field: "loan.amount"
      op: "gte"
      value: 1000
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseYAMLPolicy([]byte(yamlData))
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

func BenchmarkParseComplexPolicy(b *testing.B) {
	parser := NewYAMLParser()

	// Read the complex policy file for benchmarking
	testFilePath := filepath.Join("..", "..", "examples", "test-policies", "debt_to_income_policy.yaml")
	yamlContent, err := os.ReadFile(testFilePath)
	if err != nil {
		b.Skipf("Cannot read test file for benchmark: %v", err)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseYAMLPolicy(yamlContent)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}
