package parser

import (
	"reflect"
	"testing"
)

// TestYAMLExpressionIntegration tests the integration between YAML parser and expression engine
func TestYAMLExpressionIntegration(t *testing.T) {
	parser := NewYAMLParser()

	// Test YAML with value_expr field
	yamlWithExpression := `
policy_id: "integration-test-policy"
version: "1.0.0"
jurisdiction: "US"
asset_class: "consumer_loans"

rules:
  - name: "debt_to_income_test"
    description: "Test debt to income calculation"
    required: true
    predicate:
      field: "loan.debt_to_income_ratio"
      op: "lte"
      value_expr: "loan.principal / borrower.annual_income"
`

	policy, err := parser.ParseYAMLPolicy([]byte(yamlWithExpression))
	if err != nil {
		t.Fatalf("Failed to parse YAML with expression: %v", err)
	}

	if policy == nil {
		t.Fatal("Expected policy to be parsed, got nil")
	}

	if policy.PolicyId != "integration-test-policy" {
		t.Errorf("Expected policy_id 'integration-test-policy', got '%s'", policy.PolicyId)
	}

	if len(policy.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(policy.Rules))
	}

	t.Logf("Successfully parsed policy with expression: %s", policy.PolicyId)
}

// TestExpressionEngineStandalone tests the expression engine independently
func TestExpressionEngineStandalone(t *testing.T) {
	// Create field schema
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal":         {Type: reflect.TypeOf(float64(0))},
			"borrower.annual_income": {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	// Test parsing a simple expression
	expr, err := engine.ParseExpression("loan.principal / borrower.annual_income")
	if err != nil {
		t.Fatalf("Failed to parse expression: %v", err)
	}

	if expr == nil {
		t.Fatal("Expected expression to be parsed, got nil")
	}

	// Test validation
	context := map[string]interface{}{
		"loan.principal":         100000.0,
		"borrower.annual_income": 50000.0,
		"audit_context": map[string]interface{}{
			"request_id": "test-123",
			"source":     "test",
		},
	}

	err = engine.ValidateExpression(expr, context)
	if err != nil {
		t.Errorf("Expression validation failed: %v", err)
	}

	// Test compilation
	protoExpr, err := engine.CompileToProtobuf(expr)
	if err != nil {
		t.Errorf("Expression compilation failed: %v", err)
	}

	if protoExpr == nil {
		t.Error("Expected compiled expression, got nil")
	}

	t.Logf("Successfully parsed, validated, and compiled expression")
}
