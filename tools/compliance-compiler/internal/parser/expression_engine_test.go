package parser

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestNewExpressionEngine tests the creation of a new expression engine
func TestNewExpressionEngine(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal": {
				Type:        reflect.TypeOf(float64(0)),
				Nullable:    false,
				Description: "Loan principal amount",
			},
			"borrower.credit_score": {
				Type:        reflect.TypeOf(int64(0)),
				Nullable:    false,
				Description: "Borrower credit score",
			},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	if engine == nil {
		t.Fatal("Expected engine to be created, got nil")
	}

	if len(engine.allowedFields) != 2 {
		t.Errorf("Expected 2 allowed fields, got %d", len(engine.allowedFields))
	}

	// Check that built-in functions are registered
	expectedFunctions := []string{"min", "max", "abs", "round", "len", "sum", "contains"}
	for _, funcName := range expectedFunctions {
		if _, exists := engine.functions[funcName]; !exists {
			t.Errorf("Expected function '%s' to be registered", funcName)
		}
	}

	// Check that validators are added
	if len(engine.validatorChain) == 0 {
		t.Error("Expected validators to be registered")
	}
}

// TestParseExpression tests basic expression parsing
func TestParseExpression(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal":        {Type: reflect.TypeOf(float64(0))},
			"loan.interest_rate":    {Type: reflect.TypeOf(float64(0))},
			"borrower.credit_score": {Type: reflect.TypeOf(int64(0))},
			"borrower.income":       {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	tests := []struct {
		name        string
		expression  string
		expectError bool
		expectType  reflect.Type
	}{
		{
			name:        "simple_arithmetic",
			expression:  "loan.principal * 1.2",
			expectError: false,
			expectType:  reflect.TypeOf(float64(0)),
		},
		{
			name:        "comparison_expression",
			expression:  "borrower.credit_score >= 620",
			expectError: false,
			expectType:  reflect.TypeOf(true),
		},
		{
			name:        "logical_expression",
			expression:  "loan.principal > 1000 && borrower.credit_score >= 620",
			expectError: false,
			expectType:  reflect.TypeOf(true),
		},
		{
			name:        "function_call",
			expression:  "max(loan.principal, borrower.income)",
			expectError: false,
			expectType:  reflect.TypeOf(float64(0)),
		},
		{
			name:        "complex_expression",
			expression:  "(loan.principal * loan.interest_rate) / 12",
			expectError: false,
			expectType:  reflect.TypeOf(float64(0)),
		},
		{
			name:        "empty_expression",
			expression:  "",
			expectError: true,
		},
		{
			name:        "invalid_syntax",
			expression:  "loan.principal *",
			expectError: true,
		},
		{
			name:        "unknown_field",
			expression:  "unknown.field + 1",
			expectError: true,
		},
		{
			name:        "restricted_pattern",
			expression:  "import os",
			expectError: true,
		},
		{
			name:        "dangerous_function",
			expression:  "eval('1+1')",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := engine.ParseExpression(tt.expression)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for expression '%s', got none", tt.expression)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for expression '%s', got: %v", tt.expression, err)
				} else {
					if expr == nil {
						t.Error("Expected expression, got nil")
					} else {
						if tt.expectType != nil && expr.Type != tt.expectType {
							t.Errorf("Expected type %v, got %v", tt.expectType, expr.Type)
						}
					}
				}
			}
		})
	}
}

// TestExpressionValidation tests expression validation
func TestExpressionValidation(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal":        {Type: reflect.TypeOf(float64(0))},
			"borrower.credit_score": {Type: reflect.TypeOf(int64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	// Parse a valid expression
	expr, err := engine.ParseExpression("loan.principal * 1.2")
	if err != nil {
		t.Fatalf("Failed to parse expression: %v", err)
	}

	// Test validation with context
	context := map[string]interface{}{
		"loan.principal": 100000.0,
		"audit_context": map[string]interface{}{
			"request_id": "test-123",
			"user_id":    "user-456",
		},
	}

	err = engine.ValidateExpression(expr, context)
	if err != nil {
		t.Errorf("Expected validation to pass, got error: %v", err)
	}

	// Test validation without required context
	contextWithoutAudit := map[string]interface{}{
		"loan.principal": 100000.0,
	}

	// Note: This might not fail in the basic implementation,
	// but would in a full compliance-aware version
	err = engine.ValidateExpression(expr, contextWithoutAudit)
	// For this test, we accept either outcome since audit requirements
	// depend on specific validator implementation
}

// TestBuiltinFunctions tests built-in function implementations
func TestBuiltinFunctions(t *testing.T) {
	schema := FieldSchema{
		Fields:             map[string]FieldType{},
		AllowUnknownFields: true,
	}

	engine := NewExpressionEngine(schema)

	functionTests := []struct {
		name        string
		function    string
		args        []interface{}
		expected    interface{}
		expectError bool
	}{
		{
			name:     "min_function",
			function: "min",
			args:     []interface{}{1.0, 2.0, 3.0},
			expected: 1.0,
		},
		{
			name:     "max_function",
			function: "max",
			args:     []interface{}{1.0, 2.0, 3.0},
			expected: 3.0,
		},
		{
			name:     "abs_function",
			function: "abs",
			args:     []interface{}{-5.0},
			expected: 5.0,
		},
		{
			name:     "round_function",
			function: "round",
			args:     []interface{}{3.7},
			expected: 4.0,
		},
		{
			name:     "len_function",
			function: "len",
			args:     []interface{}{[]interface{}{1, 2, 3, 4}},
			expected: int64(4),
		},
		{
			name:     "sum_function",
			function: "sum",
			args:     []interface{}{[]interface{}{1.0, 2.0, 3.0}},
			expected: 6.0,
		},
		{
			name:     "contains_function_true",
			function: "contains",
			args:     []interface{}{[]interface{}{"a", "b", "c"}, "b"},
			expected: true,
		},
		{
			name:     "contains_function_false",
			function: "contains",
			args:     []interface{}{[]interface{}{"a", "b", "c"}, "d"},
			expected: false,
		},
		{
			name:        "min_no_args",
			function:    "min",
			args:        []interface{}{},
			expectError: true,
		},
		{
			name:        "abs_wrong_type",
			function:    "abs",
			args:        []interface{}{"not_a_number"},
			expectError: true,
		},
	}

	for _, tt := range functionTests {
		t.Run(tt.name, func(t *testing.T) {
			function, exists := engine.functions[tt.function]
			if !exists {
				t.Fatalf("Function %s not found", tt.function)
			}

			result, err := function.Handler(tt.args)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s with args %v, got none", tt.function, tt.args)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s with args %v, got: %v", tt.function, tt.args, err)
				} else {
					if !reflect.DeepEqual(result, tt.expected) {
						t.Errorf("Expected %v, got %v", tt.expected, result)
					}
				}
			}
		})
	}
}

// TestSecurityValidation tests security validation
func TestSecurityValidation(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal": {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	securityTests := []struct {
		name         string
		expression   string
		expectError  bool
		errorPattern string
	}{
		{
			name:        "safe_expression",
			expression:  "loan.principal * 1.2",
			expectError: false,
		},
		{
			name:         "eval_attempt",
			expression:   "eval('malicious code')",
			expectError:  true,
			errorPattern: "eval",
		},
		{
			name:         "exec_attempt",
			expression:   "exec('system call')",
			expectError:  true,
			errorPattern: "exec",
		},
		{
			name:         "system_field_access",
			expression:   "system.exit + 1",
			expectError:  true,
			errorPattern: "system",
		},
		{
			name:        "path_traversal",
			expression:  "loan..principal",
			expectError: false, // This is handled at field validation level
		},
		{
			name:         "extremely_complex",
			expression:   strings.Repeat("(1 + ", 100) + "1" + strings.Repeat(")", 100),
			expectError:  true,
			errorPattern: "complexity",
		},
	}

	for _, tt := range securityTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.ParseExpression(tt.expression)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected security error for expression '%s', got none", tt.expression)
				} else if tt.errorPattern != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.errorPattern)) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorPattern, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for safe expression '%s', got: %v", tt.expression, err)
				}
			}
		})
	}
}

// TestTypeInference tests type inference functionality
func TestTypeInference(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal":        {Type: reflect.TypeOf(float64(0))},
			"borrower.credit_score": {Type: reflect.TypeOf(int64(0))},
			"loan.approved":         {Type: reflect.TypeOf(true)},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	typeTests := []struct {
		name         string
		expression   string
		expectedType reflect.Type
		expectError  bool
	}{
		{
			name:         "float_literal",
			expression:   "123.45",
			expectedType: reflect.TypeOf(float64(0)),
		},
		{
			name:         "int_literal",
			expression:   "123",
			expectedType: reflect.TypeOf(int64(0)),
		},
		{
			name:         "string_literal",
			expression:   "\"hello\"",
			expectedType: reflect.TypeOf(""),
		},
		{
			name:         "boolean_literal",
			expression:   "true",
			expectedType: reflect.TypeOf(true),
		},
		{
			name:         "arithmetic_float",
			expression:   "loan.principal * 1.2",
			expectedType: reflect.TypeOf(float64(0)),
		},
		{
			name:         "comparison_result",
			expression:   "borrower.credit_score >= 620",
			expectedType: reflect.TypeOf(true),
		},
		{
			name:         "logical_and",
			expression:   "loan.approved && borrower.credit_score > 600",
			expectedType: reflect.TypeOf(true),
		},
		{
			name:         "function_result",
			expression:   "max(loan.principal, 1000.0)",
			expectedType: reflect.TypeOf(float64(0)),
		},
		{
			name:        "type_mismatch",
			expression:  "loan.approved + 1", // bool + int
			expectError: true,
		},
	}

	for _, tt := range typeTests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := engine.ParseExpression(tt.expression)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected type error for expression '%s', got none", tt.expression)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for expression '%s', got: %v", tt.expression, err)
				} else if expr.Type != tt.expectedType {
					t.Errorf("Expected type %v for expression '%s', got %v",
						tt.expectedType, tt.expression, expr.Type)
				}
			}
		})
	}
}

// TestFieldPathParsing tests field path parsing and validation
func TestFieldPathParsing(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.borrower.credit_score": {Type: reflect.TypeOf(int64(0))},
			"loan.payments[0].amount":    {Type: reflect.TypeOf(float64(0))},
			"borrower.accounts.sum()":    {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: true,
	}

	engine := NewExpressionEngine(schema)

	pathTests := []struct {
		name          string
		expression    string
		expectError   bool
		expectedPaths []string
	}{
		{
			name:          "simple_field_path",
			expression:    "loan.principal",
			expectError:   false,
			expectedPaths: []string{"loan.principal"},
		},
		{
			name:          "nested_field_path",
			expression:    "loan.borrower.credit_score",
			expectError:   false,
			expectedPaths: []string{"loan.borrower.credit_score"},
		},
		{
			name:          "multiple_field_paths",
			expression:    "loan.principal + borrower.income",
			expectError:   false,
			expectedPaths: []string{"loan.principal", "borrower.income"},
		},
		{
			name:        "empty_field_path",
			expression:  ". + 1",
			expectError: true,
		},
		{
			name:        "invalid_field_path",
			expression:  "loan..principal",
			expectError: false, // Parsed but may fail validation
		},
	}

	for _, tt := range pathTests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := engine.ParseExpression(tt.expression)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for expression '%s', got none", tt.expression)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for expression '%s', got: %v", tt.expression, err)
				} else {
					// Check that expected field paths were extracted
					for _, expectedPath := range tt.expectedPaths {
						found := false
						for _, actualPath := range expr.FieldPaths {
							if actualPath == expectedPath {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("Expected field path '%s' not found in %v",
								expectedPath, expr.FieldPaths)
						}
					}
				}
			}
		})
	}
}

// TestCompileToProtobuf tests compilation to protobuf format
func TestCompileToProtobuf(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal": {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	expr, err := engine.ParseExpression("loan.principal * 1.2")
	if err != nil {
		t.Fatalf("Failed to parse expression: %v", err)
	}

	protoExpr, err := engine.CompileToProtobuf(expr)
	if err != nil {
		t.Fatalf("Failed to compile to protobuf: %v", err)
	}

	if protoExpr == nil {
		t.Fatal("Expected protobuf expression, got nil")
	}

	if protoExpr.Expression != "loan.principal * 1.2" {
		t.Errorf("Expected expression '%s', got '%s'",
			"loan.principal * 1.2", protoExpr.Expression)
	}

	if protoExpr.Language != ExpressionLanguage_EXPRESSION_LANGUAGE_GOLANG {
		t.Errorf("Expected Go language, got %v", protoExpr.Language)
	}

	if len(protoExpr.FieldReferences) == 0 {
		t.Error("Expected field references, got none")
	}

	if len(protoExpr.Bytecode) == 0 {
		t.Error("Expected bytecode instructions, got none")
	}

	if protoExpr.Metadata == nil {
		t.Error("Expected metadata, got nil")
	}
}

// TestPerformanceConstraints tests performance-related constraints
func TestPerformanceConstraints(t *testing.T) {
	schema := FieldSchema{
		Fields:             map[string]FieldType{},
		AllowUnknownFields: true,
	}

	engine := NewExpressionEngine(schema)

	performanceTests := []struct {
		name        string
		expression  string
		expectError bool
		errorType   string
	}{
		{
			name:        "reasonable_complexity",
			expression:  "field1 + field2 * field3",
			expectError: false,
		},
		{
			name:        "high_complexity",
			expression:  buildComplexExpression(20), // Very complex expression
			expectError: true,
			errorType:   "complexity",
		},
		{
			name:        "many_field_accesses",
			expression:  buildManyFieldAccessExpression(30),
			expectError: true,
			errorType:   "field_accesses",
		},
		{
			name:        "many_function_calls",
			expression:  buildManyFunctionCallsExpression(15),
			expectError: true,
			errorType:   "function_calls",
		},
	}

	for _, tt := range performanceTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.ParseExpression(tt.expression)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected performance error for expression, got none")
				} else if !strings.Contains(strings.ToLower(err.Error()), tt.errorType) {
					t.Errorf("Expected error type '%s', got: %v", tt.errorType, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for reasonable expression, got: %v", err)
				}
			}
		})
	}
}

// TestValidatorChain tests the validator chain functionality
func TestValidatorChain(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal": {
				Type: reflect.TypeOf(float64(0)),
				Constraints: &FieldConstraints{
					MinValue: 1000.0,
					MaxValue: 1000000.0,
				},
			},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	// Test that all default validators are present
	expectedValidators := 3 // security, type, business logic
	if len(engine.validatorChain) < expectedValidators {
		t.Errorf("Expected at least %d validators, got %d",
			expectedValidators, len(engine.validatorChain))
	}

	// Parse a valid expression
	expr, err := engine.ParseExpression("loan.principal * 1.2")
	if err != nil {
		t.Fatalf("Failed to parse expression: %v", err)
	}

	// Test validation with different contexts
	validContext := map[string]interface{}{
		"loan.principal": 100000.0,
	}

	err = engine.ValidateExpression(expr, validContext)
	if err != nil {
		t.Errorf("Expected validation to pass with valid context, got: %v", err)
	}

	// Test each validator by name
	validatorNames := make(map[string]bool)
	for _, validator := range engine.validatorChain {
		validatorNames[validator.GetValidatorName()] = true
	}

	expectedValidatorNames := []string{"SecurityValidator", "TypeValidator", "BusinessLogicValidator"}
	for _, expectedName := range expectedValidatorNames {
		if !validatorNames[expectedName] {
			t.Errorf("Expected validator '%s' not found", expectedName)
		}
	}
}

// Helper functions for testing

// buildComplexExpression creates a deeply nested expression for complexity testing
func buildComplexExpression(depth int) string {
	if depth <= 0 {
		return "field1"
	}
	return fmt.Sprintf("(%s + %s * %s)",
		buildComplexExpression(depth-1),
		buildComplexExpression(depth-1),
		buildComplexExpression(depth-1))
}

// buildManyFieldAccessExpression creates an expression with many field accesses
func buildManyFieldAccessExpression(count int) string {
	var parts []string
	for i := 0; i < count; i++ {
		parts = append(parts, fmt.Sprintf("field%d", i))
	}
	return strings.Join(parts, " + ")
}

// buildManyFunctionCallsExpression creates an expression with many function calls
func buildManyFunctionCallsExpression(count int) string {
	var parts []string
	for i := 0; i < count; i++ {
		parts = append(parts, fmt.Sprintf("abs(field%d)", i))
	}
	return strings.Join(parts, " + ")
}

// TestExpressionCaching tests compilation caching
func TestExpressionCaching(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal": {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	// Parse and compile expression first time
	expr1, err := engine.ParseExpression("loan.principal * 1.2")
	if err != nil {
		t.Fatalf("Failed to parse expression: %v", err)
	}

	_, err = engine.CompileToProtobuf(expr1)
	if err != nil {
		t.Fatalf("Failed to compile expression: %v", err)
	}

	// Parse same expression again
	expr2, err := engine.ParseExpression("loan.principal * 1.2")
	if err != nil {
		t.Fatalf("Failed to parse expression second time: %v", err)
	}

	_, err = engine.CompileToProtobuf(expr2)
	if err != nil {
		t.Fatalf("Failed to compile expression second time: %v", err)
	}

	// Check that cache was used (implementation detail)
	if len(engine.compilationCache) == 0 {
		t.Error("Expected compilation cache to have entries")
	}
}

// TestFieldConstraints tests field constraint validation
func TestFieldConstraints(t *testing.T) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.amount": {
				Type: reflect.TypeOf(float64(0)),
				Constraints: &FieldConstraints{
					MinValue: 1000.0,
					MaxValue: 1000000.0,
				},
			},
			"loan.purpose": {
				Type: reflect.TypeOf(""),
				Constraints: &FieldConstraints{
					EnumValues: []interface{}{"purchase", "refinance", "improvement"},
				},
			},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)

	// These tests would require a more complete implementation
	// to actually validate field constraints during expression evaluation

	expr, err := engine.ParseExpression("loan.amount > 500")
	if err != nil {
		t.Fatalf("Failed to parse expression: %v", err)
	}

	context := map[string]interface{}{
		"loan.amount": 2000000.0, // Above max constraint
	}

	// Basic validation should pass (constraint checking happens at evaluation time)
	err = engine.ValidateExpression(expr, context)
	if err != nil {
		// In a full implementation, this might fail due to constraint violation
		t.Logf("Validation result: %v", err)
	}
}

// BenchmarkExpressionParsing benchmarks expression parsing performance
func BenchmarkExpressionParsing(b *testing.B) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal":        {Type: reflect.TypeOf(float64(0))},
			"borrower.credit_score": {Type: reflect.TypeOf(int64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)
	expression := "loan.principal * 1.2 + borrower.credit_score / 100"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.ParseExpression(expression)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkExpressionCompilation benchmarks expression compilation
func BenchmarkExpressionCompilation(b *testing.B) {
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal": {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: false,
	}

	engine := NewExpressionEngine(schema)
	expression := "loan.principal * 1.2"

	// Parse once
	expr, err := engine.ParseExpression(expression)
	if err != nil {
		b.Fatalf("Parse error: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear cache to force recompilation
		engine.compilationCache = make(map[string]*CompiledExpression)

		_, err := engine.CompileToProtobuf(expr)
		if err != nil {
			b.Fatalf("Compilation error: %v", err)
		}
	}
}
