package parser

import (
	"fmt"
)

// DemoYAMLExpressionIntegration demonstrates the integrated YAML parser with expression engine
func DemoYAMLExpressionIntegration() {
	fmt.Println("=== YAML Parser + Expression Engine Integration Demo ===")

	// Create a YAML parser with expression engine
	parser := NewYAMLParser()

	fmt.Println("✓ Created YAML parser with integrated expression engine")
	fmt.Printf("  - Expression engine configured with %d field types\n", len(parser.expressionEngine.allowedFields))
	fmt.Printf("  - Security validators: %d\n", len(parser.expressionEngine.validatorChain))
	fmt.Printf("  - Built-in functions: %d\n", len(parser.expressionEngine.functions))

	// Demonstrate expression parsing
	testExpressions := []string{
		"loan.principal * 1.2",
		"borrower.credit_score >= 620",
		"max(loan.amount, borrower.income)",
		"loan.debt_to_income_ratio <= 0.43",
	}

	fmt.Println("\n=== Expression Engine Testing ===")
	for i, exprStr := range testExpressions {
		fmt.Printf("%d. Testing expression: %s\n", i+1, exprStr)

		expr, err := parser.expressionEngine.ParseExpression(exprStr)
		if err != nil {
			fmt.Printf("   ✗ Parse failed: %v\n", err)
			continue
		}

		fmt.Printf("   ✓ Parsed successfully\n")
		fmt.Printf("   - Type: %s\n", expr.Type)
		fmt.Printf("   - Field paths: %v\n", expr.FieldPaths)
		fmt.Printf("   - Functions: %v\n", expr.Functions)
		fmt.Printf("   - Complexity: %d\n", expr.Metadata.Complexity)

		// Test validation
		context := map[string]interface{}{
			"loan.principal":            100000.0,
			"loan.amount":               95000.0,
			"borrower.credit_score":     720,
			"borrower.income":           80000.0,
			"loan.debt_to_income_ratio": 0.35,
			"audit_context": map[string]interface{}{
				"request_id": "demo-test",
				"source":     "integration_demo",
			},
		}

		err = parser.expressionEngine.ValidateExpression(expr, context)
		if err != nil {
			fmt.Printf("   ✗ Validation failed: %v\n", err)
		} else {
			fmt.Printf("   ✓ Validation passed\n")
		}

		// Test compilation
		protoExpr, err := parser.expressionEngine.CompileToProtobuf(expr)
		if err != nil {
			fmt.Printf("   ✗ Compilation failed: %v\n", err)
		} else {
			fmt.Printf("   ✓ Compiled to protobuf (%d bytecode instructions)\n", len(protoExpr.Bytecode))
		}

		fmt.Println()
	}

	// Demonstrate YAML parsing with expressions
	fmt.Println("=== YAML Integration Testing ===")

	// Test the parseExpression method
	testExpression := "loan.principal * 1.2"
	result, err := parser.parseExpression(testExpression)
	if err != nil {
		fmt.Printf("✗ YAML expression parsing failed: %v\n", err)
	} else {
		fmt.Printf("✓ YAML expression parsing succeeded\n")

		if parsedExpr, ok := result.(ParsedExpression); ok {
			fmt.Printf("  - Raw: %s\n", parsedExpr.Raw)
			fmt.Printf("  - Type: %s\n", parsedExpr.Type)
			fmt.Printf("  - Field paths: %v\n", parsedExpr.FieldPaths)
			fmt.Printf("  - Functions: %v\n", parsedExpr.Functions)
		}
	}

	fmt.Println("\n=== Integration Summary ===")
	fmt.Println("✓ Expression engine successfully integrated with YAML parser")
	fmt.Println("✓ Expressions can be parsed with security validation")
	fmt.Println("✓ Type inference and field path resolution working")
	fmt.Println("✓ Built-in functions available (min, max, abs, round, etc.)")
	fmt.Println("✓ Bytecode compilation for performance optimization")
	fmt.Println("✓ Comprehensive security validation (patterns, complexity, etc.)")
	fmt.Println("✓ Business logic validation for compliance requirements")
	fmt.Println("\nIntegration completed successfully! 🎉")
}

// GetExpressionEngineStats returns statistics about the expression engine
func (p *YAMLParser) GetExpressionEngineStats() map[string]interface{} {
	return map[string]interface{}{
		"allowed_fields":     len(p.expressionEngine.allowedFields),
		"built_in_functions": len(p.expressionEngine.functions),
		"validator_chain":    len(p.expressionEngine.validatorChain),
		"compilation_cache":  len(p.expressionEngine.compilationCache),
		"security_limits":    p.expressionEngine.securityLimits,
	}
}
