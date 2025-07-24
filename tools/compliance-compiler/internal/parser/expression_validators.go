package parser

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// SecurityValidator validates expressions against security constraints
type securityValidator struct{}

func (v *securityValidator) Validate(expr *Expression, context map[string]interface{}) error {
	// Check for dangerous patterns in the raw expression
	dangerousPatterns := []string{
		`\beval\b`,          // eval functions
		`\bexec\b`,          // exec functions
		`\bsystem\b`,        // system calls
		`\bfile\b`,          // file operations
		`\bnetwork\b`,       // network operations
		`\bhttp\b`,          // HTTP requests
		`\bsql\b`,           // SQL injection attempts
		`\bscript\b`,        // Script execution
		`\bjavascript\b`,    // JavaScript execution
		`\bon[a-zA-Z]+\s*=`, // Event handlers
		`<script`,           // Script tags
		`document\.`,        // Document manipulation
		`window\.`,          // Window object access
		`global\.`,          // Global object access
		`process\.`,         // Process object access
		`require\s*\(`,      // Module loading
		`import\s+`,         // Import statements
		`__[a-zA-Z_]+__`,    // Dunder methods
	}

	for _, pattern := range dangerousPatterns {
		matched, err := regexp.MatchString(pattern, expr.Raw)
		if err != nil {
			continue
		}
		if matched {
			return fmt.Errorf("expression contains potentially dangerous pattern: %s", pattern)
		}
	}

	// Validate complexity limits
	if expr.Metadata.Complexity > 50 {
		return fmt.Errorf("expression complexity (%d) exceeds security limit (50)", expr.Metadata.Complexity)
	}

	// Check for suspicious field paths
	for _, fieldPath := range expr.FieldPaths {
		if err := v.validateFieldPathSecurity(fieldPath); err != nil {
			return fmt.Errorf("security violation in field path '%s': %w", fieldPath, err)
		}
	}

	// Check for suspicious function calls
	for _, functionName := range expr.Functions {
		if err := v.validateFunctionSecurity(functionName); err != nil {
			return fmt.Errorf("security violation with function '%s': %w", functionName, err)
		}
	}

	return nil
}

func (v *securityValidator) validateFieldPathSecurity(fieldPath string) error {
	// Check for path traversal attempts
	if strings.Contains(fieldPath, "..") {
		return fmt.Errorf("path traversal detected")
	}

	// Check for system field access attempts
	systemFields := []string{
		"system", "os", "env", "process", "runtime",
		"__proto__", "__constructor__", "constructor",
		"prototype", "__defineGetter__", "__defineSetter__",
	}

	for _, systemField := range systemFields {
		if strings.Contains(strings.ToLower(fieldPath), systemField) {
			return fmt.Errorf("attempted access to system field")
		}
	}

	// Check path length (prevent DoS via very long paths)
	if len(fieldPath) > 200 {
		return fmt.Errorf("field path too long (max 200 characters)")
	}

	return nil
}

func (v *securityValidator) validateFunctionSecurity(functionName string) error {
	// Whitelist of allowed functions - anything else is blocked
	allowedFunctions := map[string]bool{
		"min":      true,
		"max":      true,
		"abs":      true,
		"round":    true,
		"len":      true,
		"sum":      true,
		"contains": true,
		"avg":      true,
		"count":    true,
		"floor":    true,
		"ceil":     true,
		"sqrt":     true,
		"pow":      true,
	}

	if !allowedFunctions[functionName] {
		return fmt.Errorf("function '%s' is not in security whitelist", functionName)
	}

	return nil
}

func (v *securityValidator) GetValidatorName() string {
	return "SecurityValidator"
}

// TypeValidator validates type safety of expressions
type typeValidator struct{}

func (v *typeValidator) Validate(expr *Expression, context map[string]interface{}) error {
	// Validate that all field paths have known types
	for _, fieldPath := range expr.FieldPaths {
		if err := v.validateFieldType(fieldPath, context); err != nil {
			return fmt.Errorf("type validation failed for field '%s': %w", fieldPath, err)
		}
	}

	// Validate function parameter types (basic check)
	for _, functionName := range expr.Functions {
		if err := v.validateFunctionTypes(functionName, expr, context); err != nil {
			return fmt.Errorf("type validation failed for function '%s': %w", functionName, err)
		}
	}

	// Ensure expression has a valid result type
	if expr.Type == nil {
		return fmt.Errorf("expression has no result type")
	}

	// Validate type compatibility in the expression
	if err := v.validateTypeCompatibility(expr); err != nil {
		return fmt.Errorf("type compatibility error: %w", err)
	}

	return nil
}

func (v *typeValidator) validateFieldType(fieldPath string, context map[string]interface{}) error {
	// Split field path to validate each segment
	segments := strings.Split(fieldPath, ".")

	// Basic validation - ensure field path is reasonable
	if len(segments) > 10 {
		return fmt.Errorf("field path too deeply nested (max 10 levels)")
	}

	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("empty field path segment")
		}

		// Check for valid identifier format
		if !isValidIdentifier(segment) {
			return fmt.Errorf("invalid field name: %s", segment)
		}
	}

	return nil
}

func (v *typeValidator) validateFunctionTypes(functionName string, expr *Expression, context map[string]interface{}) error {
	// This is a basic validation - in a full implementation,
	// you would analyze the AST to validate parameter types

	switch functionName {
	case "min", "max", "sum", "avg":
		// These functions require numeric arguments
		return nil // Would need AST analysis for full validation

	case "len", "contains":
		// These functions work with arrays/collections
		return nil

	case "abs", "round", "floor", "ceil", "sqrt":
		// These require single numeric argument
		return nil

	default:
		return fmt.Errorf("unknown function: %s", functionName)
	}
}

func (v *typeValidator) validateTypeCompatibility(expr *Expression) error {
	// This would require full AST analysis in a complete implementation
	// For now, we do basic validation

	// Ensure result type is one of the allowed types
	allowedTypes := []reflect.Type{
		reflect.TypeOf(true),        // bool
		reflect.TypeOf(int64(0)),    // int64
		reflect.TypeOf(float64(0)),  // float64
		reflect.TypeOf(""),          // string
		reflect.TypeOf(time.Time{}), // time
	}

	typeAllowed := false
	for _, allowedType := range allowedTypes {
		if expr.Type == allowedType {
			typeAllowed = true
			break
		}
	}

	if !typeAllowed {
		return fmt.Errorf("result type %s is not allowed", expr.Type)
	}

	return nil
}

func (v *typeValidator) GetValidatorName() string {
	return "TypeValidator"
}

// BusinessLogicValidator validates business logic constraints
type businessLogicValidator struct{}

func (v *businessLogicValidator) Validate(expr *Expression, context map[string]interface{}) error {
	// Validate business-specific constraints

	// Check for reasonable field access patterns
	for _, fieldPath := range expr.FieldPaths {
		if err := v.validateBusinessLogic(fieldPath, context); err != nil {
			return fmt.Errorf("business logic validation failed for '%s': %w", fieldPath, err)
		}
	}

	// Validate that expressions make business sense
	if err := v.validateExpressionLogic(expr); err != nil {
		return fmt.Errorf("expression logic validation failed: %w", err)
	}

	// Check for potential infinite loops or recursive patterns
	if err := v.validateRecursionSafety(expr); err != nil {
		return fmt.Errorf("recursion safety validation failed: %w", err)
	}

	return nil
}

func (v *businessLogicValidator) validateBusinessLogic(fieldPath string, context map[string]interface{}) error {
	// Define business field categories and their constraints
	fieldCategories := map[string][]string{
		"financial": {
			"loan.principal", "loan.interest_rate", "loan.payment",
			"borrower.income", "borrower.debt", "collateral.value",
		},
		"personal": {
			"borrower.credit_score", "borrower.age", "borrower.employment",
			"borrower.address", "borrower.phone", "borrower.email",
		},
		"temporal": {
			"loan.origination_date", "loan.maturity_date", "application.date",
			"borrower.employment_start", "last_payment_date",
		},
	}

	// Validate field access patterns make business sense
	category := v.categorizeField(fieldPath, fieldCategories)

	switch category {
	case "financial":
		return v.validateFinancialField(fieldPath, context)
	case "personal":
		return v.validatePersonalField(fieldPath, context)
	case "temporal":
		return v.validateTemporalField(fieldPath, context)
	default:
		// Unknown fields are allowed if they follow naming conventions
		return v.validateUnknownField(fieldPath)
	}
}

func (v *businessLogicValidator) categorizeField(fieldPath string, categories map[string][]string) string {
	for category, fields := range categories {
		for _, field := range fields {
			if fieldPath == field || strings.HasPrefix(fieldPath, field+".") {
				return category
			}
		}
	}
	return "unknown"
}

func (v *businessLogicValidator) validateFinancialField(fieldPath string, context map[string]interface{}) error {
	// Financial fields should have reasonable constraints
	if strings.Contains(fieldPath, "amount") || strings.Contains(fieldPath, "principal") {
		// Amounts should be positive and reasonable
		if value, exists := context[fieldPath]; exists {
			if amount, ok := toFloat64(value); ok {
				if amount < 0 {
					return fmt.Errorf("financial amount cannot be negative")
				}
				if amount > 1e9 { // $1 billion limit
					return fmt.Errorf("financial amount exceeds reasonable limit")
				}
			}
		}
	}

	if strings.Contains(fieldPath, "rate") {
		// Interest rates should be reasonable percentages
		if value, exists := context[fieldPath]; exists {
			if rate, ok := toFloat64(value); ok {
				if rate < 0 || rate > 1 { // 0-100% range
					return fmt.Errorf("interest rate should be between 0 and 1 (0-100%%)")
				}
			}
		}
	}

	return nil
}

func (v *businessLogicValidator) validatePersonalField(fieldPath string, context map[string]interface{}) error {
	// Personal fields have different constraints
	if strings.Contains(fieldPath, "credit_score") {
		if value, exists := context[fieldPath]; exists {
			if score, ok := toFloat64(value); ok {
				if score < 300 || score > 850 {
					return fmt.Errorf("credit score should be between 300 and 850")
				}
			}
		}
	}

	if strings.Contains(fieldPath, "age") {
		if value, exists := context[fieldPath]; exists {
			if age, ok := toFloat64(value); ok {
				if age < 18 || age > 120 {
					return fmt.Errorf("age should be between 18 and 120")
				}
			}
		}
	}

	return nil
}

func (v *businessLogicValidator) validateTemporalField(fieldPath string, context map[string]interface{}) error {
	// Temporal fields should be valid dates/times
	if value, exists := context[fieldPath]; exists {
		if timeStr, ok := value.(string); ok {
			// Try to parse as various time formats
			formats := []string{
				time.RFC3339,
				"2006-01-02",
				"2006-01-02T15:04:05Z",
				"2006-01-02 15:04:05",
			}

			parsed := false
			for _, format := range formats {
				if _, err := time.Parse(format, timeStr); err == nil {
					parsed = true
					break
				}
			}

			if !parsed {
				return fmt.Errorf("temporal field has invalid date/time format")
			}
		}
	}

	return nil
}

func (v *businessLogicValidator) validateUnknownField(fieldPath string) error {
	// Unknown fields should follow naming conventions
	segments := strings.Split(fieldPath, ".")

	for _, segment := range segments {
		// Check naming convention (snake_case or camelCase)
		if !isValidFieldName(segment) {
			return fmt.Errorf("field name '%s' doesn't follow naming conventions", segment)
		}
	}

	return nil
}

func (v *businessLogicValidator) validateExpressionLogic(expr *Expression) error {
	// Check for common business logic issues

	// Prevent division by zero scenarios
	if strings.Contains(expr.Raw, "/") && !strings.Contains(expr.Raw, "/ 0") {
		// This is a simple check - full implementation would analyze AST
		// to detect potential division by zero with variable denominators
	}

	// Check for reasonable mathematical operations
	if strings.Contains(expr.Raw, "*") {
		// Multiplication should be reasonable (no obvious overflow scenarios)
		if strings.Count(expr.Raw, "*") > 3 {
			return fmt.Errorf("expression has excessive multiplication operations")
		}
	}

	// Check for exponentiation (not directly supported, but prevent patterns)
	if strings.Contains(expr.Raw, "**") || strings.Contains(expr.Raw, "^") {
		return fmt.Errorf("exponentiation not supported for security reasons")
	}

	return nil
}

func (v *businessLogicValidator) validateRecursionSafety(expr *Expression) error {
	// Check for potential recursion patterns
	fieldCount := make(map[string]int)

	for _, fieldPath := range expr.FieldPaths {
		fieldCount[fieldPath]++
		if fieldCount[fieldPath] > 3 {
			return fmt.Errorf("field '%s' accessed too many times (potential recursion)", fieldPath)
		}
	}

	// Check for self-referential patterns
	for _, fieldPath := range expr.FieldPaths {
		if strings.Contains(expr.Raw, fieldPath) && strings.Count(expr.Raw, fieldPath) > 2 {
			return fmt.Errorf("potential self-referential pattern detected with field '%s'", fieldPath)
		}
	}

	return nil
}

func (v *businessLogicValidator) GetValidatorName() string {
	return "BusinessLogicValidator"
}

// Utility functions for validation

// isValidIdentifier checks if a string is a valid identifier
func isValidIdentifier(name string) bool {
	if name == "" {
		return false
	}

	// Check first character (must be letter or underscore)
	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}

	// Check remaining characters (letter, digit, or underscore)
	for i := 1; i < len(name); i++ {
		char := name[i]
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}

	return true
}

// isValidFieldName checks if a field name follows naming conventions
func isValidFieldName(name string) bool {
	if !isValidIdentifier(name) {
		return false
	}

	// Check for snake_case pattern
	snakeCasePattern := regexp.MustCompile(`^[a-z][a-z0-9_]*[a-z0-9]$|^[a-z]$`)
	if snakeCasePattern.MatchString(name) {
		return true
	}

	// Check for camelCase pattern
	camelCasePattern := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	if camelCasePattern.MatchString(name) {
		return true
	}

	return false
}

// PerformanceValidator validates expressions for performance concerns
type performanceValidator struct {
	maxComplexity       int
	maxFieldAccesses    int
	maxFunctionCalls    int
	maxExpressionLength int
}

func newPerformanceValidator() *performanceValidator {
	return &performanceValidator{
		maxComplexity:       100,
		maxFieldAccesses:    50,
		maxFunctionCalls:    20,
		maxExpressionLength: 1000,
	}
}

func (v *performanceValidator) Validate(expr *Expression, context map[string]interface{}) error {
	// Check expression length
	if len(expr.Raw) > v.maxExpressionLength {
		return fmt.Errorf("expression too long (%d chars, max %d)",
			len(expr.Raw), v.maxExpressionLength)
	}

	// Check complexity
	if expr.Metadata.Complexity > v.maxComplexity {
		return fmt.Errorf("expression complexity (%d) exceeds limit (%d)",
			expr.Metadata.Complexity, v.maxComplexity)
	}

	// Check field access count
	if expr.Metadata.FieldAccesses > v.maxFieldAccesses {
		return fmt.Errorf("too many field accesses (%d, max %d)",
			expr.Metadata.FieldAccesses, v.maxFieldAccesses)
	}

	// Check function call count
	if expr.Metadata.FunctionCalls > v.maxFunctionCalls {
		return fmt.Errorf("too many function calls (%d, max %d)",
			expr.Metadata.FunctionCalls, v.maxFunctionCalls)
	}

	// Check for expensive operations
	if err := v.validateExpensiveOperations(expr); err != nil {
		return fmt.Errorf("expensive operation detected: %w", err)
	}

	return nil
}

func (v *performanceValidator) validateExpensiveOperations(expr *Expression) error {
	// Check for operations that might be expensive
	expensivePatterns := []string{
		`\bpow\b`,                 // Exponentiation
		`\bsqrt\b`,                // Square root
		`\blog\b`,                 // Logarithm
		`\bsin\b|\bcos\b|\btan\b`, // Trigonometric functions
	}

	for _, pattern := range expensivePatterns {
		matched, err := regexp.MatchString(pattern, expr.Raw)
		if err != nil {
			continue
		}
		if matched {
			// Allow but warn about expensive operations
			// In production, you might want to limit these
			continue
		}
	}

	// Check for nested function calls (can be expensive)
	if v.countNestedFunctionCalls(expr.Raw) > 3 {
		return fmt.Errorf("too many nested function calls (performance concern)")
	}

	return nil
}

func (v *performanceValidator) countNestedFunctionCalls(expr string) int {
	// Simple heuristic to count nesting depth of function calls
	maxDepth := 0
	currentDepth := 0

	for _, char := range expr {
		if char == '(' {
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		} else if char == ')' {
			currentDepth--
		}
	}

	return maxDepth
}

func (v *performanceValidator) GetValidatorName() string {
	return "PerformanceValidator"
}

// ComplianceValidator validates expressions against compliance requirements
type complianceValidator struct {
	allowedFieldPatterns []string
	requiredFields       []string
	auditableFields      []string
}

func newComplianceValidator() *complianceValidator {
	return &complianceValidator{
		allowedFieldPatterns: []string{
			`^loan\..*`,        // Loan-related fields
			`^borrower\..*`,    // Borrower-related fields
			`^collateral\..*`,  // Collateral-related fields
			`^application\..*`, // Application-related fields
			`^compliance\..*`,  // Compliance-related fields
		},
		requiredFields: []string{
			// Fields that must be present in certain contexts
		},
		auditableFields: []string{
			"loan.principal", "loan.interest_rate", "borrower.credit_score",
			"borrower.income", "collateral.value",
		},
	}
}

func (v *complianceValidator) Validate(expr *Expression, context map[string]interface{}) error {
	// Check that all field accesses are allowed
	for _, fieldPath := range expr.FieldPaths {
		if err := v.validateFieldAccess(fieldPath); err != nil {
			return fmt.Errorf("compliance violation for field '%s': %w", fieldPath, err)
		}
	}

	// Check for required audit trail fields
	if err := v.validateAuditRequirements(expr, context); err != nil {
		return fmt.Errorf("audit requirements not met: %w", err)
	}

	// Validate that sensitive calculations are properly handled
	if err := v.validateSensitiveCalculations(expr); err != nil {
		return fmt.Errorf("sensitive calculation validation failed: %w", err)
	}

	return nil
}

func (v *complianceValidator) validateFieldAccess(fieldPath string) error {
	// Check against allowed patterns
	allowed := false
	for _, pattern := range v.allowedFieldPatterns {
		matched, err := regexp.MatchString(pattern, fieldPath)
		if err != nil {
			continue
		}
		if matched {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("field access not allowed by compliance policy")
	}

	// Check for PII access (requires special handling)
	piiFields := []string{
		"ssn", "social_security", "tax_id", "passport", "drivers_license",
		"phone", "email", "address", "name", "date_of_birth",
	}

	for _, piiField := range piiFields {
		if strings.Contains(strings.ToLower(fieldPath), piiField) {
			return fmt.Errorf("direct PII access not allowed in expressions")
		}
	}

	return nil
}

func (v *complianceValidator) validateAuditRequirements(expr *Expression, context map[string]interface{}) error {
	// Check if expression accesses auditable fields
	accessesAuditableField := false
	for _, fieldPath := range expr.FieldPaths {
		for _, auditableField := range v.auditableFields {
			if fieldPath == auditableField || strings.HasPrefix(fieldPath, auditableField+".") {
				accessesAuditableField = true
				break
			}
		}
	}

	if accessesAuditableField {
		// Ensure audit context is provided
		if _, hasAuditInfo := context["audit_context"]; !hasAuditInfo {
			return fmt.Errorf("audit context required for expressions accessing auditable fields")
		}
	}

	return nil
}

func (v *complianceValidator) validateSensitiveCalculations(expr *Expression) error {
	// Check for calculations that might have compliance implications
	sensitivePatterns := []string{
		`debt.*ratio`,     // Debt-to-income calculations
		`credit.*score`,   // Credit score calculations
		`interest.*rate`,  // Interest rate calculations
		`payment.*amount`, // Payment calculations
	}

	for _, pattern := range sensitivePatterns {
		matched, err := regexp.MatchString(pattern, strings.ToLower(expr.Raw))
		if err != nil {
			continue
		}
		if matched {
			// These calculations require additional validation
			// In a full implementation, you'd have specific rules for each type
			continue
		}
	}

	return nil
}

func (v *complianceValidator) GetValidatorName() string {
	return "ComplianceValidator"
}
