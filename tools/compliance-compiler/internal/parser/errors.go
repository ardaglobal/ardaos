package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseError represents a parsing error with detailed location information
type ParseError struct {
	Type       ErrorType
	Field      string
	Message    string
	Line       int
	Column     int
	Context    string
	Suggestion string
	Cause      error
}

// ErrorType represents the type of parsing error
type ErrorType string

const (
	ErrorTypeYAMLSyntax         ErrorType = "yaml_syntax"
	ErrorTypeValidation         ErrorType = "validation"
	ErrorTypePredicateStructure ErrorType = "predicate_structure"
	ErrorTypeFieldPath          ErrorType = "field_path"
	ErrorTypeExpression         ErrorType = "expression"
	ErrorTypeCircularReference  ErrorType = "circular_reference"
	ErrorTypeTypeConversion     ErrorType = "type_conversion"
	ErrorTypeUnsupportedFeature ErrorType = "unsupported_feature"
	ErrorTypeSchemaViolation    ErrorType = "schema_violation"
	ErrorTypePerformanceWarning ErrorType = "performance_warning"
)

func (e *ParseError) Error() string {
	var parts []string

	// Add location information
	if e.Line > 0 && e.Column > 0 {
		parts = append(parts, fmt.Sprintf("line %d, column %d", e.Line, e.Column))
	} else if e.Line > 0 {
		parts = append(parts, fmt.Sprintf("line %d", e.Line))
	}

	// Add error type and field
	if e.Field != "" {
		parts = append(parts, fmt.Sprintf("[%s] %s", e.Type, e.Field))
	} else {
		parts = append(parts, fmt.Sprintf("[%s]", e.Type))
	}

	// Add main message
	parts = append(parts, e.Message)

	// Add context if available
	if e.Context != "" {
		parts = append(parts, fmt.Sprintf("Context: %s", e.Context))
	}

	// Add suggestion if available
	if e.Suggestion != "" {
		parts = append(parts, fmt.Sprintf("Suggestion: %s", e.Suggestion))
	}

	// Add underlying cause if available
	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("Caused by: %v", e.Cause))
	}

	return strings.Join(parts, " | ")
}

// NewParseError creates a new parse error
func NewParseError(errorType ErrorType, field, message string) *ParseError {
	return &ParseError{
		Type:    errorType,
		Field:   field,
		Message: message,
	}
}

// WithLocation adds location information to the error
func (e *ParseError) WithLocation(line, column int) *ParseError {
	e.Line = line
	e.Column = column
	return e
}

// WithContext adds context information to the error
func (e *ParseError) WithContext(context string) *ParseError {
	e.Context = context
	return e
}

// WithSuggestion adds a suggestion to fix the error
func (e *ParseError) WithSuggestion(suggestion string) *ParseError {
	e.Suggestion = suggestion
	return e
}

// WithCause adds the underlying cause of the error
func (e *ParseError) WithCause(cause error) *ParseError {
	e.Cause = cause
	return e
}

// ParseErrorCollection represents a collection of parsing errors
type ParseErrorCollection struct {
	Errors   []*ParseError
	Warnings []*ParseError
}

// NewParseErrorCollection creates a new error collection
func NewParseErrorCollection() *ParseErrorCollection {
	return &ParseErrorCollection{
		Errors:   make([]*ParseError, 0),
		Warnings: make([]*ParseError, 0),
	}
}

// AddError adds an error to the collection
func (c *ParseErrorCollection) AddError(err *ParseError) {
	c.Errors = append(c.Errors, err)
}

// AddWarning adds a warning to the collection
func (c *ParseErrorCollection) AddWarning(warning *ParseError) {
	c.Warnings = append(c.Warnings, warning)
}

// HasErrors returns true if there are any errors
func (c *ParseErrorCollection) HasErrors() bool {
	return len(c.Errors) > 0
}

// HasWarnings returns true if there are any warnings
func (c *ParseErrorCollection) HasWarnings() bool {
	return len(c.Warnings) > 0
}

// Error implements the error interface
func (c *ParseErrorCollection) Error() string {
	if len(c.Errors) == 0 {
		return "no errors"
	}

	var parts []string
	for _, err := range c.Errors {
		parts = append(parts, err.Error())
	}

	return fmt.Sprintf("%d error(s):\n%s", len(c.Errors), strings.Join(parts, "\n"))
}

// CircularReferenceDetector detects circular references in predicate trees
type CircularReferenceDetector struct {
	visited   map[string]bool
	visiting  map[string]bool
	callStack []string
}

// NewCircularReferenceDetector creates a new circular reference detector
func NewCircularReferenceDetector() *CircularReferenceDetector {
	return &CircularReferenceDetector{
		visited:   make(map[string]bool),
		visiting:  make(map[string]bool),
		callStack: make([]string, 0),
	}
}

// CheckPredicate checks a predicate for circular references
func (d *CircularReferenceDetector) CheckPredicate(predicate *Predicate, context string) error {
	if predicate == nil {
		return nil
	}

	// Generate a unique identifier for this predicate context
	predicateID := d.generatePredicateID(predicate, context)

	// Check if we're already visiting this predicate (circular reference)
	if d.visiting[predicateID] {
		return NewParseError(
			ErrorTypeCircularReference,
			context,
			fmt.Sprintf("circular reference detected in predicate: %s", strings.Join(d.callStack, " -> ")),
		).WithSuggestion("Remove or restructure the circular reference in your predicate logic")
	}

	// Check if we've already processed this predicate
	if d.visited[predicateID] {
		return nil
	}

	// Mark as visiting and add to call stack
	d.visiting[predicateID] = true
	d.callStack = append(d.callStack, predicateID)

	// Check child predicates based on type
	var err error
	switch p := predicate.PredicateType.(type) {
	case *Predicate_Logical:
		err = d.checkLogicalPredicate(p.Logical, context)
	case *Predicate_Comparison:
		err = d.checkComparisonPredicate(p.Comparison, context)
	case *Predicate_Expression:
		err = d.checkExpressionPredicate(p.Expression, context)
		// Other predicate types don't typically have circular reference issues
	}

	// Remove from visiting and call stack
	delete(d.visiting, predicateID)
	if len(d.callStack) > 0 {
		d.callStack = d.callStack[:len(d.callStack)-1]
	}

	// Mark as visited
	d.visited[predicateID] = true

	return err
}

// checkLogicalPredicate checks logical predicates for circular references
func (d *CircularReferenceDetector) checkLogicalPredicate(logical *LogicalPredicate, context string) error {
	if logical == nil {
		return nil
	}

	for i, operand := range logical.Operands {
		operandContext := fmt.Sprintf("%s.operand[%d]", context, i)
		if err := d.CheckPredicate(operand, operandContext); err != nil {
			return err
		}
	}

	return nil
}

// checkComparisonPredicate checks comparison predicates for field path issues
func (d *CircularReferenceDetector) checkComparisonPredicate(comparison *ComparisonPredicate, context string) error {
	if comparison == nil || comparison.FieldPath == nil {
		return nil
	}

	// Check for self-referential field paths
	if err := d.checkFieldPathCircularity(comparison.FieldPath, context); err != nil {
		return err
	}

	return nil
}

// checkExpressionPredicate checks expression predicates for circular references
func (d *CircularReferenceDetector) checkExpressionPredicate(expression *ExpressionPredicate, context string) error {
	if expression == nil {
		return nil
	}

	// Check for self-referential expressions
	if err := d.checkExpressionCircularity(expression.Expression, context); err != nil {
		return err
	}

	return nil
}

// checkFieldPathCircularity checks field paths for circular references
func (d *CircularReferenceDetector) checkFieldPathCircularity(fieldPath *FieldPath, context string) error {
	if fieldPath == nil {
		return nil
	}

	// Simple check for obvious self-references
	if strings.Contains(fieldPath.RawPath, fieldPath.RawPath+".") {
		return NewParseError(
			ErrorTypeCircularReference,
			context,
			fmt.Sprintf("self-referential field path detected: %s", fieldPath.RawPath),
		).WithSuggestion("Ensure field paths don't reference themselves")
	}

	return nil
}

// checkExpressionCircularity checks expressions for circular references
func (d *CircularReferenceDetector) checkExpressionCircularity(expression string, context string) error {
	// Simple heuristic checks for obvious circular references in expressions
	// More sophisticated analysis would require actual expression parsing

	// Check for obvious self-references
	if strings.Count(expression, "self") > 1 {
		return NewParseError(
			ErrorTypeCircularReference,
			context,
			"potential circular reference in expression: multiple 'self' references",
		).WithSuggestion("Review expression for circular logic")
	}

	return nil
}

// generatePredicateID generates a unique identifier for a predicate
func (d *CircularReferenceDetector) generatePredicateID(predicate *Predicate, context string) string {
	// Generate a simple ID based on predicate type and context
	var typeStr string
	switch predicate.PredicateType.(type) {
	case *Predicate_Logical:
		typeStr = "logical"
	case *Predicate_Comparison:
		typeStr = "comparison"
	case *Predicate_Exists:
		typeStr = "exists"
	case *Predicate_Range:
		typeStr = "range"
	case *Predicate_Set:
		typeStr = "set"
	case *Predicate_Time:
		typeStr = "time"
	case *Predicate_Expression:
		typeStr = "expression"
	case *Predicate_Regex:
		typeStr = "regex"
	default:
		typeStr = "unknown"
	}

	return fmt.Sprintf("%s:%s", context, typeStr)
}

// PerformanceAnalyzer analyzes policies for potential performance issues
type PerformanceAnalyzer struct {
	maxNestingDepth   int
	maxPredicateCount int
	warningThreshold  int
}

// NewPerformanceAnalyzer creates a new performance analyzer
func NewPerformanceAnalyzer() *PerformanceAnalyzer {
	return &PerformanceAnalyzer{
		maxNestingDepth:   10,
		maxPredicateCount: 100,
		warningThreshold:  5,
	}
}

// AnalyzePolicy analyzes a policy for performance issues
func (a *PerformanceAnalyzer) AnalyzePolicy(policy *CompliancePolicy) []*ParseError {
	var warnings []*ParseError

	// Check overall rule count
	if len(policy.Rules) > a.warningThreshold {
		warnings = append(warnings, NewParseError(
			ErrorTypePerformanceWarning,
			"rules",
			fmt.Sprintf("policy has %d rules, consider grouping or optimizing for performance", len(policy.Rules)),
		).WithSuggestion("Consider breaking large policies into smaller, focused policies"))
	}

	// Check each rule for performance issues
	for i, rule := range policy.Rules {
		ruleContext := fmt.Sprintf("rules[%d]", i)
		ruleWarnings := a.analyzeRule(rule, ruleContext)
		warnings = append(warnings, ruleWarnings...)
	}

	return warnings
}

// analyzeRule analyzes a single rule for performance issues
func (a *PerformanceAnalyzer) analyzeRule(rule *PolicyRule, context string) []*ParseError {
	var warnings []*ParseError

	if rule.Predicate != nil {
		// Check predicate complexity
		depth := a.calculatePredicateDepth(rule.Predicate)
		if depth > a.maxNestingDepth {
			warnings = append(warnings, NewParseError(
				ErrorTypePerformanceWarning,
				context+".predicate",
				fmt.Sprintf("predicate nesting depth (%d) exceeds recommended maximum (%d)", depth, a.maxNestingDepth),
			).WithSuggestion("Consider flattening complex predicates or breaking them into multiple rules"))
		}

		count := a.countPredicates(rule.Predicate)
		if count > a.maxPredicateCount {
			warnings = append(warnings, NewParseError(
				ErrorTypePerformanceWarning,
				context+".predicate",
				fmt.Sprintf("predicate count (%d) is very high, may impact performance", count),
			).WithSuggestion("Consider optimizing or restructuring complex predicate logic"))
		}
	}

	return warnings
}

// calculatePredicateDepth calculates the maximum nesting depth of predicates
func (a *PerformanceAnalyzer) calculatePredicateDepth(predicate *Predicate) int {
	if predicate == nil {
		return 0
	}

	switch p := predicate.PredicateType.(type) {
	case *Predicate_Logical:
		if p.Logical == nil {
			return 1
		}
		maxChildDepth := 0
		for _, operand := range p.Logical.Operands {
			childDepth := a.calculatePredicateDepth(operand)
			if childDepth > maxChildDepth {
				maxChildDepth = childDepth
			}
		}
		return 1 + maxChildDepth
	default:
		return 1
	}
}

// countPredicates counts the total number of predicates in a tree
func (a *PerformanceAnalyzer) countPredicates(predicate *Predicate) int {
	if predicate == nil {
		return 0
	}

	count := 1 // Count this predicate

	switch p := predicate.PredicateType.(type) {
	case *Predicate_Logical:
		if p.Logical != nil {
			for _, operand := range p.Logical.Operands {
				count += a.countPredicates(operand)
			}
		}
	}

	return count
}

// LineNumberTracker tracks line numbers in YAML for error reporting
type LineNumberTracker struct {
	lines   []string
	nodeMap map[*yaml.Node]int
}

// NewLineNumberTracker creates a new line number tracker
func NewLineNumberTracker(yamlContent string) *LineNumberTracker {
	return &LineNumberTracker{
		lines:   strings.Split(yamlContent, "\n"),
		nodeMap: make(map[*yaml.Node]int),
	}
}

// TrackNode tracks a YAML node and its line number
func (t *LineNumberTracker) TrackNode(node *yaml.Node) {
	if node != nil {
		t.nodeMap[node] = node.Line
	}
}

// GetLineNumber gets the line number for a YAML node
func (t *LineNumberTracker) GetLineNumber(node *yaml.Node) int {
	if line, exists := t.nodeMap[node]; exists {
		return line
	}
	if node != nil {
		return node.Line
	}
	return 0
}

// GetLineContent gets the content of a specific line
func (t *LineNumberTracker) GetLineContent(lineNumber int) string {
	if lineNumber > 0 && lineNumber <= len(t.lines) {
		return t.lines[lineNumber-1]
	}
	return ""
}

// GetContextLines gets multiple lines around a specific line for context
func (t *LineNumberTracker) GetContextLines(lineNumber, contextSize int) []string {
	if lineNumber <= 0 || lineNumber > len(t.lines) {
		return nil
	}

	start := lineNumber - contextSize - 1
	if start < 0 {
		start = 0
	}

	end := lineNumber + contextSize
	if end > len(t.lines) {
		end = len(t.lines)
	}

	return t.lines[start:end]
}

// ValidationResult represents the result of validation with errors and warnings
type ValidationResult struct {
	Valid    bool
	Errors   []*ParseError
	Warnings []*ParseError
	PolicyID string
	Version  string
}

// NewValidationResult creates a new validation result
func NewValidationResult(policyID, version string) *ValidationResult {
	return &ValidationResult{
		Valid:    true,
		Errors:   make([]*ParseError, 0),
		Warnings: make([]*ParseError, 0),
		PolicyID: policyID,
		Version:  version,
	}
}

// AddError adds an error to the validation result
func (r *ValidationResult) AddError(err *ParseError) {
	r.Errors = append(r.Errors, err)
	r.Valid = false
}

// AddWarning adds a warning to the validation result
func (r *ValidationResult) AddWarning(warning *ParseError) {
	r.Warnings = append(r.Warnings, warning)
}

// HasErrors returns true if there are validation errors
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// HasWarnings returns true if there are validation warnings
func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// Summary returns a summary of the validation results
func (r *ValidationResult) Summary() string {
	if r.Valid {
		if r.HasWarnings() {
			return fmt.Sprintf("Policy %s (v%s) is valid with %d warning(s)", r.PolicyID, r.Version, len(r.Warnings))
		}
		return fmt.Sprintf("Policy %s (v%s) is valid", r.PolicyID, r.Version)
	}

	return fmt.Sprintf("Policy %s (v%s) has %d error(s) and %d warning(s)", r.PolicyID, r.Version, len(r.Errors), len(r.Warnings))
}
