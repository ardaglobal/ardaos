package parser

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
)

// ExpressionEngine provides safe expression parsing and evaluation
type ExpressionEngine struct {
	allowedFields    map[string]FieldType
	functions        map[string]Function
	securityLimits   SecurityLimits
	fieldSchema      FieldSchema
	validatorChain   []ExpressionValidator
	compilationCache map[string]*CompiledExpression
}

// FieldType represents the expected type of a field
type FieldType struct {
	Type        reflect.Type
	Nullable    bool
	Description string
	Constraints *FieldConstraints
}

// FieldConstraints defines validation constraints for fields
type FieldConstraints struct {
	MinValue    interface{}
	MaxValue    interface{}
	Pattern     *regexp.Regexp
	EnumValues  []interface{}
	ArrayLength *ArrayLengthConstraint
}

// ArrayLengthConstraint defines array length constraints
type ArrayLengthConstraint struct {
	MinLength int
	MaxLength int
}

// Function represents a built-in function that can be called in expressions
type Function struct {
	Name        string
	Parameters  []ParameterType
	ReturnType  reflect.Type
	Pure        bool // No side effects
	Handler     FunctionHandler
	Description string
	Complexity  int // Computational complexity score
}

// FunctionHandler is the function implementation
type FunctionHandler func(args []interface{}) (interface{}, error)

// ParameterType represents a function parameter type
type ParameterType struct {
	Type     reflect.Type
	Optional bool
	Variadic bool
}

// SecurityLimits defines security constraints for expressions
type SecurityLimits struct {
	MaxDepth           int           // Maximum AST depth
	MaxNodes           int           // Maximum number of AST nodes
	MaxFieldAccesses   int           // Maximum field access operations
	MaxFunctionCalls   int           // Maximum function calls
	MaxLoops           int           // Maximum loop iterations (for future array ops)
	MaxExecutionTime   time.Duration // Maximum evaluation time
	AllowedComplexity  int           // Maximum complexity score
	RestrictedPatterns []string      // Forbidden patterns in expressions
}

// FieldSchema contains the schema definition for field validation
type FieldSchema struct {
	Fields             map[string]FieldType
	AllowUnknownFields bool
	ValidationRules    []FieldValidationRule
}

// FieldValidationRule represents a custom validation rule
type FieldValidationRule struct {
	Pattern string
	Handler func(fieldPath string, value interface{}) error
}

// Expression represents a parsed expression
type Expression struct {
	Raw        string
	AST        ast.Expr
	FieldPaths []string
	Functions  []string
	Type       reflect.Type
	Metadata   *ExpressionMetadata
	Compiled   *CompiledExpression
}

// ExpressionMetadata contains metadata about the expression
type ExpressionMetadata struct {
	Complexity    int
	FieldAccesses int
	FunctionCalls int
	Depth         int
	EstimatedTime time.Duration
	SecurityScore int
	Dependencies  []string
	Optimizations []string
}

// CompiledExpression represents a compiled expression for efficient evaluation
type CompiledExpression struct {
	Bytecode     []Instruction
	Constants    []interface{}
	FieldRefs    []string
	FunctionRefs []string
	Metadata     *CompilationMetadata
}

// Instruction represents a bytecode instruction
type Instruction struct {
	Op   OpCode
	Arg1 int
	Arg2 int
	Type reflect.Type
}

// OpCode represents bytecode operation codes
type OpCode int

const (
	OpLoadConst OpCode = iota
	OpLoadField
	OpCallFunc
	OpAdd
	OpSub
	OpMul
	OpDiv
	OpMod
	OpEq
	OpNeq
	OpLt
	OpLte
	OpGt
	OpGte
	OpAnd
	OpOr
	OpNot
	OpReturn
)

// CompilationMetadata contains information about the compilation process
type CompilationMetadata struct {
	CompiledAt    time.Time
	OptLevel      int
	Optimizations []string
	OriginalSize  int
	CompiledSize  int
}

// ExpressionValidator validates expressions against security and business rules
type ExpressionValidator interface {
	Validate(expr *Expression, context map[string]interface{}) error
	GetValidatorName() string
}

// NewExpressionEngine creates a new expression engine with the given schema
func NewExpressionEngine(schema FieldSchema) *ExpressionEngine {
	engine := &ExpressionEngine{
		allowedFields:    make(map[string]FieldType),
		functions:        make(map[string]Function),
		securityLimits:   getDefaultSecurityLimits(),
		fieldSchema:      schema,
		validatorChain:   make([]ExpressionValidator, 0),
		compilationCache: make(map[string]*CompiledExpression),
	}

	// Copy allowed fields from schema
	for path, fieldType := range schema.Fields {
		engine.allowedFields[path] = fieldType
	}

	// Register built-in functions
	engine.registerBuiltinFunctions()

	// Add default validators
	engine.addDefaultValidators()

	return engine
}

// ParseExpression parses a string expression into an AST
func (e *ExpressionEngine) ParseExpression(expr string) (*Expression, error) {
	if expr == "" {
		return nil, fmt.Errorf("expression cannot be empty")
	}

	// Check for restricted patterns
	if err := e.checkRestrictedPatterns(expr); err != nil {
		return nil, fmt.Errorf("expression contains restricted patterns: %w", err)
	}

	// Parse using Go's parser (safe subset)
	astExpr, err := e.parseToAST(expr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expression: %w", err)
	}

	// Extract metadata
	metadata, err := e.analyzeExpression(astExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze expression: %w", err)
	}

	// Security validation
	if err := e.validateSecurity(metadata); err != nil {
		return nil, fmt.Errorf("expression violates security constraints: %w", err)
	}

	// Determine result type
	resultType, err := e.inferType(astExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to infer expression type: %w", err)
	}

	expression := &Expression{
		Raw:        expr,
		AST:        astExpr,
		FieldPaths: metadata.Dependencies,
		Functions:  e.extractFunctionCalls(astExpr),
		Type:       resultType,
		Metadata:   metadata,
	}

	return expression, nil
}

// ValidateExpression validates an expression against the provided context
func (e *ExpressionEngine) ValidateExpression(expr *Expression, context map[string]interface{}) error {
	if expr == nil {
		return fmt.Errorf("expression cannot be nil")
	}

	// Run all validators in the chain
	for _, validator := range e.validatorChain {
		if err := validator.Validate(expr, context); err != nil {
			return fmt.Errorf("validation failed (%s): %w", validator.GetValidatorName(), err)
		}
	}

	// Validate field access permissions
	for _, fieldPath := range expr.FieldPaths {
		if err := e.validateFieldAccess(fieldPath, context); err != nil {
			return fmt.Errorf("field access validation failed for '%s': %w", fieldPath, err)
		}
	}

	// Validate function calls
	for _, functionName := range expr.Functions {
		if err := e.validateFunctionCall(functionName); err != nil {
			return fmt.Errorf("function call validation failed for '%s': %w", functionName, err)
		}
	}

	return nil
}

// CompileToProtobuf compiles an expression to protobuf representation
func (e *ExpressionEngine) CompileToProtobuf(expr *Expression) (*ExpressionProto, error) {
	if expr == nil {
		return nil, fmt.Errorf("expression cannot be nil")
	}

	// Check compilation cache first
	if cached, exists := e.compilationCache[expr.Raw]; exists {
		return e.compiledToProtobuf(expr, cached)
	}

	// Compile to bytecode
	compiled, err := e.compileExpression(expr)
	if err != nil {
		return nil, fmt.Errorf("compilation failed: %w", err)
	}

	// Cache the result
	e.compilationCache[expr.Raw] = compiled
	expr.Compiled = compiled

	// Convert to protobuf
	return e.compiledToProtobuf(expr, compiled)
}

// parseToAST parses the expression string to AST using Go's parser
func (e *ExpressionEngine) parseToAST(expr string) (ast.Expr, error) {
	// Wrap expression in a function to make it parseable
	wrappedExpr := fmt.Sprintf("package main\nfunc main() { _ = %s }", expr)

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "", wrappedExpr, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("invalid expression syntax: %w", err)
	}

	// Extract the expression from the AST
	if len(parsed.Decls) != 1 {
		return nil, fmt.Errorf("unexpected AST structure")
	}

	funcDecl, ok := parsed.Decls[0].(*ast.FuncDecl)
	if !ok {
		return nil, fmt.Errorf("expected function declaration")
	}

	if len(funcDecl.Body.List) != 1 {
		return nil, fmt.Errorf("expected single statement")
	}

	assignStmt, ok := funcDecl.Body.List[0].(*ast.AssignStmt)
	if !ok {
		return nil, fmt.Errorf("expected assignment statement")
	}

	if len(assignStmt.Rhs) != 1 {
		return nil, fmt.Errorf("expected single right-hand side")
	}

	return assignStmt.Rhs[0], nil
}

// analyzeExpression analyzes the AST and extracts metadata
func (e *ExpressionEngine) analyzeExpression(astExpr ast.Expr) (*ExpressionMetadata, error) {
	analyzer := &astAnalyzer{
		engine:     e,
		metadata:   &ExpressionMetadata{},
		fieldPaths: make(map[string]bool),
		functions:  make(map[string]bool),
		depth:      0,
		maxDepth:   0,
	}

	ast.Inspect(astExpr, analyzer.visit)

	// Convert maps to slices
	for fieldPath := range analyzer.fieldPaths {
		analyzer.metadata.Dependencies = append(analyzer.metadata.Dependencies, fieldPath)
	}

	analyzer.metadata.Depth = analyzer.maxDepth
	analyzer.metadata.EstimatedTime = time.Duration(analyzer.metadata.Complexity) * time.Microsecond

	return analyzer.metadata, nil
}

// astAnalyzer helps analyze AST nodes
type astAnalyzer struct {
	engine     *ExpressionEngine
	metadata   *ExpressionMetadata
	fieldPaths map[string]bool
	functions  map[string]bool
	depth      int
	maxDepth   int
}

// visit is called for each AST node during inspection
func (a *astAnalyzer) visit(node ast.Node) bool {
	if node == nil {
		a.depth--
		return true
	}

	a.depth++
	if a.depth > a.maxDepth {
		a.maxDepth = a.depth
	}

	switch n := node.(type) {
	case *ast.SelectorExpr:
		// Field access like "loan.principal"
		fieldPath := a.extractFieldPath(n)
		if fieldPath != "" {
			a.fieldPaths[fieldPath] = true
			a.metadata.FieldAccesses++
			a.metadata.Complexity += 1
		}

	case *ast.CallExpr:
		// Function call
		if ident, ok := n.Fun.(*ast.Ident); ok {
			a.functions[ident.Name] = true
			a.metadata.FunctionCalls++
			a.metadata.Complexity += 2
		}

	case *ast.BinaryExpr:
		// Binary operations
		a.metadata.Complexity += 1

	case *ast.UnaryExpr:
		// Unary operations
		a.metadata.Complexity += 1

	case *ast.BasicLit:
		// Literals
		a.metadata.Complexity += 1
	}

	return true
}

// extractFieldPath extracts field path from selector expression
func (a *astAnalyzer) extractFieldPath(sel *ast.SelectorExpr) string {
	var parts []string

	current := sel
	for current != nil {
		parts = append([]string{current.Sel.Name}, parts...)

		switch x := current.X.(type) {
		case *ast.Ident:
			parts = append([]string{x.Name}, parts...)
			current = nil
		case *ast.SelectorExpr:
			current = x
		default:
			current = nil
		}
	}

	return strings.Join(parts, ".")
}

// inferType infers the result type of an expression
func (e *ExpressionEngine) inferType(astExpr ast.Expr) (reflect.Type, error) {
	switch node := astExpr.(type) {
	case *ast.BasicLit:
		return e.inferLiteralType(node), nil

	case *ast.BinaryExpr:
		return e.inferBinaryType(node)

	case *ast.UnaryExpr:
		return e.inferUnaryType(node)

	case *ast.SelectorExpr:
		fieldPath := e.extractFieldPathFromSelector(node)
		if fieldType, exists := e.allowedFields[fieldPath]; exists {
			return fieldType.Type, nil
		}
		return reflect.TypeOf(""), fmt.Errorf("unknown field: %s", fieldPath)

	case *ast.CallExpr:
		return e.inferCallType(node)

	default:
		return reflect.TypeOf(""), fmt.Errorf("cannot infer type for expression")
	}
}

// inferLiteralType infers type from literal values
func (e *ExpressionEngine) inferLiteralType(lit *ast.BasicLit) reflect.Type {
	switch lit.Kind {
	case token.INT:
		return reflect.TypeOf(int64(0))
	case token.FLOAT:
		return reflect.TypeOf(float64(0))
	case token.STRING:
		return reflect.TypeOf("")
	case token.CHAR:
		return reflect.TypeOf("")
	default:
		return reflect.TypeOf("")
	}
}

// inferBinaryType infers type from binary expressions
func (e *ExpressionEngine) inferBinaryType(bin *ast.BinaryExpr) (reflect.Type, error) {
	leftType, err := e.inferType(bin.X)
	if err != nil {
		return nil, err
	}

	rightType, err := e.inferType(bin.Y)
	if err != nil {
		return nil, err
	}

	switch bin.Op {
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM:
		// Arithmetic operations - promote to most general numeric type
		if e.isNumericType(leftType) && e.isNumericType(rightType) {
			if e.isFloatType(leftType) || e.isFloatType(rightType) {
				return reflect.TypeOf(float64(0)), nil
			}
			return reflect.TypeOf(int64(0)), nil
		}
		return nil, fmt.Errorf("arithmetic operations require numeric operands")

	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		// Comparison operations always return bool
		return reflect.TypeOf(true), nil

	case token.LAND, token.LOR:
		// Logical operations require bool operands and return bool
		if leftType == reflect.TypeOf(true) && rightType == reflect.TypeOf(true) {
			return reflect.TypeOf(true), nil
		}
		return nil, fmt.Errorf("logical operations require boolean operands")

	default:
		return nil, fmt.Errorf("unsupported binary operator: %s", bin.Op)
	}
}

// inferUnaryType infers type from unary expressions
func (e *ExpressionEngine) inferUnaryType(unary *ast.UnaryExpr) (reflect.Type, error) {
	operandType, err := e.inferType(unary.X)
	if err != nil {
		return nil, err
	}

	switch unary.Op {
	case token.SUB, token.ADD:
		// Unary + and - require numeric operands
		if e.isNumericType(operandType) {
			return operandType, nil
		}
		return nil, fmt.Errorf("unary +/- requires numeric operand")

	case token.NOT:
		// Unary ! requires boolean operand
		if operandType == reflect.TypeOf(true) {
			return reflect.TypeOf(true), nil
		}
		return nil, fmt.Errorf("unary ! requires boolean operand")

	default:
		return nil, fmt.Errorf("unsupported unary operator: %s", unary.Op)
	}
}

// inferCallType infers type from function calls
func (e *ExpressionEngine) inferCallType(call *ast.CallExpr) (reflect.Type, error) {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if function, exists := e.functions[ident.Name]; exists {
			return function.ReturnType, nil
		}
		return nil, fmt.Errorf("unknown function: %s", ident.Name)
	}
	return nil, fmt.Errorf("unsupported function call")
}

// Helper type checking functions
func (e *ExpressionEngine) isNumericType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

func (e *ExpressionEngine) isFloatType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// extractFieldPathFromSelector extracts field path from selector expression
func (e *ExpressionEngine) extractFieldPathFromSelector(sel *ast.SelectorExpr) string {
	var parts []string
	current := sel

	for current != nil {
		parts = append([]string{current.Sel.Name}, parts...)

		switch x := current.X.(type) {
		case *ast.Ident:
			parts = append([]string{x.Name}, parts...)
			current = nil
		case *ast.SelectorExpr:
			current = x
		default:
			current = nil
		}
	}

	return strings.Join(parts, ".")
}

// extractFunctionCalls extracts function calls from AST
func (e *ExpressionEngine) extractFunctionCalls(astExpr ast.Expr) []string {
	var functions []string

	ast.Inspect(astExpr, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				functions = append(functions, ident.Name)
			}
		}
		return true
	})

	return functions
}

// validateSecurity validates expression against security constraints
func (e *ExpressionEngine) validateSecurity(metadata *ExpressionMetadata) error {
	if metadata.Depth > e.securityLimits.MaxDepth {
		return fmt.Errorf("expression depth (%d) exceeds maximum (%d)",
			metadata.Depth, e.securityLimits.MaxDepth)
	}

	if metadata.Complexity > e.securityLimits.AllowedComplexity {
		return fmt.Errorf("expression complexity (%d) exceeds maximum (%d)",
			metadata.Complexity, e.securityLimits.AllowedComplexity)
	}

	if metadata.FieldAccesses > e.securityLimits.MaxFieldAccesses {
		return fmt.Errorf("field accesses (%d) exceed maximum (%d)",
			metadata.FieldAccesses, e.securityLimits.MaxFieldAccesses)
	}

	if metadata.FunctionCalls > e.securityLimits.MaxFunctionCalls {
		return fmt.Errorf("function calls (%d) exceed maximum (%d)",
			metadata.FunctionCalls, e.securityLimits.MaxFunctionCalls)
	}

	return nil
}

// validateFieldAccess validates field access permissions
func (e *ExpressionEngine) validateFieldAccess(fieldPath string, context map[string]interface{}) error {
	// Check if field is in allowed list
	if _, allowed := e.allowedFields[fieldPath]; !allowed {
		// Check if unknown fields are allowed
		if !e.fieldSchema.AllowUnknownFields {
			return fmt.Errorf("field '%s' is not allowed", fieldPath)
		}
	}

	// Run custom validation rules
	for _, rule := range e.fieldSchema.ValidationRules {
		matched, err := regexp.MatchString(rule.Pattern, fieldPath)
		if err != nil {
			continue
		}
		if matched {
			if value, exists := context[fieldPath]; exists {
				if err := rule.Handler(fieldPath, value); err != nil {
					return fmt.Errorf("field validation failed: %w", err)
				}
			}
		}
	}

	return nil
}

// validateFunctionCall validates function call permissions
func (e *ExpressionEngine) validateFunctionCall(functionName string) error {
	function, exists := e.functions[functionName]
	if !exists {
		return fmt.Errorf("function '%s' is not allowed", functionName)
	}

	// Check complexity limits
	if function.Complexity > e.securityLimits.AllowedComplexity/4 {
		return fmt.Errorf("function '%s' complexity too high for security limits", functionName)
	}

	return nil
}

// checkRestrictedPatterns checks for restricted patterns in expressions
func (e *ExpressionEngine) checkRestrictedPatterns(expr string) error {
	for _, pattern := range e.securityLimits.RestrictedPatterns {
		matched, err := regexp.MatchString(pattern, expr)
		if err != nil {
			continue
		}
		if matched {
			return fmt.Errorf("expression matches restricted pattern: %s", pattern)
		}
	}
	return nil
}

// compileExpression compiles an expression to bytecode
func (e *ExpressionEngine) compileExpression(expr *Expression) (*CompiledExpression, error) {
	compiler := &bytecodeCompiler{
		engine:       e,
		constants:    make([]interface{}, 0),
		fieldRefs:    make([]string, 0),
		funcRefs:     make([]string, 0),
		instructions: make([]Instruction, 0),
	}

	err := compiler.compile(expr.AST)
	if err != nil {
		return nil, err
	}

	// Add return instruction
	compiler.emit(OpReturn, 0, 0, expr.Type)

	return &CompiledExpression{
		Bytecode:     compiler.instructions,
		Constants:    compiler.constants,
		FieldRefs:    compiler.fieldRefs,
		FunctionRefs: compiler.funcRefs,
		Metadata: &CompilationMetadata{
			CompiledAt:   time.Now(),
			OptLevel:     1,
			OriginalSize: len(expr.Raw),
			CompiledSize: len(compiler.instructions),
		},
	}, nil
}

// bytecodeCompiler compiles expressions to bytecode
type bytecodeCompiler struct {
	engine       *ExpressionEngine
	constants    []interface{}
	fieldRefs    []string
	funcRefs     []string
	instructions []Instruction
}

// compile compiles an AST node to bytecode
func (c *bytecodeCompiler) compile(node ast.Expr) error {
	switch n := node.(type) {
	case *ast.BasicLit:
		return c.compileLiteral(n)
	case *ast.BinaryExpr:
		return c.compileBinary(n)
	case *ast.UnaryExpr:
		return c.compileUnary(n)
	case *ast.SelectorExpr:
		return c.compileFieldAccess(n)
	case *ast.CallExpr:
		return c.compileFunctionCall(n)
	default:
		return fmt.Errorf("unsupported AST node type: %T", node)
	}
}

// compileLiteral compiles literal values
func (c *bytecodeCompiler) compileLiteral(lit *ast.BasicLit) error {
	var value interface{}
	var err error

	switch lit.Kind {
	case token.INT:
		value, err = strconv.ParseInt(lit.Value, 0, 64)
	case token.FLOAT:
		value, err = strconv.ParseFloat(lit.Value, 64)
	case token.STRING:
		value = strings.Trim(lit.Value, `"`)
	default:
		return fmt.Errorf("unsupported literal type: %s", lit.Kind)
	}

	if err != nil {
		return fmt.Errorf("failed to parse literal: %w", err)
	}

	constIndex := c.addConstant(value)
	c.emit(OpLoadConst, constIndex, 0, reflect.TypeOf(value))

	return nil
}

// compileBinary compiles binary expressions
func (c *bytecodeCompiler) compileBinary(bin *ast.BinaryExpr) error {
	// Compile left operand
	if err := c.compile(bin.X); err != nil {
		return err
	}

	// Compile right operand
	if err := c.compile(bin.Y); err != nil {
		return err
	}

	// Emit operation
	var op OpCode
	switch bin.Op {
	case token.ADD:
		op = OpAdd
	case token.SUB:
		op = OpSub
	case token.MUL:
		op = OpMul
	case token.QUO:
		op = OpDiv
	case token.REM:
		op = OpMod
	case token.EQL:
		op = OpEq
	case token.NEQ:
		op = OpNeq
	case token.LSS:
		op = OpLt
	case token.LEQ:
		op = OpLte
	case token.GTR:
		op = OpGt
	case token.GEQ:
		op = OpGte
	case token.LAND:
		op = OpAnd
	case token.LOR:
		op = OpOr
	default:
		return fmt.Errorf("unsupported binary operator: %s", bin.Op)
	}

	// Infer result type
	resultType, err := c.engine.inferBinaryType(bin)
	if err != nil {
		return err
	}

	c.emit(op, 0, 0, resultType)
	return nil
}

// compileUnary compiles unary expressions
func (c *bytecodeCompiler) compileUnary(unary *ast.UnaryExpr) error {
	// Compile operand
	if err := c.compile(unary.X); err != nil {
		return err
	}

	// Emit operation
	var op OpCode
	switch unary.Op {
	case token.SUB:
		// Unary minus: multiply by -1
		constIndex := c.addConstant(-1)
		c.emit(OpLoadConst, constIndex, 0, reflect.TypeOf(-1))
		op = OpMul
	case token.NOT:
		op = OpNot
	default:
		return fmt.Errorf("unsupported unary operator: %s", unary.Op)
	}

	resultType, err := c.engine.inferUnaryType(unary)
	if err != nil {
		return err
	}

	c.emit(op, 0, 0, resultType)
	return nil
}

// compileFieldAccess compiles field access expressions
func (c *bytecodeCompiler) compileFieldAccess(sel *ast.SelectorExpr) error {
	fieldPath := c.engine.extractFieldPathFromSelector(sel)
	fieldIndex := c.addFieldRef(fieldPath)

	var fieldType reflect.Type
	if ft, exists := c.engine.allowedFields[fieldPath]; exists {
		fieldType = ft.Type
	} else {
		fieldType = reflect.TypeOf("")
	}

	c.emit(OpLoadField, fieldIndex, 0, fieldType)
	return nil
}

// compileFunctionCall compiles function call expressions
func (c *bytecodeCompiler) compileFunctionCall(call *ast.CallExpr) error {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return fmt.Errorf("unsupported function call")
	}

	functionName := ident.Name
	function, exists := c.engine.functions[functionName]
	if !exists {
		return fmt.Errorf("unknown function: %s", functionName)
	}

	// Compile arguments
	for _, arg := range call.Args {
		if err := c.compile(arg); err != nil {
			return err
		}
	}

	funcIndex := c.addFuncRef(functionName)
	c.emit(OpCallFunc, funcIndex, len(call.Args), function.ReturnType)

	return nil
}

// emit emits a bytecode instruction
func (c *bytecodeCompiler) emit(op OpCode, arg1, arg2 int, resultType reflect.Type) {
	c.instructions = append(c.instructions, Instruction{
		Op:   op,
		Arg1: arg1,
		Arg2: arg2,
		Type: resultType,
	})
}

// addConstant adds a constant to the constant pool
func (c *bytecodeCompiler) addConstant(value interface{}) int {
	c.constants = append(c.constants, value)
	return len(c.constants) - 1
}

// addFieldRef adds a field reference
func (c *bytecodeCompiler) addFieldRef(fieldPath string) int {
	c.fieldRefs = append(c.fieldRefs, fieldPath)
	return len(c.fieldRefs) - 1
}

// addFuncRef adds a function reference
func (c *bytecodeCompiler) addFuncRef(functionName string) int {
	c.funcRefs = append(c.funcRefs, functionName)
	return len(c.funcRefs) - 1
}

// compiledToProtobuf converts compiled expression to protobuf
func (e *ExpressionEngine) compiledToProtobuf(expr *Expression, compiled *CompiledExpression) (*ExpressionProto, error) {
	// Convert constants to Any types
	constants := make([]*anypb.Any, len(compiled.Constants))
	for i, constant := range compiled.Constants {
		anyValue, err := convertToAny(constant)
		if err != nil {
			return nil, fmt.Errorf("failed to convert constant %d: %w", i, err)
		}
		constants[i] = anyValue
	}

	// Convert bytecode to protobuf format
	bytecode := make([]*BytecodeInstruction, len(compiled.Bytecode))
	for i, instruction := range compiled.Bytecode {
		bytecode[i] = &BytecodeInstruction{
			Opcode: int32(instruction.Op),
			Arg1:   int32(instruction.Arg1),
			Arg2:   int32(instruction.Arg2),
			Type:   instruction.Type.String(),
		}
	}

	return &ExpressionProto{
		Expression:      expr.Raw,
		Language:        ExpressionLanguage_EXPRESSION_LANGUAGE_GOLANG,
		ResultType:      expr.Type.String(),
		FieldReferences: compiled.FieldRefs,
		FunctionCalls:   compiled.FunctionRefs,
		Constants:       constants,
		Bytecode:        bytecode,
		Metadata: &ExpressionMetadataProto{
			Complexity:    int32(expr.Metadata.Complexity),
			FieldAccesses: int32(expr.Metadata.FieldAccesses),
			FunctionCalls: int32(expr.Metadata.FunctionCalls),
			Depth:         int32(expr.Metadata.Depth),
			Dependencies:  expr.Metadata.Dependencies,
			SecurityScore: int32(expr.Metadata.SecurityScore),
		},
	}, nil
}

// registerBuiltinFunctions registers built-in functions
func (e *ExpressionEngine) registerBuiltinFunctions() {
	// Mathematical functions
	e.functions["min"] = Function{
		Name:       "min",
		Parameters: []ParameterType{{Type: reflect.TypeOf(float64(0)), Variadic: true}},
		ReturnType: reflect.TypeOf(float64(0)),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) == 0 {
				return nil, fmt.Errorf("min requires at least one argument")
			}
			minVal := math.Inf(1)
			for _, arg := range args {
				if val, ok := toFloat64(arg); ok {
					if val < minVal {
						minVal = val
					}
				} else {
					return nil, fmt.Errorf("min requires numeric arguments")
				}
			}
			return minVal, nil
		},
		Description: "Returns the minimum value from the arguments",
		Complexity:  2,
	}

	e.functions["max"] = Function{
		Name:       "max",
		Parameters: []ParameterType{{Type: reflect.TypeOf(float64(0)), Variadic: true}},
		ReturnType: reflect.TypeOf(float64(0)),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) == 0 {
				return nil, fmt.Errorf("max requires at least one argument")
			}
			maxVal := math.Inf(-1)
			for _, arg := range args {
				if val, ok := toFloat64(arg); ok {
					if val > maxVal {
						maxVal = val
					}
				} else {
					return nil, fmt.Errorf("max requires numeric arguments")
				}
			}
			return maxVal, nil
		},
		Description: "Returns the maximum value from the arguments",
		Complexity:  2,
	}

	e.functions["abs"] = Function{
		Name:       "abs",
		Parameters: []ParameterType{{Type: reflect.TypeOf(float64(0))}},
		ReturnType: reflect.TypeOf(float64(0)),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("abs requires exactly one argument")
			}
			if val, ok := toFloat64(args[0]); ok {
				return math.Abs(val), nil
			}
			return nil, fmt.Errorf("abs requires numeric argument")
		},
		Description: "Returns the absolute value of the argument",
		Complexity:  1,
	}

	e.functions["round"] = Function{
		Name:       "round",
		Parameters: []ParameterType{{Type: reflect.TypeOf(float64(0))}},
		ReturnType: reflect.TypeOf(float64(0)),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("round requires exactly one argument")
			}
			if val, ok := toFloat64(args[0]); ok {
				return math.Round(val), nil
			}
			return nil, fmt.Errorf("round requires numeric argument")
		},
		Description: "Rounds the argument to the nearest integer",
		Complexity:  1,
	}

	// Array functions
	e.functions["len"] = Function{
		Name:       "len",
		Parameters: []ParameterType{{Type: reflect.TypeOf([]interface{}{})}},
		ReturnType: reflect.TypeOf(int64(0)),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("len requires exactly one argument")
			}

			value := reflect.ValueOf(args[0])
			switch value.Kind() {
			case reflect.Slice, reflect.Array, reflect.String, reflect.Map:
				return int64(value.Len()), nil
			default:
				return nil, fmt.Errorf("len requires array, slice, string, or map argument")
			}
		},
		Description: "Returns the length of an array, slice, string, or map",
		Complexity:  1,
	}

	e.functions["sum"] = Function{
		Name:       "sum",
		Parameters: []ParameterType{{Type: reflect.TypeOf([]interface{}{})}},
		ReturnType: reflect.TypeOf(float64(0)),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("sum requires exactly one argument")
			}

			value := reflect.ValueOf(args[0])
			if value.Kind() != reflect.Slice && value.Kind() != reflect.Array {
				return nil, fmt.Errorf("sum requires array or slice argument")
			}

			var sum float64
			for i := 0; i < value.Len(); i++ {
				if val, ok := toFloat64(value.Index(i).Interface()); ok {
					sum += val
				} else {
					return nil, fmt.Errorf("sum requires numeric array elements")
				}
			}

			return sum, nil
		},
		Description: "Returns the sum of all numeric elements in an array",
		Complexity:  3,
	}

	e.functions["contains"] = Function{
		Name: "contains",
		Parameters: []ParameterType{
			{Type: reflect.TypeOf([]interface{}{})},
			{Type: reflect.TypeOf("")},
		},
		ReturnType: reflect.TypeOf(true),
		Pure:       true,
		Handler: func(args []interface{}) (interface{}, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("contains requires exactly two arguments")
			}

			arr := reflect.ValueOf(args[0])
			if arr.Kind() != reflect.Slice && arr.Kind() != reflect.Array {
				return nil, fmt.Errorf("contains first argument must be array or slice")
			}

			searchValue := args[1]
			for i := 0; i < arr.Len(); i++ {
				if reflect.DeepEqual(arr.Index(i).Interface(), searchValue) {
					return true, nil
				}
			}

			return false, nil
		},
		Description: "Returns true if the array contains the specified value",
		Complexity:  2,
	}
}

// addDefaultValidators adds default expression validators
func (e *ExpressionEngine) addDefaultValidators() {
	e.validatorChain = append(e.validatorChain, &securityValidator{})
	e.validatorChain = append(e.validatorChain, &typeValidator{})
	e.validatorChain = append(e.validatorChain, &businessLogicValidator{})
}

// getDefaultSecurityLimits returns default security limits
func getDefaultSecurityLimits() SecurityLimits {
	return SecurityLimits{
		MaxDepth:          10,
		MaxNodes:          100,
		MaxFieldAccesses:  20,
		MaxFunctionCalls:  10,
		MaxLoops:          1000,
		MaxExecutionTime:  time.Millisecond * 100,
		AllowedComplexity: 50,
		RestrictedPatterns: []string{
			`import\s+`,    // No imports
			`package\s+`,   // No package declarations
			`func\s+`,      // No function definitions
			`go\s+`,        // No goroutines
			`defer\s+`,     // No defer statements
			`panic\s*\(`,   // No panic calls
			`recover\s*\(`, // No recover calls
			`unsafe\.`,     // No unsafe operations
			`reflect\.`,    // No reflection (beyond built-in)
			`os\.`,         // No OS operations
			`io\.`,         // No I/O operations
			`net\.`,        // No network operations
			`exec\.`,       // No command execution
			`syscall\.`,    // No system calls
		},
	}
}

// toFloat64 converts various numeric types to float64
func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint64:
		return float64(val), true
	default:
		return 0, false
	}
}
