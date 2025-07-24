package parser

import (
	"fmt"
	"time"

	compliancev1 "github.com/arda-org/arda-os/tools/compliance-compiler/gen/compliance/v1"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/schema"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PolicyParser handles the complete parsing pipeline from YAML to protobuf
// using JSON Schema validation as an intermediate representation
type PolicyParser struct {
	schemaValidator   *schema.SchemaValidator
	protobufConverter *ProtobufConverter
	strictMode        bool
	enableWarnings    bool
}

// ParsingOptions configures the parsing behavior
type ParsingOptions struct {
	StrictMode     bool   // Fail on schema validation warnings
	EnableWarnings bool   // Include warnings in results
	SchemaPath     string // Custom JSON schema file path
}

// ParseResult contains the complete parsing results
type ParseResult struct {
	Policy           *compliancev1.CompliancePolicy `json:"policy"`
	ValidationResult *schema.ValidationResult       `json:"validation_result"`
	ParseTime        time.Duration                  `json:"parse_time"`
	Warnings         []string                       `json:"warnings,omitempty"`
	Errors           []string                       `json:"errors,omitempty"`
}

// NewPolicyParser creates a new policy parser with the specified options
func NewPolicyParser(options ParsingOptions) (*PolicyParser, error) {
	var validator *schema.SchemaValidator
	var err error

	if options.SchemaPath != "" {
		validator, err = schema.NewSchemaValidatorFromFile(options.SchemaPath)
	} else {
		validator, err = schema.NewSchemaValidator()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create schema validator: %w", err)
	}

	converter, err := NewProtobufConverter()
	if err != nil {
		return nil, fmt.Errorf("failed to create protobuf converter: %w", err)
	}

	return &PolicyParser{
		schemaValidator:   validator,
		protobufConverter: converter,
		strictMode:        options.StrictMode,
		enableWarnings:    options.EnableWarnings,
	}, nil
}

// ParseYAMLFile parses a YAML file through the complete validation and conversion pipeline
func (p *PolicyParser) ParseYAMLFile(filePath string) (*ParseResult, error) {
	startTime := time.Now()

	// Step 1: Validate YAML against JSON Schema
	validationResult, err := p.schemaValidator.ValidateYAMLFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("schema validation failed: %w", err)
	}

	result := &ParseResult{
		ValidationResult: validationResult,
		ParseTime:        time.Since(startTime),
		Warnings:         make([]string, 0),
		Errors:           make([]string, 0),
	}

	// Handle validation errors
	if !validationResult.Valid {
		for _, validationError := range validationResult.Errors {
			errorMsg := fmt.Sprintf("%s: %s", validationError.Field, validationError.Message)
			if validationError.Suggestion != "" {
				errorMsg += fmt.Sprintf(" (Suggestion: %s)", validationError.Suggestion)
			}
			result.Errors = append(result.Errors, errorMsg)
		}
		return result, fmt.Errorf("schema validation failed with %d errors", len(validationResult.Errors))
	}

	// Handle validation warnings
	if p.enableWarnings {
		for _, warning := range validationResult.Warnings {
			warningMsg := fmt.Sprintf("%s: %s", warning.Field, warning.Message)
			if warning.Suggestion != "" {
				warningMsg += fmt.Sprintf(" (Suggestion: %s)", warning.Suggestion)
			}
			result.Warnings = append(result.Warnings, warningMsg)
		}

		if p.strictMode && len(validationResult.Warnings) > 0 {
			return result, fmt.Errorf("strict mode enabled: validation produced %d warnings", len(validationResult.Warnings))
		}
	}

	// Step 2: Convert validated data to protobuf
	policy, err := p.protobufConverter.ConvertToProtobuf(validationResult.Document)
	if err != nil {
		return result, fmt.Errorf("protobuf conversion failed: %w", err)
	}

	result.Policy = policy
	result.ParseTime = time.Since(startTime)

	return result, nil
}

// ParseYAMLContent parses YAML content through the validation and conversion pipeline
func (p *PolicyParser) ParseYAMLContent(yamlContent []byte) (*ParseResult, error) {
	startTime := time.Now()

	// Step 1: Validate YAML against JSON Schema
	validationResult, err := p.schemaValidator.ValidateYAML(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("schema validation failed: %w", err)
	}

	result := &ParseResult{
		ValidationResult: validationResult,
		ParseTime:        time.Since(startTime),
		Warnings:         make([]string, 0),
		Errors:           make([]string, 0),
	}

	// Handle validation errors
	if !validationResult.Valid {
		for _, validationError := range validationResult.Errors {
			errorMsg := fmt.Sprintf("%s: %s", validationError.Field, validationError.Message)
			if validationError.Suggestion != "" {
				errorMsg += fmt.Sprintf(" (Suggestion: %s)", validationError.Suggestion)
			}
			result.Errors = append(result.Errors, errorMsg)
		}
		return result, fmt.Errorf("schema validation failed with %d errors", len(validationResult.Errors))
	}

	// Handle validation warnings
	if p.enableWarnings {
		for _, warning := range validationResult.Warnings {
			warningMsg := fmt.Sprintf("%s: %s", warning.Field, warning.Message)
			if warning.Suggestion != "" {
				warningMsg += fmt.Sprintf(" (Suggestion: %s)", warning.Suggestion)
			}
			result.Warnings = append(result.Warnings, warningMsg)
		}

		if p.strictMode && len(validationResult.Warnings) > 0 {
			return result, fmt.Errorf("strict mode enabled: validation produced %d warnings", len(validationResult.Warnings))
		}
	}

	// Step 2: Convert validated data to protobuf
	policy, err := p.protobufConverter.ConvertToProtobuf(validationResult.Document)
	if err != nil {
		return result, fmt.Errorf("protobuf conversion failed: %w", err)
	}

	result.Policy = policy
	result.ParseTime = time.Since(startTime)

	return result, nil
}

// ProtobufConverter handles conversion from validated JSON data to protobuf structures
type ProtobufConverter struct {
	// Add any required configuration or helpers
}

// NewProtobufConverter creates a new protobuf converter
func NewProtobufConverter() (*ProtobufConverter, error) {
	return &ProtobufConverter{}, nil
}

// ConvertToProtobuf converts validated JSON data to protobuf CompliancePolicy
func (c *ProtobufConverter) ConvertToProtobuf(data map[string]interface{}) (*compliancev1.CompliancePolicy, error) {
	policy := &compliancev1.CompliancePolicy{}

	// Convert basic fields
	if policyID, ok := data["policy_id"].(string); ok {
		policy.PolicyId = policyID
	}

	if version, ok := data["version"].(string); ok {
		policy.Version = version
	}

	if jurisdiction, ok := data["jurisdiction"].(string); ok {
		policy.Jurisdiction = jurisdiction
	}

	if assetClass, ok := data["asset_class"].(string); ok {
		policy.AssetClass = assetClass
	}

	// Convert rules
	if rulesData, ok := data["rules"].([]interface{}); ok {
		for _, ruleData := range rulesData {
			rule, err := c.convertRule(ruleData)
			if err != nil {
				return nil, fmt.Errorf("failed to convert rule: %w", err)
			}
			policy.Rules = append(policy.Rules, rule)
		}
	}

	// Convert attestations
	if attestationsData, ok := data["attestations"].([]interface{}); ok {
		for _, attestationData := range attestationsData {
			attestation, err := c.convertAttestation(attestationData)
			if err != nil {
				return nil, fmt.Errorf("failed to convert attestation: %w", err)
			}
			policy.Attestations = append(policy.Attestations, attestation)
		}
	}

	// Convert enforcement configuration
	if enforcementData, ok := data["enforcement"]; ok {
		enforcement, err := c.convertEnforcement(enforcementData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert enforcement: %w", err)
		}
		policy.Enforcement = enforcement
	}

	// Convert metadata
	if metadataData, ok := data["metadata"]; ok {
		metadata, err := c.convertMetadata(metadataData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert metadata: %w", err)
		}
		policy.Metadata = metadata
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = timestamppb.New(now)
	policy.UpdatedAt = timestamppb.New(now)

	return policy, nil
}

// convertRule converts a rule from JSON to protobuf
func (c *ProtobufConverter) convertRule(ruleData interface{}) (*compliancev1.PolicyRule, error) {
	ruleMap, ok := ruleData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rule must be an object")
	}

	rule := &compliancev1.PolicyRule{}

	if ruleID, ok := ruleMap["rule_id"].(string); ok {
		rule.RuleId = ruleID
	}

	if name, ok := ruleMap["name"].(string); ok {
		rule.Name = name
	}

	if description, ok := ruleMap["description"].(string); ok {
		rule.Description = description
	}

	if predicateData, ok := ruleMap["predicate"]; ok {
		predicate, err := c.convertPredicate(predicateData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert predicate: %w", err)
		}
		rule.Predicate = predicate
	}

	if required, ok := ruleMap["required"].(bool); ok {
		rule.Required = required
	} else {
		rule.Required = true // Default to required
	}

	if priority, ok := ruleMap["priority"].(float64); ok {
		rule.Priority = int32(priority)
	}

	if tagsData, ok := ruleMap["tags"].([]interface{}); ok {
		for _, tagData := range tagsData {
			if tag, ok := tagData.(string); ok {
				rule.Tags = append(rule.Tags, tag)
			}
		}
	}

	return rule, nil
}

// convertPredicate converts a predicate from JSON to protobuf
func (c *ProtobufConverter) convertPredicate(predicateData interface{}) (*compliancev1.Predicate, error) {
	predicateMap, ok := predicateData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("predicate must be an object")
	}

	// Handle comparison predicate
	if _, hasField := predicateMap["field"]; hasField {
		return c.convertComparisonPredicate(predicateMap)
	}

	// Handle logical predicates
	if andOperands, hasAnd := predicateMap["and"]; hasAnd {
		return c.convertLogicalPredicate("and", andOperands)
	}
	if orOperands, hasOr := predicateMap["or"]; hasOr {
		return c.convertLogicalPredicate("or", orOperands)
	}
	if notOperand, hasNot := predicateMap["not"]; hasNot {
		return c.convertLogicalPredicate("not", notOperand)
	}

	// Handle exists predicate
	if existsField, hasExists := predicateMap["exists"]; hasExists {
		return c.convertExistsPredicate(predicateMap, existsField)
	}

	// Handle range predicate
	if rangeData, hasRange := predicateMap["range"]; hasRange {
		return c.convertRangePredicate(rangeData)
	}

	// Handle set predicates
	if inValues, hasIn := predicateMap["in"]; hasIn {
		return c.convertSetPredicate(predicateMap, inValues, true)
	}
	if notInValues, hasNotIn := predicateMap["not_in"]; hasNotIn {
		return c.convertSetPredicate(predicateMap, notInValues, false)
	}

	// Handle expression predicate
	if expression, hasExpression := predicateMap["expression"]; hasExpression {
		return c.convertExpressionPredicate(predicateMap, expression)
	}

	// Handle regex predicate
	if regex, hasRegex := predicateMap["regex"]; hasRegex {
		return c.convertRegexPredicate(predicateMap, regex)
	}

	return nil, fmt.Errorf("unrecognized predicate type")
}

// convertComparisonPredicate converts a comparison predicate
func (c *ProtobufConverter) convertComparisonPredicate(predicateMap map[string]interface{}) (*compliancev1.Predicate, error) {
	fieldPath, err := c.convertFieldPath(predicateMap["field"])
	if err != nil {
		return nil, fmt.Errorf("failed to convert field path: %w", err)
	}

	opStr, ok := predicateMap["op"].(string)
	if !ok {
		return nil, fmt.Errorf("comparison operator must be a string")
	}

	operator, err := c.convertComparisonOperator(opStr)
	if err != nil {
		return nil, fmt.Errorf("invalid comparison operator: %w", err)
	}

	// Get value (either direct value or value_expr)
	var value interface{}
	if val, ok := predicateMap["value"]; ok {
		value = val
	} else if valueExpr, ok := predicateMap["value_expr"].(string); ok {
		// For now, treat expressions as string values
		// TODO: Implement expression evaluation
		value = valueExpr
	} else {
		return nil, fmt.Errorf("either 'value' or 'value_expr' must be specified")
	}

	anyValue, err := c.convertToAny(value)
	if err != nil {
		return nil, fmt.Errorf("failed to convert value: %w", err)
	}

	return &compliancev1.Predicate{
		PredicateType: &compliancev1.Predicate_Comparison{
			Comparison: &compliancev1.ComparisonPredicate{
				FieldPath: fieldPath,
				Operator:  operator,
				Value:     anyValue,
			},
		},
	}, nil
}

// convertLogicalPredicate converts logical predicates (AND, OR, NOT)
func (c *ProtobufConverter) convertLogicalPredicate(operator string, operandsData interface{}) (*compliancev1.Predicate, error) {
	var logicalOp compliancev1.LogicalOperator
	switch operator {
	case "and":
		logicalOp = compliancev1.LogicalOperator_LOGICAL_OPERATOR_AND
	case "or":
		logicalOp = compliancev1.LogicalOperator_LOGICAL_OPERATOR_OR
	case "not":
		logicalOp = compliancev1.LogicalOperator_LOGICAL_OPERATOR_NOT
	default:
		return nil, fmt.Errorf("unsupported logical operator: %s", operator)
	}

	var operands []*compliancev1.Predicate

	if operator == "not" {
		// NOT takes a single operand
		predicate, err := c.convertPredicate(operandsData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert NOT operand: %w", err)
		}
		operands = append(operands, predicate)
	} else {
		// AND/OR take multiple operands
		operandsList, ok := operandsData.([]interface{})
		if !ok {
			return nil, fmt.Errorf("%s operands must be an array", operator)
		}

		for i, operandData := range operandsList {
			predicate, err := c.convertPredicate(operandData)
			if err != nil {
				return nil, fmt.Errorf("failed to convert %s operand %d: %w", operator, i, err)
			}
			operands = append(operands, predicate)
		}
	}

	return &compliancev1.Predicate{
		PredicateType: &compliancev1.Predicate_Logical{
			Logical: &compliancev1.LogicalPredicate{
				Operator: logicalOp,
				Operands: operands,
			},
		},
	}, nil
}

// convertExistsPredicate converts exists predicates
func (c *ProtobufConverter) convertExistsPredicate(predicateMap map[string]interface{}, existsField interface{}) (*compliancev1.Predicate, error) {
	fieldPath, err := c.convertFieldPath(existsField)
	if err != nil {
		return nil, fmt.Errorf("failed to convert exists field path: %w", err)
	}

	shouldExist := true
	if val, ok := predicateMap["should_exist"].(bool); ok {
		shouldExist = val
	}

	return &compliancev1.Predicate{
		PredicateType: &compliancev1.Predicate_Exists{
			Exists: &compliancev1.ExistsPredicate{
				FieldPath:   fieldPath,
				ShouldExist: shouldExist,
			},
		},
	}, nil
}

// convertRangePredicate converts range predicates
func (c *ProtobufConverter) convertRangePredicate(rangeData interface{}) (*compliancev1.Predicate, error) {
	rangeMap, ok := rangeData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("range must be an object")
	}

	fieldPath, err := c.convertFieldPath(rangeMap["field"])
	if err != nil {
		return nil, fmt.Errorf("failed to convert range field path: %w", err)
	}

	rangePred := &compliancev1.RangePredicate{
		FieldPath:    fieldPath,
		MinInclusive: true, // Default
		MaxInclusive: true, // Default
	}

	if minValue, ok := rangeMap["min"]; ok {
		anyMin, err := c.convertToAny(minValue)
		if err != nil {
			return nil, fmt.Errorf("failed to convert min value: %w", err)
		}
		rangePred.MinValue = anyMin
	}

	if maxValue, ok := rangeMap["max"]; ok {
		anyMax, err := c.convertToAny(maxValue)
		if err != nil {
			return nil, fmt.Errorf("failed to convert max value: %w", err)
		}
		rangePred.MaxValue = anyMax
	}

	if minInclusive, ok := rangeMap["min_inclusive"].(bool); ok {
		rangePred.MinInclusive = minInclusive
	}

	if maxInclusive, ok := rangeMap["max_inclusive"].(bool); ok {
		rangePred.MaxInclusive = maxInclusive
	}

	return &compliancev1.Predicate{
		PredicateType: &compliancev1.Predicate_Range{
			Range: rangePred,
		},
	}, nil
}

// Helper conversion methods

func (c *ProtobufConverter) convertFieldPath(fieldData interface{}) (*compliancev1.FieldPath, error) {
	fieldPath, ok := fieldData.(string)
	if !ok {
		return nil, fmt.Errorf("field path must be a string")
	}

	// For now, create a simple field path
	// TODO: Parse complex paths with array access, function calls, etc.
	return &compliancev1.FieldPath{
		Components: []*compliancev1.PathComponent{{
			ComponentType: &compliancev1.PathComponent_FieldName{
				FieldName: fieldPath,
			},
		}},
		RawPath: fieldPath,
	}, nil
}

func (c *ProtobufConverter) convertComparisonOperator(opStr string) (compliancev1.ComparisonOperator, error) {
	switch opStr {
	case "eq":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_EQUAL, nil
	case "ne":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_NOT_EQUAL, nil
	case "gt":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN, nil
	case "gte":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN_OR_EQUAL, nil
	case "lt":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_LESS_THAN, nil
	case "lte":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_LESS_THAN_OR_EQUAL, nil
	case "contains":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_CONTAINS, nil
	case "starts_with":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_STARTS_WITH, nil
	case "ends_with":
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_ENDS_WITH, nil
	default:
		return compliancev1.ComparisonOperator_COMPARISON_OPERATOR_UNSPECIFIED, fmt.Errorf("unknown comparison operator: %s", opStr)
	}
}

func (c *ProtobufConverter) convertToAny(value interface{}) (*anypb.Any, error) {
	// TODO: Implement proper Any conversion based on value type
	// For now, this is a placeholder
	return &anypb.Any{}, nil
}

// Placeholder methods for other predicate types
func (c *ProtobufConverter) convertSetPredicate(predicateMap map[string]interface{}, values interface{}, isMember bool) (*compliancev1.Predicate, error) {
	// TODO: Implement set predicate conversion
	return nil, fmt.Errorf("set predicate conversion not yet implemented")
}

func (c *ProtobufConverter) convertExpressionPredicate(predicateMap map[string]interface{}, expression interface{}) (*compliancev1.Predicate, error) {
	// TODO: Implement expression predicate conversion
	return nil, fmt.Errorf("expression predicate conversion not yet implemented")
}

func (c *ProtobufConverter) convertRegexPredicate(predicateMap map[string]interface{}, regex interface{}) (*compliancev1.Predicate, error) {
	// TODO: Implement regex predicate conversion
	return nil, fmt.Errorf("regex predicate conversion not yet implemented")
}

func (c *ProtobufConverter) convertAttestation(attestationData interface{}) (*compliancev1.AttestationRequirement, error) {
	// TODO: Implement attestation conversion
	return nil, fmt.Errorf("attestation conversion not yet implemented")
}

func (c *ProtobufConverter) convertEnforcement(enforcementData interface{}) (*compliancev1.EnforcementConfig, error) {
	// TODO: Implement enforcement conversion
	return nil, fmt.Errorf("enforcement conversion not yet implemented")
}

func (c *ProtobufConverter) convertMetadata(metadataData interface{}) (*compliancev1.PolicyMetadata, error) {
	// TODO: Implement metadata conversion
	return nil, fmt.Errorf("metadata conversion not yet implemented")
}
