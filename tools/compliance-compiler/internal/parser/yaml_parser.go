package parser

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// Local type definitions until protobuf code is generated
type CompliancePolicy struct {
	PolicyId     string                    `json:"policy_id"`
	Version      string                    `json:"version"`
	Jurisdiction string                    `json:"jurisdiction"`
	AssetClass   string                    `json:"asset_class"`
	Rules        []*PolicyRule             `json:"rules"`
	Attestations []*AttestationRequirement `json:"attestations"`
	Enforcement  *EnforcementConfig        `json:"enforcement"`
}

type PolicyRule struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Predicate   *Predicate `json:"predicate"`
	Required    bool       `json:"required"`
}

type Predicate struct {
	PredicateType isPredicate_PredicateType `json:"predicate_type"`
}

type isPredicate_PredicateType interface {
	isPredicate_PredicateType()
}

type Predicate_Comparison struct {
	Comparison *ComparisonPredicate `json:"comparison"`
}

func (*Predicate_Comparison) isPredicate_PredicateType() {}

type ComparisonPredicate struct {
	FieldPath *FieldPath         `json:"field_path"`
	Operator  ComparisonOperator `json:"operator"`
	Value     *anypb.Any         `json:"value"`
}

type FieldPath struct {
	RawPath string `json:"raw_path"`
}

type ComparisonOperator int32

const (
	ComparisonOperator_COMPARISON_OPERATOR_UNSPECIFIED           ComparisonOperator = 0
	ComparisonOperator_COMPARISON_OPERATOR_EQUAL                 ComparisonOperator = 1
	ComparisonOperator_COMPARISON_OPERATOR_NOT_EQUAL             ComparisonOperator = 2
	ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN          ComparisonOperator = 3
	ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN_OR_EQUAL ComparisonOperator = 4
	ComparisonOperator_COMPARISON_OPERATOR_LESS_THAN             ComparisonOperator = 5
	ComparisonOperator_COMPARISON_OPERATOR_LESS_THAN_OR_EQUAL    ComparisonOperator = 6
)

type AttestationRequirement struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type EnforcementConfig struct {
	Level   string   `json:"level"`
	Actions []string `json:"actions"`
}

// YAMLParser handles parsing of YAML compliance policies into protobuf structures
type YAMLParser struct {
	strictMode       bool
	fieldSchemas     map[string]ValidationFieldSchema
	knownPaths       []string
	circularRefs     map[string]bool
	expressionEngine *ExpressionEngine
}

// NewYAMLParser creates a new YAML parser with default configuration
func NewYAMLParser() *YAMLParser {
	// Create default field schema for expression engine
	schema := FieldSchema{
		Fields: map[string]FieldType{
			"loan.principal":            {Type: reflect.TypeOf(float64(0))},
			"loan.interest_rate":        {Type: reflect.TypeOf(float64(0))},
			"loan.amount":               {Type: reflect.TypeOf(float64(0))},
			"loan.debt_to_income_ratio": {Type: reflect.TypeOf(float64(0))},
			"borrower.credit_score":     {Type: reflect.TypeOf(int64(0))},
			"borrower.annual_income":    {Type: reflect.TypeOf(float64(0))},
			"borrower.income":           {Type: reflect.TypeOf(float64(0))},
			"borrower.age":              {Type: reflect.TypeOf(int64(0))},
			"collateral.value":          {Type: reflect.TypeOf(float64(0))},
		},
		AllowUnknownFields: true, // Allow unknown fields for flexibility
	}

	return &YAMLParser{
		strictMode:       false,
		fieldSchemas:     make(map[string]ValidationFieldSchema),
		knownPaths:       getDefaultKnownPaths(),
		circularRefs:     make(map[string]bool),
		expressionEngine: NewExpressionEngine(schema),
	}
}

// SetStrictMode enables or disables strict validation mode
func (p *YAMLParser) SetStrictMode(strict bool) {
	p.strictMode = strict
}

// AddFieldSchema adds a custom field schema for validation
func (p *YAMLParser) AddFieldSchema(path string, schema ValidationFieldSchema) {
	p.fieldSchemas[path] = schema
}

// ParseYAMLPolicy parses YAML content into a CompliancePolicy protobuf structure
func (p *YAMLParser) ParseYAMLPolicy(yamlContent []byte) (*CompliancePolicy, error) {
	// Parse YAML into intermediate representation
	var yamlData map[string]interface{}

	// Create a decoder that captures line numbers
	decoder := yaml.NewDecoder(strings.NewReader(string(yamlContent)))
	decoder.KnownFields(p.strictMode)

	if err := decoder.Decode(&yamlData); err != nil {
		return nil, p.wrapYAMLError(err, "failed to parse YAML")
	}

	// Validate YAML structure
	if err := p.ValidateYAMLStructure(yamlData); err != nil {
		return nil, fmt.Errorf("YAML structure validation failed: %w", err)
	}

	// Convert to protobuf structure
	policy, err := p.convertToProtobuf(yamlData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to protobuf: %w", err)
	}

	return policy, nil
}

// ValidateYAMLStructure validates the YAML structure against expected schema
func (p *YAMLParser) ValidateYAMLStructure(yamlData map[string]interface{}) error {
	// Check required top-level fields
	requiredFields := []string{"policy_id", "jurisdiction", "asset_class", "rules"}
	for _, field := range requiredFields {
		if _, exists := yamlData[field]; !exists {
			return NewValidationError(field, "required field missing", 0, 0)
		}
	}

	// Validate policy_id format
	if policyID, ok := yamlData["policy_id"].(string); ok {
		if !isValidPolicyID(policyID) {
			return NewValidationError("policy_id", "invalid policy ID format", 0, 0)
		}
	} else {
		return NewValidationError("policy_id", "must be a string", 0, 0)
	}

	// Validate jurisdiction format (ISO 3166-1 alpha-2 or custom)
	if jurisdiction, ok := yamlData["jurisdiction"].(string); ok {
		if !isValidJurisdiction(jurisdiction) {
			return NewValidationError("jurisdiction", "invalid jurisdiction format", 0, 0)
		}
	} else {
		return NewValidationError("jurisdiction", "must be a string", 0, 0)
	}

	// Validate rules array
	if rulesData, exists := yamlData["rules"]; exists {
		if rules, ok := rulesData.([]interface{}); ok {
			if len(rules) == 0 {
				return NewValidationError("rules", "must contain at least one rule", 0, 0)
			}

			for i, ruleData := range rules {
				if err := p.validateRule(ruleData, i); err != nil {
					return err
				}
			}
		} else {
			return NewValidationError("rules", "must be an array", 0, 0)
		}
	}

	// Validate attestations if present
	if attestationsData, exists := yamlData["attestations"]; exists {
		if attestations, ok := attestationsData.([]interface{}); ok {
			for i, attestationData := range attestations {
				if err := p.validateAttestation(attestationData, i); err != nil {
					return err
				}
			}
		} else {
			return NewValidationError("attestations", "must be an array", 0, 0)
		}
	}

	// Validate enforcement configuration if present
	if enforcementData, exists := yamlData["enforcement"]; exists {
		if err := p.validateEnforcement(enforcementData); err != nil {
			return err
		}
	}

	return nil
}

// ParsePredicateTree recursively parses predicate structures
func (p *YAMLParser) ParsePredicateTree(predicateData interface{}) (*Predicate, error) {
	if predicateData == nil {
		return nil, fmt.Errorf("predicate data cannot be nil")
	}

	switch data := predicateData.(type) {
	case map[string]interface{}:
		return p.parsePredicateMap(data)
	case map[interface{}]interface{}:
		// Convert map[interface{}]interface{} to map[string]interface{}
		stringMap := make(map[string]interface{})
		for k, v := range data {
			if key, ok := k.(string); ok {
				stringMap[key] = v
			} else {
				return nil, fmt.Errorf("predicate key must be string, got %T", k)
			}
		}
		return p.parsePredicateMap(stringMap)
	default:
		return nil, fmt.Errorf("predicate must be an object, got %T", predicateData)
	}
}

// parsePredicateMap parses a predicate from a map structure
func (p *YAMLParser) parsePredicateMap(data map[string]interface{}) (*Predicate, error) {
	// Check for logical operators (and, or, not)
	if andData, exists := data["and"]; exists {
		return p.parseLogicalPredicate("and", andData)
	}
	if orData, exists := data["or"]; exists {
		return p.parseLogicalPredicate("or", orData)
	}
	if notData, exists := data["not"]; exists {
		return p.parseLogicalPredicate("not", notData)
	}

	// Check for comparison predicate
	if field, exists := data["field"]; exists {
		return p.parseComparisonPredicate(data)
	}

	// Check for existence predicate
	if existsField, exists := data["exists"]; exists {
		return p.parseExistsPredicate(existsField, data)
	}

	// Check for range predicate
	if rangeData, exists := data["range"]; exists {
		return p.parseRangePredicate(rangeData)
	}

	// Check for set predicate
	if setData, exists := data["in"]; exists {
		return p.parseSetPredicate(data, true) // is_member = true
	}
	if setData, exists := data["not_in"]; exists {
		return p.parseSetPredicate(data, false) // is_member = false
	}

	// Check for time predicate
	if timeData, exists := data["time"]; exists {
		return p.parseTimePredicate(timeData)
	}

	// Check for expression predicate
	if exprData, exists := data["expression"]; exists {
		return p.parseExpressionPredicate(exprData, data)
	}

	// Check for regex predicate
	if regexData, exists := data["regex"]; exists {
		return p.parseRegexPredicate(regexData, data)
	}

	return nil, fmt.Errorf("unrecognized predicate structure")
}

// parseLogicalPredicate parses logical predicates (AND, OR, NOT)
func (p *YAMLParser) parseLogicalPredicate(operator string, operandData interface{}) (*Predicate, error) {
	var operands []*Predicate
	var logicalOp LogicalOperator

	switch strings.ToLower(operator) {
	case "and":
		logicalOp = LogicalOperator_LOGICAL_OPERATOR_AND
	case "or":
		logicalOp = LogicalOperator_LOGICAL_OPERATOR_OR
	case "not":
		logicalOp = LogicalOperator_LOGICAL_OPERATOR_NOT
	default:
		return nil, fmt.Errorf("unsupported logical operator: %s", operator)
	}

	// Handle single operand or array of operands
	switch data := operandData.(type) {
	case []interface{}:
		for i, operandData := range data {
			operand, err := p.ParsePredicateTree(operandData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse operand %d: %w", i, err)
			}
			operands = append(operands, operand)
		}
	case interface{}:
		// Single operand (common for NOT)
		operand, err := p.ParsePredicateTree(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse operand: %w", err)
		}
		operands = append(operands, operand)
	default:
		return nil, fmt.Errorf("operands must be an array or single object")
	}

	// Validate operand count
	if logicalOp == LogicalOperator_LOGICAL_OPERATOR_NOT && len(operands) != 1 {
		return nil, fmt.Errorf("NOT operator requires exactly one operand, got %d", len(operands))
	}
	if (logicalOp == LogicalOperator_LOGICAL_OPERATOR_AND || logicalOp == LogicalOperator_LOGICAL_OPERATOR_OR) && len(operands) < 2 {
		return nil, fmt.Errorf("%s operator requires at least two operands, got %d", operator, len(operands))
	}

	return &Predicate{
		PredicateType: &Predicate_Logical{
			Logical: &LogicalPredicate{
				Operator: logicalOp,
				Operands: operands,
			},
		},
	}, nil
}

// parseComparisonPredicate parses comparison predicates
func (p *YAMLParser) parseComparisonPredicate(data map[string]interface{}) (*Predicate, error) {
	fieldPath, ok := data["field"].(string)
	if !ok {
		return nil, fmt.Errorf("field must be a string")
	}

	// Validate field path
	if err := p.validateFieldPath(fieldPath); err != nil {
		return nil, fmt.Errorf("invalid field path '%s': %w", fieldPath, err)
	}

	// Parse operator
	opStr, ok := data["op"].(string)
	if !ok {
		return nil, fmt.Errorf("op (operator) must be a string")
	}

	operator, err := parseComparisonOperator(opStr)
	if err != nil {
		return nil, err
	}

	// Parse value or value_expr
	var value interface{}
	if valueExpr, exists := data["value_expr"]; exists {
		// Handle expression
		exprValue, err := p.parseExpression(valueExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value_expr: %w", err)
		}
		value = exprValue
	} else if val, exists := data["value"]; exists {
		value = val
	} else {
		return nil, fmt.Errorf("either 'value' or 'value_expr' must be specified")
	}

	// Convert value to protobuf Any
	anyValue, err := convertToAny(value)
	if err != nil {
		return nil, fmt.Errorf("failed to convert value: %w", err)
	}

	// Parse field path into FieldPath structure
	fieldPathProto, err := p.parseFieldPath(fieldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse field path: %w", err)
	}

	return &Predicate{
		PredicateType: &Predicate_Comparison{
			Comparison: &ComparisonPredicate{
				FieldPath: fieldPathProto,
				Operator:  operator,
				Value:     anyValue,
			},
		},
	}, nil
}

// parseExistsPredicate parses existence predicates
func (p *YAMLParser) parseExistsPredicate(fieldData interface{}, data map[string]interface{}) (*Predicate, error) {
	fieldPath, ok := fieldData.(string)
	if !ok {
		return nil, fmt.Errorf("exists field must be a string")
	}

	// Validate field path
	if err := p.validateFieldPath(fieldPath); err != nil {
		return nil, fmt.Errorf("invalid field path '%s': %w", fieldPath, err)
	}

	shouldExist := true
	if shouldExistData, exists := data["should_exist"]; exists {
		if val, ok := shouldExistData.(bool); ok {
			shouldExist = val
		}
	}

	fieldPathProto, err := p.parseFieldPath(fieldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse field path: %w", err)
	}

	return &Predicate{
		PredicateType: &Predicate_Exists{
			Exists: &ExistsPredicate{
				FieldPath:   fieldPathProto,
				ShouldExist: shouldExist,
			},
		},
	}, nil
}

// parseRangePredicate parses range predicates
func (p *YAMLParser) parseRangePredicate(rangeData interface{}) (*Predicate, error) {
	rangeMap, ok := rangeData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("range must be an object")
	}

	fieldPath, ok := rangeMap["field"].(string)
	if !ok {
		return nil, fmt.Errorf("range field must be a string")
	}

	// Validate field path
	if err := p.validateFieldPath(fieldPath); err != nil {
		return nil, fmt.Errorf("invalid field path '%s': %w", fieldPath, err)
	}

	minValue, minExists := rangeMap["min"]
	maxValue, maxExists := rangeMap["max"]

	if !minExists && !maxExists {
		return nil, fmt.Errorf("range must specify at least min or max")
	}

	minInclusive := true
	if val, exists := rangeMap["min_inclusive"]; exists {
		if b, ok := val.(bool); ok {
			minInclusive = b
		}
	}

	maxInclusive := true
	if val, exists := rangeMap["max_inclusive"]; exists {
		if b, ok := val.(bool); ok {
			maxInclusive = b
		}
	}

	fieldPathProto, err := p.parseFieldPath(fieldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse field path: %w", err)
	}

	rangePred := &RangePredicate{
		FieldPath:    fieldPathProto,
		MinInclusive: minInclusive,
		MaxInclusive: maxInclusive,
	}

	if minExists {
		minAny, err := convertToAny(minValue)
		if err != nil {
			return nil, fmt.Errorf("failed to convert min value: %w", err)
		}
		rangePred.MinValue = minAny
	}

	if maxExists {
		maxAny, err := convertToAny(maxValue)
		if err != nil {
			return nil, fmt.Errorf("failed to convert max value: %w", err)
		}
		rangePred.MaxValue = maxAny
	}

	return &Predicate{
		PredicateType: &Predicate_Range{
			Range: rangePred,
		},
	}, nil
}

// parseSetPredicate parses set membership predicates
func (p *YAMLParser) parseSetPredicate(data map[string]interface{}, isMember bool) (*Predicate, error) {
	fieldPath, ok := data["field"].(string)
	if !ok {
		return nil, fmt.Errorf("field must be a string")
	}

	// Validate field path
	if err := p.validateFieldPath(fieldPath); err != nil {
		return nil, fmt.Errorf("invalid field path '%s': %w", fieldPath, err)
	}

	var valuesData interface{}
	if isMember {
		valuesData = data["in"]
	} else {
		valuesData = data["not_in"]
	}

	values, ok := valuesData.([]interface{})
	if !ok {
		return nil, fmt.Errorf("values must be an array")
	}

	var anyValues []*any.Any
	for i, value := range values {
		anyValue, err := convertToAny(value)
		if err != nil {
			return nil, fmt.Errorf("failed to convert value %d: %w", i, err)
		}
		anyValues = append(anyValues, anyValue)
	}

	fieldPathProto, err := p.parseFieldPath(fieldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse field path: %w", err)
	}

	return &Predicate{
		PredicateType: &Predicate_Set{
			Set: &SetPredicate{
				FieldPath: fieldPathProto,
				Values:    anyValues,
				IsMember:  isMember,
			},
		},
	}, nil
}

// parseTimePredicate parses time-based predicates
func (p *YAMLParser) parseTimePredicate(timeData interface{}) (*Predicate, error) {
	timeMap, ok := timeData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("time predicate must be an object")
	}

	fieldPath, ok := timeMap["field"].(string)
	if !ok {
		return nil, fmt.Errorf("time field must be a string")
	}

	// Validate field path
	if err := p.validateFieldPath(fieldPath); err != nil {
		return nil, fmt.Errorf("invalid field path '%s': %w", fieldPath, err)
	}

	opStr, ok := timeMap["op"].(string)
	if !ok {
		return nil, fmt.Errorf("time operator must be a string")
	}

	operator, err := parseTimeOperator(opStr)
	if err != nil {
		return nil, err
	}

	fieldPathProto, err := p.parseFieldPath(fieldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse field path: %w", err)
	}

	timePred := &TimePredicate{
		FieldPath: fieldPathProto,
		Operator:  operator,
	}

	// Parse reference time if present
	if refTimeData, exists := timeMap["reference_time"]; exists {
		refTime, err := parseTimestamp(refTimeData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reference_time: %w", err)
		}
		timePred.ReferenceTime = refTime
	}

	// Parse duration if present
	if durationData, exists := timeMap["duration"]; exists {
		duration, err := parseDuration(durationData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse duration: %w", err)
		}
		timePred.DurationSeconds = duration
	}

	return &Predicate{
		PredicateType: &Predicate_Time{
			Time: timePred,
		},
	}, nil
}

// parseExpressionPredicate parses expression predicates
func (p *YAMLParser) parseExpressionPredicate(exprData interface{}, data map[string]interface{}) (*Predicate, error) {
	expression, ok := exprData.(string)
	if !ok {
		return nil, fmt.Errorf("expression must be a string")
	}

	// Parse expression language if specified
	language := ExpressionLanguage_EXPRESSION_LANGUAGE_CEL // default
	if langData, exists := data["language"]; exists {
		if langStr, ok := langData.(string); ok {
			parsedLang, err := parseExpressionLanguage(langStr)
			if err != nil {
				return nil, fmt.Errorf("invalid expression language: %w", err)
			}
			language = parsedLang
		}
	}

	// Parse variables if present
	var variables map[string]*any.Any
	if varsData, exists := data["variables"]; exists {
		if varsMap, ok := varsData.(map[string]interface{}); ok {
			variables = make(map[string]*any.Any)
			for k, v := range varsMap {
				anyValue, err := convertToAny(v)
				if err != nil {
					return nil, fmt.Errorf("failed to convert variable %s: %w", k, err)
				}
				variables[k] = anyValue
			}
		}
	}

	return &Predicate{
		PredicateType: &Predicate_Expression{
			Expression: &ExpressionPredicate{
				Expression: expression,
				Language:   language,
				Variables:  variables,
			},
		},
	}, nil
}

// parseRegexPredicate parses regex predicates
func (p *YAMLParser) parseRegexPredicate(regexData interface{}, data map[string]interface{}) (*Predicate, error) {
	fieldPath, ok := data["field"].(string)
	if !ok {
		return nil, fmt.Errorf("regex field must be a string")
	}

	pattern, ok := regexData.(string)
	if !ok {
		return nil, fmt.Errorf("regex pattern must be a string")
	}

	// Validate field path
	if err := p.validateFieldPath(fieldPath); err != nil {
		return nil, fmt.Errorf("invalid field path '%s': %w", fieldPath, err)
	}

	// Validate regex pattern
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	fieldPathProto, err := p.parseFieldPath(fieldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse field path: %w", err)
	}

	regexPred := &RegexPredicate{
		FieldPath: fieldPathProto,
		Pattern:   pattern,
	}

	// Parse flags if present
	if flagsData, exists := data["flags"]; exists {
		if flagsArray, ok := flagsData.([]interface{}); ok {
			for _, flagData := range flagsArray {
				if flagStr, ok := flagData.(string); ok {
					flag, err := parseRegexFlag(flagStr)
					if err != nil {
						return nil, fmt.Errorf("invalid regex flag: %w", err)
					}
					regexPred.Flags = append(regexPred.Flags, flag)
				}
			}
		}
	}

	return &Predicate{
		PredicateType: &Predicate_Regex{
			Regex: regexPred,
		},
	}, nil
}

// validateRule validates a single rule structure
func (p *YAMLParser) validateRule(ruleData interface{}, index int) error {
	rule, ok := ruleData.(map[string]interface{})
	if !ok {
		return NewValidationError(fmt.Sprintf("rules[%d]", index), "must be an object", 0, 0)
	}

	// Check required fields
	requiredFields := []string{"name", "predicate"}
	for _, field := range requiredFields {
		if _, exists := rule[field]; !exists {
			return NewValidationError(fmt.Sprintf("rules[%d].%s", index, field), "required field missing", 0, 0)
		}
	}

	// Validate predicate structure
	if predicateData, exists := rule["predicate"]; exists {
		if _, err := p.ParsePredicateTree(predicateData); err != nil {
			return NewValidationError(fmt.Sprintf("rules[%d].predicate", index), fmt.Sprintf("invalid predicate: %v", err), 0, 0)
		}
	}

	return nil
}

// validateAttestation validates an attestation requirement
func (p *YAMLParser) validateAttestation(attestationData interface{}, index int) error {
	attestation, ok := attestationData.(map[string]interface{})
	if !ok {
		return NewValidationError(fmt.Sprintf("attestations[%d]", index), "must be an object", 0, 0)
	}

	// Check required fields
	requiredFields := []string{"name", "type"}
	for _, field := range requiredFields {
		if _, exists := attestation[field]; !exists {
			return NewValidationError(fmt.Sprintf("attestations[%d].%s", index, field), "required field missing", 0, 0)
		}
	}

	// Validate attestation type
	if typeData, exists := attestation["type"]; exists {
		if typeStr, ok := typeData.(string); ok {
			if !isValidAttestationType(typeStr) {
				return NewValidationError(fmt.Sprintf("attestations[%d].type", index), fmt.Sprintf("invalid attestation type: %s", typeStr), 0, 0)
			}
		} else {
			return NewValidationError(fmt.Sprintf("attestations[%d].type", index), "must be a string", 0, 0)
		}
	}

	return nil
}

// validateEnforcement validates enforcement configuration
func (p *YAMLParser) validateEnforcement(enforcementData interface{}) error {
	enforcement, ok := enforcementData.(map[string]interface{})
	if !ok {
		return NewValidationError("enforcement", "must be an object", 0, 0)
	}

	// Validate enforcement level if present
	if levelData, exists := enforcement["level"]; exists {
		if levelStr, ok := levelData.(string); ok {
			if !isValidEnforcementLevel(levelStr) {
				return NewValidationError("enforcement.level", fmt.Sprintf("invalid enforcement level: %s", levelStr), 0, 0)
			}
		} else {
			return NewValidationError("enforcement.level", "must be a string", 0, 0)
		}
	}

	// Validate actions if present
	if actionsData, exists := enforcement["actions"]; exists {
		if actions, ok := actionsData.([]interface{}); ok {
			for i, actionData := range actions {
				if actionStr, ok := actionData.(string); ok {
					if !isValidEnforcementAction(actionStr) {
						return NewValidationError(fmt.Sprintf("enforcement.actions[%d]", i), fmt.Sprintf("invalid enforcement action: %s", actionStr), 0, 0)
					}
				} else {
					return NewValidationError(fmt.Sprintf("enforcement.actions[%d]", i), "must be a string", 0, 0)
				}
			}
		} else {
			return NewValidationError("enforcement.actions", "must be an array", 0, 0)
		}
	}

	return nil
}

// parseFieldPath parses a dot-notation field path into FieldPath structure
func (p *YAMLParser) parseFieldPath(path string) (*FieldPath, error) {
	if path == "" {
		return nil, fmt.Errorf("field path cannot be empty")
	}

	// Split path by dots, handling array access and function calls
	components, err := parsePathComponents(path)
	if err != nil {
		return nil, err
	}

	var pathComponents []*PathComponent
	for _, comp := range components {
		pathComp, err := p.parsePathComponent(comp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse path component '%s': %w", comp, err)
		}
		pathComponents = append(pathComponents, pathComp)
	}

	return &FieldPath{
		Components: pathComponents,
		RawPath:    path,
	}, nil
}

// parsePathComponent parses a single path component
func (p *YAMLParser) parsePathComponent(component string) (*PathComponent, error) {
	// Check for array access (e.g., "items[0]" or "items[amount > 100]")
	if strings.Contains(component, "[") && strings.HasSuffix(component, "]") {
		return p.parseArrayAccess(component)
	}

	// Check for function call (e.g., "sum()" or "max(amount)")
	if strings.Contains(component, "(") && strings.HasSuffix(component, ")") {
		return p.parseFunctionCall(component)
	}

	// Regular field access
	return &PathComponent{
		ComponentType: &PathComponent_FieldName{
			FieldName: component,
		},
	}, nil
}

// parseArrayAccess parses array access syntax
func (p *YAMLParser) parseArrayAccess(component string) (*PathComponent, error) {
	bracketStart := strings.Index(component, "[")
	bracketEnd := strings.LastIndex(component, "]")

	if bracketStart == -1 || bracketEnd == -1 || bracketEnd <= bracketStart {
		return nil, fmt.Errorf("invalid array access syntax")
	}

	fieldName := component[:bracketStart]
	indexContent := component[bracketStart+1 : bracketEnd]

	// Check if it's a numeric index
	if index, err := strconv.Atoi(indexContent); err == nil {
		return &PathComponent{
			ComponentType: &PathComponent_ArrayIndex{
				ArrayIndex: int32(index),
			},
		}, nil
	}

	// Otherwise, treat as array filter
	return &PathComponent{
		ComponentType: &PathComponent_ArrayFilter{
			ArrayFilter: indexContent,
		},
	}, nil
}

// parseFunctionCall parses function call syntax
func (p *YAMLParser) parseFunctionCall(component string) (*PathComponent, error) {
	parenStart := strings.Index(component, "(")
	parenEnd := strings.LastIndex(component, ")")

	if parenStart == -1 || parenEnd == -1 || parenEnd <= parenStart {
		return nil, fmt.Errorf("invalid function call syntax")
	}

	functionName := component[:parenStart]
	argsContent := component[parenStart+1 : parenEnd]

	functionCall := &FunctionCall{
		Name: functionName,
	}

	// Parse arguments if present
	if argsContent != "" {
		args := strings.Split(argsContent, ",")
		for _, arg := range args {
			arg = strings.TrimSpace(arg)
			// For now, treat all arguments as strings
			// More sophisticated parsing would be needed for complex types
			anyArg, err := convertToAny(arg)
			if err != nil {
				return nil, fmt.Errorf("failed to convert function argument: %w", err)
			}
			functionCall.Arguments = append(functionCall.Arguments, anyArg)
		}
	}

	return &PathComponent{
		ComponentType: &PathComponent_FunctionCall{
			FunctionCall: functionCall,
		},
	}, nil
}

// validateFieldPath validates a field path against known schemas
func (p *YAMLParser) validateFieldPath(path string) error {
	// Check against known paths
	if len(p.knownPaths) > 0 {
		pathValid := false
		for _, knownPath := range p.knownPaths {
			if strings.HasPrefix(path, knownPath) || matchesPattern(path, knownPath) {
				pathValid = true
				break
			}
		}
		if !pathValid && p.strictMode {
			return fmt.Errorf("unknown field path (strict mode enabled)")
		}
	}

	// Check for circular references
	if p.circularRefs[path] {
		return fmt.Errorf("circular reference detected")
	}

	// Validate field schema if available
	if schema, exists := p.fieldSchemas[path]; exists {
		// Perform schema-specific validation
		if err := p.validateAgainstSchema(path, schema); err != nil {
			return err
		}
	}

	return nil
}

// parseExpression parses a value expression using the ExpressionEngine
func (p *YAMLParser) parseExpression(exprData interface{}) (interface{}, error) {
	exprStr, ok := exprData.(string)
	if !ok {
		return exprData, nil // Return as-is if not a string
	}

	// Check if it looks like an expression (contains field references or operators)
	if isExpression(exprStr) {
		// Use the ExpressionEngine to parse and validate the expression
		expr, err := p.expressionEngine.ParseExpression(exprStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expression '%s': %w", exprStr, err)
		}

		// Validate the expression with basic context
		basicContext := map[string]interface{}{
			// Add some default audit context if needed
			"audit_context": map[string]interface{}{
				"request_id": "yaml_parse",
				"source":     "yaml_parser",
			},
		}

		if err := p.expressionEngine.ValidateExpression(expr, basicContext); err != nil {
			return nil, fmt.Errorf("expression validation failed for '%s': %w", exprStr, err)
		}

		// Convert to protobuf format for storage
		protoExpr, err := p.expressionEngine.CompileToProtobuf(expr)
		if err != nil {
			return nil, fmt.Errorf("failed to compile expression '%s' to protobuf: %w", exprStr, err)
		}

		// Return the compiled expression
		return ParsedExpression{
			Raw:        exprStr,
			Type:       expr.Type.String(),
			Compiled:   protoExpr,
			FieldPaths: expr.FieldPaths,
			Functions:  expr.Functions,
		}, nil
	}

	return exprData, nil
}

// Utility functions - these are defined in validation.go

// convertToProtobuf converts the validated YAML data to protobuf structure
func (p *YAMLParser) convertToProtobuf(yamlData map[string]interface{}) (*CompliancePolicy, error) {
	policy := &CompliancePolicy{}

	// Basic fields
	if val, exists := yamlData["policy_id"]; exists {
		policy.PolicyId = val.(string)
	}

	if val, exists := yamlData["version"]; exists {
		policy.Version = val.(string)
	}

	if val, exists := yamlData["jurisdiction"]; exists {
		policy.Jurisdiction = val.(string)
	}

	if val, exists := yamlData["asset_class"]; exists {
		policy.AssetClass = val.(string)
	}

	// Parse rules
	if rulesData, exists := yamlData["rules"]; exists {
		if rules, ok := rulesData.([]interface{}); ok {
			for _, ruleData := range rules {
				rule, err := p.convertRule(ruleData)
				if err != nil {
					return nil, fmt.Errorf("failed to convert rule: %w", err)
				}
				policy.Rules = append(policy.Rules, rule)
			}
		}
	}

	// Parse attestations
	if attestationsData, exists := yamlData["attestations"]; exists {
		if attestations, ok := attestationsData.([]interface{}); ok {
			for _, attestationData := range attestations {
				attestation, err := p.convertAttestation(attestationData)
				if err != nil {
					return nil, fmt.Errorf("failed to convert attestation: %w", err)
				}
				policy.Attestations = append(policy.Attestations, attestation)
			}
		}
	}

	// Parse enforcement
	if enforcementData, exists := yamlData["enforcement"]; exists {
		enforcement, err := p.convertEnforcement(enforcementData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert enforcement: %w", err)
		}
		policy.Enforcement = enforcement
	}

	// Parse metadata
	if metadataData, exists := yamlData["metadata"]; exists {
		metadata, err := p.convertMetadata(metadataData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert metadata: %w", err)
		}
		policy.Metadata = metadata
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = timestamppb.New(now)

	return policy, nil
}

// convertRule converts a rule from YAML to protobuf
func (p *YAMLParser) convertRule(ruleData interface{}) (*PolicyRule, error) {
	ruleMap, ok := ruleData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rule must be an object")
	}

	rule := &PolicyRule{}

	if name, exists := ruleMap["name"]; exists {
		rule.Name = name.(string)
	}

	if description, exists := ruleMap["description"]; exists {
		rule.Description = description.(string)
	}

	if predicateData, exists := ruleMap["predicate"]; exists {
		predicate, err := p.ParsePredicateTree(predicateData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rule predicate: %w", err)
		}
		rule.Predicate = predicate
	}

	if required, exists := ruleMap["required"]; exists {
		if reqBool, ok := required.(bool); ok {
			rule.Required = reqBool
		}
	}

	return rule, nil
}

// convertAttestation converts an attestation from YAML to protobuf
func (p *YAMLParser) convertAttestation(attestationData interface{}) (*AttestationRequirement, error) {
	attestationMap, ok := attestationData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("attestation must be an object")
	}

	attestation := &AttestationRequirement{}

	if name, exists := attestationMap["name"]; exists {
		attestation.Name = name.(string)
	}

	if description, exists := attestationMap["description"]; exists {
		attestation.Description = description.(string)
	}

	if typeData, exists := attestationMap["type"]; exists {
		if typeStr, ok := typeData.(string); ok {
			attestationType, err := parseAttestationType(typeStr)
			if err != nil {
				return nil, fmt.Errorf("invalid attestation type: %w", err)
			}
			attestation.Type = attestationType
		}
	}

	if required, exists := attestationMap["required"]; exists {
		if reqBool, ok := required.(bool); ok {
			attestation.Required = reqBool
		}
	}

	return attestation, nil
}

// convertEnforcement converts enforcement configuration from YAML to protobuf
func (p *YAMLParser) convertEnforcement(enforcementData interface{}) (*EnforcementConfig, error) {
	enforcementMap, ok := enforcementData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("enforcement must be an object")
	}

	enforcement := &EnforcementConfig{}

	if levelData, exists := enforcementMap["level"]; exists {
		if levelStr, ok := levelData.(string); ok {
			level, err := parseEnforcementLevel(levelStr)
			if err != nil {
				return nil, fmt.Errorf("invalid enforcement level: %w", err)
			}
			enforcement.Level = level
		}
	}

	if actionsData, exists := enforcementMap["actions"]; exists {
		if actions, ok := actionsData.([]interface{}); ok {
			for _, actionData := range actions {
				if actionStr, ok := actionData.(string); ok {
					action, err := parseEnforcementAction(actionStr)
					if err != nil {
						return nil, fmt.Errorf("invalid enforcement action: %w", err)
					}
					enforcement.Actions = append(enforcement.Actions, action)
				}
			}
		}
	}

	return enforcement, nil
}

// convertMetadata converts metadata from YAML to protobuf
func (p *YAMLParser) convertMetadata(metadataData interface{}) (*PolicyMetadata, error) {
	metadataMap, ok := metadataData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("metadata must be an object")
	}

	metadata := &PolicyMetadata{}

	if title, exists := metadataMap["title"]; exists {
		metadata.Title = title.(string)
	}

	if description, exists := metadataMap["description"]; exists {
		metadata.Description = description.(string)
	}

	if tagsData, exists := metadataMap["tags"]; exists {
		if tags, ok := tagsData.([]interface{}); ok {
			for _, tagData := range tags {
				if tagStr, ok := tagData.(string); ok {
					metadata.Tags = append(metadata.Tags, tagStr)
				}
			}
		}
	}

	return metadata, nil
}
