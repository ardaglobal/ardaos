package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// SchemaValidator provides JSON Schema validation for compliance policies
type SchemaValidator struct {
	schemaLoader gojsonschema.JSONLoader
	schemaPath   string
}

// ValidationResult contains the results of schema validation
type ValidationResult struct {
	Valid      bool                   `json:"valid"`
	Errors     []ValidationError      `json:"errors,omitempty"`
	Warnings   []ValidationWarning    `json:"warnings,omitempty"`
	SchemaPath string                 `json:"schema_path"`
	Document   map[string]interface{} `json:"-"` // Validated document for further processing
}

// ValidationError represents a schema validation error
type ValidationError struct {
	Field      string `json:"field"`
	Value      string `json:"value,omitempty"`
	Type       string `json:"type"`
	Message    string `json:"message"`
	SchemaPath string `json:"schema_path,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// ValidationWarning represents a schema validation warning
type ValidationWarning struct {
	Field      string `json:"field"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

// NewSchemaValidator creates a new JSON Schema validator for compliance policies
func NewSchemaValidator() (*SchemaValidator, error) {
	// Get the schema path relative to the current working directory
	workDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	schemaPath := filepath.Join(workDir, "schemas", "compliance-policy.json")

	// Check if schema file exists
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		// Try relative to the executable
		execPath, err := os.Executable()
		if err == nil {
			execDir := filepath.Dir(execPath)
			schemaPath = filepath.Join(execDir, "schemas", "compliance-policy.json")
		}
	}

	// Load the JSON Schema
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)

	return &SchemaValidator{
		schemaLoader: schemaLoader,
		schemaPath:   schemaPath,
	}, nil
}

// NewSchemaValidatorFromFile creates a validator with a custom schema file
func NewSchemaValidatorFromFile(schemaPath string) (*SchemaValidator, error) {
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("schema file does not exist: %s", schemaPath)
	}

	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)

	return &SchemaValidator{
		schemaLoader: schemaLoader,
		schemaPath:   schemaPath,
	}, nil
}

// ValidateYAMLFile validates a YAML file against the compliance policy schema
func (v *SchemaValidator) ValidateYAMLFile(yamlFilePath string) (*ValidationResult, error) {
	// Read and parse YAML file
	yamlData, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	return v.ValidateYAML(yamlData)
}

// ValidateYAML validates YAML content against the compliance policy schema
func (v *SchemaValidator) ValidateYAML(yamlContent []byte) (*ValidationResult, error) {
	// Parse YAML to intermediate map
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(yamlContent, &yamlData); err != nil {
		return &ValidationResult{
			Valid:      false,
			SchemaPath: v.schemaPath,
			Errors: []ValidationError{{
				Field:      "root",
				Type:       "yaml_parse_error",
				Message:    fmt.Sprintf("Failed to parse YAML: %v", err),
				Suggestion: "Check YAML syntax - ensure proper indentation, colons, and no tabs",
			}},
		}, nil
	}

	// Convert to JSON for schema validation
	jsonData, err := json.Marshal(yamlData)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	return v.ValidateJSON(jsonData, yamlData)
}

// ValidateJSON validates JSON content against the schema
func (v *SchemaValidator) ValidateJSON(jsonContent []byte, originalData map[string]interface{}) (*ValidationResult, error) {
	// Create document loader from JSON content
	documentLoader := gojsonschema.NewBytesLoader(jsonContent)

	// Perform validation
	result, err := gojsonschema.Validate(v.schemaLoader, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("schema validation failed: %w", err)
	}

	// Convert validation results
	validationResult := &ValidationResult{
		Valid:      result.Valid(),
		SchemaPath: v.schemaPath,
		Document:   originalData,
		Errors:     make([]ValidationError, 0),
		Warnings:   make([]ValidationWarning, 0),
	}

	// Process validation errors
	for _, resultError := range result.Errors() {
		validationError := ValidationError{
			Field:      resultError.Field(),
			Value:      fmt.Sprintf("%v", resultError.Value()),
			Type:       resultError.Type(),
			Message:    resultError.Description(),
			SchemaPath: resultError.Context().String(),
			Suggestion: v.generateSuggestion(resultError),
		}
		validationResult.Errors = append(validationResult.Errors, validationError)
	}

	// Generate warnings for best practices
	v.generateWarnings(originalData, validationResult)

	return validationResult, nil
}

// ValidateReader validates content from an io.Reader
func (v *SchemaValidator) ValidateReader(reader io.Reader) (*ValidationResult, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	return v.ValidateYAML(content)
}

// generateSuggestion creates helpful suggestions based on validation errors
func (v *SchemaValidator) generateSuggestion(err gojsonschema.ResultError) string {
	switch err.Type() {
	case "required":
		return fmt.Sprintf("Add the required field: %s", err.Field())
	case "enum":
		if possibleValues, ok := err.Details()["allowed"]; ok {
			return fmt.Sprintf("Use one of the allowed values: %v", possibleValues)
		}
		return "Check the allowed values for this field"
	case "pattern":
		return "Ensure the value matches the required pattern (check regex)"
	case "minimum":
		if min, ok := err.Details()["min"]; ok {
			return fmt.Sprintf("Value must be at least %v", min)
		}
		return "Increase the value to meet the minimum requirement"
	case "maximum":
		if max, ok := err.Details()["max"]; ok {
			return fmt.Sprintf("Value must not exceed %v", max)
		}
		return "Decrease the value to meet the maximum requirement"
	case "minLength":
		if minLen, ok := err.Details()["min"]; ok {
			return fmt.Sprintf("String must be at least %v characters long", minLen)
		}
		return "Increase the string length"
	case "maxLength":
		if maxLen, ok := err.Details()["max"]; ok {
			return fmt.Sprintf("String must not exceed %v characters", maxLen)
		}
		return "Reduce the string length"
	case "type":
		if expectedType, ok := err.Details()["expected"]; ok {
			return fmt.Sprintf("Expected type: %v", expectedType)
		}
		return "Check the expected data type for this field"
	case "oneOf":
		return "Value should match exactly one of the allowed schemas"
	case "additionalProperties":
		return "Remove unknown properties or check field names for typos"
	default:
		return "Check the policy documentation for field requirements"
	}
}

// generateWarnings creates warnings for best practices and recommendations
func (v *SchemaValidator) generateWarnings(data map[string]interface{}, result *ValidationResult) {
	// Check for missing optional but recommended fields
	if metadata, ok := data["metadata"].(map[string]interface{}); ok {
		if _, hasTitle := metadata["title"]; !hasTitle {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Field:      "metadata.title",
				Message:    "Missing title in metadata",
				Suggestion: "Add a descriptive title for better policy documentation",
			})
		}
		if _, hasDescription := metadata["description"]; !hasDescription {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Field:      "metadata.description",
				Message:    "Missing description in metadata",
				Suggestion: "Add a detailed description explaining the policy purpose",
			})
		}
	} else {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "metadata",
			Message:    "Missing metadata section",
			Suggestion: "Add metadata section with title, description, and author information",
		})
	}

	// Check for enforcement configuration
	if _, hasEnforcement := data["enforcement"]; !hasEnforcement {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "enforcement",
			Message:    "Missing enforcement configuration",
			Suggestion: "Add enforcement section to specify how policy violations should be handled",
		})
	}

	// Check rule complexity
	if rules, ok := data["rules"].([]interface{}); ok {
		if len(rules) > 20 {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Field:      "rules",
				Message:    fmt.Sprintf("Large number of rules (%d)", len(rules)),
				Suggestion: "Consider breaking complex policies into multiple smaller policies",
			})
		}

		// Check for rules without descriptions
		for i, rule := range rules {
			if ruleMap, ok := rule.(map[string]interface{}); ok {
				if _, hasDescription := ruleMap["description"]; !hasDescription {
					result.Warnings = append(result.Warnings, ValidationWarning{
						Field:      fmt.Sprintf("rules[%d].description", i),
						Message:    "Rule missing description",
						Suggestion: "Add description to explain the rule's purpose and requirements",
					})
				}
			}
		}
	}

	// Check for jurisdiction-specific recommendations
	if jurisdiction, ok := data["jurisdiction"].(string); ok {
		v.addJurisdictionWarnings(jurisdiction, data, result)
	}

	// Check for asset class-specific recommendations
	if assetClass, ok := data["asset_class"].(string); ok {
		v.addAssetClassWarnings(assetClass, data, result)
	}
}

// addJurisdictionWarnings adds jurisdiction-specific warnings and recommendations
func (v *SchemaValidator) addJurisdictionWarnings(jurisdiction string, data map[string]interface{}, result *ValidationResult) {
	switch jurisdiction {
	case "US":
		// Check for CFPB-related requirements
		if assetClass, ok := data["asset_class"].(string); ok && assetClass == "credit-card" {
			// Check for ability-to-pay rules
			if !v.hasRuleWithTag(data, "ability-to-pay") {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Field:      "rules",
					Message:    "Consider adding ability-to-pay assessment rules for US credit card compliance",
					Suggestion: "Add rules that assess borrower's ability to repay as required by CFPB regulations",
				})
			}
		}
	case "EU":
		// Check for GDPR and PSD2 requirements
		if !v.hasAttestationType(data, "regulatory_approval") {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Field:      "attestations",
				Message:    "Consider adding regulatory approval attestation for EU compliance",
				Suggestion: "Add regulatory approval attestation to ensure PSD2 compliance",
			})
		}
	}
}

// addAssetClassWarnings adds asset class-specific warnings
func (v *SchemaValidator) addAssetClassWarnings(assetClass string, data map[string]interface{}, result *ValidationResult) {
	switch assetClass {
	case "credit-card":
		if !v.hasRuleWithField(data, "borrower.credit_score") {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Field:      "rules",
				Message:    "Consider adding credit score validation for credit card policies",
				Suggestion: "Add rules that validate borrower credit score requirements",
			})
		}
	case "equipment-lease":
		if !v.hasRuleWithField(data, "collateral.value") {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Field:      "rules",
				Message:    "Consider adding collateral valuation rules for equipment lease policies",
				Suggestion: "Add rules that validate equipment collateral value",
			})
		}
	}
}

// Helper functions for checking policy content

func (v *SchemaValidator) hasRuleWithTag(data map[string]interface{}, tag string) bool {
	rules, ok := data["rules"].([]interface{})
	if !ok {
		return false
	}

	for _, rule := range rules {
		if ruleMap, ok := rule.(map[string]interface{}); ok {
			if tags, ok := ruleMap["tags"].([]interface{}); ok {
				for _, t := range tags {
					if tagStr, ok := t.(string); ok && tagStr == tag {
						return true
					}
				}
			}
		}
	}
	return false
}

func (v *SchemaValidator) hasRuleWithField(data map[string]interface{}, fieldPath string) bool {
	rules, ok := data["rules"].([]interface{})
	if !ok {
		return false
	}

	for _, rule := range rules {
		if ruleMap, ok := rule.(map[string]interface{}); ok {
			if v.predicateContainsField(ruleMap["predicate"], fieldPath) {
				return true
			}
		}
	}
	return false
}

func (v *SchemaValidator) predicateContainsField(predicate interface{}, fieldPath string) bool {
	predicateMap, ok := predicate.(map[string]interface{})
	if !ok {
		return false
	}

	// Check direct field reference
	if field, ok := predicateMap["field"].(string); ok && field == fieldPath {
		return true
	}

	// Check logical predicates recursively
	if andPredicates, ok := predicateMap["and"].([]interface{}); ok {
		for _, p := range andPredicates {
			if v.predicateContainsField(p, fieldPath) {
				return true
			}
		}
	}

	if orPredicates, ok := predicateMap["or"].([]interface{}); ok {
		for _, p := range orPredicates {
			if v.predicateContainsField(p, fieldPath) {
				return true
			}
		}
	}

	if notPredicate, ok := predicateMap["not"]; ok {
		return v.predicateContainsField(notPredicate, fieldPath)
	}

	// Check range predicate
	if rangePred, ok := predicateMap["range"].(map[string]interface{}); ok {
		if field, ok := rangePred["field"].(string); ok && field == fieldPath {
			return true
		}
	}

	return false
}

func (v *SchemaValidator) hasAttestationType(data map[string]interface{}, attestationType string) bool {
	attestations, ok := data["attestations"].([]interface{})
	if !ok {
		return false
	}

	for _, attestation := range attestations {
		if attestationMap, ok := attestation.(map[string]interface{}); ok {
			if attType, ok := attestationMap["type"].(string); ok && attType == attestationType {
				return true
			}
		}
	}
	return false
}
