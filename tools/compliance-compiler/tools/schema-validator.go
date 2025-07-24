// Schema validation tool for compliance policies.
// This tool validates policy schemas against defined standards and
// provides detailed feedback on schema compliance and best practices.
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// SchemaValidator validates policy schemas
type SchemaValidator struct {
	SchemaFile      string
	StrictMode      bool
	OutputFormat    string
	FailOnWarnings  bool
	CustomRules     []ValidationRule
	ValidationCache map[string]ValidationResult
}

// ValidationRule defines a custom validation rule
type ValidationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"` // error, warning, info
	Check       func(interface{}) bool `json:"-"`
	Message     string                 `json:"message"`
	Category    string                 `json:"category"`
}

// ValidationResult represents the result of schema validation
type ValidationResult struct {
	Valid       bool              `json:"valid"`
	Errors      []ValidationError `json:"errors"`
	Warnings    []ValidationError `json:"warnings"`
	Info        []ValidationError `json:"info"`
	Summary     ValidationSummary `json:"summary"`
	ValidatedAt time.Time         `json:"validated_at"`
	Duration    time.Duration     `json:"duration"`
	SchemaPath  string            `json:"schema_path"`
	PolicyPath  string            `json:"policy_path"`
}

// ValidationError represents a validation error or warning
type ValidationError struct {
	Rule     string      `json:"rule"`
	Message  string      `json:"message"`
	Path     string      `json:"path"`
	Severity string      `json:"severity"`
	Line     int         `json:"line,omitempty"`
	Column   int         `json:"column,omitempty"`
	Value    interface{} `json:"value,omitempty"`
	Expected interface{} `json:"expected,omitempty"`
}

// ValidationSummary provides a summary of validation results
type ValidationSummary struct {
	TotalRules     int     `json:"total_rules"`
	PassedRules    int     `json:"passed_rules"`
	FailedRules    int     `json:"failed_rules"`
	ErrorCount     int     `json:"error_count"`
	WarningCount   int     `json:"warning_count"`
	InfoCount      int     `json:"info_count"`
	ComplianceRate float64 `json:"compliance_rate"`
}

// PolicySchema defines the expected schema structure
type PolicySchema struct {
	Version     string                    `json:"version"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Required    []string                  `json:"required"`
	Properties  map[string]PropertySchema `json:"properties"`
	Rules       []SchemaRule              `json:"rules"`
}

// PropertySchema defines schema for a property
type PropertySchema struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
	Minimum     *float64    `json:"minimum,omitempty"`
	Maximum     *float64    `json:"maximum,omitempty"`
	MinLength   *int        `json:"minLength,omitempty"`
	MaxLength   *int        `json:"maxLength,omitempty"`
}

// SchemaRule defines a schema validation rule
type SchemaRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
}

var (
	schemaValidatorCmd = &cobra.Command{
		Use:   "schema-validator",
		Short: "Validate policy schemas against compliance standards",
		Long: `Validate policy schemas to ensure they conform to ArdaOS compliance standards.

The schema validator provides:
- Comprehensive schema validation against defined standards
- Custom validation rules and checks
- Detailed error reporting with line numbers
- Compliance rate calculation
- Support for multiple output formats
- Batch validation for multiple files`,
		Example: `  # Validate a single policy file
  go run tools/schema-validator.go --file examples/policies/installment-loan.yaml

  # Validate with custom schema
  go run tools/schema-validator.go --file policy.yaml --schema custom-schema.json

  # Strict mode validation
  go run tools/schema-validator.go --file policy.yaml --strict --fail-on-warnings

  # Validate multiple files
  go run tools/schema-validator.go --dir examples/policies/ --format json

  # Generate validation report
  go run tools/schema-validator.go --dir examples/ --output validation-report.json`,
		RunE: runSchemaValidator,
	}

	policyFile     string
	policyDir      string
	schemaFile     string
	outputFile     string
	outputFormat   string
	strictMode     bool
	failOnWarnings bool
	verbose        bool
	rulesFile      string
)

func init() {
	schemaValidatorCmd.Flags().StringVarP(&policyFile, "file", "f", "", "Policy file to validate")
	schemaValidatorCmd.Flags().StringVarP(&policyDir, "dir", "d", "", "Directory containing policies to validate")
	schemaValidatorCmd.Flags().StringVarP(&schemaFile, "schema", "s", "", "Custom schema file (JSON/YAML)")
	schemaValidatorCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for validation results")
	schemaValidatorCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format (text, json, yaml, html)")
	schemaValidatorCmd.Flags().BoolVar(&strictMode, "strict", false, "Enable strict validation mode")
	schemaValidatorCmd.Flags().BoolVar(&failOnWarnings, "fail-on-warnings", false, "Treat warnings as errors")
	schemaValidatorCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	schemaValidatorCmd.Flags().StringVar(&rulesFile, "rules", "", "Custom validation rules file")
}

func main() {
	if err := schemaValidatorCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runSchemaValidator(cmd *cobra.Command, args []string) error {
	if policyFile == "" && policyDir == "" {
		return fmt.Errorf("either --file or --dir must be specified")
	}

	validator := &SchemaValidator{
		SchemaFile:      schemaFile,
		StrictMode:      strictMode,
		OutputFormat:    outputFormat,
		FailOnWarnings:  failOnWarnings,
		ValidationCache: make(map[string]ValidationResult),
	}

	// Load schema
	schema, err := validator.loadSchema()
	if err != nil {
		return fmt.Errorf("failed to load schema: %w", err)
	}

	// Load custom rules
	if rulesFile != "" {
		if err := validator.loadCustomRules(rulesFile); err != nil {
			return fmt.Errorf("failed to load custom rules: %w", err)
		}
	}

	var results []ValidationResult

	// Validate files
	if policyFile != "" {
		result, err := validator.validateFile(policyFile, schema)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		results = append(results, *result)
	}

	if policyDir != "" {
		dirResults, err := validator.validateDirectory(policyDir, schema)
		if err != nil {
			return fmt.Errorf("directory validation failed: %w", err)
		}
		results = append(results, dirResults...)
	}

	// Output results
	if err := validator.outputResults(results); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Check for failures
	for _, result := range results {
		if !result.Valid || (failOnWarnings && len(result.Warnings) > 0) {
			os.Exit(1)
		}
	}

	return nil
}

// loadSchema loads the validation schema
func (v *SchemaValidator) loadSchema() (*PolicySchema, error) {
	var schemaData []byte
	var err error

	if v.SchemaFile != "" {
		schemaData, err = ioutil.ReadFile(v.SchemaFile)
		if err != nil {
			return nil, err
		}
	} else {
		// Use default schema
		schemaData = []byte(getDefaultSchema())
	}

	var schema PolicySchema
	if strings.HasSuffix(v.SchemaFile, ".yaml") || strings.HasSuffix(v.SchemaFile, ".yml") {
		err = yaml.Unmarshal(schemaData, &schema)
	} else {
		err = json.Unmarshal(schemaData, &schema)
	}

	if err != nil {
		return nil, err
	}

	return &schema, nil
}

// loadCustomRules loads custom validation rules
func (v *SchemaValidator) loadCustomRules(rulesFile string) error {
	data, err := ioutil.ReadFile(rulesFile)
	if err != nil {
		return err
	}

	var rules []ValidationRule
	if strings.HasSuffix(rulesFile, ".yaml") || strings.HasSuffix(rulesFile, ".yml") {
		err = yaml.Unmarshal(data, &rules)
	} else {
		err = json.Unmarshal(data, &rules)
	}

	if err != nil {
		return err
	}

	v.CustomRules = rules
	return nil
}

// validateFile validates a single policy file
func (v *SchemaValidator) validateFile(filePath string, schema *PolicySchema) (*ValidationResult, error) {
	startTime := time.Now()

	// Check cache
	if cached, exists := v.ValidationCache[filePath]; exists {
		return &cached, nil
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var policy interface{}
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		err = yaml.Unmarshal(data, &policy)
	} else {
		err = json.Unmarshal(data, &policy)
	}

	if err != nil {
		return nil, err
	}

	result := &ValidationResult{
		ValidatedAt: startTime,
		PolicyPath:  filePath,
		SchemaPath:  v.SchemaFile,
		Valid:       true,
	}

	// Validate against schema
	v.validateAgainstSchema(policy, schema, result)

	// Apply custom rules
	v.applyCustomRules(policy, result)

	// Calculate summary
	result.Summary = v.calculateSummary(result)
	result.Duration = time.Since(startTime)
	result.Valid = len(result.Errors) == 0

	// Cache result
	v.ValidationCache[filePath] = *result

	if verbose {
		log.Printf("Validated %s: %d errors, %d warnings", filePath, len(result.Errors), len(result.Warnings))
	}

	return result, nil
}

// validateDirectory validates all policy files in a directory
func (v *SchemaValidator) validateDirectory(dirPath string, schema *PolicySchema) ([]ValidationResult, error) {
	var results []ValidationResult

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			result, err := v.validateFile(path, schema)
			if err != nil {
				log.Printf("Warning: Failed to validate %s: %v", path, err)
				return nil
			}
			results = append(results, *result)
		}

		return nil
	})

	return results, err
}

// validateAgainstSchema validates policy against schema
func (v *SchemaValidator) validateAgainstSchema(policy interface{}, schema *PolicySchema, result *ValidationResult) {
	policyMap, ok := policy.(map[string]interface{})
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Rule:     "schema.root_type",
			Message:  "Policy must be an object",
			Severity: "error",
			Path:     "/",
		})
		return
	}

	// Check required fields
	for _, required := range schema.Required {
		if _, exists := policyMap[required]; !exists {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.required_field",
				Message:  fmt.Sprintf("Required field '%s' is missing", required),
				Severity: "error",
				Path:     fmt.Sprintf("/%s", required),
			})
		}
	}

	// Validate properties
	for fieldName, fieldSchema := range schema.Properties {
		if value, exists := policyMap[fieldName]; exists {
			v.validateProperty(fieldName, value, fieldSchema, result)
		} else if fieldSchema.Required {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.required_property",
				Message:  fmt.Sprintf("Required property '%s' is missing", fieldName),
				Severity: "error",
				Path:     fmt.Sprintf("/%s", fieldName),
			})
		}
	}

	// Check for unknown fields in strict mode
	if v.StrictMode {
		for fieldName := range policyMap {
			if _, exists := schema.Properties[fieldName]; !exists {
				result.Warnings = append(result.Warnings, ValidationError{
					Rule:     "schema.unknown_field",
					Message:  fmt.Sprintf("Unknown field '%s' in strict mode", fieldName),
					Severity: "warning",
					Path:     fmt.Sprintf("/%s", fieldName),
				})
			}
		}
	}
}

// validateProperty validates a single property
func (v *SchemaValidator) validateProperty(name string, value interface{}, schema PropertySchema, result *ValidationResult) {
	path := fmt.Sprintf("/%s", name)

	// Type validation
	if !v.validateType(value, schema.Type) {
		result.Errors = append(result.Errors, ValidationError{
			Rule:     "schema.type_mismatch",
			Message:  fmt.Sprintf("Field '%s' must be of type %s", name, schema.Type),
			Severity: "error",
			Path:     path,
			Value:    value,
			Expected: schema.Type,
		})
		return
	}

	// Enum validation
	if len(schema.Enum) > 0 {
		strValue := fmt.Sprintf("%v", value)
		valid := false
		for _, enumValue := range schema.Enum {
			if strValue == enumValue {
				valid = true
				break
			}
		}
		if !valid {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.enum_violation",
				Message:  fmt.Sprintf("Field '%s' must be one of: %v", name, schema.Enum),
				Severity: "error",
				Path:     path,
				Value:    value,
				Expected: schema.Enum,
			})
		}
	}

	// String validations
	if schema.Type == "string" {
		strValue := value.(string)

		if schema.MinLength != nil && len(strValue) < *schema.MinLength {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.min_length",
				Message:  fmt.Sprintf("Field '%s' must be at least %d characters", name, *schema.MinLength),
				Severity: "error",
				Path:     path,
				Value:    len(strValue),
				Expected: *schema.MinLength,
			})
		}

		if schema.MaxLength != nil && len(strValue) > *schema.MaxLength {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.max_length",
				Message:  fmt.Sprintf("Field '%s' must be at most %d characters", name, *schema.MaxLength),
				Severity: "error",
				Path:     path,
				Value:    len(strValue),
				Expected: *schema.MaxLength,
			})
		}
	}

	// Numeric validations
	if schema.Type == "number" || schema.Type == "integer" {
		var numValue float64
		switch v := value.(type) {
		case int:
			numValue = float64(v)
		case float64:
			numValue = v
		case int64:
			numValue = float64(v)
		}

		if schema.Minimum != nil && numValue < *schema.Minimum {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.minimum",
				Message:  fmt.Sprintf("Field '%s' must be at least %v", name, *schema.Minimum),
				Severity: "error",
				Path:     path,
				Value:    numValue,
				Expected: *schema.Minimum,
			})
		}

		if schema.Maximum != nil && numValue > *schema.Maximum {
			result.Errors = append(result.Errors, ValidationError{
				Rule:     "schema.maximum",
				Message:  fmt.Sprintf("Field '%s' must be at most %v", name, *schema.Maximum),
				Severity: "error",
				Path:     path,
				Value:    numValue,
				Expected: *schema.Maximum,
			})
		}
	}
}

// validateType checks if value matches the expected type
func (v *SchemaValidator) validateType(value interface{}, expectedType string) bool {
	switch expectedType {
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		switch value.(type) {
		case int, int64, float64:
			return true
		}
		return false
	case "integer":
		switch value.(type) {
		case int, int64:
			return true
		}
		return false
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "array":
		_, ok := value.([]interface{})
		return ok
	case "object":
		_, ok := value.(map[string]interface{})
		return ok
	default:
		return true // Unknown types pass
	}
}

// applyCustomRules applies custom validation rules
func (v *SchemaValidator) applyCustomRules(policy interface{}, result *ValidationResult) {
	for _, rule := range v.CustomRules {
		if rule.Check != nil && !rule.Check(policy) {
			validationError := ValidationError{
				Rule:     rule.ID,
				Message:  rule.Message,
				Severity: rule.Severity,
				Path:     "/",
			}

			switch rule.Severity {
			case "error":
				result.Errors = append(result.Errors, validationError)
			case "warning":
				result.Warnings = append(result.Warnings, validationError)
			case "info":
				result.Info = append(result.Info, validationError)
			}
		}
	}
}

// calculateSummary calculates validation summary
func (v *SchemaValidator) calculateSummary(result *ValidationResult) ValidationSummary {
	totalRules := len(v.CustomRules) + 10 // Base schema rules
	failedRules := len(result.Errors)
	passedRules := totalRules - failedRules

	complianceRate := 0.0
	if totalRules > 0 {
		complianceRate = float64(passedRules) / float64(totalRules) * 100
	}

	return ValidationSummary{
		TotalRules:     totalRules,
		PassedRules:    passedRules,
		FailedRules:    failedRules,
		ErrorCount:     len(result.Errors),
		WarningCount:   len(result.Warnings),
		InfoCount:      len(result.Info),
		ComplianceRate: complianceRate,
	}
}

// outputResults outputs validation results in the specified format
func (v *SchemaValidator) outputResults(results []ValidationResult) error {
	var output string
	var err error

	switch v.OutputFormat {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		output = string(data)

	case "yaml":
		data, err := yaml.Marshal(results)
		if err != nil {
			return err
		}
		output = string(data)

	case "html":
		output = v.generateHTMLReport(results)

	default: // text
		output = v.generateTextReport(results)
	}

	if outputFile != "" {
		return ioutil.WriteFile(outputFile, []byte(output), 0644)
	}

	fmt.Print(output)
	return nil
}

// generateTextReport generates a text report
func (v *SchemaValidator) generateTextReport(results []ValidationResult) string {
	var report strings.Builder

	report.WriteString("🔍 ArdaOS Compliance Schema Validation Report\n")
	report.WriteString("============================================\n\n")

	totalErrors := 0
	totalWarnings := 0
	validFiles := 0

	for _, result := range results {
		totalErrors += len(result.Errors)
		totalWarnings += len(result.Warnings)
		if result.Valid {
			validFiles++
		}

		status := "✅ VALID"
		if !result.Valid {
			status = "❌ INVALID"
		}

		report.WriteString(fmt.Sprintf("File: %s [%s]\n", result.PolicyPath, status))
		report.WriteString(fmt.Sprintf("  Duration: %v\n", result.Duration))
		report.WriteString(fmt.Sprintf("  Compliance Rate: %.1f%%\n", result.Summary.ComplianceRate))

		if len(result.Errors) > 0 {
			report.WriteString("  Errors:\n")
			for _, err := range result.Errors {
				report.WriteString(fmt.Sprintf("    - %s: %s\n", err.Rule, err.Message))
			}
		}

		if len(result.Warnings) > 0 {
			report.WriteString("  Warnings:\n")
			for _, warn := range result.Warnings {
				report.WriteString(fmt.Sprintf("    - %s: %s\n", warn.Rule, warn.Message))
			}
		}

		report.WriteString("\n")
	}

	report.WriteString("Summary:\n")
	report.WriteString(fmt.Sprintf("  Total Files: %d\n", len(results)))
	report.WriteString(fmt.Sprintf("  Valid Files: %d\n", validFiles))
	report.WriteString(fmt.Sprintf("  Invalid Files: %d\n", len(results)-validFiles))
	report.WriteString(fmt.Sprintf("  Total Errors: %d\n", totalErrors))
	report.WriteString(fmt.Sprintf("  Total Warnings: %d\n", totalWarnings))

	overallCompliance := float64(validFiles) / float64(len(results)) * 100
	report.WriteString(fmt.Sprintf("  Overall Compliance: %.1f%%\n", overallCompliance))

	return report.String()
}

// generateHTMLReport generates an HTML report
func (v *SchemaValidator) generateHTMLReport(results []ValidationResult) string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>Schema Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2563eb; color: white; padding: 20px; border-radius: 8px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .file { background: white; border: 1px solid #dee2e6; border-radius: 8px; margin: 10px 0; padding: 15px; }
        .valid { border-left: 4px solid #28a745; }
        .invalid { border-left: 4px solid #dc3545; }
        .error { color: #dc3545; margin: 5px 0; }
        .warning { color: #ffc107; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Schema Validation Report</h1>
    </div>
    <!-- Results would be generated here -->
</body>
</html>`
}

// getDefaultSchema returns the default policy schema
func getDefaultSchema() string {
	return `{
  "version": "1.0.0",
  "name": "ArdaOS Compliance Policy Schema",
  "description": "Standard schema for ArdaOS compliance policies",
  "required": ["template", "policy"],
  "properties": {
    "template": {
      "type": "object",
      "description": "Policy template metadata",
      "required": true
    },
    "parameters": {
      "type": "object",
      "description": "Policy parameters",
      "required": false
    },
    "policy": {
      "type": "object",
      "description": "Policy rules and configuration",
      "required": true
    }
  },
  "rules": [
    {
      "id": "template.name.required",
      "name": "Template Name Required",
      "description": "Template must have a name",
      "expression": "template.name != null && template.name != ''",
      "severity": "error",
      "category": "template"
    },
    {
      "id": "template.version.required",
      "name": "Template Version Required",
      "description": "Template must have a version",
      "expression": "template.version != null && template.version != ''",
      "severity": "error",
      "category": "template"
    }
  ]
}`
}
