package validator

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"google.golang.org/protobuf/proto"
)

// performStructuralValidation conducts comprehensive structural validation
func (v *PolicyValidator) performStructuralValidation(policy *parser.CompliancePolicy, report *ValidationReport) {
	structuralReport := &StructuralValidationReport{
		MessageCompleteness:  v.validateMessageCompleteness(policy),
		RequiredFieldsCheck:  v.validateRequiredFields(policy),
		DataTypeValidation:   v.validateDataTypes(policy),
		MessageRelationships: v.validateMessageRelationships(policy),
		SchemaCompliance:     v.validateSchemaCompliance(policy),
		FieldNamingCheck:     v.validateFieldNaming(policy),
	}

	report.StructuralReport = structuralReport

	// Collect errors and warnings from structural validation
	v.collectStructuralIssues(structuralReport, report)
}

// validateMessageCompleteness checks protobuf message completeness
func (v *PolicyValidator) validateMessageCompleteness(policy *parser.CompliancePolicy) *MessageCompletenessCheck {
	check := &MessageCompletenessCheck{
		IsComplete:       true,
		MissingFields:    make([]string, 0),
		ExtraFields:      make([]string, 0),
		CorruptedFields:  make([]string, 0),
		ValidationErrors: make([]string, 0),
	}

	// Check if policy can be marshaled to protobuf
	if _, err := proto.Marshal(policy); err != nil {
		check.IsComplete = false
		check.ValidationErrors = append(check.ValidationErrors,
			fmt.Sprintf("Failed to marshal policy to protobuf: %v", err))
	}

	// Validate proto message structure using reflection
	v.validateProtoStructure(policy, check)

	// Check for required protobuf fields
	v.checkRequiredProtobufFields(policy, check)

	return check
}

// validateProtoStructure validates the protobuf structure using reflection
func (v *PolicyValidator) validateProtoStructure(policy *parser.CompliancePolicy, check *MessageCompletenessCheck) {
	policyValue := reflect.ValueOf(policy)
	if policyValue.Kind() == reflect.Ptr {
		policyValue = policyValue.Elem()
	}

	policyType := policyValue.Type()

	// Check each field in the struct
	for i := 0; i < policyType.NumField(); i++ {
		field := policyType.Field(i)
		fieldValue := policyValue.Field(i)

		// Skip unexported fields
		if !fieldValue.CanInterface() {
			continue
		}

		// Check if field is properly initialized
		if v.isFieldCorrupted(fieldValue) {
			check.IsComplete = false
			check.CorruptedFields = append(check.CorruptedFields, field.Name)
		}

		// Validate nested structures
		if fieldValue.Kind() == reflect.Struct ||
			(fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() &&
				fieldValue.Elem().Kind() == reflect.Struct) {
			v.validateNestedStructure(fieldValue, field.Name, check)
		}

		// Validate slices of structs
		if fieldValue.Kind() == reflect.Slice && fieldValue.Len() > 0 {
			elemType := fieldValue.Type().Elem()
			if elemType.Kind() == reflect.Struct ||
				(elemType.Kind() == reflect.Ptr && elemType.Elem().Kind() == reflect.Struct) {
				v.validateSliceStructures(fieldValue, field.Name, check)
			}
		}
	}
}

// isFieldCorrupted checks if a field value appears corrupted
func (v *PolicyValidator) isFieldCorrupted(fieldValue reflect.Value) bool {
	switch fieldValue.Kind() {
	case reflect.Ptr:
		// Nil pointers are not necessarily corrupted
		return false
	case reflect.String:
		// Check for suspicious string patterns that might indicate corruption
		strValue := fieldValue.String()
		return v.containsSuspiciousPatterns(strValue)
	case reflect.Slice:
		// Check if slice contains nil elements where they shouldn't be
		for i := 0; i < fieldValue.Len(); i++ {
			elem := fieldValue.Index(i)
			if elem.Kind() == reflect.Ptr && elem.IsNil() {
				// Check if this field type should allow nil elements
				if !v.allowsNilElements(fieldValue.Type().Elem()) {
					return true
				}
			}
		}
	case reflect.Map:
		// Check for corrupted map entries
		for _, key := range fieldValue.MapKeys() {
			value := fieldValue.MapIndex(key)
			if value.Kind() == reflect.Ptr && value.IsNil() {
				if !v.allowsNilMapValues(fieldValue.Type().Elem()) {
					return true
				}
			}
		}
	}
	return false
}

// containsSuspiciousPatterns checks for suspicious string patterns
func (v *PolicyValidator) containsSuspiciousPatterns(str string) bool {
	suspiciousPatterns := []string{
		`\x00`,   // null bytes
		`\uFFFD`, // replacement character (often indicates corruption)
		`<nil>`,  // Go nil representation in strings
		`%!`,     // Go formatting errors
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, str); matched {
			return true
		}
	}
	return false
}

// allowsNilElements checks if a type allows nil slice elements
func (v *PolicyValidator) allowsNilElements(elemType reflect.Type) bool {
	// In general, proto message slices should not contain nil elements
	return elemType.Kind() != reflect.Ptr
}

// allowsNilMapValues checks if a type allows nil map values
func (v *PolicyValidator) allowsNilMapValues(valueType reflect.Type) bool {
	// Proto maps generally shouldn't have nil values for required types
	return valueType.Kind() != reflect.Ptr
}

// validateNestedStructure validates nested struct fields
func (v *PolicyValidator) validateNestedStructure(fieldValue reflect.Value, fieldName string, check *MessageCompletenessCheck) {
	if fieldValue.Kind() == reflect.Ptr {
		if fieldValue.IsNil() {
			return // Nil nested structs are generally acceptable
		}
		fieldValue = fieldValue.Elem()
	}

	fieldType := fieldValue.Type()
	for i := 0; i < fieldType.NumField(); i++ {
		nestedField := fieldType.Field(i)
		nestedValue := fieldValue.Field(i)

		if !nestedValue.CanInterface() {
			continue
		}

		if v.isFieldCorrupted(nestedValue) {
			check.IsComplete = false
			check.CorruptedFields = append(check.CorruptedFields,
				fmt.Sprintf("%s.%s", fieldName, nestedField.Name))
		}
	}
}

// validateSliceStructures validates slice of struct fields
func (v *PolicyValidator) validateSliceStructures(fieldValue reflect.Value, fieldName string, check *MessageCompletenessCheck) {
	for i := 0; i < fieldValue.Len(); i++ {
		elem := fieldValue.Index(i)
		indexedFieldName := fmt.Sprintf("%s[%d]", fieldName, i)

		if elem.Kind() == reflect.Ptr && elem.IsNil() {
			check.IsComplete = false
			check.CorruptedFields = append(check.CorruptedFields, indexedFieldName)
			continue
		}

		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}

		if elem.Kind() == reflect.Struct {
			v.validateNestedStructure(elem, indexedFieldName, check)
		}
	}
}

// checkRequiredProtobufFields checks for required protobuf fields
func (v *PolicyValidator) checkRequiredProtobufFields(policy *parser.CompliancePolicy, check *MessageCompletenessCheck) {
	requiredFields := []string{"policy_id", "version", "jurisdiction"}

	policyValue := reflect.ValueOf(policy).Elem()
	policyType := policyValue.Type()

	for _, requiredField := range requiredFields {
		// Convert to Go field name (e.g., policy_id -> PolicyId)
		goFieldName := v.toGoFieldName(requiredField)

		if field, found := policyType.FieldByName(goFieldName); found {
			fieldValue := policyValue.FieldByName(goFieldName)

			if v.isFieldEmpty(fieldValue) {
				check.IsComplete = false
				check.MissingFields = append(check.MissingFields, requiredField)
			}
		} else {
			check.IsComplete = false
			check.MissingFields = append(check.MissingFields, requiredField)
		}
	}
}

// toGoFieldName converts snake_case to GoCase
func (v *PolicyValidator) toGoFieldName(snakeCase string) string {
	parts := strings.Split(snakeCase, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, "")
}

// isFieldEmpty checks if a field is empty
func (v *PolicyValidator) isFieldEmpty(fieldValue reflect.Value) bool {
	switch fieldValue.Kind() {
	case reflect.String:
		return fieldValue.String() == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return fieldValue.Len() == 0
	case reflect.Ptr:
		return fieldValue.IsNil()
	case reflect.Interface:
		return fieldValue.IsNil()
	default:
		return fieldValue.IsZero()
	}
}

// validateRequiredFields validates presence of required fields
func (v *PolicyValidator) validateRequiredFields(policy *parser.CompliancePolicy) *RequiredFieldsCheck {
	check := &RequiredFieldsCheck{
		AllRequiredPresent: true,
		RequiredFields:     v.getRequiredFields(policy),
		MissingRequired:    make([]string, 0),
		OptionalFields:     v.getOptionalFields(policy),
		FieldChecks:        make(map[string]*FieldCheckResult),
	}

	// Check each required field
	for _, fieldName := range check.RequiredFields {
		fieldCheck := v.validateSingleField(policy, fieldName)
		check.FieldChecks[fieldName] = fieldCheck

		if !fieldCheck.IsPresent || !fieldCheck.IsValid {
			check.AllRequiredPresent = false
			if !fieldCheck.IsPresent {
				check.MissingRequired = append(check.MissingRequired, fieldName)
			}
		}
	}

	return check
}

// getRequiredFields returns the list of required fields for the policy
func (v *PolicyValidator) getRequiredFields(policy *parser.CompliancePolicy) []string {
	requiredFields := v.config.ValidationRules.RequiredFields

	// Add jurisdiction-specific required fields
	if rules, exists := v.jurisdictions[policy.Jurisdiction]; exists {
		requiredFields = append(requiredFields, rules.RequiredFields...)
	}

	// Add asset class-specific required fields
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		requiredFields = append(requiredFields, schema.RequiredFields...)
	}

	// Remove duplicates
	return v.removeDuplicateStrings(requiredFields)
}

// getOptionalFields returns the list of optional fields for the policy
func (v *PolicyValidator) getOptionalFields(policy *parser.CompliancePolicy) []string {
	optionalFields := []string{}

	// Add asset class-specific optional fields
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		optionalFields = append(optionalFields, schema.OptionalFields...)
	}

	return v.removeDuplicateStrings(optionalFields)
}

// validateSingleField validates a single field
func (v *PolicyValidator) validateSingleField(policy *parser.CompliancePolicy, fieldName string) *FieldCheckResult {
	result := &FieldCheckResult{
		FieldName:   fieldName,
		IsPresent:   false,
		IsValid:     false,
		Constraints: make([]string, 0),
		Errors:      make([]string, 0),
	}

	// Use reflection to check field presence and value
	policyValue := reflect.ValueOf(policy).Elem()
	goFieldName := v.toGoFieldName(fieldName)

	if fieldValue := policyValue.FieldByName(goFieldName); fieldValue.IsValid() {
		result.IsPresent = true
		result.ActualType = fieldValue.Type().String()
		result.Value = fieldValue.Interface()

		// Check if field is empty
		if v.isFieldEmpty(fieldValue) {
			result.IsValid = false
			result.Errors = append(result.Errors, "Field is empty")
		} else {
			result.IsValid = true
		}

		// Get expected type from schema
		if schema, exists := v.schemas[policy.AssetClass]; exists {
			if fieldSchema, exists := schema.Fields[fieldName]; exists {
				result.ExpectedType = fieldSchema.Type

				// Validate against field schema
				v.validateFieldAgainstSchema(fieldValue, fieldSchema, result)
			}
		}
	} else {
		result.Errors = append(result.Errors, "Field not found in policy structure")
	}

	return result
}

// validateFieldAgainstSchema validates a field against its schema
func (v *PolicyValidator) validateFieldAgainstSchema(fieldValue reflect.Value, schema *FieldSchema, result *FieldCheckResult) {
	// Type validation
	if !v.isTypeCompatible(fieldValue.Type().String(), schema.Type) {
		result.IsValid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("Type mismatch: expected %s, got %s", schema.Type, result.ActualType))
	}

	// Pattern validation
	if schema.Pattern != "" && fieldValue.Kind() == reflect.String {
		if matched, err := regexp.MatchString(schema.Pattern, fieldValue.String()); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Pattern validation error: %v", err))
		} else if !matched {
			result.IsValid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("Value does not match required pattern: %s", schema.Pattern))
		}
	}

	// Length validation for strings
	if fieldValue.Kind() == reflect.String {
		strLen := len(fieldValue.String())
		if schema.MinLength != nil && strLen < *schema.MinLength {
			result.IsValid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("String too short: minimum length %d, got %d", *schema.MinLength, strLen))
		}
		if schema.MaxLength != nil && strLen > *schema.MaxLength {
			result.IsValid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("String too long: maximum length %d, got %d", *schema.MaxLength, strLen))
		}
	}

	// Value range validation for numbers
	if v.isNumericType(fieldValue.Type()) {
		numValue := v.getNumericValue(fieldValue)
		if schema.MinValue != nil && numValue < *schema.MinValue {
			result.IsValid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("Value too small: minimum %f, got %f", *schema.MinValue, numValue))
		}
		if schema.MaxValue != nil && numValue > *schema.MaxValue {
			result.IsValid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("Value too large: maximum %f, got %f", *schema.MaxValue, numValue))
		}
	}

	// Allowed values validation
	if len(schema.AllowedValues) > 0 {
		if !v.isValueAllowed(fieldValue.Interface(), schema.AllowedValues) {
			result.IsValid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("Value not in allowed list: %v", schema.AllowedValues))
		}
	}

	// Deprecation warning
	if schema.Deprecated {
		result.Errors = append(result.Errors, "Field is deprecated")
	}
}

// isTypeCompatible checks if two types are compatible
func (v *PolicyValidator) isTypeCompatible(actualType, expectedType string) bool {
	// Basic type mapping
	typeMap := map[string][]string{
		"string":  {"string"},
		"number":  {"int", "int32", "int64", "float32", "float64", "uint", "uint32", "uint64"},
		"boolean": {"bool"},
		"array":   {"[]"},
		"object":  {"map", "struct"},
	}

	if allowedTypes, exists := typeMap[expectedType]; exists {
		for _, allowedType := range allowedTypes {
			if strings.Contains(actualType, allowedType) {
				return true
			}
		}
	}

	return actualType == expectedType
}

// isNumericType checks if a type is numeric
func (v *PolicyValidator) isNumericType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// getNumericValue extracts numeric value as float64
func (v *PolicyValidator) getNumericValue(fieldValue reflect.Value) float64 {
	switch fieldValue.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(fieldValue.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(fieldValue.Uint())
	case reflect.Float32, reflect.Float64:
		return fieldValue.Float()
	}
	return 0
}

// isValueAllowed checks if a value is in the allowed list
func (v *PolicyValidator) isValueAllowed(value interface{}, allowedValues []interface{}) bool {
	for _, allowed := range allowedValues {
		if reflect.DeepEqual(value, allowed) {
			return true
		}
	}
	return false
}

// validateDataTypes validates field data types and formats
func (v *PolicyValidator) validateDataTypes(policy *parser.CompliancePolicy) *DataTypeValidation {
	validation := &DataTypeValidation{
		AllTypesValid:     true,
		TypeErrors:        make([]*DataTypeError, 0),
		FormatErrors:      make([]*FormatError, 0),
		TypeConversions:   make([]*TypeConversion, 0),
		ValidationResults: make(map[string]*TypeValidationResult),
	}

	// Validate each field's data type
	v.validatePolicyDataTypes(policy, validation)

	return validation
}

// validatePolicyDataTypes validates data types for all policy fields
func (v *PolicyValidator) validatePolicyDataTypes(policy *parser.CompliancePolicy, validation *DataTypeValidation) {
	policyValue := reflect.ValueOf(policy).Elem()
	policyType := policyValue.Type()

	for i := 0; i < policyType.NumField(); i++ {
		field := policyType.Field(i)
		fieldValue := policyValue.Field(i)

		if !fieldValue.CanInterface() {
			continue
		}

		fieldName := v.toSnakeCase(field.Name)
		result := v.validateFieldDataType(fieldName, fieldValue, policy)
		validation.ValidationResults[fieldName] = result

		if !result.IsValid {
			validation.AllTypesValid = false
		}

		// Collect errors
		for _, errorMsg := range result.Errors {
			validation.TypeErrors = append(validation.TypeErrors, &DataTypeError{
				Field:        fieldName,
				ExpectedType: v.getExpectedType(fieldName, policy),
				ActualType:   fieldValue.Type().String(),
				Value:        fieldValue.Interface(),
				Message:      errorMsg,
			})
		}
	}
}

// validateFieldDataType validates the data type of a single field
func (v *PolicyValidator) validateFieldDataType(fieldName string, fieldValue reflect.Value, policy *parser.CompliancePolicy) *TypeValidationResult {
	result := &TypeValidationResult{
		Field:           fieldName,
		IsValid:         true,
		TypeMatches:     true,
		FormatMatches:   true,
		ConstraintsMet:  true,
		Errors:          make([]string, 0),
		Warnings:        make([]string, 0),
		Suggestions:     make([]string, 0),
		ValidationRules: make([]string, 0),
		Context:         make(map[string]interface{}),
	}

	// Get expected type from schema
	expectedType := v.getExpectedType(fieldName, policy)
	actualType := fieldValue.Type().String()

	// Type compatibility check
	if expectedType != "" && !v.isTypeCompatible(actualType, expectedType) {
		result.IsValid = false
		result.TypeMatches = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("Type mismatch: expected %s, got %s", expectedType, actualType))

		// Suggest type conversion if possible
		if conversion := v.suggestTypeConversion(fieldValue, expectedType); conversion != nil {
			result.Suggestions = append(result.Suggestions,
				fmt.Sprintf("Consider converting from %s to %s", conversion.FromType, conversion.ToType))
		}
	}

	// Format validation
	if !v.validateFieldFormat(fieldName, fieldValue, policy, result) {
		result.FormatMatches = false
	}

	// Constraint validation
	if !v.validateFieldConstraints(fieldName, fieldValue, policy, result) {
		result.ConstraintsMet = false
	}

	// Set context information
	result.Context["actual_type"] = actualType
	result.Context["expected_type"] = expectedType
	result.Context["field_kind"] = fieldValue.Kind().String()

	return result
}

// getExpectedType gets the expected data type for a field
func (v *PolicyValidator) getExpectedType(fieldName string, policy *parser.CompliancePolicy) string {
	// Check asset class schema
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		if fieldSchema, exists := schema.Fields[fieldName]; exists {
			return fieldSchema.Type
		}
	}

	// Default type mappings
	defaultTypes := map[string]string{
		"policy_id":    "string",
		"version":      "string",
		"jurisdiction": "string",
		"asset_class":  "string",
		"rules":        "array",
		"attestations": "array",
		"enforcement":  "object",
	}

	if expectedType, exists := defaultTypes[fieldName]; exists {
		return expectedType
	}

	return ""
}

// validateFieldFormat validates field format
func (v *PolicyValidator) validateFieldFormat(fieldName string, fieldValue reflect.Value, policy *parser.CompliancePolicy, result *TypeValidationResult) bool {
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		if fieldSchema, exists := schema.Fields[fieldName]; exists {
			if fieldSchema.Format != "" {
				return v.validateFormat(fieldValue, fieldSchema.Format, result)
			}
		}
	}
	return true
}

// validateFormat validates a value against a format specification
func (v *PolicyValidator) validateFormat(fieldValue reflect.Value, format string, result *TypeValidationResult) bool {
	if fieldValue.Kind() != reflect.String {
		return true // Format validation only applies to strings
	}

	strValue := fieldValue.String()

	switch format {
	case "email":
		return v.validateEmailFormat(strValue, result)
	case "uuid":
		return v.validateUUIDFormat(strValue, result)
	case "date":
		return v.validateDateFormat(strValue, result)
	case "datetime":
		return v.validateDateTimeFormat(strValue, result)
	case "url":
		return v.validateURLFormat(strValue, result)
	case "uri":
		return v.validateURIFormat(strValue, result)
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("Unknown format: %s", format))
		return true
	}
}

// validateEmailFormat validates email format
func (v *PolicyValidator) validateEmailFormat(value string, result *TypeValidationResult) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(value) {
		result.Errors = append(result.Errors, "Invalid email format")
		return false
	}
	return true
}

// validateUUIDFormat validates UUID format
func (v *PolicyValidator) validateUUIDFormat(value string, result *TypeValidationResult) bool {
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !uuidRegex.MatchString(value) {
		result.Errors = append(result.Errors, "Invalid UUID format")
		return false
	}
	return true
}

// validateDateFormat validates date format
func (v *PolicyValidator) validateDateFormat(value string, result *TypeValidationResult) bool {
	_, err := time.Parse("2006-01-02", value)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid date format: %v", err))
		return false
	}
	return true
}

// validateDateTimeFormat validates datetime format
func (v *PolicyValidator) validateDateTimeFormat(value string, result *TypeValidationResult) bool {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if _, err := time.Parse(format, value); err == nil {
			return true
		}
	}

	result.Errors = append(result.Errors, "Invalid datetime format")
	return false
}

// validateURLFormat validates URL format
func (v *PolicyValidator) validateURLFormat(value string, result *TypeValidationResult) bool {
	urlRegex := regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:[/?#].*)?$`)
	if !urlRegex.MatchString(value) {
		result.Errors = append(result.Errors, "Invalid URL format")
		return false
	}
	return true
}

// validateURIFormat validates URI format
func (v *PolicyValidator) validateURIFormat(value string, result *TypeValidationResult) bool {
	uriRegex := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
	if !uriRegex.MatchString(value) {
		result.Errors = append(result.Errors, "Invalid URI format")
		return false
	}
	return true
}

// validateFieldConstraints validates field constraints
func (v *PolicyValidator) validateFieldConstraints(fieldName string, fieldValue reflect.Value, policy *parser.CompliancePolicy, result *TypeValidationResult) bool {
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		if fieldSchema, exists := schema.Fields[fieldName]; exists {
			return v.validateSchemaConstraints(fieldValue, fieldSchema, result)
		}
	}
	return true
}

// validateSchemaConstraints validates constraints from field schema
func (v *PolicyValidator) validateSchemaConstraints(fieldValue reflect.Value, schema *FieldSchema, result *TypeValidationResult) bool {
	valid := true

	// Required field check (already handled elsewhere)

	// Pattern validation
	if schema.Pattern != "" && fieldValue.Kind() == reflect.String {
		if matched, err := regexp.MatchString(schema.Pattern, fieldValue.String()); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Pattern validation error: %v", err))
			valid = false
		} else if !matched {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Value does not match pattern: %s", schema.Pattern))
			valid = false
		}
	}

	// Add constraint information to context
	result.ValidationRules = append(result.ValidationRules, fmt.Sprintf("pattern:%s", schema.Pattern))

	return valid
}

// suggestTypeConversion suggests a type conversion
func (v *PolicyValidator) suggestTypeConversion(fieldValue reflect.Value, expectedType string) *TypeConversion {
	actualType := fieldValue.Type().String()

	// Define conversion possibilities and their risk levels
	conversions := map[string]map[string]string{
		"string": {
			"int":     "medium",
			"float64": "medium",
			"bool":    "high",
		},
		"int": {
			"string":  "low",
			"float64": "low",
			"bool":    "high",
		},
		"float64": {
			"string": "low",
			"int":    "medium",
			"bool":   "high",
		},
	}

	for fromType, toTypes := range conversions {
		if strings.Contains(actualType, fromType) {
			if risk, exists := toTypes[expectedType]; exists {
				return &TypeConversion{
					FromType:   actualType,
					ToType:     expectedType,
					OldValue:   fieldValue.Interface(),
					NewValue:   v.convertValue(fieldValue, expectedType),
					Confidence: v.getConversionConfidence(risk),
					Risk:       risk,
				}
			}
		}
	}

	return nil
}

// convertValue attempts to convert a value to the target type
func (v *PolicyValidator) convertValue(fieldValue reflect.Value, targetType string) interface{} {
	// This is a simplified conversion - in practice, you'd implement proper conversion logic
	switch targetType {
	case "string":
		return fmt.Sprintf("%v", fieldValue.Interface())
	case "int":
		if fieldValue.Kind() == reflect.String {
			// Would use strconv.Atoi in real implementation
			return 0
		}
	case "float64":
		if fieldValue.Kind() == reflect.String {
			// Would use strconv.ParseFloat in real implementation
			return 0.0
		}
	}
	return fieldValue.Interface()
}

// getConversionConfidence returns confidence level for conversion
func (v *PolicyValidator) getConversionConfidence(risk string) float64 {
	switch risk {
	case "low":
		return 0.9
	case "medium":
		return 0.7
	case "high":
		return 0.3
	default:
		return 0.5
	}
}

// validateMessageRelationships validates relationships between messages
func (v *PolicyValidator) validateMessageRelationships(policy *parser.CompliancePolicy) *MessageRelationshipsCheck {
	check := &MessageRelationshipsCheck{
		RelationshipsValid: true,
		BrokenReferences:   make([]*BrokenReference, 0),
		CircularReferences: make([]*CircularReference, 0),
		OrphanedObjects:    make([]*OrphanedObject, 0),
		RelationshipMap:    make(map[string]*RelationshipInfo),
	}

	// Build relationship map
	v.buildRelationshipMap(policy, check)

	// Validate references
	v.validateReferences(policy, check)

	// Check for circular references
	v.checkCircularReferences(check)

	// Identify orphaned objects
	v.identifyOrphanedObjects(check)

	return check
}

// buildRelationshipMap builds a map of object relationships
func (v *PolicyValidator) buildRelationshipMap(policy *parser.CompliancePolicy, check *MessageRelationshipsCheck) {
	// Build relationships for rules
	for i, rule := range policy.Rules {
		ruleID := fmt.Sprintf("rule_%d", i)
		check.RelationshipMap[ruleID] = &RelationshipInfo{
			ObjectType:   "rule",
			ObjectID:     ruleID,
			References:   make([]string, 0),
			ReferencedBy: make([]string, 0),
			IsOrphaned:   false,
			IsCircular:   false,
		}

		// Check if rule references other elements
		if rule.Predicate != nil {
			// Would analyze predicate for references to other rules/fields
		}
	}

	// Build relationships for attestations
	for i, attestation := range policy.Attestations {
		attestationID := fmt.Sprintf("attestation_%d", i)
		check.RelationshipMap[attestationID] = &RelationshipInfo{
			ObjectType:   "attestation",
			ObjectID:     attestationID,
			References:   make([]string, 0),
			ReferencedBy: make([]string, 0),
			IsOrphaned:   false,
			IsCircular:   false,
		}
	}
}

// validateReferences validates object references
func (v *PolicyValidator) validateReferences(policy *parser.CompliancePolicy, check *MessageRelationshipsCheck) {
	// This would implement reference validation logic
	// For now, we'll add a placeholder implementation
}

// checkCircularReferences checks for circular references
func (v *PolicyValidator) checkCircularReferences(check *MessageRelationshipsCheck) {
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	for objectID := range check.RelationshipMap {
		if !visited[objectID] {
			v.detectCircularReferenceDFS(objectID, visited, recursionStack, check, []string{})
		}
	}
}

// detectCircularReferenceDFS performs DFS to detect circular references
func (v *PolicyValidator) detectCircularReferenceDFS(objectID string, visited map[string]bool,
	recursionStack map[string]bool, check *MessageRelationshipsCheck, path []string) {

	visited[objectID] = true
	recursionStack[objectID] = true
	path = append(path, objectID)

	if relationInfo, exists := check.RelationshipMap[objectID]; exists {
		for _, refObjectID := range relationInfo.References {
			if !visited[refObjectID] {
				v.detectCircularReferenceDFS(refObjectID, visited, recursionStack, check, path)
			} else if recursionStack[refObjectID] {
				// Circular reference detected
				circularRef := &CircularReference{
					ReferencePath: append(path, refObjectID),
					StartField:    objectID,
					EndField:      refObjectID,
					Message:       fmt.Sprintf("Circular reference detected: %s -> %s", objectID, refObjectID),
				}
				check.CircularReferences = append(check.CircularReferences, circularRef)
				check.RelationshipsValid = false

				// Mark objects as having circular references
				if info := check.RelationshipMap[objectID]; info != nil {
					info.IsCircular = true
				}
				if info := check.RelationshipMap[refObjectID]; info != nil {
					info.IsCircular = true
				}
			}
		}
	}

	recursionStack[objectID] = false
}

// identifyOrphanedObjects identifies objects without proper references
func (v *PolicyValidator) identifyOrphanedObjects(check *MessageRelationshipsCheck) {
	for objectID, relationInfo := range check.RelationshipMap {
		// An object is considered orphaned if it has no incoming references
		// and is not a root object (like policy itself)
		if len(relationInfo.ReferencedBy) == 0 && relationInfo.ObjectType != "policy" {
			orphaned := &OrphanedObject{
				ObjectType:   relationInfo.ObjectType,
				ObjectID:     objectID,
				ExpectedRefs: []string{"policy", "other_rules"},
				Message:      fmt.Sprintf("Object %s (%s) has no incoming references", objectID, relationInfo.ObjectType),
			}
			check.OrphanedObjects = append(check.OrphanedObjects, orphaned)
			relationInfo.IsOrphaned = true
			check.RelationshipsValid = false
		}
	}
}

// validateSchemaCompliance validates compliance with schemas
func (v *PolicyValidator) validateSchemaCompliance(policy *parser.CompliancePolicy) *SchemaComplianceCheck {
	check := &SchemaComplianceCheck{
		IsCompliant:      true,
		SchemaVersion:    "1.0.0",
		ComplianceIssues: make([]*SchemaComplianceIssue, 0),
		MissingElements:  make([]string, 0),
		ExtraElements:    make([]string, 0),
	}

	// Check against asset class schema
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		v.validateAgainstAssetClassSchema(policy, schema, check)
	} else {
		check.IsCompliant = false
		check.ComplianceIssues = append(check.ComplianceIssues, &SchemaComplianceIssue{
			IssueType:  "missing",
			Element:    "asset_class_schema",
			SchemaRule: "asset_class_validation",
			Message:    fmt.Sprintf("No schema found for asset class: %s", policy.AssetClass),
			Severity:   "high",
			Suggestion: "Register a schema for this asset class",
		})
	}

	// Check against jurisdiction rules
	if rules, exists := v.jurisdictions[policy.Jurisdiction]; exists {
		v.validateAgainstJurisdictionRules(policy, rules, check)
	}

	return check
}

// validateAgainstAssetClassSchema validates policy against asset class schema
func (v *PolicyValidator) validateAgainstAssetClassSchema(policy *parser.CompliancePolicy, schema *AssetClassSchema, check *SchemaComplianceCheck) {
	// Check required fields
	for _, requiredField := range schema.RequiredFields {
		if !v.hasField(policy, requiredField) {
			check.IsCompliant = false
			check.MissingElements = append(check.MissingElements, requiredField)
			check.ComplianceIssues = append(check.ComplianceIssues, &SchemaComplianceIssue{
				IssueType:  "missing",
				Element:    requiredField,
				SchemaRule: "required_fields",
				Message:    fmt.Sprintf("Required field missing: %s", requiredField),
				Severity:   "high",
				Suggestion: fmt.Sprintf("Add the required field: %s", requiredField),
			})
		}
	}

	// Check business rules
	for _, businessRule := range schema.BusinessRules {
		if !v.validateBusinessRule(policy, businessRule) {
			check.IsCompliant = false
			check.ComplianceIssues = append(check.ComplianceIssues, &SchemaComplianceIssue{
				IssueType:  "invalid",
				Element:    businessRule.Name,
				SchemaRule: businessRule.RuleID,
				Message:    fmt.Sprintf("Business rule violation: %s", businessRule.Description),
				Severity:   "medium",
				Suggestion: "Review and adjust policy to comply with business rule",
			})
		}
	}

	// Check compliance rules
	for _, complianceRule := range schema.ComplianceRules {
		if !v.validateComplianceRule(policy, complianceRule) {
			check.IsCompliant = false
			check.ComplianceIssues = append(check.ComplianceIssues, &SchemaComplianceIssue{
				IssueType:  "invalid",
				Element:    complianceRule.Requirement,
				SchemaRule: complianceRule.RuleID,
				Message:    fmt.Sprintf("Compliance rule violation: %s", complianceRule.Description),
				Severity:   v.getSeverity(complianceRule.Mandatory),
				Suggestion: "Ensure policy meets regulatory compliance requirements",
			})
		}
	}
}

// validateAgainstJurisdictionRules validates policy against jurisdiction rules
func (v *PolicyValidator) validateAgainstJurisdictionRules(policy *parser.CompliancePolicy, rules *JurisdictionRules, check *SchemaComplianceCheck) {
	// Check forbidden fields
	for _, forbiddenField := range rules.ForbiddenFields {
		if v.hasField(policy, forbiddenField) {
			check.IsCompliant = false
			check.ExtraElements = append(check.ExtraElements, forbiddenField)
			check.ComplianceIssues = append(check.ComplianceIssues, &SchemaComplianceIssue{
				IssueType:  "extra",
				Element:    forbiddenField,
				SchemaRule: "forbidden_fields",
				Message:    fmt.Sprintf("Forbidden field present: %s", forbiddenField),
				Severity:   "high",
				Suggestion: fmt.Sprintf("Remove the forbidden field: %s", forbiddenField),
			})
		}
	}

	// Validate enforcement levels
	if policy.Enforcement != nil {
		validLevel := false
		for _, allowedLevel := range rules.EnforcementLevels {
			if policy.Enforcement.Level == allowedLevel {
				validLevel = true
				break
			}
		}

		if !validLevel {
			check.IsCompliant = false
			check.ComplianceIssues = append(check.ComplianceIssues, &SchemaComplianceIssue{
				IssueType:  "invalid",
				Element:    "enforcement_level",
				SchemaRule: "allowed_enforcement_levels",
				Message:    fmt.Sprintf("Invalid enforcement level: %s", policy.Enforcement.Level),
				Severity:   "high",
				Suggestion: fmt.Sprintf("Use one of the allowed levels: %v", rules.EnforcementLevels),
			})
		}
	}
}

// hasField checks if policy has a specific field
func (v *PolicyValidator) hasField(policy *parser.CompliancePolicy, fieldName string) bool {
	policyValue := reflect.ValueOf(policy).Elem()
	goFieldName := v.toGoFieldName(fieldName)

	if fieldValue := policyValue.FieldByName(goFieldName); fieldValue.IsValid() {
		return !v.isFieldEmpty(fieldValue)
	}
	return false
}

// validateBusinessRule validates a business rule
func (v *PolicyValidator) validateBusinessRule(policy *parser.CompliancePolicy, rule *BusinessRule) bool {
	// This would implement business rule validation logic
	// For now, return true as a placeholder
	return true
}

// validateComplianceRule validates a compliance rule
func (v *PolicyValidator) validateComplianceRule(policy *parser.CompliancePolicy, rule *ComplianceRule) bool {
	// This would implement compliance rule validation logic
	// For now, return true as a placeholder
	return true
}

// validateFieldNaming validates field naming conventions
func (v *PolicyValidator) validateFieldNaming(policy *parser.CompliancePolicy) *FieldNamingCheck {
	check := &FieldNamingCheck{
		AllNamesValid:   true,
		NamingErrors:    make([]*FieldNamingError, 0),
		StyleViolations: make([]*NamingStyleViolation, 0),
		Suggestions:     make([]*NamingSuggestion, 0),
	}

	policyValue := reflect.ValueOf(policy).Elem()
	policyType := policyValue.Type()

	for i := 0; i < policyType.NumField(); i++ {
		field := policyType.Field(i)
		fieldName := v.toSnakeCase(field.Name)

		// Validate against naming rules
		v.validateSingleFieldNaming(fieldName, field.Name, check)
	}

	return check
}

// validateSingleFieldNaming validates naming for a single field
func (v *PolicyValidator) validateSingleFieldNaming(fieldName, goFieldName string, check *FieldNamingCheck) {
	rules := v.config.ValidationRules.FieldNamingRules

	// Pattern validation
	if rules.Pattern != "" {
		if matched, err := regexp.MatchString(rules.Pattern, fieldName); err != nil {
			check.AllNamesValid = false
			check.NamingErrors = append(check.NamingErrors, &FieldNamingError{
				Field:       fieldName,
				Issue:       "pattern_error",
				CurrentName: fieldName,
				Rule:        rules.Pattern,
				Message:     fmt.Sprintf("Pattern validation error: %v", err),
			})
		} else if !matched {
			check.AllNamesValid = false
			check.NamingErrors = append(check.NamingErrors, &FieldNamingError{
				Field:       fieldName,
				Issue:       "invalid_pattern",
				CurrentName: fieldName,
				Rule:        rules.Pattern,
				Message:     fmt.Sprintf("Field name does not match pattern: %s", rules.Pattern),
			})
		}
	}

	// Length validation
	if rules.MaxLength > 0 && len(fieldName) > rules.MaxLength {
		check.AllNamesValid = false
		check.NamingErrors = append(check.NamingErrors, &FieldNamingError{
			Field:       fieldName,
			Issue:       "too_long",
			CurrentName: fieldName,
			Rule:        fmt.Sprintf("max_length_%d", rules.MaxLength),
			Message:     fmt.Sprintf("Field name too long: %d characters, maximum %d", len(fieldName), rules.MaxLength),
		})
	}

	// Reserved words validation
	for _, reservedWord := range rules.ReservedWords {
		if fieldName == reservedWord {
			check.AllNamesValid = false
			check.NamingErrors = append(check.NamingErrors, &FieldNamingError{
				Field:       fieldName,
				Issue:       "reserved_word",
				CurrentName: fieldName,
				Rule:        "reserved_words",
				Message:     fmt.Sprintf("Field name is a reserved word: %s", reservedWord),
			})
		}
	}

	// Forbidden prefixes validation
	for _, prefix := range rules.ForbiddenPrefixes {
		if strings.HasPrefix(fieldName, prefix) {
			check.AllNamesValid = false
			check.NamingErrors = append(check.NamingErrors, &FieldNamingError{
				Field:       fieldName,
				Issue:       "forbidden_prefix",
				CurrentName: fieldName,
				Rule:        "forbidden_prefixes",
				Message:     fmt.Sprintf("Field name has forbidden prefix: %s", prefix),
			})
		}
	}

	// Forbidden suffixes validation
	for _, suffix := range rules.ForbiddenSuffixes {
		if strings.HasSuffix(fieldName, suffix) {
			check.AllNamesValid = false
			check.NamingErrors = append(check.NamingErrors, &FieldNamingError{
				Field:       fieldName,
				Issue:       "forbidden_suffix",
				CurrentName: fieldName,
				Rule:        "forbidden_suffixes",
				Message:     fmt.Sprintf("Field name has forbidden suffix: %s", suffix),
			})
		}
	}

	// Case style validation
	expectedCase := v.convertToExpectedCase(goFieldName, rules.CaseStyle)
	if fieldName != expectedCase {
		check.StyleViolations = append(check.StyleViolations, &NamingStyleViolation{
			Field:         fieldName,
			CurrentStyle:  v.detectCaseStyle(fieldName),
			ExpectedStyle: rules.CaseStyle,
			Suggestion:    expectedCase,
		})
	}
}

// toSnakeCase converts GoCase to snake_case
func (v *PolicyValidator) toSnakeCase(goCase string) string {
	var result []rune
	for i, r := range goCase {
		if i > 0 && 'A' <= r && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, rune(strings.ToLower(string(r))))
	}
	return string(result)
}

// convertToExpectedCase converts field name to expected case style
func (v *PolicyValidator) convertToExpectedCase(fieldName, caseStyle string) string {
	switch caseStyle {
	case "snake_case":
		return v.toSnakeCase(fieldName)
	case "camelCase":
		return v.toCamelCase(fieldName)
	case "PascalCase":
		return v.toPascalCase(fieldName)
	default:
		return fieldName
	}
}

// toCamelCase converts to camelCase
func (v *PolicyValidator) toCamelCase(str string) string {
	parts := strings.Split(str, "_")
	if len(parts) == 0 {
		return str
	}

	result := strings.ToLower(parts[0])
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			result += strings.ToUpper(parts[i][:1]) + strings.ToLower(parts[i][1:])
		}
	}
	return result
}

// toPascalCase converts to PascalCase
func (v *PolicyValidator) toPascalCase(str string) string {
	parts := strings.Split(str, "_")
	result := ""
	for _, part := range parts {
		if len(part) > 0 {
			result += strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return result
}

// detectCaseStyle detects the case style of a field name
func (v *PolicyValidator) detectCaseStyle(fieldName string) string {
	if strings.Contains(fieldName, "_") {
		return "snake_case"
	} else if len(fieldName) > 0 && 'A' <= fieldName[0] && fieldName[0] <= 'Z' {
		return "PascalCase"
	} else {
		return "camelCase"
	}
}

// collectStructuralIssues collects issues from structural validation
func (v *PolicyValidator) collectStructuralIssues(structuralReport *StructuralValidationReport, report *ValidationReport) {
	// Collect message completeness issues
	if !structuralReport.MessageCompleteness.IsComplete {
		for _, missingField := range structuralReport.MessageCompleteness.MissingFields {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:   v.generateErrorID(),
				Code:      "INCOMPLETE_MESSAGE",
				Message:   fmt.Sprintf("Missing required field: %s", missingField),
				Severity:  "high",
				Category:  "structural",
				Field:     missingField,
				Timestamp: time.Now(),
			})
		}

		for _, corruptedField := range structuralReport.MessageCompleteness.CorruptedFields {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:   v.generateErrorID(),
				Code:      "CORRUPTED_FIELD",
				Message:   fmt.Sprintf("Corrupted field detected: %s", corruptedField),
				Severity:  "critical",
				Category:  "structural",
				Field:     corruptedField,
				Timestamp: time.Now(),
			})
		}
	}

	// Collect required fields issues
	if !structuralReport.RequiredFieldsCheck.AllRequiredPresent {
		for _, missingField := range structuralReport.RequiredFieldsCheck.MissingRequired {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:      v.generateErrorID(),
				Code:         "MISSING_REQUIRED_FIELD",
				Message:      fmt.Sprintf("Required field missing: %s", missingField),
				Severity:     "high",
				Category:     "structural",
				Field:        missingField,
				SuggestedFix: fmt.Sprintf("Add the required field: %s", missingField),
				Timestamp:    time.Now(),
			})
		}
	}

	// Collect data type issues
	if !structuralReport.DataTypeValidation.AllTypesValid {
		for _, typeError := range structuralReport.DataTypeValidation.TypeErrors {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:      v.generateErrorID(),
				Code:         "DATA_TYPE_MISMATCH",
				Message:      typeError.Message,
				Severity:     "medium",
				Category:     "structural",
				Field:        typeError.Field,
				SuggestedFix: fmt.Sprintf("Convert field type from %s to %s", typeError.ActualType, typeError.ExpectedType),
				Timestamp:    time.Now(),
			})
		}

		for _, formatError := range structuralReport.DataTypeValidation.FormatErrors {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:   v.generateErrorID(),
				Code:      "FORMAT_VALIDATION_ERROR",
				Message:   formatError.Message,
				Severity:  "medium",
				Category:  "structural",
				Field:     formatError.Field,
				Timestamp: time.Now(),
			})
		}
	}

	// Collect relationship issues
	if !structuralReport.MessageRelationships.RelationshipsValid {
		for _, brokenRef := range structuralReport.MessageRelationships.BrokenReferences {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:   v.generateErrorID(),
				Code:      "BROKEN_REFERENCE",
				Message:   brokenRef.Message,
				Severity:  "high",
				Category:  "structural",
				Field:     brokenRef.SourceField,
				Timestamp: time.Now(),
			})
		}

		for _, circularRef := range structuralReport.MessageRelationships.CircularReferences {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:   v.generateErrorID(),
				Code:      "CIRCULAR_REFERENCE",
				Message:   circularRef.Message,
				Severity:  "high",
				Category:  "structural",
				Field:     circularRef.StartField,
				Timestamp: time.Now(),
			})
		}

		for _, orphaned := range structuralReport.MessageRelationships.OrphanedObjects {
			report.Warnings = append(report.Warnings, &ValidationWarning{
				WarningID: v.generateWarningID(),
				Code:      "ORPHANED_OBJECT",
				Message:   orphaned.Message,
				Category:  "structural",
				Field:     orphaned.ObjectID,
				Impact:    "maintainability",
				Timestamp: time.Now(),
			})
		}
	}

	// Collect schema compliance issues
	if !structuralReport.SchemaCompliance.IsCompliant {
		for _, issue := range structuralReport.SchemaCompliance.ComplianceIssues {
			severity := issue.Severity
			if severity == "critical" || severity == "high" {
				report.Errors = append(report.Errors, &ValidationError{
					ErrorID:      v.generateErrorID(),
					Code:         "SCHEMA_COMPLIANCE_VIOLATION",
					Message:      issue.Message,
					Severity:     severity,
					Category:     "structural",
					Field:        issue.Element,
					SuggestedFix: issue.Suggestion,
					Timestamp:    time.Now(),
				})
			} else {
				report.Warnings = append(report.Warnings, &ValidationWarning{
					WarningID:      v.generateWarningID(),
					Code:           "SCHEMA_COMPLIANCE_WARNING",
					Message:        issue.Message,
					Category:       "structural",
					Field:          issue.Element,
					Recommendation: issue.Suggestion,
					Impact:         "compliance",
					Timestamp:      time.Now(),
				})
			}
		}
	}

	// Collect field naming issues
	if !structuralReport.FieldNamingCheck.AllNamesValid {
		for _, namingError := range structuralReport.FieldNamingCheck.NamingErrors {
			report.Errors = append(report.Errors, &ValidationError{
				ErrorID:   v.generateErrorID(),
				Code:      "FIELD_NAMING_VIOLATION",
				Message:   namingError.Message,
				Severity:  "low",
				Category:  "structural",
				Field:     namingError.Field,
				Timestamp: time.Now(),
			})
		}

		for _, styleViolation := range structuralReport.FieldNamingCheck.StyleViolations {
			report.Warnings = append(report.Warnings, &ValidationWarning{
				WarningID:      v.generateWarningID(),
				Code:           "NAMING_STYLE_VIOLATION",
				Message:        fmt.Sprintf("Field %s uses %s but expected %s", styleViolation.Field, styleViolation.CurrentStyle, styleViolation.ExpectedStyle),
				Category:       "structural",
				Field:          styleViolation.Field,
				Recommendation: styleViolation.Suggestion,
				Impact:         "maintainability",
				Timestamp:      time.Now(),
			})
		}
	}
}

// generateErrorID generates a unique error ID
func (v *PolicyValidator) generateErrorID() string {
	return fmt.Sprintf("ERR_%d", time.Now().UnixNano())
}

// getSeverity returns severity based on mandatory flag
func (v *PolicyValidator) getSeverity(mandatory bool) string {
	if mandatory {
		return "critical"
	}
	return "medium"
}

// generateWarningID generates a unique warning ID
func (v *PolicyValidator) generateWarningID() string {
	return fmt.Sprintf("WARN_%d", time.Now().UnixNano())
}

// removeDuplicateStrings removes duplicate strings from a slice
func (v *PolicyValidator) removeDuplicateStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}
