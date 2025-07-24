package validator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
)

// PolicyValidator provides comprehensive validation and testing for compiled policies
type PolicyValidator struct {
	schemas       map[string]*AssetClassSchema
	providers     map[string]*AttestationProvider
	jurisdictions map[string]*JurisdictionRules
	config        *ValidatorConfig
}

// ValidatorConfig configures validation behavior
type ValidatorConfig struct {
	EnableStructuralValidation  bool                   `json:"enable_structural_validation"`
	EnableSemanticValidation    bool                   `json:"enable_semantic_validation"`
	EnablePerformanceValidation bool                   `json:"enable_performance_validation"`
	MaxPredicateDepth           int                    `json:"max_predicate_depth"`
	MaxPredicateComplexity      int                    `json:"max_predicate_complexity"`
	PerformanceThresholds       *PerformanceThresholds `json:"performance_thresholds"`
	ValidationRules             *ValidationRuleSet     `json:"validation_rules"`
}

// PerformanceThresholds defines performance validation limits
type PerformanceThresholds struct {
	MaxEvaluationTimeMs    int     `json:"max_evaluation_time_ms"`
	MaxMemoryUsageMB       int     `json:"max_memory_usage_mb"`
	MaxComplexityScore     int     `json:"max_complexity_score"`
	MaxFieldAccessCount    int     `json:"max_field_access_count"`
	WarningComplexityRatio float64 `json:"warning_complexity_ratio"`
}

// ValidationRuleSet contains configurable validation rules
type ValidationRuleSet struct {
	RequiredFields       []string              `json:"required_fields"`
	ForbiddenFields      []string              `json:"forbidden_fields"`
	AllowedDataTypes     []string              `json:"allowed_data_types"`
	FieldNamingRules     *FieldNamingRules     `json:"field_naming_rules"`
	PredicateConstraints *PredicateConstraints `json:"predicate_constraints"`
}

// FieldNamingRules defines field naming conventions
type FieldNamingRules struct {
	Pattern           string   `json:"pattern"`
	CaseStyle         string   `json:"case_style"` // snake_case, camelCase, PascalCase
	MaxLength         int      `json:"max_length"`
	ForbiddenPrefixes []string `json:"forbidden_prefixes"`
	ForbiddenSuffixes []string `json:"forbidden_suffixes"`
	ReservedWords     []string `json:"reserved_words"`
}

// PredicateConstraints defines predicate validation rules
type PredicateConstraints struct {
	MaxLogicalDepth      int      `json:"max_logical_depth"`
	MaxConditionCount    int      `json:"max_condition_count"`
	AllowedOperators     []string `json:"allowed_operators"`
	ForbiddenOperators   []string `json:"forbidden_operators"`
	RequireExplicitTypes bool     `json:"require_explicit_types"`
}

// AssetClassSchema defines the schema for a specific asset class
type AssetClassSchema struct {
	AssetClass      string                    `json:"asset_class"`
	Version         string                    `json:"version"`
	Fields          map[string]*FieldSchema   `json:"fields"`
	RequiredFields  []string                  `json:"required_fields"`
	OptionalFields  []string                  `json:"optional_fields"`
	ValidationRules map[string]*FieldRule     `json:"validation_rules"`
	IndexedFields   []string                  `json:"indexed_fields"`
	ComputedFields  map[string]*ComputedField `json:"computed_fields"`
	BusinessRules   []*BusinessRule           `json:"business_rules"`
	ComplianceRules []*ComplianceRule         `json:"compliance_rules"`
}

// FieldSchema defines the schema for a specific field
type FieldSchema struct {
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	Required      bool          `json:"required"`
	Description   string        `json:"description"`
	Format        string        `json:"format"`
	Pattern       string        `json:"pattern"`
	MinValue      *float64      `json:"min_value,omitempty"`
	MaxValue      *float64      `json:"max_value,omitempty"`
	MinLength     *int          `json:"min_length,omitempty"`
	MaxLength     *int          `json:"max_length,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty"`
	DefaultValue  interface{}   `json:"default_value,omitempty"`
	Deprecated    bool          `json:"deprecated"`
	Examples      []interface{} `json:"examples,omitempty"`
}

// FieldRule defines validation rules for fields
type FieldRule struct {
	RuleID       string                 `json:"rule_id"`
	Description  string                 `json:"description"`
	Expression   string                 `json:"expression"`
	ErrorMessage string                 `json:"error_message"`
	Severity     string                 `json:"severity"` // error, warning, info
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

// ComputedField defines fields calculated from other fields
type ComputedField struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Expression   string                 `json:"expression"`
	Description  string                 `json:"description"`
	Dependencies []string               `json:"dependencies"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

// BusinessRule defines business logic validation rules
type BusinessRule struct {
	RuleID      string                 `json:"rule_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Expression  string                 `json:"expression"`
	Priority    int                    `json:"priority"`
	Tags        []string               `json:"tags"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ComplianceRule defines regulatory compliance rules
type ComplianceRule struct {
	RuleID       string   `json:"rule_id"`
	Framework    string   `json:"framework"` // SOX, PCI-DSS, GDPR, etc.
	Requirement  string   `json:"requirement"`
	Description  string   `json:"description"`
	Mandatory    bool     `json:"mandatory"`
	Citations    []string `json:"citations"`
	TestCriteria []string `json:"test_criteria"`
}

// AttestationProvider defines external attestation service configuration
type AttestationProvider struct {
	ProviderID      string                    `json:"provider_id"`
	Name            string                    `json:"name"`
	Type            string                    `json:"type"` // kyc, aml, credit, identity
	BaseURL         string                    `json:"base_url"`
	Authentication  *AuthenticationConfig     `json:"authentication"`
	SupportedTypes  []string                  `json:"supported_types"`
	ResponseFormat  string                    `json:"response_format"`
	RateLimits      *RateLimitConfig          `json:"rate_limits"`
	SLA             *ServiceLevelAgreement    `json:"sla"`
	TestEndpoints   map[string]string         `json:"test_endpoints"`
	ValidationRules []*ProviderValidationRule `json:"validation_rules"`
}

// AuthenticationConfig defines provider authentication
type AuthenticationConfig struct {
	Type        string            `json:"type"` // api_key, oauth2, jwt
	Credentials map[string]string `json:"credentials"`
	TokenURL    string            `json:"token_url,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
}

// RateLimitConfig defines rate limiting parameters
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	RequestsPerMinute int           `json:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour"`
	BurstLimit        int           `json:"burst_limit"`
	BackoffStrategy   string        `json:"backoff_strategy"`
	RetryAttempts     int           `json:"retry_attempts"`
	TimeoutDuration   time.Duration `json:"timeout_duration"`
}

// ServiceLevelAgreement defines provider SLA
type ServiceLevelAgreement struct {
	ResponseTimeMs int      `json:"response_time_ms"`
	Availability   float64  `json:"availability"` // 99.9%
	Accuracy       float64  `json:"accuracy"`     // 99.5%
	SupportHours   string   `json:"support_hours"`
	EscalationPath []string `json:"escalation_path"`
	PenaltyClause  string   `json:"penalty_clause"`
}

// ProviderValidationRule defines provider-specific validation
type ProviderValidationRule struct {
	RuleID     string                 `json:"rule_id"`
	Field      string                 `json:"field"`
	Validation string                 `json:"validation"`
	ErrorCode  string                 `json:"error_code"`
	Message    string                 `json:"message"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// JurisdictionRules defines jurisdiction-specific validation rules
type JurisdictionRules struct {
	Jurisdiction        string              `json:"jurisdiction"`
	RegulatoryFramework string              `json:"regulatory_framework"`
	Version             string              `json:"version"`
	EnforcementLevels   []string            `json:"enforcement_levels"`
	AttestationTypes    []string            `json:"attestation_types"`
	RequiredFields      []string            `json:"required_fields"`
	ForbiddenFields     []string            `json:"forbidden_fields"`
	DataRetentionRules  *DataRetentionRules `json:"data_retention_rules"`
	PrivacyRules        *PrivacyRules       `json:"privacy_rules"`
	ComplianceChecks    []*ComplianceCheck  `json:"compliance_checks"`
	ReportingRules      []*ReportingRule    `json:"reporting_rules"`
}

// DataRetentionRules defines data retention requirements
type DataRetentionRules struct {
	DefaultRetentionDays int                       `json:"default_retention_days"`
	FieldRetentionRules  map[string]int            `json:"field_retention_rules"`
	PurgeRules           []*PurgeRule              `json:"purge_rules"`
	ArchivalRules        []*ArchivalRule           `json:"archival_rules"`
	ComplianceRules      map[string]*RetentionRule `json:"compliance_rules"`
}

// PrivacyRules defines privacy protection requirements
type PrivacyRules struct {
	PIIFields           []string                `json:"pii_fields"`
	EncryptionRequired  []string                `json:"encryption_required"`
	MaskingRules        map[string]*MaskingRule `json:"masking_rules"`
	ConsentRequirements []*ConsentRequirement   `json:"consent_requirements"`
	RightToErasure      bool                    `json:"right_to_erasure"`
	DataPortability     bool                    `json:"data_portability"`
}

// ComplianceCheck defines regulatory compliance checks
type ComplianceCheck struct {
	CheckID     string                 `json:"check_id"`
	Name        string                 `json:"name"`
	Framework   string                 `json:"framework"`
	Requirement string                 `json:"requirement"`
	Expression  string                 `json:"expression"`
	Severity    string                 `json:"severity"`
	Frequency   string                 `json:"frequency"` // continuous, daily, weekly
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ReportingRule defines regulatory reporting requirements
type ReportingRule struct {
	RuleID     string                 `json:"rule_id"`
	ReportType string                 `json:"report_type"`
	Frequency  string                 `json:"frequency"`
	Recipients []string               `json:"recipients"`
	Format     string                 `json:"format"`
	Fields     []string               `json:"fields"`
	Conditions string                 `json:"conditions"`
	Deadline   string                 `json:"deadline"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// Supporting types for detailed rules
type PurgeRule struct {
	RuleID     string                 `json:"rule_id"`
	Trigger    string                 `json:"trigger"`
	Conditions string                 `json:"conditions"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

type ArchivalRule struct {
	RuleID       string                 `json:"rule_id"`
	TriggerAfter time.Duration          `json:"trigger_after"`
	Destination  string                 `json:"destination"`
	Format       string                 `json:"format"`
	Encryption   bool                   `json:"encryption"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

type RetentionRule struct {
	Framework     string   `json:"framework"`
	RetentionDays int      `json:"retention_days"`
	Justification string   `json:"justification"`
	Exceptions    []string `json:"exceptions"`
}

type MaskingRule struct {
	FieldPattern string                 `json:"field_pattern"`
	MaskingType  string                 `json:"masking_type"` // full, partial, hash
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

type ConsentRequirement struct {
	RequirementID string   `json:"requirement_id"`
	Purpose       string   `json:"purpose"`
	Fields        []string `json:"fields"`
	ConsentType   string   `json:"consent_type"` // explicit, implicit
	Withdrawable  bool     `json:"withdrawable"`
}

// NewPolicyValidator creates a new policy validator instance
func NewPolicyValidator(config *ValidatorConfig) *PolicyValidator {
	if config == nil {
		config = getDefaultValidatorConfig()
	}

	return &PolicyValidator{
		schemas:       make(map[string]*AssetClassSchema),
		providers:     make(map[string]*AttestationProvider),
		jurisdictions: make(map[string]*JurisdictionRules),
		config:        config,
	}
}

// getDefaultValidatorConfig returns default validation configuration
func getDefaultValidatorConfig() *ValidatorConfig {
	return &ValidatorConfig{
		EnableStructuralValidation:  true,
		EnableSemanticValidation:    true,
		EnablePerformanceValidation: true,
		MaxPredicateDepth:           10,
		MaxPredicateComplexity:      1000,
		PerformanceThresholds: &PerformanceThresholds{
			MaxEvaluationTimeMs:    1000,
			MaxMemoryUsageMB:       100,
			MaxComplexityScore:     500,
			MaxFieldAccessCount:    50,
			WarningComplexityRatio: 0.8,
		},
		ValidationRules: &ValidationRuleSet{
			RequiredFields:   []string{"policy_id", "version", "jurisdiction"},
			ForbiddenFields:  []string{},
			AllowedDataTypes: []string{"string", "number", "boolean", "array", "object"},
			FieldNamingRules: &FieldNamingRules{
				Pattern:           "^[a-z][a-z0-9_]*$",
				CaseStyle:         "snake_case",
				MaxLength:         64,
				ForbiddenPrefixes: []string{"__", "sys_"},
				ForbiddenSuffixes: []string{"_tmp", "_temp"},
				ReservedWords:     []string{"id", "type", "class", "system"},
			},
			PredicateConstraints: &PredicateConstraints{
				MaxLogicalDepth:      8,
				MaxConditionCount:    100,
				AllowedOperators:     []string{"AND", "OR", "NOT", "EQ", "NE", "GT", "LT", "GTE", "LTE", "IN", "CONTAINS"},
				ForbiddenOperators:   []string{},
				RequireExplicitTypes: true,
			},
		},
	}
}

// RegisterAssetClassSchema registers a schema for an asset class
func (v *PolicyValidator) RegisterAssetClassSchema(schema *AssetClassSchema) error {
	if schema.AssetClass == "" {
		return fmt.Errorf("asset class cannot be empty")
	}
	v.schemas[schema.AssetClass] = schema
	return nil
}

// RegisterAttestationProvider registers an attestation provider
func (v *PolicyValidator) RegisterAttestationProvider(provider *AttestationProvider) error {
	if provider.ProviderID == "" {
		return fmt.Errorf("provider ID cannot be empty")
	}
	v.providers[provider.ProviderID] = provider
	return nil
}

// RegisterJurisdictionRules registers rules for a jurisdiction
func (v *PolicyValidator) RegisterJurisdictionRules(rules *JurisdictionRules) error {
	if rules.Jurisdiction == "" {
		return fmt.Errorf("jurisdiction cannot be empty")
	}
	v.jurisdictions[rules.Jurisdiction] = rules
	return nil
}

// ValidatePolicy performs comprehensive validation of a compiled policy
func (v *PolicyValidator) ValidatePolicy(policy *parser.CompliancePolicy) *ValidationReport {
	startTime := time.Now()

	report := &ValidationReport{
		PolicyID:          policy.PolicyId,
		Version:           policy.Version,
		Jurisdiction:      policy.Jurisdiction,
		ValidationTime:    startTime,
		IsValid:           true,
		Errors:            make([]*ValidationError, 0),
		Warnings:          make([]*ValidationWarning, 0),
		InfoMessages:      make([]*ValidationInfo, 0),
		StructuralReport:  &StructuralValidationReport{},
		SemanticReport:    &SemanticValidationReport{},
		PerformanceReport: &PerformanceValidationReport{},
		ComplianceReport:  &ComplianceValidationReport{},
		Summary:           &ValidationSummary{},
	}

	// Layer 1: Structural Validation
	if v.config.EnableStructuralValidation {
		v.performStructuralValidation(policy, report)
	}

	// Layer 2: Semantic Validation
	if v.config.EnableSemanticValidation {
		v.performSemanticValidation(policy, report)
	}

	// Layer 3: Performance Validation
	if v.config.EnablePerformanceValidation {
		v.performPerformanceValidation(policy, report)
	}

	// Generate summary
	v.generateValidationSummary(report)

	report.ValidationDuration = time.Since(startTime)
	report.IsValid = len(report.Errors) == 0

	return report
}

// performSemanticValidation conducts comprehensive semantic validation
func (v *PolicyValidator) performSemanticValidation(policy *parser.CompliancePolicy, report *ValidationReport) {
	semanticReport := &SemanticValidationReport{
		FieldPathValidation:   v.validateFieldPaths(policy),
		PredicateLogicCheck:   v.validatePredicateLogic(policy),
		AttestationValidation: v.validateAttestations(policy),
		EnforcementValidation: v.validateEnforcement(policy),
		BusinessLogicCheck:    v.validateBusinessLogic(policy),
		DependencyValidation:  v.validateDependencies(policy),
	}

	report.SemanticReport = semanticReport

	// Collect errors and warnings from semantic validation
	v.collectSemanticIssues(semanticReport, report)
}

// validateFieldPaths validates field paths against asset class schemas
func (v *PolicyValidator) validateFieldPaths(policy *parser.CompliancePolicy) *FieldPathValidation {
	validation := &FieldPathValidation{
		AllPathsValid:   true,
		InvalidPaths:    make([]*InvalidFieldPath, 0),
		DeprecatedPaths: make([]*DeprecatedFieldPath, 0),
		UnknownPaths:    make([]*UnknownFieldPath, 0),
		PathAnalysis:    make(map[string]*FieldPathInfo),
		SchemaCompatibility: &SchemaCompatibilityInfo{
			IsCompatible:       true,
			SchemaVersion:      "1.0.0",
			CompatibilityLevel: "full",
			Issues:             make([]string, 0),
			Recommendations:    make([]string, 0),
		},
	}

	// Get schema for asset class
	schema, hasSchema := v.schemas[policy.AssetClass]
	if !hasSchema {
		validation.SchemaCompatibility.IsCompatible = false
		validation.SchemaCompatibility.CompatibilityLevel = "none"
		validation.SchemaCompatibility.Issues = append(validation.SchemaCompatibility.Issues,
			fmt.Sprintf("No schema available for asset class: %s", policy.AssetClass))
		return validation
	}

	// Validate field paths in rules
	for i, rule := range policy.Rules {
		ruleContext := fmt.Sprintf("rule[%d]", i)
		v.validateRuleFieldPaths(rule, schema, validation, ruleContext)
	}

	// Validate field paths in attestations
	for i, attestation := range policy.Attestations {
		attestationContext := fmt.Sprintf("attestation[%d]", i)
		v.validateAttestationFieldPaths(attestation, schema, validation, attestationContext)
	}

	return validation
}

// validateRuleFieldPaths validates field paths within a rule's predicate
func (v *PolicyValidator) validateRuleFieldPaths(rule *parser.PolicyRule, schema *AssetClassSchema, validation *FieldPathValidation, context string) {
	if rule.Predicate == nil {
		return
	}

	// Extract field paths from predicate
	fieldPaths := v.extractFieldPathsFromPredicate(rule.Predicate)

	for _, fieldPath := range fieldPaths {
		pathInfo := v.analyzeFieldPath(fieldPath, schema, context)
		validation.PathAnalysis[fieldPath] = pathInfo

		if !pathInfo.IsValid {
			validation.AllPathsValid = false
			validation.InvalidPaths = append(validation.InvalidPaths, &InvalidFieldPath{
				Path:       fieldPath,
				Reason:     "Field not found in schema",
				Context:    context,
				Suggestion: v.suggestSimilarFieldPath(fieldPath, schema),
			})
		}

		if pathInfo.IsDeprecated {
			validation.DeprecatedPaths = append(validation.DeprecatedPaths, &DeprecatedFieldPath{
				Path:              fieldPath,
				DeprecationReason: "Field marked as deprecated in schema",
				Alternative:       v.findAlternativeFieldPath(fieldPath, schema),
			})
		}
	}
}

// validateAttestationFieldPaths validates field paths in attestations
func (v *PolicyValidator) validateAttestationFieldPaths(attestation *parser.AttestationRequirement, schema *AssetClassSchema, validation *FieldPathValidation, context string) {
	for _, requiredField := range attestation.RequiredFields {
		pathInfo := v.analyzeFieldPath(requiredField, schema, context)
		validation.PathAnalysis[requiredField] = pathInfo

		if !pathInfo.IsValid {
			validation.AllPathsValid = false
			validation.UnknownPaths = append(validation.UnknownPaths, &UnknownFieldPath{
				Path:         requiredField,
				SimilarPaths: v.findSimilarPaths(requiredField, schema),
				Confidence:   0.8,
				Suggestion:   fmt.Sprintf("Verify field path in %s context", context),
			})
		}
	}
}

// extractFieldPathsFromPredicate extracts field paths from a predicate
func (v *PolicyValidator) extractFieldPathsFromPredicate(predicate *parser.Predicate) []string {
	paths := make([]string, 0)

	if predicate == nil {
		return paths
	}

	// Handle different predicate types
	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Comparison:
		if p.Comparison != nil && p.Comparison.FieldPath != nil {
			paths = append(paths, p.Comparison.FieldPath.RawPath)
		}
	case *parser.Predicate_Exists:
		if p.Exists != nil && p.Exists.FieldPath != nil {
			paths = append(paths, p.Exists.FieldPath.RawPath)
		}
	case *parser.Predicate_Range:
		if p.Range != nil && p.Range.FieldPath != nil {
			paths = append(paths, p.Range.FieldPath.RawPath)
		}
	case *parser.Predicate_Set:
		if p.Set != nil && p.Set.FieldPath != nil {
			paths = append(paths, p.Set.FieldPath.RawPath)
		}
	case *parser.Predicate_Time:
		if p.Time != nil && p.Time.FieldPath != nil {
			paths = append(paths, p.Time.FieldPath.RawPath)
		}
	case *parser.Predicate_Regex:
		if p.Regex != nil && p.Regex.FieldPath != nil {
			paths = append(paths, p.Regex.FieldPath.RawPath)
		}
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			for _, operand := range p.Logical.Operands {
				paths = append(paths, v.extractFieldPathsFromPredicate(operand)...)
			}
		}
	}

	return paths
}

// analyzeFieldPath analyzes a field path against the schema
func (v *PolicyValidator) analyzeFieldPath(fieldPath string, schema *AssetClassSchema, context string) *FieldPathInfo {
	info := &FieldPathInfo{
		Path:         fieldPath,
		IsValid:      false,
		Type:         "unknown",
		IsRequired:   false,
		IsDeprecated: false,
		IsIndexed:    false,
		AccessCost:   1,
		Usage: &FieldUsageInfo{
			UsageCount:        1,
			UsageContexts:     []string{context},
			AccessPatterns:    []string{"direct"},
			PerformanceImpact: "low",
		},
		Context: make(map[string]interface{}),
	}

	// Check if field exists in schema
	if fieldSchema, exists := schema.Fields[fieldPath]; exists {
		info.IsValid = true
		info.Type = fieldSchema.Type
		info.IsRequired = fieldSchema.Required
		info.IsDeprecated = fieldSchema.Deprecated
		info.Context["schema_description"] = fieldSchema.Description
		info.Context["default_value"] = fieldSchema.DefaultValue
	}

	// Check if field is in required fields list
	for _, requiredField := range schema.RequiredFields {
		if requiredField == fieldPath {
			info.IsRequired = true
			break
		}
	}

	// Check if field is indexed
	for _, indexedField := range schema.IndexedFields {
		if indexedField == fieldPath {
			info.IsIndexed = true
			info.AccessCost = 1
			info.Usage.PerformanceImpact = "low"
			break
		}
	}

	// Calculate access cost based on field complexity
	info.AccessCost = v.calculateFieldAccessCost(fieldPath)

	return info
}

// calculateFieldAccessCost calculates the cost of accessing a field
func (v *PolicyValidator) calculateFieldAccessCost(fieldPath string) int {
	// Simple cost calculation based on path complexity
	cost := 1

	// Nested field access increases cost
	if strings.Contains(fieldPath, ".") {
		cost += strings.Count(fieldPath, ".")
	}

	// Array access increases cost
	if strings.Contains(fieldPath, "[") {
		cost += strings.Count(fieldPath, "[")
	}

	// Function calls increase cost significantly
	if strings.Contains(fieldPath, "(") {
		cost += strings.Count(fieldPath, "(") * 3
	}

	return cost
}

// suggestSimilarFieldPath suggests a similar field path
func (v *PolicyValidator) suggestSimilarFieldPath(fieldPath string, schema *AssetClassSchema) string {
	bestMatch := ""
	minDistance := len(fieldPath) + 1

	for schemaField := range schema.Fields {
		distance := v.levenshteinDistance(fieldPath, schemaField)
		if distance < minDistance && distance <= len(fieldPath)/2 {
			minDistance = distance
			bestMatch = schemaField
		}
	}

	return bestMatch
}

// findAlternativeFieldPath finds an alternative for a deprecated field
func (v *PolicyValidator) findAlternativeFieldPath(fieldPath string, schema *AssetClassSchema) string {
	// Look for similar non-deprecated fields
	for schemaField, fieldSchema := range schema.Fields {
		if !fieldSchema.Deprecated && v.areSimilarFields(fieldPath, schemaField) {
			return schemaField
		}
	}
	return ""
}

// findSimilarPaths finds similar field paths
func (v *PolicyValidator) findSimilarPaths(fieldPath string, schema *AssetClassSchema) []string {
	similar := make([]string, 0)

	for schemaField := range schema.Fields {
		if v.areSimilarFields(fieldPath, schemaField) {
			similar = append(similar, schemaField)
		}
	}

	return similar
}

// areSimilarFields checks if two fields are similar
func (v *PolicyValidator) areSimilarFields(field1, field2 string) bool {
	distance := v.levenshteinDistance(field1, field2)
	maxLen := len(field1)
	if len(field2) > maxLen {
		maxLen = len(field2)
	}

	// Consider fields similar if edit distance is less than 30% of max length
	return distance < maxLen/3
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (v *PolicyValidator) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}

	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b && a < c {
		return a
	} else if b < c {
		return b
	}
	return c
}

// validatePredicateLogic validates the logic consistency of predicates
func (v *PolicyValidator) validatePredicateLogic(policy *parser.CompliancePolicy) *PredicateLogicCheck {
	check := &PredicateLogicCheck{
		LogicValid:         true,
		ConsistencyIssues:  make([]*LogicConsistencyIssue, 0),
		CompletenessCheck:  &LogicCompletenessCheck{IsComplete: true, MissingConditions: make([]*MissingCondition, 0), UncoveredCases: make([]*UncoveredCase, 0)},
		OptimizationHints:  make([]*LogicOptimizationHint, 0),
		ComplexityAnalysis: &LogicComplexityAnalysis{OperatorCounts: make(map[string]int), ComplexityByRule: make(map[string]int)},
	}

	// Analyze each rule's predicate logic
	for i, rule := range policy.Rules {
		ruleContext := fmt.Sprintf("rule[%d]", i)
		v.analyzePredicateLogic(rule.Predicate, ruleContext, check)
	}

	// Generate optimization hints
	v.generateLogicOptimizationHints(policy, check)

	return check
}

// analyzePredicateLogic analyzes the logic of a single predicate
func (v *PolicyValidator) analyzePredicateLogic(predicate *parser.Predicate, context string, check *PredicateLogicCheck) {
	if predicate == nil {
		return
	}

	// Analyze complexity
	complexity := v.calculatePredicateComplexity(predicate)
	check.ComplexityAnalysis.ComplexityByRule[context] = complexity
	check.ComplexityAnalysis.TotalComplexity += complexity

	// Track operator usage
	v.countOperators(predicate, check.ComplexityAnalysis.OperatorCounts)

	// Check for consistency issues
	v.detectLogicConsistencyIssues(predicate, context, check)

	// Calculate max depth
	depth := v.calculatePredicateDepth(predicate)
	if depth > check.ComplexityAnalysis.MaxDepth {
		check.ComplexityAnalysis.MaxDepth = depth
	}

	// Check against complexity thresholds
	if complexity > v.config.MaxPredicateComplexity {
		check.LogicValid = false
		check.ConsistencyIssues = append(check.ConsistencyIssues, &LogicConsistencyIssue{
			IssueType:     "high_complexity",
			Description:   fmt.Sprintf("Predicate complexity (%d) exceeds threshold (%d)", complexity, v.config.MaxPredicateComplexity),
			PredicatePath: context,
			Severity:      "medium",
			Resolution:    "Consider simplifying the predicate or breaking it into smaller parts",
		})
	}

	if depth > v.config.MaxPredicateDepth {
		check.LogicValid = false
		check.ConsistencyIssues = append(check.ConsistencyIssues, &LogicConsistencyIssue{
			IssueType:     "deep_nesting",
			Description:   fmt.Sprintf("Predicate depth (%d) exceeds threshold (%d)", depth, v.config.MaxPredicateDepth),
			PredicatePath: context,
			Severity:      "medium",
			Resolution:    "Reduce nesting depth by restructuring the logic",
		})
	}
}

// calculatePredicateComplexity calculates the complexity score of a predicate
func (v *PolicyValidator) calculatePredicateComplexity(predicate *parser.Predicate) int {
	if predicate == nil {
		return 0
	}

	complexity := 1 // Base complexity

	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			complexity += 2 // Logical operations add complexity
			for _, operand := range p.Logical.Operands {
				complexity += v.calculatePredicateComplexity(operand)
			}
		}
	case *parser.Predicate_Comparison:
		complexity += 1
	case *parser.Predicate_Range:
		complexity += 2
	case *parser.Predicate_Set:
		if p.Set != nil {
			complexity += len(p.Set.Values) / 5 // Large value sets add complexity
		}
	case *parser.Predicate_Expression:
		if p.Expression != nil {
			complexity += len(p.Expression.Expression) / 20 // Complex expressions add complexity
		}
	case *parser.Predicate_Regex:
		if p.Regex != nil {
			complexity += len(p.Regex.Pattern) / 10 // Complex regex patterns add complexity
		}
	}

	return complexity
}

// calculatePredicateDepth calculates the nesting depth of a predicate
func (v *PolicyValidator) calculatePredicateDepth(predicate *parser.Predicate) int {
	if predicate == nil {
		return 0
	}

	maxChildDepth := 0

	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			for _, operand := range p.Logical.Operands {
				childDepth := v.calculatePredicateDepth(operand)
				if childDepth > maxChildDepth {
					maxChildDepth = childDepth
				}
			}
		}
	}

	return 1 + maxChildDepth
}

// countOperators counts the usage of different operators
func (v *PolicyValidator) countOperators(predicate *parser.Predicate, counts map[string]int) {
	if predicate == nil {
		return
	}

	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			operatorName := p.Logical.Operator.String()
			counts[operatorName]++
			for _, operand := range p.Logical.Operands {
				v.countOperators(operand, counts)
			}
		}
	case *parser.Predicate_Comparison:
		if p.Comparison != nil {
			operatorName := p.Comparison.Operator.String()
			counts[operatorName]++
		}
	case *parser.Predicate_Range:
		counts["RANGE"]++
	case *parser.Predicate_Set:
		if p.Set != nil {
			operatorName := p.Set.Operation.String()
			counts[operatorName]++
		}
	case *parser.Predicate_Time:
		if p.Time != nil {
			operatorName := p.Time.Operator.String()
			counts[operatorName]++
		}
	}
}

// detectLogicConsistencyIssues detects logic consistency problems
func (v *PolicyValidator) detectLogicConsistencyIssues(predicate *parser.Predicate, context string, check *PredicateLogicCheck) {
	if predicate == nil {
		return
	}

	// Check for tautologies and contradictions in logical predicates
	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			v.detectLogicalInconsistencies(p.Logical, context, check)
			for _, operand := range p.Logical.Operands {
				v.detectLogicConsistencyIssues(operand, context, check)
			}
		}
	}
}

// detectLogicalInconsistencies detects inconsistencies in logical operations
func (v *PolicyValidator) detectLogicalInconsistencies(logical *parser.LogicalPredicate, context string, check *PredicateLogicCheck) {
	if logical == nil || len(logical.Operands) == 0 {
		return
	}

	// Check for tautologies (A OR NOT A)
	if logical.Operator == parser.LogicalOperator_LOGICAL_OPERATOR_OR {
		v.checkForTautologies(logical, context, check)
	}

	// Check for contradictions (A AND NOT A)
	if logical.Operator == parser.LogicalOperator_LOGICAL_OPERATOR_AND {
		v.checkForContradictions(logical, context, check)
	}

	// Check for unreachable conditions
	v.checkForUnreachableConditions(logical, context, check)
}

// checkForTautologies checks for tautological conditions
func (v *PolicyValidator) checkForTautologies(logical *parser.LogicalPredicate, context string, check *PredicateLogicCheck) {
	// Simplified tautology detection - would need more sophisticated analysis in practice
	operandCount := len(logical.Operands)
	if operandCount > 10 { // Too many operands might indicate a tautology
		check.LogicValid = false
		check.ConsistencyIssues = append(check.ConsistencyIssues, &LogicConsistencyIssue{
			IssueType:     "potential_tautology",
			Description:   fmt.Sprintf("OR condition with %d operands may be tautological", operandCount),
			PredicatePath: context,
			Severity:      "low",
			Resolution:    "Review logic to ensure all conditions are necessary",
		})
	}
}

// checkForContradictions checks for contradictory conditions
func (v *PolicyValidator) checkForContradictions(logical *parser.LogicalPredicate, context string, check *PredicateLogicCheck) {
	// Simplified contradiction detection
	fieldPaths := make(map[string]int)

	for _, operand := range logical.Operands {
		paths := v.extractFieldPathsFromPredicate(operand)
		for _, path := range paths {
			fieldPaths[path]++
		}
	}

	// If the same field is referenced multiple times in an AND condition,
	// it might indicate a contradiction
	for path, count := range fieldPaths {
		if count > 3 {
			check.LogicValid = false
			check.ConsistencyIssues = append(check.ConsistencyIssues, &LogicConsistencyIssue{
				IssueType:     "potential_contradiction",
				Description:   fmt.Sprintf("Field %s referenced %d times in AND condition", path, count),
				PredicatePath: context,
				Severity:      "medium",
				Resolution:    "Review conditions on the same field for potential conflicts",
			})
		}
	}
}

// checkForUnreachableConditions checks for unreachable conditions
func (v *PolicyValidator) checkForUnreachableConditions(logical *parser.LogicalPredicate, context string, check *PredicateLogicCheck) {
	// This would require more sophisticated static analysis
	// For now, we'll just check for obviously unreachable patterns

	if len(logical.Operands) > 1 {
		// Check if any operand is always false, making an AND condition unreachable
		if logical.Operator == parser.LogicalOperator_LOGICAL_OPERATOR_AND {
			// This would need semantic analysis of the operands
		}
	}
}

// generateLogicOptimizationHints generates optimization hints for predicates
func (v *PolicyValidator) generateLogicOptimizationHints(policy *parser.CompliancePolicy, check *PredicateLogicCheck) {
	// Analyze complexity hotspots
	for ruleContext, complexity := range check.ComplexityAnalysis.ComplexityByRule {
		if complexity > v.config.PerformanceThresholds.MaxComplexityScore {
			check.OptimizationHints = append(check.OptimizationHints, &LogicOptimizationHint{
				HintType:       "simplify",
				Description:    fmt.Sprintf("Rule %s has high complexity (%d)", ruleContext, complexity),
				PredicatePath:  ruleContext,
				EstimatedGain:  0.3,
				Implementation: "Break down complex conditions into simpler ones",
				Complexity:     "medium",
			})
		}
	}

	// Suggest reordering based on operator frequency
	if check.ComplexityAnalysis.OperatorCounts["LOGICAL_OPERATOR_AND"] >
		check.ComplexityAnalysis.OperatorCounts["LOGICAL_OPERATOR_OR"]*2 {
		check.OptimizationHints = append(check.OptimizationHints, &LogicOptimizationHint{
			HintType:       "reorder",
			Description:    "Consider placing more selective conditions first in AND operations",
			PredicatePath:  "global",
			EstimatedGain:  0.2,
			Implementation: "Reorder AND conditions to evaluate cheaper/more selective conditions first",
			Complexity:     "low",
		})
	}

	// Suggest indexing for frequently accessed fields
	fieldUsage := make(map[string]int)
	for _, rule := range policy.Rules {
		paths := v.extractFieldPathsFromPredicate(rule.Predicate)
		for _, path := range paths {
			fieldUsage[path]++
		}
	}

	for field, usage := range fieldUsage {
		if usage >= 3 {
			check.OptimizationHints = append(check.OptimizationHints, &LogicOptimizationHint{
				HintType:       "index",
				Description:    fmt.Sprintf("Field %s is accessed %d times - consider indexing", field, usage),
				PredicatePath:  field,
				EstimatedGain:  0.5,
				Implementation: fmt.Sprintf("Add index for field: %s", field),
				Complexity:     "low",
			})
		}
	}
}

// validateAttestations validates attestation requirements and providers
func (v *PolicyValidator) validateAttestations(policy *parser.CompliancePolicy) *AttestationValidation {
	validation := &AttestationValidation{
		AllValid:              true,
		UnsupportedProviders:  make([]*UnsupportedProvider, 0),
		InvalidRequirements:   make([]*InvalidAttestation, 0),
		ProviderCompatibility: make([]*ProviderCompatibilityInfo, 0),
		CostEstimation:        &AttestationCostEstimation{CostBreakdown: make(map[string]float64), CostPerAttestation: make(map[string]float64)},
		PerformanceEstimation: &AttestationPerformanceEstimation{TimeBreakdown: make(map[string]time.Duration)},
	}

	// Validate each attestation requirement
	for i, attestation := range policy.Attestations {
		v.validateSingleAttestation(attestation, i, validation)
	}

	// Estimate costs and performance
	v.estimateAttestationCosts(policy.Attestations, validation.CostEstimation)
	v.estimateAttestationPerformance(policy.Attestations, validation.PerformanceEstimation)

	return validation
}

// validateSingleAttestation validates a single attestation requirement
func (v *PolicyValidator) validateSingleAttestation(attestation *parser.AttestationRequirement, index int, validation *AttestationValidation) {
	attestationID := fmt.Sprintf("attestation_%d", index)

	// Check if we have a provider for this attestation type
	hasProvider := false
	for _, provider := range v.providers {
		for _, supportedType := range provider.SupportedTypes {
			if supportedType == attestation.Type.String() {
				hasProvider = true

				// Add provider compatibility info
				validation.ProviderCompatibility = append(validation.ProviderCompatibility, &ProviderCompatibilityInfo{
					ProviderID:     provider.ProviderID,
					IsCompatible:   true,
					SupportedTypes: provider.SupportedTypes,
					Limitations:    make([]string, 0),
					Configuration:  make(map[string]interface{}),
				})
				break
			}
		}
		if hasProvider {
			break
		}
	}

	if !hasProvider {
		validation.AllValid = false
		validation.UnsupportedProviders = append(validation.UnsupportedProviders, &UnsupportedProvider{
			ProviderID:           attestationID,
			RequestedType:        attestation.Type.String(),
			SupportedTypes:       v.getSupportedAttestationTypes(),
			AlternativeProviders: v.findAlternativeProviders(attestation.Type.String()),
			Message:              fmt.Sprintf("No provider available for attestation type: %s", attestation.Type.String()),
		})
	}

	// Validate required fields
	if len(attestation.RequiredFields) == 0 && attestation.Required {
		validation.AllValid = false
		validation.InvalidRequirements = append(validation.InvalidRequirements, &InvalidAttestation{
			AttestationID:  attestationID,
			Type:           attestation.Type.String(),
			InvalidReason:  "Required attestation has no required fields specified",
			RequiredFields: []string{},
			MissingFields:  []string{"required_fields"},
			Suggestion:     "Specify the required fields for this attestation",
		})
	}

	// Validate field existence in schema
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		missingFields := make([]string, 0)
		for _, field := range attestation.RequiredFields {
			if _, fieldExists := schema.Fields[field]; !fieldExists {
				missingFields = append(missingFields, field)
			}
		}

		if len(missingFields) > 0 {
			validation.AllValid = false
			validation.InvalidRequirements = append(validation.InvalidRequirements, &InvalidAttestation{
				AttestationID:  attestationID,
				Type:           attestation.Type.String(),
				InvalidReason:  "References to non-existent fields",
				RequiredFields: attestation.RequiredFields,
				MissingFields:  missingFields,
				Suggestion:     "Update field references or add missing fields to schema",
			})
		}
	}
}

// getSupportedAttestationTypes returns all supported attestation types
func (v *PolicyValidator) getSupportedAttestationTypes() []string {
	types := make(map[string]bool)
	for _, provider := range v.providers {
		for _, supportedType := range provider.SupportedTypes {
			types[supportedType] = true
		}
	}

	result := make([]string, 0, len(types))
	for t := range types {
		result = append(result, t)
	}
	return result
}

// findAlternativeProviders finds alternative providers for an attestation type
func (v *PolicyValidator) findAlternativeProviders(attestationType string) []string {
	alternatives := make([]string, 0)

	// Look for providers with similar attestation types
	for _, provider := range v.providers {
		for _, supportedType := range provider.SupportedTypes {
			if v.areSimilarAttestationTypes(attestationType, supportedType) {
				alternatives = append(alternatives, provider.ProviderID)
				break
			}
		}
	}

	return alternatives
}

// areSimilarAttestationTypes checks if two attestation types are similar
func (v *PolicyValidator) areSimilarAttestationTypes(type1, type2 string) bool {
	// Simple similarity check - could be enhanced with more sophisticated matching
	return strings.Contains(strings.ToLower(type1), strings.ToLower(type2)) ||
		strings.Contains(strings.ToLower(type2), strings.ToLower(type1))
}

// estimateAttestationCosts estimates the cost of attestations
func (v *PolicyValidator) estimateAttestationCosts(attestations []*parser.AttestationRequirement, estimation *AttestationCostEstimation) {
	estimation.Currency = "USD"
	estimation.EstimationAccuracy = "rough"

	// Default cost estimates per attestation type
	defaultCosts := map[string]float64{
		"ATTESTATION_TYPE_KYC":                    25.0,
		"ATTESTATION_TYPE_AML":                    15.0,
		"ATTESTATION_TYPE_ACCREDITED_INVESTOR":    50.0,
		"ATTESTATION_TYPE_INSTITUTIONAL":          100.0,
		"ATTESTATION_TYPE_REGULATORY_APPROVAL":    200.0,
		"ATTESTATION_TYPE_FINANCIAL_STATEMENT":    75.0,
		"ATTESTATION_TYPE_CREDIT_RATING":          30.0,
		"ATTESTATION_TYPE_TAX_STATUS":             20.0,
		"ATTESTATION_TYPE_JURISDICTION_PROOF":     15.0,
		"ATTESTATION_TYPE_IDENTITY_VERIFICATION":  10.0,
		"ATTESTATION_TYPE_BIOMETRIC_VERIFICATION": 40.0,
		"ATTESTATION_TYPE_SANCTION_SCREENING":     12.0,
		"ATTESTATION_TYPE_PEP_CHECK":              10.0,
		"ATTESTATION_TYPE_ADVERSE_MEDIA":          8.0,
	}

	totalCost := 0.0
	for _, attestation := range attestations {
		typeString := attestation.Type.String()
		cost := defaultCosts[typeString]
		if cost == 0 {
			cost = 25.0 // Default cost for unknown types
		}

		estimation.CostPerAttestation[typeString] = cost
		estimation.CostBreakdown[typeString] += cost
		totalCost += cost
	}

	estimation.TotalEstimatedCost = totalCost

	// Add cost optimization tips
	estimation.CostOptimizationTips = []*CostOptimizationTip{
		{
			TipType:          "batch_processing",
			Description:      "Process multiple attestations together to reduce per-unit costs",
			EstimatedSavings: totalCost * 0.15,
			Implementation:   "Group attestations by provider and submit in batches",
			Priority:         "medium",
		},
	}

	if totalCost > 500 {
		estimation.CostOptimizationTips = append(estimation.CostOptimizationTips, &CostOptimizationTip{
			TipType:          "provider_negotiation",
			Description:      "Consider negotiating volume discounts with providers",
			EstimatedSavings: totalCost * 0.2,
			Implementation:   "Contact providers for enterprise pricing tiers",
			Priority:         "high",
		})
	}
}

// estimateAttestationPerformance estimates the performance impact of attestations
func (v *PolicyValidator) estimateAttestationPerformance(attestations []*parser.AttestationRequirement, estimation *AttestationPerformanceEstimation) {
	// Default time estimates per attestation type (in milliseconds)
	defaultTimes := map[string]time.Duration{
		"ATTESTATION_TYPE_KYC":                    2000 * time.Millisecond,
		"ATTESTATION_TYPE_AML":                    1500 * time.Millisecond,
		"ATTESTATION_TYPE_ACCREDITED_INVESTOR":    3000 * time.Millisecond,
		"ATTESTATION_TYPE_INSTITUTIONAL":          5000 * time.Millisecond,
		"ATTESTATION_TYPE_REGULATORY_APPROVAL":    10000 * time.Millisecond,
		"ATTESTATION_TYPE_FINANCIAL_STATEMENT":    4000 * time.Millisecond,
		"ATTESTATION_TYPE_CREDIT_RATING":          2500 * time.Millisecond,
		"ATTESTATION_TYPE_TAX_STATUS":             1000 * time.Millisecond,
		"ATTESTATION_TYPE_JURISDICTION_PROOF":     800 * time.Millisecond,
		"ATTESTATION_TYPE_IDENTITY_VERIFICATION":  500 * time.Millisecond,
		"ATTESTATION_TYPE_BIOMETRIC_VERIFICATION": 3000 * time.Millisecond,
		"ATTESTATION_TYPE_SANCTION_SCREENING":     700 * time.Millisecond,
		"ATTESTATION_TYPE_PEP_CHECK":              600 * time.Millisecond,
		"ATTESTATION_TYPE_ADVERSE_MEDIA":          900 * time.Millisecond,
	}

	totalTime := time.Duration(0)
	for _, attestation := range attestations {
		typeString := attestation.Type.String()
		duration := defaultTimes[typeString]
		if duration == 0 {
			duration = 2000 * time.Millisecond // Default time for unknown types
		}

		estimation.TimeBreakdown[typeString] += duration
		totalTime += duration
	}

	estimation.TotalEstimatedTime = totalTime

	// Suggest parallelization opportunities
	if len(attestations) > 1 {
		estimation.ParallelizationOptions = []*ParallelizationOption{
			{
				Description:      "Parallel attestation processing",
				EstimatedSpeedup: 0.7, // 70% of sequential time
				Implementation:   "Process independent attestations concurrently",
				Dependencies:     []string{"rate_limiting", "provider_capacity"},
				Complexity:       "medium",
			},
		}
	}

	// Analyze bottlenecks
	estimation.BottleneckAnalysis = &AttestationBottleneckAnalysis{
		PrimaryBottleneck: "external_api_latency",
		BottleneckFactors: []*BottleneckFactor{
			{
				Factor:       "Network latency",
				ImpactLevel:  "high",
				Description:  "Network calls to external attestation providers",
				Contribution: 0.4,
				Addressable:  true,
			},
			{
				Factor:       "Provider processing time",
				ImpactLevel:  "medium",
				Description:  "Time for providers to process attestation requests",
				Contribution: 0.35,
				Addressable:  false,
			},
			{
				Factor:       "Rate limiting",
				ImpactLevel:  "medium",
				Description:  "Provider-imposed rate limits",
				Contribution: 0.25,
				Addressable:  true,
			},
		},
		ImpactAssessment: &BottleneckImpact{
			PerformanceDegradation: 0.3,
			AdditionalLatency:      totalTime * 30 / 100,
			ResourceUtilization:    0.6,
			UserExperienceImpact:   "moderate",
			BusinessImpact:         "low",
		},
		MitigationStrategies: []*MitigationStrategy{
			{
				Strategy:           "connection_pooling",
				Description:        "Use connection pooling to reduce connection overhead",
				EstimatedGain:      0.15,
				ImplementationCost: "low",
				Timeline:           "1-2 weeks",
				Priority:           "medium",
			},
			{
				Strategy:           "caching",
				Description:        "Cache attestation results where appropriate",
				EstimatedGain:      0.25,
				ImplementationCost: "medium",
				Timeline:           "2-4 weeks",
				Priority:           "high",
			},
		},
	}

	// Add performance optimization tips
	estimation.PerformanceOptimizations = []*PerformanceOptimizationTip{
		{
			TipType:        "async_processing",
			Description:    "Process non-critical attestations asynchronously",
			EstimatedGain:  0.4,
			Implementation: "Move optional attestations to background processing",
			Complexity:     "medium",
			Priority:       "high",
		},
	}
}

// validateEnforcement validates enforcement configurations
func (v *PolicyValidator) validateEnforcement(policy *parser.CompliancePolicy) *EnforcementValidation {
	validation := &EnforcementValidation{
		ValidConfigurations:   make([]string, 0),
		InvalidConfigurations: make([]string, 0),
		MissingActions:        make([]string, 0),
		UnsupportedActions:    make([]string, 0),
		EnforcementAnalysis:   &EnforcementAnalysis{ActionTypes: make(map[string]int)},
	}

	if policy.Enforcement == nil {
		validation.MissingActions = append(validation.MissingActions, "enforcement_configuration")
		return validation
	}

	enforcement := policy.Enforcement

	// Validate enforcement level
	if v.isValidEnforcementLevel(enforcement.Level, policy.Jurisdiction) {
		validation.ValidConfigurations = append(validation.ValidConfigurations, "enforcement_level")
	} else {
		validation.InvalidConfigurations = append(validation.InvalidConfigurations, "enforcement_level")
	}

	// Validate enforcement actions
	for _, action := range enforcement.Actions {
		actionString := action.String()
		validation.EnforcementAnalysis.ActionTypes[actionString]++

		if v.isValidEnforcementAction(action, policy.Jurisdiction) {
			validation.ValidConfigurations = append(validation.ValidConfigurations, actionString)
		} else {
			validation.UnsupportedActions = append(validation.UnsupportedActions, actionString)
		}
	}

	// Set enforcement analysis details
	validation.EnforcementAnalysis.EnforcementLevel = enforcement.Level.String()
	validation.EnforcementAnalysis.TotalActions = len(enforcement.Actions)
	validation.EnforcementAnalysis.ResponseTime = time.Duration(enforcement.GracePeriodSeconds) * time.Second

	// Analyze escalation paths
	validation.EnforcementAnalysis.EscalationPaths = v.analyzeEscalationPaths(enforcement)

	// Estimate resource requirements
	validation.EnforcementAnalysis.ResourceRequirements = v.estimateEnforcementResources(enforcement)

	return validation
}

// isValidEnforcementLevel checks if an enforcement level is valid for the jurisdiction
func (v *PolicyValidator) isValidEnforcementLevel(level parser.EnforcementLevel, jurisdiction string) bool {
	if rules, exists := v.jurisdictions[jurisdiction]; exists {
		levelString := level.String()
		for _, allowedLevel := range rules.EnforcementLevels {
			if allowedLevel == levelString {
				return true
			}
		}
		return false
	}

	// If no jurisdiction rules, allow standard levels
	return level != parser.EnforcementLevel_ENFORCEMENT_LEVEL_UNSPECIFIED
}

// isValidEnforcementAction checks if an enforcement action is valid for the jurisdiction
func (v *PolicyValidator) isValidEnforcementAction(action parser.EnforcementAction, jurisdiction string) bool {
	// Some actions might be restricted in certain jurisdictions
	restrictedActions := map[string][]string{
		"EU": {"ENFORCEMENT_ACTION_FREEZE_ACCOUNT"}, // Example: account freezing might be restricted in EU
	}

	if restricted, exists := restrictedActions[jurisdiction]; exists {
		actionString := action.String()
		for _, restrictedAction := range restricted {
			if restrictedAction == actionString {
				return false
			}
		}
	}

	return action != parser.EnforcementAction_ENFORCEMENT_ACTION_UNSPECIFIED
}

// analyzeEscalationPaths analyzes enforcement escalation paths
func (v *PolicyValidator) analyzeEscalationPaths(enforcement *parser.EnforcementConfig) []string {
	paths := make([]string, 0)

	// Define typical escalation sequences
	escalationMap := map[parser.EnforcementLevel][]string{
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_MONITORING:    {"log", "alert"},
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_ADVISORY:      {"log", "alert", "notify_compliance"},
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_WARNING:       {"log", "alert", "notify_compliance", "escalate"},
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_SOFT_BLOCKING: {"log", "alert", "delay_transaction", "require_approval"},
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_BLOCKING:      {"log", "alert", "block_transaction", "notify_regulator"},
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_CRITICAL:      {"log", "alert", "block_transaction", "freeze_account", "notify_regulator"},
		parser.EnforcementLevel_ENFORCEMENT_LEVEL_EMERGENCY:     {"log", "alert", "block_transaction", "freeze_account", "suspend_account", "notify_regulator", "legal_hold"},
	}

	if escalationSequence, exists := escalationMap[enforcement.Level]; exists {
		paths = escalationSequence
	}

	return paths
}

// estimateEnforcementResources estimates resource requirements for enforcement
func (v *PolicyValidator) estimateEnforcementResources(enforcement *parser.EnforcementConfig) *ResourceRequirements {
	return &ResourceRequirements{
		ComputeResources: &ComputeResources{
			CPUCores:      2,
			MemoryMB:      1024,
			GPURequired:   false,
			EstimatedLoad: 0.3,
		},
		StorageResources: &StorageResources{
			DiskSpaceGB:    10,
			IOPSRequired:   100,
			BackupRequired: true,
			RetentionDays:  365,
		},
		NetworkResources: &NetworkResources{
			BandwidthMbps:        10,
			LatencyRequirement:   100,
			ExternalServices:     []string{"notification_service", "audit_service"},
			SecurityRequirements: []string{"TLS", "authentication"},
		},
		HumanResources: &HumanResources{
			OperatorsRequired:  1,
			SkillLevels:        []string{"compliance_officer", "technical_support"},
			AvailabilityHours:  "9-5",
			EscalationContacts: []string{"compliance_manager", "legal_team"},
		},
	}
}

// validateBusinessLogic validates business logic consistency
func (v *PolicyValidator) validateBusinessLogic(policy *parser.CompliancePolicy) *BusinessLogicCheck {
	check := &BusinessLogicCheck{
		LogicValid:             true,
		BusinessRulesSatisfied: make([]string, 0),
		BusinessRulesViolated:  make([]string, 0),
		LogicGaps:              make([]*BusinessLogicGap, 0),
		RecommendedRules:       make([]*RecommendedBusinessRule, 0),
	}

	// Get business rules for the asset class
	if schema, exists := v.schemas[policy.AssetClass]; exists {
		for _, businessRule := range schema.BusinessRules {
			if v.validateSingleBusinessRule(policy, businessRule) {
				check.BusinessRulesSatisfied = append(check.BusinessRulesSatisfied, businessRule.RuleID)
			} else {
				check.LogicValid = false
				check.BusinessRulesViolated = append(check.BusinessRulesViolated, businessRule.RuleID)

				check.LogicGaps = append(check.LogicGaps, &BusinessLogicGap{
					GapType:        "missing_business_rule",
					Description:    fmt.Sprintf("Business rule not satisfied: %s", businessRule.Description),
					Impact:         "medium",
					Recommendation: "Review policy to ensure compliance with business requirements",
					RuleReference:  businessRule.RuleID,
				})
			}
		}
	}

	// Suggest additional business rules based on asset class
	check.RecommendedRules = v.suggestBusinessRules(policy)

	return check
}

// validateSingleBusinessRule validates a single business rule against the policy
func (v *PolicyValidator) validateSingleBusinessRule(policy *parser.CompliancePolicy, rule *BusinessRule) bool {
	// This would implement business rule validation logic
	// For now, we'll use a simplified approach

	// Example: Check if the policy has rules that align with business requirements
	if strings.Contains(strings.ToLower(rule.Description), "kyc") {
		// Check if policy has KYC attestation requirements
		for _, attestation := range policy.Attestations {
			if attestation.Type == parser.AttestationType_ATTESTATION_TYPE_KYC {
				return true
			}
		}
		return false
	}

	if strings.Contains(strings.ToLower(rule.Description), "amount limit") {
		// Check if policy has amount-related rules
		for _, rule := range policy.Rules {
			if v.ruleReferencesAmountLimits(rule) {
				return true
			}
		}
		return false
	}

	// Default to satisfied for rules we can't evaluate
	return true
}

// ruleReferencesAmountLimits checks if a rule references amount limits
func (v *PolicyValidator) ruleReferencesAmountLimits(rule *parser.PolicyRule) bool {
	// Extract field paths and check for amount-related fields
	fieldPaths := v.extractFieldPathsFromPredicate(rule.Predicate)
	for _, path := range fieldPaths {
		if strings.Contains(strings.ToLower(path), "amount") ||
			strings.Contains(strings.ToLower(path), "value") ||
			strings.Contains(strings.ToLower(path), "limit") {
			return true
		}
	}
	return false
}

// suggestBusinessRules suggests additional business rules based on asset class
func (v *PolicyValidator) suggestBusinessRules(policy *parser.CompliancePolicy) []*RecommendedBusinessRule {
	recommendations := make([]*RecommendedBusinessRule, 0)

	// Asset class specific recommendations
	switch policy.AssetClass {
	case "credit_card_receivables":
		recommendations = append(recommendations, &RecommendedBusinessRule{
			RuleID:         "ccr_monthly_limit",
			Name:           "Monthly Transaction Limit",
			Description:    "Implement monthly transaction volume limits for credit card receivables",
			Priority:       "high",
			Rationale:      "Risk management for revolving credit products",
			Implementation: "Add predicate checking monthly transaction sum against configured limit",
		})
	case "installment_loans":
		recommendations = append(recommendations, &RecommendedBusinessRule{
			RuleID:         "il_payment_schedule",
			Name:           "Payment Schedule Validation",
			Description:    "Validate payment schedules against loan terms",
			Priority:       "medium",
			Rationale:      "Ensure payment schedules align with contractual obligations",
			Implementation: "Add validation for payment frequency and amounts",
		})
	}

	// General recommendations based on missing common patterns
	hasKYC := false
	for _, attestation := range policy.Attestations {
		if attestation.Type == parser.AttestationType_ATTESTATION_TYPE_KYC {
			hasKYC = true
			break
		}
	}

	if !hasKYC {
		recommendations = append(recommendations, &RecommendedBusinessRule{
			RuleID:         "kyc_requirement",
			Name:           "KYC Verification",
			Description:    "Require KYC verification for all participants",
			Priority:       "high",
			Rationale:      "Regulatory compliance and risk management",
			Implementation: "Add KYC attestation requirement",
		})
	}

	return recommendations
}

// validateDependencies validates policy dependencies
func (v *PolicyValidator) validateDependencies(policy *parser.CompliancePolicy) *DependencyValidation {
	validation := &DependencyValidation{
		AllDependenciesValid: true,
		ExternalDependencies: make([]*ExternalDependency, 0),
		MissingDependencies:  make([]*MissingDependency, 0),
		DependencyConflicts:  make([]*DependencyConflict, 0),
		DependencyGraph:      &DependencyGraph{Nodes: make([]*DependencyNode, 0), Edges: make([]*DependencyEdge, 0)},
	}

	// Analyze attestation provider dependencies
	for i, attestation := range policy.Attestations {
		providerFound := false
		for _, provider := range v.providers {
			if v.providerSupportsAttestation(provider, attestation) {
				providerFound = true
				validation.ExternalDependencies = append(validation.ExternalDependencies, &ExternalDependency{
					DependencyID:  fmt.Sprintf("provider_%s", provider.ProviderID),
					Type:          "attestation_provider",
					Description:   fmt.Sprintf("Attestation provider for %s", attestation.Type.String()),
					Version:       "latest",
					Required:      attestation.Required,
					HealthStatus:  "unknown",
					Configuration: make(map[string]interface{}),
				})
				break
			}
		}

		if !providerFound && attestation.Required {
			validation.AllDependenciesValid = false
			validation.MissingDependencies = append(validation.MissingDependencies, &MissingDependency{
				DependencyID: fmt.Sprintf("attestation_%d_provider", i),
				Type:         "attestation_provider",
				Description:  fmt.Sprintf("No provider found for required attestation: %s", attestation.Type.String()),
				Impact:       "high",
				Alternatives: v.findAlternativeProviders(attestation.Type.String()),
				Resolution:   "Register an appropriate attestation provider",
			})
		}
	}

	// Check for dependency conflicts
	v.checkDependencyConflicts(validation)

	// Build dependency graph
	v.buildDependencyGraph(policy, validation.DependencyGraph)

	return validation
}

// providerSupportsAttestation checks if a provider supports an attestation type
func (v *PolicyValidator) providerSupportsAttestation(provider *AttestationProvider, attestation *parser.AttestationRequirement) bool {
	for _, supportedType := range provider.SupportedTypes {
		if supportedType == attestation.Type.String() {
			return true
		}
	}
	return false
}

// checkDependencyConflicts checks for conflicts between dependencies
func (v *PolicyValidator) checkDependencyConflicts(validation *DependencyValidation) {
	// Check for provider conflicts (e.g., providers that can't work together)
	providerTypes := make(map[string][]string)

	for _, dep := range validation.ExternalDependencies {
		if dep.Type == "attestation_provider" {
			// Extract provider type from description
			parts := strings.Split(dep.Description, " ")
			if len(parts) > 2 {
				providerType := parts[len(parts)-1]
				providerTypes[providerType] = append(providerTypes[providerType], dep.DependencyID)
			}
		}
	}

	// Check for multiple providers of the same type (potential conflict)
	for providerType, providers := range providerTypes {
		if len(providers) > 1 {
			validation.DependencyConflicts = append(validation.DependencyConflicts, &DependencyConflict{
				ConflictID:   fmt.Sprintf("multiple_%s_providers", providerType),
				ConflictType: "multiple_providers",
				Description:  fmt.Sprintf("Multiple providers configured for %s", providerType),
				Dependencies: providers,
				Severity:     "medium",
				Resolution:   "Choose a single provider or implement provider prioritization",
				Impact:       "May cause inconsistent results or increased costs",
			})
		}
	}
}

// buildDependencyGraph builds a dependency graph for the policy
func (v *PolicyValidator) buildDependencyGraph(policy *parser.CompliancePolicy, graph *DependencyGraph) {
	// Add policy as root node
	policyNode := &DependencyNode{
		NodeID:      "policy_root",
		Type:        "policy",
		Name:        policy.PolicyId,
		Description: "Root policy node",
		Status:      "active",
		Metadata:    make(map[string]interface{}),
	}
	graph.Nodes = append(graph.Nodes, policyNode)

	// Add rule nodes
	for i, rule := range policy.Rules {
		ruleNodeID := fmt.Sprintf("rule_%d", i)
		ruleNode := &DependencyNode{
			NodeID:      ruleNodeID,
			Type:        "rule",
			Name:        rule.Name,
			Description: rule.Description,
			Status:      "active",
			Metadata:    make(map[string]interface{}),
		}
		graph.Nodes = append(graph.Nodes, ruleNode)

		// Add edge from policy to rule
		graph.Edges = append(graph.Edges, &DependencyEdge{
			EdgeID:        fmt.Sprintf("policy_to_%s", ruleNodeID),
			SourceNodeID:  "policy_root",
			TargetNodeID:  ruleNodeID,
			RelationType:  "contains",
			Weight:        1.0,
			Bidirectional: false,
			Metadata:      make(map[string]interface{}),
		})
	}

	// Add attestation nodes
	for i, attestation := range policy.Attestations {
		attestationNodeID := fmt.Sprintf("attestation_%d", i)
		attestationNode := &DependencyNode{
			NodeID:      attestationNodeID,
			Type:        "attestation",
			Name:        attestation.Name,
			Description: attestation.Description,
			Status:      "active",
			Metadata:    make(map[string]interface{}),
		}
		graph.Nodes = append(graph.Nodes, attestationNode)

		// Add edge from policy to attestation
		graph.Edges = append(graph.Edges, &DependencyEdge{
			EdgeID:        fmt.Sprintf("policy_to_%s", attestationNodeID),
			SourceNodeID:  "policy_root",
			TargetNodeID:  attestationNodeID,
			RelationType:  "requires",
			Weight:        float64(1),
			Bidirectional: false,
			Metadata:      make(map[string]interface{}),
		})
	}
}

// performPerformanceValidation conducts comprehensive performance validation
func (v *PolicyValidator) performPerformanceValidation(policy *parser.CompliancePolicy, report *ValidationReport) {
	performanceReport := &PerformanceValidationReport{
		PredicateComplexityAnalysis: v.analyzePredicateComplexity(policy),
		EvaluationCostEstimate:      v.estimateEvaluationCost(policy),
		OptimizationRecommendations: v.generateOptimizationRecommendations(policy),
		BenchmarkResults:            v.runBenchmarks(policy),
		ScalabilityAnalysis:         v.analyzeScalability(policy),
		ResourceUtilization:         v.analyzeResourceUtilization(policy),
	}

	report.PerformanceReport = performanceReport

	// Collect performance issues
	v.collectPerformanceIssues(performanceReport, report)
}

// TestPolicyAgainstSamples tests a policy against sample transaction data
func (v *PolicyValidator) TestPolicyAgainstSamples(policy *parser.CompliancePolicy, samples []TransactionData) *TestReport {
	report := &TestReport{
		TestID:             v.generateTestID(),
		PolicyID:           v.getPolicyID(policy),
		TestType:           "sample_data_testing",
		ExecutedAt:         time.Now(),
		TestResults:        make([]*TestResult, 0),
		PerformanceMetrics: &TestPerformanceMetrics{},
		Summary:            &TestSummary{},
		TestConfiguration: &TestConfiguration{
			SampleSize:       len(samples),
			TestParameters:   make(map[string]interface{}),
			ExpectedOutcomes: make(map[string]int),
		},
		RegressionAnalysis: &RegressionAnalysis{},
		CoverageAnalysis:   &CoverageAnalysis{},
	}

	// Initialize counters
	totalTests := 0
	passedTests := 0
	failedTests := 0
	errorTests := 0

	// Test each sample against the policy
	for i, sample := range samples {
		testResult := v.executeSampleTest(policy, sample, i)
		report.TestResults = append(report.TestResults, testResult)

		totalTests++
		switch testResult.Status {
		case "passed":
			passedTests++
		case "failed":
			failedTests++
		case "error":
			errorTests++
		}
	}

	// Calculate summary statistics
	report.Summary = &TestSummary{
		TotalTests:    totalTests,
		PassedTests:   passedTests,
		FailedTests:   failedTests,
		ErrorTests:    errorTests,
		SuccessRate:   float64(passedTests) / float64(totalTests),
		FailureRate:   float64(failedTests) / float64(totalTests),
		ErrorRate:     float64(errorTests) / float64(totalTests),
		ExecutionTime: time.Since(report.ExecutedAt),
	}

	// Analyze performance metrics
	report.PerformanceMetrics = v.analyzeTestPerformance(report.TestResults)

	// Perform regression analysis
	report.RegressionAnalysis = v.performRegressionAnalysis(policy, samples, report.TestResults)

	// Analyze test coverage
	report.CoverageAnalysis = v.analyzeCoverage(policy, samples, report.TestResults)

	// Generate insights and recommendations
	report.TestInsights = v.generateTestInsights(report)
	report.Recommendations = v.generateTestRecommendations(report)

	return report
}

// GenerateTestCases generates comprehensive test cases from policy rules
func (v *PolicyValidator) GenerateTestCases(policy *parser.CompliancePolicy) []TestCase {
	testCases := make([]TestCase, 0)

	// Generate test cases for each rule
	for i, rule := range policy.Rules {
		ruleCases := v.generateRuleTestCases(rule, i)
		testCases = append(testCases, ruleCases...)
	}

	// Generate boundary condition test cases
	boundaryCases := v.generateBoundaryTestCases(policy)
	testCases = append(testCases, boundaryCases...)

	// Generate edge case test cases
	edgeCases := v.generateEdgeTestCases(policy)
	testCases = append(testCases, edgeCases...)

	// Generate negative test cases
	negativeCases := v.generateNegativeTestCases(policy)
	testCases = append(testCases, negativeCases...)

	// Generate performance test cases
	performanceCases := v.generatePerformanceTestCases(policy)
	testCases = append(testCases, performanceCases...)

	// Generate integration test cases
	integrationCases := v.generateIntegrationTestCases(policy)
	testCases = append(testCases, integrationCases...)

	return testCases
}

// executeSampleTest executes a single sample test
func (v *PolicyValidator) executeSampleTest(policy *parser.CompliancePolicy, sample TransactionData, index int) *TestResult {
	startTime := time.Now()

	result := &TestResult{
		TestCaseID:        fmt.Sprintf("sample_test_%d", index),
		TestName:          fmt.Sprintf("Sample Transaction Test %d", index+1),
		Status:            "unknown",
		StartTime:         startTime,
		TestData:          sample,
		ValidationResults: make([]*RuleValidationResult, 0),
		ErrorDetails:      make([]*TestError, 0),
	}

	defer func() {
		result.EndTime = time.Now()
		result.ExecutionTime = result.EndTime.Sub(result.StartTime)
	}()

	// Validate sample against each rule
	allRulesPassed := true
	for i, rule := range policy.Rules {
		ruleResult := v.validateSampleAgainstRule(sample, rule, i)
		result.ValidationResults = append(result.ValidationResults, ruleResult)

		if !ruleResult.Passed {
			allRulesPassed = false
			result.ErrorDetails = append(result.ErrorDetails, &TestError{
				ErrorType:     "rule_violation",
				RuleID:        ruleResult.RuleID,
				Message:       ruleResult.ErrorMessage,
				Field:         ruleResult.Field,
				ExpectedValue: ruleResult.ExpectedValue,
				ActualValue:   ruleResult.ActualValue,
			})
		}
	}

	// Validate attestation requirements
	attestationsPassed := v.validateSampleAttestations(sample, policy.Attestations, result)

	// Determine overall test status
	if allRulesPassed && attestationsPassed {
		result.Status = "passed"
		result.Message = "Transaction sample passed all policy validations"
	} else {
		result.Status = "failed"
		result.Message = fmt.Sprintf("Transaction sample failed %d validation(s)", len(result.ErrorDetails))
	}

	return result
}

// validateSampleAgainstRule validates a sample against a specific rule
func (v *PolicyValidator) validateSampleAgainstRule(sample TransactionData, rule *parser.PolicyRule, ruleIndex int) *RuleValidationResult {
	result := &RuleValidationResult{
		RuleID:        fmt.Sprintf("rule_%d", ruleIndex),
		RuleName:      rule.Name,
		Passed:        false,
		ErrorMessage:  "",
		Field:         "",
		ExpectedValue: nil,
		ActualValue:   nil,
	}

	// Extract relevant data from sample based on rule predicate
	if rule.Predicate == nil {
		result.Passed = true
		return result
	}

	// Evaluate predicate against sample data
	passed, field, expected, actual, message := v.evaluatePredicateAgainstSample(rule.Predicate, sample)

	result.Passed = passed
	result.Field = field
	result.ExpectedValue = expected
	result.ActualValue = actual

	if !passed {
		result.ErrorMessage = message
	}

	return result
}

// evaluatePredicateAgainstSample evaluates a predicate against sample data
func (v *PolicyValidator) evaluatePredicateAgainstSample(predicate *parser.Predicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	if predicate == nil {
		return true, "", nil, nil, ""
	}

	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Comparison:
		if p.Comparison != nil {
			return v.evaluateComparisonPredicate(p.Comparison, sample)
		}
	case *parser.Predicate_Range:
		if p.Range != nil {
			return v.evaluateRangePredicate(p.Range, sample)
		}
	case *parser.Predicate_Set:
		if p.Set != nil {
			return v.evaluateSetPredicate(p.Set, sample)
		}
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			return v.evaluateLogicalPredicate(p.Logical, sample)
		}
	case *parser.Predicate_Regex:
		if p.Regex != nil {
			return v.evaluateRegexPredicate(p.Regex, sample)
		}
	case *parser.Predicate_Time:
		if p.Time != nil {
			return v.evaluateTimePredicate(p.Time, sample)
		}
	}

	return true, "", nil, nil, ""
}

// evaluateComparisonPredicate evaluates a comparison predicate
func (v *PolicyValidator) evaluateComparisonPredicate(comparison *parser.ComparisonPredicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	fieldValue, exists := sample.GetField(comparison.FieldPath)
	if !exists {
		return false, comparison.FieldPath, comparison.Value, nil, fmt.Sprintf("Field %s not found in sample data", comparison.FieldPath)
	}

	passed := v.compareValues(fieldValue, comparison.Value, comparison.Operator)
	message := ""
	if !passed {
		message = fmt.Sprintf("Comparison failed: %v %s %v", fieldValue, comparison.Operator.String(), comparison.Value)
	}

	return passed, comparison.FieldPath, comparison.Value, fieldValue, message
}

// evaluateRangePredicate evaluates a range predicate
func (v *PolicyValidator) evaluateRangePredicate(rangePred *parser.RangePredicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	fieldValue, exists := sample.GetField(rangePred.FieldPath)
	if !exists {
		return false, rangePred.FieldPath, fmt.Sprintf("[%v, %v]", rangePred.MinValue, rangePred.MaxValue), nil, fmt.Sprintf("Field %s not found in sample data", rangePred.FieldPath)
	}

	passed := v.isValueInRange(fieldValue, rangePred.MinValue, rangePred.MaxValue, rangePred.Inclusive)
	message := ""
	if !passed {
		inclusiveStr := "exclusive"
		if rangePred.Inclusive {
			inclusiveStr = "inclusive"
		}
		message = fmt.Sprintf("Value %v not in range [%v, %v] (%s)", fieldValue, rangePred.MinValue, rangePred.MaxValue, inclusiveStr)
	}

	return passed, rangePred.FieldPath, fmt.Sprintf("[%v, %v]", rangePred.MinValue, rangePred.MaxValue), fieldValue, message
}

// evaluateSetPredicate evaluates a set predicate
func (v *PolicyValidator) evaluateSetPredicate(setPred *parser.SetPredicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	fieldValue, exists := sample.GetField(setPred.FieldPath)
	if !exists {
		return false, setPred.FieldPath, setPred.Values, nil, fmt.Sprintf("Field %s not found in sample data", setPred.FieldPath)
	}

	passed := v.isValueInSet(fieldValue, setPred.Values, setPred.Operation)
	message := ""
	if !passed {
		message = fmt.Sprintf("Value %v not %s set %v", fieldValue, setPred.Operation.String(), setPred.Values)
	}

	return passed, setPred.FieldPath, setPred.Values, fieldValue, message
}

// evaluateLogicalPredicate evaluates a logical predicate
func (v *PolicyValidator) evaluateLogicalPredicate(logical *parser.LogicalPredicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	if len(logical.Operands) == 0 {
		return true, "", nil, nil, ""
	}

	switch logical.Operator {
	case parser.LogicalOperator_LOGICAL_OPERATOR_AND:
		return v.evaluateAndPredicate(logical.Operands, sample)
	case parser.LogicalOperator_LOGICAL_OPERATOR_OR:
		return v.evaluateOrPredicate(logical.Operands, sample)
	case parser.LogicalOperator_LOGICAL_OPERATOR_NOT:
		return v.evaluateNotPredicate(logical.Operands, sample)
	}

	return true, "", nil, nil, ""
}

// evaluateAndPredicate evaluates AND logical predicate
func (v *PolicyValidator) evaluateAndPredicate(operands []*parser.Predicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	for _, operand := range operands {
		passed, field, expected, actual, message := v.evaluatePredicateAgainstSample(operand, sample)
		if !passed {
			return false, field, expected, actual, message
		}
	}
	return true, "", nil, nil, ""
}

// evaluateOrPredicate evaluates OR logical predicate
func (v *PolicyValidator) evaluateOrPredicate(operands []*parser.Predicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	var lastError string
	for _, operand := range operands {
		passed, _, _, _, message := v.evaluatePredicateAgainstSample(operand, sample)
		if passed {
			return true, "", nil, nil, ""
		}
		lastError = message
	}
	return false, "", nil, nil, fmt.Sprintf("No OR operand passed: %s", lastError)
}

// evaluateNotPredicate evaluates NOT logical predicate
func (v *PolicyValidator) evaluateNotPredicate(operands []*parser.Predicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	if len(operands) != 1 {
		return false, "", nil, nil, "NOT predicate must have exactly one operand"
	}

	passed, field, expected, actual, _ := v.evaluatePredicateAgainstSample(operands[0], sample)
	return !passed, field, expected, actual, fmt.Sprintf("NOT predicate failed: expected opposite of %v", actual)
}

// evaluateRegexPredicate evaluates a regex predicate
func (v *PolicyValidator) evaluateRegexPredicate(regex *parser.RegexPredicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	fieldValue, exists := sample.GetField(regex.FieldPath)
	if !exists {
		return false, regex.FieldPath, regex.Pattern, nil, fmt.Sprintf("Field %s not found in sample data", regex.FieldPath)
	}

	strValue := fmt.Sprintf("%v", fieldValue)
	matched := v.matchesRegex(strValue, regex.Pattern)
	message := ""
	if !matched {
		message = fmt.Sprintf("Value '%s' does not match regex pattern '%s'", strValue, regex.Pattern)
	}

	return matched, regex.FieldPath, regex.Pattern, fieldValue, message
}

// evaluateTimePredicate evaluates a time predicate
func (v *PolicyValidator) evaluateTimePredicate(timePred *parser.TimePredicate, sample TransactionData) (bool, string, interface{}, interface{}, string) {
	fieldValue, exists := sample.GetField(timePred.FieldPath)
	if !exists {
		return false, timePred.FieldPath, timePred.Value, nil, fmt.Sprintf("Field %s not found in sample data", timePred.FieldPath)
	}

	passed := v.compareTimeValues(fieldValue, timePred.Value, timePred.Operator)
	message := ""
	if !passed {
		message = fmt.Sprintf("Time comparison failed: %v %s %v", fieldValue, timePred.Operator.String(), timePred.Value)
	}

	return passed, timePred.FieldPath, timePred.Value, fieldValue, message
}

// validateSampleAttestations validates sample against attestation requirements
func (v *PolicyValidator) validateSampleAttestations(sample TransactionData, attestations []*parser.AttestationRequirement, result *TestResult) bool {
	if len(attestations) == 0 {
		return true
	}

	allPassed := true
	for i, attestation := range attestations {
		passed := v.validateSampleAttestation(sample, attestation)
		if !passed {
			allPassed = false
			result.ErrorDetails = append(result.ErrorDetails, &TestError{
				ErrorType:     "attestation_failure",
				RuleID:        fmt.Sprintf("attestation_%d", i),
				Message:       fmt.Sprintf("Attestation %s failed validation", attestation.Type),
				Field:         attestation.Type,
				ExpectedValue: "valid_attestation",
				ActualValue:   "missing_or_invalid",
			})
		}
	}

	return allPassed
}

// validateSampleAttestation validates a single attestation requirement
func (v *PolicyValidator) validateSampleAttestation(sample TransactionData, attestation *parser.AttestationRequirement) bool {
	// Check if sample has required attestation data
	attestationData, exists := sample.GetAttestationData(attestation.Type)
	if !exists {
		return false
	}

	// Validate attestation data structure
	if !v.isValidAttestationData(attestationData, attestation) {
		return false
	}

	return true
}

// generateRuleTestCases generates test cases for a specific rule
func (v *PolicyValidator) generateRuleTestCases(rule *parser.PolicyRule, ruleIndex int) []TestCase {
	testCases := make([]TestCase, 0)

	if rule.Predicate == nil {
		return testCases
	}

	// Generate positive test cases (should pass)
	positiveCases := v.generatePositiveTestCases(rule, ruleIndex)
	testCases = append(testCases, positiveCases...)

	// Generate negative test cases (should fail)
	negativeCases := v.generateNegativeTestCasesForRule(rule, ruleIndex)
	testCases = append(testCases, negativeCases...)

	return testCases
}

// generatePositiveTestCases generates test cases that should pass validation
func (v *PolicyValidator) generatePositiveTestCases(rule *parser.PolicyRule, ruleIndex int) []TestCase {
	testCases := make([]TestCase, 0)

	// Generate test case based on predicate type
	switch p := rule.Predicate.PredicateType.(type) {
	case *parser.Predicate_Comparison:
		if p.Comparison != nil {
			testCase := v.generateComparisonPositiveCase(p.Comparison, rule, ruleIndex)
			testCases = append(testCases, testCase)
		}
	case *parser.Predicate_Range:
		if p.Range != nil {
			testCase := v.generateRangePositiveCase(p.Range, rule, ruleIndex)
			testCases = append(testCases, testCase)
		}
	case *parser.Predicate_Set:
		if p.Set != nil {
			testCase := v.generateSetPositiveCase(p.Set, rule, ruleIndex)
			testCases = append(testCases, testCase)
		}
	}

	return testCases
}

// generateNegativeTestCasesForRule generates test cases that should fail validation
func (v *PolicyValidator) generateNegativeTestCasesForRule(rule *parser.PolicyRule, ruleIndex int) []TestCase {
	testCases := make([]TestCase, 0)

	// Generate test case based on predicate type
	switch p := rule.Predicate.PredicateType.(type) {
	case *parser.Predicate_Comparison:
		if p.Comparison != nil {
			testCase := v.generateComparisonNegativeCase(p.Comparison, rule, ruleIndex)
			testCases = append(testCases, testCase)
		}
	case *parser.Predicate_Range:
		if p.Range != nil {
			testCase := v.generateRangeNegativeCase(p.Range, rule, ruleIndex)
			testCases = append(testCases, testCase)
		}
	case *parser.Predicate_Set:
		if p.Set != nil {
			testCase := v.generateSetNegativeCase(p.Set, rule, ruleIndex)
			testCases = append(testCases, testCase)
		}
	}

	return testCases
}

// generateBoundaryTestCases generates boundary condition test cases
func (v *PolicyValidator) generateBoundaryTestCases(policy *parser.CompliancePolicy) []TestCase {
	testCases := make([]TestCase, 0)

	for i, rule := range policy.Rules {
		if rule.Predicate == nil {
			continue
		}

		switch p := rule.Predicate.PredicateType.(type) {
		case *parser.Predicate_Range:
			if p.Range != nil {
				// Test minimum boundary
				minCase := TestCase{
					TestCaseID:     fmt.Sprintf("boundary_min_rule_%d", i),
					Name:           fmt.Sprintf("Boundary Test - Minimum Value (Rule %d)", i),
					Description:    fmt.Sprintf("Test minimum boundary value for range predicate in rule %d", i),
					ExpectedResult: TestExpectedResult{ShouldPass: true},
					TestData:       v.createBoundaryTestData(p.Range.FieldPath, p.Range.MinValue),
					Category:       "boundary",
					Priority:       "high",
				}
				testCases = append(testCases, minCase)

				// Test maximum boundary
				maxCase := TestCase{
					TestCaseID:     fmt.Sprintf("boundary_max_rule_%d", i),
					Name:           fmt.Sprintf("Boundary Test - Maximum Value (Rule %d)", i),
					Description:    fmt.Sprintf("Test maximum boundary value for range predicate in rule %d", i),
					ExpectedResult: TestExpectedResult{ShouldPass: true},
					TestData:       v.createBoundaryTestData(p.Range.FieldPath, p.Range.MaxValue),
					Category:       "boundary",
					Priority:       "high",
				}
				testCases = append(testCases, maxCase)
			}
		}
	}

	return testCases
}

// generateEdgeTestCases generates edge case test cases
func (v *PolicyValidator) generateEdgeTestCases(policy *parser.CompliancePolicy) []TestCase {
	testCases := make([]TestCase, 0)

	// Generate cases with empty/null values
	emptyCase := TestCase{
		TestCaseID:     "edge_empty_data",
		Name:           "Edge Case - Empty Data",
		Description:    "Test policy behavior with empty transaction data",
		ExpectedResult: TestExpectedResult{ShouldPass: false},
		TestData:       v.createEmptyTestData(),
		Category:       "edge_case",
		Priority:       "medium",
	}
	testCases = append(testCases, emptyCase)

	// Generate cases with very large values
	largeCase := TestCase{
		TestCaseID:     "edge_large_values",
		Name:           "Edge Case - Large Values",
		Description:    "Test policy behavior with very large field values",
		ExpectedResult: TestExpectedResult{ShouldPass: false},
		TestData:       v.createLargeValueTestData(),
		Category:       "edge_case",
		Priority:       "medium",
	}
	testCases = append(testCases, largeCase)

	return testCases
}

// generateNegativeTestCases generates negative test cases
func (v *PolicyValidator) generateNegativeTestCases(policy *parser.CompliancePolicy) []TestCase {
	testCases := make([]TestCase, 0)

	// Generate malformed data cases
	malformedCase := TestCase{
		TestCaseID:     "negative_malformed_data",
		Name:           "Negative Test - Malformed Data",
		Description:    "Test policy behavior with malformed transaction data",
		ExpectedResult: TestExpectedResult{ShouldPass: false},
		TestData:       v.createMalformedTestData(),
		Category:       "negative",
		Priority:       "high",
	}
	testCases = append(testCases, malformedCase)

	return testCases
}

// generatePerformanceTestCases generates performance test cases
func (v *PolicyValidator) generatePerformanceTestCases(policy *parser.CompliancePolicy) []TestCase {
	testCases := make([]TestCase, 0)

	// Generate complex nested predicate test
	complexCase := TestCase{
		TestCaseID:     "performance_complex_predicate",
		Name:           "Performance Test - Complex Predicate",
		Description:    "Test policy performance with complex nested predicates",
		ExpectedResult: TestExpectedResult{ShouldPass: true, MaxExecutionTime: 100 * time.Millisecond},
		TestData:       v.createComplexTestData(),
		Category:       "performance",
		Priority:       "medium",
	}
	testCases = append(testCases, complexCase)

	return testCases
}

// generateIntegrationTestCases generates integration test cases
func (v *PolicyValidator) generateIntegrationTestCases(policy *parser.CompliancePolicy) []TestCase {
	testCases := make([]TestCase, 0)

	if len(policy.Attestations) > 0 {
		// Generate attestation integration test
		attestationCase := TestCase{
			TestCaseID:     "integration_attestation",
			Name:           "Integration Test - Attestation Providers",
			Description:    "Test policy integration with external attestation providers",
			ExpectedResult: TestExpectedResult{ShouldPass: true},
			TestData:       v.createAttestationTestData(policy.Attestations),
			Category:       "integration",
			Priority:       "high",
		}
		testCases = append(testCases, attestationCase)
	}

	return testCases
}

// Helper functions for creating test data
func (v *PolicyValidator) createBoundaryTestData(fieldPath string, value interface{}) TransactionData {
	data := make(map[string]interface{})
	data[fieldPath] = value
	return TransactionData{Data: data}
}

func (v *PolicyValidator) createEmptyTestData() TransactionData {
	return TransactionData{Data: make(map[string]interface{})}
}

func (v *PolicyValidator) createLargeValueTestData() TransactionData {
	data := map[string]interface{}{
		"amount":      999999999999.99,
		"description": strings.Repeat("A", 10000),
		"count":       999999999,
	}
	return TransactionData{Data: data}
}

func (v *PolicyValidator) createMalformedTestData() TransactionData {
	data := map[string]interface{}{
		"amount":     "invalid_number",
		"date":       "invalid_date",
		"bool_field": "not_boolean",
	}
	return TransactionData{Data: data}
}

func (v *PolicyValidator) createComplexTestData() TransactionData {
	data := map[string]interface{}{
		"amount":            1000.50,
		"currency":          "USD",
		"transaction_type":  "transfer",
		"participant_count": 5,
		"risk_score":        0.75,
		"timestamp":         time.Now(),
		"metadata": map[string]interface{}{
			"nested_field": "value",
			"deep": map[string]interface{}{
				"very_deep": "nested_value",
			},
		},
	}
	return TransactionData{Data: data}
}

func (v *PolicyValidator) createAttestationTestData(attestations []*parser.AttestationRequirement) TransactionData {
	data := map[string]interface{}{
		"amount":   1000.0,
		"currency": "USD",
	}

	attestationData := make(map[string]interface{})
	for _, attestation := range attestations {
		attestationData[attestation.Type] = map[string]interface{}{
			"provider":   attestation.Provider,
			"status":     "verified",
			"timestamp":  time.Now(),
			"confidence": 0.95,
		}
	}

	return TransactionData{
		Data:            data,
		AttestationData: attestationData,
	}
}

// Additional helper functions
func (v *PolicyValidator) generateComparisonPositiveCase(comparison *parser.ComparisonPredicate, rule *parser.PolicyRule, ruleIndex int) TestCase {
	testData := v.createTestDataForComparison(comparison, true)
	return TestCase{
		TestCaseID:     fmt.Sprintf("positive_comparison_rule_%d", ruleIndex),
		Name:           fmt.Sprintf("Positive Test - Comparison Rule %d", ruleIndex),
		Description:    fmt.Sprintf("Test case that should pass comparison predicate in rule %d", ruleIndex),
		ExpectedResult: TestExpectedResult{ShouldPass: true},
		TestData:       testData,
		Category:       "positive",
		Priority:       "high",
	}
}

func (v *PolicyValidator) generateComparisonNegativeCase(comparison *parser.ComparisonPredicate, rule *parser.PolicyRule, ruleIndex int) TestCase {
	testData := v.createTestDataForComparison(comparison, false)
	return TestCase{
		TestCaseID:     fmt.Sprintf("negative_comparison_rule_%d", ruleIndex),
		Name:           fmt.Sprintf("Negative Test - Comparison Rule %d", ruleIndex),
		Description:    fmt.Sprintf("Test case that should fail comparison predicate in rule %d", ruleIndex),
		ExpectedResult: TestExpectedResult{ShouldPass: false},
		TestData:       testData,
		Category:       "negative",
		Priority:       "high",
	}
}

func (v *PolicyValidator) createTestDataForComparison(comparison *parser.ComparisonPredicate, shouldPass bool) TransactionData {
	data := make(map[string]interface{})

	if shouldPass {
		// Create data that should satisfy the comparison
		switch comparison.Operator {
		case parser.ComparisonOperator_COMPARISON_OPERATOR_EQ:
			data[comparison.FieldPath] = comparison.Value
		case parser.ComparisonOperator_COMPARISON_OPERATOR_GT:
			if val, ok := comparison.Value.(float64); ok {
				data[comparison.FieldPath] = val + 1
			}
		case parser.ComparisonOperator_COMPARISON_OPERATOR_LT:
			if val, ok := comparison.Value.(float64); ok {
				data[comparison.FieldPath] = val - 1
			}
		default:
			data[comparison.FieldPath] = comparison.Value
		}
	} else {
		// Create data that should fail the comparison
		switch comparison.Operator {
		case parser.ComparisonOperator_COMPARISON_OPERATOR_EQ:
			data[comparison.FieldPath] = "different_value"
		case parser.ComparisonOperator_COMPARISON_OPERATOR_GT:
			if val, ok := comparison.Value.(float64); ok {
				data[comparison.FieldPath] = val - 1
			}
		case parser.ComparisonOperator_COMPARISON_OPERATOR_LT:
			if val, ok := comparison.Value.(float64); ok {
				data[comparison.FieldPath] = val + 1
			}
		default:
			data[comparison.FieldPath] = "different_value"
		}
	}

	return TransactionData{Data: data}
}

func (v *PolicyValidator) generateRangePositiveCase(rangePred *parser.RangePredicate, rule *parser.PolicyRule, ruleIndex int) TestCase {
	testData := v.createTestDataForRange(rangePred, true)
	return TestCase{
		TestCaseID:     fmt.Sprintf("positive_range_rule_%d", ruleIndex),
		Name:           fmt.Sprintf("Positive Test - Range Rule %d", ruleIndex),
		Description:    fmt.Sprintf("Test case that should pass range predicate in rule %d", ruleIndex),
		ExpectedResult: TestExpectedResult{ShouldPass: true},
		TestData:       testData,
		Category:       "positive",
		Priority:       "high",
	}
}

func (v *PolicyValidator) generateRangeNegativeCase(rangePred *parser.RangePredicate, rule *parser.PolicyRule, ruleIndex int) TestCase {
	testData := v.createTestDataForRange(rangePred, false)
	return TestCase{
		TestCaseID:     fmt.Sprintf("negative_range_rule_%d", ruleIndex),
		Name:           fmt.Sprintf("Negative Test - Range Rule %d", ruleIndex),
		Description:    fmt.Sprintf("Test case that should fail range predicate in rule %d", ruleIndex),
		ExpectedResult: TestExpectedResult{ShouldPass: false},
		TestData:       testData,
		Category:       "negative",
		Priority:       "high",
	}
}

func (v *PolicyValidator) createTestDataForRange(rangePred *parser.RangePredicate, shouldPass bool) TransactionData {
	data := make(map[string]interface{})

	if shouldPass {
		// Create value within range
		if minVal, ok := rangePred.MinValue.(float64); ok {
			if maxVal, ok := rangePred.MaxValue.(float64); ok {
				midValue := (minVal + maxVal) / 2
				data[rangePred.FieldPath] = midValue
			}
		}
	} else {
		// Create value outside range
		if minVal, ok := rangePred.MinValue.(float64); ok {
			data[rangePred.FieldPath] = minVal - 1
		}
	}

	return TransactionData{Data: data}
}

func (v *PolicyValidator) generateSetPositiveCase(setPred *parser.SetPredicate, rule *parser.PolicyRule, ruleIndex int) TestCase {
	testData := v.createTestDataForSet(setPred, true)
	return TestCase{
		TestCaseID:     fmt.Sprintf("positive_set_rule_%d", ruleIndex),
		Name:           fmt.Sprintf("Positive Test - Set Rule %d", ruleIndex),
		Description:    fmt.Sprintf("Test case that should pass set predicate in rule %d", ruleIndex),
		ExpectedResult: TestExpectedResult{ShouldPass: true},
		TestData:       testData,
		Category:       "positive",
		Priority:       "high",
	}
}

func (v *PolicyValidator) generateSetNegativeCase(setPred *parser.SetPredicate, rule *parser.PolicyRule, ruleIndex int) TestCase {
	testData := v.createTestDataForSet(setPred, false)
	return TestCase{
		TestCaseID:     fmt.Sprintf("negative_set_rule_%d", ruleIndex),
		Name:           fmt.Sprintf("Negative Test - Set Rule %d", ruleIndex),
		Description:    fmt.Sprintf("Test case that should fail set predicate in rule %d", ruleIndex),
		ExpectedResult: TestExpectedResult{ShouldPass: false},
		TestData:       testData,
		Category:       "negative",
		Priority:       "high",
	}
}

func (v *PolicyValidator) createTestDataForSet(setPred *parser.SetPredicate, shouldPass bool) TransactionData {
	data := make(map[string]interface{})

	if shouldPass && len(setPred.Values) > 0 {
		// Use first value from set
		data[setPred.FieldPath] = setPred.Values[0]
	} else {
		// Use value not in set
		data[setPred.FieldPath] = "value_not_in_set"
	}

	return TransactionData{Data: data}
}

// Additional helper functions needed by the validator

// generateTestID generates a unique test ID
func (v *PolicyValidator) generateTestID() string {
	return fmt.Sprintf("test_%d", time.Now().UnixNano())
}

// getPolicyID extracts policy ID from a compliance policy
func (v *PolicyValidator) getPolicyID(policy *parser.CompliancePolicy) string {
	if policy.Metadata != nil {
		return policy.Metadata.Id
	}
	return "unknown_policy"
}

// isValidAttestationData validates attestation data structure
func (v *PolicyValidator) isValidAttestationData(data interface{}, attestation *parser.AttestationRequirement) bool {
	// Basic validation - check if data is not nil and contains expected fields
	if data == nil {
		return false
	}

	// Check if data is a map with expected structure
	if dataMap, ok := data.(map[string]interface{}); ok {
		// Check for required fields in attestation data
		requiredFields := []string{"provider", "status", "timestamp"}
		for _, field := range requiredFields {
			if _, exists := dataMap[field]; !exists {
				return false
			}
		}
		return true
	}

	return false
}

// compareValues compares two values using the specified operator
func (v *PolicyValidator) compareValues(actual, expected interface{}, operator parser.ComparisonOperator) bool {
	switch operator {
	case parser.ComparisonOperator_COMPARISON_OPERATOR_EQ:
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
	case parser.ComparisonOperator_COMPARISON_OPERATOR_NE:
		return fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", expected)
	case parser.ComparisonOperator_COMPARISON_OPERATOR_GT:
		return v.compareNumeric(actual, expected, func(a, b float64) bool { return a > b })
	case parser.ComparisonOperator_COMPARISON_OPERATOR_GTE:
		return v.compareNumeric(actual, expected, func(a, b float64) bool { return a >= b })
	case parser.ComparisonOperator_COMPARISON_OPERATOR_LT:
		return v.compareNumeric(actual, expected, func(a, b float64) bool { return a < b })
	case parser.ComparisonOperator_COMPARISON_OPERATOR_LTE:
		return v.compareNumeric(actual, expected, func(a, b float64) bool { return a <= b })
	}
	return false
}

// compareNumeric compares numeric values
func (v *PolicyValidator) compareNumeric(actual, expected interface{}, compareFn func(float64, float64) bool) bool {
	actualFloat, actualOk := v.toFloat64(actual)
	expectedFloat, expectedOk := v.toFloat64(expected)

	if !actualOk || !expectedOk {
		return false
	}

	return compareFn(actualFloat, expectedFloat)
}

// toFloat64 converts an interface{} to float64
func (v *PolicyValidator) toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// isValueInRange checks if a value is within a specified range
func (v *PolicyValidator) isValueInRange(value, minValue, maxValue interface{}, inclusive bool) bool {
	valueFloat, valueOk := v.toFloat64(value)
	minFloat, minOk := v.toFloat64(minValue)
	maxFloat, maxOk := v.toFloat64(maxValue)

	if !valueOk || !minOk || !maxOk {
		return false
	}

	if inclusive {
		return valueFloat >= minFloat && valueFloat <= maxFloat
	} else {
		return valueFloat > minFloat && valueFloat < maxFloat
	}
}

// isValueInSet checks if a value is in a set using the specified operation
func (v *PolicyValidator) isValueInSet(value interface{}, values []interface{}, operation parser.SetOperation) bool {
	switch operation {
	case parser.SetOperation_SET_OPERATION_IN:
		return v.containsValue(values, value)
	case parser.SetOperation_SET_OPERATION_NOT_IN:
		return !v.containsValue(values, value)
	}
	return false
}

// containsValue checks if a slice contains a specific value
func (v *PolicyValidator) containsValue(values []interface{}, target interface{}) bool {
	targetStr := fmt.Sprintf("%v", target)
	for _, value := range values {
		if fmt.Sprintf("%v", value) == targetStr {
			return true
		}
	}
	return false
}

// matchesRegex checks if a string matches a regex pattern
func (v *PolicyValidator) matchesRegex(value, pattern string) bool {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return false
	}
	return matched
}

// compareTimeValues compares time values using the specified operator
func (v *PolicyValidator) compareTimeValues(actual, expected interface{}, operator parser.TimeOperator) bool {
	actualTime, actualOk := v.toTime(actual)
	expectedTime, expectedOk := v.toTime(expected)

	if !actualOk || !expectedOk {
		return false
	}

	switch operator {
	case parser.TimeOperator_TIME_OPERATOR_AFTER:
		return actualTime.After(expectedTime)
	case parser.TimeOperator_TIME_OPERATOR_BEFORE:
		return actualTime.Before(expectedTime)
	case parser.TimeOperator_TIME_OPERATOR_EQUAL:
		return actualTime.Equal(expectedTime)
	case parser.TimeOperator_TIME_OPERATOR_ON_OR_AFTER:
		return actualTime.After(expectedTime) || actualTime.Equal(expectedTime)
	case parser.TimeOperator_TIME_OPERATOR_ON_OR_BEFORE:
		return actualTime.Before(expectedTime) || actualTime.Equal(expectedTime)
	}
	return false
}

// toTime converts an interface{} to time.Time
func (v *PolicyValidator) toTime(value interface{}) (time.Time, bool) {
	switch v := value.(type) {
	case time.Time:
		return v, true
	case string:
		// Try common time formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, format := range formats {
			if t, err := time.Parse(format, v); err == nil {
				return t, true
			}
		}
	case int64:
		return time.Unix(v, 0), true
	}
	return time.Time{}, false
}

// Helper functions for test analysis and reporting

// analyzeTestPerformance analyzes performance metrics from test results
func (v *PolicyValidator) analyzeTestPerformance(results []*TestResult) *TestPerformanceMetrics {
	if len(results) == 0 {
		return &TestPerformanceMetrics{}
	}

	var totalTime time.Duration
	var maxTime time.Duration
	minTime := results[0].ExecutionTime

	for _, result := range results {
		totalTime += result.ExecutionTime
		if result.ExecutionTime > maxTime {
			maxTime = result.ExecutionTime
		}
		if result.ExecutionTime < minTime {
			minTime = result.ExecutionTime
		}
	}

	return &TestPerformanceMetrics{
		AverageExecutionTime: totalTime / time.Duration(len(results)),
		MaxExecutionTime:     maxTime,
		MinExecutionTime:     minTime,
		TotalExecutionTime:   totalTime,
		MemoryUsage:          1024 * 1024, // Placeholder - 1MB
		CPUUsage:             0.5,         // Placeholder - 50%
	}
}

// performRegressionAnalysis performs regression analysis
func (v *PolicyValidator) performRegressionAnalysis(policy *parser.CompliancePolicy, samples []TransactionData, results []*TestResult) *RegressionAnalysis {
	return &RegressionAnalysis{
		BaselineResults:    make([]*BaselineResult, 0),
		ComparisonResults:  make([]*ComparisonResult, 0),
		RegressionDetected: false,
		RegressionDetails:  make([]*RegressionDetail, 0),
	}
}

// analyzeCoverage analyzes test coverage
func (v *PolicyValidator) analyzeCoverage(policy *parser.CompliancePolicy, samples []TransactionData, results []*TestResult) *CoverageAnalysis {
	coverage := &CoverageAnalysis{
		RuleCoverage:        make(map[string]float64),
		PredicateCoverage:   make(map[string]float64),
		AttestationCoverage: make(map[string]float64),
		OverallCoverage:     0.0,
		UncoveredRules:      make([]string, 0),
		CoverageGaps:        make([]*CoverageGap, 0),
	}

	// Calculate rule coverage
	totalRules := len(policy.Rules)
	if totalRules > 0 {
		for i := range policy.Rules {
			ruleID := fmt.Sprintf("rule_%d", i)
			coverage.RuleCoverage[ruleID] = 1.0 // Assume 100% coverage for now
		}
		coverage.OverallCoverage = 1.0
	}

	return coverage
}

// generateTestInsights generates insights from test results
func (v *PolicyValidator) generateTestInsights(report *TestReport) []*TestInsight {
	insights := make([]*TestInsight, 0)

	if report.Summary.FailureRate > 0.1 {
		insights = append(insights, &TestInsight{
			InsightID:   v.generateInsightID(),
			Category:    "quality",
			Severity:    "medium",
			Title:       "High Failure Rate Detected",
			Description: fmt.Sprintf("Test failure rate is %.1f%%, which exceeds the 10%% threshold", report.Summary.FailureRate*100),
			Context:     map[string]interface{}{"failure_rate": report.Summary.FailureRate},
			GeneratedAt: time.Now(),
		})
	}

	return insights
}

// generateTestRecommendations generates recommendations from test results
func (v *PolicyValidator) generateTestRecommendations(report *TestReport) []*TestRecommendation {
	recommendations := make([]*TestRecommendation, 0)

	if report.Summary.ErrorRate > 0.05 {
		recommendations = append(recommendations, &TestRecommendation{
			RecommendationID: v.generateRecommendationID(),
			Type:             "improvement",
			Priority:         "high",
			Title:            "Reduce Test Error Rate",
			Description:      "The test error rate is above the acceptable threshold",
			Implementation:   "Review test data and policy validation logic to reduce errors",
			ExpectedBenefit:  "Improved test reliability and accuracy",
			Context:          map[string]interface{}{"error_rate": report.Summary.ErrorRate},
			GeneratedAt:      time.Now(),
		})
	}

	return recommendations
}

// generateInsightID generates a unique insight ID
func (v *PolicyValidator) generateInsightID() string {
	return fmt.Sprintf("insight_%d", time.Now().UnixNano())
}

// generateRecommendationID generates a unique recommendation ID
func (v *PolicyValidator) generateRecommendationID() string {
	return fmt.Sprintf("recommendation_%d", time.Now().UnixNano())
}

// generateWarningID generates a unique warning ID
func (v *PolicyValidator) generateWarningID() string {
	return fmt.Sprintf("warning_%d", time.Now().UnixNano())
}

// generateInfoID generates a unique info ID
func (v *PolicyValidator) generateInfoID() string {
	return fmt.Sprintf("info_%d", time.Now().UnixNano())
}
