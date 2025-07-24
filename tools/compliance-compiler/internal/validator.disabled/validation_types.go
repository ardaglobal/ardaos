package validator

import (
	"time"
)

// ValidationReport contains comprehensive validation results
type ValidationReport struct {
	PolicyID           string                       `json:"policy_id"`
	Version            string                       `json:"version"`
	Jurisdiction       string                       `json:"jurisdiction"`
	ValidationTime     time.Time                    `json:"validation_time"`
	ValidationDuration time.Duration                `json:"validation_duration"`
	IsValid            bool                         `json:"is_valid"`
	OverallScore       float64                      `json:"overall_score"`
	Errors             []*ValidationError           `json:"errors"`
	Warnings           []*ValidationWarning         `json:"warnings"`
	InfoMessages       []*ValidationInfo            `json:"info_messages"`
	StructuralReport   *StructuralValidationReport  `json:"structural_report"`
	SemanticReport     *SemanticValidationReport    `json:"semantic_report"`
	PerformanceReport  *PerformanceValidationReport `json:"performance_report"`
	ComplianceReport   *ComplianceValidationReport  `json:"compliance_report"`
	Summary            *ValidationSummary           `json:"summary"`
	Recommendations    []*ValidationRecommendation  `json:"recommendations"`
	Metadata           *ValidationMetadata          `json:"metadata"`
}

// ValidationError represents a validation error
type ValidationError struct {
	ErrorID      string                 `json:"error_id"`
	Code         string                 `json:"code"`
	Message      string                 `json:"message"`
	Severity     string                 `json:"severity"` // critical, high, medium, low
	Category     string                 `json:"category"` // structural, semantic, performance, compliance
	Field        string                 `json:"field,omitempty"`
	Location     *ValidationLocation    `json:"location,omitempty"`
	SuggestedFix string                 `json:"suggested_fix,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	WarningID      string                 `json:"warning_id"`
	Code           string                 `json:"code"`
	Message        string                 `json:"message"`
	Category       string                 `json:"category"`
	Field          string                 `json:"field,omitempty"`
	Location       *ValidationLocation    `json:"location,omitempty"`
	Recommendation string                 `json:"recommendation,omitempty"`
	Impact         string                 `json:"impact"` // performance, maintainability, compliance
	Context        map[string]interface{} `json:"context,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
}

// ValidationInfo represents informational validation messages
type ValidationInfo struct {
	InfoID    string                 `json:"info_id"`
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Category  string                 `json:"category"`
	Field     string                 `json:"field,omitempty"`
	Location  *ValidationLocation    `json:"location,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// ValidationLocation specifies where a validation issue occurs
type ValidationLocation struct {
	RuleName      string `json:"rule_name,omitempty"`
	PredicatePath string `json:"predicate_path,omitempty"`
	FieldPath     string `json:"field_path,omitempty"`
	LineNumber    int    `json:"line_number,omitempty"`
	ColumnNumber  int    `json:"column_number,omitempty"`
}

// StructuralValidationReport contains structural validation results
type StructuralValidationReport struct {
	MessageCompleteness  *MessageCompletenessCheck  `json:"message_completeness"`
	RequiredFieldsCheck  *RequiredFieldsCheck       `json:"required_fields_check"`
	DataTypeValidation   *DataTypeValidation        `json:"data_type_validation"`
	MessageRelationships *MessageRelationshipsCheck `json:"message_relationships"`
	SchemaCompliance     *SchemaComplianceCheck     `json:"schema_compliance"`
	FieldNamingCheck     *FieldNamingCheck          `json:"field_naming_check"`
}

// MessageCompletenessCheck validates protobuf message completeness
type MessageCompletenessCheck struct {
	IsComplete       bool     `json:"is_complete"`
	MissingFields    []string `json:"missing_fields"`
	ExtraFields      []string `json:"extra_fields"`
	CorruptedFields  []string `json:"corrupted_fields"`
	ValidationErrors []string `json:"validation_errors"`
}

// RequiredFieldsCheck validates required fields presence
type RequiredFieldsCheck struct {
	AllRequiredPresent bool                         `json:"all_required_present"`
	RequiredFields     []string                     `json:"required_fields"`
	MissingRequired    []string                     `json:"missing_required"`
	OptionalFields     []string                     `json:"optional_fields"`
	FieldChecks        map[string]*FieldCheckResult `json:"field_checks"`
}

// FieldCheckResult contains individual field validation results
type FieldCheckResult struct {
	FieldName    string      `json:"field_name"`
	IsPresent    bool        `json:"is_present"`
	IsValid      bool        `json:"is_valid"`
	ExpectedType string      `json:"expected_type"`
	ActualType   string      `json:"actual_type"`
	Value        interface{} `json:"value,omitempty"`
	Constraints  []string    `json:"constraints,omitempty"`
	Errors       []string    `json:"errors,omitempty"`
}

// DataTypeValidation validates field data types and formats
type DataTypeValidation struct {
	AllTypesValid     bool                             `json:"all_types_valid"`
	TypeErrors        []*DataTypeError                 `json:"type_errors"`
	FormatErrors      []*FormatError                   `json:"format_errors"`
	TypeConversions   []*TypeConversion                `json:"type_conversions"`
	ValidationResults map[string]*TypeValidationResult `json:"validation_results"`
}

// DataTypeError represents a data type validation error
type DataTypeError struct {
	Field        string      `json:"field"`
	ExpectedType string      `json:"expected_type"`
	ActualType   string      `json:"actual_type"`
	Value        interface{} `json:"value"`
	Message      string      `json:"message"`
}

// FormatError represents a format validation error
type FormatError struct {
	Field          string      `json:"field"`
	ExpectedFormat string      `json:"expected_format"`
	ActualValue    interface{} `json:"actual_value"`
	FormatPattern  string      `json:"format_pattern,omitempty"`
	ValidationRule string      `json:"validation_rule,omitempty"`
	Message        string      `json:"message"`
}

// TypeConversion represents a suggested type conversion
type TypeConversion struct {
	Field      string      `json:"field"`
	FromType   string      `json:"from_type"`
	ToType     string      `json:"to_type"`
	OldValue   interface{} `json:"old_value"`
	NewValue   interface{} `json:"new_value"`
	Confidence float64     `json:"confidence"`
	Risk       string      `json:"risk"` // low, medium, high
}

// TypeValidationResult contains detailed type validation results
type TypeValidationResult struct {
	Field           string                 `json:"field"`
	IsValid         bool                   `json:"is_valid"`
	TypeMatches     bool                   `json:"type_matches"`
	FormatMatches   bool                   `json:"format_matches"`
	ConstraintsMet  bool                   `json:"constraints_met"`
	Errors          []string               `json:"errors"`
	Warnings        []string               `json:"warnings"`
	Suggestions     []string               `json:"suggestions"`
	ValidationRules []string               `json:"validation_rules"`
	Context         map[string]interface{} `json:"context,omitempty"`
}

// MessageRelationshipsCheck validates message relationships
type MessageRelationshipsCheck struct {
	RelationshipsValid bool                         `json:"relationships_valid"`
	BrokenReferences   []*BrokenReference           `json:"broken_references"`
	CircularReferences []*CircularReference         `json:"circular_references"`
	OrphanedObjects    []*OrphanedObject            `json:"orphaned_objects"`
	RelationshipMap    map[string]*RelationshipInfo `json:"relationship_map"`
}

// BrokenReference represents a broken reference between objects
type BrokenReference struct {
	SourceField     string `json:"source_field"`
	TargetReference string `json:"target_reference"`
	TargetType      string `json:"target_type"`
	Message         string `json:"message"`
}

// CircularReference represents a circular reference
type CircularReference struct {
	ReferencePath []string `json:"reference_path"`
	StartField    string   `json:"start_field"`
	EndField      string   `json:"end_field"`
	Message       string   `json:"message"`
}

// OrphanedObject represents an object without proper references
type OrphanedObject struct {
	ObjectType   string   `json:"object_type"`
	ObjectID     string   `json:"object_id"`
	ExpectedRefs []string `json:"expected_refs"`
	Message      string   `json:"message"`
}

// RelationshipInfo contains information about object relationships
type RelationshipInfo struct {
	ObjectType   string   `json:"object_type"`
	ObjectID     string   `json:"object_id"`
	References   []string `json:"references"`
	ReferencedBy []string `json:"referenced_by"`
	IsOrphaned   bool     `json:"is_orphaned"`
	IsCircular   bool     `json:"is_circular"`
}

// SchemaComplianceCheck validates schema compliance
type SchemaComplianceCheck struct {
	IsCompliant      bool                     `json:"is_compliant"`
	SchemaVersion    string                   `json:"schema_version"`
	ComplianceIssues []*SchemaComplianceIssue `json:"compliance_issues"`
	MissingElements  []string                 `json:"missing_elements"`
	ExtraElements    []string                 `json:"extra_elements"`
	VersionMismatch  *VersionMismatchInfo     `json:"version_mismatch,omitempty"`
}

// SchemaComplianceIssue represents a schema compliance issue
type SchemaComplianceIssue struct {
	IssueType  string `json:"issue_type"` // missing, extra, invalid, deprecated
	Element    string `json:"element"`
	SchemaRule string `json:"schema_rule"`
	Message    string `json:"message"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion,omitempty"`
}

// VersionMismatchInfo contains version mismatch details
type VersionMismatchInfo struct {
	ExpectedVersion string `json:"expected_version"`
	ActualVersion   string `json:"actual_version"`
	IsCompatible    bool   `json:"is_compatible"`
	MigrationPath   string `json:"migration_path,omitempty"`
}

// FieldNamingCheck validates field naming conventions
type FieldNamingCheck struct {
	AllNamesValid   bool                    `json:"all_names_valid"`
	NamingErrors    []*FieldNamingError     `json:"naming_errors"`
	StyleViolations []*NamingStyleViolation `json:"style_violations"`
	Suggestions     []*NamingSuggestion     `json:"suggestions"`
}

// FieldNamingError represents a field naming error
type FieldNamingError struct {
	Field       string `json:"field"`
	Issue       string `json:"issue"` // reserved_word, invalid_pattern, too_long
	CurrentName string `json:"current_name"`
	Rule        string `json:"rule"`
	Message     string `json:"message"`
}

// NamingStyleViolation represents a naming style violation
type NamingStyleViolation struct {
	Field         string `json:"field"`
	CurrentStyle  string `json:"current_style"`
	ExpectedStyle string `json:"expected_style"`
	Suggestion    string `json:"suggestion"`
}

// NamingSuggestion represents a naming improvement suggestion
type NamingSuggestion struct {
	Field          string   `json:"field"`
	CurrentName    string   `json:"current_name"`
	SuggestedNames []string `json:"suggested_names"`
	Justification  string   `json:"justification"`
	ImpactLevel    string   `json:"impact_level"` // low, medium, high
}

// SemanticValidationReport contains semantic validation results
type SemanticValidationReport struct {
	FieldPathValidation   *FieldPathValidation   `json:"field_path_validation"`
	PredicateLogicCheck   *PredicateLogicCheck   `json:"predicate_logic_check"`
	AttestationValidation *AttestationValidation `json:"attestation_validation"`
	EnforcementValidation *EnforcementValidation `json:"enforcement_validation"`
	BusinessLogicCheck    *BusinessLogicCheck    `json:"business_logic_check"`
	DependencyValidation  *DependencyValidation  `json:"dependency_validation"`
}

// FieldPathValidation validates field paths against schemas
type FieldPathValidation struct {
	AllPathsValid       bool                      `json:"all_paths_valid"`
	InvalidPaths        []*InvalidFieldPath       `json:"invalid_paths"`
	DeprecatedPaths     []*DeprecatedFieldPath    `json:"deprecated_paths"`
	UnknownPaths        []*UnknownFieldPath       `json:"unknown_paths"`
	PathAnalysis        map[string]*FieldPathInfo `json:"path_analysis"`
	SchemaCompatibility *SchemaCompatibilityInfo  `json:"schema_compatibility"`
}

// InvalidFieldPath represents an invalid field path
type InvalidFieldPath struct {
	Path         string `json:"path"`
	Reason       string `json:"reason"`
	ExpectedType string `json:"expected_type,omitempty"`
	Context      string `json:"context"`
	Suggestion   string `json:"suggestion,omitempty"`
}

// DeprecatedFieldPath represents a deprecated field path
type DeprecatedFieldPath struct {
	Path              string `json:"path"`
	DeprecationReason string `json:"deprecation_reason"`
	Alternative       string `json:"alternative,omitempty"`
	RemovalVersion    string `json:"removal_version,omitempty"`
}

// UnknownFieldPath represents an unknown field path
type UnknownFieldPath struct {
	Path         string   `json:"path"`
	SimilarPaths []string `json:"similar_paths,omitempty"`
	Confidence   float64  `json:"confidence"`
	Suggestion   string   `json:"suggestion,omitempty"`
}

// FieldPathInfo contains detailed field path information
type FieldPathInfo struct {
	Path         string                 `json:"path"`
	IsValid      bool                   `json:"is_valid"`
	Type         string                 `json:"type"`
	IsRequired   bool                   `json:"is_required"`
	IsDeprecated bool                   `json:"is_deprecated"`
	IsIndexed    bool                   `json:"is_indexed"`
	AccessCost   int                    `json:"access_cost"`
	Usage        *FieldUsageInfo        `json:"usage"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// FieldUsageInfo contains field usage statistics
type FieldUsageInfo struct {
	UsageCount        int      `json:"usage_count"`
	UsageContexts     []string `json:"usage_contexts"`
	AccessPatterns    []string `json:"access_patterns"`
	PerformanceImpact string   `json:"performance_impact"`
}

// SchemaCompatibilityInfo contains schema compatibility information
type SchemaCompatibilityInfo struct {
	IsCompatible       bool     `json:"is_compatible"`
	SchemaVersion      string   `json:"schema_version"`
	CompatibilityLevel string   `json:"compatibility_level"` // full, partial, none
	Issues             []string `json:"issues"`
	Recommendations    []string `json:"recommendations"`
}

// PredicateLogicCheck validates predicate logic
type PredicateLogicCheck struct {
	LogicValid         bool                     `json:"logic_valid"`
	ConsistencyIssues  []*LogicConsistencyIssue `json:"consistency_issues"`
	CompletenessCheck  *LogicCompletenessCheck  `json:"completeness_check"`
	OptimizationHints  []*LogicOptimizationHint `json:"optimization_hints"`
	ComplexityAnalysis *LogicComplexityAnalysis `json:"complexity_analysis"`
}

// LogicConsistencyIssue represents a logic consistency issue
type LogicConsistencyIssue struct {
	IssueType     string `json:"issue_type"` // contradiction, tautology, unreachable
	Description   string `json:"description"`
	PredicatePath string `json:"predicate_path"`
	Severity      string `json:"severity"`
	Resolution    string `json:"resolution,omitempty"`
}

// LogicCompletenessCheck checks predicate completeness
type LogicCompletenessCheck struct {
	IsComplete        bool                       `json:"is_complete"`
	MissingConditions []*MissingCondition        `json:"missing_conditions"`
	UncoveredCases    []*UncoveredCase           `json:"uncovered_cases"`
	CoverageAnalysis  *PredicateCoverageAnalysis `json:"coverage_analysis"`
}

// MissingCondition represents a missing logical condition
type MissingCondition struct {
	Field             string `json:"field"`
	ExpectedCondition string `json:"expected_condition"`
	Reason            string `json:"reason"`
	Impact            string `json:"impact"`
	Suggestion        string `json:"suggestion"`
}

// UncoveredCase represents an uncovered logical case
type UncoveredCase struct {
	CaseDescription   string                 `json:"case_description"`
	Conditions        map[string]interface{} `json:"conditions"`
	Likelihood        string                 `json:"likelihood"`
	BusinessImpact    string                 `json:"business_impact"`
	RecommendedAction string                 `json:"recommended_action"`
}

// PredicateCoverageAnalysis analyzes predicate coverage
type PredicateCoverageAnalysis struct {
	TotalConditions    int            `json:"total_conditions"`
	CoveredConditions  int            `json:"covered_conditions"`
	CoveragePercentage float64        `json:"coverage_percentage"`
	UncoveredAreas     []string       `json:"uncovered_areas"`
	CoverageGaps       []*CoverageGap `json:"coverage_gaps"`
}

// CoverageGap represents a coverage gap
type CoverageGap struct {
	Area           string `json:"area"`
	Description    string `json:"description"`
	RiskLevel      string `json:"risk_level"`
	RecommendedFix string `json:"recommended_fix"`
}

// LogicOptimizationHint suggests logic optimizations
type LogicOptimizationHint struct {
	HintType       string  `json:"hint_type"` // reorder, combine, simplify, index
	Description    string  `json:"description"`
	PredicatePath  string  `json:"predicate_path"`
	EstimatedGain  float64 `json:"estimated_gain"`
	Implementation string  `json:"implementation"`
	Complexity     string  `json:"complexity"` // low, medium, high
}

// LogicComplexityAnalysis analyzes predicate complexity
type LogicComplexityAnalysis struct {
	TotalComplexity    int                          `json:"total_complexity"`
	MaxDepth           int                          `json:"max_depth"`
	OperatorCounts     map[string]int               `json:"operator_counts"`
	ComplexityByRule   map[string]int               `json:"complexity_by_rule"`
	ComplexityHotspots []*ComplexityHotspot         `json:"complexity_hotspots"`
	SimplificationOps  []*SimplificationOpportunity `json:"simplification_opportunities"`
}

// ComplexityHotspot identifies high-complexity areas
type ComplexityHotspot struct {
	Location        string `json:"location"`
	ComplexityScore int    `json:"complexity_score"`
	Description     string `json:"description"`
	ImpactLevel     string `json:"impact_level"`
	Suggestion      string `json:"suggestion"`
}

// SimplificationOpportunity suggests simplification
type SimplificationOpportunity struct {
	Location             string  `json:"location"`
	CurrentExpression    string  `json:"current_expression"`
	SimplifiedExpression string  `json:"simplified_expression"`
	ComplexityReduction  int     `json:"complexity_reduction"`
	ConfidenceLevel      float64 `json:"confidence_level"`
}

// AttestationValidation validates attestation requirements
type AttestationValidation struct {
	AllValid              bool                              `json:"all_valid"`
	UnsupportedProviders  []*UnsupportedProvider            `json:"unsupported_providers"`
	InvalidRequirements   []*InvalidAttestation             `json:"invalid_requirements"`
	ProviderCompatibility []*ProviderCompatibilityInfo      `json:"provider_compatibility"`
	CostEstimation        *AttestationCostEstimation        `json:"cost_estimation"`
	PerformanceEstimation *AttestationPerformanceEstimation `json:"performance_estimation"`
}

// UnsupportedProvider represents an unsupported attestation provider
type UnsupportedProvider struct {
	ProviderID           string   `json:"provider_id"`
	RequestedType        string   `json:"requested_type"`
	SupportedTypes       []string `json:"supported_types"`
	AlternativeProviders []string `json:"alternative_providers"`
	Message              string   `json:"message"`
}

// InvalidAttestation represents an invalid attestation requirement
type InvalidAttestation struct {
	AttestationID  string   `json:"attestation_id"`
	Type           string   `json:"type"`
	InvalidReason  string   `json:"invalid_reason"`
	RequiredFields []string `json:"required_fields"`
	MissingFields  []string `json:"missing_fields"`
	Suggestion     string   `json:"suggestion,omitempty"`
}

// ProviderCompatibilityInfo contains provider compatibility information
type ProviderCompatibilityInfo struct {
	ProviderID     string                 `json:"provider_id"`
	IsCompatible   bool                   `json:"is_compatible"`
	SupportedTypes []string               `json:"supported_types"`
	Limitations    []string               `json:"limitations"`
	Configuration  map[string]interface{} `json:"configuration,omitempty"`
	TestResults    *ProviderTestResults   `json:"test_results,omitempty"`
}

// ProviderTestResults contains provider testing results
type ProviderTestResults struct {
	Connectivity   bool          `json:"connectivity"`
	Authentication bool          `json:"authentication"`
	ResponseTime   time.Duration `json:"response_time"`
	ErrorRate      float64       `json:"error_rate"`
	LastTested     time.Time     `json:"last_tested"`
	TestErrors     []string      `json:"test_errors,omitempty"`
}

// AttestationCostEstimation estimates attestation costs
type AttestationCostEstimation struct {
	TotalEstimatedCost   float64                `json:"total_estimated_cost"`
	CostBreakdown        map[string]float64     `json:"cost_breakdown"`
	CostPerAttestation   map[string]float64     `json:"cost_per_attestation"`
	VolumeDiscounts      map[string]float64     `json:"volume_discounts,omitempty"`
	Currency             string                 `json:"currency"`
	EstimationAccuracy   string                 `json:"estimation_accuracy"`
	CostOptimizationTips []*CostOptimizationTip `json:"cost_optimization_tips"`
}

// CostOptimizationTip suggests cost optimization
type CostOptimizationTip struct {
	TipType          string  `json:"tip_type"`
	Description      string  `json:"description"`
	EstimatedSavings float64 `json:"estimated_savings"`
	Implementation   string  `json:"implementation"`
	Priority         string  `json:"priority"`
}

// AttestationPerformanceEstimation estimates performance impact
type AttestationPerformanceEstimation struct {
	TotalEstimatedTime       time.Duration                  `json:"total_estimated_time"`
	TimeBreakdown            map[string]time.Duration       `json:"time_breakdown"`
	ParallelizationOptions   []*ParallelizationOption       `json:"parallelization_options"`
	BottleneckAnalysis       *AttestationBottleneckAnalysis `json:"bottleneck_analysis"`
	PerformanceOptimizations []*PerformanceOptimizationTip  `json:"performance_optimizations"`
}

// ParallelizationOption suggests parallelization
type ParallelizationOption struct {
	Description      string   `json:"description"`
	EstimatedSpeedup float64  `json:"estimated_speedup"`
	Implementation   string   `json:"implementation"`
	Dependencies     []string `json:"dependencies"`
	Complexity       string   `json:"complexity"`
}

// AttestationBottleneckAnalysis identifies performance bottlenecks
type AttestationBottleneckAnalysis struct {
	PrimaryBottleneck    string                `json:"primary_bottleneck"`
	BottleneckFactors    []*BottleneckFactor   `json:"bottleneck_factors"`
	ImpactAssessment     *BottleneckImpact     `json:"impact_assessment"`
	MitigationStrategies []*MitigationStrategy `json:"mitigation_strategies"`
}

// BottleneckFactor represents a performance bottleneck factor
type BottleneckFactor struct {
	Factor       string  `json:"factor"`
	ImpactLevel  string  `json:"impact_level"`
	Description  string  `json:"description"`
	Contribution float64 `json:"contribution"` // percentage contribution to bottleneck
	Addressable  bool    `json:"addressable"`
}

// BottleneckImpact assesses bottleneck impact
type BottleneckImpact struct {
	PerformanceDegradation float64       `json:"performance_degradation"`
	AdditionalLatency      time.Duration `json:"additional_latency"`
	ResourceUtilization    float64       `json:"resource_utilization"`
	UserExperienceImpact   string        `json:"user_experience_impact"`
	BusinessImpact         string        `json:"business_impact"`
}

// MitigationStrategy suggests bottleneck mitigation
type MitigationStrategy struct {
	Strategy           string  `json:"strategy"`
	Description        string  `json:"description"`
	EstimatedGain      float64 `json:"estimated_gain"`
	ImplementationCost string  `json:"implementation_cost"`
	Timeline           string  `json:"timeline"`
	Priority           string  `json:"priority"`
}

// PerformanceOptimizationTip suggests performance optimization
type PerformanceOptimizationTip struct {
	TipType        string  `json:"tip_type"`
	Description    string  `json:"description"`
	EstimatedGain  float64 `json:"estimated_gain"`
	Implementation string  `json:"implementation"`
	Complexity     string  `json:"complexity"`
	Priority       string  `json:"priority"`
}

// ValidationSummary provides a high-level validation summary
type ValidationSummary struct {
	OverallStatus        string               `json:"overall_status"` // pass, fail, warning
	TotalIssues          int                  `json:"total_issues"`
	CriticalIssues       int                  `json:"critical_issues"`
	HighPriorityIssues   int                  `json:"high_priority_issues"`
	MediumPriorityIssues int                  `json:"medium_priority_issues"`
	LowPriorityIssues    int                  `json:"low_priority_issues"`
	CategoryBreakdown    map[string]int       `json:"category_breakdown"`
	ComplianceScore      float64              `json:"compliance_score"`
	SecurityScore        float64              `json:"security_score"`
	PerformanceScore     float64              `json:"performance_score"`
	MaintainabilityScore float64              `json:"maintainability_score"`
	KeyInsights          []*ValidationInsight `json:"key_insights"`
	RecommendedActions   []*RecommendedAction `json:"recommended_actions"`
}

// ValidationInsight provides key insights from validation
type ValidationInsight struct {
	InsightType    string   `json:"insight_type"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	ImpactLevel    string   `json:"impact_level"`
	Confidence     float64  `json:"confidence"`
	DataPoints     []string `json:"data_points"`
	Recommendation string   `json:"recommendation"`
}

// RecommendedAction suggests specific actions
type RecommendedAction struct {
	ActionType      string `json:"action_type"`
	Priority        string `json:"priority"`
	Description     string `json:"description"`
	Justification   string `json:"justification"`
	EstimatedEffort string `json:"estimated_effort"`
	ExpectedBenefit string `json:"expected_benefit"`
	Timeline        string `json:"timeline"`
}

// ValidationRecommendation provides detailed recommendations
type ValidationRecommendation struct {
	RecommendationID   string                 `json:"recommendation_id"`
	Type               string                 `json:"type"`
	Category           string                 `json:"category"`
	Priority           string                 `json:"priority"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description"`
	Rationale          string                 `json:"rationale"`
	Implementation     string                 `json:"implementation"`
	ExpectedBenefit    string                 `json:"expected_benefit"`
	EstimatedEffort    string                 `json:"estimated_effort"`
	Prerequisites      []string               `json:"prerequisites,omitempty"`
	Risks              []string               `json:"risks,omitempty"`
	AlternativeOptions []string               `json:"alternative_options,omitempty"`
	Context            map[string]interface{} `json:"context,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
}

// ValidationMetadata contains validation metadata
type ValidationMetadata struct {
	ValidatorVersion string                 `json:"validator_version"`
	SchemaVersions   map[string]string      `json:"schema_versions"`
	ValidationRules  []string               `json:"validation_rules"`
	EnabledFeatures  []string               `json:"enabled_features"`
	Configuration    map[string]interface{} `json:"configuration"`
	Environment      *ValidationEnvironment `json:"environment"`
	Statistics       *ValidationStatistics  `json:"statistics"`
}

// ValidationEnvironment contains environment information
type ValidationEnvironment struct {
	Platform        string            `json:"platform"`
	RuntimeVersion  string            `json:"runtime_version"`
	AvailableMemory int64             `json:"available_memory"`
	ProcessorCount  int               `json:"processor_count"`
	EnvironmentVars map[string]string `json:"environment_vars,omitempty"`
	SystemResources *SystemResources  `json:"system_resources"`
}

// SystemResources contains system resource information
type SystemResources struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage int64   `json:"memory_usage"`
	DiskUsage   int64   `json:"disk_usage"`
	NetworkIO   int64   `json:"network_io"`
}

// ValidationStatistics contains validation statistics
type ValidationStatistics struct {
	RulesChecked       int                           `json:"rules_checked"`
	FieldsValidated    int                           `json:"fields_validated"`
	PredicatesAnalyzed int                           `json:"predicates_analyzed"`
	SchemasLoaded      int                           `json:"schemas_loaded"`
	ProvidersValidated int                           `json:"providers_validated"`
	TestCasesGenerated int                           `json:"test_cases_generated"`
	PerformanceMetrics *ValidationPerformanceMetrics `json:"performance_metrics"`
}

// ValidationPerformanceMetrics contains performance metrics
type ValidationPerformanceMetrics struct {
	TotalValidationTime       time.Duration `json:"total_validation_time"`
	StructuralValidationTime  time.Duration `json:"structural_validation_time"`
	SemanticValidationTime    time.Duration `json:"semantic_validation_time"`
	PerformanceValidationTime time.Duration `json:"performance_validation_time"`
	MemoryPeakUsage           int64         `json:"memory_peak_usage"`
	CacheHitRate              float64       `json:"cache_hit_rate"`
	ValidationRate            float64       `json:"validation_rate"` // validations per second
}

// EnforcementValidation validates enforcement configurations
type EnforcementValidation struct {
	ValidConfigurations   []string             `json:"valid_configurations"`
	InvalidConfigurations []string             `json:"invalid_configurations"`
	MissingActions        []string             `json:"missing_actions"`
	UnsupportedActions    []string             `json:"unsupported_actions"`
	EnforcementAnalysis   *EnforcementAnalysis `json:"enforcement_analysis"`
}

// EnforcementAnalysis analyzes enforcement configurations
type EnforcementAnalysis struct {
	EnforcementLevel     string                `json:"enforcement_level"`
	TotalActions         int                   `json:"total_actions"`
	ActionTypes          map[string]int        `json:"action_types"`
	EscalationPaths      []string              `json:"escalation_paths"`
	ResponseTime         time.Duration         `json:"response_time"`
	ResourceRequirements *ResourceRequirements `json:"resource_requirements"`
}

// ResourceRequirements defines required resources for enforcement
type ResourceRequirements struct {
	ComputeResources *ComputeResources `json:"compute_resources"`
	StorageResources *StorageResources `json:"storage_resources"`
	NetworkResources *NetworkResources `json:"network_resources"`
	HumanResources   *HumanResources   `json:"human_resources"`
}

// ComputeResources defines compute resource requirements
type ComputeResources struct {
	CPUCores      int     `json:"cpu_cores"`
	MemoryMB      int     `json:"memory_mb"`
	GPURequired   bool    `json:"gpu_required"`
	EstimatedLoad float64 `json:"estimated_load"`
}

// StorageResources defines storage resource requirements
type StorageResources struct {
	DiskSpaceGB    int  `json:"disk_space_gb"`
	IOPSRequired   int  `json:"iops_required"`
	BackupRequired bool `json:"backup_required"`
	RetentionDays  int  `json:"retention_days"`
}

// NetworkResources defines network resource requirements
type NetworkResources struct {
	BandwidthMbps        int      `json:"bandwidth_mbps"`
	LatencyRequirement   int      `json:"latency_requirement_ms"`
	ExternalServices     []string `json:"external_services"`
	SecurityRequirements []string `json:"security_requirements"`
}

// HumanResources defines human resource requirements
type HumanResources struct {
	OperatorsRequired  int      `json:"operators_required"`
	SkillLevels        []string `json:"skill_levels"`
	AvailabilityHours  string   `json:"availability_hours"`
	EscalationContacts []string `json:"escalation_contacts"`
}

// BusinessLogicCheck validates business logic consistency
type BusinessLogicCheck struct {
	LogicValid             bool                       `json:"logic_valid"`
	BusinessRulesSatisfied []string                   `json:"business_rules_satisfied"`
	BusinessRulesViolated  []string                   `json:"business_rules_violated"`
	LogicGaps              []*BusinessLogicGap        `json:"logic_gaps"`
	RecommendedRules       []*RecommendedBusinessRule `json:"recommended_rules"`
}

// BusinessLogicGap represents a gap in business logic
type BusinessLogicGap struct {
	GapType        string `json:"gap_type"`
	Description    string `json:"description"`
	Impact         string `json:"impact"`
	Recommendation string `json:"recommendation"`
	RuleReference  string `json:"rule_reference"`
}

// RecommendedBusinessRule suggests a business rule
type RecommendedBusinessRule struct {
	RuleID         string `json:"rule_id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Priority       string `json:"priority"`
	Rationale      string `json:"rationale"`
	Implementation string `json:"implementation"`
}

// DependencyValidation validates policy dependencies
type DependencyValidation struct {
	AllDependenciesValid bool                  `json:"all_dependencies_valid"`
	ExternalDependencies []*ExternalDependency `json:"external_dependencies"`
	MissingDependencies  []*MissingDependency  `json:"missing_dependencies"`
	DependencyConflicts  []*DependencyConflict `json:"dependency_conflicts"`
	DependencyGraph      *DependencyGraph      `json:"dependency_graph"`
}

// ExternalDependency represents an external dependency
type ExternalDependency struct {
	DependencyID  string                 `json:"dependency_id"`
	Type          string                 `json:"type"`
	Description   string                 `json:"description"`
	Version       string                 `json:"version"`
	Required      bool                   `json:"required"`
	HealthStatus  string                 `json:"health_status"`
	Configuration map[string]interface{} `json:"configuration"`
}

// MissingDependency represents a missing dependency
type MissingDependency struct {
	DependencyID string   `json:"dependency_id"`
	Type         string   `json:"type"`
	Description  string   `json:"description"`
	Impact       string   `json:"impact"`
	Alternatives []string `json:"alternatives"`
	Resolution   string   `json:"resolution"`
}

// DependencyConflict represents a conflict between dependencies
type DependencyConflict struct {
	ConflictID   string   `json:"conflict_id"`
	ConflictType string   `json:"conflict_type"`
	Description  string   `json:"description"`
	Dependencies []string `json:"dependencies"`
	Severity     string   `json:"severity"`
	Resolution   string   `json:"resolution"`
	Impact       string   `json:"impact"`
}

// DependencyGraph represents the dependency graph
type DependencyGraph struct {
	Nodes []*DependencyNode `json:"nodes"`
	Edges []*DependencyEdge `json:"edges"`
}

// DependencyNode represents a node in the dependency graph
type DependencyNode struct {
	NodeID      string                 `json:"node_id"`
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DependencyEdge represents an edge in the dependency graph
type DependencyEdge struct {
	EdgeID        string                 `json:"edge_id"`
	SourceNodeID  string                 `json:"source_node_id"`
	TargetNodeID  string                 `json:"target_node_id"`
	RelationType  string                 `json:"relation_type"`
	Weight        float64                `json:"weight"`
	Bidirectional bool                   `json:"bidirectional"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// PerformanceValidationReport contains performance validation results
type PerformanceValidationReport struct {
	PredicateComplexityAnalysis *PredicateComplexityAnalysis  `json:"predicate_complexity_analysis"`
	EvaluationCostEstimate      *EvaluationCostEstimate       `json:"evaluation_cost_estimate"`
	OptimizationRecommendations []*OptimizationRecommendation `json:"optimization_recommendations"`
	BenchmarkResults            *BenchmarkResults             `json:"benchmark_results"`
	ScalabilityAnalysis         *ScalabilityAnalysis          `json:"scalability_analysis"`
	ResourceUtilization         *ResourceUtilization          `json:"resource_utilization"`
}

// PredicateComplexityAnalysis analyzes predicate complexity
type PredicateComplexityAnalysis struct {
	TotalComplexityScore     int                     `json:"total_complexity_score"`
	ComplexityDistribution   map[string]int          `json:"complexity_distribution"`
	HighComplexityPredicates []*ComplexPredicateInfo `json:"high_complexity_predicates"`
	ComplexityMetrics        *ComplexityMetrics      `json:"complexity_metrics"`
	ComplexityTrends         *ComplexityTrends       `json:"complexity_trends"`
}

// ComplexPredicateInfo contains information about complex predicates
type ComplexPredicateInfo struct {
	PredicateID      string   `json:"predicate_id"`
	Location         string   `json:"location"`
	ComplexityScore  int      `json:"complexity_score"`
	AnalysisDetails  string   `json:"analysis_details"`
	OptimizationTips []string `json:"optimization_tips"`
}

// ComplexityMetrics contains various complexity metrics
type ComplexityMetrics struct {
	AverageComplexity float64 `json:"average_complexity"`
	MaxComplexity     int     `json:"max_complexity"`
	MinComplexity     int     `json:"min_complexity"`
	ComplexityRange   int     `json:"complexity_range"`
	StandardDeviation float64 `json:"standard_deviation"`
}

// ComplexityTrends analyzes complexity trends
type ComplexityTrends struct {
	Trend                string  `json:"trend"` // increasing, decreasing, stable
	TrendStrength        float64 `json:"trend_strength"`
	ComplexityGrowthRate float64 `json:"complexity_growth_rate"`
	PredictedComplexity  int     `json:"predicted_complexity"`
}

// EvaluationCostEstimate estimates evaluation costs
type EvaluationCostEstimate struct {
	TotalEstimatedCost   int                   `json:"total_estimated_cost"`
	CostBreakdown        map[string]int        `json:"cost_breakdown"`
	ExpensiveOperations  []*ExpensiveOperation `json:"expensive_operations"`
	CostOptimizations    []*CostOptimization   `json:"cost_optimizations"`
	BenchmarkComparisons *BenchmarkComparisons `json:"benchmark_comparisons"`
}

// ExpensiveOperation identifies costly operations
type ExpensiveOperation struct {
	OperationID     string `json:"operation_id"`
	Location        string `json:"location"`
	EstimatedCost   int    `json:"estimated_cost"`
	CostFactor      string `json:"cost_factor"`
	OptimizationTip string `json:"optimization_tip"`
}

// CostOptimization suggests cost optimizations
type CostOptimization struct {
	OptimizationID   string `json:"optimization_id"`
	Type             string `json:"type"`
	Description      string `json:"description"`
	EstimatedSavings int    `json:"estimated_savings"`
	Implementation   string `json:"implementation"`
	Difficulty       string `json:"difficulty"`
}

// BenchmarkComparisons compares against benchmarks
type BenchmarkComparisons struct {
	IndustryAverage   int     `json:"industry_average"`
	BestPractice      int     `json:"best_practice"`
	PerformanceRatio  float64 `json:"performance_ratio"`
	RecommendedTarget int     `json:"recommended_target"`
}

// OptimizationRecommendation suggests optimizations
type OptimizationRecommendation struct {
	RecommendationID string   `json:"recommendation_id"`
	Type             string   `json:"type"`
	Priority         string   `json:"priority"`
	Description      string   `json:"description"`
	ExpectedGain     float64  `json:"expected_gain"`
	Implementation   string   `json:"implementation"`
	Prerequisites    []string `json:"prerequisites"`
	RiskLevel        string   `json:"risk_level"`
}

// BenchmarkResults contains benchmarking results
type BenchmarkResults struct {
	ExecutionTimes     map[string]time.Duration `json:"execution_times"`
	MemoryUsage        map[string]int64         `json:"memory_usage"`
	ThroughputMetrics  *ThroughputMetrics       `json:"throughput_metrics"`
	LatencyMetrics     *LatencyMetrics          `json:"latency_metrics"`
	ConcurrencyResults *ConcurrencyResults      `json:"concurrency_results"`
	StressTestResults  *StressTestResults       `json:"stress_test_results"`
}

// ThroughputMetrics measures throughput
type ThroughputMetrics struct {
	RequestsPerSecond   float64 `json:"requests_per_second"`
	PoliciesPerSecond   float64 `json:"policies_per_second"`
	PredicatesPerSecond float64 `json:"predicates_per_second"`
	PeakThroughput      float64 `json:"peak_throughput"`
	SustainedThroughput float64 `json:"sustained_throughput"`
}

// LatencyMetrics measures latency
type LatencyMetrics struct {
	AverageLatency time.Duration `json:"average_latency"`
	MedianLatency  time.Duration `json:"median_latency"`
	P95Latency     time.Duration `json:"p95_latency"`
	P99Latency     time.Duration `json:"p99_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	MinLatency     time.Duration `json:"min_latency"`
}

// ConcurrencyResults measures concurrent performance
type ConcurrencyResults struct {
	OptimalConcurrency    int     `json:"optimal_concurrency"`
	MaxConcurrency        int     `json:"max_concurrency"`
	ConcurrencyEfficiency float64 `json:"concurrency_efficiency"`
	ScalingFactor         float64 `json:"scaling_factor"`
	BottleneckAnalysis    string  `json:"bottleneck_analysis"`
}

// StressTestResults contains stress testing results
type StressTestResults struct {
	BreakingPoint    int           `json:"breaking_point"`
	DegradationPoint int           `json:"degradation_point"`
	RecoveryTime     time.Duration `json:"recovery_time"`
	FailureMode      string        `json:"failure_mode"`
	StabilityScore   float64       `json:"stability_score"`
}

// ScalabilityAnalysis analyzes scalability characteristics
type ScalabilityAnalysis struct {
	HorizontalScaling      *ScalingAnalysis         `json:"horizontal_scaling"`
	VerticalScaling        *ScalingAnalysis         `json:"vertical_scaling"`
	ScalabilityLimits      *ScalabilityLimits       `json:"scalability_limits"`
	ScalingRecommendations []*ScalingRecommendation `json:"scaling_recommendations"`
}

// ScalingAnalysis analyzes scaling characteristics
type ScalingAnalysis struct {
	ScalingEfficiency    float64                `json:"scaling_efficiency"`
	OptimalConfiguration map[string]interface{} `json:"optimal_configuration"`
	ScalingBottlenecks   []string               `json:"scaling_bottlenecks"`
	CostScalingRatio     float64                `json:"cost_scaling_ratio"`
}

// ScalabilityLimits defines scalability limits
type ScalabilityLimits struct {
	MaxPolicySize            int   `json:"max_policy_size"`
	MaxPredicateDepth        int   `json:"max_predicate_depth"`
	MaxConcurrentEvaluations int   `json:"max_concurrent_evaluations"`
	MemoryLimit              int64 `json:"memory_limit"`
	ComputeLimit             int   `json:"compute_limit"`
}

// ScalingRecommendation suggests scaling improvements
type ScalingRecommendation struct {
	RecommendationID string  `json:"recommendation_id"`
	ScalingType      string  `json:"scaling_type"`
	TriggerCondition string  `json:"trigger_condition"`
	ScalingAction    string  `json:"scaling_action"`
	ExpectedBenefit  float64 `json:"expected_benefit"`
	Implementation   string  `json:"implementation"`
}

// ResourceUtilization tracks resource usage
type ResourceUtilization struct {
	CPUUtilization     *CPUUtilization     `json:"cpu_utilization"`
	MemoryUtilization  *MemoryUtilization  `json:"memory_utilization"`
	IOUtilization      *IOUtilization      `json:"io_utilization"`
	NetworkUtilization *NetworkUtilization `json:"network_utilization"`
	ResourceEfficiency *ResourceEfficiency `json:"resource_efficiency"`
}

// CPUUtilization tracks CPU usage
type CPUUtilization struct {
	AverageUsage    float64         `json:"average_usage"`
	PeakUsage       float64         `json:"peak_usage"`
	IdleTime        float64         `json:"idle_time"`
	CoreUtilization map[int]float64 `json:"core_utilization"`
	HotSpots        []string        `json:"hot_spots"`
}

// MemoryUtilization tracks memory usage
type MemoryUtilization struct {
	AverageUsage   int64    `json:"average_usage"`
	PeakUsage      int64    `json:"peak_usage"`
	AllocationRate float64  `json:"allocation_rate"`
	GCPressure     float64  `json:"gc_pressure"`
	MemoryLeaks    []string `json:"memory_leaks"`
}

// IOUtilization tracks I/O usage
type IOUtilization struct {
	ReadThroughput  float64  `json:"read_throughput"`
	WriteThroughput float64  `json:"write_throughput"`
	IOWaitTime      float64  `json:"io_wait_time"`
	DiskUtilization float64  `json:"disk_utilization"`
	IOBottlenecks   []string `json:"io_bottlenecks"`
}

// NetworkUtilization tracks network usage
type NetworkUtilization struct {
	InboundThroughput  float64       `json:"inbound_throughput"`
	OutboundThroughput float64       `json:"outbound_throughput"`
	Latency            time.Duration `json:"latency"`
	PacketLoss         float64       `json:"packet_loss"`
	ConnectionPool     int           `json:"connection_pool"`
}

// ResourceEfficiency measures resource efficiency
type ResourceEfficiency struct {
	OverallEfficiency     float64            `json:"overall_efficiency"`
	ResourceEfficiencies  map[string]float64 `json:"resource_efficiencies"`
	WasteAnalysis         *WasteAnalysis     `json:"waste_analysis"`
	OptimizationPotential float64            `json:"optimization_potential"`
}

// WasteAnalysis identifies resource waste
type WasteAnalysis struct {
	UnusedResources          []string `json:"unused_resources"`
	UnderUtilizedResources   []string `json:"under_utilized_resources"`
	OverProvisionedResources []string `json:"over_provisioned_resources"`
	EstimatedWaste           float64  `json:"estimated_waste"`
}

// ComplianceValidationReport contains compliance validation results
type ComplianceValidationReport struct {
	RegulatoryCompliance   *RegulatoryCompliance   `json:"regulatory_compliance"`
	JurisdictionCompliance *JurisdictionCompliance `json:"jurisdiction_compliance"`
	IndustryStandards      *IndustryStandards      `json:"industry_standards"`
	ComplianceGaps         []*ComplianceGap        `json:"compliance_gaps"`
	ComplianceScore        *ComplianceScore        `json:"compliance_score"`
	AuditReadiness         *AuditReadiness         `json:"audit_readiness"`
}

// RegulatoryCompliance tracks regulatory compliance
type RegulatoryCompliance struct {
	ApplicableRegulations []string            `json:"applicable_regulations"`
	ComplianceStatus      map[string]string   `json:"compliance_status"`
	NonCompliantAreas     []string            `json:"non_compliant_areas"`
	RequiredActions       []*RequiredAction   `json:"required_actions"`
	ComplianceTimeline    *ComplianceTimeline `json:"compliance_timeline"`
}

// RequiredAction defines required compliance actions
type RequiredAction struct {
	ActionID     string    `json:"action_id"`
	Description  string    `json:"description"`
	Priority     string    `json:"priority"`
	Deadline     time.Time `json:"deadline"`
	Responsible  string    `json:"responsible"`
	Dependencies []string  `json:"dependencies"`
	Status       string    `json:"status"`
}

// ComplianceTimeline tracks compliance timeline
type ComplianceTimeline struct {
	Milestones          []*ComplianceMilestone `json:"milestones"`
	CriticalPath        []string               `json:"critical_path"`
	EstimatedCompletion time.Time              `json:"estimated_completion"`
	RiskFactors         []string               `json:"risk_factors"`
}

// ComplianceMilestone defines compliance milestones
type ComplianceMilestone struct {
	MilestoneID  string    `json:"milestone_id"`
	Description  string    `json:"description"`
	TargetDate   time.Time `json:"target_date"`
	ActualDate   time.Time `json:"actual_date,omitempty"`
	Status       string    `json:"status"`
	Dependencies []string  `json:"dependencies"`
}

// JurisdictionCompliance tracks jurisdiction-specific compliance
type JurisdictionCompliance struct {
	PrimaryJurisdiction        string                    `json:"primary_jurisdiction"`
	SecondaryJurisdictions     []string                  `json:"secondary_jurisdictions"`
	JurisdictionRules          map[string]int            `json:"jurisdiction_rules"`
	ConflictingRequirements    []*ConflictingRequirement `json:"conflicting_requirements"`
	HarmonizationOpportunities []string                  `json:"harmonization_opportunities"`
}

// ConflictingRequirement identifies conflicting requirements
type ConflictingRequirement struct {
	RequirementID string   `json:"requirement_id"`
	Jurisdictions []string `json:"jurisdictions"`
	ConflictType  string   `json:"conflict_type"`
	Description   string   `json:"description"`
	Resolution    string   `json:"resolution"`
	Impact        string   `json:"impact"`
}

// IndustryStandards tracks industry standard compliance
type IndustryStandards struct {
	ApplicableStandards []string            `json:"applicable_standards"`
	StandardsCompliance map[string]string   `json:"standards_compliance"`
	BestPractices       []*BestPractice     `json:"best_practices"`
	IndustryBenchmarks  *IndustryBenchmarks `json:"industry_benchmarks"`
}

// BestPractice defines industry best practices
type BestPractice struct {
	PracticeID     string   `json:"practice_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Category       string   `json:"category"`
	Implemented    bool     `json:"implemented"`
	Benefits       []string `json:"benefits"`
	Implementation string   `json:"implementation"`
}

// IndustryBenchmarks provides industry benchmarks
type IndustryBenchmarks struct {
	ComplianceScores   map[string]float64       `json:"compliance_scores"`
	PerformanceMetrics map[string]float64       `json:"performance_metrics"`
	CostMetrics        map[string]float64       `json:"cost_metrics"`
	TimeToCompliance   map[string]time.Duration `json:"time_to_compliance"`
}

// ComplianceScore provides overall compliance scoring
type ComplianceScore struct {
	OverallScore    float64            `json:"overall_score"`
	CategoryScores  map[string]float64 `json:"category_scores"`
	ScoreBreakdown  *ScoreBreakdown    `json:"score_breakdown"`
	ScoreHistory    []*ScoreEntry      `json:"score_history"`
	TargetScore     float64            `json:"target_score"`
	ImprovementPlan *ImprovementPlan   `json:"improvement_plan"`
}

// ScoreBreakdown breaks down compliance scores
type ScoreBreakdown struct {
	StructuralScore   float64 `json:"structural_score"`
	SemanticScore     float64 `json:"semantic_score"`
	PerformanceScore  float64 `json:"performance_score"`
	SecurityScore     float64 `json:"security_score"`
	AuditabilityScore float64 `json:"auditability_score"`
}

// ScoreEntry tracks score history
type ScoreEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Reason    string    `json:"reason"`
	Changes   []string  `json:"changes"`
}

// ImprovementPlan defines compliance improvement plan
type ImprovementPlan struct {
	PlanID          string                  `json:"plan_id"`
	TargetScore     float64                 `json:"target_score"`
	Timeline        time.Duration           `json:"timeline"`
	Actions         []*ImprovementAction    `json:"actions"`
	Milestones      []*ImprovementMilestone `json:"milestones"`
	EstimatedCost   float64                 `json:"estimated_cost"`
	ExpectedBenefit float64                 `json:"expected_benefit"`
}

// ImprovementAction defines improvement actions
type ImprovementAction struct {
	ActionID        string        `json:"action_id"`
	Description     string        `json:"description"`
	Priority        string        `json:"priority"`
	EstimatedEffort string        `json:"estimated_effort"`
	Timeline        time.Duration `json:"timeline"`
	Dependencies    []string      `json:"dependencies"`
	Owner           string        `json:"owner"`
	Status          string        `json:"status"`
}

// ImprovementMilestone defines improvement milestones
type ImprovementMilestone struct {
	MilestoneID        string    `json:"milestone_id"`
	Description        string    `json:"description"`
	TargetDate         time.Time `json:"target_date"`
	ExpectedScore      float64   `json:"expected_score"`
	CompletionCriteria []string  `json:"completion_criteria"`
	Status             string    `json:"status"`
}

// AuditReadiness assesses audit readiness
type AuditReadiness struct {
	ReadinessScore      float64              `json:"readiness_score"`
	ReadinessFactors    []*ReadinessFactor   `json:"readiness_factors"`
	DocumentationStatus *DocumentationStatus `json:"documentation_status"`
	ProcessMaturity     *ProcessMaturity     `json:"process_maturity"`
	AuditPreparation    *AuditPreparation    `json:"audit_preparation"`
}

// ReadinessFactor identifies readiness factors
type ReadinessFactor struct {
	FactorID    string  `json:"factor_id"`
	Name        string  `json:"name"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
	GapAnalysis string  `json:"gap_analysis"`
}

// DocumentationStatus tracks documentation completeness
type DocumentationStatus struct {
	CompletenessScore float64            `json:"completeness_score"`
	RequiredDocuments []string           `json:"required_documents"`
	MissingDocuments  []string           `json:"missing_documents"`
	OutdatedDocuments []string           `json:"outdated_documents"`
	DocumentQuality   map[string]float64 `json:"document_quality"`
}

// ProcessMaturity assesses process maturity
type ProcessMaturity struct {
	MaturityLevel         string         `json:"maturity_level"`
	MaturityScore         float64        `json:"maturity_score"`
	ProcessAreas          []*ProcessArea `json:"process_areas"`
	MaturityGaps          []*MaturityGap `json:"maturity_gaps"`
	NextLevelRequirements []string       `json:"next_level_requirements"`
}

// ProcessArea defines process areas
type ProcessArea struct {
	AreaID        string   `json:"area_id"`
	Name          string   `json:"name"`
	MaturityLevel string   `json:"maturity_level"`
	Score         float64  `json:"score"`
	Strengths     []string `json:"strengths"`
	Weaknesses    []string `json:"weaknesses"`
}

// MaturityGap identifies maturity gaps
type MaturityGap struct {
	GapID        string   `json:"gap_id"`
	ProcessArea  string   `json:"process_area"`
	CurrentLevel string   `json:"current_level"`
	TargetLevel  string   `json:"target_level"`
	GapAnalysis  string   `json:"gap_analysis"`
	Remediation  []string `json:"remediation"`
}

// AuditPreparation tracks audit preparation
type AuditPreparation struct {
	PreparationScore  float64            `json:"preparation_score"`
	PreparationTasks  []*PreparationTask `json:"preparation_tasks"`
	MockAuditResults  *MockAuditResults  `json:"mock_audit_results"`
	AuditorFeedback   []*AuditorFeedback `json:"auditor_feedback"`
	ReadinessTimeline *ReadinessTimeline `json:"readiness_timeline"`
}

// PreparationTask defines audit preparation tasks
type PreparationTask struct {
	TaskID       string    `json:"task_id"`
	Description  string    `json:"description"`
	Priority     string    `json:"priority"`
	Status       string    `json:"status"`
	Owner        string    `json:"owner"`
	Deadline     time.Time `json:"deadline"`
	Dependencies []string  `json:"dependencies"`
	Progress     float64   `json:"progress"`
}

// MockAuditResults contains mock audit results
type MockAuditResults struct {
	OverallScore           float64                 `json:"overall_score"`
	AreaScores             map[string]float64      `json:"area_scores"`
	FindingsSummary        *FindingsSummary        `json:"findings_summary"`
	RecommendationsSummary *RecommendationsSummary `json:"recommendations_summary"`
	AuditDate              time.Time               `json:"audit_date"`
}

// FindingsSummary summarizes audit findings
type FindingsSummary struct {
	TotalFindings    int            `json:"total_findings"`
	CriticalFindings int            `json:"critical_findings"`
	HighFindings     int            `json:"high_findings"`
	MediumFindings   int            `json:"medium_findings"`
	LowFindings      int            `json:"low_findings"`
	FindingTypes     map[string]int `json:"finding_types"`
}

// RecommendationsSummary summarizes audit recommendations
type RecommendationsSummary struct {
	TotalRecommendations int            `json:"total_recommendations"`
	PriorityDistribution map[string]int `json:"priority_distribution"`
	CategoryDistribution map[string]int `json:"category_distribution"`
	EstimatedEffort      time.Duration  `json:"estimated_effort"`
	EstimatedCost        float64        `json:"estimated_cost"`
}

// AuditorFeedback contains feedback from auditors
type AuditorFeedback struct {
	FeedbackID  string    `json:"feedback_id"`
	AuditorName string    `json:"auditor_name"`
	Date        time.Time `json:"date"`
	Category    string    `json:"category"`
	Feedback    string    `json:"feedback"`
	Rating      float64   `json:"rating"`
	Actionable  bool      `json:"actionable"`
}

// ReadinessTimeline tracks audit readiness timeline
type ReadinessTimeline struct {
	CurrentPhase       string            `json:"current_phase"`
	Phases             []*ReadinessPhase `json:"phases"`
	CriticalPath       []string          `json:"critical_path"`
	EstimatedReadiness time.Time         `json:"estimated_readiness"`
	RiskFactors        []string          `json:"risk_factors"`
}

// ReadinessPhase defines audit readiness phases
type ReadinessPhase struct {
	PhaseID      string    `json:"phase_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	StartDate    time.Time `json:"start_date"`
	EndDate      time.Time `json:"end_date"`
	Status       string    `json:"status"`
	Progress     float64   `json:"progress"`
	Tasks        []string  `json:"tasks"`
	Dependencies []string  `json:"dependencies"`
}

// TransactionData represents sample transaction data for testing
type TransactionData struct {
	Data            map[string]interface{} `json:"data"`
	AttestationData map[string]interface{} `json:"attestation_data,omitempty"`
}

// GetField retrieves a field value from transaction data
func (td TransactionData) GetField(fieldPath string) (interface{}, bool) {
	value, exists := td.Data[fieldPath]
	return value, exists
}

// GetAttestationData retrieves attestation data for a specific type
func (td TransactionData) GetAttestationData(attestationType string) (interface{}, bool) {
	if td.AttestationData == nil {
		return nil, false
	}
	value, exists := td.AttestationData[attestationType]
	return value, exists
}

// TestReport represents the results of testing a policy against sample data
type TestReport struct {
	TestID             string                  `json:"test_id"`
	PolicyID           string                  `json:"policy_id"`
	TestType           string                  `json:"test_type"`
	ExecutedAt         time.Time               `json:"executed_at"`
	TestResults        []*TestResult           `json:"test_results"`
	PerformanceMetrics *TestPerformanceMetrics `json:"performance_metrics"`
	Summary            *TestSummary            `json:"summary"`
	TestConfiguration  *TestConfiguration      `json:"test_configuration"`
	RegressionAnalysis *RegressionAnalysis     `json:"regression_analysis"`
	CoverageAnalysis   *CoverageAnalysis       `json:"coverage_analysis"`
	TestInsights       []*TestInsight          `json:"test_insights,omitempty"`
	Recommendations    []*TestRecommendation   `json:"recommendations,omitempty"`
}

// TestResult represents the result of a single test execution
type TestResult struct {
	TestCaseID        string                  `json:"test_case_id"`
	TestName          string                  `json:"test_name"`
	Status            string                  `json:"status"` // passed, failed, error
	Message           string                  `json:"message,omitempty"`
	StartTime         time.Time               `json:"start_time"`
	EndTime           time.Time               `json:"end_time"`
	ExecutionTime     time.Duration           `json:"execution_time"`
	TestData          TransactionData         `json:"test_data"`
	ValidationResults []*RuleValidationResult `json:"validation_results"`
	ErrorDetails      []*TestError            `json:"error_details,omitempty"`
}

// RuleValidationResult represents the result of validating a rule against sample data
type RuleValidationResult struct {
	RuleID        string      `json:"rule_id"`
	RuleName      string      `json:"rule_name"`
	Passed        bool        `json:"passed"`
	ErrorMessage  string      `json:"error_message,omitempty"`
	Field         string      `json:"field,omitempty"`
	ExpectedValue interface{} `json:"expected_value,omitempty"`
	ActualValue   interface{} `json:"actual_value,omitempty"`
}

// TestError represents an error encountered during testing
type TestError struct {
	ErrorType     string      `json:"error_type"`
	RuleID        string      `json:"rule_id,omitempty"`
	Message       string      `json:"message"`
	Field         string      `json:"field,omitempty"`
	ExpectedValue interface{} `json:"expected_value,omitempty"`
	ActualValue   interface{} `json:"actual_value,omitempty"`
}

// TestPerformanceMetrics contains performance metrics from test execution
type TestPerformanceMetrics struct {
	AverageExecutionTime time.Duration `json:"average_execution_time"`
	MaxExecutionTime     time.Duration `json:"max_execution_time"`
	MinExecutionTime     time.Duration `json:"min_execution_time"`
	TotalExecutionTime   time.Duration `json:"total_execution_time"`
	MemoryUsage          int64         `json:"memory_usage"`
	CPUUsage             float64       `json:"cpu_usage"`
}

// TestSummary contains summary statistics for test execution
type TestSummary struct {
	TotalTests    int           `json:"total_tests"`
	PassedTests   int           `json:"passed_tests"`
	FailedTests   int           `json:"failed_tests"`
	ErrorTests    int           `json:"error_tests"`
	SuccessRate   float64       `json:"success_rate"`
	FailureRate   float64       `json:"failure_rate"`
	ErrorRate     float64       `json:"error_rate"`
	ExecutionTime time.Duration `json:"execution_time"`
}

// BaselineResult represents baseline test results for regression analysis
type BaselineResult struct {
	TestCaseID    string        `json:"test_case_id"`
	ExecutionTime time.Duration `json:"execution_time"`
	Status        string        `json:"status"`
	Timestamp     time.Time     `json:"timestamp"`
}

// ComparisonResult represents comparison with baseline for regression detection
type ComparisonResult struct {
	TestCaseID        string        `json:"test_case_id"`
	BaselineTime      time.Duration `json:"baseline_time"`
	CurrentTime       time.Duration `json:"current_time"`
	PerformanceChange float64       `json:"performance_change"`
	StatusChanged     bool          `json:"status_changed"`
	IsRegression      bool          `json:"is_regression"`
}

// RegressionDetail provides details about detected regressions
type RegressionDetail struct {
	TestCaseID        string    `json:"test_case_id"`
	RegressionType    string    `json:"regression_type"` // performance, functional
	Severity          string    `json:"severity"`        // low, medium, high, critical
	Description       string    `json:"description"`
	RecommendedAction string    `json:"recommended_action"`
	DetectedAt        time.Time `json:"detected_at"`
}

// TestInsight provides insights from test execution
type TestInsight struct {
	InsightID   string                 `json:"insight_id"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Context     map[string]interface{} `json:"context,omitempty"`
	GeneratedAt time.Time              `json:"generated_at"`
}

// TestRecommendation provides recommendations based on test results
type TestRecommendation struct {
	RecommendationID string                 `json:"recommendation_id"`
	Type             string                 `json:"type"`
	Priority         string                 `json:"priority"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Implementation   string                 `json:"implementation"`
	ExpectedBenefit  string                 `json:"expected_benefit"`
	Context          map[string]interface{} `json:"context,omitempty"`
	GeneratedAt      time.Time              `json:"generated_at"`
}

// TestCase represents a single test case
type TestCase struct {
	TestCaseID     string             `json:"test_case_id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	ExpectedResult TestExpectedResult `json:"expected_result"`
	TestData       TransactionData    `json:"test_data"`
	Category       string             `json:"category"` // positive, negative, boundary, edge_case, performance, integration
	Priority       string             `json:"priority"` // low, medium, high
	Tags           []string           `json:"tags,omitempty"`
	Prerequisites  []string           `json:"prerequisites,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
}

// TestExpectedResult defines the expected outcome of a test case
type TestExpectedResult struct {
	ShouldPass          bool            `json:"should_pass"`
	ExpectedErrors      []string        `json:"expected_errors,omitempty"`
	MaxExecutionTime    time.Duration   `json:"max_execution_time,omitempty"`
	ExpectedValidations map[string]bool `json:"expected_validations,omitempty"`
}
