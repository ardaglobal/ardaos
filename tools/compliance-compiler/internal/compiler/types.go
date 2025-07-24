package compiler

import (
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
)

// PolicySchema defines the expected structure and validation rules for policies
type PolicySchema struct {
	Version           string                    `json:"version"`
	Jurisdiction      string                    `json:"jurisdiction"`
	AssetClasses      []string                  `json:"asset_classes"`
	RequiredFields    []string                  `json:"required_fields"`
	FieldSchemas      map[string]*FieldSchema   `json:"field_schemas"`
	PredicateRules    *PredicateValidationRules `json:"predicate_rules"`
	AttestationTypes  []string                  `json:"attestation_types"`
	EnforcementLevels []string                  `json:"enforcement_levels"`
}

// FieldSchema defines validation rules for individual fields
type FieldSchema struct {
	Type          string        `json:"type"`
	Required      bool          `json:"required"`
	Pattern       string        `json:"pattern,omitempty"`
	MinValue      interface{}   `json:"min_value,omitempty"`
	MaxValue      interface{}   `json:"max_value,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty"`
	Description   string        `json:"description,omitempty"`
}

// PredicateValidationRules defines rules for predicate validation
type PredicateValidationRules struct {
	MaxDepth         int      `json:"max_depth"`
	MaxConditions    int      `json:"max_conditions"`
	AllowedOperators []string `json:"allowed_operators"`
	RequiredFields   []string `json:"required_fields"`
}

// PolicyTemplate defines reusable policy patterns
type PolicyTemplate struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Version      string                 `json:"version"`
	BaseTemplate string                 `json:"base_template,omitempty"`
	Parameters   map[string]interface{} `json:"parameters"`
	Rules        []interface{}          `json:"rules"`
	Attestations []interface{}          `json:"attestations"`
	Enforcement  interface{}            `json:"enforcement"`
}

// CompilationResult contains the complete compilation output
type CompilationResult struct {
	CompiledPolicy    *parser.CompliancePolicy `json:"compiled_policy"`
	BinaryData        []byte                   `json:"binary_data"`
	JSONData          []byte                   `json:"json_data"`
	PolicyFingerprint string                   `json:"policy_fingerprint"`
	Metadata          *CompilationMetadata     `json:"metadata"`
	OptimizationStats *OptimizationStats       `json:"optimization_stats"`
	ValidationReport  *ValidationReport        `json:"validation_report"`
	AuditTrail        *CompilationAuditTrail   `json:"audit_trail,omitempty"`
}

// CompilationMetadata contains information about the compilation process
type CompilationMetadata struct {
	CompilerVersion   string               `json:"compiler_version"`
	CompilationTime   time.Time            `json:"compilation_time"`
	OptimizationLevel int                  `json:"optimization_level"`
	SourceHash        string               `json:"source_hash"`
	Dependencies      []string             `json:"dependencies"`
	Warnings          []CompilationWarning `json:"warnings"`
	Performance       *PerformanceMetrics  `json:"performance"`
	Schema            *SchemaInfo          `json:"schema"`
}

// CompilationWarning represents a compilation warning
type CompilationWarning struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion,omitempty"`
}

// PerformanceMetrics tracks compilation performance
type PerformanceMetrics struct {
	CompilationTime   time.Duration `json:"compilation_time"`
	MemoryUsage       int64         `json:"memory_usage"`
	OptimizationTime  time.Duration `json:"optimization_time"`
	ValidationTime    time.Duration `json:"validation_time"`
	SerializationTime time.Duration `json:"serialization_time"`
}

// SchemaInfo contains information about the schema used
type SchemaInfo struct {
	SchemaVersion string   `json:"schema_version"`
	Jurisdiction  string   `json:"jurisdiction"`
	AssetClass    string   `json:"asset_class"`
	Extensions    []string `json:"extensions,omitempty"`
}

// OptimizationStats tracks optimization effectiveness
type OptimizationStats struct {
	OriginalPredicates   int                `json:"original_predicates"`
	OptimizedPredicates  int                `json:"optimized_predicates"`
	FlattenedConditions  int                `json:"flattened_conditions"`
	EliminatedDuplicates int                `json:"eliminated_duplicates"`
	ReorderedConditions  int                `json:"reordered_conditions"`
	ConstantsFolded      int                `json:"constants_folded"`
	OptimizationTime     time.Duration      `json:"optimization_time"`
	CompressionRatio     float64            `json:"compression_ratio"`
	OptimizationDetails  []OptimizationStep `json:"optimization_details"`
}

// OptimizationStep records individual optimization transformations
type OptimizationStep struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	BeforeSize  int       `json:"before_size"`
	AfterSize   int       `json:"after_size"`
	Savings     int       `json:"savings"`
	Timestamp   time.Time `json:"timestamp"`
}

// ValidationReport contains comprehensive validation results
type ValidationReport struct {
	IsValid           bool                         `json:"is_valid"`
	Errors            []ValidationError            `json:"errors"`
	Warnings          []ValidationWarning          `json:"warnings"`
	FieldValidation   *FieldValidationResult       `json:"field_validation"`
	PredicateAnalysis *PredicateAnalysisResult     `json:"predicate_analysis"`
	AttestationCheck  *AttestationValidationResult `json:"attestation_check"`
	EnforcementCheck  *EnforcementValidationResult `json:"enforcement_check"`
	PolicyImpact      *PolicyImpactAssessment      `json:"policy_impact"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Field      string `json:"field,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Field      string `json:"field,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion,omitempty"`
}

// FieldValidationResult contains field validation results
type FieldValidationResult struct {
	ValidFields     []string            `json:"valid_fields"`
	InvalidFields   []string            `json:"invalid_fields"`
	MissingRequired []string            `json:"missing_required"`
	UnknownFields   []string            `json:"unknown_fields"`
	FieldErrors     map[string][]string `json:"field_errors"`
	FieldAnalysis   *FieldUsageAnalysis `json:"field_analysis"`
}

// FieldUsageAnalysis provides analysis of field usage patterns
type FieldUsageAnalysis struct {
	TotalFields     int                 `json:"total_fields"`
	UniqueFields    int                 `json:"unique_fields"`
	MostUsedFields  []string            `json:"most_used_fields"`
	UnusedFields    []string            `json:"unused_fields"`
	FieldComplexity map[string]int      `json:"field_complexity"`
	AccessPatterns  map[string][]string `json:"access_patterns"`
}

// PredicateAnalysisResult contains predicate analysis results
type PredicateAnalysisResult struct {
	TotalPredicates     int                         `json:"total_predicates"`
	PredicateDepth      int                         `json:"predicate_depth"`
	LogicalOperators    map[string]int              `json:"logical_operators"`
	ComparisonOperators map[string]int              `json:"comparison_operators"`
	ComplexityScore     int                         `json:"complexity_score"`
	CircularReferences  []string                    `json:"circular_references"`
	OptimizationHints   []PredicateOptimizationHint `json:"optimization_hints"`
}

// PredicateOptimizationHint suggests predicate optimizations
type PredicateOptimizationHint struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Impact      string `json:"impact"`
	Suggestion  string `json:"suggestion"`
}

// AttestationValidationResult contains attestation validation results
type AttestationValidationResult struct {
	ValidAttestations    []string              `json:"valid_attestations"`
	InvalidAttestations  []string              `json:"invalid_attestations"`
	MissingRequirements  []string              `json:"missing_requirements"`
	UnsupportedTypes     []string              `json:"unsupported_types"`
	AttestationAnalysis  *AttestationAnalysis  `json:"attestation_analysis"`
	DataSourceValidation *DataSourceValidation `json:"data_source_validation"`
}

// AttestationAnalysis provides analysis of attestation requirements
type AttestationAnalysis struct {
	TotalAttestations    int             `json:"total_attestations"`
	RequiredAttestations int             `json:"required_attestations"`
	OptionalAttestations int             `json:"optional_attestations"`
	AttestationTypes     map[string]int  `json:"attestation_types"`
	EstimatedCost        float64         `json:"estimated_cost"`
	EstimatedTime        time.Duration   `json:"estimated_time"`
	RiskAssessment       *RiskAssessment `json:"risk_assessment"`
}

// DataSourceValidation validates attestation data sources
type DataSourceValidation struct {
	ValidSources       []string            `json:"valid_sources"`
	InvalidSources     []string            `json:"invalid_sources"`
	UnavailableSources []string            `json:"unavailable_sources"`
	SourceReliability  map[string]float64  `json:"source_reliability"`
	AccessRequirements map[string][]string `json:"access_requirements"`
}

// RiskAssessment assesses policy risk factors
type RiskAssessment struct {
	OverallRisk     string          `json:"overall_risk"`
	RiskFactors     []RiskFactor    `json:"risk_factors"`
	MitigationSteps []string        `json:"mitigation_steps"`
	ComplianceGaps  []ComplianceGap `json:"compliance_gaps"`
}

// RiskFactor represents a specific risk factor
type RiskFactor struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Probability float64 `json:"probability"`
	Impact      string  `json:"impact"`
	Description string  `json:"description"`
	Mitigation  string  `json:"mitigation"`
}

// ComplianceGap represents a gap in compliance coverage
type ComplianceGap struct {
	Area         string   `json:"area"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	Requirements []string `json:"requirements"`
	Remediation  string   `json:"remediation"`
}

// EnforcementValidationResult contains enforcement validation results
type EnforcementValidationResult struct {
	ValidConfigurations   []string             `json:"valid_configurations"`
	InvalidConfigurations []string             `json:"invalid_configurations"`
	MissingActions        []string             `json:"missing_actions"`
	UnsupportedActions    []string             `json:"unsupported_actions"`
	EnforcementAnalysis   *EnforcementAnalysis `json:"enforcement_analysis"`
}

// EnforcementAnalysis provides analysis of enforcement configurations
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

// PolicyImpactAssessment assesses the impact of the policy
type PolicyImpactAssessment struct {
	BusinessImpact    *BusinessImpact    `json:"business_impact"`
	TechnicalImpact   *TechnicalImpact   `json:"technical_impact"`
	ComplianceImpact  *ComplianceImpact  `json:"compliance_impact"`
	OperationalImpact *OperationalImpact `json:"operational_impact"`
	FinancialImpact   *FinancialImpact   `json:"financial_impact"`
}

// BusinessImpact assesses business-level impact
type BusinessImpact struct {
	ProcessesAffected    []string       `json:"processes_affected"`
	StakeholdersImpacted []string       `json:"stakeholders_impacted"`
	BusinessContinuity   string         `json:"business_continuity"`
	CustomerImpact       string         `json:"customer_impact"`
	RevenueImpact        *RevenueImpact `json:"revenue_impact"`
}

// RevenueImpact quantifies revenue impact
type RevenueImpact struct {
	EstimatedChange   float64       `json:"estimated_change"`
	ChangeType        string        `json:"change_type"` // "increase", "decrease", "neutral"
	TimeToRealization time.Duration `json:"time_to_realization"`
	ConfidenceLevel   float64       `json:"confidence_level"`
}

// TechnicalImpact assesses technical system impact
type TechnicalImpact struct {
	SystemsAffected   []string           `json:"systems_affected"`
	PerformanceImpact *PerformanceImpact `json:"performance_impact"`
	ScalabilityImpact *ScalabilityImpact `json:"scalability_impact"`
	SecurityImpact    *SecurityImpact    `json:"security_impact"`
	MaintenanceImpact *MaintenanceImpact `json:"maintenance_impact"`
}

// PerformanceImpact quantifies performance impact
type PerformanceImpact struct {
	LatencyChange       time.Duration `json:"latency_change"`
	ThroughputChange    float64       `json:"throughput_change"`
	ResourceUtilization float64       `json:"resource_utilization"`
	CacheHitRate        float64       `json:"cache_hit_rate"`
}

// ScalabilityImpact assesses scalability implications
type ScalabilityImpact struct {
	HorizontalScaling string `json:"horizontal_scaling"`
	VerticalScaling   string `json:"vertical_scaling"`
	ScalingComplexity string `json:"scaling_complexity"`
	MaxSupportedLoad  int    `json:"max_supported_load"`
}

// SecurityImpact assesses security implications
type SecurityImpact struct {
	ThreatModel         []string `json:"threat_model"`
	VulnerabilityRisk   string   `json:"vulnerability_risk"`
	DataExposureRisk    string   `json:"data_exposure_risk"`
	AccessControlImpact string   `json:"access_control_impact"`
	AuditRequirements   []string `json:"audit_requirements"`
}

// MaintenanceImpact assesses maintenance requirements
type MaintenanceImpact struct {
	MaintenanceComplexity string   `json:"maintenance_complexity"`
	UpdateFrequency       string   `json:"update_frequency"`
	SkillRequirements     []string `json:"skill_requirements"`
	MaintenanceWindows    []string `json:"maintenance_windows"`
}

// ComplianceImpact assesses regulatory compliance impact
type ComplianceImpact struct {
	RegulatoryFrameworks  []string         `json:"regulatory_frameworks"`
	ComplianceLevel       string           `json:"compliance_level"`
	AuditRequirements     []string         `json:"audit_requirements"`
	ReportingRequirements []string         `json:"reporting_requirements"`
	ComplianceGaps        []ComplianceGap  `json:"compliance_gaps"`
	RemediationPlan       *RemediationPlan `json:"remediation_plan"`
}

// RemediationPlan defines steps to address compliance gaps
type RemediationPlan struct {
	Steps              []RemediationStep `json:"steps"`
	Timeline           time.Duration     `json:"timeline"`
	RequiredResources  []string          `json:"required_resources"`
	ResponsibleParties []string          `json:"responsible_parties"`
	SuccessMetrics     []string          `json:"success_metrics"`
}

// RemediationStep defines a single remediation step
type RemediationStep struct {
	ID           string        `json:"id"`
	Description  string        `json:"description"`
	Priority     string        `json:"priority"`
	Timeline     time.Duration `json:"timeline"`
	Dependencies []string      `json:"dependencies"`
	Owner        string        `json:"owner"`
	Status       string        `json:"status"`
}

// OperationalImpact assesses operational implications
type OperationalImpact struct {
	ProcessChanges         []ProcessChange         `json:"process_changes"`
	TrainingRequirements   []TrainingRequirement   `json:"training_requirements"`
	ToolingRequirements    []ToolingRequirement    `json:"tooling_requirements"`
	MonitoringRequirements []MonitoringRequirement `json:"monitoring_requirements"`
}

// ProcessChange describes changes to operational processes
type ProcessChange struct {
	ProcessName      string        `json:"process_name"`
	ChangeType       string        `json:"change_type"`
	Description      string        `json:"description"`
	Impact           string        `json:"impact"`
	Timeline         time.Duration `json:"timeline"`
	ResponsibleParty string        `json:"responsible_party"`
}

// TrainingRequirement describes training needs
type TrainingRequirement struct {
	Topic         string        `json:"topic"`
	Audience      []string      `json:"audience"`
	Duration      time.Duration `json:"duration"`
	Format        string        `json:"format"`
	Prerequisites []string      `json:"prerequisites"`
	Certification bool          `json:"certification"`
}

// ToolingRequirement describes required tooling
type ToolingRequirement struct {
	ToolName    string        `json:"tool_name"`
	Purpose     string        `json:"purpose"`
	Priority    string        `json:"priority"`
	Cost        float64       `json:"cost"`
	Timeline    time.Duration `json:"timeline"`
	Integration []string      `json:"integration"`
}

// MonitoringRequirement describes monitoring needs
type MonitoringRequirement struct {
	MetricName string        `json:"metric_name"`
	MetricType string        `json:"metric_type"`
	Threshold  interface{}   `json:"threshold"`
	AlertLevel string        `json:"alert_level"`
	Frequency  time.Duration `json:"frequency"`
	Dashboard  string        `json:"dashboard"`
}

// FinancialImpact assesses financial implications
type FinancialImpact struct {
	ImplementationCost  *CostBreakdown       `json:"implementation_cost"`
	OperationalCost     *CostBreakdown       `json:"operational_cost"`
	ComplianceCost      *CostBreakdown       `json:"compliance_cost"`
	ROIAnalysis         *ROIAnalysis         `json:"roi_analysis"`
	CostBenefitAnalysis *CostBenefitAnalysis `json:"cost_benefit_analysis"`
}

// CostBreakdown provides detailed cost analysis
type CostBreakdown struct {
	TotalCost      float64            `json:"total_cost"`
	CostCategories map[string]float64 `json:"cost_categories"`
	Timeline       map[string]float64 `json:"timeline"`
	Currency       string             `json:"currency"`
	Assumptions    []string           `json:"assumptions"`
}

// ROIAnalysis provides return on investment analysis
type ROIAnalysis struct {
	InitialInvestment float64       `json:"initial_investment"`
	ExpectedReturns   float64       `json:"expected_returns"`
	PaybackPeriod     time.Duration `json:"payback_period"`
	ROI               float64       `json:"roi"`
	NPV               float64       `json:"npv"`
	IRR               float64       `json:"irr"`
}

// CostBenefitAnalysis provides cost-benefit analysis
type CostBenefitAnalysis struct {
	TotalCosts          float64            `json:"total_costs"`
	TotalBenefits       float64            `json:"total_benefits"`
	NetBenefit          float64            `json:"net_benefit"`
	BenefitCostRatio    float64            `json:"benefit_cost_ratio"`
	QualitativeBenefits []string           `json:"qualitative_benefits"`
	RiskAdjustments     map[string]float64 `json:"risk_adjustments"`
}

// CompilationAuditTrail tracks all compilation activities for compliance
type CompilationAuditTrail struct {
	TrailID        string                  `json:"trail_id"`
	CompilationID  string                  `json:"compilation_id"`
	StartTime      time.Time               `json:"start_time"`
	EndTime        time.Time               `json:"end_time"`
	UserID         string                  `json:"user_id"`
	SourceDocument *SourceDocumentInfo     `json:"source_document"`
	Operations     []CompilationOperation  `json:"operations"`
	DataAccess     []DataAccessRecord      `json:"data_access"`
	Compliance     *ComplianceTrackingInfo `json:"compliance"`
}

// SourceDocumentInfo tracks source document metadata
type SourceDocumentInfo struct {
	FileName     string    `json:"file_name"`
	FileSize     int64     `json:"file_size"`
	FileHash     string    `json:"file_hash"`
	LastModified time.Time `json:"last_modified"`
	Author       string    `json:"author"`
	Version      string    `json:"version"`
}

// CompilationOperation tracks individual compilation operations
type CompilationOperation struct {
	OperationID string                 `json:"operation_id"`
	Type        string                 `json:"type"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Status      string                 `json:"status"`
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output"`
	Errors      []string               `json:"errors"`
	Warnings    []string               `json:"warnings"`
}

// DataAccessRecord tracks data access for compliance
type DataAccessRecord struct {
	AccessID      string    `json:"access_id"`
	DataType      string    `json:"data_type"`
	DataSource    string    `json:"data_source"`
	AccessTime    time.Time `json:"access_time"`
	AccessPurpose string    `json:"access_purpose"`
	DataFields    []string  `json:"data_fields"`
	AccessResult  string    `json:"access_result"`
}

// ComplianceTrackingInfo tracks compliance-related information
type ComplianceTrackingInfo struct {
	ComplianceFramework   string        `json:"compliance_framework"`
	RequiredRetention     time.Duration `json:"required_retention"`
	DataClassification    string        `json:"data_classification"`
	AccessControls        []string      `json:"access_controls"`
	AuditRequirements     []string      `json:"audit_requirements"`
	PrivacyConsiderations []string      `json:"privacy_considerations"`
}
