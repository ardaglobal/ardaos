package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
)

// OutputFormatter handles multiple output formats for compiled policies
type OutputFormatter struct {
	includeMetadata    bool
	prettyPrint        bool
	compressionEnabled bool
	checksumValidation bool
}

// NewOutputFormatter creates a new output formatter
func NewOutputFormatter(options OutputFormatOptions) *OutputFormatter {
	return &OutputFormatter{
		includeMetadata:    options.IncludeMetadata,
		prettyPrint:        options.PrettyPrint,
		compressionEnabled: options.CompressionEnabled,
		checksumValidation: options.ChecksumValidation,
	}
}

// OutputFormatOptions configures output formatting
type OutputFormatOptions struct {
	IncludeMetadata    bool `json:"include_metadata"`
	PrettyPrint        bool `json:"pretty_print"`
	CompressionEnabled bool `json:"compression_enabled"`
	ChecksumValidation bool `json:"checksum_validation"`
}

// OutputBundle contains all output formats for a compiled policy
type OutputBundle struct {
	BinaryProtobuf    *BinaryOutput      `json:"binary_protobuf"`
	JSONProtobuf      *JSONOutput        `json:"json_protobuf"`
	HumanReadable     *HumanOutput       `json:"human_readable"`
	PolicyFingerprint *FingerprintOutput `json:"policy_fingerprint"`
	Metadata          *MetadataOutput    `json:"metadata"`
	AuditFormat       *AuditOutput       `json:"audit_format,omitempty"`
}

// BinaryOutput represents binary protobuf output
type BinaryOutput struct {
	Data        []byte           `json:"data"`
	Size        int              `json:"size"`
	Checksum    string           `json:"checksum"`
	Compression *CompressionInfo `json:"compression,omitempty"`
	Encoding    string           `json:"encoding"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// JSONOutput represents JSON protobuf output
type JSONOutput struct {
	Data        []byte           `json:"data"`
	Size        int              `json:"size"`
	Checksum    string           `json:"checksum"`
	Pretty      bool             `json:"pretty"`
	Encoding    string           `json:"encoding"`
	Schema      *SchemaReference `json:"schema,omitempty"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// HumanOutput represents human-readable output
type HumanOutput struct {
	Summary     string          `json:"summary"`
	Details     string          `json:"details"`
	Format      string          `json:"format"` // yaml, text, markdown
	Size        int             `json:"size"`
	Sections    []OutputSection `json:"sections"`
	GeneratedAt time.Time       `json:"generated_at"`
}

// FingerprintOutput represents policy fingerprint output
type FingerprintOutput struct {
	Fingerprint  string                 `json:"fingerprint"`
	Algorithm    string                 `json:"algorithm"`
	Version      string                 `json:"version"`
	Components   *FingerprintComponents `json:"components"`
	Dependencies []string               `json:"dependencies"`
	GeneratedAt  time.Time              `json:"generated_at"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
}

// MetadataOutput represents compilation metadata output
type MetadataOutput struct {
	CompilerInfo     *CompilerInfo     `json:"compiler_info"`
	SourceInfo       *SourceInfo       `json:"source_info"`
	OptimizationInfo *OptimizationInfo `json:"optimization_info"`
	ValidationInfo   *ValidationInfo   `json:"validation_info"`
	TimingInfo       *TimingInfo       `json:"timing_info"`
	GeneratedAt      time.Time         `json:"generated_at"`
}

// AuditOutput represents audit-specific output
type AuditOutput struct {
	AuditTrail       *CompilationAuditTrail `json:"audit_trail"`
	ComplianceInfo   *ComplianceInfo        `json:"compliance_info"`
	SecurityAnalysis *SecurityAnalysis      `json:"security_analysis"`
	Format           string                 `json:"format"`
	GeneratedAt      time.Time              `json:"generated_at"`
}

// CompressionInfo contains compression details
type CompressionInfo struct {
	Algorithm        string  `json:"algorithm"`
	OriginalSize     int     `json:"original_size"`
	CompressedSize   int     `json:"compressed_size"`
	CompressionRatio float64 `json:"compression_ratio"`
	SpaceSaved       int     `json:"space_saved"`
}

// SchemaReference contains schema information
type SchemaReference struct {
	Version   string `json:"version"`
	Namespace string `json:"namespace"`
	Location  string `json:"location"`
	Checksum  string `json:"checksum"`
}

// OutputSection represents a section in human-readable output
type OutputSection struct {
	Title       string                 `json:"title"`
	Content     string                 `json:"content"`
	Type        string                 `json:"type"` // summary, rules, attestations, enforcement
	Priority    int                    `json:"priority"`
	Subsections []OutputSection        `json:"subsections,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// FingerprintComponents contains detailed fingerprint components
type FingerprintComponents struct {
	PolicyStructure  string `json:"policy_structure"`
	RulesHash        string `json:"rules_hash"`
	AttestationsHash string `json:"attestations_hash"`
	EnforcementHash  string `json:"enforcement_hash"`
	MetadataHash     string `json:"metadata_hash"`
}

// CompilerInfo contains compiler information
type CompilerInfo struct {
	Version       string            `json:"version"`
	BuildDate     string            `json:"build_date"`
	GitCommit     string            `json:"git_commit"`
	Platform      string            `json:"platform"`
	Configuration map[string]string `json:"configuration"`
}

// SourceInfo contains source document information
type SourceInfo struct {
	FileName     string    `json:"file_name"`
	FileSize     int64     `json:"file_size"`
	FileHash     string    `json:"file_hash"`
	LastModified time.Time `json:"last_modified"`
	Author       string    `json:"author"`
	LineCount    int       `json:"line_count"`
}

// OptimizationInfo contains optimization details
type OptimizationInfo struct {
	Level             int                `json:"level"`
	TechniquesApplied []string           `json:"techniques_applied"`
	PerformanceGains  map[string]float64 `json:"performance_gains"`
	SizeReduction     int                `json:"size_reduction"`
	OptimizationTime  time.Duration      `json:"optimization_time"`
}

// ValidationInfo contains validation results
type ValidationInfo struct {
	IsValid         bool          `json:"is_valid"`
	ErrorCount      int           `json:"error_count"`
	WarningCount    int           `json:"warning_count"`
	ValidationTime  time.Duration `json:"validation_time"`
	ChecksPerformed []string      `json:"checks_performed"`
}

// TimingInfo contains timing details
type TimingInfo struct {
	TotalTime         time.Duration            `json:"total_time"`
	ParsingTime       time.Duration            `json:"parsing_time"`
	OptimizationTime  time.Duration            `json:"optimization_time"`
	ValidationTime    time.Duration            `json:"validation_time"`
	SerializationTime time.Duration            `json:"serialization_time"`
	PhaseBreakdown    map[string]time.Duration `json:"phase_breakdown"`
}

// ComplianceInfo contains compliance-related information
type ComplianceInfo struct {
	Framework         string             `json:"framework"`
	RequirementsMet   []string           `json:"requirements_met"`
	RemainingGaps     []string           `json:"remaining_gaps"`
	CertificationInfo *CertificationInfo `json:"certification_info,omitempty"`
}

// CertificationInfo contains certification details
type CertificationInfo struct {
	CertificationBody string    `json:"certification_body"`
	Standard          string    `json:"standard"`
	Level             string    `json:"level"`
	ValidFrom         time.Time `json:"valid_from"`
	ValidUntil        time.Time `json:"valid_until"`
	CertificateID     string    `json:"certificate_id"`
}

// SecurityAnalysis contains security analysis results
type SecurityAnalysis struct {
	ThreatModel        *ThreatModel             `json:"threat_model"`
	VulnerabilityScans []VulnerabilityResult    `json:"vulnerability_scans"`
	SecurityScore      int                      `json:"security_score"`
	Recommendations    []SecurityRecommendation `json:"recommendations"`
}

// ThreatModel represents the security threat model
type ThreatModel struct {
	Threats     []ThreatVector `json:"threats"`
	Mitigations []Mitigation   `json:"mitigations"`
	RiskLevel   string         `json:"risk_level"`
	LastUpdated time.Time      `json:"last_updated"`
}

// ThreatVector represents a specific threat
type ThreatVector struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Likelihood  string  `json:"likelihood"`
	Impact      string  `json:"impact"`
	RiskScore   float64 `json:"risk_score"`
}

// Mitigation represents a security mitigation
type Mitigation struct {
	ThreatID       string `json:"threat_id"`
	Description    string `json:"description"`
	Effectiveness  string `json:"effectiveness"`
	Implementation string `json:"implementation"`
}

// VulnerabilityResult represents a vulnerability scan result
type VulnerabilityResult struct {
	ScannerID string       `json:"scanner_id"`
	ScanTime  time.Time    `json:"scan_time"`
	Findings  []Finding    `json:"findings"`
	Summary   *ScanSummary `json:"summary"`
}

// Finding represents a security finding
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
}

// ScanSummary summarizes vulnerability scan results
type ScanSummary struct {
	TotalFindings     int            `json:"total_findings"`
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	RiskScore         float64        `json:"risk_score"`
}

// SecurityRecommendation represents a security recommendation
type SecurityRecommendation struct {
	ID          string `json:"id"`
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// GenerateOutputBundle creates all output formats for a compiled policy
func (of *OutputFormatter) GenerateOutputBundle(result *CompilationResult) (*OutputBundle, error) {
	bundle := &OutputBundle{}

	// Generate binary protobuf output
	binaryOutput, err := of.generateBinaryOutput(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate binary output: %w", err)
	}
	bundle.BinaryProtobuf = binaryOutput

	// Generate JSON protobuf output
	jsonOutput, err := of.generateJSONOutput(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JSON output: %w", err)
	}
	bundle.JSONProtobuf = jsonOutput

	// Generate human-readable output
	humanOutput, err := of.generateHumanOutput(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate human output: %w", err)
	}
	bundle.HumanReadable = humanOutput

	// Generate policy fingerprint
	fingerprintOutput, err := of.generateFingerprintOutput(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate fingerprint output: %w", err)
	}
	bundle.PolicyFingerprint = fingerprintOutput

	// Generate metadata output
	if of.includeMetadata {
		metadataOutput, err := of.generateMetadataOutput(result)
		if err != nil {
			return nil, fmt.Errorf("failed to generate metadata output: %w", err)
		}
		bundle.Metadata = metadataOutput
	}

	// Generate audit output if available
	if result.AuditTrail != nil {
		auditOutput, err := of.generateAuditOutput(result)
		if err != nil {
			return nil, fmt.Errorf("failed to generate audit output: %w", err)
		}
		bundle.AuditFormat = auditOutput
	}

	return bundle, nil
}

// generateBinaryOutput creates binary protobuf output
func (of *OutputFormatter) generateBinaryOutput(result *CompilationResult) (*BinaryOutput, error) {
	data := result.BinaryData

	// Apply compression if enabled
	var compression *CompressionInfo
	if of.compressionEnabled {
		// Compression would be applied here
		compression = &CompressionInfo{
			Algorithm:        "gzip",
			OriginalSize:     len(data),
			CompressedSize:   len(data), // Would be actual compressed size
			CompressionRatio: 1.0,
			SpaceSaved:       0,
		}
	}

	// Generate checksum if validation enabled
	checksum := ""
	if of.checksumValidation {
		hash := sha256.Sum256(data)
		checksum = hex.EncodeToString(hash[:])
	}

	return &BinaryOutput{
		Data:        data,
		Size:        len(data),
		Checksum:    checksum,
		Compression: compression,
		Encoding:    "protobuf",
		GeneratedAt: time.Now(),
	}, nil
}

// generateJSONOutput creates JSON protobuf output
func (of *OutputFormatter) generateJSONOutput(result *CompilationResult) (*JSONOutput, error) {
	var data []byte
	var err error

	if of.prettyPrint {
		// Pretty print JSON
		var jsonData interface{}
		if err := json.Unmarshal(result.JSONData, &jsonData); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
		data, err = json.MarshalIndent(jsonData, "", "  ")
	} else {
		data = result.JSONData
	}

	if err != nil {
		return nil, fmt.Errorf("failed to format JSON: %w", err)
	}

	// Generate checksum if validation enabled
	checksum := ""
	if of.checksumValidation {
		hash := sha256.Sum256(data)
		checksum = hex.EncodeToString(hash[:])
	}

	return &JSONOutput{
		Data:     data,
		Size:     len(data),
		Checksum: checksum,
		Pretty:   of.prettyPrint,
		Encoding: "json",
		Schema: &SchemaReference{
			Version:   "1.0.0",
			Namespace: "ardaos.compliance.v1",
			Location:  "https://schema.arda.org/compliance/v1/policy.proto",
		},
		GeneratedAt: time.Now(),
	}, nil
}

// generateHumanOutput creates human-readable output
func (of *OutputFormatter) generateHumanOutput(result *CompilationResult) (*HumanOutput, error) {
	policy := result.CompiledPolicy

	// Generate summary
	summary := fmt.Sprintf("Policy: %s (v%s)\nJurisdiction: %s\nAsset Class: %s\nRules: %d\nAttestations: %d",
		policy.PolicyId, policy.Version, policy.Jurisdiction, policy.AssetClass,
		len(policy.Rules), len(policy.Attestations))

	// Generate detailed sections
	sections := []OutputSection{
		{
			Title:    "Policy Overview",
			Content:  of.formatPolicyOverview(policy),
			Type:     "summary",
			Priority: 1,
		},
		{
			Title:    "Rules",
			Content:  of.formatRules(policy.Rules),
			Type:     "rules",
			Priority: 2,
		},
		{
			Title:    "Attestations",
			Content:  of.formatAttestations(policy.Attestations),
			Type:     "attestations",
			Priority: 3,
		},
		{
			Title:    "Enforcement",
			Content:  of.formatEnforcement(policy.Enforcement),
			Type:     "enforcement",
			Priority: 4,
		},
	}

	// Combine all content for details
	details := of.combineDetails(sections)

	return &HumanOutput{
		Summary:     summary,
		Details:     details,
		Format:      "text",
		Size:        len(details),
		Sections:    sections,
		GeneratedAt: time.Now(),
	}, nil
}

// generateFingerprintOutput creates policy fingerprint output
func (of *OutputFormatter) generateFingerprintOutput(result *CompilationResult) (*FingerprintOutput, error) {
	policy := result.CompiledPolicy

	// Generate component fingerprints
	components := &FingerprintComponents{
		PolicyStructure:  of.generateStructureHash(policy),
		RulesHash:        of.generateRulesHash(policy.Rules),
		AttestationsHash: of.generateAttestationsHash(policy.Attestations),
		EnforcementHash:  of.generateEnforcementHash(policy.Enforcement),
		MetadataHash:     of.generateMetadataHash(result.Metadata),
	}

	return &FingerprintOutput{
		Fingerprint:  result.PolicyFingerprint,
		Algorithm:    "SHA-256",
		Version:      "1.0",
		Components:   components,
		Dependencies: []string{}, // Would list template dependencies
		GeneratedAt:  time.Now(),
	}, nil
}

// generateMetadataOutput creates metadata output
func (of *OutputFormatter) generateMetadataOutput(result *CompilationResult) (*MetadataOutput, error) {
	return &MetadataOutput{
		CompilerInfo: &CompilerInfo{
			Version:   result.Metadata.CompilerVersion,
			BuildDate: time.Now().Format("2006-01-02"),
			Platform:  "go",
			Configuration: map[string]string{
				"optimization_level": fmt.Sprintf("%d", result.Metadata.OptimizationLevel),
			},
		},
		SourceInfo: &SourceInfo{
			FileHash:  result.Metadata.SourceHash,
			LineCount: 0, // Would be calculated from source
		},
		OptimizationInfo: &OptimizationInfo{
			Level:             result.Metadata.OptimizationLevel,
			TechniquesApplied: of.getAppliedTechniques(result.OptimizationStats),
			OptimizationTime:  result.OptimizationStats.OptimizationTime,
		},
		ValidationInfo: &ValidationInfo{
			IsValid:      result.ValidationReport.IsValid,
			ErrorCount:   len(result.ValidationReport.Errors),
			WarningCount: len(result.ValidationReport.Warnings),
		},
		TimingInfo: &TimingInfo{
			TotalTime:        result.Metadata.Performance.CompilationTime,
			OptimizationTime: result.Metadata.Performance.OptimizationTime,
		},
		GeneratedAt: time.Now(),
	}, nil
}

// generateAuditOutput creates audit-specific output
func (of *OutputFormatter) generateAuditOutput(result *CompilationResult) (*AuditOutput, error) {
	return &AuditOutput{
		AuditTrail: result.AuditTrail,
		ComplianceInfo: &ComplianceInfo{
			Framework:       "internal",
			RequirementsMet: []string{"data_retention", "access_control"},
			RemainingGaps:   []string{},
		},
		SecurityAnalysis: &SecurityAnalysis{
			SecurityScore:   85,
			Recommendations: []SecurityRecommendation{},
		},
		Format:      "json",
		GeneratedAt: time.Now(),
	}, nil
}

// Helper methods for formatting
func (of *OutputFormatter) formatPolicyOverview(policy *parser.CompliancePolicy) string {
	return fmt.Sprintf("Policy ID: %s\nVersion: %s\nJurisdiction: %s\nAsset Class: %s",
		policy.PolicyId, policy.Version, policy.Jurisdiction, policy.AssetClass)
}

func (of *OutputFormatter) formatRules(rules []*parser.PolicyRule) string {
	if len(rules) == 0 {
		return "No rules defined"
	}

	var result strings.Builder
	for i, rule := range rules {
		result.WriteString(fmt.Sprintf("%d. %s\n", i+1, rule.Name))
		if rule.Description != "" {
			result.WriteString(fmt.Sprintf("   Description: %s\n", rule.Description))
		}
		result.WriteString(fmt.Sprintf("   Required: %t\n", rule.Required))
	}
	return result.String()
}

func (of *OutputFormatter) formatAttestations(attestations []*parser.AttestationRequirement) string {
	if len(attestations) == 0 {
		return "No attestations required"
	}

	var result strings.Builder
	for i, attestation := range attestations {
		result.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, attestation.Name, attestation.Type))
		result.WriteString(fmt.Sprintf("   Required: %t\n", attestation.Required))
	}
	return result.String()
}

func (of *OutputFormatter) formatEnforcement(enforcement *parser.EnforcementConfig) string {
	if enforcement == nil {
		return "No enforcement configuration"
	}

	return fmt.Sprintf("Level: %s\nActions: %s",
		enforcement.Level, strings.Join(enforcement.Actions, ", "))
}

func (of *OutputFormatter) combineDetails(sections []OutputSection) string {
	var result strings.Builder
	for _, section := range sections {
		result.WriteString(fmt.Sprintf("## %s\n\n%s\n\n", section.Title, section.Content))
	}
	return result.String()
}

// Hash generation methods
func (of *OutputFormatter) generateStructureHash(policy *parser.CompliancePolicy) string {
	content := fmt.Sprintf("%s:%s:%s:%s", policy.PolicyId, policy.Version,
		policy.Jurisdiction, policy.AssetClass)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (of *OutputFormatter) generateRulesHash(rules []*parser.PolicyRule) string {
	var content strings.Builder
	for _, rule := range rules {
		content.WriteString(rule.Name)
	}
	hash := sha256.Sum256([]byte(content.String()))
	return hex.EncodeToString(hash[:])
}

func (of *OutputFormatter) generateAttestationsHash(attestations []*parser.AttestationRequirement) string {
	var content strings.Builder
	for _, attestation := range attestations {
		content.WriteString(attestation.Name + attestation.Type)
	}
	hash := sha256.Sum256([]byte(content.String()))
	return hex.EncodeToString(hash[:])
}

func (of *OutputFormatter) generateEnforcementHash(enforcement *parser.EnforcementConfig) string {
	if enforcement == nil {
		return ""
	}
	content := enforcement.Level + strings.Join(enforcement.Actions, ",")
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (of *OutputFormatter) generateMetadataHash(metadata *CompilationMetadata) string {
	content := metadata.CompilerVersion + metadata.SourceHash
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (of *OutputFormatter) getAppliedTechniques(stats *OptimizationStats) []string {
	techniques := []string{}
	for _, detail := range stats.OptimizationDetails {
		techniques = append(techniques, detail.Type)
	}
	return techniques
}
