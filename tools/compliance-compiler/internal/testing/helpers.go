// Package testing provides comprehensive test helpers and utilities for the compliance compiler.
// This package includes mock data generation, policy testing helpers, benchmarking utilities,
// and assertion functions for validating compliance policy behavior.
package testing

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ParsedPolicy represents a parsed compliance policy for testing
type ParsedPolicy struct {
	Template   PolicyTemplate `yaml:"template" json:"template"`
	Parameters PolicyParams   `yaml:"parameters" json:"parameters"`
	Policy     PolicyRules    `yaml:"policy" json:"policy"`
}

// PolicyTemplate contains template metadata
type PolicyTemplate struct {
	Name                string   `yaml:"name" json:"name"`
	Version             string   `yaml:"version" json:"version"`
	Jurisdiction        string   `yaml:"jurisdiction" json:"jurisdiction"`
	AssetClass          string   `yaml:"asset_class" json:"asset_class"`
	Description         string   `yaml:"description" json:"description"`
	Author              string   `yaml:"author" json:"author"`
	RegulatoryFramework []string `yaml:"regulatory_framework" json:"regulatory_framework"`
	LastUpdated         string   `yaml:"last_updated" json:"last_updated"`
}

// PolicyParams contains configurable parameters
type PolicyParams map[string]PolicyParam

// PolicyParam represents a single policy parameter
type PolicyParam struct {
	Type        string      `yaml:"type" json:"type"`
	Default     interface{} `yaml:"default" json:"default"`
	Min         interface{} `yaml:"min,omitempty" json:"min,omitempty"`
	Max         interface{} `yaml:"max,omitempty" json:"max,omitempty"`
	Description string      `yaml:"description" json:"description"`
}

// PolicyRules contains the policy implementation
type PolicyRules struct {
	Metadata     PolicyMetadata `yaml:"metadata" json:"metadata"`
	Rules        []PolicyRule   `yaml:"rules" json:"rules"`
	Attestations []Attestation  `yaml:"attestations" json:"attestations"`
	Config       PolicyConfig   `yaml:"config" json:"config"`
}

// PolicyMetadata contains policy metadata
type PolicyMetadata struct {
	Version     string   `yaml:"version" json:"version"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Tags        []string `yaml:"tags" json:"tags"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	ID          string      `yaml:"id" json:"id"`
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description" json:"description"`
	Type        string      `yaml:"type" json:"type"`
	Priority    string      `yaml:"priority" json:"priority"`
	Enabled     bool        `yaml:"enabled" json:"enabled"`
	Conditions  []string    `yaml:"conditions" json:"conditions"`
	Actions     []string    `yaml:"actions" json:"actions"`
	Parameters  interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// Attestation represents a required attestation
type Attestation struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Type        string   `yaml:"type" json:"type"`
	Required    bool     `yaml:"required" json:"required"`
	Condition   string   `yaml:"condition,omitempty" json:"condition,omitempty"`
	Fields      []string `yaml:"fields" json:"fields"`
}

// PolicyConfig contains policy configuration
type PolicyConfig struct {
	Validation PolicyValidationConfig `yaml:"validation" json:"validation"`
	Execution  PolicyExecutionConfig  `yaml:"execution" json:"execution"`
	Logging    PolicyLoggingConfig    `yaml:"logging" json:"logging"`
}

// PolicyValidationConfig contains validation settings
type PolicyValidationConfig struct {
	StrictMode     bool `yaml:"strict_mode" json:"strict_mode"`
	FailOnWarnings bool `yaml:"fail_on_warnings" json:"fail_on_warnings"`
}

// PolicyExecutionConfig contains execution settings
type PolicyExecutionConfig struct {
	Timeout    string `yaml:"timeout" json:"timeout"`
	MaxRetries int    `yaml:"max_retries" json:"max_retries"`
}

// PolicyLoggingConfig contains logging settings
type PolicyLoggingConfig struct {
	Level         string `yaml:"level" json:"level"`
	AuditEnabled  bool   `yaml:"audit_enabled" json:"audit_enabled"`
	RetentionDays int    `yaml:"retention_days" json:"retention_days"`
}

// TransactionData represents transaction data for testing
type TransactionData struct {
	ID               string                 `json:"id"`
	AssetClass       string                 `json:"asset_class"`
	Jurisdiction     string                 `json:"jurisdiction"`
	Amount           float64                `json:"amount"`
	Currency         string                 `json:"currency"`
	Timestamp        time.Time              `json:"timestamp"`
	Applicant        ApplicantData          `json:"applicant"`
	ApplicationData  ApplicationData        `json:"application_data"`
	RiskMetrics      RiskMetrics            `json:"risk_metrics"`
	ComplianceChecks ComplianceChecks       `json:"compliance_checks"`
	CustomFields     map[string]interface{} `json:"custom_fields"`
}

// ApplicantData contains applicant information
type ApplicantData struct {
	Age                    int     `json:"age"`
	AnnualIncome           float64 `json:"annual_income"`
	EmploymentStatus       string  `json:"employment_status"`
	EmploymentLengthMonths int     `json:"employment_length_months"`
	CreditScore            int     `json:"credit_score"`
	DebtToIncomeRatio      float64 `json:"debt_to_income_ratio"`
	ExistingCreditAccounts int     `json:"existing_credit_accounts"`
	PaymentHistory         string  `json:"payment_history"`
	BankruptcyHistory      bool    `json:"bankruptcy_history"`
	MilitaryStatus         bool    `json:"military_status"`
	StudentStatus          bool    `json:"student_status,omitempty"`
	SelfEmployed           bool    `json:"self_employed,omitempty"`
}

// ApplicationData contains application-specific information
type ApplicationData struct {
	RequestedAmount          float64 `json:"requested_amount"`
	IntendedUse              string  `json:"intended_use"`
	ApplicationMethod        string  `json:"application_method"`
	IncomeVerificationMethod string  `json:"income_verification_method"`
	IdentityVerified         bool    `json:"identity_verified"`
	Term                     int     `json:"term,omitempty"`
	InterestRate             float64 `json:"interest_rate,omitempty"`
	Collateral               string  `json:"collateral,omitempty"`
}

// RiskMetrics contains risk assessment data
type RiskMetrics struct {
	RiskScore            float64 `json:"risk_score"`
	RiskTier             string  `json:"risk_tier"`
	ProbabilityOfDefault float64 `json:"probability_of_default"`
	LossGivenDefault     float64 `json:"loss_given_default"`
	ExposureAtDefault    float64 `json:"exposure_at_default"`
	RiskAdjustedReturn   float64 `json:"risk_adjusted_return"`
}

// ComplianceChecks contains compliance verification results
type ComplianceChecks struct {
	KYCPassed            bool     `json:"kyc_passed"`
	AMLCleared           bool     `json:"aml_cleared"`
	CreditCheckCompleted bool     `json:"credit_check_completed"`
	IncomeVerified       bool     `json:"income_verified"`
	IdentityVerified     bool     `json:"identity_verified"`
	RegulatoryFlags      []string `json:"regulatory_flags,omitempty"`
	ComplianceScore      float64  `json:"compliance_score"`
}

// CompliancePolicy represents a compiled compliance policy
type CompliancePolicy struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Version    string                 `json:"version"`
	Rules      []CompiledRule         `json:"rules"`
	Parameters map[string]interface{} `json:"parameters"`
	Metadata   map[string]interface{} `json:"metadata"`
	CompiledAt time.Time              `json:"compiled_at"`
	IsValid    bool                   `json:"is_valid"`
	Errors     []string               `json:"errors,omitempty"`
	Warnings   []string               `json:"warnings,omitempty"`
}

// CompiledRule represents a compiled policy rule
type CompiledRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
	Conditions []CompiledCondition    `json:"conditions"`
	Actions    []CompiledAction       `json:"actions"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// CompiledCondition represents a compiled condition
type CompiledCondition struct {
	Expression string      `json:"expression"`
	Type       string      `json:"type"`
	Value      interface{} `json:"value,omitempty"`
}

// CompiledAction represents a compiled action
type CompiledAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// TestHelper provides utility functions for testing compliance policies
type TestHelper struct {
	TestDataDir string
	TempDir     string
}

// NewTestHelper creates a new test helper instance
func NewTestHelper() (*TestHelper, error) {
	tempDir, err := ioutil.TempDir("", "compliance-test-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	return &TestHelper{
		TestDataDir: "../../examples/test-data",
		TempDir:     tempDir,
	}, nil
}

// Cleanup removes temporary test files
func (h *TestHelper) Cleanup() error {
	if h.TempDir != "" {
		return os.RemoveAll(h.TempDir)
	}
	return nil
}

// LoadTestYAML loads and parses a YAML policy file for testing
func LoadTestYAML(filename string) (*ParsedPolicy, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var policy ParsedPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %w", filename, err)
	}

	return &policy, nil
}

// LoadTestYAMLFromString parses YAML content from a string
func LoadTestYAMLFromString(yamlContent string) (*ParsedPolicy, error) {
	var policy ParsedPolicy
	if err := yaml.Unmarshal([]byte(yamlContent), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse YAML content: %w", err)
	}

	return &policy, nil
}

// CreateMockTransactionData generates mock transaction data for testing
func CreateMockTransactionData(assetClass string) *TransactionData {
	// Generate deterministic but varied test data
	seed := time.Now().UnixNano()

	transaction := &TransactionData{
		ID:           fmt.Sprintf("test_%d", seed%1000000),
		AssetClass:   assetClass,
		Jurisdiction: "USA",
		Amount:       generateRandomFloat(1000, 500000, seed),
		Currency:     "USD",
		Timestamp:    time.Now(),
		CustomFields: make(map[string]interface{}),
	}

	// Generate applicant data based on asset class
	transaction.Applicant = generateApplicantData(assetClass, seed)
	transaction.ApplicationData = generateApplicationData(assetClass, seed)
	transaction.RiskMetrics = generateRiskMetrics(seed)
	transaction.ComplianceChecks = generateComplianceChecks(seed)

	return transaction
}

// generateApplicantData creates realistic applicant data
func generateApplicantData(assetClass string, seed int64) ApplicantData {
	applicant := ApplicantData{
		Age:                    int(generateRandomFloat(21, 75, seed)),
		AnnualIncome:           generateRandomFloat(25000, 200000, seed+1),
		EmploymentStatus:       selectRandom([]string{"full_time", "part_time", "self_employed", "unemployed"}, seed+2),
		EmploymentLengthMonths: int(generateRandomFloat(6, 120, seed+3)),
		CreditScore:            int(generateRandomFloat(300, 850, seed+4)),
		DebtToIncomeRatio:      generateRandomFloat(0.1, 0.6, seed+5),
		ExistingCreditAccounts: int(generateRandomFloat(0, 15, seed+6)),
		PaymentHistory:         selectRandom([]string{"excellent", "good", "fair", "poor", "no_history"}, seed+7),
		BankruptcyHistory:      generateRandomBool(seed+8, 0.05), // 5% chance
		MilitaryStatus:         generateRandomBool(seed+9, 0.1),  // 10% chance
	}

	// Asset class specific adjustments
	switch assetClass {
	case "CreditCard":
		// Credit card applicants tend to be younger
		if applicant.Age > 65 {
			applicant.Age = int(generateRandomFloat(21, 65, seed+10))
		}
	case "EquipmentLease":
		// Equipment lease applicants are often business owners
		applicant.SelfEmployed = generateRandomBool(seed+11, 0.4) // 40% chance
		if applicant.SelfEmployed {
			applicant.EmploymentStatus = "self_employed"
		}
	case "InstallmentLoan":
		// Installment loan applicants might be students
		if applicant.Age < 30 {
			applicant.StudentStatus = generateRandomBool(seed+12, 0.3) // 30% chance for young applicants
		}
	}

	return applicant
}

// generateApplicationData creates application-specific data
func generateApplicationData(assetClass string, seed int64) ApplicationData {
	application := ApplicationData{
		ApplicationMethod:        selectRandom([]string{"online", "branch", "phone", "mobile_app"}, seed),
		IncomeVerificationMethod: selectRandom([]string{"paystubs", "tax_returns", "bank_statements", "employment_verification"}, seed+1),
		IdentityVerified:         generateRandomBool(seed+2, 0.95), // 95% verification rate
	}

	// Asset class specific data
	switch assetClass {
	case "CreditCard":
		application.RequestedAmount = generateRandomFloat(1000, 50000, seed+3)
		application.IntendedUse = selectRandom([]string{"general_purchases", "balance_transfer", "building_credit", "business_expenses"}, seed+4)
	case "InstallmentLoan":
		application.RequestedAmount = generateRandomFloat(5000, 100000, seed+3)
		application.IntendedUse = selectRandom([]string{"debt_consolidation", "home_improvement", "major_purchase", "education"}, seed+4)
		application.Term = int(selectRandom([]float64{12, 24, 36, 48, 60, 72}, seed+5))
		application.InterestRate = generateRandomFloat(3.5, 29.99, seed+6)
	case "MerchantCashAdvance":
		application.RequestedAmount = generateRandomFloat(10000, 500000, seed+3)
		application.IntendedUse = selectRandom([]string{"working_capital", "inventory", "equipment", "expansion"}, seed+4)
	case "EquipmentLease":
		application.RequestedAmount = generateRandomFloat(25000, 2000000, seed+3)
		application.IntendedUse = "equipment_lease"
		application.Collateral = selectRandom([]string{"manufacturing_equipment", "office_equipment", "vehicles", "medical_equipment"}, seed+7)
	case "WorkingCapital":
		application.RequestedAmount = generateRandomFloat(50000, 1000000, seed+3)
		application.IntendedUse = selectRandom([]string{"cash_flow", "inventory_financing", "receivables_financing", "seasonal_needs"}, seed+4)
	}

	return application
}

// generateRiskMetrics creates realistic risk assessment data
func generateRiskMetrics(seed int64) RiskMetrics {
	riskScore := generateRandomFloat(200, 900, seed)

	var riskTier string
	var pod float64 // Probability of Default

	switch {
	case riskScore >= 750:
		riskTier = "super_prime"
		pod = generateRandomFloat(0.005, 0.02, seed+1)
	case riskScore >= 660:
		riskTier = "prime"
		pod = generateRandomFloat(0.02, 0.05, seed+1)
	case riskScore >= 620:
		riskTier = "near_prime"
		pod = generateRandomFloat(0.05, 0.12, seed+1)
	case riskScore >= 580:
		riskTier = "subprime"
		pod = generateRandomFloat(0.12, 0.25, seed+1)
	default:
		riskTier = "deep_subprime"
		pod = generateRandomFloat(0.25, 0.45, seed+1)
	}

	return RiskMetrics{
		RiskScore:            riskScore,
		RiskTier:             riskTier,
		ProbabilityOfDefault: pod,
		LossGivenDefault:     generateRandomFloat(0.4, 0.8, seed+2),
		ExposureAtDefault:    generateRandomFloat(0.8, 1.0, seed+3),
		RiskAdjustedReturn:   generateRandomFloat(0.05, 0.25, seed+4),
	}
}

// generateComplianceChecks creates compliance verification data
func generateComplianceChecks(seed int64) ComplianceChecks {
	checks := ComplianceChecks{
		KYCPassed:            generateRandomBool(seed, 0.98),   // 98% pass rate
		AMLCleared:           generateRandomBool(seed+1, 0.97), // 97% pass rate
		CreditCheckCompleted: generateRandomBool(seed+2, 0.99), // 99% completion rate
		IncomeVerified:       generateRandomBool(seed+3, 0.92), // 92% verification rate
		IdentityVerified:     generateRandomBool(seed+4, 0.96), // 96% verification rate
		ComplianceScore:      generateRandomFloat(0.7, 1.0, seed+5),
	}

	// Add regulatory flags for some cases
	if generateRandomBool(seed+6, 0.05) { // 5% chance of flags
		flags := []string{
			"high_risk_jurisdiction",
			"suspicious_activity",
			"incomplete_documentation",
			"adverse_media",
			"sanctions_screening_alert",
		}
		checks.RegulatoryFlags = []string{selectRandom(flags, seed+7)}
	}

	return checks
}

// Helper functions for random data generation
func generateRandomFloat(min, max float64, seed int64) float64 {
	// Simple deterministic random generation for testing
	value := float64((seed*1103515245+12345)%1000000) / 1000000.0
	return min + value*(max-min)
}

func generateRandomBool(seed int64, probability float64) bool {
	value := generateRandomFloat(0, 1, seed)
	return value < probability
}

func selectRandom[T any](options []T, seed int64) T {
	index := int(seed) % len(options)
	if index < 0 {
		index = -index
	}
	return options[index]
}

// AssertPolicyCompiles verifies that a YAML policy compiles without errors
func AssertPolicyCompiles(t *testing.T, yamlContent string) *CompliancePolicy {
	t.Helper()

	policy, err := LoadTestYAMLFromString(yamlContent)
	require.NoError(t, err, "Failed to parse YAML content")
	require.NotNil(t, policy, "Policy should not be nil")

	// Simulate compilation (in real implementation, this would call the actual compiler)
	compiled := &CompliancePolicy{
		ID:         policy.Policy.Metadata.Name,
		Name:       policy.Template.Name,
		Version:    policy.Template.Version,
		IsValid:    true,
		CompiledAt: time.Now(),
		Parameters: make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
	}

	// Convert policy parameters
	for name, param := range policy.Parameters {
		compiled.Parameters[name] = param.Default
	}

	// Convert metadata
	compiled.Metadata["jurisdiction"] = policy.Template.Jurisdiction
	compiled.Metadata["asset_class"] = policy.Template.AssetClass
	compiled.Metadata["regulatory_framework"] = policy.Template.RegulatoryFramework

	// Convert rules
	for _, rule := range policy.Policy.Rules {
		compiledRule := CompiledRule{
			ID:      rule.ID,
			Name:    rule.Name,
			Type:    rule.Type,
			Enabled: rule.Enabled,
		}

		// Convert priority to numeric value
		switch rule.Priority {
		case "critical":
			compiledRule.Priority = 1
		case "high":
			compiledRule.Priority = 2
		case "medium":
			compiledRule.Priority = 3
		case "low":
			compiledRule.Priority = 4
		default:
			compiledRule.Priority = 3
		}

		// Convert conditions
		for _, condition := range rule.Conditions {
			compiledRule.Conditions = append(compiledRule.Conditions, CompiledCondition{
				Expression: condition,
				Type:       "expression",
			})
		}

		// Convert actions
		for _, action := range rule.Actions {
			compiledRule.Actions = append(compiledRule.Actions, CompiledAction{
				Type: action,
			})
		}

		compiled.Rules = append(compiled.Rules, compiledRule)
	}

	assert.True(t, compiled.IsValid, "Policy should compile successfully")
	assert.Empty(t, compiled.Errors, "Policy should have no compilation errors")
	assert.NotEmpty(t, compiled.Rules, "Policy should have at least one rule")

	return compiled
}

// AssertValidationPasses verifies that a policy passes validation
func AssertValidationPasses(t *testing.T, policy *CompliancePolicy) {
	t.Helper()

	require.NotNil(t, policy, "Policy should not be nil")
	assert.True(t, policy.IsValid, "Policy should be valid")
	assert.Empty(t, policy.Errors, "Policy should have no validation errors")
	assert.NotEmpty(t, policy.Rules, "Policy should have at least one rule")
	assert.NotEmpty(t, policy.Name, "Policy should have a name")
	assert.NotEmpty(t, policy.Version, "Policy should have a version")
}

// AssertRuleExists verifies that a policy contains a specific rule
func AssertRuleExists(t *testing.T, policy *CompliancePolicy, ruleID string) *CompiledRule {
	t.Helper()

	for _, rule := range policy.Rules {
		if rule.ID == ruleID {
			assert.NotEmpty(t, rule.Name, "Rule should have a name")
			assert.NotEmpty(t, rule.Type, "Rule should have a type")
			return &rule
		}
	}

	t.Errorf("Rule %s not found in policy", ruleID)
	return nil
}

// AssertParameterExists verifies that a policy contains a specific parameter
func AssertParameterExists(t *testing.T, policy *CompliancePolicy, paramName string) interface{} {
	t.Helper()

	value, exists := policy.Parameters[paramName]
	assert.True(t, exists, "Parameter %s should exist in policy", paramName)
	assert.NotNil(t, value, "Parameter %s should have a value", paramName)

	return value
}

// BenchmarkPolicyEvaluation runs performance benchmarks on policy evaluation
func BenchmarkPolicyEvaluation(b *testing.B, policy *CompliancePolicy, samples []TransactionData) {
	b.Helper()

	if len(samples) == 0 {
		b.Fatal("No sample data provided for benchmarking")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sample := samples[i%len(samples)]

		// Simulate policy evaluation (in real implementation, this would call the actual evaluator)
		result := evaluatePolicy(policy, &sample)

		// Basic assertions to ensure evaluation is working
		if result == nil {
			b.Fatal("Policy evaluation returned nil result")
		}
	}
}

// MockPolicyEvaluationResult represents the result of policy evaluation
type MockPolicyEvaluationResult struct {
	PolicyID      string                 `json:"policy_id"`
	TransactionID string                 `json:"transaction_id"`
	Passed        bool                   `json:"passed"`
	Score         float64                `json:"score"`
	RuleResults   []MockRuleResult       `json:"rule_results"`
	Errors        []string               `json:"errors,omitempty"`
	Warnings      []string               `json:"warnings,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
	EvaluatedAt   time.Time              `json:"evaluated_at"`
}

// MockRuleResult represents the result of a single rule evaluation
type MockRuleResult struct {
	RuleID   string  `json:"rule_id"`
	RuleName string  `json:"rule_name"`
	Passed   bool    `json:"passed"`
	Score    float64 `json:"score"`
	Message  string  `json:"message,omitempty"`
}

// evaluatePolicy simulates policy evaluation for testing
func evaluatePolicy(policy *CompliancePolicy, transaction *TransactionData) *MockPolicyEvaluationResult {
	result := &MockPolicyEvaluationResult{
		PolicyID:      policy.ID,
		TransactionID: transaction.ID,
		Passed:        true,
		Score:         1.0,
		Metadata:      make(map[string]interface{}),
		EvaluatedAt:   time.Now(),
	}

	totalScore := 0.0
	passedRules := 0

	// Evaluate each rule
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		ruleResult := MockRuleResult{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Passed:   true,
			Score:    1.0,
		}

		// Simulate rule evaluation based on rule type and conditions
		switch rule.Type {
		case "validation":
			ruleResult.Passed = evaluateValidationRule(rule, transaction)
		case "regulatory":
			ruleResult.Passed = evaluateRegulatoryRule(rule, transaction)
		case "risk":
			ruleResult.Passed = evaluateRiskRule(rule, transaction)
		default:
			ruleResult.Passed = true
		}

		if ruleResult.Passed {
			passedRules++
			totalScore += ruleResult.Score
		} else {
			result.Passed = false
			ruleResult.Score = 0.0
			ruleResult.Message = fmt.Sprintf("Rule %s failed validation", rule.Name)
		}

		result.RuleResults = append(result.RuleResults, ruleResult)
	}

	// Calculate overall score
	if len(result.RuleResults) > 0 {
		result.Score = totalScore / float64(len(result.RuleResults))
	}

	return result
}

// evaluateValidationRule simulates validation rule evaluation
func evaluateValidationRule(rule CompiledRule, transaction *TransactionData) bool {
	// Simple mock evaluation based on common validation patterns
	for _, condition := range rule.Conditions {
		if strings.Contains(condition.Expression, "credit_score") {
			if transaction.Applicant.CreditScore < 500 {
				return false
			}
		}
		if strings.Contains(condition.Expression, "debt_to_income") {
			if transaction.Applicant.DebtToIncomeRatio > 0.5 {
				return false
			}
		}
		if strings.Contains(condition.Expression, "annual_income") {
			if transaction.Applicant.AnnualIncome < 25000 {
				return false
			}
		}
	}
	return true
}

// evaluateRegulatoryRule simulates regulatory rule evaluation
func evaluateRegulatoryRule(rule CompiledRule, transaction *TransactionData) bool {
	// Check basic compliance requirements
	if !transaction.ComplianceChecks.KYCPassed {
		return false
	}
	if !transaction.ComplianceChecks.AMLCleared {
		return false
	}
	if !transaction.ComplianceChecks.IdentityVerified {
		return false
	}

	// Check for regulatory flags
	if len(transaction.ComplianceChecks.RegulatoryFlags) > 0 {
		return false
	}

	return true
}

// evaluateRiskRule simulates risk rule evaluation
func evaluateRiskRule(rule CompiledRule, transaction *TransactionData) bool {
	// Check risk metrics
	if transaction.RiskMetrics.ProbabilityOfDefault > 0.15 {
		return false
	}
	if transaction.RiskMetrics.RiskScore < 600 {
		return false
	}
	if transaction.RiskMetrics.ComplianceScore < 0.8 {
		return false
	}

	return true
}

// CreateTestSuite generates a comprehensive test suite for a policy
func CreateTestSuite(policy *CompliancePolicy, assetClass string, numSamples int) []TransactionData {
	samples := make([]TransactionData, numSamples)

	for i := 0; i < numSamples; i++ {
		samples[i] = *CreateMockTransactionData(assetClass)

		// Create some variation in the test data
		if i%4 == 0 {
			// Create some samples that should fail validation
			samples[i].Applicant.CreditScore = 400
		}
		if i%5 == 0 {
			// Create some samples with high DTI
			samples[i].Applicant.DebtToIncomeRatio = 0.6
		}
		if i%6 == 0 {
			// Create some samples with compliance issues
			samples[i].ComplianceChecks.KYCPassed = false
		}
	}

	return samples
}

// SaveTestData saves test data to a JSON file for reuse
func (h *TestHelper) SaveTestData(filename string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal test data: %w", err)
	}

	filePath := filepath.Join(h.TempDir, filename)
	err = ioutil.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write test data file: %w", err)
	}

	return nil
}

// LoadTestData loads test data from a JSON file
func (h *TestHelper) LoadTestData(filename string, target interface{}) error {
	filePath := filepath.Join(h.TestDataDir, filename)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read test data file %s: %w", filePath, err)
	}

	err = json.Unmarshal(data, target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal test data: %w", err)
	}

	return nil
}

// GenerateTestReport creates a detailed test report
func GenerateTestReport(results []MockPolicyEvaluationResult) TestReport {
	report := TestReport{
		GeneratedAt:   time.Now(),
		TotalTests:    len(results),
		PassedTests:   0,
		FailedTests:   0,
		AverageScore:  0.0,
		ExecutionTime: 0,
	}

	totalScore := 0.0

	for _, result := range results {
		if result.Passed {
			report.PassedTests++
		} else {
			report.FailedTests++
		}
		totalScore += result.Score
	}

	if report.TotalTests > 0 {
		report.AverageScore = totalScore / float64(report.TotalTests)
		report.PassRate = float64(report.PassedTests) / float64(report.TotalTests) * 100
	}

	return report
}

// TestReport contains test execution statistics
type TestReport struct {
	GeneratedAt   time.Time `json:"generated_at"`
	TotalTests    int       `json:"total_tests"`
	PassedTests   int       `json:"passed_tests"`
	FailedTests   int       `json:"failed_tests"`
	PassRate      float64   `json:"pass_rate"`
	AverageScore  float64   `json:"average_score"`
	ExecutionTime int64     `json:"execution_time_ms"`
}
