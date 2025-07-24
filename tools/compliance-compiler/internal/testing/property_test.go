// Package testing provides property-based testing for the compliance compiler.
// Property-based testing generates random inputs to test invariants and edge cases
// that might not be covered by traditional unit tests.
package testing

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// PropertyTestConfig contains configuration for property-based tests
type PropertyTestConfig struct {
	Iterations       int           // Number of test iterations
	MaxSize          int           // Maximum size for generated data
	RandomSeed       int64         // Random seed for reproducibility
	ShrinkIterations int           // Number of shrinking attempts
	Timeout          time.Duration // Maximum test duration
	VerboseOutput    bool          // Enable verbose logging
}

// DefaultPropertyTestConfig returns default configuration for property tests
func DefaultPropertyTestConfig() PropertyTestConfig {
	return PropertyTestConfig{
		Iterations:       100,
		MaxSize:          100,
		RandomSeed:       time.Now().UnixNano(),
		ShrinkIterations: 50,
		Timeout:          30 * time.Second,
		VerboseOutput:    false,
	}
}

// PropertyTest represents a property-based test
type PropertyTest struct {
	Name       string
	Property   PropertyFunc
	Generators []Generator
	Config     PropertyTestConfig
	Statistics TestStatistics
}

// PropertyFunc is a function that tests a property
type PropertyFunc func(args ...interface{}) bool

// Generator generates random test data
type Generator interface {
	Generate(rand *rand.Rand, size int) interface{}
	Shrink(value interface{}) []interface{}
	String() string
}

// TestStatistics tracks test execution statistics
type TestStatistics struct {
	TotalTests     int
	PassedTests    int
	FailedTests    int
	ShrinkAttempts int
	ExecutionTime  time.Duration
	FailureInputs  [][]interface{}
}

// PolicyGenerator generates random compliance policies
type PolicyGenerator struct {
	AssetClasses  []string
	Jurisdictions []string
	MinRules      int
	MaxRules      int
}

// NewPolicyGenerator creates a new policy generator
func NewPolicyGenerator() *PolicyGenerator {
	return &PolicyGenerator{
		AssetClasses:  []string{"CreditCard", "InstallmentLoan", "MerchantCashAdvance", "EquipmentLease", "WorkingCapital"},
		Jurisdictions: []string{"USA", "USA-NY", "USA-CA", "EU", "UK"},
		MinRules:      1,
		MaxRules:      10,
	}
}

// Generate creates a random policy
func (g *PolicyGenerator) Generate(rng *rand.Rand, size int) interface{} {
	// Determine number of rules based on size
	numRules := g.MinRules + rng.Intn(min(g.MaxRules-g.MinRules+1, size))

	policy := ParsedPolicy{
		Template: PolicyTemplate{
			Name:                fmt.Sprintf("Generated Policy %d", rng.Int31()),
			Version:             fmt.Sprintf("%d.%d.%d", rng.Intn(10), rng.Intn(10), rng.Intn(10)),
			Jurisdiction:        g.Jurisdictions[rng.Intn(len(g.Jurisdictions))],
			AssetClass:          g.AssetClasses[rng.Intn(len(g.AssetClasses))],
			Description:         "Automatically generated policy for property testing",
			Author:              "Property Test Generator",
			RegulatoryFramework: g.generateRegulatoryFramework(rng),
			LastUpdated:         time.Now().Format("2006-01-02"),
		},
		Parameters: g.generateParameters(rng, size),
		Policy: PolicyRules{
			Metadata: PolicyMetadata{
				Version:     "1.0.0",
				Name:        fmt.Sprintf("generated-policy-%d", rng.Int31()),
				Description: "Generated for property testing",
				Tags:        g.generateTags(rng),
			},
			Rules:        g.generateRules(rng, numRules),
			Attestations: g.generateAttestations(rng, min(3, size/10+1)),
			Config:       g.generateConfig(rng),
		},
	}

	return policy
}

// Shrink reduces the size of a policy to find minimal failing cases
func (g *PolicyGenerator) Shrink(value interface{}) []interface{} {
	policy, ok := value.(ParsedPolicy)
	if !ok {
		return []interface{}{}
	}

	var shrunk []interface{}

	// Remove rules one by one
	if len(policy.Policy.Rules) > 1 {
		for i := range policy.Policy.Rules {
			smaller := policy
			smaller.Policy.Rules = append(policy.Policy.Rules[:i], policy.Policy.Rules[i+1:]...)
			shrunk = append(shrunk, smaller)
		}
	}

	// Remove parameters
	if len(policy.Parameters) > 0 {
		for name := range policy.Parameters {
			smaller := policy
			smaller.Parameters = make(PolicyParams)
			for k, v := range policy.Parameters {
				if k != name {
					smaller.Parameters[k] = v
				}
			}
			shrunk = append(shrunk, smaller)
		}
	}

	// Simplify rule conditions
	for i, rule := range policy.Policy.Rules {
		if len(rule.Conditions) > 1 {
			for j := range rule.Conditions {
				smaller := policy
				smaller.Policy.Rules = make([]PolicyRule, len(policy.Policy.Rules))
				copy(smaller.Policy.Rules, policy.Policy.Rules)
				smaller.Policy.Rules[i].Conditions = append(rule.Conditions[:j], rule.Conditions[j+1:]...)
				shrunk = append(shrunk, smaller)
			}
		}
	}

	return shrunk
}

func (g *PolicyGenerator) String() string {
	return "PolicyGenerator"
}

// TransactionGenerator generates random transaction data
type TransactionGenerator struct {
	AssetClasses []string
	MinAmount    float64
	MaxAmount    float64
}

// NewTransactionGenerator creates a new transaction generator
func NewTransactionGenerator() *TransactionGenerator {
	return &TransactionGenerator{
		AssetClasses: []string{"CreditCard", "InstallmentLoan", "MerchantCashAdvance", "EquipmentLease", "WorkingCapital"},
		MinAmount:    1000,
		MaxAmount:    1000000,
	}
}

// Generate creates a random transaction
func (g *TransactionGenerator) Generate(rng *rand.Rand, size int) interface{} {
	assetClass := g.AssetClasses[rng.Intn(len(g.AssetClasses))]

	transaction := TransactionData{
		ID:           fmt.Sprintf("prop_test_%d", rng.Int63()),
		AssetClass:   assetClass,
		Jurisdiction: []string{"USA", "USA-NY", "USA-CA", "EU", "UK"}[rng.Intn(5)],
		Amount:       g.MinAmount + rng.Float64()*(g.MaxAmount-g.MinAmount),
		Currency:     "USD",
		Timestamp:    time.Now().Add(-time.Duration(rng.Intn(365)) * 24 * time.Hour),
		CustomFields: make(map[string]interface{}),
	}

	// Generate applicant data
	transaction.Applicant = ApplicantData{
		Age:                    21 + rng.Intn(60),
		AnnualIncome:           20000 + rng.Float64()*300000,
		EmploymentStatus:       []string{"full_time", "part_time", "self_employed", "unemployed"}[rng.Intn(4)],
		EmploymentLengthMonths: rng.Intn(240),
		CreditScore:            300 + rng.Intn(550),
		DebtToIncomeRatio:      rng.Float64() * 0.8,
		ExistingCreditAccounts: rng.Intn(20),
		PaymentHistory:         []string{"excellent", "good", "fair", "poor", "no_history"}[rng.Intn(5)],
		BankruptcyHistory:      rng.Float32() < 0.1,  // 10% chance
		MilitaryStatus:         rng.Float32() < 0.15, // 15% chance
	}

	// Generate application data
	transaction.ApplicationData = ApplicationData{
		RequestedAmount:          transaction.Amount,
		IntendedUse:              []string{"general", "consolidation", "improvement", "business"}[rng.Intn(4)],
		ApplicationMethod:        []string{"online", "branch", "phone", "mobile"}[rng.Intn(4)],
		IncomeVerificationMethod: []string{"paystubs", "tax_returns", "bank_statements"}[rng.Intn(3)],
		IdentityVerified:         rng.Float32() < 0.95, // 95% verification rate
	}

	// Generate risk metrics
	transaction.RiskMetrics = RiskMetrics{
		RiskScore:            200 + rng.Float64()*700,
		RiskTier:             []string{"super_prime", "prime", "near_prime", "subprime"}[rng.Intn(4)],
		ProbabilityOfDefault: rng.Float64() * 0.5,
		LossGivenDefault:     0.3 + rng.Float64()*0.5,
		ExposureAtDefault:    0.7 + rng.Float64()*0.3,
		RiskAdjustedReturn:   rng.Float64() * 0.3,
	}

	// Generate compliance checks
	transaction.ComplianceChecks = ComplianceChecks{
		KYCPassed:            rng.Float32() < 0.98,
		AMLCleared:           rng.Float32() < 0.97,
		CreditCheckCompleted: rng.Float32() < 0.99,
		IncomeVerified:       rng.Float32() < 0.92,
		IdentityVerified:     rng.Float32() < 0.96,
		ComplianceScore:      0.5 + rng.Float64()*0.5,
	}

	return transaction
}

// Shrink reduces transaction complexity to find minimal failing cases
func (g *TransactionGenerator) Shrink(value interface{}) []interface{} {
	transaction, ok := value.(TransactionData)
	if !ok {
		return []interface{}{}
	}

	var shrunk []interface{}

	// Reduce amount
	if transaction.Amount > g.MinAmount {
		smaller := transaction
		smaller.Amount = (transaction.Amount + g.MinAmount) / 2
		shrunk = append(shrunk, smaller)
	}

	// Reduce credit score
	if transaction.Applicant.CreditScore > 300 {
		smaller := transaction
		smaller.Applicant.CreditScore = (transaction.Applicant.CreditScore + 300) / 2
		shrunk = append(shrunk, smaller)
	}

	// Increase DTI ratio (make worse)
	if transaction.Applicant.DebtToIncomeRatio < 0.8 {
		smaller := transaction
		smaller.Applicant.DebtToIncomeRatio = min(0.8, transaction.Applicant.DebtToIncomeRatio*1.2)
		shrunk = append(shrunk, smaller)
	}

	return shrunk
}

func (g *TransactionGenerator) String() string {
	return "TransactionGenerator"
}

// Helper methods for policy generation

func (g *PolicyGenerator) generateRegulatoryFramework(rng *rand.Rand) []string {
	frameworks := []string{
		"CFPB", "CARD Act", "TILA", "FCRA", "FDCPA", "NACHA Rules",
		"UCC Article 9", "State Regulations", "EU PSD2", "GDPR",
		"Banking Regulations", "SBA Regulations",
	}

	count := 1 + rng.Intn(3) // 1-3 frameworks
	selected := make([]string, count)

	for i := 0; i < count; i++ {
		selected[i] = frameworks[rng.Intn(len(frameworks))]
	}

	return selected
}

func (g *PolicyGenerator) generateParameters(rng *rand.Rand, size int) PolicyParams {
	params := make(PolicyParams)
	numParams := 1 + rng.Intn(min(10, size))

	paramTypes := []string{"float", "int", "string", "boolean"}

	for i := 0; i < numParams; i++ {
		paramName := fmt.Sprintf("param_%d", i)
		paramType := paramTypes[rng.Intn(len(paramTypes))]

		param := PolicyParam{
			Type:        paramType,
			Description: fmt.Sprintf("Generated parameter %d", i),
		}

		switch paramType {
		case "float":
			param.Default = rng.Float64() * 1000
			param.Min = 0.0
			param.Max = 2000.0
		case "int":
			param.Default = rng.Intn(100)
			param.Min = 0
			param.Max = 200
		case "string":
			param.Default = fmt.Sprintf("value_%d", rng.Intn(100))
		case "boolean":
			param.Default = rng.Float32() < 0.5
		}

		params[paramName] = param
	}

	return params
}

func (g *PolicyGenerator) generateTags(rng *rand.Rand) []string {
	allTags := []string{
		"credit", "loan", "finance", "compliance", "regulatory",
		"risk", "validation", "assessment", "verification", "scoring",
	}

	count := 1 + rng.Intn(4) // 1-4 tags
	tags := make([]string, count)

	for i := 0; i < count; i++ {
		tags[i] = allTags[rng.Intn(len(allTags))]
	}

	return tags
}

func (g *PolicyGenerator) generateRules(rng *rand.Rand, numRules int) []PolicyRule {
	rules := make([]PolicyRule, numRules)

	ruleTypes := []string{"validation", "regulatory", "risk", "compliance"}
	priorities := []string{"critical", "high", "medium", "low"}

	for i := 0; i < numRules; i++ {
		rule := PolicyRule{
			ID:          fmt.Sprintf("rule_%d", i),
			Name:        fmt.Sprintf("Generated Rule %d", i),
			Description: fmt.Sprintf("Auto-generated rule for property testing %d", i),
			Type:        ruleTypes[rng.Intn(len(ruleTypes))],
			Priority:    priorities[rng.Intn(len(priorities))],
			Enabled:     rng.Float32() < 0.9, // 90% enabled
			Conditions:  g.generateConditions(rng, 1+rng.Intn(4)),
			Actions:     g.generateActions(rng, 1+rng.Intn(3)),
		}

		rules[i] = rule
	}

	return rules
}

func (g *PolicyGenerator) generateConditions(rng *rand.Rand, numConditions int) []string {
	conditionTemplates := []string{
		"credit_score >= %d",
		"annual_income >= %d",
		"debt_to_income_ratio <= %.2f",
		"age >= %d",
		"employment_length_months >= %d",
		"kyc_passed == true",
		"aml_cleared == true",
		"identity_verified == true",
		"amount <= %d",
		"risk_score >= %d",
	}

	conditions := make([]string, numConditions)

	for i := 0; i < numConditions; i++ {
		template := conditionTemplates[rng.Intn(len(conditionTemplates))]

		var condition string
		switch {
		case strings.Contains(template, "credit_score"):
			condition = fmt.Sprintf(template, 300+rng.Intn(550))
		case strings.Contains(template, "annual_income"):
			condition = fmt.Sprintf(template, 20000+rng.Intn(100000))
		case strings.Contains(template, "debt_to_income_ratio"):
			condition = fmt.Sprintf(template, 0.1+rng.Float64()*0.5)
		case strings.Contains(template, "age"):
			condition = fmt.Sprintf(template, 18+rng.Intn(50))
		case strings.Contains(template, "employment_length_months"):
			condition = fmt.Sprintf(template, rng.Intn(120))
		case strings.Contains(template, "amount"):
			condition = fmt.Sprintf(template, 1000+rng.Intn(500000))
		case strings.Contains(template, "risk_score"):
			condition = fmt.Sprintf(template, 200+rng.Intn(600))
		default:
			condition = template
		}

		conditions[i] = condition
	}

	return conditions
}

func (g *PolicyGenerator) generateActions(rng *rand.Rand, numActions int) []string {
	actionTemplates := []string{
		"validate_credit_score",
		"verify_income",
		"check_employment",
		"assess_risk",
		"validate_identity",
		"check_compliance",
		"generate_report",
		"log_decision",
		"notify_applicant",
		"update_status",
	}

	actions := make([]string, numActions)

	for i := 0; i < numActions; i++ {
		actions[i] = actionTemplates[rng.Intn(len(actionTemplates))]
	}

	return actions
}

func (g *PolicyGenerator) generateAttestations(rng *rand.Rand, numAttestations int) []Attestation {
	attestations := make([]Attestation, numAttestations)

	attestationTypes := []string{"legal", "regulatory", "compliance", "risk"}

	for i := 0; i < numAttestations; i++ {
		attestation := Attestation{
			ID:          fmt.Sprintf("attestation_%d", i),
			Name:        fmt.Sprintf("Generated Attestation %d", i),
			Description: fmt.Sprintf("Auto-generated attestation %d", i),
			Type:        attestationTypes[rng.Intn(len(attestationTypes))],
			Required:    rng.Float32() < 0.8, // 80% required
			Fields:      g.generateAttestationFields(rng, 2+rng.Intn(4)),
		}

		attestations[i] = attestation
	}

	return attestations
}

func (g *PolicyGenerator) generateAttestationFields(rng *rand.Rand, numFields int) []string {
	fieldTemplates := []string{
		"officer_signature",
		"validation_date",
		"compliance_check",
		"risk_assessment",
		"regulatory_review",
		"documentation_complete",
		"verification_method",
		"approval_status",
	}

	fields := make([]string, numFields)

	for i := 0; i < numFields; i++ {
		fields[i] = fieldTemplates[rng.Intn(len(fieldTemplates))]
	}

	return fields
}

func (g *PolicyGenerator) generateConfig(rng *rand.Rand) PolicyConfig {
	return PolicyConfig{
		Validation: PolicyValidationConfig{
			StrictMode:     rng.Float32() < 0.7, // 70% strict mode
			FailOnWarnings: rng.Float32() < 0.3, // 30% fail on warnings
		},
		Execution: PolicyExecutionConfig{
			Timeout:    fmt.Sprintf("%ds", 30+rng.Intn(120)),
			MaxRetries: 1 + rng.Intn(5),
		},
		Logging: PolicyLoggingConfig{
			Level:         []string{"debug", "info", "warn", "error"}[rng.Intn(4)],
			AuditEnabled:  rng.Float32() < 0.8, // 80% audit enabled
			RetentionDays: 30 + rng.Intn(335),  // 30-365 days
		},
	}
}

// Property test functions

// RunPropertyTest executes a property-based test
func RunPropertyTest(t *testing.T, test PropertyTest) {
	config := test.Config
	if config.Iterations == 0 {
		config = DefaultPropertyTestConfig()
	}

	rng := rand.New(rand.NewSource(config.RandomSeed))
	stats := TestStatistics{}

	startTime := time.Now()
	timeout := time.After(config.Timeout)

	for i := 0; i < config.Iterations; i++ {
		select {
		case <-timeout:
			t.Logf("Property test timed out after %v", config.Timeout)
			break
		default:
		}

		// Generate test data
		args := make([]interface{}, len(test.Generators))
		for j, gen := range test.Generators {
			args[j] = gen.Generate(rng, min(config.MaxSize, i+1))
		}

		// Run the property test
		stats.TotalTests++

		if config.VerboseOutput {
			t.Logf("Property test iteration %d with args: %v", i+1, args)
		}

		if test.Property(args...) {
			stats.PassedTests++
		} else {
			stats.FailedTests++
			stats.FailureInputs = append(stats.FailureInputs, args)

			// Try to shrink the failing input
			shrunkArgs := shrinkFailingInput(test.Generators, args, test.Property, config.ShrinkIterations)
			if shrunkArgs != nil {
				t.Errorf("Property %s failed with minimal input: %v", test.Name, shrunkArgs)
				stats.ShrinkAttempts++
			} else {
				t.Errorf("Property %s failed with input: %v", test.Name, args)
			}

			// Fail fast for critical issues
			if strings.Contains(test.Name, "Critical") {
				break
			}
		}
	}

	stats.ExecutionTime = time.Since(startTime)
	test.Statistics = stats

	// Report statistics
	t.Logf("Property test %s completed:", test.Name)
	t.Logf("  Total tests: %d", stats.TotalTests)
	t.Logf("  Passed: %d", stats.PassedTests)
	t.Logf("  Failed: %d", stats.FailedTests)
	t.Logf("  Execution time: %v", stats.ExecutionTime)
	t.Logf("  Shrink attempts: %d", stats.ShrinkAttempts)

	if stats.FailedTests > 0 {
		t.Errorf("Property test %s failed %d out of %d tests", test.Name, stats.FailedTests, stats.TotalTests)
	}
}

// shrinkFailingInput attempts to find a minimal failing input
func shrinkFailingInput(generators []Generator, failingArgs []interface{}, property PropertyFunc, maxAttempts int) []interface{} {
	current := failingArgs

	for attempt := 0; attempt < maxAttempts; attempt++ {
		improved := false

		for i, gen := range generators {
			shrunkValues := gen.Shrink(current[i])

			for _, shrunkValue := range shrunkValues {
				testArgs := make([]interface{}, len(current))
				copy(testArgs, current)
				testArgs[i] = shrunkValue

				// If this smaller input still fails, use it
				if !property(testArgs...) {
					current = testArgs
					improved = true
					break
				}
			}

			if improved {
				break
			}
		}

		if !improved {
			break
		}
	}

	return current
}

// Utility functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Common property test cases

// TestPolicyParsingRoundTrip tests that parsing and serializing policies is consistent
func TestPolicyParsingRoundTrip(t *testing.T) {
	test := PropertyTest{
		Name: "Policy Parsing Round Trip",
		Property: func(args ...interface{}) bool {
			policy := args[0].(ParsedPolicy)

			// Serialize to YAML
			yamlData, err := yaml.Marshal(policy)
			if err != nil {
				return false
			}

			// Parse back from YAML
			var parsed ParsedPolicy
			err = yaml.Unmarshal(yamlData, &parsed)
			if err != nil {
				return false
			}

			// Compare structures (basic comparison)
			return policy.Template.Name == parsed.Template.Name &&
				policy.Template.Version == parsed.Template.Version &&
				len(policy.Policy.Rules) == len(parsed.Policy.Rules)
		},
		Generators: []Generator{NewPolicyGenerator()},
		Config:     DefaultPropertyTestConfig(),
	}

	RunPropertyTest(t, test)
}

// TestPolicyCompilationDeterminism tests that compilation is deterministic
func TestPolicyCompilationDeterminism(t *testing.T) {
	test := PropertyTest{
		Name: "Policy Compilation Determinism",
		Property: func(args ...interface{}) bool {
			policy := args[0].(ParsedPolicy)

			// Serialize to YAML
			yamlData, err := yaml.Marshal(policy)
			if err != nil {
				return false
			}

			// Compile twice
			compiled1 := AssertPolicyCompiles(t, string(yamlData))
			compiled2 := AssertPolicyCompiles(t, string(yamlData))

			// Should produce identical results
			return compiled1.Name == compiled2.Name &&
				compiled1.Version == compiled2.Version &&
				len(compiled1.Rules) == len(compiled2.Rules)
		},
		Generators: []Generator{NewPolicyGenerator()},
		Config:     DefaultPropertyTestConfig(),
	}

	RunPropertyTest(t, test)
}

// TestPolicyEvaluationConsistency tests that policy evaluation is consistent
func TestPolicyEvaluationConsistency(t *testing.T) {
	test := PropertyTest{
		Name: "Policy Evaluation Consistency",
		Property: func(args ...interface{}) bool {
			policy := args[0].(ParsedPolicy)
			transaction := args[1].(TransactionData)

			// Create compiled policy
			yamlData, err := yaml.Marshal(policy)
			if err != nil {
				return false
			}

			compiled := AssertPolicyCompiles(t, string(yamlData))
			if compiled == nil {
				return false
			}

			// Evaluate twice
			result1 := evaluatePolicy(compiled, &transaction)
			result2 := evaluatePolicy(compiled, &transaction)

			// Should produce identical results
			return result1.Passed == result2.Passed &&
				result1.Score == result2.Score &&
				len(result1.RuleResults) == len(result2.RuleResults)
		},
		Generators: []Generator{NewPolicyGenerator(), NewTransactionGenerator()},
		Config:     DefaultPropertyTestConfig(),
	}

	RunPropertyTest(t, test)
}

// TestTransactionValidation tests transaction validation properties
func TestTransactionValidation(t *testing.T) {
	test := PropertyTest{
		Name: "Transaction Validation Properties",
		Property: func(args ...interface{}) bool {
			transaction := args[0].(TransactionData)

			// Basic validation properties
			validAmount := transaction.Amount > 0
			validAge := transaction.Applicant.Age >= 18 && transaction.Applicant.Age <= 120
			validDTI := transaction.Applicant.DebtToIncomeRatio >= 0 && transaction.Applicant.DebtToIncomeRatio <= 1.0
			validCreditScore := transaction.Applicant.CreditScore >= 300 && transaction.Applicant.CreditScore <= 850

			return validAmount && validAge && validDTI && validCreditScore
		},
		Generators: []Generator{NewTransactionGenerator()},
		Config:     DefaultPropertyTestConfig(),
	}

	RunPropertyTest(t, test)
}

// PropertyTestSuite runs all property-based tests
func RunPropertyTestSuite(t *testing.T) {
	t.Run("PolicyParsingRoundTrip", TestPolicyParsingRoundTrip)
	t.Run("PolicyCompilationDeterminism", TestPolicyCompilationDeterminism)
	t.Run("PolicyEvaluationConsistency", TestPolicyEvaluationConsistency)
	t.Run("TransactionValidation", TestTransactionValidation)
}
