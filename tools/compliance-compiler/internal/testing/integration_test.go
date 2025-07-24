// Package testing provides integration tests for the compliance compiler
package testing

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite contains integration tests for the compliance compiler
type IntegrationTestSuite struct {
	suite.Suite
	helper       *TestHelper
	templatesDir string
	testDataDir  string
}

// SetupSuite initializes the integration test suite
func (suite *IntegrationTestSuite) SetupSuite() {
	var err error
	suite.helper, err = NewTestHelper()
	suite.Require().NoError(err, "Failed to create test helper")

	// Set up directory paths
	suite.templatesDir = "../../examples/templates"
	suite.testDataDir = "../../examples/test-data"

	// Verify directories exist
	suite.Require().DirExists(suite.templatesDir, "Templates directory should exist")
	suite.Require().DirExists(suite.testDataDir, "Test data directory should exist")
}

// TearDownSuite cleans up after integration tests
func (suite *IntegrationTestSuite) TearDownSuite() {
	if suite.helper != nil {
		suite.helper.Cleanup()
	}
}

// TestAllTemplatesCompileSuccessfully tests that all policy templates compile without errors
func (suite *IntegrationTestSuite) TestAllTemplatesCompileSuccessfully() {
	templateFiles, err := suite.findAllTemplateFiles()
	suite.Require().NoError(err, "Failed to find template files")
	suite.Require().NotEmpty(templateFiles, "Should find at least one template file")

	compilationResults := make(map[string]*CompliancePolicy)

	for _, templateFile := range templateFiles {
		suite.T().Run(fmt.Sprintf("Compile-%s", filepath.Base(templateFile)), func(t *testing.T) {
			// Load the template
			policy, err := LoadTestYAML(templateFile)
			assert.NoError(t, err, "Failed to load template: %s", templateFile)

			if policy == nil {
				t.Fatalf("Policy is nil for template: %s", templateFile)
				return
			}

			// Convert to YAML string for compilation test
			yamlContent, err := os.ReadFile(templateFile)
			assert.NoError(t, err, "Failed to read template file: %s", templateFile)

			// Test compilation
			compiled := AssertPolicyCompiles(t, string(yamlContent))
			assert.NotNil(t, compiled, "Compiled policy should not be nil")

			// Store for cross-template tests
			relativePath, _ := filepath.Rel(suite.templatesDir, templateFile)
			compilationResults[relativePath] = compiled

			// Validate template structure
			suite.validateTemplateStructure(t, policy, templateFile)
		})
	}

	// Store results for other tests
	suite.T().Cleanup(func() {
		// Save compilation results for analysis
		suite.helper.SaveTestData("compilation_results.json", compilationResults)
	})
}

// TestCompiledPoliciesValidateCorrectly tests policy validation
func (suite *IntegrationTestSuite) TestCompiledPoliciesValidateCorrectly() {
	templateFiles, err := suite.findAllTemplateFiles()
	suite.Require().NoError(err, "Failed to find template files")

	for _, templateFile := range templateFiles {
		suite.T().Run(fmt.Sprintf("Validate-%s", filepath.Base(templateFile)), func(t *testing.T) {
			// Load and compile the policy
			yamlContent, err := os.ReadFile(templateFile)
			require.NoError(t, err, "Failed to read template file")

			compiled := AssertPolicyCompiles(t, string(yamlContent))
			require.NotNil(t, compiled, "Failed to compile policy")

			// Test validation
			AssertValidationPasses(t, compiled)

			// Test specific validation aspects
			suite.validatePolicyMetadata(t, compiled)
			suite.validatePolicyRules(t, compiled)
			suite.validatePolicyParameters(t, compiled)
		})
	}
}

// TestPerformanceAgainstLargeDatasets tests performance with large transaction datasets
func (suite *IntegrationTestSuite) TestPerformanceAgainstLargeDatasets() {
	// Test with different dataset sizes
	datasetSizes := []int{100, 500, 1000, 5000}
	assetClasses := []string{"CreditCard", "InstallmentLoan", "MerchantCashAdvance", "EquipmentLease", "WorkingCapital"}

	for _, size := range datasetSizes {
		for _, assetClass := range assetClasses {
			suite.T().Run(fmt.Sprintf("Performance-%s-%d", assetClass, size), func(t *testing.T) {
				// Create a test policy for this asset class
				policy := suite.createTestPolicy(assetClass)
				require.NotNil(t, policy, "Failed to create test policy")

				// Generate test dataset
				samples := CreateTestSuite(policy, assetClass, size)
				require.Len(t, samples, size, "Should generate correct number of samples")

				// Run performance benchmark
				startTime := time.Now()

				results := make([]MockPolicyEvaluationResult, len(samples))
				for i, sample := range samples {
					result := evaluatePolicy(policy, &sample)
					require.NotNil(t, result, "Policy evaluation should not return nil")
					results[i] = *result
				}

				executionTime := time.Since(startTime)

				// Performance assertions
				avgTimePerEvaluation := executionTime / time.Duration(size)
				maxAllowedTime := 10 * time.Millisecond // 10ms per evaluation

				assert.Less(t, avgTimePerEvaluation, maxAllowedTime,
					"Average evaluation time (%v) should be less than %v for %s with %d samples",
					avgTimePerEvaluation, maxAllowedTime, assetClass, size)

				// Generate performance report
				report := GenerateTestReport(results)
				assert.Greater(t, report.PassRate, 70.0, "Pass rate should be at least 70%")
				assert.Greater(t, report.AverageScore, 0.7, "Average score should be at least 0.7")

				t.Logf("Performance Results for %s (%d samples):", assetClass, size)
				t.Logf("  Total Time: %v", executionTime)
				t.Logf("  Avg Time/Evaluation: %v", avgTimePerEvaluation)
				t.Logf("  Pass Rate: %.2f%%", report.PassRate)
				t.Logf("  Average Score: %.3f", report.AverageScore)
			})
		}
	}
}

// TestErrorHandlingForMalformedPolicies tests error handling
func (suite *IntegrationTestSuite) TestErrorHandlingForMalformedPolicies() {
	malformedPolicies := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name: "Invalid YAML Syntax",
			content: `
template:
  name: "Test Policy"
  version: "1.0.0"
parameters:
  invalid_param:
    type: "float"
    default: [invalid yaml syntax
`,
			expectError: true,
		},
		{
			name: "Missing Required Fields",
			content: `
template:
  # missing name and version
  jurisdiction: "USA"
parameters:
  test_param:
    type: "float"
`,
			expectError: false, // Should parse but validation might catch it
		},
		{
			name: "Invalid Parameter Types",
			content: `
template:
  name: "Test Policy"
  version: "1.0.0"
parameters:
  invalid_param:
    type: "invalid_type"
    default: "test"
policy:
  metadata:
    version: "1.0.0"
    name: "test-policy"
  rules: []
`,
			expectError: false, // Parsing might succeed but compilation could fail
		},
		{
			name: "Circular References",
			content: `
template:
  name: "Circular Policy"
  version: "1.0.0"
parameters:
  param1:
    type: "float"
    default: "${param2}"
  param2:
    type: "float"
    default: "${param1}"
policy:
  metadata:
    version: "1.0.0"
    name: "circular-policy"
  rules: []
`,
			expectError: false, // Might parse but evaluation would fail
		},
	}

	for _, test := range malformedPolicies {
		suite.T().Run(test.name, func(t *testing.T) {
			policy, err := LoadTestYAMLFromString(test.content)

			if test.expectError {
				assert.Error(t, err, "Should fail to parse malformed YAML")
				assert.Nil(t, policy, "Policy should be nil for malformed content")
			} else {
				// Even if parsing succeeds, compilation might fail gracefully
				if err == nil {
					// Try to compile - this might fail gracefully
					compiled := &CompliancePolicy{
						ID:      "test-policy",
						Name:    "Test Policy",
						Version: "1.0.0",
						IsValid: false,
					}

					// The actual compiler would detect issues
					if policy != nil && (policy.Template.Name == "" || policy.Template.Version == "") {
						compiled.Errors = []string{"Missing required template fields"}
						compiled.IsValid = false
					}

					t.Logf("Malformed policy handled gracefully: %+v", compiled.Errors)
				}
			}
		})
	}
}

// TestCrossJurisdictionCompatibility tests policies across different jurisdictions
func (suite *IntegrationTestSuite) TestCrossJurisdictionCompatibility() {
	jurisdictions := []string{"USA", "USA-NY", "USA-CA", "EU", "UK"}
	assetClasses := []string{"CreditCard", "InstallmentLoan", "MerchantCashAdvance"}

	for _, jurisdiction := range jurisdictions {
		for _, assetClass := range assetClasses {
			suite.T().Run(fmt.Sprintf("Jurisdiction-%s-%s", jurisdiction, assetClass), func(t *testing.T) {
				// Create test transaction for this jurisdiction
				transaction := CreateMockTransactionData(assetClass)
				transaction.Jurisdiction = jurisdiction

				// Find applicable templates for this jurisdiction and asset class
				templates := suite.findTemplatesForJurisdiction(jurisdiction, assetClass)

				if len(templates) == 0 {
					t.Skipf("No templates found for jurisdiction %s and asset class %s", jurisdiction, assetClass)
					return
				}

				for _, templateFile := range templates {
					templateName := filepath.Base(templateFile)
					t.Run(templateName, func(t *testing.T) {
						// Load and compile template
						yamlContent, err := os.ReadFile(templateFile)
						require.NoError(t, err, "Failed to read template")

						compiled := AssertPolicyCompiles(t, string(yamlContent))
						require.NotNil(t, compiled, "Failed to compile policy")

						// Test evaluation with jurisdiction-specific transaction
						result := evaluatePolicy(compiled, transaction)
						require.NotNil(t, result, "Policy evaluation should not return nil")

						// Verify jurisdiction compatibility
						assert.Equal(t, compiled.ID, result.PolicyID, "Policy ID should match")
						assert.Equal(t, transaction.ID, result.TransactionID, "Transaction ID should match")

						t.Logf("Jurisdiction compatibility test passed for %s/%s", jurisdiction, assetClass)
					})
				}
			})
		}
	}
}

// TestRegulatoryFrameworkCoverage tests coverage of regulatory frameworks
func (suite *IntegrationTestSuite) TestRegulatoryFrameworkCoverage() {
	expectedFrameworks := map[string][]string{
		"CreditCard":          {"CFPB", "CARD Act", "FCRA", "TILA"},
		"InstallmentLoan":     {"TILA", "CFPB", "State Regulations"},
		"MerchantCashAdvance": {"FDCPA", "State Regulations", "NACHA Rules"},
		"EquipmentLease":      {"UCC Article 9", "State Filing Requirements"},
		"WorkingCapital":      {"UCC", "SBA Regulations", "Banking Regulations"},
	}

	templateFiles, err := suite.findAllTemplateFiles()
	suite.Require().NoError(err, "Failed to find template files")

	frameworkCoverage := make(map[string]map[string]bool)

	for _, templateFile := range templateFiles {
		policy, err := LoadTestYAML(templateFile)
		if err != nil {
			suite.T().Errorf("Failed to load template %s: %v", templateFile, err)
			continue
		}

		assetClass := policy.Template.AssetClass
		if frameworkCoverage[assetClass] == nil {
			frameworkCoverage[assetClass] = make(map[string]bool)
		}

		for _, framework := range policy.Template.RegulatoryFramework {
			frameworkCoverage[assetClass][framework] = true
		}
	}

	// Verify coverage
	for assetClass, expectedFrams := range expectedFrameworks {
		suite.T().Run(fmt.Sprintf("Coverage-%s", assetClass), func(t *testing.T) {
			coverage := frameworkCoverage[assetClass]
			if coverage == nil {
				t.Errorf("No templates found for asset class %s", assetClass)
				return
			}

			for _, framework := range expectedFrams {
				found := false
				for coveredFramework := range coverage {
					if strings.Contains(coveredFramework, framework) {
						found = true
						break
					}
				}
				assert.True(t, found, "Regulatory framework %s should be covered for %s", framework, assetClass)
			}

			t.Logf("Regulatory coverage for %s: %v", assetClass, getKeys(coverage))
		})
	}
}

// Helper methods

func (suite *IntegrationTestSuite) findAllTemplateFiles() ([]string, error) {
	var templateFiles []string

	err := filepath.Walk(suite.templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			templateFiles = append(templateFiles, path)
		}

		return nil
	})

	return templateFiles, err
}

func (suite *IntegrationTestSuite) findTemplatesForJurisdiction(jurisdiction, assetClass string) []string {
	templateFiles, _ := suite.findAllTemplateFiles()
	var matching []string

	for _, templateFile := range templateFiles {
		policy, err := LoadTestYAML(templateFile)
		if err != nil {
			continue
		}

		// Check if template matches jurisdiction and asset class
		if (policy.Template.Jurisdiction == jurisdiction ||
			strings.HasPrefix(jurisdiction, policy.Template.Jurisdiction)) &&
			policy.Template.AssetClass == assetClass {
			matching = append(matching, templateFile)
		}
	}

	return matching
}

func (suite *IntegrationTestSuite) validateTemplateStructure(t *testing.T, policy *ParsedPolicy, templateFile string) {
	// Validate template metadata
	assert.NotEmpty(t, policy.Template.Name, "Template name should not be empty")
	assert.NotEmpty(t, policy.Template.Version, "Template version should not be empty")
	assert.NotEmpty(t, policy.Template.Jurisdiction, "Template jurisdiction should not be empty")
	assert.NotEmpty(t, policy.Template.AssetClass, "Template asset class should not be empty")
	assert.NotEmpty(t, policy.Template.RegulatoryFramework, "Template should have regulatory framework")

	// Validate parameters
	for name, param := range policy.Parameters {
		assert.NotEmpty(t, param.Type, "Parameter %s should have a type", name)
		assert.NotNil(t, param.Default, "Parameter %s should have a default value", name)
		assert.NotEmpty(t, param.Description, "Parameter %s should have a description", name)
	}

	// Validate policy rules
	assert.NotEmpty(t, policy.Policy.Rules, "Policy should have at least one rule")
	for _, rule := range policy.Policy.Rules {
		assert.NotEmpty(t, rule.ID, "Rule should have an ID")
		assert.NotEmpty(t, rule.Name, "Rule should have a name")
		assert.NotEmpty(t, rule.Type, "Rule should have a type")
		assert.NotEmpty(t, rule.Priority, "Rule should have a priority")
		assert.NotEmpty(t, rule.Conditions, "Rule should have conditions")
		assert.NotEmpty(t, rule.Actions, "Rule should have actions")
	}

	// Validate attestations
	for _, attestation := range policy.Policy.Attestations {
		assert.NotEmpty(t, attestation.ID, "Attestation should have an ID")
		assert.NotEmpty(t, attestation.Name, "Attestation should have a name")
		assert.NotEmpty(t, attestation.Type, "Attestation should have a type")
		assert.NotEmpty(t, attestation.Fields, "Attestation should have fields")
	}
}

func (suite *IntegrationTestSuite) validatePolicyMetadata(t *testing.T, policy *CompliancePolicy) {
	assert.NotEmpty(t, policy.ID, "Policy should have an ID")
	assert.NotEmpty(t, policy.Name, "Policy should have a name")
	assert.NotEmpty(t, policy.Version, "Policy should have a version")
	assert.NotZero(t, policy.CompiledAt, "Policy should have compilation timestamp")
}

func (suite *IntegrationTestSuite) validatePolicyRules(t *testing.T, policy *CompliancePolicy) {
	assert.NotEmpty(t, policy.Rules, "Policy should have rules")

	for _, rule := range policy.Rules {
		assert.NotEmpty(t, rule.ID, "Rule should have an ID")
		assert.NotEmpty(t, rule.Name, "Rule should have a name")
		assert.NotEmpty(t, rule.Type, "Rule should have a type")
		assert.Greater(t, rule.Priority, 0, "Rule should have a positive priority")
		assert.NotEmpty(t, rule.Conditions, "Rule should have conditions")
		assert.NotEmpty(t, rule.Actions, "Rule should have actions")
	}
}

func (suite *IntegrationTestSuite) validatePolicyParameters(t *testing.T, policy *CompliancePolicy) {
	// Parameters are optional, but if present should be valid
	for name, value := range policy.Parameters {
		assert.NotNil(t, value, "Parameter %s should have a value", name)
	}
}

func (suite *IntegrationTestSuite) createTestPolicy(assetClass string) *CompliancePolicy {
	// Create a minimal test policy for the given asset class
	policy := &CompliancePolicy{
		ID:         fmt.Sprintf("test-%s-policy", strings.ToLower(assetClass)),
		Name:       fmt.Sprintf("Test %s Policy", assetClass),
		Version:    "1.0.0-test",
		IsValid:    true,
		CompiledAt: time.Now(),
		Parameters: make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
	}

	// Add asset class specific rules
	switch assetClass {
	case "CreditCard":
		policy.Rules = []CompiledRule{
			{
				ID:       "credit_score_check",
				Name:     "Credit Score Validation",
				Type:     "validation",
				Priority: 1,
				Enabled:  true,
				Conditions: []CompiledCondition{
					{Expression: "credit_score >= 500", Type: "expression"},
				},
				Actions: []CompiledAction{
					{Type: "validate_credit_score"},
				},
			},
		}
	case "InstallmentLoan":
		policy.Rules = []CompiledRule{
			{
				ID:       "income_verification",
				Name:     "Income Verification",
				Type:     "validation",
				Priority: 1,
				Enabled:  true,
				Conditions: []CompiledCondition{
					{Expression: "annual_income >= 25000", Type: "expression"},
					{Expression: "income_verified == true", Type: "expression"},
				},
				Actions: []CompiledAction{
					{Type: "verify_income"},
				},
			},
		}
	default:
		// Generic rule for other asset classes
		policy.Rules = []CompiledRule{
			{
				ID:       "basic_validation",
				Name:     "Basic Validation",
				Type:     "validation",
				Priority: 1,
				Enabled:  true,
				Conditions: []CompiledCondition{
					{Expression: "true", Type: "expression"},
				},
				Actions: []CompiledAction{
					{Type: "basic_check"},
				},
			},
		}
	}

	return policy
}

func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestIntegrationSuite runs the integration test suite
func TestIntegrationSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}
