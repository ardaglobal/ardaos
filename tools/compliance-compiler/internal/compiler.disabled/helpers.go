package compiler

import (
	"fmt"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
)

// Helper methods for the compiler

// Deep copy methods
func (c *ComplianceCompiler) deepCopyPolicy(policy *parser.CompliancePolicy) *parser.CompliancePolicy {
	// Create a shallow copy for now
	// In a full implementation, this would create a complete deep copy
	copied := *policy
	return &copied
}

func (c *ComplianceCompiler) deepCopyPredicate(predicate *parser.Predicate) *parser.Predicate {
	// Create a shallow copy for now
	// In a full implementation, this would create a complete deep copy
	copied := *predicate
	return &copied
}

// Analysis methods
func (c *ComplianceCompiler) countPredicates(policy *parser.CompliancePolicy) int {
	count := 0
	for _, rule := range policy.Rules {
		if rule.Predicate != nil {
			count += c.countPredicatesInTree(rule.Predicate)
		}
	}
	return count
}

func (c *ComplianceCompiler) countPredicatesInTree(predicate *parser.Predicate) int {
	// Recursive count of predicates in tree
	// For now, return 1 per predicate
	return 1
}

func (c *ComplianceCompiler) calculateMaxDepth(policy *parser.CompliancePolicy) int {
	maxDepth := 0
	for _, rule := range policy.Rules {
		if rule.Predicate != nil {
			depth := c.calculatePredicateDepth(rule.Predicate, 0)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
	}
	return maxDepth
}

func (c *ComplianceCompiler) calculatePredicateDepth(predicate *parser.Predicate, currentDepth int) int {
	// Recursive calculation of predicate depth
	// For now, return current depth + 1
	return currentDepth + 1
}

func (c *ComplianceCompiler) calculateComplexityScore(policy *parser.CompliancePolicy) int {
	// Calculate a complexity score based on number of rules, predicates, etc.
	score := 0
	score += len(policy.Rules) * 10        // 10 points per rule
	score += len(policy.Attestations) * 5  // 5 points per attestation
	score += c.countPredicates(policy) * 3 // 3 points per predicate
	return score
}

func (c *ComplianceCompiler) calculatePolicySize(policy *parser.CompliancePolicy) int {
	// Calculate an approximate size metric for the policy
	size := 0
	size += len(policy.PolicyId)
	size += len(policy.Version)
	size += len(policy.Jurisdiction)
	size += len(policy.AssetClass)
	size += len(policy.Rules) * 100       // Approximate size per rule
	size += len(policy.Attestations) * 50 // Approximate size per attestation
	return size
}

func (c *ComplianceCompiler) countRequiredAttestations(policy *parser.CompliancePolicy) int {
	count := 0
	for _, attestation := range policy.Attestations {
		if attestation.Required {
			count++
		}
	}
	return count
}

// Validation helper methods
func (c *ComplianceCompiler) validateAgainstSchema(policy *parser.CompliancePolicy, schema *PolicySchema) error {
	// Validate policy against jurisdiction-specific schema
	if schema.Version != "" {
		// Check schema version compatibility
	}

	// Validate asset class
	if len(schema.AssetClasses) > 0 {
		found := false
		for _, allowedClass := range schema.AssetClasses {
			if policy.AssetClass == allowedClass {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("asset class '%s' not allowed in jurisdiction '%s'",
				policy.AssetClass, schema.Jurisdiction)
		}
	}

	// Validate required fields are present
	for _, requiredField := range schema.RequiredFields {
		if err := c.validateRequiredField(policy, requiredField); err != nil {
			return fmt.Errorf("required field validation failed: %w", err)
		}
	}

	return nil
}

func (c *ComplianceCompiler) validateRequiredField(policy *parser.CompliancePolicy, fieldName string) error {
	// Check if required field is present in the policy
	switch fieldName {
	case "policy_id":
		if policy.PolicyId == "" {
			return fmt.Errorf("required field '%s' is missing", fieldName)
		}
	case "version":
		if policy.Version == "" {
			return fmt.Errorf("required field '%s' is missing", fieldName)
		}
	case "jurisdiction":
		if policy.Jurisdiction == "" {
			return fmt.Errorf("required field '%s' is missing", fieldName)
		}
	case "asset_class":
		if policy.AssetClass == "" {
			return fmt.Errorf("required field '%s' is missing", fieldName)
		}
	case "rules":
		if len(policy.Rules) == 0 {
			return fmt.Errorf("required field '%s' is missing or empty", fieldName)
		}
	}
	return nil
}

func (c *ComplianceCompiler) validateFieldReferences(policy *parser.CompliancePolicy, schema *PolicySchema) error {
	// Validate all field references in predicates against schema
	// For now, return nil (basic implementation)
	return nil
}

func (c *ComplianceCompiler) validatePredicateLogic(policy *parser.CompliancePolicy) error {
	// Validate predicate logic for completeness and consistency
	for _, rule := range policy.Rules {
		if rule.Predicate != nil {
			if err := c.validateSinglePredicate(rule.Predicate); err != nil {
				return fmt.Errorf("predicate validation failed for rule '%s': %w", rule.Name, err)
			}
		}
	}
	return nil
}

func (c *ComplianceCompiler) validateSinglePredicate(predicate *parser.Predicate) error {
	// Validate a single predicate for logical consistency
	// Check for basic structural issues
	if predicate.PredicateType == nil {
		return fmt.Errorf("predicate type cannot be nil")
	}

	// Additional validation would check for circular references,
	// impossible conditions, etc.
	return nil
}

func (c *ComplianceCompiler) validateAttestationRequirements(policy *parser.CompliancePolicy, schema *PolicySchema) error {
	// Validate that attestation requirements are achievable
	for _, attestation := range policy.Attestations {
		if schema != nil && len(schema.AttestationTypes) > 0 {
			// Check if attestation type is supported
			found := false
			for _, allowedType := range schema.AttestationTypes {
				if attestation.Type == allowedType {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("attestation type '%s' not supported in jurisdiction '%s'",
					attestation.Type, schema.Jurisdiction)
			}
		}
	}
	return nil
}

func (c *ComplianceCompiler) validateEnforcementConfiguration(policy *parser.CompliancePolicy, schema *PolicySchema) error {
	// Validate enforcement configurations
	if policy.Enforcement == nil {
		return fmt.Errorf("enforcement configuration is required")
	}

	if schema != nil && len(schema.EnforcementLevels) > 0 {
		// Check if enforcement level is supported
		found := false
		for _, allowedLevel := range schema.EnforcementLevels {
			if policy.Enforcement.Level == allowedLevel {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("enforcement level '%s' not supported in jurisdiction '%s'",
				policy.Enforcement.Level, schema.Jurisdiction)
		}
	}

	if len(policy.Enforcement.Actions) == 0 {
		return fmt.Errorf("at least one enforcement action must be specified")
	}

	return nil
}

// Optimization helper methods
func (c *ComplianceCompiler) optimizePredicateTreesInPolicy(policy *parser.CompliancePolicy, stats *OptimizationStats) error {
	optimizedCount := 0
	for _, rule := range policy.Rules {
		if rule.Predicate != nil {
			optimized, err := c.OptimizePredicateTree(rule.Predicate)
			if err != nil {
				return fmt.Errorf("failed to optimize predicate for rule '%s': %w", rule.Name, err)
			}
			rule.Predicate = optimized
			optimizedCount++
		}
	}

	stats.OptimizationDetails = append(stats.OptimizationDetails, OptimizationStep{
		Type:        "predicate_optimization",
		Description: fmt.Sprintf("Optimized %d predicate trees", optimizedCount),
		BeforeSize:  optimizedCount,
		AfterSize:   optimizedCount,
		Savings:     0, // Would calculate actual savings
		Timestamp:   time.Now(),
	})

	return nil
}

func (c *ComplianceCompiler) eliminateDuplicateConditions(policy *parser.CompliancePolicy, stats *OptimizationStats) error {
	// Eliminate duplicate conditions across the policy
	eliminatedCount := 0

	// Implementation would identify and remove duplicate conditions
	// For now, just record the optimization step
	stats.EliminatedDuplicates = eliminatedCount
	stats.OptimizationDetails = append(stats.OptimizationDetails, OptimizationStep{
		Type:        "duplicate_elimination",
		Description: fmt.Sprintf("Eliminated %d duplicate conditions", eliminatedCount),
		BeforeSize:  0,
		AfterSize:   0,
		Savings:     eliminatedCount,
		Timestamp:   time.Now(),
	})

	return nil
}

func (c *ComplianceCompiler) performConstantFolding(policy *parser.CompliancePolicy, stats *OptimizationStats) error {
	// Fold constant expressions
	foldedCount := 0

	// Implementation would identify and evaluate constant sub-expressions
	// For now, just record the optimization step
	stats.ConstantsFolded = foldedCount
	stats.OptimizationDetails = append(stats.OptimizationDetails, OptimizationStep{
		Type:        "constant_folding",
		Description: fmt.Sprintf("Folded %d constant expressions", foldedCount),
		BeforeSize:  0,
		AfterSize:   0,
		Savings:     foldedCount,
		Timestamp:   time.Now(),
	})

	return nil
}

func (c *ComplianceCompiler) generateIndexHintsForPolicy(policy *parser.CompliancePolicy, stats *OptimizationStats) error {
	// Generate hints for efficient field access
	hintsGenerated := 0

	// Implementation would analyze field access patterns and generate optimization hints
	// For now, just record the optimization step
	stats.OptimizationDetails = append(stats.OptimizationDetails, OptimizationStep{
		Type:        "index_hints",
		Description: fmt.Sprintf("Generated %d index hints", hintsGenerated),
		BeforeSize:  0,
		AfterSize:   0,
		Savings:     0,
		Timestamp:   time.Now(),
	})

	return nil
}

// Audit trail methods
func (c *ComplianceCompiler) initializeAuditTrail(policy *parser.CompliancePolicy) *CompilationAuditTrail {
	return &CompilationAuditTrail{
		TrailID:       generateTrailID(),
		CompilationID: generateCompilationID(),
		StartTime:     time.Now(),
		UserID:        "system", // Would be populated from context
		SourceDocument: &SourceDocumentInfo{
			FileName:     "policy.yaml",
			FileSize:     0, // Would calculate actual size
			FileHash:     c.calculateSourceHash(policy),
			LastModified: time.Now(),
			Author:       "unknown",
			Version:      policy.Version,
		},
		Operations: make([]CompilationOperation, 0),
		DataAccess: make([]DataAccessRecord, 0),
		Compliance: &ComplianceTrackingInfo{
			ComplianceFramework:   "internal",
			RequiredRetention:     365 * 24 * time.Hour, // 1 year
			DataClassification:    "internal",
			AccessControls:        []string{"authenticated"},
			AuditRequirements:     []string{"compilation_tracking"},
			PrivacyConsiderations: []string{"none"},
		},
	}
}

func (c *ComplianceCompiler) finalizeAuditTrail(trail *CompilationAuditTrail, policy *parser.CompliancePolicy) {
	// Add final compilation operation
	trail.Operations = append(trail.Operations, CompilationOperation{
		OperationID: generateOperationID(),
		Type:        "compilation_complete",
		StartTime:   trail.StartTime,
		EndTime:     time.Now(),
		Status:      "success",
		Input: map[string]interface{}{
			"policy_id":    policy.PolicyId,
			"version":      policy.Version,
			"jurisdiction": policy.Jurisdiction,
			"rules_count":  len(policy.Rules),
		},
		Output: map[string]interface{}{
			"compilation_success": true,
			"fingerprint":         c.generatePolicyFingerprint(policy),
		},
		Errors:   []string{},
		Warnings: []string{},
	})
}

// Utility functions
func generateTrailID() string {
	return fmt.Sprintf("trail_%d", time.Now().UnixNano())
}

func generateCompilationID() string {
	return fmt.Sprintf("compile_%d", time.Now().UnixNano())
}

func generateOperationID() string {
	return fmt.Sprintf("op_%d", time.Now().UnixNano())
}
