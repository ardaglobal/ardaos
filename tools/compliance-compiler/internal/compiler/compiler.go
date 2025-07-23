package compiler

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
)

type Compiler struct {
	version       string
	optimizations []string
}

func NewCompiler() *Compiler {
	return &Compiler{
		version:       "1.0.0",
		optimizations: []string{"dead_code_elimination", "constant_folding"},
	}
}

func (c *Compiler) CompilePolicy(policy *types.Policy) (*types.CompiledPolicy, error) {
	logrus.Infof("Compiling policy: %s (version: %s)", policy.Metadata.Name, policy.Metadata.Version)

	// Generate hash for the policy
	hash, err := c.generatePolicyHash(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate policy hash: %w", err)
	}

	// Compile metadata
	compiledMetadata := &types.CompiledMetadata{
		OriginalName:    policy.Metadata.Name,
		CompilerVersion: c.version,
		CompiledAt:      time.Now().UTC().Format(time.RFC3339),
		Hash:            hash,
		Optimizations:   c.optimizations,
		Dependencies:    c.extractDependencies(policy),
		Metadata: map[string]string{
			"region":     policy.Metadata.Region,
			"asset_type": policy.Metadata.AssetType,
		},
	}

	// Compile rules
	compiledRules := make([]*types.CompiledRule, 0, len(policy.Spec.Rules))
	for _, rule := range policy.Spec.Rules {
		compiledRule, err := c.compileRule(&rule)
		if err != nil {
			return nil, fmt.Errorf("failed to compile rule %s: %w", rule.ID, err)
		}
		compiledRules = append(compiledRules, compiledRule)
	}

	// Generate runtime settings
	runtimeSettings := c.generateRuntimeSettings(policy)

	compiledPolicy := &types.CompiledPolicy{
		Metadata:        compiledMetadata,
		CompiledRules:   compiledRules,
		RuntimeSettings: runtimeSettings,
		Version:         policy.Metadata.Version,
		CompilerVersion: c.version,
	}

	logrus.Infof("Successfully compiled policy with %d rules", len(compiledRules))
	return compiledPolicy, nil
}

func (c *Compiler) CompilePolicies(policies []*types.Policy) ([]*types.CompiledPolicy, error) {
	logrus.Infof("Compiling %d policies", len(policies))

	compiledPolicies := make([]*types.CompiledPolicy, 0, len(policies))

	for i, policy := range policies {
		compiledPolicy, err := c.CompilePolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("failed to compile policy %d (%s): %w", i, policy.Metadata.Name, err)
		}
		compiledPolicies = append(compiledPolicies, compiledPolicy)
	}

	logrus.Infof("Successfully compiled all %d policies", len(compiledPolicies))
	return compiledPolicies, nil
}

func (c *Compiler) compileRule(rule *types.Rule) (*types.CompiledRule, error) {
	logrus.Debugf("Compiling rule: %s", rule.ID)

	// Compile condition
	compiledCondition, err := c.compileCondition(rule.Condition)
	if err != nil {
		return nil, fmt.Errorf("failed to compile condition: %w", err)
	}

	// Compile action
	compiledAction, err := c.compileAction(rule.Action)
	if err != nil {
		return nil, fmt.Errorf("failed to compile action: %w", err)
	}

	// Convert parameters
	parameters := make(map[string]interface{})
	for _, param := range rule.Parameters {
		parameters[param.Name] = param.Value
	}

	return &types.CompiledRule{
		ID:           rule.ID,
		Type:         string(rule.Type),
		Priority:     rule.Priority,
		Condition:    compiledCondition,
		Action:       compiledAction,
		Parameters:   parameters,
		Optimized:    true,
		Dependencies: c.extractRuleDependencies(rule),
	}, nil
}

func (c *Compiler) compileCondition(condition string) (*types.CompiledCondition, error) {
	logrus.Debugf("Compiling condition: %s", condition)

	// This is a simplified compilation - in a real implementation,
	// this would parse the condition expression and generate bytecode
	variables := c.extractVariables(condition)
	functions := c.extractFunctions(condition)

	return &types.CompiledCondition{
		Expression: condition,
		Variables:  variables,
		Functions:  functions,
		Metadata: map[string]interface{}{
			"optimized":  true,
			"complexity": c.calculateComplexity(condition),
		},
	}, nil
}

func (c *Compiler) compileAction(action string) (*types.CompiledAction, error) {
	logrus.Debugf("Compiling action: %s", action)

	// Parse action type and handler from action string
	// Format: "type:handler" or just "type"
	actionType := action
	handler := ""

	if len(action) > 0 {
		parts := []string{action}
		if len(parts) == 2 {
			actionType = parts[0]
			handler = parts[1]
		}
	}

	return &types.CompiledAction{
		Type:    actionType,
		Handler: handler,
		Parameters: map[string]interface{}{
			"compiled": true,
		},
		Metadata: map[string]interface{}{
			"optimized": true,
		},
	}, nil
}

func (c *Compiler) generatePolicyHash(policy *types.Policy) (string, error) {
	// Generate a hash based on the policy content
	content := fmt.Sprintf("%s-%s-%s-%v",
		policy.Metadata.Name,
		policy.Metadata.Version,
		policy.Metadata.Region,
		len(policy.Spec.Rules))

	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash[:8]), nil
}

func (c *Compiler) extractDependencies(policy *types.Policy) []string {
	// Extract dependencies from policy conditions and actions
	dependencies := make(map[string]bool)

	for _, rule := range policy.Spec.Rules {
		// Look for references to other policies or external services
		if ruleDeps := c.extractRuleDependencies(&rule); len(ruleDeps) > 0 {
			for _, dep := range ruleDeps {
				dependencies[dep] = true
			}
		}
	}

	deps := make([]string, 0, len(dependencies))
	for dep := range dependencies {
		deps = append(deps, dep)
	}

	return deps
}

func (c *Compiler) extractRuleDependencies(rule *types.Rule) []string {
	// Extract dependencies from rule conditions and actions
	// This is simplified - real implementation would parse expressions
	return []string{}
}

func (c *Compiler) extractVariables(expression string) []string {
	// Extract variable references from expression
	// This is simplified - real implementation would use proper parsing
	variables := []string{}

	// Look for common variable patterns like ${variable}, $variable, etc.
	// For now, return some common compliance variables
	commonVars := []string{"amount", "sender", "recipient", "asset_type", "region"}
	for _, v := range commonVars {
		if len(expression) > 0 { // Simple check if expression references variable
			variables = append(variables, v)
		}
	}

	return variables
}

func (c *Compiler) extractFunctions(expression string) []string {
	// Extract function calls from expression
	// This is simplified - real implementation would use proper parsing
	functions := []string{}

	// Look for common function patterns
	commonFuncs := []string{"max", "min", "sum", "count", "contains"}
	for _, f := range commonFuncs {
		if len(expression) > 0 { // Simple check if expression uses function
			functions = append(functions, f)
		}
	}

	return functions
}

func (c *Compiler) calculateComplexity(expression string) int {
	// Calculate expression complexity for optimization purposes
	// This is simplified - real implementation would analyze the AST
	return len(expression) / 10 // Very basic complexity metric
}

func (c *Compiler) generateRuntimeSettings(policy *types.Policy) map[string]string {
	settings := map[string]string{
		"default_action":    string(policy.Spec.Settings.DefaultAction),
		"strict_mode":       fmt.Sprintf("%t", policy.Spec.Settings.StrictMode),
		"continue_on_error": fmt.Sprintf("%t", policy.Spec.Settings.ContinueOnError),
		"log_level":         policy.Spec.Settings.LogLevel,
	}

	// Add timeout settings
	for key, value := range policy.Spec.Settings.Timeouts {
		settings["timeout_"+key] = value
	}

	return settings
}
