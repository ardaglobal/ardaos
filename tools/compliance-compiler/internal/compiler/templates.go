package compiler

import (
	"fmt"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
)

// PolicyTemplateEngine handles policy templates and inheritance
type PolicyTemplateEngine struct {
	templates       map[string]*PolicyTemplate
	inheritanceTree map[string][]string
	parameterCache  map[string]interface{}
	validationRules *TemplateValidationRules
}

// TemplateValidationRules defines validation rules for templates
type TemplateValidationRules struct {
	MaxInheritanceDepth    int      `json:"max_inheritance_depth"`
	RequiredParameters     []string `json:"required_parameters"`
	AllowedParameterTypes  []string `json:"allowed_parameter_types"`
	CircularReferenceCheck bool     `json:"circular_reference_check"`
}

// TemplateApplication represents the result of applying a template
type TemplateApplication struct {
	AppliedTemplates   []string               `json:"applied_templates"`
	ResolvedParameters map[string]interface{} `json:"resolved_parameters"`
	InheritanceChain   []string               `json:"inheritance_chain"`
	Warnings           []TemplateWarning      `json:"warnings"`
	AppliedAt          time.Time              `json:"applied_at"`
}

// TemplateWarning represents a warning during template application
type TemplateWarning struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Template  string `json:"template"`
	Parameter string `json:"parameter,omitempty"`
	Severity  string `json:"severity"`
}

// TemplateRegistry manages policy templates
type TemplateRegistry struct {
	templates    map[string]*PolicyTemplate
	categories   map[string][]string
	versions     map[string]map[string]*PolicyTemplate
	dependencies map[string][]string
}

// NewPolicyTemplateEngine creates a new template engine
func NewPolicyTemplateEngine() *PolicyTemplateEngine {
	return &PolicyTemplateEngine{
		templates:       make(map[string]*PolicyTemplate),
		inheritanceTree: make(map[string][]string),
		parameterCache:  make(map[string]interface{}),
		validationRules: &TemplateValidationRules{
			MaxInheritanceDepth:    5,
			RequiredParameters:     []string{},
			AllowedParameterTypes:  []string{"string", "number", "boolean", "array", "object"},
			CircularReferenceCheck: true,
		},
	}
}

// NewTemplateRegistry creates a new template registry
func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{
		templates:    make(map[string]*PolicyTemplate),
		categories:   make(map[string][]string),
		versions:     make(map[string]map[string]*PolicyTemplate),
		dependencies: make(map[string][]string),
	}
}

// RegisterTemplate registers a new policy template
func (pte *PolicyTemplateEngine) RegisterTemplate(template *PolicyTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID cannot be empty")
	}

	// Validate template structure
	if err := pte.validateTemplate(template); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Check for circular references if base template is specified
	if template.BaseTemplate != "" {
		if err := pte.checkCircularReference(template.ID, template.BaseTemplate); err != nil {
			return fmt.Errorf("circular reference detected: %w", err)
		}
	}

	pte.templates[template.ID] = template

	// Update inheritance tree
	if template.BaseTemplate != "" {
		pte.inheritanceTree[template.BaseTemplate] = append(
			pte.inheritanceTree[template.BaseTemplate], template.ID)
	}

	return nil
}

// ApplyTemplate applies a template to a policy
func (pte *PolicyTemplateEngine) ApplyTemplate(policy *parser.CompliancePolicy, templateID string, parameters map[string]interface{}) (*parser.CompliancePolicy, *TemplateApplication, error) {
	template, exists := pte.templates[templateID]
	if !exists {
		return nil, nil, fmt.Errorf("template '%s' not found", templateID)
	}

	application := &TemplateApplication{
		AppliedTemplates:   []string{},
		ResolvedParameters: make(map[string]interface{}),
		InheritanceChain:   []string{},
		Warnings:           []TemplateWarning{},
		AppliedAt:          time.Now(),
	}

	// Build inheritance chain
	chain, err := pte.buildInheritanceChain(templateID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build inheritance chain: %w", err)
	}
	application.InheritanceChain = chain

	// Resolve parameters through inheritance chain
	resolvedParams, err := pte.resolveParameters(chain, parameters)
	if err != nil {
		return nil, nil, fmt.Errorf("parameter resolution failed: %w", err)
	}
	application.ResolvedParameters = resolvedParams

	// Apply templates in inheritance order (base first)
	enhancedPolicy := pte.deepCopyPolicy(policy)

	for _, tmplID := range chain {
		tmpl := pte.templates[tmplID]
		if err := pte.applyTemplateToPolicy(enhancedPolicy, tmpl, resolvedParams, application); err != nil {
			return nil, application, fmt.Errorf("failed to apply template '%s': %w", tmplID, err)
		}
		application.AppliedTemplates = append(application.AppliedTemplates, tmplID)
	}

	return enhancedPolicy, application, nil
}

// ApplyMultipleTemplates applies multiple templates to a policy
func (pte *PolicyTemplateEngine) ApplyMultipleTemplates(policy *parser.CompliancePolicy, templateSpecs []TemplateSpec) (*parser.CompliancePolicy, *TemplateApplication, error) {
	combinedApplication := &TemplateApplication{
		AppliedTemplates:   []string{},
		ResolvedParameters: make(map[string]interface{}),
		InheritanceChain:   []string{},
		Warnings:           []TemplateWarning{},
		AppliedAt:          time.Now(),
	}

	enhancedPolicy := pte.deepCopyPolicy(policy)

	// Apply templates in specified order
	for _, spec := range templateSpecs {
		appliedPolicy, application, err := pte.ApplyTemplate(enhancedPolicy, spec.TemplateID, spec.Parameters)
		if err != nil {
			return nil, combinedApplication, fmt.Errorf("failed to apply template '%s': %w", spec.TemplateID, err)
		}

		enhancedPolicy = appliedPolicy

		// Merge application results
		combinedApplication.AppliedTemplates = append(combinedApplication.AppliedTemplates, application.AppliedTemplates...)
		combinedApplication.InheritanceChain = append(combinedApplication.InheritanceChain, application.InheritanceChain...)
		combinedApplication.Warnings = append(combinedApplication.Warnings, application.Warnings...)

		// Merge parameters (later templates override earlier ones)
		for k, v := range application.ResolvedParameters {
			combinedApplication.ResolvedParameters[k] = v
		}
	}

	return enhancedPolicy, combinedApplication, nil
}

// TemplateSpec specifies a template to apply
type TemplateSpec struct {
	TemplateID string                 `json:"template_id"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   int                    `json:"priority"`
}

// validateTemplate validates a template structure
func (pte *PolicyTemplateEngine) validateTemplate(template *PolicyTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name cannot be empty")
	}

	if template.Version == "" {
		return fmt.Errorf("template version cannot be empty")
	}

	// Validate parameters
	for paramName, paramValue := range template.Parameters {
		if err := pte.validateParameter(paramName, paramValue); err != nil {
			return fmt.Errorf("invalid parameter '%s': %w", paramName, err)
		}
	}

	// Validate base template exists if specified
	if template.BaseTemplate != "" {
		if _, exists := pte.templates[template.BaseTemplate]; !exists {
			return fmt.Errorf("base template '%s' not found", template.BaseTemplate)
		}
	}

	return nil
}

// checkCircularReference checks for circular references in template inheritance
func (pte *PolicyTemplateEngine) checkCircularReference(templateID, baseTemplateID string) error {
	if !pte.validationRules.CircularReferenceCheck {
		return nil
	}

	visited := make(map[string]bool)
	return pte.checkCircularReferenceRecursive(templateID, baseTemplateID, visited)
}

func (pte *PolicyTemplateEngine) checkCircularReferenceRecursive(originalID, currentID string, visited map[string]bool) error {
	if currentID == originalID {
		return fmt.Errorf("circular reference detected: %s -> %s", originalID, currentID)
	}

	if visited[currentID] {
		return nil // Already processed this branch
	}

	visited[currentID] = true

	if template, exists := pte.templates[currentID]; exists && template.BaseTemplate != "" {
		return pte.checkCircularReferenceRecursive(originalID, template.BaseTemplate, visited)
	}

	return nil
}

// buildInheritanceChain builds the complete inheritance chain for a template
func (pte *PolicyTemplateEngine) buildInheritanceChain(templateID string) ([]string, error) {
	chain := []string{}
	current := templateID
	depth := 0

	for current != "" {
		if depth > pte.validationRules.MaxInheritanceDepth {
			return nil, fmt.Errorf("maximum inheritance depth (%d) exceeded for template '%s'",
				pte.validationRules.MaxInheritanceDepth, templateID)
		}

		template, exists := pte.templates[current]
		if !exists {
			return nil, fmt.Errorf("template '%s' not found in inheritance chain", current)
		}

		// Add to front of chain (we want base templates first)
		chain = append([]string{current}, chain...)
		current = template.BaseTemplate
		depth++
	}

	return chain, nil
}

// resolveParameters resolves parameters through the inheritance chain
func (pte *PolicyTemplateEngine) resolveParameters(chain []string, userParams map[string]interface{}) (map[string]interface{}, error) {
	resolved := make(map[string]interface{})

	// Apply parameters from base templates first
	for _, templateID := range chain {
		template := pte.templates[templateID]
		for paramName, paramValue := range template.Parameters {
			resolved[paramName] = paramValue
		}
	}

	// Override with user-provided parameters
	for paramName, paramValue := range userParams {
		if err := pte.validateParameter(paramName, paramValue); err != nil {
			return nil, fmt.Errorf("invalid user parameter '%s': %w", paramName, err)
		}
		resolved[paramName] = paramValue
	}

	return resolved, nil
}

// validateParameter validates a template parameter
func (pte *PolicyTemplateEngine) validateParameter(name string, value interface{}) error {
	if name == "" {
		return fmt.Errorf("parameter name cannot be empty")
	}

	// Check parameter type
	paramType := getParameterType(value)
	if !pte.isAllowedParameterType(paramType) {
		return fmt.Errorf("parameter type '%s' not allowed", paramType)
	}

	return nil
}

// isAllowedParameterType checks if a parameter type is allowed
func (pte *PolicyTemplateEngine) isAllowedParameterType(paramType string) bool {
	for _, allowedType := range pte.validationRules.AllowedParameterTypes {
		if paramType == allowedType {
			return true
		}
	}
	return false
}

// applyTemplateToPolicy applies a single template to a policy
func (pte *PolicyTemplateEngine) applyTemplateToPolicy(policy *parser.CompliancePolicy, template *PolicyTemplate, parameters map[string]interface{}, application *TemplateApplication) error {
	// Apply template rules
	if err := pte.applyTemplateRules(policy, template.Rules, parameters, application); err != nil {
		return fmt.Errorf("failed to apply template rules: %w", err)
	}

	// Apply template attestations
	if err := pte.applyTemplateAttestations(policy, template.Attestations, parameters, application); err != nil {
		return fmt.Errorf("failed to apply template attestations: %w", err)
	}

	// Apply template enforcement
	if err := pte.applyTemplateEnforcement(policy, template.Enforcement, parameters, application); err != nil {
		return fmt.Errorf("failed to apply template enforcement: %w", err)
	}

	return nil
}

// applyTemplateRules applies template rules to the policy
func (pte *PolicyTemplateEngine) applyTemplateRules(policy *parser.CompliancePolicy, templateRules []interface{}, parameters map[string]interface{}, application *TemplateApplication) error {
	for _, rule := range templateRules {
		// Parse template rule
		processedRule, err := pte.processTemplateRule(rule, parameters)
		if err != nil {
			application.Warnings = append(application.Warnings, TemplateWarning{
				Code:     "RULE_PROCESSING_ERROR",
				Message:  fmt.Sprintf("Failed to process template rule: %v", err),
				Severity: "warning",
			})
			continue
		}

		// Add processed rule to policy
		policy.Rules = append(policy.Rules, processedRule)
	}

	return nil
}

// applyTemplateAttestations applies template attestations to the policy
func (pte *PolicyTemplateEngine) applyTemplateAttestations(policy *parser.CompliancePolicy, templateAttestations []interface{}, parameters map[string]interface{}, application *TemplateApplication) error {
	for _, attestation := range templateAttestations {
		// Parse template attestation
		processedAttestation, err := pte.processTemplateAttestation(attestation, parameters)
		if err != nil {
			application.Warnings = append(application.Warnings, TemplateWarning{
				Code:     "ATTESTATION_PROCESSING_ERROR",
				Message:  fmt.Sprintf("Failed to process template attestation: %v", err),
				Severity: "warning",
			})
			continue
		}

		// Add processed attestation to policy
		policy.Attestations = append(policy.Attestations, processedAttestation)
	}

	return nil
}

// applyTemplateEnforcement applies template enforcement to the policy
func (pte *PolicyTemplateEngine) applyTemplateEnforcement(policy *parser.CompliancePolicy, templateEnforcement interface{}, parameters map[string]interface{}, application *TemplateApplication) error {
	if templateEnforcement == nil {
		return nil
	}

	// Process template enforcement
	processedEnforcement, err := pte.processTemplateEnforcement(templateEnforcement, parameters)
	if err != nil {
		application.Warnings = append(application.Warnings, TemplateWarning{
			Code:     "ENFORCEMENT_PROCESSING_ERROR",
			Message:  fmt.Sprintf("Failed to process template enforcement: %v", err),
			Severity: "warning",
		})
		return nil
	}

	// Apply to policy (merge with existing enforcement if present)
	if policy.Enforcement == nil {
		policy.Enforcement = processedEnforcement
	} else {
		// Merge enforcement configurations
		pte.mergeEnforcementConfigs(policy.Enforcement, processedEnforcement)
	}

	return nil
}

// processTemplateRule processes a template rule with parameter substitution
func (pte *PolicyTemplateEngine) processTemplateRule(rule interface{}, parameters map[string]interface{}) (*parser.PolicyRule, error) {
	// Convert rule interface to map for processing
	ruleMap, ok := rule.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rule must be a map/object")
	}

	// Create policy rule
	policyRule := &parser.PolicyRule{}

	// Process rule fields with parameter substitution
	if name, exists := ruleMap["name"]; exists {
		policyRule.Name = pte.substituteParameters(name.(string), parameters)
	}

	if description, exists := ruleMap["description"]; exists {
		policyRule.Description = pte.substituteParameters(description.(string), parameters)
	}

	if required, exists := ruleMap["required"]; exists {
		policyRule.Required = required.(bool)
	}

	// Process predicate (this would be more complex in a full implementation)
	if predicateData, exists := ruleMap["predicate"]; exists {
		predicate, err := pte.processTemplatePredicate(predicateData, parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to process predicate: %w", err)
		}
		policyRule.Predicate = predicate
	}

	return policyRule, nil
}

// processTemplateAttestation processes a template attestation with parameter substitution
func (pte *PolicyTemplateEngine) processTemplateAttestation(attestation interface{}, parameters map[string]interface{}) (*parser.AttestationRequirement, error) {
	// Convert attestation interface to map for processing
	attestationMap, ok := attestation.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("attestation must be a map/object")
	}

	// Create attestation requirement
	requirement := &parser.AttestationRequirement{}

	// Process attestation fields with parameter substitution
	if name, exists := attestationMap["name"]; exists {
		requirement.Name = pte.substituteParameters(name.(string), parameters)
	}

	if attestationType, exists := attestationMap["type"]; exists {
		requirement.Type = pte.substituteParameters(attestationType.(string), parameters)
	}

	if required, exists := attestationMap["required"]; exists {
		requirement.Required = required.(bool)
	}

	return requirement, nil
}

// processTemplateEnforcement processes template enforcement with parameter substitution
func (pte *PolicyTemplateEngine) processTemplateEnforcement(enforcement interface{}, parameters map[string]interface{}) (*parser.EnforcementConfig, error) {
	// Convert enforcement interface to map for processing
	enforcementMap, ok := enforcement.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("enforcement must be a map/object")
	}

	// Create enforcement config
	config := &parser.EnforcementConfig{}

	// Process enforcement fields with parameter substitution
	if level, exists := enforcementMap["level"]; exists {
		config.Level = pte.substituteParameters(level.(string), parameters)
	}

	if actions, exists := enforcementMap["actions"]; exists {
		if actionsList, ok := actions.([]interface{}); ok {
			config.Actions = make([]string, len(actionsList))
			for i, action := range actionsList {
				config.Actions[i] = pte.substituteParameters(action.(string), parameters)
			}
		}
	}

	return config, nil
}

// processTemplatePredicate processes a template predicate with parameter substitution
func (pte *PolicyTemplateEngine) processTemplatePredicate(predicate interface{}, parameters map[string]interface{}) (*parser.Predicate, error) {
	// This would be a complex implementation to handle predicate templates
	// For now, return a basic predicate
	return &parser.Predicate{}, nil
}

// substituteParameters performs parameter substitution in strings
func (pte *PolicyTemplateEngine) substituteParameters(template string, parameters map[string]interface{}) string {
	result := template

	// Simple parameter substitution using ${parameter_name} syntax
	for paramName, paramValue := range parameters {
		placeholder := fmt.Sprintf("${%s}", paramName)
		replacement := fmt.Sprintf("%v", paramValue)
		result = strings.ReplaceAll(result, placeholder, replacement)
	}

	return result
}

// mergeEnforcementConfigs merges two enforcement configurations
func (pte *PolicyTemplateEngine) mergeEnforcementConfigs(base, override *parser.EnforcementConfig) {
	// Override level if specified
	if override.Level != "" {
		base.Level = override.Level
	}

	// Merge actions (append new ones)
	for _, action := range override.Actions {
		// Check if action already exists
		exists := false
		for _, existingAction := range base.Actions {
			if existingAction == action {
				exists = true
				break
			}
		}
		if !exists {
			base.Actions = append(base.Actions, action)
		}
	}
}

// deepCopyPolicy creates a deep copy of a policy for template application
func (pte *PolicyTemplateEngine) deepCopyPolicy(policy *parser.CompliancePolicy) *parser.CompliancePolicy {
	// Create a shallow copy for now
	// In a full implementation, this would create a complete deep copy
	copied := *policy

	// Deep copy slices
	copied.Rules = make([]*parser.PolicyRule, len(policy.Rules))
	copy(copied.Rules, policy.Rules)

	copied.Attestations = make([]*parser.AttestationRequirement, len(policy.Attestations))
	copy(copied.Attestations, policy.Attestations)

	return &copied
}

// Helper functions

// getParameterType determines the type of a parameter value
func getParameterType(value interface{}) string {
	switch value.(type) {
	case string:
		return "string"
	case int, int32, int64, float32, float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

// Template registry methods

// RegisterTemplate registers a template in the registry
func (tr *TemplateRegistry) RegisterTemplate(template *PolicyTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID cannot be empty")
	}

	tr.templates[template.ID] = template

	// Update version tracking
	if tr.versions[template.ID] == nil {
		tr.versions[template.ID] = make(map[string]*PolicyTemplate)
	}
	tr.versions[template.ID][template.Version] = template

	return nil
}

// GetTemplate retrieves a template by ID
func (tr *TemplateRegistry) GetTemplate(templateID string) (*PolicyTemplate, error) {
	template, exists := tr.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template '%s' not found", templateID)
	}
	return template, nil
}

// GetTemplateVersion retrieves a specific version of a template
func (tr *TemplateRegistry) GetTemplateVersion(templateID, version string) (*PolicyTemplate, error) {
	versions, exists := tr.versions[templateID]
	if !exists {
		return nil, fmt.Errorf("template '%s' not found", templateID)
	}

	template, exists := versions[version]
	if !exists {
		return nil, fmt.Errorf("template '%s' version '%s' not found", templateID, version)
	}

	return template, nil
}

// ListTemplates returns all registered templates
func (tr *TemplateRegistry) ListTemplates() map[string]*PolicyTemplate {
	return tr.templates
}

// ListTemplatesByCategory returns templates in a specific category
func (tr *TemplateRegistry) ListTemplatesByCategory(category string) ([]*PolicyTemplate, error) {
	templateIDs, exists := tr.categories[category]
	if !exists {
		return nil, fmt.Errorf("category '%s' not found", category)
	}

	templates := make([]*PolicyTemplate, 0, len(templateIDs))
	for _, templateID := range templateIDs {
		if template, exists := tr.templates[templateID]; exists {
			templates = append(templates, template)
		}
	}

	return templates, nil
}
