package compiler

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
)

type Validator struct {
	strictMode bool
	errors     []string
	warnings   []string
}

func NewValidator() *Validator {
	return &Validator{
		strictMode: false,
		errors:     []string{},
		warnings:   []string{},
	}
}

func (v *Validator) SetStrictMode(strict bool) {
	v.strictMode = strict
}

func (v *Validator) ValidatePolicy(policy *types.Policy) error {
	logrus.Debugf("Validating policy: %s", policy.Metadata.Name)

	v.errors = []string{}
	v.warnings = []string{}

	// Validate metadata
	v.validateMetadata(&policy.Metadata)

	// Validate spec
	v.validateSpec(&policy.Spec)

	// Validate cross-references
	v.validateCrossReferences(policy)

	// Validate business logic
	v.validateBusinessLogic(policy)

	if len(v.errors) > 0 || (v.strictMode && len(v.warnings) > 0) {
		return &types.ValidationError{
			Errors:   v.errors,
			Warnings: v.warnings,
		}
	}

	if len(v.warnings) > 0 {
		logrus.Warnf("Policy validation completed with %d warnings", len(v.warnings))
	} else {
		logrus.Debugf("Policy validation completed successfully")
	}

	return nil
}

func (v *Validator) ValidatePolicies(policies []*types.Policy) error {
	logrus.Infof("Validating %d policies", len(policies))

	for i, policy := range policies {
		if err := v.ValidatePolicy(policy); err != nil {
			return fmt.Errorf("validation failed for policy %d (%s): %w", i, policy.Metadata.Name, err)
		}
	}

	// Validate cross-policy dependencies
	v.validatePolicyDependencies(policies)

	if len(v.errors) > 0 {
		return &types.ValidationError{
			Errors:   v.errors,
			Warnings: v.warnings,
		}
	}

	logrus.Infof("Successfully validated all %d policies", len(policies))
	return nil
}

func (v *Validator) validateMetadata(metadata *types.PolicyMetadata) {
	// Validate required fields
	if metadata.Name == "" {
		v.addError("metadata.name is required")
	} else {
		if !v.isValidPolicyName(metadata.Name) {
			v.addError("metadata.name must be a valid identifier (alphanumeric and hyphens only)")
		}
	}

	if metadata.Version == "" {
		v.addError("metadata.version is required")
	} else {
		if !v.isValidVersion(metadata.Version) {
			v.addError("metadata.version must follow semantic versioning (e.g., 1.0.0)")
		}
	}

	if metadata.Region == "" {
		v.addError("metadata.region is required")
	} else {
		if !v.isValidRegion(metadata.Region) {
			v.addWarning(fmt.Sprintf("metadata.region '%s' is not a recognized region code", metadata.Region))
		}
	}

	if metadata.AssetType == "" {
		v.addWarning("metadata.asset_type is recommended for better policy organization")
	} else {
		if !v.isValidAssetType(metadata.AssetType) {
			v.addWarning(fmt.Sprintf("metadata.asset_type '%s' is not a recognized asset type", metadata.AssetType))
		}
	}

	// Validate optional fields
	if metadata.Description == "" {
		v.addWarning("metadata.description is recommended for policy documentation")
	}
}

func (v *Validator) validateSpec(spec *types.PolicySpec) {
	// Validate rules
	if len(spec.Rules) == 0 {
		v.addError("spec.rules must contain at least one rule")
		return
	}

	ruleIDs := make(map[string]bool)
	for i, rule := range spec.Rules {
		v.validateRule(&rule, i)

		// Check for duplicate rule IDs
		if ruleIDs[rule.ID] {
			v.addError(fmt.Sprintf("duplicate rule ID '%s' at rule[%d]", rule.ID, i))
		}
		ruleIDs[rule.ID] = true
	}

	// Validate conditions
	conditionIDs := make(map[string]bool)
	for i, condition := range spec.Conditions {
		v.validateCondition(&condition, i)

		if conditionIDs[condition.ID] {
			v.addError(fmt.Sprintf("duplicate condition ID '%s' at condition[%d]", condition.ID, i))
		}
		conditionIDs[condition.ID] = true
	}

	// Validate actions
	actionIDs := make(map[string]bool)
	for i, action := range spec.Actions {
		v.validateAction(&action, i)

		if actionIDs[action.ID] {
			v.addError(fmt.Sprintf("duplicate action ID '%s' at action[%d]", action.ID, i))
		}
		actionIDs[action.ID] = true
	}

	// Validate limits
	v.validateLimits(spec.Limits)

	// Validate settings
	v.validateSettings(&spec.Settings)
}

func (v *Validator) validateRule(rule *types.Rule, index int) {
	prefix := fmt.Sprintf("rule[%d]", index)

	if rule.ID == "" {
		v.addError(fmt.Sprintf("%s.id is required", prefix))
	}

	if rule.Name == "" {
		v.addError(fmt.Sprintf("%s.name is required", prefix))
	}

	if rule.Type == "" {
		v.addError(fmt.Sprintf("%s.type is required", prefix))
	} else {
		if !v.isValidRuleType(rule.Type) {
			v.addError(fmt.Sprintf("%s.type '%s' is not valid", prefix, rule.Type))
		}
	}

	if rule.Condition == "" {
		v.addError(fmt.Sprintf("%s.condition is required", prefix))
	} else {
		v.validateExpression(rule.Condition, fmt.Sprintf("%s.condition", prefix))
	}

	if rule.Action == "" {
		v.addError(fmt.Sprintf("%s.action is required", prefix))
	}

	if rule.Priority < 0 {
		v.addWarning(fmt.Sprintf("%s.priority is negative, which may cause unexpected behavior", prefix))
	}

	if rule.Priority > 1000 {
		v.addWarning(fmt.Sprintf("%s.priority is very high (%d), consider using lower values", prefix, rule.Priority))
	}

	// Validate parameters
	for j, param := range rule.Parameters {
		v.validateParameter(&param, fmt.Sprintf("%s.parameters[%d]", prefix, j))
	}
}

func (v *Validator) validateCondition(condition *types.Condition, index int) {
	prefix := fmt.Sprintf("condition[%d]", index)

	if condition.ID == "" {
		v.addError(fmt.Sprintf("%s.id is required", prefix))
	}

	if condition.Name == "" {
		v.addWarning(fmt.Sprintf("%s.name is recommended", prefix))
	}

	if condition.Expression == "" {
		v.addError(fmt.Sprintf("%s.expression is required", prefix))
	} else {
		v.validateExpression(condition.Expression, fmt.Sprintf("%s.expression", prefix))
	}
}

func (v *Validator) validateAction(action *types.Action, index int) {
	prefix := fmt.Sprintf("action[%d]", index)

	if action.ID == "" {
		v.addError(fmt.Sprintf("%s.id is required", prefix))
	}

	if action.Name == "" {
		v.addWarning(fmt.Sprintf("%s.name is recommended", prefix))
	}

	if action.Type == "" {
		v.addError(fmt.Sprintf("%s.type is required", prefix))
	} else {
		if !v.isValidActionType(action.Type) {
			v.addError(fmt.Sprintf("%s.type '%s' is not valid", prefix, action.Type))
		}
	}

	if action.Handler == "" && action.Type != types.ActionTypeAllow && action.Type != types.ActionTypeDeny {
		v.addWarning(fmt.Sprintf("%s.handler is recommended for action type '%s'", prefix, action.Type))
	}
}

func (v *Validator) validateParameter(param *types.Parameter, prefix string) {
	if param.Name == "" {
		v.addError(fmt.Sprintf("%s.name is required", prefix))
	}

	if param.Type == "" {
		v.addError(fmt.Sprintf("%s.type is required", prefix))
	} else {
		if !v.isValidParameterType(param.Type) {
			v.addWarning(fmt.Sprintf("%s.type '%s' is not a recognized parameter type", prefix, param.Type))
		}
	}

	if param.Value == nil && param.Required {
		v.addError(fmt.Sprintf("%s.value is required when parameter is marked as required", prefix))
	}
}

func (v *Validator) validateLimits(limits map[string]types.Limit) {
	for name, limit := range limits {
		prefix := fmt.Sprintf("limits[%s]", name)

		if limit.Type == "" {
			v.addError(fmt.Sprintf("%s.type is required", prefix))
		} else {
			if !v.isValidLimitType(limit.Type) {
				v.addError(fmt.Sprintf("%s.type '%s' is not valid", prefix, limit.Type))
			}
		}

		if limit.Value == nil {
			v.addError(fmt.Sprintf("%s.value is required", prefix))
		}

		// Validate period for time-based limits
		if limit.Period != "" && !v.isValidPeriod(limit.Period) {
			v.addError(fmt.Sprintf("%s.period '%s' is not a valid time period", prefix, limit.Period))
		}

		// Validate currency for amount limits
		if limit.Type == types.LimitTypeAmount && limit.Currency == "" {
			v.addWarning(fmt.Sprintf("%s.currency is recommended for amount limits", prefix))
		}
	}
}

func (v *Validator) validateSettings(settings *types.PolicySettings) {
	if settings.DefaultAction != "" && !v.isValidActionType(settings.DefaultAction) {
		v.addError(fmt.Sprintf("settings.default_action '%s' is not valid", settings.DefaultAction))
	}

	if settings.LogLevel != "" && !v.isValidLogLevel(settings.LogLevel) {
		v.addWarning(fmt.Sprintf("settings.log_level '%s' is not a recognized log level", settings.LogLevel))
	}

	// Validate timeout values
	for key, timeout := range settings.Timeouts {
		if !v.isValidTimeout(timeout) {
			v.addError(fmt.Sprintf("settings.timeouts[%s] '%s' is not a valid timeout duration", key, timeout))
		}
	}
}

func (v *Validator) validateExpression(expression, prefix string) {
	// Basic syntax validation for expressions
	if strings.TrimSpace(expression) == "" {
		v.addError(fmt.Sprintf("%s cannot be empty", prefix))
		return
	}

	// Check for balanced parentheses
	if !v.hasBalancedParentheses(expression) {
		v.addError(fmt.Sprintf("%s has unbalanced parentheses", prefix))
	}

	// Check for common syntax errors
	if strings.Contains(expression, "&&&&") || strings.Contains(expression, "||||") {
		v.addError(fmt.Sprintf("%s contains invalid operator sequences", prefix))
	}
}

func (v *Validator) validateCrossReferences(policy *types.Policy) {
	// Collect all available condition and action IDs
	conditionIDs := make(map[string]bool)
	for _, condition := range policy.Spec.Conditions {
		conditionIDs[condition.ID] = true
	}

	actionIDs := make(map[string]bool)
	for _, action := range policy.Spec.Actions {
		actionIDs[action.ID] = true
	}

	// Validate rule references
	for i, rule := range policy.Spec.Rules {
		// Check if rule references conditions by ID
		if v.referencesCondition(rule.Condition) {
			conditionID := v.extractConditionID(rule.Condition)
			if conditionID != "" && !conditionIDs[conditionID] {
				v.addError(fmt.Sprintf("rule[%d].condition references unknown condition '%s'", i, conditionID))
			}
		}

		// Check if rule references actions by ID
		if v.referencesAction(rule.Action) {
			actionID := v.extractActionID(rule.Action)
			if actionID != "" && !actionIDs[actionID] {
				v.addError(fmt.Sprintf("rule[%d].action references unknown action '%s'", i, actionID))
			}
		}
	}
}

func (v *Validator) validateBusinessLogic(policy *types.Policy) {
	// Validate business logic consistency

	// Check for conflicting rules
	v.checkConflictingRules(policy.Spec.Rules)

	// Check for unreachable rules
	v.checkUnreachableRules(policy.Spec.Rules)

	// Validate limit consistency
	v.checkLimitConsistency(policy.Spec.Limits)
}

func (v *Validator) validatePolicyDependencies(policies []*types.Policy) {
	// Validate dependencies between policies
	policyNames := make(map[string]bool)
	for _, policy := range policies {
		policyNames[policy.Metadata.Name] = true
	}

	// Check for circular dependencies and missing dependencies
	// This is simplified - real implementation would build a dependency graph
}

// Helper validation methods

func (v *Validator) isValidPolicyName(name string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9-_]+$`, name)
	return matched
}

func (v *Validator) isValidVersion(version string) bool {
	matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+$`, version)
	return matched
}

func (v *Validator) isValidRegion(region string) bool {
	validRegions := []string{"US", "EU", "APAC", "CA", "UK", "AU", "JP"}
	for _, valid := range validRegions {
		if region == valid {
			return true
		}
	}
	return false
}

func (v *Validator) isValidAssetType(assetType string) bool {
	validTypes := []string{"loan", "equity", "bond", "derivative", "commodity", "currency"}
	for _, valid := range validTypes {
		if assetType == valid {
			return true
		}
	}
	return false
}

func (v *Validator) isValidRuleType(ruleType types.RuleType) bool {
	switch ruleType {
	case types.RuleTypeValidation, types.RuleTypeLimit, types.RuleTypeRestriction,
		types.RuleTypeRequirement, types.RuleTypeNotification:
		return true
	default:
		return false
	}
}

func (v *Validator) isValidActionType(actionType types.ActionType) bool {
	switch actionType {
	case types.ActionTypeAllow, types.ActionTypeDeny, types.ActionTypeRequire,
		types.ActionTypeNotify, types.ActionTypeLog, types.ActionTypeEscalate:
		return true
	default:
		return false
	}
}

func (v *Validator) isValidParameterType(paramType string) bool {
	validTypes := []string{"string", "int", "float", "bool", "array", "object"}
	for _, valid := range validTypes {
		if paramType == valid {
			return true
		}
	}
	return false
}

func (v *Validator) isValidLimitType(limitType types.LimitType) bool {
	switch limitType {
	case types.LimitTypeAmount, types.LimitTypeCount, types.LimitTypeFrequency, types.LimitTypePercentage:
		return true
	default:
		return false
	}
}

func (v *Validator) isValidPeriod(period string) bool {
	matched, _ := regexp.MatchString(`^\d+[smhd]$`, period)
	return matched
}

func (v *Validator) isValidLogLevel(logLevel string) bool {
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	for _, valid := range validLevels {
		if logLevel == valid {
			return true
		}
	}
	return false
}

func (v *Validator) isValidTimeout(timeout string) bool {
	matched, _ := regexp.MatchString(`^\d+[ms]?$`, timeout)
	return matched
}

func (v *Validator) hasBalancedParentheses(expression string) bool {
	count := 0
	for _, char := range expression {
		if char == '(' {
			count++
		} else if char == ')' {
			count--
			if count < 0 {
				return false
			}
		}
	}
	return count == 0
}

func (v *Validator) referencesCondition(condition string) bool {
	// Simple check for condition references - real implementation would parse properly
	return strings.Contains(condition, "@condition:")
}

func (v *Validator) referencesAction(action string) bool {
	// Simple check for action references - real implementation would parse properly
	return strings.Contains(action, "@action:")
}

func (v *Validator) extractConditionID(condition string) string {
	// Extract condition ID from reference - simplified implementation
	return ""
}

func (v *Validator) extractActionID(action string) string {
	// Extract action ID from reference - simplified implementation
	return ""
}

func (v *Validator) checkConflictingRules(rules []types.Rule) {
	// Check for rules that might conflict with each other
	// This is simplified - real implementation would analyze rule logic
}

func (v *Validator) checkUnreachableRules(rules []types.Rule) {
	// Check for rules that can never be executed due to priority or conditions
	// This is simplified - real implementation would analyze rule dependencies
}

func (v *Validator) checkLimitConsistency(limits map[string]types.Limit) {
	// Check that limits are consistent and don't contradict each other
	// This is simplified - real implementation would analyze limit relationships
}

func (v *Validator) addError(message string) {
	v.errors = append(v.errors, message)
	logrus.Debugf("Validation error: %s", message)
}

func (v *Validator) addWarning(message string) {
	v.warnings = append(v.warnings, message)
	logrus.Debugf("Validation warning: %s", message)
}
