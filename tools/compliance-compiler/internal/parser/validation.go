package parser

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ValidationError represents a YAML validation error with location information
type ValidationError struct {
	Field   string
	Message string
	Line    int
	Column  int
}

func (e *ValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d, column %d: %s: %s", e.Line, e.Column, e.Field, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string, line, column int) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
		Line:    line,
		Column:  column,
	}
}

// ValidationFieldSchema defines the expected schema for a field (validation-specific)
type ValidationFieldSchema struct {
	Type          string
	Required      bool
	Pattern       *regexp.Regexp
	MinValue      interface{}
	MaxValue      interface{}
	AllowedValues []interface{}
}

// ExpressionValue represents a parsed expression value (legacy format)
type ExpressionValue struct {
	Expression string
	Language   string
}

// ParsedExpression represents a fully parsed and validated expression
type ParsedExpression struct {
	Raw        string           // Original expression string
	Type       string           // Inferred result type
	Compiled   *ExpressionProto // Compiled protobuf representation
	FieldPaths []string         // Field paths referenced in expression
	Functions  []string         // Functions called in expression
}

// Parser validation functions

// isValidPolicyID validates policy ID format
func isValidPolicyID(policyID string) bool {
	// Policy ID should follow a specific format (e.g., alphanumeric with hyphens/underscores)
	pattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return pattern.MatchString(policyID) && len(policyID) >= 3 && len(policyID) <= 64
}

// isValidJurisdiction validates jurisdiction format
func isValidJurisdiction(jurisdiction string) bool {
	// Accept ISO 3166-1 alpha-2 codes or custom jurisdiction identifiers
	pattern := regexp.MustCompile(`^[A-Z]{2}$|^[a-zA-Z0-9_-]+$`)
	return pattern.MatchString(jurisdiction) && len(jurisdiction) >= 2 && len(jurisdiction) <= 32
}

// isValidAttestationType validates attestation type
func isValidAttestationType(attestationType string) bool {
	validTypes := []string{
		"kyc", "aml", "accredited_investor", "institutional", "regulatory_approval",
		"financial_statement", "credit_rating", "tax_status", "jurisdiction_proof",
		"identity_verification", "biometric_verification", "sanction_screening",
		"pep_check", "adverse_media", "custom",
	}

	for _, validType := range validTypes {
		if attestationType == validType {
			return true
		}
	}
	return false
}

// isValidEnforcementLevel validates enforcement level
func isValidEnforcementLevel(level string) bool {
	validLevels := []string{
		"disabled", "monitoring", "advisory", "warning", "soft_blocking",
		"blocking", "critical", "emergency",
	}

	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}

// isValidEnforcementAction validates enforcement action
func isValidEnforcementAction(action string) bool {
	validActions := []string{
		"log", "alert", "block_transaction", "freeze_account", "require_approval",
		"escalate", "audit_log", "notify_compliance", "notify_regulator",
		"quarantine_transaction", "delay_transaction", "suspend_account",
		"restrict_account", "flag_account", "trigger_remediation",
		"require_attestation", "force_compliance_check", "regulatory_filing",
		"legal_hold", "webhook", "api_call", "queue_message",
	}

	for _, validAction := range validActions {
		if action == validAction {
			return true
		}
	}
	return false
}

// Parser utility functions

// parseComparisonOperator parses a comparison operator string
func parseComparisonOperator(op string) (ComparisonOperator, error) {
	switch strings.ToLower(op) {
	case "eq", "equals", "==":
		return ComparisonOperator_COMPARISON_OPERATOR_EQUAL, nil
	case "ne", "not_equals", "!=", "<>":
		return ComparisonOperator_COMPARISON_OPERATOR_NOT_EQUAL, nil
	case "lt", "less_than", "<":
		return ComparisonOperator_COMPARISON_OPERATOR_LESS_THAN, nil
	case "gt", "greater_than", ">":
		return ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN, nil
	case "lte", "less_than_or_equal", "<=":
		return ComparisonOperator_COMPARISON_OPERATOR_LESS_THAN_OR_EQUAL, nil
	case "gte", "greater_than_or_equal", ">=":
		return ComparisonOperator_COMPARISON_OPERATOR_GREATER_THAN_OR_EQUAL, nil
	case "contains":
		return ComparisonOperator_COMPARISON_OPERATOR_CONTAINS, nil
	case "starts_with":
		return ComparisonOperator_COMPARISON_OPERATOR_STARTS_WITH, nil
	case "ends_with":
		return ComparisonOperator_COMPARISON_OPERATOR_ENDS_WITH, nil
	case "matches", "regex":
		return ComparisonOperator_COMPARISON_OPERATOR_MATCHES_REGEX, nil
	case "fuzzy_match":
		return ComparisonOperator_COMPARISON_OPERATOR_FUZZY_MATCH, nil
	case "approx_equal", "approximately_equal":
		return ComparisonOperator_COMPARISON_OPERATOR_APPROXIMATELY_EQUAL, nil
	default:
		return ComparisonOperator_COMPARISON_OPERATOR_UNSPECIFIED, fmt.Errorf("unknown comparison operator: %s", op)
	}
}

// parseTimeOperator parses a time operator string
func parseTimeOperator(op string) (TimeOperator, error) {
	switch strings.ToLower(op) {
	case "before":
		return TimeOperator_TIME_OPERATOR_BEFORE, nil
	case "after":
		return TimeOperator_TIME_OPERATOR_AFTER, nil
	case "within":
		return TimeOperator_TIME_OPERATOR_WITHIN, nil
	case "older_than":
		return TimeOperator_TIME_OPERATOR_OLDER_THAN, nil
	case "newer_than":
		return TimeOperator_TIME_OPERATOR_NEWER_THAN, nil
	case "same_day":
		return TimeOperator_TIME_OPERATOR_SAME_DAY, nil
	case "same_week":
		return TimeOperator_TIME_OPERATOR_SAME_WEEK, nil
	case "same_month":
		return TimeOperator_TIME_OPERATOR_SAME_MONTH, nil
	case "same_year":
		return TimeOperator_TIME_OPERATOR_SAME_YEAR, nil
	case "business_days_between":
		return TimeOperator_TIME_OPERATOR_BUSINESS_DAYS_BETWEEN, nil
	case "weekend":
		return TimeOperator_TIME_OPERATOR_WEEKEND, nil
	case "business_hour":
		return TimeOperator_TIME_OPERATOR_BUSINESS_HOUR, nil
	default:
		return TimeOperator_TIME_OPERATOR_UNSPECIFIED, fmt.Errorf("unknown time operator: %s", op)
	}
}

// parseExpressionLanguage parses an expression language string
func parseExpressionLanguage(lang string) (ExpressionLanguage, error) {
	switch strings.ToLower(lang) {
	case "cel":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_CEL, nil
	case "jsonpath":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_JSONPATH, nil
	case "jmespath":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_JMESPATH, nil
	case "javascript", "js":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_JAVASCRIPT, nil
	case "golang", "go":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_GOLANG, nil
	case "python", "py":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_PYTHON, nil
	case "sql":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_SQL, nil
	case "xpath":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_XPATH, nil
	case "regex":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_REGEX, nil
	case "mathematical", "math":
		return ExpressionLanguage_EXPRESSION_LANGUAGE_MATHEMATICAL, nil
	default:
		return ExpressionLanguage_EXPRESSION_LANGUAGE_UNSPECIFIED, fmt.Errorf("unknown expression language: %s", lang)
	}
}

// parseRegexFlag parses a regex flag string
func parseRegexFlag(flag string) (RegexFlag, error) {
	switch strings.ToLower(flag) {
	case "i", "case_insensitive":
		return RegexFlag_REGEX_FLAG_CASE_INSENSITIVE, nil
	case "m", "multiline":
		return RegexFlag_REGEX_FLAG_MULTILINE, nil
	case "s", "dot_all":
		return RegexFlag_REGEX_FLAG_DOT_ALL, nil
	case "u", "unicode":
		return RegexFlag_REGEX_FLAG_UNICODE, nil
	case "x", "extended":
		return RegexFlag_REGEX_FLAG_EXTENDED, nil
	default:
		return RegexFlag_REGEX_FLAG_UNSPECIFIED, fmt.Errorf("unknown regex flag: %s", flag)
	}
}

// parseAttestationType parses an attestation type string
func parseAttestationType(typeStr string) (AttestationType, error) {
	switch strings.ToLower(typeStr) {
	case "kyc":
		return AttestationType_ATTESTATION_TYPE_KYC, nil
	case "aml":
		return AttestationType_ATTESTATION_TYPE_AML, nil
	case "accredited_investor":
		return AttestationType_ATTESTATION_TYPE_ACCREDITED_INVESTOR, nil
	case "institutional":
		return AttestationType_ATTESTATION_TYPE_INSTITUTIONAL, nil
	case "regulatory_approval":
		return AttestationType_ATTESTATION_TYPE_REGULATORY_APPROVAL, nil
	case "financial_statement":
		return AttestationType_ATTESTATION_TYPE_FINANCIAL_STATEMENT, nil
	case "credit_rating":
		return AttestationType_ATTESTATION_TYPE_CREDIT_RATING, nil
	case "tax_status":
		return AttestationType_ATTESTATION_TYPE_TAX_STATUS, nil
	case "jurisdiction_proof":
		return AttestationType_ATTESTATION_TYPE_JURISDICTION_PROOF, nil
	case "identity_verification":
		return AttestationType_ATTESTATION_TYPE_IDENTITY_VERIFICATION, nil
	case "biometric_verification":
		return AttestationType_ATTESTATION_TYPE_BIOMETRIC_VERIFICATION, nil
	case "sanction_screening":
		return AttestationType_ATTESTATION_TYPE_SANCTION_SCREENING, nil
	case "pep_check":
		return AttestationType_ATTESTATION_TYPE_PEP_CHECK, nil
	case "adverse_media":
		return AttestationType_ATTESTATION_TYPE_ADVERSE_MEDIA, nil
	case "custom":
		return AttestationType_ATTESTATION_TYPE_CUSTOM, nil
	default:
		return AttestationType_ATTESTATION_TYPE_UNSPECIFIED, fmt.Errorf("unknown attestation type: %s", typeStr)
	}
}

// parseEnforcementLevel parses an enforcement level string
func parseEnforcementLevel(level string) (EnforcementLevel, error) {
	switch strings.ToLower(level) {
	case "disabled":
		return EnforcementLevel_ENFORCEMENT_LEVEL_DISABLED, nil
	case "monitoring":
		return EnforcementLevel_ENFORCEMENT_LEVEL_MONITORING, nil
	case "advisory":
		return EnforcementLevel_ENFORCEMENT_LEVEL_ADVISORY, nil
	case "warning":
		return EnforcementLevel_ENFORCEMENT_LEVEL_WARNING, nil
	case "soft_blocking":
		return EnforcementLevel_ENFORCEMENT_LEVEL_SOFT_BLOCKING, nil
	case "blocking":
		return EnforcementLevel_ENFORCEMENT_LEVEL_BLOCKING, nil
	case "critical":
		return EnforcementLevel_ENFORCEMENT_LEVEL_CRITICAL, nil
	case "emergency":
		return EnforcementLevel_ENFORCEMENT_LEVEL_EMERGENCY, nil
	default:
		return EnforcementLevel_ENFORCEMENT_LEVEL_UNSPECIFIED, fmt.Errorf("unknown enforcement level: %s", level)
	}
}

// parseEnforcementAction parses an enforcement action string
func parseEnforcementAction(action string) (EnforcementAction, error) {
	switch strings.ToLower(action) {
	case "log":
		return EnforcementAction_ENFORCEMENT_ACTION_LOG, nil
	case "alert":
		return EnforcementAction_ENFORCEMENT_ACTION_ALERT, nil
	case "block_transaction":
		return EnforcementAction_ENFORCEMENT_ACTION_BLOCK_TRANSACTION, nil
	case "freeze_account":
		return EnforcementAction_ENFORCEMENT_ACTION_FREEZE_ACCOUNT, nil
	case "require_approval":
		return EnforcementAction_ENFORCEMENT_ACTION_REQUIRE_APPROVAL, nil
	case "escalate":
		return EnforcementAction_ENFORCEMENT_ACTION_ESCALATE, nil
	case "audit_log":
		return EnforcementAction_ENFORCEMENT_ACTION_AUDIT_LOG, nil
	case "notify_compliance":
		return EnforcementAction_ENFORCEMENT_ACTION_NOTIFY_COMPLIANCE, nil
	case "notify_regulator":
		return EnforcementAction_ENFORCEMENT_ACTION_NOTIFY_REGULATOR, nil
	case "quarantine_transaction":
		return EnforcementAction_ENFORCEMENT_ACTION_QUARANTINE_TRANSACTION, nil
	case "delay_transaction":
		return EnforcementAction_ENFORCEMENT_ACTION_DELAY_TRANSACTION, nil
	case "suspend_account":
		return EnforcementAction_ENFORCEMENT_ACTION_SUSPEND_ACCOUNT, nil
	case "restrict_account":
		return EnforcementAction_ENFORCEMENT_ACTION_RESTRICT_ACCOUNT, nil
	case "flag_account":
		return EnforcementAction_ENFORCEMENT_ACTION_FLAG_ACCOUNT, nil
	case "trigger_remediation":
		return EnforcementAction_ENFORCEMENT_ACTION_TRIGGER_REMEDIATION, nil
	case "require_attestation":
		return EnforcementAction_ENFORCEMENT_ACTION_REQUIRE_ATTESTATION, nil
	case "force_compliance_check":
		return EnforcementAction_ENFORCEMENT_ACTION_FORCE_COMPLIANCE_CHECK, nil
	case "regulatory_filing":
		return EnforcementAction_ENFORCEMENT_ACTION_REGULATORY_FILING, nil
	case "legal_hold":
		return EnforcementAction_ENFORCEMENT_ACTION_LEGAL_HOLD, nil
	case "webhook":
		return EnforcementAction_ENFORCEMENT_ACTION_WEBHOOK, nil
	case "api_call":
		return EnforcementAction_ENFORCEMENT_ACTION_API_CALL, nil
	case "queue_message":
		return EnforcementAction_ENFORCEMENT_ACTION_QUEUE_MESSAGE, nil
	default:
		return EnforcementAction_ENFORCEMENT_ACTION_UNSPECIFIED, fmt.Errorf("unknown enforcement action: %s", action)
	}
}

// parseTimestamp parses various timestamp formats
func parseTimestamp(timestampData interface{}) (*timestamppb.Timestamp, error) {
	switch ts := timestampData.(type) {
	case string:
		// Try parsing common formats
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}

		for _, format := range formats {
			if t, err := time.Parse(format, ts); err == nil {
				return timestamppb.New(t), nil
			}
		}
		return nil, fmt.Errorf("unable to parse timestamp: %s", ts)

	case time.Time:
		return timestamppb.New(ts), nil

	case int64:
		// Assume Unix timestamp
		return timestamppb.New(time.Unix(ts, 0)), nil

	default:
		return nil, fmt.Errorf("unsupported timestamp type: %T", timestampData)
	}
}

// parseDuration parses duration in seconds from various formats
func parseDuration(durationData interface{}) (int64, error) {
	switch dur := durationData.(type) {
	case int:
		return int64(dur), nil
	case int64:
		return dur, nil
	case float64:
		return int64(dur), nil
	case string:
		// Try parsing as Go duration
		if d, err := time.ParseDuration(dur); err == nil {
			return int64(d.Seconds()), nil
		}
		return 0, fmt.Errorf("unable to parse duration: %s", dur)
	default:
		return 0, fmt.Errorf("unsupported duration type: %T", durationData)
	}
}

// convertToAny converts a value to protobuf Any type
func convertToAny(value interface{}) (*anypb.Any, error) {
	switch v := value.(type) {
	case string:
		return anypb.New(&wrapperspb.StringValue{Value: v})
	case int:
		return anypb.New(&wrapperspb.Int64Value{Value: int64(v)})
	case int32:
		return anypb.New(&wrapperspb.Int32Value{Value: v})
	case int64:
		return anypb.New(&wrapperspb.Int64Value{Value: v})
	case float32:
		return anypb.New(&wrapperspb.FloatValue{Value: v})
	case float64:
		return anypb.New(&wrapperspb.DoubleValue{Value: v})
	case bool:
		return anypb.New(&wrapperspb.BoolValue{Value: v})
	case ExpressionValue:
		// Convert expression to string for now
		return anypb.New(&wrapperspb.StringValue{Value: v.Expression})
	case ParsedExpression:
		// Convert parsed expression to protobuf format
		return anypb.New(v.Compiled)
	default:
		return nil, fmt.Errorf("unsupported value type: %T", value)
	}
}

// Path parsing utilities

// parsePathComponents splits a field path into components, handling complex syntax
func parsePathComponents(path string) ([]string, error) {
	var components []string
	var current strings.Builder
	var inBrackets, inParens int

	for i, char := range path {
		switch char {
		case '.':
			if inBrackets == 0 && inParens == 0 {
				if current.Len() > 0 {
					components = append(components, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(char)
			}
		case '[':
			inBrackets++
			current.WriteRune(char)
		case ']':
			inBrackets--
			if inBrackets < 0 {
				return nil, fmt.Errorf("unmatched ']' at position %d", i)
			}
			current.WriteRune(char)
		case '(':
			inParens++
			current.WriteRune(char)
		case ')':
			inParens--
			if inParens < 0 {
				return nil, fmt.Errorf("unmatched ')' at position %d", i)
			}
			current.WriteRune(char)
		default:
			current.WriteRune(char)
		}
	}

	if inBrackets != 0 {
		return nil, fmt.Errorf("unmatched '[' in path")
	}
	if inParens != 0 {
		return nil, fmt.Errorf("unmatched '(' in path")
	}

	if current.Len() > 0 {
		components = append(components, current.String())
	}

	return components, nil
}

// isExpression checks if a string looks like an expression
func isExpression(s string) bool {
	// Simple heuristics to detect expressions
	expressionIndicators := []string{
		"*", "+", "-", "/", "%", // Math operators
		"&&", "||", "!", // Logical operators
		"==", "!=", "<", ">", "<=", ">=", // Comparison operators
		"(", ")", // Function calls or grouping
		".", // Field access
	}

	for _, indicator := range expressionIndicators {
		if strings.Contains(s, indicator) {
			return true
		}
	}

	return false
}

// matchesPattern checks if a path matches a pattern (supports wildcards)
func matchesPattern(path, pattern string) bool {
	// Convert simple wildcard pattern to regex
	regexPattern := strings.ReplaceAll(pattern, "*", ".*")
	regexPattern = "^" + regexPattern + "$"

	if regex, err := regexp.Compile(regexPattern); err == nil {
		return regex.MatchString(path)
	}

	return false
}

// validateAgainstSchema validates a field path against its schema
func (p *YAMLParser) validateAgainstSchema(path string, schema FieldSchema) error {
	// This is a placeholder for schema validation logic
	// In a full implementation, this would validate the field type,
	// check patterns, validate ranges, etc.
	return nil
}

// wrapYAMLError wraps a YAML parsing error with additional context
func (p *YAMLParser) wrapYAMLError(err error, context string) error {
	return fmt.Errorf("%s: %w", context, err)
}

// Default configuration functions

// getDefaultFieldSchemas returns default field schemas for validation
func getDefaultFieldSchemas() map[string]FieldSchema {
	return map[string]FieldSchema{
		"loan.principal": {
			Type:     "number",
			Required: false,
			MinValue: 0,
		},
		"loan.debt_to_income_ratio": {
			Type:     "number",
			Required: false,
			MinValue: 0.0,
			MaxValue: 10.0,
		},
		"borrower.credit_score": {
			Type:     "number",
			Required: false,
			MinValue: 300,
			MaxValue: 850,
		},
		"borrower.annual_income": {
			Type:     "number",
			Required: false,
			MinValue: 0,
		},
	}
}

// getDefaultKnownPaths returns default known field paths
func getDefaultKnownPaths() []string {
	return []string{
		"loan.*",
		"borrower.*",
		"collateral.*",
		"transaction.*",
		"account.*",
		"compliance.*",
		"attestation.*",
	}
}
