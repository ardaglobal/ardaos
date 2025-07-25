package types

import (
	"time"
)

type Policy struct {
	Metadata PolicyMetadata `yaml:"metadata" json:"metadata"`
	Spec     PolicySpec     `yaml:"spec" json:"spec"`
}

type PolicyMetadata struct {
	Name        string            `yaml:"name" json:"name"`
	Version     string            `yaml:"version" json:"version"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Region      string            `yaml:"region" json:"region"`
	AssetType   string            `yaml:"asset_type" json:"asset_type"`
	CreatedAt   time.Time         `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt   time.Time         `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

type PolicySpec struct {
	Rules       []Rule            `yaml:"rules" json:"rules"`
	Conditions  []Condition       `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Actions     []Action          `yaml:"actions,omitempty" json:"actions,omitempty"`
	Limits      map[string]Limit  `yaml:"limits,omitempty" json:"limits,omitempty"`
	Constraints map[string]string `yaml:"constraints,omitempty" json:"constraints,omitempty"`
	Settings    PolicySettings    `yaml:"settings,omitempty" json:"settings,omitempty"`
}

type Rule struct {
	ID          string      `yaml:"id" json:"id"`
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Type        RuleType    `yaml:"type" json:"type"`
	Condition   string      `yaml:"condition" json:"condition"`
	Action      string      `yaml:"action" json:"action"`
	Priority    int         `yaml:"priority,omitempty" json:"priority,omitempty"`
	Enabled     bool        `yaml:"enabled" json:"enabled"`
	Parameters  []Parameter `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type RuleType string

const (
	RuleTypeValidation   RuleType = "validation"
	RuleTypeLimit        RuleType = "limit"
	RuleTypeRestriction  RuleType = "restriction"
	RuleTypeRequirement  RuleType = "requirement"
	RuleTypeNotification RuleType = "notification"
)

type Condition struct {
	ID         string            `yaml:"id" json:"id"`
	Name       string            `yaml:"name" json:"name"`
	Expression string            `yaml:"expression" json:"expression"`
	Parameters map[string]string `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type Action struct {
	ID         string            `yaml:"id" json:"id"`
	Name       string            `yaml:"name" json:"name"`
	Type       ActionType        `yaml:"type" json:"type"`
	Handler    string            `yaml:"handler" json:"handler"`
	Parameters map[string]string `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type ActionType string

const (
	ActionTypeAllow    ActionType = "allow"
	ActionTypeDeny     ActionType = "deny"
	ActionTypeRequire  ActionType = "require"
	ActionTypeNotify   ActionType = "notify"
	ActionTypeLog      ActionType = "log"
	ActionTypeEscalate ActionType = "escalate"
)

type Limit struct {
	Type     LimitType   `yaml:"type" json:"type"`
	Value    interface{} `yaml:"value" json:"value"`
	Period   string      `yaml:"period,omitempty" json:"period,omitempty"`
	Currency string      `yaml:"currency,omitempty" json:"currency,omitempty"`
}

type LimitType string

const (
	LimitTypeAmount     LimitType = "amount"
	LimitTypeCount      LimitType = "count"
	LimitTypeFrequency  LimitType = "frequency"
	LimitTypePercentage LimitType = "percentage"
)

type Parameter struct {
	Name        string      `yaml:"name" json:"name"`
	Type        string      `yaml:"type" json:"type"`
	Value       interface{} `yaml:"value" json:"value"`
	Required    bool        `yaml:"required,omitempty" json:"required,omitempty"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
}

type PolicySettings struct {
	DefaultAction    ActionType        `yaml:"default_action,omitempty" json:"default_action,omitempty"`
	StrictMode       bool              `yaml:"strict_mode,omitempty" json:"strict_mode,omitempty"`
	ContinueOnError  bool              `yaml:"continue_on_error,omitempty" json:"continue_on_error,omitempty"`
	LogLevel         string            `yaml:"log_level,omitempty" json:"log_level,omitempty"`
	NotificationUrls []string          `yaml:"notification_urls,omitempty" json:"notification_urls,omitempty"`
	Timeouts         map[string]string `yaml:"timeouts,omitempty" json:"timeouts,omitempty"`
}

type ComplianceResult struct {
	PolicyID    string            `json:"policy_id"`
	Version     string            `json:"version"`
	Status      ComplianceStatus  `json:"status"`
	Violations  []Violation       `json:"violations,omitempty"`
	Warnings    []Warning         `json:"warnings,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	ProcessedAt time.Time         `json:"processed_at"`
}

type ComplianceStatus string

const (
	StatusCompliant    ComplianceStatus = "compliant"
	StatusNonCompliant ComplianceStatus = "non_compliant"
	StatusPending      ComplianceStatus = "pending"
	StatusError        ComplianceStatus = "error"
)

type Violation struct {
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	Severity    Severity          `json:"severity"`
	Message     string            `json:"message"`
	Field       string            `json:"field,omitempty"`
	Value       interface{}       `json:"value,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
}

type Warning struct {
	RuleID   string            `json:"rule_id"`
	RuleName string            `json:"rule_name"`
	Message  string            `json:"message"`
	Field    string            `json:"field,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
}

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type TestData struct {
	TestCases []TestCase `json:"test_cases"`
}

type TestCase struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Input       map[string]interface{} `json:"input"`
	Expected    TestExpectation        `json:"expected"`
}

type TestExpectation struct {
	Pass   bool   `json:"pass"`
	Reason string `json:"reason,omitempty"`
}

type TestResults struct {
	Summary TestSummary  `json:"summary"`
	Cases   []TestResult `json:"cases"`
}

type TestSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

type TestResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // passed, failed, skipped
	Expected bool   `json:"expected"`
	Actual   bool   `json:"actual"`
	Reason   string `json:"reason,omitempty"`
	Duration string `json:"duration,omitempty"`
	ErrorMsg string `json:"error,omitempty"`
}
