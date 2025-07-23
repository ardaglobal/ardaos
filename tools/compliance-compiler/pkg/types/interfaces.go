package types

import (
	"context"
	"io"
)

type Parser interface {
	Parse(data []byte) (*Policy, error)
	ParseFile(filename string) (*Policy, error)
	ParseReader(reader io.Reader) (*Policy, error)
}

type Compiler interface {
	CompilePolicy(policy *Policy) (*CompiledPolicy, error)
	CompilePolicies(policies []*Policy) ([]*CompiledPolicy, error)
}

type Validator interface {
	ValidatePolicy(policy *Policy) error
	ValidatePolicies(policies []*Policy) error
	SetStrictMode(strict bool)
}

type Writer interface {
	Write(policy *CompiledPolicy) ([]byte, error)
	WriteToFile(policy *CompiledPolicy, filename string) error
	WriteToWriter(policy *CompiledPolicy, writer io.Writer) error
}

type TemplateGenerator interface {
	GenerateTemplate(config *GenerationConfig) (string, error)
	GetAvailableTypes() []TemplateType
	ValidateConfig(config *GenerationConfig) error
}

type PolicyEngine interface {
	EvaluatePolicy(ctx context.Context, policy *CompiledPolicy, data interface{}) (*ComplianceResult, error)
	EvaluatePolicies(ctx context.Context, policies []*CompiledPolicy, data interface{}) ([]*ComplianceResult, error)
}

type Tester interface {
	RunTests(policy *CompiledPolicy, testData *TestData) (*TestResults, error)
	RunSingleTest(policy *CompiledPolicy, testCase *TestCase) (*TestResult, error)
	SetVerbose(verbose bool)
	SetParallel(parallel bool)
}

type PolicyRepository interface {
	Store(policy *Policy) error
	Retrieve(name, version string) (*Policy, error)
	List(filters map[string]string) ([]*Policy, error)
	Delete(name, version string) error
	Exists(name, version string) (bool, error)
}

type CompiledPolicy struct {
	Metadata        *CompiledMetadata `json:"metadata"`
	CompiledRules   []*CompiledRule   `json:"compiled_rules"`
	RuntimeSettings map[string]string `json:"runtime_settings"`
	Bytecode        []byte            `json:"bytecode,omitempty"`
	Version         string            `json:"version"`
	CompilerVersion string            `json:"compiler_version"`
}

type CompiledMetadata struct {
	OriginalName    string            `json:"original_name"`
	CompilerVersion string            `json:"compiler_version"`
	CompiledAt      string            `json:"compiled_at"`
	Hash            string            `json:"hash"`
	Dependencies    []string          `json:"dependencies,omitempty"`
	Optimizations   []string          `json:"optimizations,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type CompiledRule struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Priority     int                    `json:"priority"`
	Condition    *CompiledCondition     `json:"condition"`
	Action       *CompiledAction        `json:"action"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	Optimized    bool                   `json:"optimized"`
	Dependencies []string               `json:"dependencies,omitempty"`
}

type CompiledCondition struct {
	Expression string                 `json:"expression"`
	Bytecode   []byte                 `json:"bytecode,omitempty"`
	Variables  []string               `json:"variables,omitempty"`
	Functions  []string               `json:"functions,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type CompiledAction struct {
	Type       string                 `json:"type"`
	Handler    string                 `json:"handler"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type GenerationConfig struct {
	Type         string            `json:"type"`
	Region       string            `json:"region,omitempty"`
	AssetType    string            `json:"asset_type,omitempty"`
	BusinessType string            `json:"business_type,omitempty"`
	Features     []string          `json:"features,omitempty"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

type TemplateType struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	RequiredParams   []string `json:"required_params,omitempty"`
	OptionalParams   []string `json:"optional_params,omitempty"`
	SupportedRegions []string `json:"supported_regions,omitempty"`
	SupportedAssets  []string `json:"supported_assets,omitempty"`
}

type ValidationError struct {
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

func (e *ValidationError) Error() string {
	if len(e.Errors) > 0 {
		return e.Errors[0]
	}
	return "validation failed"
}

type CompilerError struct {
	PolicyName string `json:"policy_name"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
}

func (e *CompilerError) Error() string {
	return e.Message
}

type EngineOptions struct {
	StrictMode     bool              `json:"strict_mode"`
	DebugMode      bool              `json:"debug_mode"`
	MaxConcurrency int               `json:"max_concurrency"`
	Timeout        string            `json:"timeout"`
	CustomHandlers map[string]string `json:"custom_handlers,omitempty"`
}
