# ArdaOS Compliance Compiler - API Reference

## Table of Contents

- [Go Library Usage](#go-library-usage)
- [Core Types](#core-types)
- [Compiler API](#compiler-api)
- [Parser API](#parser-api)
- [Validator API](#validator-api)
- [Evaluation Engine](#evaluation-engine)
- [Integration Examples](#integration-examples)
- [Error Handling](#error-handling)
- [Thread Safety](#thread-safety)

## Go Library Usage

### Installation

Add the compliance compiler to your Go module:

```go
go get github.com/ardaos/arda-os/tools/compliance-compiler
```

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/compiler"
    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/parser"
)

func main() {
    // Create a new compiler instance
    comp := compiler.New()

    // Parse a policy from YAML
    policy, err := parser.ParsePolicyFromFile("policy.yaml")
    if err != nil {
        log.Fatal(err)
    }

    // Compile the policy
    compiled, err := comp.Compile(context.Background(), policy)
    if err != nil {
        log.Fatal(err)
    }

    // Create transaction data
    transaction := &compiler.TransactionData{
        ID:          "txn-001",
        AssetClass:  "InstallmentLoan",
        Amount:      25000.0,
        Currency:    "USD",
        Applicant: &compiler.ApplicantData{
            Age:         30,
            CreditScore: 720,
            AnnualIncome: 60000.0,
        },
    }

    // Evaluate the policy
    result, err := compiled.Evaluate(context.Background(), transaction)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Evaluation Result: %s\n", result.Decision)
    fmt.Printf("Compliance Score: %.2f\n", result.ComplianceScore)
}
```

## Core Types

### PolicyTemplate

Represents policy metadata and classification information.

```go
type PolicyTemplate struct {
    Name                string    `yaml:"name" json:"name"`
    Version             string    `yaml:"version" json:"version"`
    AssetClass          string    `yaml:"asset_class" json:"asset_class"`
    Jurisdiction        string    `yaml:"jurisdiction" json:"jurisdiction"`
    RegulatoryFramework []string  `yaml:"regulatory_framework" json:"regulatory_framework"`
    Description         string    `yaml:"description,omitempty" json:"description,omitempty"`
    Author              string    `yaml:"author,omitempty" json:"author,omitempty"`
    LastUpdated         string    `yaml:"last_updated,omitempty" json:"last_updated,omitempty"`
    Tags                []string  `yaml:"tags,omitempty" json:"tags,omitempty"`
    Extends             string    `yaml:"extends,omitempty" json:"extends,omitempty"`
}

// Methods
func (pt *PolicyTemplate) Validate() error
func (pt *PolicyTemplate) GetEffectiveVersion() string
func (pt *PolicyTemplate) SupportsAssetClass(assetClass string) bool
func (pt *PolicyTemplate) SupportsJurisdiction(jurisdiction string) bool
```

### PolicyParams

Represents configurable policy parameters.

```go
type PolicyParams map[string]PolicyParam

type PolicyParam struct {
    Type        string      `yaml:"type" json:"type"`
    Default     interface{} `yaml:"default,omitempty" json:"default,omitempty"`
    Description string      `yaml:"description,omitempty" json:"description,omitempty"`
    Min         interface{} `yaml:"min,omitempty" json:"min,omitempty"`
    Max         interface{} `yaml:"max,omitempty" json:"max,omitempty"`
    MinLength   *int        `yaml:"minLength,omitempty" json:"minLength,omitempty"`
    MaxLength   *int        `yaml:"maxLength,omitempty" json:"maxLength,omitempty"`
    Enum        []string    `yaml:"enum,omitempty" json:"enum,omitempty"`
    Pattern     string      `yaml:"pattern,omitempty" json:"pattern,omitempty"`
    Required    bool        `yaml:"required,omitempty" json:"required,omitempty"`
}

// Methods
func (pp PolicyParams) Get(name string) (PolicyParam, bool)
func (pp PolicyParams) GetWithDefault(name string, defaultValue interface{}) interface{}
func (pp PolicyParams) Validate() error
func (pp PolicyParams) ResolveValue(name string, context map[string]interface{}) (interface{}, error)
```

### PolicyRule

Represents individual compliance rules.

```go
type PolicyRule struct {
    ID          string                 `yaml:"id" json:"id"`
    Name        string                 `yaml:"name" json:"name"`
    Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
    Type        string                 `yaml:"type" json:"type"`
    Priority    string                 `yaml:"priority" json:"priority"`
    Enabled     bool                   `yaml:"enabled" json:"enabled"`
    Conditions  []string               `yaml:"conditions" json:"conditions"`
    Actions     []string               `yaml:"actions" json:"actions"`
    Metadata    map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Methods
func (pr *PolicyRule) Validate() error
func (pr *PolicyRule) GetPriorityLevel() int
func (pr *PolicyRule) IsEnabled() bool
func (pr *PolicyRule) HasCondition(condition string) bool
func (pr *PolicyRule) HasAction(action string) bool
```

### TransactionData

Represents transaction data for policy evaluation.

```go
type TransactionData struct {
    ID                  string                 `json:"id"`
    AssetClass         string                 `json:"asset_class"`
    Jurisdiction       string                 `json:"jurisdiction"`
    Amount             float64                `json:"amount"`
    Currency           string                 `json:"currency"`
    Timestamp          time.Time              `json:"timestamp"`
    Applicant          *ApplicantData         `json:"applicant"`
    ApplicationData    *ApplicationData       `json:"application_data"`
    RiskMetrics        *RiskMetrics           `json:"risk_metrics"`
    ComplianceChecks   *ComplianceChecks      `json:"compliance_checks"`
    CustomFields       map[string]interface{} `json:"custom_fields,omitempty"`
}

// Methods
func (td *TransactionData) Validate() error
func (td *TransactionData) GetFieldValue(path string) (interface{}, error)
func (td *TransactionData) SetFieldValue(path string, value interface{}) error
func (td *TransactionData) ToMap() map[string]interface{}
```

### ApplicantData

Represents applicant information.

```go
type ApplicantData struct {
    Age                    int     `json:"age"`
    AnnualIncome          float64 `json:"annual_income"`
    EmploymentStatus      string  `json:"employment_status"`
    EmploymentLengthMonths int     `json:"employment_length_months"`
    CreditScore           int     `json:"credit_score"`
    DebtToIncomeRatio     float64 `json:"debt_to_income_ratio"`
    ExistingCreditAccounts int     `json:"existing_credit_accounts"`
    PaymentHistory        string  `json:"payment_history"`
    BankruptcyHistory     bool    `json:"bankruptcy_history"`
    MilitaryStatus        bool    `json:"military_status"`
    // Additional fields...
}

// Methods
func (ad *ApplicantData) Validate() error
func (ad *ApplicantData) GetCreditTier() string
func (ad *ApplicantData) IsQualifiedBorrower() bool
func (ad *ApplicantData) CalculateDebtServiceRatio(monthlyPayment float64) float64
```

### EvaluationResult

Represents the result of policy evaluation.

```go
type EvaluationResult struct {
    TransactionID    string              `json:"transaction_id"`
    PolicyID         string              `json:"policy_id"`
    PolicyVersion    string              `json:"policy_version"`
    Decision         Decision            `json:"decision"`
    ComplianceScore  float64             `json:"compliance_score"`
    RuleResults      []RuleResult        `json:"rule_results"`
    Attestations     []AttestationResult `json:"attestations"`
    Timestamp        time.Time           `json:"timestamp"`
    ProcessingTime   time.Duration       `json:"processing_time"`
    Errors           []string            `json:"errors,omitempty"`
    Warnings         []string            `json:"warnings,omitempty"`
    Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type Decision string

const (
    DecisionApproved         Decision = "approved"
    DecisionDenied          Decision = "denied"
    DecisionConditional     Decision = "conditional"
    DecisionPending         Decision = "pending"
    DecisionManualReview    Decision = "manual_review"
)

// Methods
func (er *EvaluationResult) IsApproved() bool
func (er *EvaluationResult) HasErrors() bool
func (er *EvaluationResult) HasWarnings() bool
func (er *EvaluationResult) GetFailedRules() []RuleResult
func (er *EvaluationResult) GetPendingAttestations() []AttestationResult
```

## Compiler API

### Compiler Interface

The main compiler interface for policy compilation.

```go
type Compiler interface {
    // Compile compiles a parsed policy into executable format
    Compile(ctx context.Context, policy *ParsedPolicy) (*CompiledPolicy, error)

    // CompileWithOptions compiles with specific options
    CompileWithOptions(ctx context.Context, policy *ParsedPolicy, opts CompileOptions) (*CompiledPolicy, error)

    // Validate validates a policy before compilation
    Validate(ctx context.Context, policy *ParsedPolicy) error

    // GetVersion returns the compiler version
    GetVersion() string

    // GetSupportedFormats returns supported output formats
    GetSupportedFormats() []string
}
```

### Creating a Compiler

```go
// Create a new compiler with default options
func New() Compiler

// Create a compiler with custom options
func NewWithOptions(opts CompilerOptions) Compiler

type CompilerOptions struct {
    OptimizationLevel   int                    `json:"optimization_level"`
    TargetFormat       string                 `json:"target_format"`
    IncludeDebugInfo   bool                   `json:"include_debug_info"`
    MaxRuleDepth       int                    `json:"max_rule_depth"`
    EnableCaching      bool                   `json:"enable_caching"`
    CacheConfig        *CacheConfig           `json:"cache_config,omitempty"`
    Logger             Logger                 `json:"-"`
    Hooks              CompilerHooks          `json:"-"`
    CustomFunctions    map[string]Function    `json:"-"`
}

type CompileOptions struct {
    OutputFormat      string            `json:"output_format"`
    Optimize         bool              `json:"optimize"`
    IncludeSource    bool              `json:"include_source"`
    ValidationLevel  ValidationLevel   `json:"validation_level"`
    Context          map[string]interface{} `json:"context,omitempty"`
}
```

### Example Usage

```go
// Basic compilation
compiler := compiler.New()
compiled, err := compiler.Compile(ctx, policy)
if err != nil {
    return fmt.Errorf("compilation failed: %w", err)
}

// Compilation with options
opts := compiler.CompileOptions{
    OutputFormat:    "protobuf",
    Optimize:        true,
    IncludeSource:   true,
    ValidationLevel: compiler.ValidationStrict,
}
compiled, err := compiler.CompileWithOptions(ctx, policy, opts)

// Validation before compilation
if err := compiler.Validate(ctx, policy); err != nil {
    return fmt.Errorf("policy validation failed: %w", err)
}
```

### CompiledPolicy

```go
type CompiledPolicy struct {
    ID               string                 `json:"id"`
    Version          string                 `json:"version"`
    Template         *PolicyTemplate        `json:"template"`
    CompiledRules    []CompiledRule         `json:"compiled_rules"`
    Parameters       PolicyParams           `json:"parameters"`
    Attestations     []Attestation          `json:"attestations"`
    ExecutionPlan    *ExecutionPlan         `json:"execution_plan"`
    Metadata         map[string]interface{} `json:"metadata"`
    CompiledAt       time.Time              `json:"compiled_at"`
    CompilerVersion  string                 `json:"compiler_version"`
}

// Methods
func (cp *CompiledPolicy) Evaluate(ctx context.Context, transaction *TransactionData) (*EvaluationResult, error)
func (cp *CompiledPolicy) ValidateTransaction(transaction *TransactionData) error
func (cp *CompiledPolicy) GetExecutionStats() ExecutionStats
func (cp *CompiledPolicy) Export(format string) ([]byte, error)
func (cp *CompiledPolicy) GetChecksum() string
```

## Parser API

### Parser Interface

```go
type Parser interface {
    // ParsePolicy parses a policy from YAML bytes
    ParsePolicy(data []byte) (*ParsedPolicy, error)

    // ParsePolicyFromFile parses a policy from a file
    ParsePolicyFromFile(filename string) (*ParsedPolicy, error)

    // ParsePolicyFromReader parses from an io.Reader
    ParsePolicyFromReader(reader io.Reader) (*ParsedPolicy, error)

    // ValidateSchema validates against policy schema
    ValidateSchema(policy *ParsedPolicy) error

    // GetSchemaVersion returns the supported schema version
    GetSchemaVersion() string
}
```

### Creating a Parser

```go
// Create a new parser with default options
func NewParser() Parser

// Create parser with custom options
func NewParserWithOptions(opts ParserOptions) Parser

type ParserOptions struct {
    StrictMode        bool              `json:"strict_mode"`
    AllowUnknownFields bool             `json:"allow_unknown_fields"`
    SchemaValidation  bool              `json:"schema_validation"`
    CustomValidators  []Validator       `json:"-"`
    Logger           Logger            `json:"-"`
}
```

### Example Usage

```go
// Parse from file
parser := parser.NewParser()
policy, err := parser.ParsePolicyFromFile("policy.yaml")
if err != nil {
    return fmt.Errorf("parsing failed: %w", err)
}

// Parse from bytes with validation
data, err := ioutil.ReadFile("policy.yaml")
if err != nil {
    return err
}

policy, err := parser.ParsePolicy(data)
if err != nil {
    return fmt.Errorf("parsing failed: %w", err)
}

// Validate schema
if err := parser.ValidateSchema(policy); err != nil {
    return fmt.Errorf("schema validation failed: %w", err)
}
```

### ParsedPolicy

```go
type ParsedPolicy struct {
    Template     PolicyTemplate  `yaml:"template" json:"template"`
    Parameters   PolicyParams    `yaml:"parameters,omitempty" json:"parameters,omitempty"`
    Policy       PolicyRules     `yaml:"policy" json:"policy"`
    SourceFile   string          `json:"source_file,omitempty"`
    ParsedAt     time.Time       `json:"parsed_at"`
    Checksum     string          `json:"checksum"`
}

// Methods
func (pp *ParsedPolicy) Validate() error
func (pp *ParsedPolicy) GetRuleByID(id string) (*PolicyRule, bool)
func (pp *ParsedPolicy) GetAttestationByID(id string) (*Attestation, bool)
func (pp *ParsedPolicy) ToYAML() ([]byte, error)
func (pp *ParsedPolicy) ToJSON() ([]byte, error)
```

## Validator API

### Validator Interface

```go
type Validator interface {
    // Validate validates a parsed policy
    Validate(ctx context.Context, policy *ParsedPolicy) (*ValidationResult, error)

    // ValidateRule validates a specific rule
    ValidateRule(ctx context.Context, rule *PolicyRule, context *ValidationContext) error

    // ValidateCondition validates a condition expression
    ValidateCondition(condition string, context *ValidationContext) error

    // GetValidationRules returns available validation rules
    GetValidationRules() []ValidationRule
}
```

### Creating a Validator

```go
// Create validator with default rules
func NewValidator() Validator

// Create validator with custom configuration
func NewValidatorWithConfig(config ValidatorConfig) Validator

type ValidatorConfig struct {
    StrictMode       bool                `json:"strict_mode"`
    FailOnWarnings   bool                `json:"fail_on_warnings"`
    CustomRules      []ValidationRule    `json:"custom_rules"`
    DisabledRules    []string           `json:"disabled_rules"`
    MaxComplexity    int                `json:"max_complexity"`
    TimeoutDuration  time.Duration      `json:"timeout_duration"`
}
```

### ValidationResult

```go
type ValidationResult struct {
    Valid        bool               `json:"valid"`
    Errors       []ValidationError  `json:"errors"`
    Warnings     []ValidationError  `json:"warnings"`
    Info         []ValidationError  `json:"info"`
    Summary      ValidationSummary  `json:"summary"`
    ValidatedAt  time.Time          `json:"validated_at"`
    Duration     time.Duration      `json:"duration"`
}

type ValidationError struct {
    Rule     string      `json:"rule"`
    Message  string      `json:"message"`
    Path     string      `json:"path"`
    Severity string      `json:"severity"`
    Line     int         `json:"line,omitempty"`
    Column   int         `json:"column,omitempty"`
    Value    interface{} `json:"value,omitempty"`
    Expected interface{} `json:"expected,omitempty"`
}

// Methods
func (vr *ValidationResult) HasErrors() bool
func (vr *ValidationResult) HasWarnings() bool
func (vr *ValidationResult) GetErrorsByRule(rule string) []ValidationError
func (vr *ValidationResult) String() string
```

### Example Usage

```go
// Basic validation
validator := validator.NewValidator()
result, err := validator.Validate(ctx, policy)
if err != nil {
    return fmt.Errorf("validation failed: %w", err)
}

if !result.Valid {
    for _, error := range result.Errors {
        fmt.Printf("Error: %s at %s\n", error.Message, error.Path)
    }
}

// Validate individual rule
rule := &PolicyRule{
    ID:         "test_rule",
    Conditions: []string{"applicant.age >= 18"},
    Actions:    []string{"approve"},
}

ctx := &ValidationContext{
    AssetClass:   "InstallmentLoan",
    Jurisdiction: "USA",
}

if err := validator.ValidateRule(ctx, rule, ctx); err != nil {
    return fmt.Errorf("rule validation failed: %w", err)
}
```

## Evaluation Engine

### Engine Interface

```go
type Engine interface {
    // Evaluate evaluates a compiled policy against transaction data
    Evaluate(ctx context.Context, policy *CompiledPolicy, transaction *TransactionData) (*EvaluationResult, error)

    // EvaluateRule evaluates a specific rule
    EvaluateRule(ctx context.Context, rule *CompiledRule, transaction *TransactionData) (*RuleResult, error)

    // EvaluateCondition evaluates a condition expression
    EvaluateCondition(condition string, context map[string]interface{}) (bool, error)

    // RegisterFunction registers a custom function
    RegisterFunction(name string, fn Function) error

    // GetStatistics returns engine statistics
    GetStatistics() EngineStatistics
}
```

### Creating an Engine

```go
// Create engine with default configuration
func NewEngine() Engine

// Create engine with custom configuration
func NewEngineWithConfig(config EngineConfig) Engine

type EngineConfig struct {
    MaxConcurrentRules  int                    `json:"max_concurrent_rules"`
    RuleTimeout        time.Duration           `json:"rule_timeout"`
    EnableCaching      bool                    `json:"enable_caching"`
    CacheSize          int                     `json:"cache_size"`
    EnableMetrics      bool                    `json:"enable_metrics"`
    MetricsCollector   MetricsCollector        `json:"-"`
    Logger            Logger                  `json:"-"`
    CustomFunctions   map[string]Function     `json:"-"`
    Hooks             EngineHooks             `json:"-"`
}
```

### RuleResult

```go
type RuleResult struct {
    RuleID           string                 `json:"rule_id"`
    RuleName         string                 `json:"rule_name"`
    Status           RuleStatus             `json:"status"`
    Passed           bool                   `json:"passed"`
    ExecutionTime    time.Duration          `json:"execution_time"`
    ConditionResults []ConditionResult      `json:"condition_results"`
    ActionsExecuted  []string               `json:"actions_executed"`
    ErrorMessage     string                 `json:"error_message,omitempty"`
    Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type RuleStatus string

const (
    RuleStatusPassed    RuleStatus = "passed"
    RuleStatusFailed    RuleStatus = "failed"
    RuleStatusSkipped   RuleStatus = "skipped"
    RuleStatusError     RuleStatus = "error"
    RuleStatusPending   RuleStatus = "pending"
)

type ConditionResult struct {
    Condition    string        `json:"condition"`
    Passed       bool          `json:"passed"`
    Value        interface{}   `json:"value"`
    Expected     interface{}   `json:"expected,omitempty"`
    ErrorMessage string        `json:"error_message,omitempty"`
}
```

### Example Usage

```go
// Create and configure engine
engine := engine.NewEngineWithConfig(engine.EngineConfig{
    MaxConcurrentRules: 4,
    RuleTimeout:       30 * time.Second,
    EnableCaching:     true,
    EnableMetrics:     true,
})

// Register custom function
engine.RegisterFunction("calculate_payment", func(principal, rate, term float64) float64 {
    monthlyRate := rate / 12
    return principal * (monthlyRate * math.Pow(1+monthlyRate, term)) / (math.Pow(1+monthlyRate, term) - 1)
})

// Evaluate policy
result, err := engine.Evaluate(ctx, compiledPolicy, transaction)
if err != nil {
    return fmt.Errorf("evaluation failed: %w", err)
}

// Process results
switch result.Decision {
case engine.DecisionApproved:
    fmt.Println("Application approved!")
case engine.DecisionDenied:
    fmt.Printf("Application denied. Failed rules: %v\n", result.GetFailedRules())
case engine.DecisionConditional:
    fmt.Printf("Application approved with conditions. Pending attestations: %v\n", result.GetPendingAttestations())
}
```

## Integration Examples

### Basic Integration

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/compiler"
    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/engine"
    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/parser"
)

type LendingService struct {
    compiler compiler.Compiler
    engine   engine.Engine
    policies map[string]*compiler.CompiledPolicy
}

func NewLendingService() *LendingService {
    return &LendingService{
        compiler: compiler.New(),
        engine:   engine.NewEngine(),
        policies: make(map[string]*compiler.CompiledPolicy),
    }
}

func (ls *LendingService) LoadPolicy(name, filename string) error {
    // Parse policy
    parser := parser.NewParser()
    policy, err := parser.ParsePolicyFromFile(filename)
    if err != nil {
        return fmt.Errorf("failed to parse policy: %w", err)
    }

    // Compile policy
    compiled, err := ls.compiler.Compile(context.Background(), policy)
    if err != nil {
        return fmt.Errorf("failed to compile policy: %w", err)
    }

    // Store compiled policy
    ls.policies[name] = compiled
    return nil
}

func (ls *LendingService) EvaluateApplication(policyName string, transaction *compiler.TransactionData) (*compiler.EvaluationResult, error) {
    policy, exists := ls.policies[policyName]
    if !exists {
        return nil, fmt.Errorf("policy %s not found", policyName)
    }

    return ls.engine.Evaluate(context.Background(), policy, transaction)
}

// Usage
func main() {
    service := NewLendingService()

    // Load policies
    if err := service.LoadPolicy("installment_loan", "policies/installment-loan.yaml"); err != nil {
        log.Fatal(err)
    }

    // Process application
    transaction := &compiler.TransactionData{
        ID:         "app-001",
        AssetClass: "InstallmentLoan",
        Amount:     25000.0,
        Applicant: &compiler.ApplicantData{
            Age:         30,
            CreditScore: 720,
            AnnualIncome: 60000.0,
        },
    }

    result, err := service.EvaluateApplication("installment_loan", transaction)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decision: %s\n", result.Decision)
}
```

### Advanced Integration with Caching

```go
package main

import (
    "context"
    "sync"
    "time"

    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/compiler"
    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/engine"
    "github.com/patrickmn/go-cache"
)

type CachedComplianceService struct {
    compiler compiler.Compiler
    engine   engine.Engine
    cache    *cache.Cache
    policies sync.Map // thread-safe policy storage
}

func NewCachedComplianceService() *CachedComplianceService {
    // Create cache with 5 minute default expiration and 10 minute cleanup interval
    c := cache.New(5*time.Minute, 10*time.Minute)

    return &CachedComplianceService{
        compiler: compiler.NewWithOptions(compiler.CompilerOptions{
            EnableCaching:     true,
            OptimizationLevel: 2,
        }),
        engine: engine.NewEngineWithConfig(engine.EngineConfig{
            EnableCaching:      true,
            MaxConcurrentRules: 8,
            RuleTimeout:       30 * time.Second,
        }),
        cache: c,
    }
}

func (ccs *CachedComplianceService) EvaluateWithCaching(
    ctx context.Context,
    policyID string,
    transaction *compiler.TransactionData,
) (*compiler.EvaluationResult, error) {
    // Create cache key based on policy and transaction hash
    cacheKey := fmt.Sprintf("%s:%s", policyID, transaction.GetHash())

    // Check cache first
    if cached, found := ccs.cache.Get(cacheKey); found {
        return cached.(*compiler.EvaluationResult), nil
    }

    // Load policy
    policyInterface, exists := ccs.policies.Load(policyID)
    if !exists {
        return nil, fmt.Errorf("policy %s not found", policyID)
    }

    policy := policyInterface.(*compiler.CompiledPolicy)

    // Evaluate
    result, err := ccs.engine.Evaluate(ctx, policy, transaction)
    if err != nil {
        return nil, err
    }

    // Cache result (if successful)
    if result.Decision != compiler.DecisionError {
        ccs.cache.Set(cacheKey, result, cache.DefaultExpiration)
    }

    return result, nil
}

func (ccs *CachedComplianceService) WarmCache(policyID string, sampleTransactions []*compiler.TransactionData) error {
    ctx := context.Background()

    for _, transaction := range sampleTransactions {
        _, err := ccs.EvaluateWithCaching(ctx, policyID, transaction)
        if err != nil {
            return fmt.Errorf("failed to warm cache for transaction %s: %w", transaction.ID, err)
        }
    }

    return nil
}
```

### Microservice Integration

```go
package main

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/compiler"
    "github.com/ardaos/arda-os/tools/compliance-compiler/internal/engine"
)

type ComplianceAPI struct {
    service *ComplianceService
}

type ComplianceService struct {
    compiler compiler.Compiler
    engine   engine.Engine
    policies map[string]*compiler.CompiledPolicy
}

type EvaluationRequest struct {
    PolicyID    string                 `json:"policy_id"`
    Transaction *compiler.TransactionData `json:"transaction"`
}

type EvaluationResponse struct {
    Result    *compiler.EvaluationResult `json:"result"`
    Timestamp time.Time                  `json:"timestamp"`
    Error     string                     `json:"error,omitempty"`
}

func (api *ComplianceAPI) EvaluateHandler(w http.ResponseWriter, r *http.Request) {
    var req EvaluationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
    defer cancel()

    result, err := api.service.Evaluate(ctx, req.PolicyID, req.Transaction)

    response := EvaluationResponse{
        Timestamp: time.Now(),
    }

    if err != nil {
        response.Error = err.Error()
        w.WriteHeader(http.StatusInternalServerError)
    } else {
        response.Result = result
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (api *ComplianceAPI) HealthHandler(w http.ResponseWriter, r *http.Request) {
    stats := api.service.engine.GetStatistics()

    health := map[string]interface{}{
        "status":            "healthy",
        "policies_loaded":   len(api.service.policies),
        "evaluations_total": stats.TotalEvaluations,
        "avg_response_time": stats.AverageResponseTime,
        "error_rate":        stats.ErrorRate,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(health)
}

func main() {
    service := &ComplianceService{
        compiler: compiler.New(),
        engine:   engine.NewEngine(),
        policies: make(map[string]*compiler.CompiledPolicy),
    }

    api := &ComplianceAPI{service: service}

    router := mux.NewRouter()
    router.HandleFunc("/evaluate", api.EvaluateHandler).Methods("POST")
    router.HandleFunc("/health", api.HealthHandler).Methods("GET")

    http.ListenAndServe(":8080", router)
}
```

## Error Handling

### Error Types

The compliance compiler defines specific error types for different failure scenarios:

```go
// Core error types
type CompilerError struct {
    Type    ErrorType `json:"type"`
    Message string    `json:"message"`
    Path    string    `json:"path,omitempty"`
    Line    int       `json:"line,omitempty"`
    Column  int       `json:"column,omitempty"`
    Cause   error     `json:"-"`
}

type ErrorType string

const (
    ErrorTypeParser     ErrorType = "parser_error"
    ErrorTypeValidator  ErrorType = "validation_error"
    ErrorTypeCompiler   ErrorType = "compiler_error"
    ErrorTypeRuntime    ErrorType = "runtime_error"
    ErrorTypeTimeout    ErrorType = "timeout_error"
    ErrorTypeNotFound   ErrorType = "not_found_error"
)

// Methods
func (ce *CompilerError) Error() string
func (ce *CompilerError) Unwrap() error
func (ce *CompilerError) Is(target error) bool
```

### Error Handling Patterns

```go
// Check for specific error types
result, err := compiler.Compile(ctx, policy)
if err != nil {
    var compilerErr *compiler.CompilerError
    if errors.As(err, &compilerErr) {
        switch compilerErr.Type {
        case compiler.ErrorTypeParser:
            // Handle parsing errors
            fmt.Printf("Parsing error at line %d: %s\n", compilerErr.Line, compilerErr.Message)
        case compiler.ErrorTypeValidator:
            // Handle validation errors
            fmt.Printf("Validation error at %s: %s\n", compilerErr.Path, compilerErr.Message)
        case compiler.ErrorTypeTimeout:
            // Handle timeout errors
            fmt.Printf("Operation timed out: %s\n", compilerErr.Message)
        default:
            // Handle other errors
            fmt.Printf("Compilation failed: %s\n", compilerErr.Message)
        }
        return
    }

    // Handle other error types
    return fmt.Errorf("unexpected error: %w", err)
}
```

### Validation Error Handling

```go
// Handle validation errors with detailed information
validator := validator.NewValidator()
result, err := validator.Validate(ctx, policy)
if err != nil {
    return fmt.Errorf("validation failed: %w", err)
}

if !result.Valid {
    // Group errors by type
    errorsByType := make(map[string][]validator.ValidationError)
    for _, err := range result.Errors {
        errorsByType[err.Rule] = append(errorsByType[err.Rule], err)
    }

    // Handle specific error types
    if templateErrors, exists := errorsByType["template_validation"]; exists {
        for _, err := range templateErrors {
            fmt.Printf("Template error: %s\n", err.Message)
        }
    }

    if ruleErrors, exists := errorsByType["rule_validation"]; exists {
        for _, err := range ruleErrors {
            fmt.Printf("Rule error in %s: %s\n", err.Path, err.Message)
        }
    }

    return fmt.Errorf("policy validation failed with %d errors", len(result.Errors))
}
```

### Runtime Error Handling

```go
// Handle evaluation errors gracefully
engine := engine.NewEngine()
result, err := engine.Evaluate(ctx, policy, transaction)

if err != nil {
    var runtimeErr *engine.RuntimeError
    if errors.As(err, &runtimeErr) {
        switch runtimeErr.Phase {
        case engine.PhaseRuleExecution:
            fmt.Printf("Rule execution failed: %s in rule %s\n", runtimeErr.Message, runtimeErr.RuleID)
            // Maybe continue with remaining rules or fail fast
        case engine.PhaseConditionEvaluation:
            fmt.Printf("Condition evaluation failed: %s\n", runtimeErr.Message)
            // Log and potentially skip the condition
        case engine.PhaseActionExecution:
            fmt.Printf("Action execution failed: %s\n", runtimeErr.Message)
            // Actions failures might be non-critical
        }
    }

    return fmt.Errorf("policy evaluation failed: %w", err)
}

// Check for partial failures in result
if result.HasErrors() {
    fmt.Printf("Evaluation completed with %d errors:\n", len(result.Errors))
    for _, errMsg := range result.Errors {
        fmt.Printf("  - %s\n", errMsg)
    }
}
```

## Thread Safety

### Thread-Safe Usage Patterns

The compliance compiler is designed to be thread-safe for concurrent usage:

```go
// Compiler instances are thread-safe for read operations
var (
    globalCompiler = compiler.New()
    globalEngine   = engine.NewEngine()
    policiesCache  = sync.Map{} // Thread-safe cache
)

// Safe concurrent compilation
func compilePolicy(policyData []byte) (*compiler.CompiledPolicy, error) {
    parser := parser.NewParser() // Parser is thread-safe
    policy, err := parser.ParsePolicy(policyData)
    if err != nil {
        return nil, err
    }

    // Compiler.Compile is thread-safe
    return globalCompiler.Compile(context.Background(), policy)
}

// Safe concurrent evaluation
func evaluateTransaction(policyID string, transaction *compiler.TransactionData) (*compiler.EvaluationResult, error) {
    // Load from thread-safe cache
    policyInterface, exists := policiesCache.Load(policyID)
    if !exists {
        return nil, fmt.Errorf("policy not found: %s", policyID)
    }

    policy := policyInterface.(*compiler.CompiledPolicy)

    // Engine.Evaluate is thread-safe
    return globalEngine.Evaluate(context.Background(), policy, transaction)
}

// Concurrent policy loading with proper synchronization
func loadPolicies(policyFiles []string) error {
    var wg sync.WaitGroup
    errChan := make(chan error, len(policyFiles))

    for _, file := range policyFiles {
        wg.Add(1)
        go func(filename string) {
            defer wg.Done()

            policy, err := compilePolicy(filename)
            if err != nil {
                errChan <- fmt.Errorf("failed to compile %s: %w", filename, err)
                return
            }

            // Store in thread-safe cache
            policyID := policy.Template.Name
            policiesCache.Store(policyID, policy)
        }(file)
    }

    wg.Wait()
    close(errChan)

    // Check for errors
    for err := range errChan {
        return err
    }

    return nil
}
```

### Performance Considerations

```go
// Pool pattern for high-throughput scenarios
type CompilerPool struct {
    compilers chan compiler.Compiler
    engines   chan engine.Engine
}

func NewCompilerPool(size int) *CompilerPool {
    pool := &CompilerPool{
        compilers: make(chan compiler.Compiler, size),
        engines:   make(chan engine.Engine, size),
    }

    // Pre-populate pool
    for i := 0; i < size; i++ {
        pool.compilers <- compiler.New()
        pool.engines <- engine.NewEngine()
    }

    return pool
}

func (cp *CompilerPool) Compile(ctx context.Context, policy *parser.ParsedPolicy) (*compiler.CompiledPolicy, error) {
    select {
    case compiler := <-cp.compilers:
        defer func() { cp.compilers <- compiler }()
        return compiler.Compile(ctx, policy)
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}

func (cp *CompilerPool) Evaluate(ctx context.Context, policy *compiler.CompiledPolicy, transaction *compiler.TransactionData) (*compiler.EvaluationResult, error) {
    select {
    case engine := <-cp.engines:
        defer func() { cp.engines <- engine }()
        return engine.Evaluate(ctx, policy, transaction)
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}
```

### Best Practices

1. **Immutable Policies**: Once compiled, policies are immutable and safe for concurrent access.

2. **Context Usage**: Always use context for cancellation and timeouts:
   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
   defer cancel()

   result, err := engine.Evaluate(ctx, policy, transaction)
   ```

3. **Resource Management**: Properly manage resources in concurrent scenarios:
   ```go
   // Use connection pools for external services
   type ExternalServicePool struct {
       connections chan *http.Client
   }

   // Implement proper cleanup
   defer func() {
       if r := recover(); r != nil {
           // Log panic and cleanup resources
           log.Printf("Panic in policy evaluation: %v", r)
           // Return connection to pool, etc.
       }
   }()
   ```

4. **Metrics and Monitoring**: Implement proper monitoring for concurrent operations:
   ```go
   // Thread-safe metrics collection
   type Metrics struct {
       mu                sync.RWMutex
       totalEvaluations  int64
       successfulEvals   int64
       failedEvals       int64
       averageTime       time.Duration
   }

   func (m *Metrics) RecordEvaluation(duration time.Duration, success bool) {
       m.mu.Lock()
       defer m.mu.Unlock()

       m.totalEvaluations++
       if success {
           m.successfulEvals++
       } else {
           m.failedEvals++
       }

       // Update running average
       m.averageTime = (m.averageTime*time.Duration(m.totalEvaluations-1) + duration) / time.Duration(m.totalEvaluations)
   }
   ```

This comprehensive API reference provides all the information needed to integrate the ArdaOS Compliance Compiler into Go applications, with examples covering basic usage, advanced patterns, error handling, and thread safety considerations.
