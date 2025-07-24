# ArdaOS Compliance Compiler - Architecture Guide

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Component Architecture](#component-architecture)
- [Compilation Pipeline](#compilation-pipeline)
- [Extension Mechanisms](#extension-mechanisms)
- [Performance Characteristics](#performance-characteristics)
- [Security Considerations](#security-considerations)
- [Deployment Architecture](#deployment-architecture)

## Overview

The ArdaOS Compliance Compiler is a sophisticated policy compilation and evaluation system designed to handle complex regulatory compliance requirements for financial services. The architecture is built around modularity, extensibility, and performance, enabling it to scale from single-application integration to enterprise-wide compliance platforms.

### Design Principles

1. **Modularity**: Clean separation of concerns with well-defined interfaces
2. **Extensibility**: Plugin architecture for custom functions, validators, and attestation providers
3. **Performance**: Optimized compilation and evaluation pipeline with caching and parallel processing
4. **Security**: Secure policy execution with sandboxing and access controls
5. **Reliability**: Robust error handling, validation, and recovery mechanisms
6. **Observability**: Comprehensive logging, metrics, and tracing capabilities

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  CLI Tools  │  Web UI  │  API Server  │  SDK Integration       │
├─────────────────────────────────────────────────────────────────┤
│                      Compliance Compiler                       │
├─────────────────────────────────────────────────────────────────┤
│  Parser  │  Validator  │  Compiler  │  Engine  │  Extensions    │
├─────────────────────────────────────────────────────────────────┤
│                       Runtime Layer                            │
├─────────────────────────────────────────────────────────────────┤
│  Cache  │  Metrics  │  Logging  │  Tracing  │  Configuration    │
├─────────────────────────────────────────────────────────────────┤
│                     Infrastructure Layer                       │
├─────────────────────────────────────────────────────────────────┤
│  Storage  │  Network  │  Security  │  Monitoring  │  Deployment │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interaction Flow

```
┌──────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐
│  Policy  │───▶│  Parser  │───▶│ Validator │───▶│  Compiler   │
│   YAML   │    │          │    │           │    │             │
└──────────┘    └──────────┘    └───────────┘    └─────────────┘
                                                         │
                                                         ▼
┌──────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐
│  Result  │◀───│  Engine  │◀───│Transaction│◀───│  Compiled   │
│          │    │          │    │   Data    │    │   Policy    │
└──────────┘    └──────────┘    └───────────┘    └─────────────┘
```

## Component Architecture

### Parser Component

The parser component handles policy file parsing and initial syntax validation.

```go
// Parser architecture
type Parser struct {
    schema       *Schema              // YAML schema definition
    validators   []SyntaxValidator    // Syntax validation rules
    preprocessor *Preprocessor       // Macro expansion and includes
    cache        *ParseCache         // Parsed policy cache
    metrics      *ParseMetrics       // Performance metrics
}

// Parser pipeline stages
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Raw YAML  │───▶│Preprocessor │───▶│Schema Valid.│───▶│  Parsed     │
│    Input    │    │             │    │             │    │  Policy     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**Key Features:**
- **Incremental Parsing**: Support for parsing large policies in chunks
- **Error Recovery**: Continues parsing after encountering errors
- **Schema Validation**: Validates against predefined YAML schema
- **Macro Expansion**: Supports policy templates and includes
- **Source Mapping**: Maintains mapping between parsed elements and source locations

### Validator Component

The validator ensures policy correctness and compliance with business rules.

```go
// Validator architecture
type Validator struct {
    ruleEngine    *ValidationRuleEngine  // Core validation rules
    customRules   []CustomValidator      // User-defined validation rules
    contextBuilder *ValidationContext    // Builds validation context
    errorCollector *ErrorCollector       // Collects and categorizes errors
    cache         *ValidationCache      // Validation result cache
}

// Validation pipeline
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Parsed    │───▶│  Context    │───▶│ Rule Engine │───▶│ Validation  │
│   Policy    │    │  Builder    │    │             │    │   Result    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                             │
                                             ▼
                                   ┌─────────────┐
                                   │   Custom    │
                                   │ Validators  │
                                   └─────────────┘
```

**Validation Categories:**
- **Syntax Validation**: YAML structure and field types
- **Semantic Validation**: Business rule consistency
- **Regulatory Validation**: Compliance with regulatory requirements
- **Performance Validation**: Checks for performance anti-patterns
- **Security Validation**: Identifies potential security issues

### Compiler Component

The compiler transforms validated policies into optimized executable format.

```go
// Compiler architecture
type Compiler struct {
    frontend      *CompilerFrontend     // Parse and analyze
    optimizer     *Optimizer           // Optimization passes
    backend       *CompilerBackend     // Code generation
    targetFormats map[string]Backend   // Multiple output formats
    cache         *CompilationCache    // Compiled policy cache
    profiler      *CompilationProfiler // Performance profiling
}

// Compilation pipeline
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Validated  │───▶│   Frontend  │───▶│  Optimizer  │───▶│   Backend   │
│   Policy    │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                    │                  │
                          ▼                    ▼                  ▼
                  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                  │    AST      │    │ Optimized   │    │  Compiled   │
                  │Generation   │    │    AST      │    │   Policy    │
                  └─────────────┘    └─────────────┘    └─────────────┘
```

**Optimization Passes:**
1. **Dead Code Elimination**: Removes unreachable rules and conditions
2. **Constant Folding**: Pre-computes constant expressions
3. **Rule Reordering**: Optimizes rule execution order for performance
4. **Condition Merging**: Combines similar conditions to reduce evaluation overhead
5. **Cache Insertion**: Identifies opportunities for result caching

### Engine Component

The engine executes compiled policies against transaction data.

```go
// Engine architecture
type Engine struct {
    ruleExecutor    *RuleExecutor        // Executes individual rules
    conditionEngine *ConditionEngine     // Evaluates conditions
    actionExecutor  *ActionExecutor      // Executes rule actions
    attestationMgr  *AttestationManager  // Manages attestations
    contextManager  *ExecutionContext    // Manages execution context
    scheduler       *RuleScheduler       // Schedules parallel execution
    cache          *EvaluationCache     // Result caching
    metrics        *EngineMetrics       // Performance metrics
}

// Execution pipeline
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Compiled   │───▶│Rule Executor│───▶│ Attestation │───▶│ Evaluation  │
│   Policy    │    │             │    │  Manager    │    │   Result    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Transaction  │    │ Condition   │    │   Action    │
│    Data     │    │  Engine     │    │  Executor   │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Compilation Pipeline

### Phase 1: Parsing and Preprocessing

```go
// Parsing phase implementation
func (p *Parser) Parse(input []byte) (*ParsedPolicy, error) {
    // Stage 1: Preprocessing
    preprocessed, err := p.preprocessor.Process(input)
    if err != nil {
        return nil, fmt.Errorf("preprocessing failed: %w", err)
    }

    // Stage 2: YAML parsing
    var raw map[string]interface{}
    if err := yaml.Unmarshal(preprocessed, &raw); err != nil {
        return nil, fmt.Errorf("YAML parsing failed: %w", err)
    }

    // Stage 3: Schema validation
    if err := p.schema.Validate(raw); err != nil {
        return nil, fmt.Errorf("schema validation failed: %w", err)
    }

    // Stage 4: Structural conversion
    policy := &ParsedPolicy{}
    if err := p.convertStructure(raw, policy); err != nil {
        return nil, fmt.Errorf("structure conversion failed: %w", err)
    }

    return policy, nil
}
```

### Phase 2: Semantic Validation

```go
// Validation phase implementation
func (v *Validator) Validate(policy *ParsedPolicy) (*ValidationResult, error) {
    result := &ValidationResult{}
    ctx := v.contextBuilder.Build(policy)

    // Stage 1: Template validation
    if err := v.validateTemplate(policy.Template, ctx, result); err != nil {
        return nil, err
    }

    // Stage 2: Parameter validation
    if err := v.validateParameters(policy.Parameters, ctx, result); err != nil {
        return nil, err
    }

    // Stage 3: Rule validation
    for _, rule := range policy.Policy.Rules {
        if err := v.validateRule(rule, ctx, result); err != nil {
            return nil, err
        }
    }

    // Stage 4: Cross-references validation
    if err := v.validateCrossReferences(policy, ctx, result); err != nil {
        return nil, err
    }

    // Stage 5: Custom validations
    for _, customValidator := range v.customRules {
        if err := customValidator.Validate(policy, ctx, result); err != nil {
            return nil, err
        }
    }

    result.Valid = len(result.Errors) == 0
    return result, nil
}
```

### Phase 3: Compilation and Optimization

```go
// Compilation phase implementation
func (c *Compiler) Compile(policy *ParsedPolicy) (*CompiledPolicy, error) {
    // Stage 1: AST generation
    ast, err := c.frontend.GenerateAST(policy)
    if err != nil {
        return nil, fmt.Errorf("AST generation failed: %w", err)
    }

    // Stage 2: Optimization passes
    optimizedAST := ast
    for _, pass := range c.optimizer.GetPasses() {
        var err error
        optimizedAST, err = pass.Transform(optimizedAST)
        if err != nil {
            return nil, fmt.Errorf("optimization pass %s failed: %w", pass.Name(), err)
        }
    }

    // Stage 3: Code generation
    compiled, err := c.backend.Generate(optimizedAST)
    if err != nil {
        return nil, fmt.Errorf("code generation failed: %w", err)
    }

    // Stage 4: Metadata attachment
    compiled.AttachMetadata(&CompilationMetadata{
        SourcePolicy:    policy,
        CompilerVersion: c.GetVersion(),
        CompiledAt:      time.Now(),
        Optimizations:   c.optimizer.GetAppliedOptimizations(),
    })

    return compiled, nil
}
```

### Phase 4: Runtime Execution

```go
// Execution phase implementation
func (e *Engine) Evaluate(policy *CompiledPolicy, transaction *TransactionData) (*EvaluationResult, error) {
    ctx := e.contextManager.CreateContext(transaction)
    result := &EvaluationResult{
        TransactionID: transaction.ID,
        PolicyID:     policy.ID,
        Timestamp:    time.Now(),
    }

    // Stage 1: Pre-execution setup
    if err := e.setupExecution(ctx, policy); err != nil {
        return nil, fmt.Errorf("execution setup failed: %w", err)
    }

    // Stage 2: Rule execution
    ruleResults := make([]RuleResult, 0, len(policy.CompiledRules))

    // Parallel execution for independent rules
    if policy.ExecutionPlan.AllowParallel {
        ruleResults, err = e.executeRulesParallel(ctx, policy.CompiledRules)
    } else {
        ruleResults, err = e.executeRulesSequential(ctx, policy.CompiledRules)
    }

    if err != nil {
        return nil, fmt.Errorf("rule execution failed: %w", err)
    }

    result.RuleResults = ruleResults

    // Stage 3: Decision aggregation
    decision, err := e.aggregateDecision(ruleResults, policy.DecisionLogic)
    if err != nil {
        return nil, fmt.Errorf("decision aggregation failed: %w", err)
    }

    result.Decision = decision

    // Stage 4: Attestation processing
    if len(policy.Attestations) > 0 {
        attestationResults, err := e.processAttestations(ctx, policy.Attestations)
        if err != nil {
            return nil, fmt.Errorf("attestation processing failed: %w", err)
        }
        result.Attestations = attestationResults
    }

    // Stage 5: Compliance scoring
    result.ComplianceScore = e.calculateComplianceScore(ruleResults)
    result.ProcessingTime = time.Since(result.Timestamp)

    return result, nil
}
```

## Extension Mechanisms

### Plugin Architecture

The compiler supports a robust plugin system for extending functionality.

```go
// Plugin interface definition
type Plugin interface {
    Name() string
    Version() string
    Initialize(config PluginConfig) error
    Shutdown() error
}

// Function plugin for custom expressions
type FunctionPlugin interface {
    Plugin
    GetFunctions() map[string]Function
}

// Validator plugin for custom validation rules
type ValidatorPlugin interface {
    Plugin
    GetValidators() []Validator
}

// Attestation provider plugin
type AttestationPlugin interface {
    Plugin
    GetProviders() map[string]AttestationProvider
}

// Plugin manager
type PluginManager struct {
    plugins       map[string]Plugin
    functions     map[string]Function
    validators    []Validator
    providers     map[string]AttestationProvider
    config        PluginConfig
}

func (pm *PluginManager) LoadPlugin(path string) error {
    plugin, err := plugin.Open(path)
    if err != nil {
        return fmt.Errorf("failed to load plugin %s: %w", path, err)
    }

    // Get plugin symbol
    symPlugin, err := plugin.Lookup("Plugin")
    if err != nil {
        return fmt.Errorf("plugin symbol not found: %w", err)
    }

    // Type assertion
    p, ok := symPlugin.(Plugin)
    if !ok {
        return fmt.Errorf("invalid plugin interface")
    }

    // Initialize plugin
    if err := p.Initialize(pm.config); err != nil {
        return fmt.Errorf("plugin initialization failed: %w", err)
    }

    pm.plugins[p.Name()] = p

    // Register plugin extensions
    pm.registerPluginExtensions(p)

    return nil
}
```

### Custom Function Registration

```go
// Custom function example
type RiskCalculatorPlugin struct {
    config RiskConfig
}

func (rcp *RiskCalculatorPlugin) GetFunctions() map[string]Function {
    return map[string]Function{
        "calculate_risk_score": Function{
            Name:        "calculate_risk_score",
            Description: "Calculates comprehensive risk score",
            Parameters: []Parameter{
                {Name: "credit_score", Type: "int"},
                {Name: "income", Type: "float"},
                {Name: "debt_ratio", Type: "float"},
            },
            ReturnType: "float",
            Handler: func(args []interface{}) (interface{}, error) {
                creditScore := args[0].(int)
                income := args[1].(float64)
                debtRatio := args[2].(float64)

                // Custom risk calculation logic
                riskScore := rcp.calculateRisk(creditScore, income, debtRatio)
                return riskScore, nil
            },
        },

        "get_market_rate": Function{
            Name:        "get_market_rate",
            Description: "Retrieves current market rate for asset class",
            Parameters: []Parameter{
                {Name: "asset_class", Type: "string"},
                {Name: "term", Type: "int"},
                {Name: "credit_tier", Type: "string"},
            },
            ReturnType: "float",
            Handler: func(args []interface{}) (interface{}, error) {
                assetClass := args[0].(string)
                term := args[1].(int)
                creditTier := args[2].(string)

                // Fetch from external rate service
                rate, err := rcp.fetchMarketRate(assetClass, term, creditTier)
                if err != nil {
                    return 0.0, fmt.Errorf("failed to fetch market rate: %w", err)
                }

                return rate, nil
            },
        },
    }
}

// Usage in policy
// conditions:
//   - "calculate_risk_score(applicant.credit_score, applicant.income, applicant.debt_ratio) >= 0.7"
//   - "get_market_rate(asset_class, term, credit_tier) <= max_rate"
```

### Custom Attestation Providers

```go
// Custom attestation provider example
type BankVerificationProvider struct {
    client *http.Client
    config BankVerificationConfig
}

func (bvp *BankVerificationProvider) ProcessAttestation(
    ctx context.Context,
    attestation *Attestation,
    transaction *TransactionData,
) (*AttestationResult, error) {

    // Extract bank account information
    accountNumber := transaction.Applicant.Banking.AccountNumber
    routingNumber := transaction.Applicant.Banking.RoutingNumber

    // Call external verification service
    verificationRequest := &BankVerificationRequest{
        AccountNumber: accountNumber,
        RoutingNumber: routingNumber,
        NameOnAccount: transaction.Applicant.Name,
    }

    response, err := bvp.callVerificationAPI(ctx, verificationRequest)
    if err != nil {
        return nil, fmt.Errorf("bank verification API call failed: %w", err)
    }

    // Process response
    result := &AttestationResult{
        AttestationID: attestation.ID,
        Status:       AttestationStatusCompleted,
        Fields: map[string]interface{}{
            "verification_result": response.VerificationResult,
            "account_status":      response.AccountStatus,
            "account_type":        response.AccountType,
            "verification_date":   time.Now(),
        },
        ProcessedAt: time.Now(),
    }

    if response.VerificationResult != "verified" {
        result.Status = AttestationStatusFailed
        result.ErrorMessage = "Bank account verification failed"
    }

    return result, nil
}

// Provider registration
func init() {
    attestation.RegisterProvider("bank_verification", func(config map[string]interface{}) AttestationProvider {
        return &BankVerificationProvider{
            client: &http.Client{Timeout: 30 * time.Second},
            config: parseBankVerificationConfig(config),
        }
    })
}
```

### Hooks and Interceptors

```go
// Hook system for extending compilation and execution behavior
type Hooks struct {
    PreParsing      []PreParsingHook
    PostParsing     []PostParsingHook
    PreValidation   []PreValidationHook
    PostValidation  []PostValidationHook
    PreCompilation  []PreCompilationHook
    PostCompilation []PostCompilationHook
    PreExecution    []PreExecutionHook
    PostExecution   []PostExecutionHook
    OnError         []ErrorHook
}

type PreExecutionHook func(ctx context.Context, policy *CompiledPolicy, transaction *TransactionData) error
type PostExecutionHook func(ctx context.Context, result *EvaluationResult) error

// Hook registration example
compiler := compiler.NewWithOptions(compiler.CompilerOptions{
    Hooks: compiler.Hooks{
        PreExecution: []compiler.PreExecutionHook{
            func(ctx context.Context, policy *CompiledPolicy, transaction *TransactionData) error {
                // Log execution start
                log.Printf("Starting policy evaluation for transaction %s", transaction.ID)

                // Validate transaction data
                if err := validateTransactionData(transaction); err != nil {
                    return fmt.Errorf("transaction data validation failed: %w", err)
                }

                // Add custom context
                ctx = context.WithValue(ctx, "execution_id", generateExecutionID())

                return nil
            },
        },

        PostExecution: []compiler.PostExecutionHook{
            func(ctx context.Context, result *EvaluationResult) error {
                // Log execution completion
                log.Printf("Policy evaluation completed for transaction %s: %s",
                    result.TransactionID, result.Decision)

                // Send metrics
                metrics.RecordEvaluation(result.ProcessingTime, result.Decision == DecisionApproved)

                // Trigger notifications
                if result.Decision == DecisionDenied {
                    notifications.SendDeclinedApplicationNotification(result)
                }

                return nil
            },
        },
    },
})
```

## Performance Characteristics

### Compilation Performance

The compiler is optimized for both development and production scenarios:

**Development Mode:**
- Fast compilation with minimal optimization
- Detailed error reporting and debugging information
- Hot-reload support for policy changes

**Production Mode:**
- Aggressive optimization for runtime performance
- Compile-time constant folding and dead code elimination
- Optimized memory layout and cache-friendly data structures

```go
// Performance benchmarks
BenchmarkPolicyCompilation/small_policy-8      1000    120ms/op    15MB/op
BenchmarkPolicyCompilation/medium_policy-8      500    250ms/op    32MB/op
BenchmarkPolicyCompilation/large_policy-8       200    650ms/op    78MB/op

BenchmarkPolicyEvaluation/simple_rules-8      10000      8.5μs/op    2.3KB/op
BenchmarkPolicyEvaluation/complex_rules-8      5000     45.2μs/op    8.1KB/op
BenchmarkPolicyEvaluation/parallel_rules-8     8000     12.3μs/op    3.7KB/op
```

### Memory Management

The system implements several memory optimization strategies:

1. **Object Pooling**: Reuse of frequently allocated objects
2. **Lazy Loading**: Load data only when needed
3. **Memory Mapping**: Efficient storage of large policy datasets
4. **Garbage Collection Optimization**: Minimize GC pressure through careful object lifetime management

```go
// Memory pool implementation
type PolicyEvaluationPool struct {
    contextPool    sync.Pool
    resultPool     sync.Pool
    conditionPool  sync.Pool
}

func (pep *PolicyEvaluationPool) GetContext() *ExecutionContext {
    if ctx := pep.contextPool.Get(); ctx != nil {
        return ctx.(*ExecutionContext)
    }
    return &ExecutionContext{}
}

func (pep *PolicyEvaluationPool) PutContext(ctx *ExecutionContext) {
    ctx.Reset() // Clear context data
    pep.contextPool.Put(ctx)
}
```

### Caching Strategy

Multi-level caching improves performance for repeated operations:

```go
// Caching architecture
type CacheManager struct {
    l1Cache *LRUCache    // In-memory fast cache
    l2Cache *RedisCache  // Distributed cache
    l3Cache *FileCache   // Persistent cache
}

func (cm *CacheManager) Get(key string) (interface{}, bool) {
    // Try L1 cache first
    if value, found := cm.l1Cache.Get(key); found {
        return value, true
    }

    // Try L2 cache
    if value, found := cm.l2Cache.Get(key); found {
        cm.l1Cache.Set(key, value) // Populate L1
        return value, true
    }

    // Try L3 cache
    if value, found := cm.l3Cache.Get(key); found {
        cm.l1Cache.Set(key, value) // Populate L1
        cm.l2Cache.Set(key, value) // Populate L2
        return value, true
    }

    return nil, false
}
```

## Security Considerations

### Policy Execution Sandbox

Policies execute in a sandboxed environment to prevent malicious code execution:

```go
// Sandbox implementation
type PolicySandbox struct {
    maxExecutionTime time.Duration
    maxMemoryUsage   int64
    allowedFunctions map[string]bool
    resourceLimiter  *ResourceLimiter
}

func (ps *PolicySandbox) Execute(policy *CompiledPolicy, transaction *TransactionData) (*EvaluationResult, error) {
    // Create isolated execution context
    ctx, cancel := context.WithTimeout(context.Background(), ps.maxExecutionTime)
    defer cancel()

    // Set up resource monitoring
    monitor := ps.resourceLimiter.CreateMonitor()
    defer monitor.Close()

    // Execute with resource limits
    done := make(chan struct{})
    var result *EvaluationResult
    var err error

    go func() {
        defer close(done)
        result, err = ps.executeWithLimits(ctx, policy, transaction, monitor)
    }()

    select {
    case <-done:
        return result, err
    case <-ctx.Done():
        return nil, fmt.Errorf("execution timeout exceeded")
    case <-monitor.MemoryLimitExceeded():
        return nil, fmt.Errorf("memory limit exceeded")
    }
}
```

### Access Control

Fine-grained access control for policy operations:

```go
// RBAC implementation
type AccessController struct {
    roles       map[string]Role
    permissions map[string]Permission
    policies    map[string]AccessPolicy
}

type Permission string

const (
    PermissionReadPolicy   Permission = "policy:read"
    PermissionWritePolicy  Permission = "policy:write"
    PermissionCompilePolicy Permission = "policy:compile"
    PermissionEvaluatePolicy Permission = "policy:evaluate"
    PermissionManageUsers   Permission = "users:manage"
)

func (ac *AccessController) CheckPermission(userID string, resource string, permission Permission) error {
    user, err := ac.getUser(userID)
    if err != nil {
        return fmt.Errorf("user not found: %w", err)
    }

    // Check role-based permissions
    for _, roleID := range user.Roles {
        role, exists := ac.roles[roleID]
        if !exists {
            continue
        }

        if role.HasPermission(permission) {
            return nil // Permission granted
        }
    }

    // Check resource-based policies
    if policy, exists := ac.policies[resource]; exists {
        if policy.AllowsUserPermission(userID, permission) {
            return nil // Permission granted by policy
        }
    }

    return fmt.Errorf("permission denied: user %s does not have %s permission for resource %s",
        userID, permission, resource)
}
```

### Audit Logging

Comprehensive audit trail for compliance and security monitoring:

```go
// Audit system
type AuditLogger struct {
    logger     *structured.Logger
    storage    AuditStorage
    formatter  AuditFormatter
    rules      []AuditRule
}

type AuditEvent struct {
    EventID     string                 `json:"event_id"`
    Timestamp   time.Time              `json:"timestamp"`
    UserID      string                 `json:"user_id"`
    Action      string                 `json:"action"`
    Resource    string                 `json:"resource"`
    Result      string                 `json:"result"`
    IPAddress   string                 `json:"ip_address"`
    UserAgent   string                 `json:"user_agent"`
    PolicyID    string                 `json:"policy_id,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (al *AuditLogger) LogPolicyEvaluation(
    userID string,
    policyID string,
    transactionID string,
    result *EvaluationResult,
    context *RequestContext,
) {
    event := &AuditEvent{
        EventID:   generateEventID(),
        Timestamp: time.Now(),
        UserID:    userID,
        Action:    "policy_evaluation",
        Resource:  fmt.Sprintf("policy:%s", policyID),
        Result:    string(result.Decision),
        IPAddress: context.IPAddress,
        UserAgent: context.UserAgent,
        PolicyID:  policyID,
        Metadata: map[string]interface{}{
            "transaction_id":    transactionID,
            "compliance_score":  result.ComplianceScore,
            "processing_time":   result.ProcessingTime.String(),
            "rules_evaluated":   len(result.RuleResults),
            "attestations_required": len(result.Attestations),
        },
    }

    // Apply audit rules
    for _, rule := range al.rules {
        if rule.ShouldLog(event) {
            rule.Process(event)
        }
    }

    // Store audit event
    if err := al.storage.Store(event); err != nil {
        al.logger.Error("Failed to store audit event", "error", err, "event_id", event.EventID)
    }
}
```

## Deployment Architecture

### Standalone Deployment

For single-application integration:

```
┌─────────────────────────────────────────────┐
│                Application                  │
├─────────────────────────────────────────────┤
│           Compliance Compiler               │
│  ┌─────────┐ ┌─────────┐ ┌─────────────────┐│
│  │ Parser  │ │Validator│ │    Compiler     ││
│  └─────────┘ └─────────┘ └─────────────────┘│
│  ┌─────────┐ ┌─────────┐ ┌─────────────────┐│
│  │ Engine  │ │ Cache   │ │   Extensions    ││
│  └─────────┘ └─────────┘ └─────────────────┘│
├─────────────────────────────────────────────┤
│              Local Storage                  │
└─────────────────────────────────────────────┘
```

### Microservice Deployment

For distributed architectures:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Gateway   │    │ Load Balancer   │    │   Web Client    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
        ┌──────────────────────────────────────────────────┐
        │              Compliance Service                  │
        ├──────────────────────────────────────────────────┤
        │  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
        │  │   Parser    │  │  Validator  │  │ Compiler  │ │
        │  │   Service   │  │   Service   │  │  Service  │ │
        │  └─────────────┘  └─────────────┘  └───────────┘ │
        │  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
        │  │   Engine    │  │    Cache    │  │Extension  │ │
        │  │   Service   │  │   Service   │  │ Manager   │ │
        │  └─────────────┘  └─────────────┘  └───────────┘ │
        └──────────────────────────────────────────────────┘
                                 │
        ┌──────────────────────────────────────────────────┐
        │                Infrastructure                    │
        ├──────────────────────────────────────────────────┤
        │  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
        │  │  Database   │  │   Redis     │  │ Message   │ │
        │  │ (Policies)  │  │   Cache     │  │  Queue    │ │
        │  └─────────────┘  └─────────────┘  └───────────┘ │
        │  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
        │  │ Monitoring  │  │   Logging   │  │  Metrics  │ │
        │  │   System    │  │   System    │  │ Storage   │ │
        │  └─────────────┘  └─────────────┘  └───────────┘ │
        └──────────────────────────────────────────────────┘
```

### Container Deployment

Docker and Kubernetes deployment configurations:

```yaml
# docker-compose.yml
version: '3.8'
services:
  compliance-compiler:
    image: ardaos/compliance-compiler:latest
    ports:
      - "8080:8080"
    environment:
      - COMPILER_LOG_LEVEL=info
      - COMPILER_CACHE_SIZE=1000
      - COMPILER_MAX_WORKERS=4
    volumes:
      - ./policies:/app/policies:ro
      - ./config:/app/config:ro
    depends_on:
      - redis
      - postgres

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: compliance
      POSTGRES_USER: compiler
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

```yaml
# kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliance-compiler
spec:
  replicas: 3
  selector:
    matchLabels:
      app: compliance-compiler
  template:
    metadata:
      labels:
        app: compliance-compiler
    spec:
      containers:
      - name: compiler
        image: ardaos/compliance-compiler:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: COMPILER_CACHE_SIZE
          value: "2000"
        - name: COMPILER_MAX_WORKERS
          value: "8"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

This comprehensive architecture guide provides the foundational understanding needed to deploy, extend, and maintain the ArdaOS Compliance Compiler in various environments while ensuring security, performance, and reliability.
