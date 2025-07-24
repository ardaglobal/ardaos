package parser

import (
	"time"

	"google.golang.org/protobuf/types/known/anypb"
)

// ExpressionProto represents a compiled expression in protobuf format
type ExpressionProto struct {
	Expression       string                   `json:"expression"`
	Language         ExpressionLanguage       `json:"language"`
	ResultType       string                   `json:"result_type"`
	FieldReferences  []string                 `json:"field_references"`
	FunctionCalls    []string                 `json:"function_calls"`
	Constants        []*anypb.Any             `json:"constants"`
	Bytecode         []*BytecodeInstruction   `json:"bytecode"`
	Metadata         *ExpressionMetadataProto `json:"metadata"`
	Variables        map[string]*anypb.Any    `json:"variables"`
	RequiredFields   []string                 `json:"required_fields"`
	SecurityContext  *SecurityContextProto    `json:"security_context"`
	PerformanceHints *PerformanceHintsProto   `json:"performance_hints"`
}

// BytecodeInstruction represents a single bytecode instruction
type BytecodeInstruction struct {
	Opcode int32  `json:"opcode"`
	Arg1   int32  `json:"arg1"`
	Arg2   int32  `json:"arg2"`
	Type   string `json:"type"`
}

// ExpressionMetadataProto contains metadata about the expression in protobuf format
type ExpressionMetadataProto struct {
	Complexity      int32            `json:"complexity"`
	FieldAccesses   int32            `json:"field_accesses"`
	FunctionCalls   int32            `json:"function_calls"`
	Depth           int32            `json:"depth"`
	Dependencies    []string         `json:"dependencies"`
	SecurityScore   int32            `json:"security_score"`
	EstimatedTimeMs int64            `json:"estimated_time_ms"`
	Optimizations   []string         `json:"optimizations"`
	CompilationInfo *CompilationInfo `json:"compilation_info"`
}

// CompilationInfo contains information about the compilation process
type CompilationInfo struct {
	CompiledAt        string     `json:"compiled_at"`
	CompilerVersion   string     `json:"compiler_version"`
	OptimizationLevel int32      `json:"optimization_level"`
	Warnings          []string   `json:"warnings"`
	SourceMap         *SourceMap `json:"source_map"`
}

// SourceMap provides mapping between bytecode and source expression
type SourceMap struct {
	Mappings    []SourceMapping `json:"mappings"`
	SourceLines []string        `json:"source_lines"`
}

// SourceMapping maps bytecode instruction to source location
type SourceMapping struct {
	BytecodeIndex int32 `json:"bytecode_index"`
	SourceStart   int32 `json:"source_start"`
	SourceEnd     int32 `json:"source_end"`
	SourceLine    int32 `json:"source_line"`
	SourceColumn  int32 `json:"source_column"`
}

// SecurityContextProto contains security context information
type SecurityContextProto struct {
	SecurityLevel     SecurityLevel `json:"security_level"`
	AllowedOperations []string      `json:"allowed_operations"`
	RestrictedFields  []string      `json:"restricted_fields"`
	AuditRequired     bool          `json:"audit_required"`
	Sandboxed         bool          `json:"sandboxed"`
	TrustedContext    bool          `json:"trusted_context"`
}

// SecurityLevel enumeration for protobuf
type SecurityLevel int32

const (
	SecurityLevel_SECURITY_LEVEL_UNSPECIFIED SecurityLevel = 0
	SecurityLevel_SECURITY_LEVEL_LOW         SecurityLevel = 1
	SecurityLevel_SECURITY_LEVEL_MEDIUM      SecurityLevel = 2
	SecurityLevel_SECURITY_LEVEL_HIGH        SecurityLevel = 3
	SecurityLevel_SECURITY_LEVEL_CRITICAL    SecurityLevel = 4
)

// PerformanceHintsProto contains performance optimization hints
type PerformanceHintsProto struct {
	CachingEnabled          bool               `json:"caching_enabled"`
	CacheTtlSeconds         int64              `json:"cache_ttl_seconds"`
	ParallelExecution       bool               `json:"parallel_execution"`
	LazyEvaluation          bool               `json:"lazy_evaluation"`
	OptimizationHints       []OptimizationHint `json:"optimization_hints"`
	ExpectedExecutionTimeMs int64              `json:"expected_execution_time_ms"`
}

// OptimizationHint provides hints for expression optimization
type OptimizationHint struct {
	Type        OptimizationType  `json:"type"`
	Description string            `json:"description"`
	Parameters  map[string]string `json:"parameters"`
	Priority    int32             `json:"priority"`
}

// OptimizationType enumeration
type OptimizationType int32

const (
	OptimizationType_OPTIMIZATION_TYPE_UNSPECIFIED    OptimizationType = 0
	OptimizationType_OPTIMIZATION_TYPE_CONSTANT_FOLD  OptimizationType = 1
	OptimizationType_OPTIMIZATION_TYPE_DEAD_CODE_ELIM OptimizationType = 2
	OptimizationType_OPTIMIZATION_TYPE_INLINE_FUNC    OptimizationType = 3
	OptimizationType_OPTIMIZATION_TYPE_LOOP_UNROLL    OptimizationType = 4
	OptimizationType_OPTIMIZATION_TYPE_CACHE_FIELD    OptimizationType = 5
	OptimizationType_OPTIMIZATION_TYPE_VECTORIZE      OptimizationType = 6
)

// EvaluationContext provides context for expression evaluation
type EvaluationContext struct {
	FieldValues      map[string]interface{} `json:"field_values"`
	FunctionRegistry map[string]Function    `json:"function_registry"`
	SecurityContext  *SecurityContext       `json:"security_context"`
	AuditContext     *AuditContext          `json:"audit_context"`
	PerformanceCtx   *PerformanceContext    `json:"performance_context"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// SecurityContext for expression evaluation
type SecurityContext struct {
	Level            SecurityLevel         `json:"level"`
	AllowedFields    map[string]bool       `json:"allowed_fields"`
	AllowedFunctions map[string]bool       `json:"allowed_functions"`
	Restrictions     []SecurityRestriction `json:"restrictions"`
	AuditMode        bool                  `json:"audit_mode"`
}

// SecurityRestriction defines a security restriction
type SecurityRestriction struct {
	Type        RestrictionType `json:"type"`
	Pattern     string          `json:"pattern"`
	Description string          `json:"description"`
	Severity    int32           `json:"severity"`
}

// RestrictionType enumeration
type RestrictionType int32

const (
	RestrictionType_RESTRICTION_TYPE_UNSPECIFIED   RestrictionType = 0
	RestrictionType_RESTRICTION_TYPE_FIELD_ACCESS  RestrictionType = 1
	RestrictionType_RESTRICTION_TYPE_FUNCTION_CALL RestrictionType = 2
	RestrictionType_RESTRICTION_TYPE_OPERATION     RestrictionType = 3
	RestrictionType_RESTRICTION_TYPE_COMPLEXITY    RestrictionType = 4
	RestrictionType_RESTRICTION_TYPE_PATTERN_MATCH RestrictionType = 5
)

// AuditContext for tracking expression evaluation
type AuditContext struct {
	RequestId       string                 `json:"request_id"`
	UserId          string                 `json:"user_id"`
	SessionId       string                 `json:"session_id"`
	Timestamp       time.Time              `json:"timestamp"`
	Source          string                 `json:"source"`
	Purpose         string                 `json:"purpose"`
	ComplianceMode  bool                   `json:"compliance_mode"`
	RetentionPolicy string                 `json:"retention_policy"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// PerformanceContext for performance monitoring
type PerformanceContext struct {
	MaxExecutionTime  time.Duration   `json:"max_execution_time"`
	MaxMemoryUsage    int64           `json:"max_memory_usage"`
	CacheEnabled      bool            `json:"cache_enabled"`
	ProfilingEnabled  bool            `json:"profiling_enabled"`
	MetricsCollection bool            `json:"metrics_collection"`
	TimeoutBehavior   TimeoutBehavior `json:"timeout_behavior"`
	Limits            *ResourceLimits `json:"limits"`
}

// TimeoutBehavior defines what happens on timeout
type TimeoutBehavior int32

const (
	TimeoutBehavior_TIMEOUT_BEHAVIOR_UNSPECIFIED    TimeoutBehavior = 0
	TimeoutBehavior_TIMEOUT_BEHAVIOR_ERROR          TimeoutBehavior = 1
	TimeoutBehavior_TIMEOUT_BEHAVIOR_DEFAULT_VALUE  TimeoutBehavior = 2
	TimeoutBehavior_TIMEOUT_BEHAVIOR_PARTIAL_RESULT TimeoutBehavior = 3
	TimeoutBehavior_TIMEOUT_BEHAVIOR_RETRY          TimeoutBehavior = 4
)

// ResourceLimits defines resource constraints
type ResourceLimits struct {
	MaxCpuTime        time.Duration `json:"max_cpu_time"`
	MaxMemory         int64         `json:"max_memory"`
	MaxFieldAccesses  int32         `json:"max_field_accesses"`
	MaxFunctionCalls  int32         `json:"max_function_calls"`
	MaxLoopIterations int32         `json:"max_loop_iterations"`
	MaxRecursionDepth int32         `json:"max_recursion_depth"`
}

// EvaluationResult contains the result of expression evaluation
type EvaluationResult struct {
	Value           interface{}         `json:"value"`
	Type            string              `json:"type"`
	Success         bool                `json:"success"`
	Error           error               `json:"error"`
	ExecutionTime   time.Duration       `json:"execution_time"`
	MemoryUsage     int64               `json:"memory_usage"`
	FieldsAccessed  []string            `json:"fields_accessed"`
	FunctionsCalled []string            `json:"functions_called"`
	CacheHit        bool                `json:"cache_hit"`
	Warnings        []EvaluationWarning `json:"warnings"`
	Metadata        *EvaluationMetadata `json:"metadata"`
	AuditTrail      *AuditTrail         `json:"audit_trail"`
}

// EvaluationWarning represents a warning during evaluation
type EvaluationWarning struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Severity   WarningSeverity        `json:"severity"`
	Location   *SourceLocation        `json:"location"`
	Suggestion string                 `json:"suggestion"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// WarningSeverity enumeration
type WarningSeverity int32

const (
	WarningSeverity_WARNING_SEVERITY_UNSPECIFIED WarningSeverity = 0
	WarningSeverity_WARNING_SEVERITY_INFO        WarningSeverity = 1
	WarningSeverity_WARNING_SEVERITY_LOW         WarningSeverity = 2
	WarningSeverity_WARNING_SEVERITY_MEDIUM      WarningSeverity = 3
	WarningSeverity_WARNING_SEVERITY_HIGH        WarningSeverity = 4
)

// SourceLocation pinpoints a location in the source expression
type SourceLocation struct {
	Start  int32 `json:"start"`
	End    int32 `json:"end"`
	Line   int32 `json:"line"`
	Column int32 `json:"column"`
}

// EvaluationMetadata contains detailed evaluation information
type EvaluationMetadata struct {
	EvaluationId         string            `json:"evaluation_id"`
	StartTime            time.Time         `json:"start_time"`
	EndTime              time.Time         `json:"end_time"`
	BytecodeVersion      string            `json:"bytecode_version"`
	OptimizerVersion     string            `json:"optimizer_version"`
	InstructionsExecuted int32             `json:"instructions_executed"`
	CacheOperations      int32             `json:"cache_operations"`
	MemoryAllocations    int32             `json:"memory_allocations"`
	PerformanceStats     *PerformanceStats `json:"performance_stats"`
	DebugInfo            *DebugInfo        `json:"debug_info"`
}

// PerformanceStats contains detailed performance metrics
type PerformanceStats struct {
	CpuTimeNs        int64            `json:"cpu_time_ns"`
	WallTimeNs       int64            `json:"wall_time_ns"`
	PeakMemoryBytes  int64            `json:"peak_memory_bytes"`
	CacheHitRate     float64          `json:"cache_hit_rate"`
	InstructionRate  float64          `json:"instruction_rate"`
	FieldAccessTime  map[string]int64 `json:"field_access_time"`
	FunctionCallTime map[string]int64 `json:"function_call_time"`
}

// DebugInfo contains debugging information
type DebugInfo struct {
	StackTrace       []StackFrame           `json:"stack_trace"`
	VariableValues   map[string]interface{} `json:"variable_values"`
	InstructionTrace []InstructionTrace     `json:"instruction_trace"`
	BreakpointHits   []int32                `json:"breakpoint_hits"`
	AssertionResults []AssertionResult      `json:"assertion_results"`
}

// StackFrame represents a frame in the execution stack
type StackFrame struct {
	Function       string                 `json:"function"`
	Location       *SourceLocation        `json:"location"`
	Variables      map[string]interface{} `json:"variables"`
	InstructionPtr int32                  `json:"instruction_ptr"`
}

// InstructionTrace traces instruction execution
type InstructionTrace struct {
	InstructionIndex int32         `json:"instruction_index"`
	Opcode           OpCode        `json:"opcode"`
	Args             []int32       `json:"args"`
	StackBefore      []interface{} `json:"stack_before"`
	StackAfter       []interface{} `json:"stack_after"`
	ExecutionTimeNs  int64         `json:"execution_time_ns"`
	MemoryDelta      int64         `json:"memory_delta"`
}

// AssertionResult contains the result of an assertion
type AssertionResult struct {
	Name     string          `json:"name"`
	Expected interface{}     `json:"expected"`
	Actual   interface{}     `json:"actual"`
	Success  bool            `json:"success"`
	Message  string          `json:"message"`
	Location *SourceLocation `json:"location"`
}

// AuditTrail tracks all operations for compliance
type AuditTrail struct {
	TrailId            string            `json:"trail_id"`
	Expression         string            `json:"expression"`
	StartTime          time.Time         `json:"start_date"`
	EndTime            time.Time         `json:"end_time"`
	UserId             string            `json:"user_id"`
	SessionId          string            `json:"session_id"`
	InputHash          string            `json:"input_hash"`
	OutputHash         string            `json:"output_hash"`
	FieldsAccessed     []FieldAccess     `json:"fields_accessed"`
	FunctionsCalled    []FunctionCall    `json:"functions_called"`
	SecurityChecks     []SecurityCheck   `json:"security_checks"`
	ComplianceEvents   []ComplianceEvent `json:"compliance_events"`
	DataClassification string            `json:"data_classification"`
	RetentionPeriod    time.Duration     `json:"retention_period"`
}

// FieldAccess records access to a field
type FieldAccess struct {
	FieldPath      string      `json:"field_path"`
	AccessTime     time.Time   `json:"access_time"`
	Value          interface{} `json:"value"`
	Classification string      `json:"classification"`
	Purpose        string      `json:"purpose"`
	Authorized     bool        `json:"authorized"`
}

// FunctionCall records a function call
type FunctionCall struct {
	FunctionName  string        `json:"function_name"`
	CallTime      time.Time     `json:"call_time"`
	Arguments     []interface{} `json:"arguments"`
	ReturnValue   interface{}   `json:"return_value"`
	ExecutionTime time.Duration `json:"execution_time"`
	Success       bool          `json:"success"`
	Error         string        `json:"error"`
}

// SecurityCheck records a security validation
type SecurityCheck struct {
	CheckType   string    `json:"check_type"`
	CheckTime   time.Time `json:"check_time"`
	Target      string    `json:"target"`
	Result      bool      `json:"result"`
	Severity    int32     `json:"severity"`
	Message     string    `json:"message"`
	Remediation string    `json:"remediation"`
}

// ComplianceEvent records compliance-related events
type ComplianceEvent struct {
	EventType      string                 `json:"event_type"`
	EventTime      time.Time              `json:"event_time"`
	Description    string                 `json:"description"`
	Severity       ComplianceSeverity     `json:"severity"`
	PolicyRef      string                 `json:"policy_ref"`
	RequiredAction string                 `json:"required_action"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ComplianceSeverity enumeration
type ComplianceSeverity int32

const (
	ComplianceSeverity_COMPLIANCE_SEVERITY_UNSPECIFIED ComplianceSeverity = 0
	ComplianceSeverity_COMPLIANCE_SEVERITY_INFO        ComplianceSeverity = 1
	ComplianceSeverity_COMPLIANCE_SEVERITY_LOW         ComplianceSeverity = 2
	ComplianceSeverity_COMPLIANCE_SEVERITY_MEDIUM      ComplianceSeverity = 3
	ComplianceSeverity_COMPLIANCE_SEVERITY_HIGH        ComplianceSeverity = 4
	ComplianceSeverity_COMPLIANCE_SEVERITY_CRITICAL    ComplianceSeverity = 5
)

// ExpressionEvaluator provides the interface for evaluating expressions
type ExpressionEvaluator interface {
	Evaluate(expr *Expression, context *EvaluationContext) (*EvaluationResult, error)
	EvaluateWithTimeout(expr *Expression, context *EvaluationContext, timeout time.Duration) (*EvaluationResult, error)
	ValidateContext(context *EvaluationContext) error
	GetSupportedFunctions() []string
	GetSecurityLevel() SecurityLevel
}

// ExpressionOptimizer provides expression optimization capabilities
type ExpressionOptimizer interface {
	Optimize(expr *Expression, hints *PerformanceHintsProto) (*Expression, error)
	AnalyzePerformance(expr *Expression) (*PerformanceAnalysis, error)
	SuggestOptimizations(expr *Expression) ([]*OptimizationHint, error)
}

// PerformanceAnalysis contains performance analysis results
type PerformanceAnalysis struct {
	EstimatedExecutionTime time.Duration           `json:"estimated_execution_time"`
	MemoryRequirement      int64                   `json:"memory_requirement"`
	ComplexityScore        int32                   `json:"complexity_score"`
	Bottlenecks            []PerformanceBottleneck `json:"bottlenecks"`
	Recommendations        []string                `json:"recommendations"`
	OptimizationPotential  float64                 `json:"optimization_potential"`
}

// PerformanceBottleneck identifies performance issues
type PerformanceBottleneck struct {
	Type        BottleneckType  `json:"type"`
	Location    *SourceLocation `json:"location"`
	Description string          `json:"description"`
	Impact      float64         `json:"impact"`
	Suggestion  string          `json:"suggestion"`
}

// BottleneckType enumeration
type BottleneckType int32

const (
	BottleneckType_BOTTLENECK_TYPE_UNSPECIFIED     BottleneckType = 0
	BottleneckType_BOTTLENECK_TYPE_FIELD_ACCESS    BottleneckType = 1
	BottleneckType_BOTTLENECK_TYPE_FUNCTION_CALL   BottleneckType = 2
	BottleneckType_BOTTLENECK_TYPE_COMPUTATION     BottleneckType = 3
	BottleneckType_BOTTLENECK_TYPE_MEMORY_USAGE    BottleneckType = 4
	BottleneckType_BOTTLENECK_TYPE_CACHE_MISS      BottleneckType = 5
	BottleneckType_BOTTLENECK_TYPE_TYPE_CONVERSION BottleneckType = 6
)
