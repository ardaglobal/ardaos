package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewDebugCmd() *cobra.Command {
	var (
		policyFile    string
		testDataFile  string
		interactive   bool
		stepMode      bool
		breakPoints   []string
		watchVars     []string
		outputFile    string
		transactionID string
	)

	cmd := &cobra.Command{
		Use:   "debug [policy-file] [options]",
		Short: "Interactive policy debugging tool",
		Long: `Interactive debugging tool for compliance policies.

The debugger provides:
- Step-by-step policy execution
- Breakpoint support
- Variable inspection
- Execution tracing
- Interactive debugging session
- Detailed error analysis

Examples:
  # Debug a policy with test data
  compliance-compiler debug policy.yaml --test-data data.json

  # Start interactive debugging session
  compliance-compiler debug policy.yaml --test-data data.json --interactive

  # Debug with breakpoints
  compliance-compiler debug policy.yaml --test-data data.json --break rule_id_1,rule_id_2

  # Save debug session
  compliance-compiler debug policy.yaml --test-data data.json --output debug-session.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policyFile = args[0]
			return runDebugger(policyFile, testDataFile, interactive, stepMode, breakPoints, watchVars, outputFile, transactionID)
		},
	}

	cmd.Flags().StringVarP(&testDataFile, "test-data", "t", "", "Test data file (JSON)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Start interactive debugging session")
	cmd.Flags().BoolVarP(&stepMode, "step", "s", false, "Enable step-by-step execution")
	cmd.Flags().StringSliceVar(&breakPoints, "break", []string{}, "Set breakpoints on rule IDs")
	cmd.Flags().StringSliceVar(&watchVars, "watch", []string{}, "Variables to watch")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Save debug session to file")
	cmd.Flags().StringVar(&transactionID, "transaction", "", "Specific transaction ID to debug")

	return cmd
}

// PolicyDebugger provides interactive debugging capabilities
type PolicyDebugger struct {
	PolicyFile         string
	TestDataFile       string
	Policy             *ParsedPolicy
	TestData           []TransactionData
	CurrentTransaction int
	BreakPoints        map[string]bool
	StepMode           bool
	WatchVariables     []string
	ExecutionTrace     []ExecutionStep
	Variables          map[string]interface{}
	Interactive        bool
	OutputFile         string
}

// ParsedPolicy represents a parsed compliance policy
type ParsedPolicy struct {
	Template   PolicyTemplate `yaml:"template" json:"template"`
	Parameters PolicyParams   `yaml:"parameters" json:"parameters"`
	Policy     PolicyRules    `yaml:"policy" json:"policy"`
}

// PolicyTemplate contains template metadata
type PolicyTemplate struct {
	Name                string   `yaml:"name" json:"name"`
	Version             string   `yaml:"version" json:"version"`
	Jurisdiction        string   `yaml:"jurisdiction" json:"jurisdiction"`
	AssetClass          string   `yaml:"asset_class" json:"asset_class"`
	Description         string   `yaml:"description" json:"description"`
	RegulatoryFramework []string `yaml:"regulatory_framework" json:"regulatory_framework"`
}

// PolicyParams contains configurable parameters
type PolicyParams map[string]PolicyParam

// PolicyParam represents a single policy parameter
type PolicyParam struct {
	Type        string      `yaml:"type" json:"type"`
	Default     interface{} `yaml:"default" json:"default"`
	Min         interface{} `yaml:"min,omitempty" json:"min,omitempty"`
	Max         interface{} `yaml:"max,omitempty" json:"max,omitempty"`
	Description string      `yaml:"description" json:"description"`
}

// PolicyRules contains the policy implementation
type PolicyRules struct {
	Metadata     PolicyMetadata `yaml:"metadata" json:"metadata"`
	Rules        []PolicyRule   `yaml:"rules" json:"rules"`
	Attestations []Attestation  `yaml:"attestations" json:"attestations"`
}

// PolicyMetadata contains policy metadata
type PolicyMetadata struct {
	Version     string   `yaml:"version" json:"version"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Tags        []string `yaml:"tags" json:"tags"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Type        string   `yaml:"type" json:"type"`
	Priority    string   `yaml:"priority" json:"priority"`
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Conditions  []string `yaml:"conditions" json:"conditions"`
	Actions     []string `yaml:"actions" json:"actions"`
}

// Attestation represents a required attestation
type Attestation struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Type        string   `yaml:"type" json:"type"`
	Required    bool     `yaml:"required" json:"required"`
	Fields      []string `yaml:"fields" json:"fields"`
}

// TransactionData represents transaction data for testing
type TransactionData struct {
	ID               string                 `json:"id"`
	AssetClass       string                 `json:"asset_class"`
	Jurisdiction     string                 `json:"jurisdiction"`
	Amount           float64                `json:"amount"`
	Currency         string                 `json:"currency"`
	Timestamp        time.Time              `json:"timestamp"`
	Applicant        ApplicantData          `json:"applicant"`
	ApplicationData  ApplicationData        `json:"application_data"`
	RiskMetrics      RiskMetrics            `json:"risk_metrics"`
	ComplianceChecks ComplianceChecks       `json:"compliance_checks"`
	CustomFields     map[string]interface{} `json:"custom_fields"`
}

// ApplicantData contains applicant information
type ApplicantData struct {
	Age                    int     `json:"age"`
	AnnualIncome           float64 `json:"annual_income"`
	EmploymentStatus       string  `json:"employment_status"`
	EmploymentLengthMonths int     `json:"employment_length_months"`
	CreditScore            int     `json:"credit_score"`
	DebtToIncomeRatio      float64 `json:"debt_to_income_ratio"`
	ExistingCreditAccounts int     `json:"existing_credit_accounts"`
	PaymentHistory         string  `json:"payment_history"`
	BankruptcyHistory      bool    `json:"bankruptcy_history"`
	MilitaryStatus         bool    `json:"military_status"`
}

// ApplicationData contains application-specific information
type ApplicationData struct {
	RequestedAmount          float64 `json:"requested_amount"`
	IntendedUse              string  `json:"intended_use"`
	ApplicationMethod        string  `json:"application_method"`
	IncomeVerificationMethod string  `json:"income_verification_method"`
	IdentityVerified         bool    `json:"identity_verified"`
}

// RiskMetrics contains risk assessment data
type RiskMetrics struct {
	RiskScore            float64 `json:"risk_score"`
	RiskTier             string  `json:"risk_tier"`
	ProbabilityOfDefault float64 `json:"probability_of_default"`
	LossGivenDefault     float64 `json:"loss_given_default"`
	ExposureAtDefault    float64 `json:"exposure_at_default"`
	RiskAdjustedReturn   float64 `json:"risk_adjusted_return"`
}

// ComplianceChecks contains compliance verification results
type ComplianceChecks struct {
	KYCPassed            bool     `json:"kyc_passed"`
	AMLCleared           bool     `json:"aml_cleared"`
	CreditCheckCompleted bool     `json:"credit_check_completed"`
	IncomeVerified       bool     `json:"income_verified"`
	IdentityVerified     bool     `json:"identity_verified"`
	RegulatoryFlags      []string `json:"regulatory_flags"`
	ComplianceScore      float64  `json:"compliance_score"`
}

// ExecutionStep represents a single step in policy execution
type ExecutionStep struct {
	StepID     int                    `json:"step_id"`
	RuleID     string                 `json:"rule_id"`
	RuleName   string                 `json:"rule_name"`
	StepType   string                 `json:"step_type"` // condition, action, evaluation
	Expression string                 `json:"expression,omitempty"`
	Input      map[string]interface{} `json:"input"`
	Output     interface{}            `json:"output"`
	Result     bool                   `json:"result"`
	Duration   time.Duration          `json:"duration"`
	Timestamp  time.Time              `json:"timestamp"`
	Variables  map[string]interface{} `json:"variables"`
	Message    string                 `json:"message,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// DebugSession represents a debugging session
type DebugSession struct {
	ID             string                 `json:"id"`
	PolicyFile     string                 `json:"policy_file"`
	TestDataFile   string                 `json:"test_data_file"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	TotalSteps     int                    `json:"total_steps"`
	BreakPoints    map[string]bool        `json:"break_points"`
	Variables      map[string]interface{} `json:"variables"`
	ExecutionTrace []ExecutionStep        `json:"execution_trace"`
}

func runDebugger(policyFile, testDataFile string, interactive, stepMode bool, breakPoints, watchVars []string, outputFile, transactionID string) error {
	debugger := &PolicyDebugger{
		PolicyFile:     policyFile,
		TestDataFile:   testDataFile,
		BreakPoints:    make(map[string]bool),
		StepMode:       stepMode,
		WatchVariables: watchVars,
		Interactive:    interactive,
		OutputFile:     outputFile,
		Variables:      make(map[string]interface{}),
	}

	// Set breakpoints
	for _, bp := range breakPoints {
		debugger.BreakPoints[bp] = true
	}

	// Load policy
	if err := debugger.loadPolicy(); err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Load test data if provided
	if testDataFile != "" {
		if err := debugger.loadTestData(transactionID); err != nil {
			return fmt.Errorf("failed to load test data: %w", err)
		}
	}

	// Start debugging session
	if interactive {
		return debugger.runInteractiveSession()
	} else {
		return debugger.runBatchSession()
	}
}

// loadPolicy loads and parses the policy file
func (d *PolicyDebugger) loadPolicy() error {
	data, err := ioutil.ReadFile(d.PolicyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	d.Policy = &ParsedPolicy{}
	if err := yaml.Unmarshal(data, d.Policy); err != nil {
		return fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	fmt.Printf("✅ Loaded policy: %s (version %s)\n", d.Policy.Template.Name, d.Policy.Template.Version)
	fmt.Printf("   Asset Class: %s\n", d.Policy.Template.AssetClass)
	fmt.Printf("   Jurisdiction: %s\n", d.Policy.Template.Jurisdiction)
	fmt.Printf("   Rules: %d\n", len(d.Policy.Policy.Rules))
	fmt.Printf("   Parameters: %d\n", len(d.Policy.Parameters))

	return nil
}

// loadTestData loads test transaction data
func (d *PolicyDebugger) loadTestData(transactionID string) error {
	data, err := ioutil.ReadFile(d.TestDataFile)
	if err != nil {
		return fmt.Errorf("failed to read test data file: %w", err)
	}

	if err := json.Unmarshal(data, &d.TestData); err != nil {
		return fmt.Errorf("failed to parse test data JSON: %w", err)
	}

	fmt.Printf("✅ Loaded test data: %d transactions\n", len(d.TestData))

	// Filter by transaction ID if specified
	if transactionID != "" {
		var filtered []TransactionData
		for _, tx := range d.TestData {
			if tx.ID == transactionID {
				filtered = append(filtered, tx)
				break
			}
		}

		if len(filtered) == 0 {
			return fmt.Errorf("transaction ID %s not found", transactionID)
		}

		d.TestData = filtered
		fmt.Printf("   Filtered to transaction: %s\n", transactionID)
	}

	return nil
}

// runInteractiveSession starts an interactive debugging session
func (d *PolicyDebugger) runInteractiveSession() error {
	fmt.Println("\n🐛 Starting Interactive Policy Debugging Session")
	fmt.Println("===============================================")
	fmt.Println("Commands:")
	fmt.Println("  help, h          - Show help")
	fmt.Println("  run, r           - Run policy evaluation")
	fmt.Println("  step, s          - Step to next rule")
	fmt.Println("  break <rule_id>  - Set breakpoint")
	fmt.Println("  unbreak <rule_id>- Remove breakpoint")
	fmt.Println("  list, l          - List rules")
	fmt.Println("  vars, v          - Show variables")
	fmt.Println("  watch <var>      - Watch variable")
	fmt.Println("  unwatch <var>    - Stop watching variable")
	fmt.Println("  trace, t         - Show execution trace")
	fmt.Println("  transaction <n>  - Switch to transaction N")
	fmt.Println("  save <file>      - Save debug session")
	fmt.Println("  quit, q          - Quit debugger")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("(debugger) ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := strings.ToLower(parts[0])

		switch command {
		case "help", "h":
			d.showHelp()
		case "run", "r":
			d.runEvaluation()
		case "step", "s":
			d.stepExecution()
		case "break":
			if len(parts) > 1 {
				d.setBreakpoint(parts[1])
			} else {
				fmt.Println("Usage: break <rule_id>")
			}
		case "unbreak":
			if len(parts) > 1 {
				d.removeBreakpoint(parts[1])
			} else {
				fmt.Println("Usage: unbreak <rule_id>")
			}
		case "list", "l":
			d.listRules()
		case "vars", "v":
			d.showVariables()
		case "watch":
			if len(parts) > 1 {
				d.watchVariable(parts[1])
			} else {
				fmt.Println("Usage: watch <variable_name>")
			}
		case "unwatch":
			if len(parts) > 1 {
				d.unwatchVariable(parts[1])
			} else {
				fmt.Println("Usage: unwatch <variable_name>")
			}
		case "trace", "t":
			d.showExecutionTrace()
		case "transaction":
			if len(parts) > 1 {
				if n, err := strconv.Atoi(parts[1]); err == nil {
					d.switchTransaction(n)
				} else {
					fmt.Printf("Invalid transaction number: %s\n", parts[1])
				}
			} else {
				fmt.Println("Usage: transaction <number>")
			}
		case "save":
			if len(parts) > 1 {
				d.saveSession(parts[1])
			} else {
				fmt.Println("Usage: save <filename>")
			}
		case "quit", "q":
			fmt.Println("Exiting debugger...")
			return nil
		default:
			fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", command)
		}
	}

	return nil
}

// runBatchSession runs a non-interactive debugging session
func (d *PolicyDebugger) runBatchSession() error {
	fmt.Println("\n🐛 Running Batch Policy Debugging Session")
	fmt.Println("========================================")

	if len(d.TestData) == 0 {
		return fmt.Errorf("no test data provided for batch debugging")
	}

	session := &DebugSession{
		ID:           fmt.Sprintf("debug-%d", time.Now().Unix()),
		PolicyFile:   d.PolicyFile,
		TestDataFile: d.TestDataFile,
		StartTime:    time.Now(),
		BreakPoints:  d.BreakPoints,
		Variables:    d.Variables,
	}

	// Run evaluation for each transaction
	for i, transaction := range d.TestData {
		fmt.Printf("\n📊 Evaluating Transaction %d: %s\n", i+1, transaction.ID)
		d.CurrentTransaction = i

		if err := d.debugTransaction(&transaction); err != nil {
			fmt.Printf("❌ Error evaluating transaction %s: %v\n", transaction.ID, err)
			continue
		}
	}

	session.EndTime = time.Now()
	session.TotalSteps = len(d.ExecutionTrace)
	session.ExecutionTrace = d.ExecutionTrace

	// Save session if output file specified
	if d.OutputFile != "" {
		if err := d.saveSessionToFile(session, d.OutputFile); err != nil {
			return fmt.Errorf("failed to save session: %w", err)
		}
		fmt.Printf("\n💾 Debug session saved to: %s\n", d.OutputFile)
	}

	fmt.Printf("\n✅ Batch debugging completed. Total steps: %d\n", len(d.ExecutionTrace))
	return nil
}

// debugTransaction debugs a single transaction
func (d *PolicyDebugger) debugTransaction(transaction *TransactionData) error {
	// Initialize variables with transaction data
	d.Variables = map[string]interface{}{
		"transaction_id":             transaction.ID,
		"asset_class":                transaction.AssetClass,
		"jurisdiction":               transaction.Jurisdiction,
		"amount":                     transaction.Amount,
		"currency":                   transaction.Currency,
		"age":                        transaction.Applicant.Age,
		"annual_income":              transaction.Applicant.AnnualIncome,
		"employment_status":          transaction.Applicant.EmploymentStatus,
		"employment_length_months":   transaction.Applicant.EmploymentLengthMonths,
		"credit_score":               transaction.Applicant.CreditScore,
		"debt_to_income_ratio":       transaction.Applicant.DebtToIncomeRatio,
		"existing_credit_accounts":   transaction.Applicant.ExistingCreditAccounts,
		"payment_history":            transaction.Applicant.PaymentHistory,
		"bankruptcy_history":         transaction.Applicant.BankruptcyHistory,
		"military_status":            transaction.Applicant.MilitaryStatus,
		"requested_amount":           transaction.ApplicationData.RequestedAmount,
		"intended_use":               transaction.ApplicationData.IntendedUse,
		"application_method":         transaction.ApplicationData.ApplicationMethod,
		"income_verification_method": transaction.ApplicationData.IncomeVerificationMethod,
		"identity_verified":          transaction.ApplicationData.IdentityVerified,
		"risk_score":                 transaction.RiskMetrics.RiskScore,
		"risk_tier":                  transaction.RiskMetrics.RiskTier,
		"probability_of_default":     transaction.RiskMetrics.ProbabilityOfDefault,
		"loss_given_default":         transaction.RiskMetrics.LossGivenDefault,
		"kyc_passed":                 transaction.ComplianceChecks.KYCPassed,
		"aml_cleared":                transaction.ComplianceChecks.AMLCleared,
		"credit_check_completed":     transaction.ComplianceChecks.CreditCheckCompleted,
		"income_verified":            transaction.ComplianceChecks.IncomeVerified,
		"compliance_score":           transaction.ComplianceChecks.ComplianceScore,
	}

	// Add policy parameters to variables
	for name, param := range d.Policy.Parameters {
		d.Variables[name] = param.Default
	}

	// Process each rule
	for _, rule := range d.Policy.Policy.Rules {
		if !rule.Enabled {
			continue
		}

		if err := d.debugRule(&rule, transaction); err != nil {
			return fmt.Errorf("error debugging rule %s: %w", rule.ID, err)
		}

		// Check for breakpoints
		if d.BreakPoints[rule.ID] && d.Interactive {
			fmt.Printf("🔴 Breakpoint hit at rule: %s (%s)\n", rule.ID, rule.Name)
			return nil
		}
	}

	return nil
}

// debugRule debugs a single policy rule
func (d *PolicyDebugger) debugRule(rule *PolicyRule, transaction *TransactionData) error {
	fmt.Printf("  🔍 Rule: %s (%s)\n", rule.ID, rule.Name)
	fmt.Printf("      Type: %s, Priority: %s\n", rule.Type, rule.Priority)

	stepID := len(d.ExecutionTrace)
	startTime := time.Now()

	// Evaluate conditions
	conditionResults := make([]bool, len(rule.Conditions))
	allConditionsPassed := true

	for i, condition := range rule.Conditions {
		conditionResult, err := d.evaluateCondition(condition, rule.ID, stepID+i)
		if err != nil {
			return fmt.Errorf("error evaluating condition '%s': %w", condition, err)
		}

		conditionResults[i] = conditionResult
		if !conditionResult {
			allConditionsPassed = false
		}

		fmt.Printf("      Condition %d: %s -> %v\n", i+1, condition, conditionResult)

		// Record execution step
		step := ExecutionStep{
			StepID:     stepID + i,
			RuleID:     rule.ID,
			RuleName:   rule.Name,
			StepType:   "condition",
			Expression: condition,
			Input:      copyMap(d.Variables),
			Output:     conditionResult,
			Result:     conditionResult,
			Duration:   time.Since(startTime),
			Timestamp:  time.Now(),
			Variables:  copyMap(d.Variables),
		}

		d.ExecutionTrace = append(d.ExecutionTrace, step)
	}

	// Execute actions if conditions pass
	if allConditionsPassed {
		fmt.Printf("      ✅ All conditions passed, executing actions\n")

		for i, action := range rule.Actions {
			if err := d.executeAction(action, rule.ID, stepID+len(rule.Conditions)+i); err != nil {
				return fmt.Errorf("error executing action '%s': %w", action, err)
			}

			fmt.Printf("      Action %d: %s -> executed\n", i+1, action)
		}
	} else {
		fmt.Printf("      ❌ Conditions failed, skipping actions\n")
	}

	// Show watched variables
	d.showWatchedVariables()

	return nil
}

// evaluateCondition evaluates a single condition
func (d *PolicyDebugger) evaluateCondition(condition string, ruleID string, stepID int) (bool, error) {
	// Simple expression evaluation (in a real implementation, this would use a proper expression evaluator)

	// Replace variables in the condition
	evaluatedCondition := condition
	for varName, varValue := range d.Variables {
		placeholder := fmt.Sprintf("${%s}", varName)
		if strings.Contains(evaluatedCondition, placeholder) {
			evaluatedCondition = strings.ReplaceAll(evaluatedCondition, placeholder, fmt.Sprintf("%v", varValue))
		}

		// Also handle direct variable references
		if strings.Contains(evaluatedCondition, varName) && !strings.Contains(evaluatedCondition, "${") {
			// Simple heuristic - replace standalone variable names
			evaluatedCondition = strings.ReplaceAll(evaluatedCondition, varName, fmt.Sprintf("%v", varValue))
		}
	}

	// Simple condition evaluation (in practice, you'd use a proper expression evaluator)
	result := d.evaluateSimpleExpression(evaluatedCondition)

	return result, nil
}

// evaluateSimpleExpression performs basic expression evaluation
func (d *PolicyDebugger) evaluateSimpleExpression(expr string) bool {
	// Very basic expression evaluation for demonstration
	// In a real implementation, you'd use a proper expression parser

	expr = strings.TrimSpace(expr)

	// Handle boolean literals
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	// Handle simple comparisons
	if strings.Contains(expr, ">=") {
		parts := strings.Split(expr, ">=")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, leftErr := strconv.ParseFloat(left, 64)
			rightVal, rightErr := strconv.ParseFloat(right, 64)

			if leftErr == nil && rightErr == nil {
				return leftVal >= rightVal
			}
		}
	}

	if strings.Contains(expr, "<=") {
		parts := strings.Split(expr, "<=")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, leftErr := strconv.ParseFloat(left, 64)
			rightVal, rightErr := strconv.ParseFloat(right, 64)

			if leftErr == nil && rightErr == nil {
				return leftVal <= rightVal
			}
		}
	}

	if strings.Contains(expr, "==") {
		parts := strings.Split(expr, "==")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			// Try numeric comparison
			leftVal, leftErr := strconv.ParseFloat(left, 64)
			rightVal, rightErr := strconv.ParseFloat(right, 64)

			if leftErr == nil && rightErr == nil {
				return leftVal == rightVal
			}

			// String comparison
			return left == right
		}
	}

	if strings.Contains(expr, ">") && !strings.Contains(expr, ">=") {
		parts := strings.Split(expr, ">")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, leftErr := strconv.ParseFloat(left, 64)
			rightVal, rightErr := strconv.ParseFloat(right, 64)

			if leftErr == nil && rightErr == nil {
				return leftVal > rightVal
			}
		}
	}

	if strings.Contains(expr, "<") && !strings.Contains(expr, "<=") {
		parts := strings.Split(expr, "<")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			leftVal, leftErr := strconv.ParseFloat(left, 64)
			rightVal, rightErr := strconv.ParseFloat(right, 64)

			if leftErr == nil && rightErr == nil {
				return leftVal < rightVal
			}
		}
	}

	// Default to true for unrecognized expressions (in practice, this should be an error)
	return true
}

// executeAction executes a policy action
func (d *PolicyDebugger) executeAction(action string, ruleID string, stepID int) error {
	startTime := time.Now()

	// Record action execution
	step := ExecutionStep{
		StepID:     stepID,
		RuleID:     ruleID,
		StepType:   "action",
		Expression: action,
		Input:      copyMap(d.Variables),
		Output:     "executed",
		Result:     true,
		Duration:   time.Since(startTime),
		Timestamp:  time.Now(),
		Variables:  copyMap(d.Variables),
		Message:    fmt.Sprintf("Executed action: %s", action),
	}

	d.ExecutionTrace = append(d.ExecutionTrace, step)

	// Simulate action execution (in practice, this would perform actual actions)
	switch action {
	case "validate_credit_score":
		d.Variables["credit_validation_result"] = d.Variables["credit_score"].(int) >= 600
	case "verify_income":
		d.Variables["income_verification_result"] = d.Variables["income_verified"].(bool)
	case "assess_risk":
		d.Variables["risk_assessment_result"] = d.Variables["risk_score"].(float64) >= 650
	}

	return nil
}

// Interactive session commands

func (d *PolicyDebugger) showHelp() {
	fmt.Println("Available Commands:")
	fmt.Println("==================")
	fmt.Println("  help, h          - Show this help message")
	fmt.Println("  run, r           - Run policy evaluation on current transaction")
	fmt.Println("  step, s          - Step to next rule execution")
	fmt.Println("  break <rule_id>  - Set breakpoint on rule")
	fmt.Println("  unbreak <rule_id>- Remove breakpoint from rule")
	fmt.Println("  list, l          - List all policy rules")
	fmt.Println("  vars, v          - Show current variables")
	fmt.Println("  watch <var>      - Watch a variable for changes")
	fmt.Println("  unwatch <var>    - Stop watching a variable")
	fmt.Println("  trace, t         - Show execution trace")
	fmt.Println("  transaction <n>  - Switch to transaction N (0-based)")
	fmt.Println("  save <file>      - Save debug session to file")
	fmt.Println("  quit, q          - Exit debugger")
	fmt.Println()
}

func (d *PolicyDebugger) runEvaluation() {
	if len(d.TestData) == 0 {
		fmt.Println("❌ No test data loaded. Use --test-data flag to load transaction data.")
		return
	}

	transaction := &d.TestData[d.CurrentTransaction]
	fmt.Printf("🚀 Running evaluation for transaction: %s\n", transaction.ID)

	if err := d.debugTransaction(transaction); err != nil {
		fmt.Printf("❌ Error during evaluation: %v\n", err)
	} else {
		fmt.Printf("✅ Evaluation completed\n")
	}
}

func (d *PolicyDebugger) stepExecution() {
	// This would implement step-by-step execution
	fmt.Println("⏭️  Stepping to next rule... (not fully implemented in this example)")
}

func (d *PolicyDebugger) setBreakpoint(ruleID string) {
	d.BreakPoints[ruleID] = true
	fmt.Printf("🔴 Breakpoint set on rule: %s\n", ruleID)
}

func (d *PolicyDebugger) removeBreakpoint(ruleID string) {
	delete(d.BreakPoints, ruleID)
	fmt.Printf("⚪ Breakpoint removed from rule: %s\n", ruleID)
}

func (d *PolicyDebugger) listRules() {
	fmt.Println("📋 Policy Rules:")
	fmt.Println("===============")

	for i, rule := range d.Policy.Policy.Rules {
		status := "⚪"
		if d.BreakPoints[rule.ID] {
			status = "🔴"
		}
		if !rule.Enabled {
			status = "⚫"
		}

		fmt.Printf("  %s %d. %s (%s)\n", status, i+1, rule.Name, rule.ID)
		fmt.Printf("      Type: %s, Priority: %s, Enabled: %v\n", rule.Type, rule.Priority, rule.Enabled)
		fmt.Printf("      Conditions: %d, Actions: %d\n", len(rule.Conditions), len(rule.Actions))
	}

	fmt.Println("\nLegend: 🔴 Breakpoint, ⚪ Normal, ⚫ Disabled")
}

func (d *PolicyDebugger) showVariables() {
	fmt.Println("📊 Current Variables:")
	fmt.Println("====================")

	// Sort variables for consistent output
	var keys []string
	for k := range d.Variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := d.Variables[key]
		watchStatus := ""
		for _, watchVar := range d.WatchVariables {
			if watchVar == key {
				watchStatus = " 👁️"
				break
			}
		}

		fmt.Printf("  %s%s = %v\n", key, watchStatus, value)
	}
}

func (d *PolicyDebugger) watchVariable(varName string) {
	// Check if already watching
	for _, watchVar := range d.WatchVariables {
		if watchVar == varName {
			fmt.Printf("Variable %s is already being watched\n", varName)
			return
		}
	}

	d.WatchVariables = append(d.WatchVariables, varName)
	fmt.Printf("👁️  Now watching variable: %s\n", varName)
}

func (d *PolicyDebugger) unwatchVariable(varName string) {
	for i, watchVar := range d.WatchVariables {
		if watchVar == varName {
			d.WatchVariables = append(d.WatchVariables[:i], d.WatchVariables[i+1:]...)
			fmt.Printf("⚪ Stopped watching variable: %s\n", varName)
			return
		}
	}

	fmt.Printf("Variable %s was not being watched\n", varName)
}

func (d *PolicyDebugger) showWatchedVariables() {
	if len(d.WatchVariables) == 0 {
		return
	}

	fmt.Printf("      👁️  Watched variables: ")
	for i, varName := range d.WatchVariables {
		if i > 0 {
			fmt.Printf(", ")
		}
		if value, exists := d.Variables[varName]; exists {
			fmt.Printf("%s=%v", varName, value)
		} else {
			fmt.Printf("%s=<undefined>", varName)
		}
	}
	fmt.Println()
}

func (d *PolicyDebugger) showExecutionTrace() {
	fmt.Println("📈 Execution Trace:")
	fmt.Println("==================")

	if len(d.ExecutionTrace) == 0 {
		fmt.Println("No execution trace available. Run evaluation first.")
		return
	}

	for _, step := range d.ExecutionTrace {
		status := "✅"
		if !step.Result {
			status = "❌"
		}

		fmt.Printf("  %s Step %d: %s (%s)\n", status, step.StepID, step.RuleName, step.StepType)
		if step.Expression != "" {
			fmt.Printf("      Expression: %s\n", step.Expression)
		}
		fmt.Printf("      Result: %v, Duration: %v\n", step.Result, step.Duration)
		if step.Message != "" {
			fmt.Printf("      Message: %s\n", step.Message)
		}
		if step.Error != "" {
			fmt.Printf("      Error: %s\n", step.Error)
		}
	}
}

func (d *PolicyDebugger) switchTransaction(n int) {
	if n < 0 || n >= len(d.TestData) {
		fmt.Printf("❌ Invalid transaction number. Available: 0-%d\n", len(d.TestData)-1)
		return
	}

	d.CurrentTransaction = n
	transaction := &d.TestData[n]
	fmt.Printf("✅ Switched to transaction %d: %s\n", n, transaction.ID)
	fmt.Printf("   Asset Class: %s, Amount: %.2f %s\n",
		transaction.AssetClass, transaction.Amount, transaction.Currency)
}

func (d *PolicyDebugger) saveSession(filename string) {
	session := &DebugSession{
		ID:             fmt.Sprintf("debug-%d", time.Now().Unix()),
		PolicyFile:     d.PolicyFile,
		TestDataFile:   d.TestDataFile,
		StartTime:      time.Now(),
		EndTime:        time.Now(),
		TotalSteps:     len(d.ExecutionTrace),
		BreakPoints:    d.BreakPoints,
		Variables:      d.Variables,
		ExecutionTrace: d.ExecutionTrace,
	}

	if err := d.saveSessionToFile(session, filename); err != nil {
		fmt.Printf("❌ Failed to save session: %v\n", err)
	} else {
		fmt.Printf("💾 Session saved to: %s\n", filename)
	}
}

func (d *PolicyDebugger) saveSessionToFile(session *DebugSession, filename string) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// Helper functions

func copyMap(original map[string]interface{}) map[string]interface{} {
	copy := make(map[string]interface{})
	for k, v := range original {
		copy[k] = v
	}
	return copy
}
