package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/validator"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewValidateCmd() *cobra.Command {
	var (
		schemaFile   string
		strict       bool
		jurisdiction string
		assetClass   string
		reportFormat string
		outputFile   string
		recursive    bool
		pattern      string
		quiet        bool
		showSummary  bool
		interactive  bool
	)

	cmd := &cobra.Command{
		Use:   "validate [yaml-file] [options]",
		Short: "Validate YAML policies without compilation",
		Long: `Validate YAML compliance policies for syntax, structure, and business logic.

The validate command performs comprehensive validation including:
- YAML syntax and structure validation
- Schema compliance checking
- Business logic consistency
- Jurisdiction-specific requirements
- Cross-policy dependencies
- Performance impact analysis

Examples:
  # Basic validation
  compliance-compiler validate policy.yaml

  # Validate with custom schema
  compliance-compiler validate policy.yaml --schema custom-schema.json

  # Strict validation (fail on warnings)
  compliance-compiler validate policy.yaml --strict

  # Jurisdiction-specific validation
  compliance-compiler validate policy.yaml --jurisdiction US --asset-class credit-card

  # Validate multiple files recursively
  compliance-compiler validate ./policies --recursive --pattern "*.yaml"

  # Generate detailed report
  compliance-compiler validate policy.yaml --report-format detailed --output report.json

  # Interactive validation with guided fixes
  compliance-compiler validate policy.yaml --interactive`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(ValidateOptions{
				Target:       args[0],
				SchemaFile:   schemaFile,
				Strict:       strict,
				Jurisdiction: jurisdiction,
				AssetClass:   assetClass,
				ReportFormat: reportFormat,
				OutputFile:   outputFile,
				Recursive:    recursive,
				Pattern:      pattern,
				Quiet:        quiet,
				ShowSummary:  showSummary,
				Interactive:  interactive,
			})
		},
	}

	cmd.Flags().StringVar(&schemaFile, "schema", "", "schema file for validation")
	cmd.Flags().BoolVar(&strict, "strict", false, "enable strict validation mode (fail on warnings)")
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "jurisdiction-specific validation (US, EU, CA, etc.)")
	cmd.Flags().StringVar(&assetClass, "asset-class", "", "asset class validation (credit-card, installment-loan, etc.)")
	cmd.Flags().StringVar(&reportFormat, "report-format", "summary", "validation report format: summary, detailed, json, junit")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for validation report (default: stdout)")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "validate files recursively")
	cmd.Flags().StringVarP(&pattern, "pattern", "p", "*.yaml", "file pattern for recursive validation")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress progress output")
	cmd.Flags().BoolVar(&showSummary, "summary", true, "show validation summary")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "interactive mode with guided fixes")

	// Add shell completion
	cmd.RegisterFlagCompletionFunc("report-format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"summary", "detailed", "json", "junit"}, cobra.ShellCompDirectiveDefault
	})

	cmd.RegisterFlagCompletionFunc("jurisdiction", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"US", "EU", "CA", "UK", "AU", "JP", "SG"}, cobra.ShellCompDirectiveDefault
	})

	cmd.RegisterFlagCompletionFunc("asset-class", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"credit-card", "installment-loan", "mca", "equipment-lease", "working-capital"}, cobra.ShellCompDirectiveDefault
	})

	return cmd
}

type ValidateOptions struct {
	Target       string
	SchemaFile   string
	Strict       bool
	Jurisdiction string
	AssetClass   string
	ReportFormat string
	OutputFile   string
	Recursive    bool
	Pattern      string
	Quiet        bool
	ShowSummary  bool
	Interactive  bool
}

func runValidate(opts ValidateOptions) error {
	// Initialize colored output
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)

	if !opts.Quiet {
		blue.Printf("🔍 Starting validation of: %s\n", opts.Target)
	}

	// Check target exists
	stat, err := os.Stat(opts.Target)
	if os.IsNotExist(err) {
		return &ValidateError{
			Type:    "target_not_found",
			Message: fmt.Sprintf("Target does not exist: %s", opts.Target),
			Suggestions: []string{
				"Check the path for typos",
				"Ensure the file or directory exists",
				"Use an absolute path if needed",
			},
		}
	}

	// Find files to validate
	files, err := findValidationFiles(opts.Target, stat.IsDir(), opts.Recursive, opts.Pattern)
	if err != nil {
		return &ValidateError{
			Type:    "file_discovery_error",
			Message: fmt.Sprintf("Failed to find files: %v", err),
			Suggestions: []string{
				"Check directory permissions",
				"Verify the file pattern is correct",
				"Ensure files have the correct extension",
			},
		}
	}

	if len(files) == 0 {
		return &ValidateError{
			Type:    "no_files_found",
			Message: "No policy files found to validate",
			Suggestions: []string{
				fmt.Sprintf("Check if files match pattern: %s", opts.Pattern),
				"Use --recursive flag for subdirectories",
				"Verify file extensions are correct (.yaml, .yml)",
			},
		}
	}

	if !opts.Quiet {
		fmt.Printf("📁 Found %d policy file(s) to validate\n", len(files))
	}

	// Initialize progress bar
	var bar *progressbar.ProgressBar
	if !opts.Quiet {
		bar = progressbar.NewOptions(len(files),
			progressbar.OptionSetDescription("Validating policies..."),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(50),
		)
	}

	// Initialize validator
	policyValidator := validator.NewPolicyValidator()

	// Configure validator
	if opts.SchemaFile != "" {
		if !opts.Quiet {
			fmt.Printf("📋 Using custom schema: %s\n", opts.SchemaFile)
		}
		// TODO: Load and configure custom schema
	}

	if opts.Jurisdiction != "" {
		if !opts.Quiet {
			fmt.Printf("⚖️  Jurisdiction: %s\n", opts.Jurisdiction)
		}
		// TODO: Configure jurisdiction-specific validation
	}

	if opts.AssetClass != "" {
		if !opts.Quiet {
			fmt.Printf("🏷️  Asset Class: %s\n", opts.AssetClass)
		}
		// TODO: Configure asset class-specific validation
	}

	// Validate each file
	results := make([]FileValidationResult, 0, len(files))
	totalErrors := 0
	totalWarnings := 0

	for i, file := range files {
		if !opts.Quiet {
			bar.Set(i)
		}

		result := validateSingleFile(file, policyValidator, opts)
		results = append(results, result)

		totalErrors += len(result.Errors)
		totalWarnings += len(result.Warnings)

		// Interactive mode - offer to fix issues
		if opts.Interactive && (len(result.Errors) > 0 || len(result.Warnings) > 0) {
			if err := interactiveFixSuggestions(file, result); err != nil {
				logrus.Debugf("Interactive fix failed: %v", err)
			}
		}
	}

	if !opts.Quiet {
		bar.Set(len(files))
		bar.Finish()
		fmt.Println()
	}

	// Generate validation report
	report := &ValidationReport{
		Timestamp:     time.Now(),
		TotalFiles:    len(files),
		TotalErrors:   totalErrors,
		TotalWarnings: totalWarnings,
		Results:       results,
		Options:       opts,
	}

	// Output report
	if err := outputValidationReport(report, opts); err != nil {
		return &ValidateError{
			Type:    "report_output_error",
			Message: fmt.Sprintf("Failed to output validation report: %v", err),
			Suggestions: []string{
				"Check output file permissions",
				"Ensure output directory exists",
				"Verify disk space is available",
			},
		}
	}

	// Show summary
	if opts.ShowSummary && !opts.Quiet {
		printValidationSummary(report)
	}

	// Determine exit status
	if totalErrors > 0 {
		return &ValidateError{
			Type:    "validation_failed",
			Message: fmt.Sprintf("Validation failed with %d error(s)", totalErrors),
			Suggestions: []string{
				"Review the validation errors above",
				"Use --interactive mode for guided fixes",
				"Check the policy documentation",
			},
		}
	}

	if opts.Strict && totalWarnings > 0 {
		return &ValidateError{
			Type:    "strict_mode_warnings",
			Message: fmt.Sprintf("Strict mode: %d warning(s) treated as errors", totalWarnings),
			Suggestions: []string{
				"Fix the warnings to pass strict validation",
				"Remove --strict flag to allow warnings",
				"Review warning details for specific fixes",
			},
		}
	}

	if !opts.Quiet {
		green.Printf("✅ All policies validated successfully!\n")
		if totalWarnings > 0 {
			yellow.Printf("⚠️  %d warning(s) found but validation passed\n", totalWarnings)
		}
	}

	return nil
}

func validateSingleFile(file string, policyValidator *validator.PolicyValidator, opts ValidateOptions) FileValidationResult {
	result := FileValidationResult{
		File:      file,
		Timestamp: time.Now(),
	}

	// Parse YAML file
	yamlParser := parser.NewYAMLParser()
	policy, err := yamlParser.ParseFile(file)
	if err != nil {
		result.Errors = append(result.Errors, ValidationIssue{
			Type:     "parse_error",
			Severity: "error",
			Message:  fmt.Sprintf("Failed to parse YAML: %v", err),
			Location: "file",
			Suggestions: []string{
				"Check YAML syntax (indentation, colons, quotes)",
				"Validate with a YAML linter",
				"Check for special characters that need escaping",
			},
		})
		return result
	}

	// Perform comprehensive validation
	validationReport := policyValidator.ValidatePolicy(policy)

	// Convert validator errors to our format
	for _, err := range validationReport.Errors {
		result.Errors = append(result.Errors, ValidationIssue{
			Type:        err.Code,
			Severity:    "error",
			Message:     err.Message,
			Location:    err.Field,
			Suggestions: []string{err.SuggestedFix},
		})
	}

	// Convert validator warnings to our format
	for _, warn := range validationReport.Warnings {
		result.Warnings = append(result.Warnings, ValidationIssue{
			Type:        warn.Code,
			Severity:    "warning",
			Message:     warn.Message,
			Location:    warn.Field,
			Suggestions: []string{warn.Recommendation},
		})
	}

	// Add validation metadata
	result.ValidationDuration = time.Since(result.Timestamp)
	result.PolicyInfo = &PolicyInfo{
		RuleCount:        len(policy.Rules),
		AttestationCount: len(policy.Attestations),
		// Add more policy metadata as needed
	}

	return result
}

type FileValidationResult struct {
	File               string            `json:"file"`
	Timestamp          time.Time         `json:"timestamp"`
	ValidationDuration time.Duration     `json:"validation_duration"`
	Errors             []ValidationIssue `json:"errors,omitempty"`
	Warnings           []ValidationIssue `json:"warnings,omitempty"`
	PolicyInfo         *PolicyInfo       `json:"policy_info,omitempty"`
}

type ValidationIssue struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Message     string   `json:"message"`
	Location    string   `json:"location,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

type PolicyInfo struct {
	RuleCount        int `json:"rule_count"`
	AttestationCount int `json:"attestation_count"`
}

type ValidationReport struct {
	Timestamp     time.Time              `json:"timestamp"`
	TotalFiles    int                    `json:"total_files"`
	TotalErrors   int                    `json:"total_errors"`
	TotalWarnings int                    `json:"total_warnings"`
	Results       []FileValidationResult `json:"results"`
	Options       ValidateOptions        `json:"options"`
}

func findValidationFiles(target string, isDir, recursive bool, pattern string) ([]string, error) {
	if !isDir {
		return []string{target}, nil
	}

	var files []string

	if recursive {
		err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				matched, err := filepath.Match(pattern, info.Name())
				if err != nil {
					return err
				}
				if matched {
					files = append(files, path)
				}
			}
			return nil
		})
		return files, err
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			matched, err := filepath.Match(pattern, entry.Name())
			if err != nil {
				return nil, err
			}
			if matched {
				files = append(files, filepath.Join(target, entry.Name()))
			}
		}
	}

	return files, nil
}

func outputValidationReport(report *ValidationReport, opts ValidateOptions) error {
	var output []byte
	var err error

	switch opts.ReportFormat {
	case "summary":
		return outputSummaryReport(report, opts.OutputFile)
	case "detailed":
		return outputDetailedReport(report, opts.OutputFile)
	case "json":
		output, err = json.MarshalIndent(report, "", "  ")
	case "junit":
		return outputJUnitReport(report, opts.OutputFile)
	default:
		return fmt.Errorf("unsupported report format: %s", opts.ReportFormat)
	}

	if err != nil {
		return err
	}

	if opts.OutputFile != "" {
		return os.WriteFile(opts.OutputFile, output, 0644)
	}

	fmt.Print(string(output))
	return nil
}

func outputSummaryReport(report *ValidationReport, outputFile string) error {
	// Implementation for summary format
	return outputDetailedReport(report, outputFile) // Simplified for now
}

func outputDetailedReport(report *ValidationReport, outputFile string) error {
	var output strings.Builder

	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	output.WriteString("📋 Validation Report\n")
	output.WriteString("===================\n\n")

	for _, result := range report.Results {
		output.WriteString(fmt.Sprintf("File: %s\n", result.File))

		if len(result.Errors) == 0 && len(result.Warnings) == 0 {
			green.Fprintf(&output, "  Status: ✅ Valid\n")
		} else {
			if len(result.Errors) > 0 {
				red.Fprintf(&output, "  Status: ❌ Invalid (%d errors)\n", len(result.Errors))
				output.WriteString("  Errors:\n")
				for _, err := range result.Errors {
					output.WriteString(fmt.Sprintf("    • %s: %s\n", err.Type, err.Message))
					if len(err.Suggestions) > 0 && err.Suggestions[0] != "" {
						output.WriteString(fmt.Sprintf("      💡 %s\n", err.Suggestions[0]))
					}
				}
			}

			if len(result.Warnings) > 0 {
				yellow.Fprintf(&output, "  Warnings (%d):\n", len(result.Warnings))
				for _, warn := range result.Warnings {
					output.WriteString(fmt.Sprintf("    • %s: %s\n", warn.Type, warn.Message))
				}
			}
		}

		if result.PolicyInfo != nil {
			output.WriteString(fmt.Sprintf("  Rules: %d, Attestations: %d\n",
				result.PolicyInfo.RuleCount, result.PolicyInfo.AttestationCount))
		}

		output.WriteString(fmt.Sprintf("  Duration: %v\n\n", result.ValidationDuration))
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output.String()), 0644)
	}

	fmt.Print(output.String())
	return nil
}

func outputJUnitReport(report *ValidationReport, outputFile string) error {
	// Placeholder for JUnit XML format
	return fmt.Errorf("JUnit format not yet implemented")
}

func printValidationSummary(report *ValidationReport) {
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	fmt.Println("\n📊 Validation Summary")
	fmt.Println("====================")
	fmt.Printf("Total Files: %d\n", report.TotalFiles)

	if report.TotalErrors > 0 {
		red.Printf("Errors: %d\n", report.TotalErrors)
	} else {
		green.Printf("Errors: %d\n", report.TotalErrors)
	}

	if report.TotalWarnings > 0 {
		yellow.Printf("Warnings: %d\n", report.TotalWarnings)
	} else {
		fmt.Printf("Warnings: %d\n", report.TotalWarnings)
	}

	validFiles := 0
	for _, result := range report.Results {
		if len(result.Errors) == 0 {
			validFiles++
		}
	}

	if validFiles == report.TotalFiles {
		green.Printf("Valid Files: %d/%d (100%%)\n", validFiles, report.TotalFiles)
	} else {
		fmt.Printf("Valid Files: %d/%d (%.1f%%)\n", validFiles, report.TotalFiles,
			float64(validFiles)/float64(report.TotalFiles)*100)
	}
}

func interactiveFixSuggestions(file string, result FileValidationResult) error {
	// Placeholder for interactive mode implementation
	fmt.Printf("Interactive fixes for %s would be offered here\n", file)
	return nil
}

// ValidateError represents a user-friendly validation error
type ValidateError struct {
	Type        string   `json:"type"`
	Message     string   `json:"message"`
	Suggestions []string `json:"suggestions,omitempty"`
}

func (e *ValidateError) Error() string {
	var builder strings.Builder

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	red.Fprintf(&builder, "❌ Validation Error: %s\n", e.Message)

	if len(e.Suggestions) > 0 {
		builder.WriteString("\n")
		yellow.Fprintf(&builder, "💡 Suggestions:\n")
		for _, suggestion := range e.Suggestions {
			fmt.Fprintf(&builder, "  • %s\n", suggestion)
		}
	}

	return builder.String()
}
