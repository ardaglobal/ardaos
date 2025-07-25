package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	compliancev1 "github.com/arda-org/arda-os/tools/compliance-compiler/gen/compliance/v1"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func NewCompileCmd() *cobra.Command {
	var (
		inputFile    string
		outputFile   string
		outputDir    string
		format       string
		validate     bool
		optimize     bool
		overwrite    bool
		jurisdiction string
		assetClass   string
		quiet        bool
	)

	cmd := &cobra.Command{
		Use:   "compile [yaml-file] [options]",
		Short: "Convert YAML policies to protobuf",
		Long: `Compile YAML compliance policies into protobuf format for use with ArdaOS.

The compile command takes YAML policy files and converts them into optimized
protobuf messages that can be used by the ArdaOS compliance module. It supports
comprehensive validation, optimization passes, and multiple output formats.

Examples:
  # Basic compilation
  compliance-compiler compile policy.yaml

  # Compile with validation for specific jurisdiction
  compliance-compiler compile policy.yaml --jurisdiction US --asset-class credit-card

  # Compile with optimization and custom output
  compliance-compiler compile policy.yaml -o policy.pb --optimize --format binary

  # Compile to JSON format for debugging
  compliance-compiler compile policy.yaml --format json -o policy.json

  # Compile without validation (faster but not recommended)
  compliance-compiler compile policy.yaml --no-validate

  # Quiet mode for CI/CD
  compliance-compiler compile policy.yaml --quiet`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile = args[0]
			return runCompile(inputFile, outputFile, outputDir, format, validate, optimize, overwrite, jurisdiction, assetClass, quiet)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path (default: stdout or <input>.pb)")
	cmd.Flags().StringVar(&format, "format", "binary", "output format: binary, json, text")
	cmd.Flags().BoolVar(&validate, "validate", true, "validate policy before compilation")
	cmd.Flags().BoolVar(&optimize, "optimize", false, "apply optimization passes")
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "target jurisdiction for validation (e.g., US, EU, CA)")
	cmd.Flags().StringVar(&assetClass, "asset-class", "", "target asset class (credit-card, installment-loan, mca, equipment-lease, working-capital)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing output files")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress all non-error output")

	// Add shell completion for format flag
	cmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"binary", "json", "text"}, cobra.ShellCompDirectiveDefault
	})

	// Add shell completion for jurisdiction flag
	cmd.RegisterFlagCompletionFunc("jurisdiction", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"US", "EU", "CA", "UK", "AU", "JP", "SG"}, cobra.ShellCompDirectiveDefault
	})

	// Add shell completion for asset-class flag
	cmd.RegisterFlagCompletionFunc("asset-class", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"credit-card", "installment-loan", "mca", "equipment-lease", "working-capital"}, cobra.ShellCompDirectiveDefault
	})

	return cmd
}

func runCompile(inputFile, outputFile, outputDir, format string, validate, optimize, overwrite bool, jurisdiction, assetClass string, quiet bool) error {
	// Initialize colored output
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)

	if !quiet {
		blue.Printf("🚀 Starting compilation of: %s\n", inputFile)
	}

	// Check input file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return &CompileError{
			Type:    "input_file_not_found",
			Message: fmt.Sprintf("Input file does not exist: %s", inputFile),
			Suggestions: []string{
				"Check the file path for typos",
				"Ensure the file exists in the current directory",
				"Use an absolute path if the file is in a different directory",
			},
		}
	}

	// Initialize progress bar if not in quiet mode
	var bar *progressbar.ProgressBar
	if !quiet {
		bar = progressbar.NewOptions(100,
			progressbar.OptionSetDescription("Compiling policy..."),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetWidth(50),
		)
	}

	// Step 1: Parse and Validate YAML with JSON Schema (60%)
	if !quiet {
		bar.Set(10)
		fmt.Printf("\n📖 Parsing and validating YAML policy file...\n")
	}

	// Create parser with options
	parsingOptions := parser.ParsingOptions{
		StrictMode:     false, // Don't fail on warnings by default
		EnableWarnings: true,  // Show warnings
	}

	// Override strict mode if specified
	if jurisdiction != "" || assetClass != "" {
		if !quiet {
			if jurisdiction != "" {
				fmt.Printf("  ⚖️  Jurisdiction: %s\n", jurisdiction)
			}
			if assetClass != "" {
				fmt.Printf("  🏷️  Asset Class: %s\n", assetClass)
			}
		}
	}

	policyParser, err := parser.NewPolicyParser(parsingOptions)
	if err != nil {
		return &CompileError{
			Type:    "parser_init_error",
			Message: fmt.Sprintf("Failed to initialize policy parser: %v", err),
			Suggestions: []string{
				"Check that JSON schema files are present",
				"Verify compliance-compiler installation",
			},
		}
	}

	parseResult, err := policyParser.ParseYAMLFile(inputFile)
	if err != nil {
		// Handle validation errors
		if parseResult != nil && parseResult.ValidationResult != nil && !parseResult.ValidationResult.Valid {
			if !quiet {
				red.Printf("\n❌ Policy validation failed:\n")
				for _, validationError := range parseResult.ValidationResult.Errors {
					fmt.Printf("  • %s: %s\n", validationError.Field, validationError.Message)
					if validationError.Suggestion != "" {
						yellow.Printf("    💡 Suggestion: %s\n", validationError.Suggestion)
					}
				}
			}
			return &CompileError{
				Type:    "validation_error",
				Message: "Policy validation failed",
				Details: parseResult.Errors,
				Suggestions: []string{
					"Review the validation errors above",
					"Check the JSON Schema documentation",
					"Ensure all required fields are present",
					"Consider using a template from 'compliance-compiler generate'",
				},
			}
		}

		return &CompileError{
			Type:    "parse_error",
			Message: fmt.Sprintf("Failed to parse YAML file: %v", err),
			Suggestions: []string{
				"Check YAML syntax for errors (indentation, colons, etc.)",
				"Validate YAML structure using a YAML linter",
				"Ensure all required fields are present",
				"Check for special characters that need escaping",
			},
		}
	}

	// Show warnings if any
	if !quiet && len(parseResult.Warnings) > 0 {
		yellow.Printf("  ⚠️  %d warnings found:\n", len(parseResult.Warnings))
		for _, warning := range parseResult.Warnings {
			fmt.Printf("    • %s\n", warning)
		}
	}

	if !quiet {
		green.Printf("  ✅ Policy parsed and validated successfully\n")
		bar.Set(60)
	}

	// Step 2: Output (100%)
	policy := parseResult.Policy

	if outputFile == "" && format != "binary" {
		// Output to stdout for non-binary formats
		if !quiet {
			fmt.Printf("📤 Writing to stdout...\n")
			bar.Set(100)
			bar.Finish()
			fmt.Println()
		}

		return writeProtobufOutput(policy, "", format)
	}

	// Determine output path
	outputPath, err := determineOutputPath(inputFile, outputFile, format)
	if err != nil {
		return &CompileError{
			Type:    "output_path_error",
			Message: fmt.Sprintf("Failed to determine output path: %v", err),
			Suggestions: []string{
				"Check output directory permissions",
				"Ensure output directory exists or can be created",
				"Verify output file extension is correct",
			},
		}
	}

	// Check for existing file
	if !overwrite {
		if _, err := os.Stat(outputPath); err == nil {
			return &CompileError{
				Type:    "output_file_exists",
				Message: fmt.Sprintf("Output file already exists: %s", outputPath),
				Suggestions: []string{
					"Use --overwrite to replace the existing file",
					"Specify a different output path with -o",
					"Move or rename the existing file",
				},
			}
		}
	}

	// Create output directory if needed
	if dir := filepath.Dir(outputPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return &CompileError{
				Type:    "create_directory_error",
				Message: fmt.Sprintf("Failed to create output directory: %v", err),
				Suggestions: []string{
					"Check directory permissions",
					"Ensure parent directories exist",
				},
			}
		}
	}

	if !quiet {
		fmt.Printf("📤 Writing to: %s\n", outputPath)
	}

	// Write output file
	if err := writeProtobufOutput(policy, outputPath, format); err != nil {
		return &CompileError{
			Type:    "write_error",
			Message: fmt.Sprintf("Failed to write output file: %v", err),
			Suggestions: []string{
				"Check file permissions",
				"Ensure sufficient disk space",
				"Verify output directory is writable",
			},
		}
	}

	if !quiet {
		bar.Set(100)
		bar.Finish()
		fmt.Println()
		green.Printf("✅ Successfully compiled policy to: %s\n", outputPath)

		// Show file size
		if stat, err := os.Stat(outputPath); err == nil {
			fmt.Printf("📊 Output file size: %s\n", formatFileSize(stat.Size()))
		}
	}

	return nil
}

func determineOutputPath(inputFile, outputFile, format string) (string, error) {
	if outputFile != "" {
		return outputFile, nil
	}

	var ext string
	switch format {
	case "binary":
		ext = ".pb"
	case "text":
		ext = ".pbtxt"
	case "json":
		ext = ".pb.json"
	default:
		return "", fmt.Errorf("unsupported output format: %s", format)
	}

	baseName := filepath.Base(inputFile)
	baseNameWithoutExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]
	outputFileName := baseNameWithoutExt + ext

	return filepath.Join(filepath.Dir(inputFile), outputFileName), nil
}

// CompileError represents a user-friendly compilation error
type CompileError struct {
	Type        string   `json:"type"`
	Message     string   `json:"message"`
	Details     []string `json:"details,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

func (e *CompileError) Error() string {
	var builder strings.Builder

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	red.Fprintf(&builder, "❌ Error: %s\n", e.Message)

	if len(e.Details) > 0 {
		builder.WriteString("\nDetails:\n")
		for _, detail := range e.Details {
			fmt.Fprintf(&builder, "  • %s\n", detail)
		}
	}

	if len(e.Suggestions) > 0 {
		builder.WriteString("\n")
		yellow.Fprintf(&builder, "💡 Suggestions:\n")
		for _, suggestion := range e.Suggestions {
			fmt.Fprintf(&builder, "  • %s\n", suggestion)
		}
	}

	return builder.String()
}

// writeProtobufOutput writes the policy in the specified format
func writeProtobufOutput(policy *compliancev1.CompliancePolicy, outputPath, format string) error {
	switch format {
	case "json":
		jsonData, err := protojson.MarshalOptions{
			Multiline: true,
			Indent:    "  ",
		}.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to marshal to JSON: %w", err)
		}

		if outputPath == "" {
			fmt.Print(string(jsonData))
			return nil
		}
		return os.WriteFile(outputPath, jsonData, 0644)

	case "text":
		textData := fmt.Sprintf("%+v", policy)
		if outputPath == "" {
			fmt.Print(textData)
			return nil
		}
		return os.WriteFile(outputPath, []byte(textData), 0644)

	case "binary":
		binaryData, err := proto.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to marshal to binary: %w", err)
		}

		if outputPath == "" {
			return fmt.Errorf("binary format requires output file")
		}
		return os.WriteFile(outputPath, binaryData, 0644)

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// formatFileSize formats file size in human-readable format
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
