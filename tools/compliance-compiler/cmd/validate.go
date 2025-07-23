package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/compiler"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewValidateCmd() *cobra.Command {
	var (
		recursive bool
		pattern   string
		strict    bool
		outputFmt string
	)

	cmd := &cobra.Command{
		Use:   "validate [flags] <file-or-directory>",
		Short: "Validate YAML compliance policies",
		Long: `Validate YAML compliance policies for syntax and semantic correctness.

The validate command checks YAML policy files for:
- YAML syntax correctness
- Required fields and structure
- Business rule consistency
- Regional compliance requirements
- Cross-policy dependencies

Examples:
  # Validate a single policy file
  compliance-compiler validate policy.yaml

  # Validate all YAML files in a directory
  compliance-compiler validate -r ./policies

  # Validate with custom file pattern
  compliance-compiler validate -r -p "*.policy.yaml" ./policies

  # Strict validation (fail on warnings)
  compliance-compiler validate --strict policy.yaml

  # Output validation results as JSON
  compliance-compiler validate --output json policy.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(args[0], recursive, pattern, strict, outputFmt)
		},
	}

	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "validate files recursively")
	cmd.Flags().StringVarP(&pattern, "pattern", "p", "*.yaml", "file pattern to match")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail on warnings (strict mode)")
	cmd.Flags().StringVar(&outputFmt, "output", "text", "output format (text, json)")

	return cmd
}

func runValidate(target string, recursive bool, pattern string, strict bool, outputFmt string) error {
	logrus.Infof("Validating: %s", target)

	stat, err := os.Stat(target)
	if os.IsNotExist(err) {
		return fmt.Errorf("target does not exist: %s", target)
	}

	var files []string
	if stat.IsDir() {
		files, err = findPolicyFiles(target, recursive, pattern)
		if err != nil {
			return fmt.Errorf("failed to find policy files: %w", err)
		}
	} else {
		files = []string{target}
	}

	if len(files) == 0 {
		logrus.Warn("No policy files found to validate")
		return nil
	}

	logrus.Infof("Found %d policy files to validate", len(files))

	yamlParser := parser.NewYAMLParser()
	validator := compiler.NewValidator()
	validator.SetStrictMode(strict)

	results := make([]ValidationResult, 0, len(files))
	hasErrors := false
	hasWarnings := false

	for _, file := range files {
		logrus.Debugf("Validating file: %s", file)

		result := ValidationResult{
			File: file,
		}

		policy, err := yamlParser.ParseFile(file)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Parse error: %v", err))
			hasErrors = true
		} else {
			if err := validator.ValidatePolicy(policy); err != nil {
				if validationErr, ok := err.(*types.ValidationError); ok {
					result.Errors = append(result.Errors, validationErr.Errors...)
					result.Warnings = append(result.Warnings, validationErr.Warnings...)
					if len(validationErr.Errors) > 0 {
						hasErrors = true
					}
					if len(validationErr.Warnings) > 0 {
						hasWarnings = true
					}
				} else {
					result.Errors = append(result.Errors, err.Error())
					hasErrors = true
				}
			}
		}

		results = append(results, result)
	}

	if err := outputValidationResults(results, outputFmt); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if hasErrors {
		return fmt.Errorf("validation failed with errors")
	}

	if strict && hasWarnings {
		return fmt.Errorf("validation failed with warnings (strict mode)")
	}

	logrus.Info("All policies validated successfully")
	return nil
}

type ValidationResult struct {
	File     string   `json:"file"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func findPolicyFiles(dir string, recursive bool, pattern string) ([]string, error) {
	var files []string

	if recursive {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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

	entries, err := os.ReadDir(dir)
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
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
	}

	return files, nil
}

func outputValidationResults(results []ValidationResult, format string) error {
	switch format {
	case "text":
		return outputTextResults(results)
	case "json":
		return outputJSONResults(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputTextResults(results []ValidationResult) error {
	for _, result := range results {
		fmt.Printf("File: %s\n", result.File)

		if len(result.Errors) == 0 && len(result.Warnings) == 0 {
			fmt.Println("  Status: ✓ Valid")
		} else {
			if len(result.Errors) > 0 {
				fmt.Println("  Status: ✗ Invalid")
				fmt.Println("  Errors:")
				for _, err := range result.Errors {
					fmt.Printf("    - %s\n", err)
				}
			}

			if len(result.Warnings) > 0 {
				fmt.Println("  Warnings:")
				for _, warn := range result.Warnings {
					fmt.Printf("    - %s\n", warn)
				}
			}
		}
		fmt.Println()
	}
	return nil
}

func outputJSONResults(results []ValidationResult) error {
	// This would use encoding/json to output structured results
	// Implementation simplified for now
	fmt.Println("JSON output not yet implemented")
	return outputTextResults(results)
}
