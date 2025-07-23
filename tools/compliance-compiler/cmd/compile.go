package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/compiler"
	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewCompileCmd() *cobra.Command {
	var (
		inputFile  string
		outputFile string
		outputDir  string
		format     string
		validate   bool
		overwrite  bool
	)

	cmd := &cobra.Command{
		Use:   "compile [flags] <input-file>",
		Short: "Compile YAML compliance policies to protobuf",
		Long: `Compile YAML compliance policies into protobuf format for use with ArdaOS.

The compile command takes YAML policy files and converts them into protobuf
messages that can be used by the ArdaOS compliance module. It supports
validation of policies before compilation and multiple output formats.

Examples:
  # Compile a single policy file
  compliance-compiler compile policy.yaml

  # Compile with custom output file
  compliance-compiler compile -o compiled_policy.pb policy.yaml

  # Compile to specific directory
  compliance-compiler compile -d ./output policy.yaml

  # Compile without validation
  compliance-compiler compile --no-validate policy.yaml

  # Compile and overwrite existing output
  compliance-compiler compile --overwrite policy.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile = args[0]
			return runCompile(inputFile, outputFile, outputDir, format, validate, overwrite)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path (default: <input>.pb)")
	cmd.Flags().StringVarP(&outputDir, "output-dir", "d", "", "output directory (default: same as input)")
	cmd.Flags().StringVar(&format, "format", "binary", "output format (binary, text, json)")
	cmd.Flags().BoolVar(&validate, "validate", true, "validate policy before compilation")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing output files")

	return cmd
}

func runCompile(inputFile, outputFile, outputDir, format string, validate, overwrite bool) error {
	logrus.Infof("Compiling policy file: %s", inputFile)

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", inputFile)
	}

	yamlParser := parser.NewYAMLParser()
	policy, err := yamlParser.ParseFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to parse YAML file: %w", err)
	}

	if validate {
		logrus.Debug("Validating policy before compilation")
		validator := compiler.NewValidator()
		if err := validator.ValidatePolicy(policy); err != nil {
			return fmt.Errorf("policy validation failed: %w", err)
		}
		logrus.Info("Policy validation passed")
	}

	policyCompiler := compiler.NewCompiler()
	protoPolicy, err := policyCompiler.CompilePolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to compile policy: %w", err)
	}

	outputPath, err := determineOutputPath(inputFile, outputFile, outputDir, format)
	if err != nil {
		return fmt.Errorf("failed to determine output path: %w", err)
	}

	if !overwrite {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("output file already exists: %s (use --overwrite to force)", outputPath)
		}
	}

	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	writer := compiler.NewWriter(format)
	if err := writer.WriteToFile(protoPolicy, outputPath); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	logrus.Infof("Successfully compiled policy to: %s", outputPath)
	return nil
}

func determineOutputPath(inputFile, outputFile, outputDir, format string) (string, error) {
	if outputFile != "" {
		if outputDir != "" {
			return filepath.Join(outputDir, filepath.Base(outputFile)), nil
		}
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

	if outputDir != "" {
		return filepath.Join(outputDir, outputFileName), nil
	}

	return filepath.Join(filepath.Dir(inputFile), outputFileName), nil
}
