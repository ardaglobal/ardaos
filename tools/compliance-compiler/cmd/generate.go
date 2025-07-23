package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/templates"
	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewGenerateCmd() *cobra.Command {
	var (
		templateType string
		outputFile   string
		region       string
		assetType    string
		interactive  bool
		overwrite    bool
		listTypes    bool
	)

	cmd := &cobra.Command{
		Use:   "generate [flags]",
		Short: "Generate compliance policy templates",
		Long: `Generate compliance policy templates for different use cases and regions.

The generate command creates YAML policy templates that can be customized
for specific compliance requirements. It supports various template types:
- Basic policies for standard compliance rules
- Regional templates for specific jurisdictions
- Asset-specific templates for different financial instruments
- Custom templates based on business requirements

Examples:
  # Generate a basic compliance policy template
  compliance-compiler generate --type basic

  # Generate a regional template for US compliance
  compliance-compiler generate --type regional --region US -o us_policy.yaml

  # Generate an asset-specific template
  compliance-compiler generate --type asset --asset-type loan -o loan_policy.yaml

  # Interactive template generation
  compliance-compiler generate --interactive

  # List available template types
  compliance-compiler generate --list-types`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(templateType, outputFile, region, assetType, interactive, overwrite, listTypes)
		},
	}

	cmd.Flags().StringVarP(&templateType, "type", "t", "", "template type (basic, regional, asset, custom)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	cmd.Flags().StringVar(&region, "region", "", "region code for regional templates (US, EU, APAC)")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "asset type for asset templates (loan, equity, bond)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interactive template generation")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing files")
	cmd.Flags().BoolVar(&listTypes, "list-types", false, "list available template types")

	return cmd
}

func runGenerate(templateType, outputFile, region, assetType string, interactive, overwrite, listTypes bool) error {
	generator := templates.NewGenerator()

	if listTypes {
		return printAvailableTypes(generator)
	}

	if interactive {
		return runInteractiveGeneration(generator, overwrite)
	}

	if templateType == "" {
		return fmt.Errorf("template type is required (use --type or --interactive)")
	}

	logrus.Infof("Generating %s template", templateType)

	config := &types.GenerationConfig{
		Type:      templateType,
		Region:    region,
		AssetType: assetType,
	}

	template, err := generator.GenerateTemplate(config)
	if err != nil {
		return fmt.Errorf("failed to generate template: %w", err)
	}

	if outputFile == "" {
		outputFile = generateDefaultOutputFile(templateType, region, assetType)
	}

	if !overwrite {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file already exists: %s (use --overwrite to force)", outputFile)
		}
	}

	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to write template file: %w", err)
	}

	logrus.Infof("Successfully generated template: %s", outputFile)
	fmt.Printf("\nGenerated compliance policy template: %s\n", outputFile)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Review and customize the template for your requirements\n")
	fmt.Printf("2. Validate the policy: compliance-compiler validate %s\n", outputFile)
	fmt.Printf("3. Compile the policy: compliance-compiler compile %s\n", outputFile)

	return nil
}

func printAvailableTypes(generator *templates.Generator) error {
	types := generator.GetAvailableTypes()

	fmt.Printf("Available Template Types:\n")
	fmt.Printf("========================\n\n")

	for _, typeInfo := range types {
		fmt.Printf("Type: %s\n", typeInfo.Name)
		fmt.Printf("Description: %s\n", typeInfo.Description)
		if len(typeInfo.RequiredParams) > 0 {
			fmt.Printf("Required Parameters: %s\n", strings.Join(typeInfo.RequiredParams, ", "))
		}
		if len(typeInfo.OptionalParams) > 0 {
			fmt.Printf("Optional Parameters: %s\n", strings.Join(typeInfo.OptionalParams, ", "))
		}
		fmt.Printf("\n")
	}

	return nil
}

func runInteractiveGeneration(generator *templates.Generator, overwrite bool) error {
	fmt.Printf("Interactive Compliance Policy Template Generator\n")
	fmt.Printf("==============================================\n\n")

	config := &types.GenerationConfig{}

	// Interactive prompts would be implemented here
	fmt.Printf("Select template type:\n")
	fmt.Printf("1. Basic - Standard compliance template\n")
	fmt.Printf("2. Regional - Region-specific compliance\n")
	fmt.Printf("3. Asset - Asset-specific compliance\n")
	fmt.Printf("4. Custom - Custom compliance template\n")
	fmt.Printf("\nEnter selection (1-4): ")

	// Simplified interactive flow
	config.Type = "basic"

	template, err := generator.GenerateTemplate(config)
	if err != nil {
		return fmt.Errorf("failed to generate template: %w", err)
	}

	outputFile := "compliance_policy.yaml"

	if !overwrite {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file already exists: %s (use --overwrite to force)", outputFile)
		}
	}

	if err := os.WriteFile(outputFile, []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to write template file: %w", err)
	}

	logrus.Infof("Successfully generated interactive template: %s", outputFile)
	return nil
}

func generateDefaultOutputFile(templateType, region, assetType string) string {
	parts := []string{"compliance"}

	if templateType != "" {
		parts = append(parts, templateType)
	}

	if region != "" {
		parts = append(parts, strings.ToLower(region))
	}

	if assetType != "" {
		parts = append(parts, assetType)
	}

	return strings.Join(parts, "_") + "_policy.yaml"
}
