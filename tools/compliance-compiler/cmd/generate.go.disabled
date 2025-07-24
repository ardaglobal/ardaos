package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewGenerateCmd() *cobra.Command {
	var (
		jurisdiction    string
		assetClass      string
		outputDir       string
		includeExamples bool
		templateType    string
		quiet           bool
		overwrite       bool
	)

	cmd := &cobra.Command{
		Use:   "generate [options]",
		Short: "Generate policy templates and examples",
		Long: `Generate compliance policy templates and examples for different jurisdictions and asset classes.

The generate command creates structured YAML policy templates that serve as starting points
for creating compliant policies. It supports various jurisdictions and asset classes with
pre-configured rules and requirements.

Templates include:
- Basic policy structure with all required fields
- Jurisdiction-specific regulatory requirements
- Asset class-specific validation rules
- Example rules and attestations
- Documentation and comments

Examples:
  # Generate basic policy template
  compliance-compiler generate --output-dir ./templates

  # Generate US credit card receivables template
  compliance-compiler generate --jurisdiction US --asset-class credit-card --output-dir ./templates

  # Generate with examples and documentation
  compliance-compiler generate --jurisdiction EU --asset-class installment-loan --include-examples --output-dir ./templates

  # Generate specific template type
  compliance-compiler generate --template-type minimal --jurisdiction CA --output-dir ./templates

  # Overwrite existing files
  compliance-compiler generate --jurisdiction US --output-dir ./templates --overwrite`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(GenerateOptions{
				Jurisdiction:    jurisdiction,
				AssetClass:      assetClass,
				OutputDir:       outputDir,
				IncludeExamples: includeExamples,
				TemplateType:    templateType,
				Quiet:           quiet,
				Overwrite:       overwrite,
			})
		},
	}

	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "target jurisdiction (US, EU, CA, UK, AU, JP, SG)")
	cmd.Flags().StringVar(&assetClass, "asset-class", "", "target asset class (credit-card, installment-loan, mca, equipment-lease, working-capital)")
	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./", "output directory for generated templates")
	cmd.Flags().BoolVar(&includeExamples, "include-examples", false, "include example policies and test data")
	cmd.Flags().StringVar(&templateType, "template-type", "standard", "template type: minimal, standard, comprehensive")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress output except errors")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing files")

	// Add shell completion
	cmd.RegisterFlagCompletionFunc("jurisdiction", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"US", "EU", "CA", "UK", "AU", "JP", "SG"}, cobra.ShellCompDirectiveDefault
	})

	cmd.RegisterFlagCompletionFunc("asset-class", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"credit-card", "installment-loan", "mca", "equipment-lease", "working-capital"}, cobra.ShellCompDirectiveDefault
	})

	cmd.RegisterFlagCompletionFunc("template-type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"minimal", "standard", "comprehensive"}, cobra.ShellCompDirectiveDefault
	})

	return cmd
}

type GenerateOptions struct {
	Jurisdiction    string
	AssetClass      string
	OutputDir       string
	IncludeExamples bool
	TemplateType    string
	Quiet           bool
	Overwrite       bool
}

func runGenerate(opts GenerateOptions) error {
	// Initialize colored output
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)

	if !opts.Quiet {
		blue.Printf("🎯 Generating compliance policy templates\n")
	}

	// Validate output directory
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return &GenerateError{
			Type:    "output_directory_error",
			Message: fmt.Sprintf("Failed to create output directory: %v", err),
			Suggestions: []string{
				"Check directory permissions",
				"Ensure parent directories exist",
				"Verify disk space is available",
			},
		}
	}

	// Configure template data based on options
	templateData := buildTemplateData(opts)

	// Generate base policy template
	if err := generatePolicyTemplate(templateData, opts); err != nil {
		return err
	}

	// Generate examples if requested
	if opts.IncludeExamples {
		if !opts.Quiet {
			fmt.Printf("📝 Generating example policies and test data...\n")
		}
		if err := generateExamples(templateData, opts); err != nil {
			return err
		}
	}

	// Generate documentation
	if err := generateDocumentation(templateData, opts); err != nil {
		return err
	}

	if !opts.Quiet {
		green.Printf("✅ Successfully generated templates in: %s\n", opts.OutputDir)
		if opts.Jurisdiction != "" {
			fmt.Printf("⚖️  Jurisdiction: %s\n", opts.Jurisdiction)
		}
		if opts.AssetClass != "" {
			fmt.Printf("🏷️  Asset Class: %s\n", opts.AssetClass)
		}
		fmt.Printf("📊 Template Type: %s\n", opts.TemplateType)
	}

	return nil
}

type TemplateData struct {
	Jurisdiction     string
	AssetClass       string
	TemplateType     string
	Timestamp        string
	GeneratorInfo    string
	Rules            []RuleTemplate
	Attestations     []AttestationTemplate
	Metadata         MetadataTemplate
	JurisdictionInfo JurisdictionInfo
	AssetClassInfo   AssetClassInfo
}

type RuleTemplate struct {
	ID          string
	Name        string
	Description string
	Type        string
	Conditions  []string
	Actions     []string
}

type AttestationTemplate struct {
	ID          string
	Name        string
	Description string
	Type        string
	Required    bool
	Fields      []string
}

type MetadataTemplate struct {
	Version     string
	Author      string
	Description string
	Tags        []string
}

type JurisdictionInfo struct {
	Name         string
	Code         string
	Requirements []string
	Regulations  []string
}

type AssetClassInfo struct {
	Name         string
	Code         string
	Requirements []string
	Constraints  []string
}

func buildTemplateData(opts GenerateOptions) TemplateData {
	data := TemplateData{
		Jurisdiction:  opts.Jurisdiction,
		AssetClass:    opts.AssetClass,
		TemplateType:  opts.TemplateType,
		Timestamp:     time.Now().Format(time.RFC3339),
		GeneratorInfo: "Generated by ArdaOS Compliance Compiler",
		Metadata: MetadataTemplate{
			Version:     "1.0.0",
			Author:      "compliance-compiler",
			Description: "Generated compliance policy template",
			Tags:        []string{"template", "compliance"},
		},
	}

	// Add jurisdiction-specific information
	if opts.Jurisdiction != "" {
		data.JurisdictionInfo = getJurisdictionInfo(opts.Jurisdiction)
		data.Metadata.Tags = append(data.Metadata.Tags, strings.ToLower(opts.Jurisdiction))
	}

	// Add asset class-specific information
	if opts.AssetClass != "" {
		data.AssetClassInfo = getAssetClassInfo(opts.AssetClass)
		data.Metadata.Tags = append(data.Metadata.Tags, opts.AssetClass)
	}

	// Build rules based on template type
	data.Rules = buildRuleTemplates(opts)
	data.Attestations = buildAttestationTemplates(opts)

	return data
}

func getJurisdictionInfo(jurisdiction string) JurisdictionInfo {
	jurisdictions := map[string]JurisdictionInfo{
		"US": {
			Name: "United States",
			Code: "US",
			Requirements: []string{
				"FINRA compliance for securities",
				"CFPB regulations for consumer finance",
				"State lending license requirements",
				"Anti-money laundering (AML) compliance",
			},
			Regulations: []string{"FINRA", "CFPB", "BSA", "PATRIOT Act"},
		},
		"EU": {
			Name: "European Union",
			Code: "EU",
			Requirements: []string{
				"GDPR data protection compliance",
				"MiFID II investment services",
				"PSD2 payment services directive",
				"Anti-money laundering directives",
			},
			Regulations: []string{"GDPR", "MiFID II", "PSD2", "5AMLD"},
		},
		"CA": {
			Name: "Canada",
			Code: "CA",
			Requirements: []string{
				"OSFI financial institution oversight",
				"Provincial lending regulations",
				"PIPEDA privacy compliance",
				"FINTRAC anti-money laundering",
			},
			Regulations: []string{"OSFI", "PIPEDA", "FINTRAC", "CSA"},
		},
	}

	if info, exists := jurisdictions[jurisdiction]; exists {
		return info
	}

	return JurisdictionInfo{
		Name:         jurisdiction,
		Code:         jurisdiction,
		Requirements: []string{"Standard compliance requirements"},
		Regulations:  []string{"Local regulations"},
	}
}

func getAssetClassInfo(assetClass string) AssetClassInfo {
	assetClasses := map[string]AssetClassInfo{
		"credit-card": {
			Name: "Credit Card Receivables",
			Code: "credit-card",
			Requirements: []string{
				"Credit underwriting standards",
				"Interest rate compliance",
				"Payment processing regulations",
				"Consumer protection requirements",
			},
			Constraints: []string{
				"Maximum credit limits",
				"Interest rate caps",
				"Payment terms",
				"Default procedures",
			},
		},
		"installment-loan": {
			Name: "Installment Loans",
			Code: "installment-loan",
			Requirements: []string{
				"Fixed repayment schedules",
				"Truth in lending disclosures",
				"Borrower qualification standards",
				"Collection procedures",
			},
			Constraints: []string{
				"Loan amount limits",
				"Term length restrictions",
				"APR calculations",
				"Prepayment options",
			},
		},
		"mca": {
			Name: "Merchant Cash Advances",
			Code: "mca",
			Requirements: []string{
				"Revenue-based repayment",
				"Factor rate disclosures",
				"Business qualification criteria",
				"UCC filing requirements",
			},
			Constraints: []string{
				"Advance amount limits",
				"Factor rate ranges",
				"Repayment percentages",
				"Default triggers",
			},
		},
	}

	if info, exists := assetClasses[assetClass]; exists {
		return info
	}

	return AssetClassInfo{
		Name:         assetClass,
		Code:         assetClass,
		Requirements: []string{"Standard asset requirements"},
		Constraints:  []string{"Standard constraints"},
	}
}

func buildRuleTemplates(opts GenerateOptions) []RuleTemplate {
	var rules []RuleTemplate

	// Base rules for all templates
	rules = append(rules, RuleTemplate{
		ID:          "amount_validation",
		Name:        "Transaction Amount Validation",
		Description: "Validates transaction amounts are within acceptable ranges",
		Type:        "validation",
		Conditions:  []string{"amount > 0", "amount <= maximum_allowed"},
		Actions:     []string{"validate", "log"},
	})

	// Add complexity based on template type
	switch opts.TemplateType {
	case "comprehensive":
		rules = append(rules, []RuleTemplate{
			{
				ID:          "kyc_verification",
				Name:        "KYC Verification",
				Description: "Ensures all participants have completed KYC verification",
				Type:        "compliance",
				Conditions:  []string{"participant.kyc_status == 'verified'", "participant.kyc_date < 90_days_ago"},
				Actions:     []string{"verify", "flag_if_expired"},
			},
			{
				ID:          "risk_assessment",
				Name:        "Risk Assessment",
				Description: "Evaluates transaction risk based on multiple factors",
				Type:        "risk",
				Conditions:  []string{"risk_score <= threshold", "no_sanctions_match"},
				Actions:     []string{"calculate_risk", "approve_or_flag"},
			},
		}...)
	case "standard":
		rules = append(rules, RuleTemplate{
			ID:          "participant_validation",
			Name:        "Participant Validation",
			Description: "Basic participant verification requirements",
			Type:        "validation",
			Conditions:  []string{"participant.verified == true"},
			Actions:     []string{"validate"},
		})
	}

	// Add jurisdiction-specific rules
	if opts.Jurisdiction == "US" {
		rules = append(rules, RuleTemplate{
			ID:          "finra_compliance",
			Name:        "FINRA Compliance Check",
			Description: "Ensures compliance with FINRA regulations",
			Type:        "regulatory",
			Conditions:  []string{"participant.finra_registered == true", "transaction.type in allowed_securities"},
			Actions:     []string{"validate_finra", "report_if_required"},
		})
	}

	return rules
}

func buildAttestationTemplates(opts GenerateOptions) []AttestationTemplate {
	var attestations []AttestationTemplate

	// Base attestations
	attestations = append(attestations, AttestationTemplate{
		ID:          "transaction_validity",
		Name:        "Transaction Validity Attestation",
		Description: "Attests that the transaction meets basic validity requirements",
		Type:        "validity",
		Required:    true,
		Fields:      []string{"transaction_id", "amount", "participants", "timestamp"},
	})

	// Add complexity based on template type
	if opts.TemplateType == "comprehensive" {
		attestations = append(attestations, []AttestationTemplate{
			{
				ID:          "compliance_review",
				Name:        "Compliance Review Attestation",
				Description: "Attests that compliance review has been completed",
				Type:        "compliance",
				Required:    true,
				Fields:      []string{"reviewer_id", "review_date", "compliance_status", "exceptions"},
			},
			{
				ID:          "risk_assessment",
				Name:        "Risk Assessment Attestation",
				Description: "Attests to the risk assessment results",
				Type:        "risk",
				Required:    false,
				Fields:      []string{"risk_score", "risk_factors", "mitigation_measures"},
			},
		}...)
	}

	return attestations
}

func generatePolicyTemplate(data TemplateData, opts GenerateOptions) error {
	templateStr := getPolicyTemplate()

	tmpl, err := template.New("policy").Parse(templateStr)
	if err != nil {
		return &GenerateError{
			Type:    "template_parse_error",
			Message: fmt.Sprintf("Failed to parse policy template: %v", err),
		}
	}

	filename := buildTemplateFileName(opts)
	outputPath := filepath.Join(opts.OutputDir, filename)

	// Check if file exists and not overwriting
	if !opts.Overwrite {
		if _, err := os.Stat(outputPath); err == nil {
			return &GenerateError{
				Type:    "file_exists",
				Message: fmt.Sprintf("Template file already exists: %s", outputPath),
				Suggestions: []string{
					"Use --overwrite to replace the existing file",
					"Specify a different output directory",
					"Change the jurisdiction or asset class parameters",
				},
			}
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return &GenerateError{
			Type:    "file_create_error",
			Message: fmt.Sprintf("Failed to create template file: %v", err),
		}
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return &GenerateError{
			Type:    "template_execute_error",
			Message: fmt.Sprintf("Failed to execute template: %v", err),
		}
	}

	if !opts.Quiet {
		fmt.Printf("📄 Generated policy template: %s\n", outputPath)
	}

	return nil
}

func generateExamples(data TemplateData, opts GenerateOptions) error {
	// Generate example test data
	exampleData := buildExampleTestData(opts)
	examplePath := filepath.Join(opts.OutputDir, "example-test-data.json")

	if err := writeExampleTestData(exampleData, examplePath, opts.Overwrite); err != nil {
		return err
	}

	if !opts.Quiet {
		fmt.Printf("📊 Generated example test data: %s\n", examplePath)
	}

	return nil
}

func generateDocumentation(data TemplateData, opts GenerateOptions) error {
	docContent := buildDocumentationContent(data)
	docPath := filepath.Join(opts.OutputDir, "README.md")

	if !opts.Overwrite {
		if _, err := os.Stat(docPath); err == nil {
			logrus.Debug("Documentation file exists, skipping")
			return nil
		}
	}

	if err := os.WriteFile(docPath, []byte(docContent), 0644); err != nil {
		return &GenerateError{
			Type:    "documentation_error",
			Message: fmt.Sprintf("Failed to generate documentation: %v", err),
		}
	}

	if !opts.Quiet {
		fmt.Printf("📚 Generated documentation: %s\n", docPath)
	}

	return nil
}

func buildTemplateFileName(opts GenerateOptions) string {
	parts := []string{"policy-template"}

	if opts.Jurisdiction != "" {
		parts = append(parts, strings.ToLower(opts.Jurisdiction))
	}

	if opts.AssetClass != "" {
		parts = append(parts, opts.AssetClass)
	}

	if opts.TemplateType != "standard" {
		parts = append(parts, opts.TemplateType)
	}

	return strings.Join(parts, "-") + ".yaml"
}

func buildExampleTestData(opts GenerateOptions) string {
	// Simplified example - in reality this would be more sophisticated
	return `[
  {
    "transaction_id": "tx_001",
    "amount": 1000.00,
    "currency": "USD",
    "transaction_type": "transfer",
    "participants": [
      {
        "id": "participant_1",
        "role": "sender",
        "verified": true
      },
      {
        "id": "participant_2",
        "role": "receiver",
        "verified": true
      }
    ],
    "timestamp": "2024-01-15T10:30:00Z"
  },
  {
    "transaction_id": "tx_002",
    "amount": 50000.00,
    "currency": "USD",
    "transaction_type": "large_transfer",
    "participants": [
      {
        "id": "participant_1",
        "role": "sender",
        "verified": true
      },
      {
        "id": "participant_3",
        "role": "receiver",
        "verified": true
      }
    ],
    "timestamp": "2024-01-15T14:45:00Z"
  }
]`
}

func writeExampleTestData(data, path string, overwrite bool) error {
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return nil // Skip if exists and not overwriting
		}
	}

	return os.WriteFile(path, []byte(data), 0644)
}

func buildDocumentationContent(data TemplateData) string {
	var doc strings.Builder

	doc.WriteString("# Compliance Policy Template\n\n")
	doc.WriteString(fmt.Sprintf("Generated on: %s\n", data.Timestamp))
	doc.WriteString(fmt.Sprintf("Generator: %s\n\n", data.GeneratorInfo))

	if data.Jurisdiction != "" {
		doc.WriteString(fmt.Sprintf("## Jurisdiction: %s\n\n", data.JurisdictionInfo.Name))
		doc.WriteString("### Regulatory Requirements:\n")
		for _, req := range data.JurisdictionInfo.Requirements {
			doc.WriteString(fmt.Sprintf("- %s\n", req))
		}
		doc.WriteString("\n")
	}

	if data.AssetClass != "" {
		doc.WriteString(fmt.Sprintf("## Asset Class: %s\n\n", data.AssetClassInfo.Name))
		doc.WriteString("### Requirements:\n")
		for _, req := range data.AssetClassInfo.Requirements {
			doc.WriteString(fmt.Sprintf("- %s\n", req))
		}
		doc.WriteString("\n")
	}

	doc.WriteString("## Usage\n\n")
	doc.WriteString("1. Review the generated policy template\n")
	doc.WriteString("2. Customize rules and attestations for your use case\n")
	doc.WriteString("3. Validate the policy using: `compliance-compiler validate policy.yaml`\n")
	doc.WriteString("4. Test the policy using: `compliance-compiler test policy.yaml example-test-data.json`\n")
	doc.WriteString("5. Compile the policy using: `compliance-compiler compile policy.yaml`\n\n")

	doc.WriteString("## Template Structure\n\n")
	doc.WriteString("The generated template includes:\n")
	doc.WriteString("- **Metadata**: Policy version, description, and tags\n")
	doc.WriteString("- **Rules**: Validation and compliance rules\n")
	doc.WriteString("- **Attestations**: Required attestations and their fields\n")
	doc.WriteString("- **Configuration**: Jurisdiction and asset class specific settings\n\n")

	return doc.String()
}

func getPolicyTemplate() string {
	return `# Compliance Policy Template
# {{.GeneratorInfo}}
# Generated: {{.Timestamp}}
{{if .Jurisdiction}}# Jurisdiction: {{.JurisdictionInfo.Name}} ({{.JurisdictionInfo.Code}}){{end}}
{{if .AssetClass}}# Asset Class: {{.AssetClassInfo.Name}}{{end}}

metadata:
  version: "{{.Metadata.Version}}"
  name: "{{if .Jurisdiction}}{{.Jurisdiction}}-{{end}}{{if .AssetClass}}{{.AssetClass}}-{{end}}compliance-policy"
  description: "{{.Metadata.Description}}{{if .Jurisdiction}} for {{.JurisdictionInfo.Name}}{{end}}{{if .AssetClass}} - {{.AssetClassInfo.Name}}{{end}}"
  author: "{{.Metadata.Author}}"
  created: "{{.Timestamp}}"
  tags: [{{range $i, $tag := .Metadata.Tags}}{{if $i}}, {{end}}"{{$tag}}"{{end}}]
{{if .Jurisdiction}}
  jurisdiction:
    code: "{{.JurisdictionInfo.Code}}"
    name: "{{.JurisdictionInfo.Name}}"
    regulations: [{{range $i, $reg := .JurisdictionInfo.Regulations}}{{if $i}}, {{end}}"{{$reg}}"{{end}}]
{{end}}
{{if .AssetClass}}
  asset_class:
    code: "{{.AssetClassInfo.Code}}"
    name: "{{.AssetClassInfo.Name}}"
{{end}}

# Policy Rules
rules:
{{range .Rules}}
  - id: "{{.ID}}"
    name: "{{.Name}}"
    description: "{{.Description}}"
    type: "{{.Type}}"
    enabled: true
    conditions:
{{range .Conditions}}      - "{{.}}"
{{end}}    actions:
{{range .Actions}}      - "{{.}}"
{{end}}

{{end}}
# Required Attestations
attestations:
{{range .Attestations}}
  - id: "{{.ID}}"
    name: "{{.Name}}"
    description: "{{.Description}}"
    type: "{{.Type}}"
    required: {{.Required}}
    fields:
{{range .Fields}}      - "{{.}}"
{{end}}

{{end}}
# Configuration
config:
  validation:
    strict_mode: true
    fail_on_warnings: false

  execution:
    timeout: "30s"
    max_retries: 3

  logging:
    level: "info"
    audit_enabled: true

{{if .Jurisdiction}}
# Jurisdiction-Specific Requirements
jurisdiction_requirements:
{{range .JurisdictionInfo.Requirements}}  - "{{.}}"
{{end}}
{{end}}

{{if .AssetClass}}
# Asset Class Constraints
asset_constraints:
{{range .AssetClassInfo.Constraints}}  - "{{.}}"
{{end}}
{{end}}`
}

// GenerateError represents a user-friendly generation error
type GenerateError struct {
	Type        string   `json:"type"`
	Message     string   `json:"message"`
	Suggestions []string `json:"suggestions,omitempty"`
}

func (e *GenerateError) Error() string {
	var builder strings.Builder

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)

	red.Fprintf(&builder, "❌ Generation Error: %s\n", e.Message)

	if len(e.Suggestions) > 0 {
		builder.WriteString("\n")
		yellow.Fprintf(&builder, "💡 Suggestions:\n")
		for _, suggestion := range e.Suggestions {
			fmt.Fprintf(&builder, "  • %s\n", suggestion)
		}
	}

	return builder.String()
}
