// Package docs provides automated documentation generation for the compliance compiler.
// This package generates comprehensive documentation from source code, templates, and schemas.
package docs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DocumentationGenerator generates comprehensive documentation
type DocumentationGenerator struct {
	ProjectRoot    string
	OutputDir      string
	TemplatesDir   string
	DocsTemplate   string
	IncludePrivate bool
	GeneratedAt    time.Time
}

// NewDocumentationGenerator creates a new documentation generator
func NewDocumentationGenerator(projectRoot, outputDir string) *DocumentationGenerator {
	return &DocumentationGenerator{
		ProjectRoot:    projectRoot,
		OutputDir:      outputDir,
		TemplatesDir:   filepath.Join(projectRoot, "examples", "templates"),
		DocsTemplate:   filepath.Join(projectRoot, "internal", "docs", "templates"),
		IncludePrivate: false,
		GeneratedAt:    time.Now(),
	}
}

// DocumentationConfig contains configuration for documentation generation
type DocumentationConfig struct {
	ProjectName        string            `yaml:"project_name"`
	ProjectDescription string            `yaml:"project_description"`
	Version            string            `yaml:"version"`
	Author             string            `yaml:"author"`
	License            string            `yaml:"license"`
	Repository         string            `yaml:"repository"`
	Homepage           string            `yaml:"homepage"`
	DocsURL            string            `yaml:"docs_url"`
	Sections           []DocSection      `yaml:"sections"`
	Templates          TemplateConfig    `yaml:"templates"`
	CustomFields       map[string]string `yaml:"custom_fields"`
}

// DocSection represents a documentation section
type DocSection struct {
	Name        string   `yaml:"name"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Files       []string `yaml:"files"`
	Generate    bool     `yaml:"generate"`
	Template    string   `yaml:"template"`
	Order       int      `yaml:"order"`
}

// TemplateConfig contains template-specific documentation settings
type TemplateConfig struct {
	IncludeExamples        bool     `yaml:"include_examples"`
	IncludeTestData        bool     `yaml:"include_test_data"`
	GenerateSchemas        bool     `yaml:"generate_schemas"`
	SupportedVerticals     []string `yaml:"supported_verticals"`
	SupportedJurisdictions []string `yaml:"supported_jurisdictions"`
}

// CLIDocumentation represents CLI command documentation
type CLIDocumentation struct {
	Commands    []CommandDoc `json:"commands"`
	GlobalFlags []FlagDoc    `json:"global_flags"`
	Examples    []ExampleDoc `json:"examples"`
	GeneratedAt time.Time    `json:"generated_at"`
}

// CommandDoc represents a single CLI command documentation
type CommandDoc struct {
	Name        string       `json:"name"`
	Use         string       `json:"use"`
	Short       string       `json:"short"`
	Long        string       `json:"long"`
	Example     string       `json:"example"`
	Flags       []FlagDoc    `json:"flags"`
	Subcommands []CommandDoc `json:"subcommands,omitempty"`
	Aliases     []string     `json:"aliases,omitempty"`
}

// FlagDoc represents a CLI flag documentation
type FlagDoc struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Usage     string `json:"usage"`
	DefValue  string `json:"default_value,omitempty"`
	Required  bool   `json:"required"`
	Type      string `json:"type"`
}

// ExampleDoc represents a usage example
type ExampleDoc struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Output      string `json:"output,omitempty"`
	Category    string `json:"category"`
}

// APIDocumentation represents API documentation
type APIDocumentation struct {
	Packages    []PackageDoc  `json:"packages"`
	Types       []TypeDoc     `json:"types"`
	Functions   []FunctionDoc `json:"functions"`
	Constants   []ConstantDoc `json:"constants"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// PackageDoc represents a Go package documentation
type PackageDoc struct {
	Name       string        `json:"name"`
	ImportPath string        `json:"import_path"`
	Synopsis   string        `json:"synopsis"`
	Doc        string        `json:"doc"`
	Types      []TypeDoc     `json:"types"`
	Functions  []FunctionDoc `json:"functions"`
	Constants  []ConstantDoc `json:"constants"`
	Variables  []VariableDoc `json:"variables"`
	Examples   []ExampleDoc  `json:"examples"`
}

// TypeDoc represents a type documentation
type TypeDoc struct {
	Name     string       `json:"name"`
	Doc      string       `json:"doc"`
	Kind     string       `json:"kind"`
	Fields   []FieldDoc   `json:"fields,omitempty"`
	Methods  []MethodDoc  `json:"methods,omitempty"`
	Examples []ExampleDoc `json:"examples,omitempty"`
}

// FieldDoc represents a struct field documentation
type FieldDoc struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`
	Doc  string `json:"doc"`
}

// MethodDoc represents a method documentation
type MethodDoc struct {
	Name      string       `json:"name"`
	Doc       string       `json:"doc"`
	Signature string       `json:"signature"`
	Examples  []ExampleDoc `json:"examples,omitempty"`
}

// FunctionDoc represents a function documentation
type FunctionDoc struct {
	Name      string       `json:"name"`
	Doc       string       `json:"doc"`
	Signature string       `json:"signature"`
	Package   string       `json:"package"`
	Examples  []ExampleDoc `json:"examples,omitempty"`
}

// ConstantDoc represents a constant documentation
type ConstantDoc struct {
	Name    string `json:"name"`
	Doc     string `json:"doc"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Package string `json:"package"`
}

// VariableDoc represents a variable documentation
type VariableDoc struct {
	Name    string `json:"name"`
	Doc     string `json:"doc"`
	Type    string `json:"type"`
	Package string `json:"package"`
}

// TemplateDocumentation represents policy template documentation
type TemplateDocumentation struct {
	Templates   []PolicyTemplateDoc `json:"templates"`
	Verticals   []VerticalDoc       `json:"verticals"`
	Frameworks  []FrameworkDoc      `json:"frameworks"`
	Schemas     []SchemaDoc         `json:"schemas"`
	Examples    []TemplateExample   `json:"examples"`
	GeneratedAt time.Time           `json:"generated_at"`
}

// PolicyTemplateDoc represents a single policy template documentation
type PolicyTemplateDoc struct {
	Name                string            `json:"name"`
	FilePath            string            `json:"file_path"`
	AssetClass          string            `json:"asset_class"`
	Jurisdiction        string            `json:"jurisdiction"`
	RegulatoryFramework []string          `json:"regulatory_framework"`
	Description         string            `json:"description"`
	Parameters          []ParameterDoc    `json:"parameters"`
	Rules               []RuleDoc         `json:"rules"`
	Attestations        []AttestationDoc  `json:"attestations"`
	Examples            []TemplateExample `json:"examples"`
	TestData            []string          `json:"test_data"`
	LastUpdated         string            `json:"last_updated"`
}

// ParameterDoc represents a template parameter documentation
type ParameterDoc struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Default     interface{} `json:"default"`
	Min         interface{} `json:"min,omitempty"`
	Max         interface{} `json:"max,omitempty"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
}

// RuleDoc represents a policy rule documentation
type RuleDoc struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Priority    string   `json:"priority"`
	Enabled     bool     `json:"enabled"`
	Conditions  []string `json:"conditions"`
	Actions     []string `json:"actions"`
}

// AttestationDoc represents an attestation documentation
type AttestationDoc struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Required    bool     `json:"required"`
	Fields      []string `json:"fields"`
}

// VerticalDoc represents a finance vertical documentation
type VerticalDoc struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	AssetClasses []string `json:"asset_classes"`
	Templates    []string `json:"templates"`
	Regulations  []string `json:"regulations"`
	UseCases     []string `json:"use_cases"`
}

// FrameworkDoc represents a regulatory framework documentation
type FrameworkDoc struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Jurisdiction string   `json:"jurisdiction"`
	Templates    []string `json:"templates"`
	Requirements []string `json:"requirements"`
	References   []string `json:"references"`
}

// SchemaDoc represents a schema documentation
type SchemaDoc struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Properties  map[string]PropertyDoc `json:"properties"`
	Required    []string               `json:"required"`
	Examples    []interface{}          `json:"examples"`
}

// PropertyDoc represents a schema property documentation
type PropertyDoc struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Format      string      `json:"format,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Min         interface{} `json:"minimum,omitempty"`
	Max         interface{} `json:"maximum,omitempty"`
}

// TemplateExample represents a template usage example
type TemplateExample struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Template    string `json:"template"`
	Data        string `json:"data"`
	Expected    string `json:"expected"`
	Category    string `json:"category"`
}

// GenerateAll generates all documentation
func (g *DocumentationGenerator) GenerateAll() error {
	// Ensure output directory exists
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Load configuration
	config, err := g.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Generate different types of documentation
	if err := g.generateCLIDocumentation(); err != nil {
		return fmt.Errorf("failed to generate CLI documentation: %w", err)
	}

	if err := g.generateAPIDocumentation(); err != nil {
		return fmt.Errorf("failed to generate API documentation: %w", err)
	}

	if err := g.generateTemplateDocumentation(); err != nil {
		return fmt.Errorf("failed to generate template documentation: %w", err)
	}

	if err := g.generateSchemaDocumentation(); err != nil {
		return fmt.Errorf("failed to generate schema documentation: %w", err)
	}

	// Generate markdown files
	if err := g.generateMarkdownDocumentation(config); err != nil {
		return fmt.Errorf("failed to generate markdown documentation: %w", err)
	}

	return nil
}

// generateCLIDocumentation generates CLI command documentation
func (g *DocumentationGenerator) generateCLIDocumentation() error {
	// This would normally analyze the actual CLI commands
	// For now, we'll create a mock structure based on known commands

	cliDoc := CLIDocumentation{
		GeneratedAt: g.GeneratedAt,
		GlobalFlags: []FlagDoc{
			{
				Name:     "config",
				Usage:    "Configuration file path",
				Type:     "string",
				DefValue: "~/.config/compliance-compiler/config.yaml",
			},
			{
				Name:      "verbose",
				Shorthand: "v",
				Usage:     "Enable verbose output",
				Type:      "bool",
			},
			{
				Name:      "output",
				Shorthand: "o",
				Usage:     "Output file path",
				Type:      "string",
			},
		},
		Commands: []CommandDoc{
			{
				Name:  "compile",
				Use:   "compile [flags] <policy-file>",
				Short: "Compile policy files to protobuf format",
				Long:  "Compile YAML policy files to optimized protobuf format for use with ArdaOS blockchain.",
				Example: `  # Compile a single policy
  compliance-compiler compile policy.yaml

  # Compile with specific output
  compliance-compiler compile policy.yaml -o output.pb

  # Compile with optimization
  compliance-compiler compile policy.yaml --optimize`,
				Flags: []FlagDoc{
					{
						Name:      "format",
						Shorthand: "f",
						Usage:     "Output format (protobuf, json)",
						Type:      "string",
						DefValue:  "protobuf",
					},
					{
						Name:  "optimize",
						Usage: "Enable optimization",
						Type:  "bool",
					},
					{
						Name:  "overwrite",
						Usage: "Overwrite existing output file",
						Type:  "bool",
					},
				},
			},
			{
				Name:  "validate",
				Use:   "validate [flags] <files...>",
				Short: "Validate policy files for correctness",
				Long:  "Validate YAML policy files for syntax, structure, and compliance requirements.",
				Example: `  # Validate a single file
  compliance-compiler validate policy.yaml

  # Validate multiple files
  compliance-compiler validate policy1.yaml policy2.yaml

  # Validate directory recursively
  compliance-compiler validate -r templates/

  # Validate with detailed output
  compliance-compiler validate --format=detailed policy.yaml`,
				Flags: []FlagDoc{
					{
						Name:      "recursive",
						Shorthand: "r",
						Usage:     "Validate directory recursively",
						Type:      "bool",
					},
					{
						Name:      "format",
						Shorthand: "f",
						Usage:     "Output format (text, json, detailed)",
						Type:      "string",
						DefValue:  "text",
					},
					{
						Name:  "strict",
						Usage: "Enable strict validation mode",
						Type:  "bool",
					},
					{
						Name:  "fail-on-warnings",
						Usage: "Fail on validation warnings",
						Type:  "bool",
					},
				},
			},
			{
				Name:  "generate",
				Use:   "generate [flags]",
				Short: "Generate policy templates",
				Long:  "Generate policy templates from specifications for different asset classes and jurisdictions.",
				Example: `  # Generate credit card template
  compliance-compiler generate --type credit-card

  # Generate for specific jurisdiction
  compliance-compiler generate --type installment-loan --jurisdiction US

  # Generate with custom output
  compliance-compiler generate --type mca --output custom-template.yaml`,
				Flags: []FlagDoc{
					{
						Name:     "type",
						Usage:    "Template type (credit-card, installment-loan, mca, equipment-lease, working-capital)",
						Type:     "string",
						Required: true,
					},
					{
						Name:     "jurisdiction",
						Usage:    "Target jurisdiction (US, EU, UK, etc.)",
						Type:     "string",
						DefValue: "US",
					},
					{
						Name:  "regulatory-framework",
						Usage: "Regulatory framework to include",
						Type:  "string",
					},
					{
						Name:  "list-types",
						Usage: "List available template types",
						Type:  "bool",
					},
				},
			},
			{
				Name:  "test",
				Use:   "test [flags] <policy-file>",
				Short: "Test policies against sample data",
				Long:  "Test policy files against sample transaction data to verify correct behavior.",
				Example: `  # Test with sample data
  compliance-compiler test policy.yaml --test-data samples.json

  # Test with coverage report
  compliance-compiler test policy.yaml --test-data samples.json --coverage

  # Test with verbose output
  compliance-compiler test policy.yaml --test-data samples.json --verbose`,
				Flags: []FlagDoc{
					{
						Name:      "test-data",
						Shorthand: "t",
						Usage:     "Test data file (JSON)",
						Type:      "string",
						Required:  true,
					},
					{
						Name:  "coverage",
						Usage: "Generate coverage report",
						Type:  "bool",
					},
					{
						Name:  "benchmark",
						Usage: "Run performance benchmarks",
						Type:  "bool",
					},
				},
			},
		},
		Examples: []ExampleDoc{
			{
				Title:       "Basic Policy Validation",
				Description: "Validate a single policy file",
				Command:     "compliance-compiler validate examples/templates/credit-card/us-cfpb-card-act.yaml",
				Category:    "validation",
			},
			{
				Title:       "Compile to Protobuf",
				Description: "Compile a policy to protobuf format",
				Command:     "compliance-compiler compile examples/templates/mca/revenue-based-qualification.yaml -o policy.pb",
				Category:    "compilation",
			},
			{
				Title:       "Generate Template",
				Description: "Generate a new credit card template",
				Command:     "compliance-compiler generate --type credit-card --jurisdiction US --output my-template.yaml",
				Category:    "generation",
			},
		},
	}

	// Save CLI documentation
	cliJSON, err := json.MarshalIndent(cliDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CLI documentation: %w", err)
	}

	cliPath := filepath.Join(g.OutputDir, "cli-documentation.json")
	if err := ioutil.WriteFile(cliPath, cliJSON, 0644); err != nil {
		return fmt.Errorf("failed to write CLI documentation: %w", err)
	}

	return nil
}

// generateAPIDocumentation generates API documentation from Go source
func (g *DocumentationGenerator) generateAPIDocumentation() error {
	apiDoc := APIDocumentation{
		GeneratedAt: g.GeneratedAt,
		Packages:    []PackageDoc{},
	}

	// Parse Go packages
	packageDirs := []string{
		"internal/compiler",
		"internal/parser",
		"internal/validator",
		"internal/testing",
		"pkg/types",
	}

	for _, pkgDir := range packageDirs {
		fullPath := filepath.Join(g.ProjectRoot, pkgDir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		pkgDoc, err := g.parsePackage(fullPath, pkgDir)
		if err != nil {
			continue // Skip packages that can't be parsed
		}

		apiDoc.Packages = append(apiDoc.Packages, pkgDoc)
	}

	// Save API documentation
	apiJSON, err := json.MarshalIndent(apiDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal API documentation: %w", err)
	}

	apiPath := filepath.Join(g.OutputDir, "api-documentation.json")
	if err := ioutil.WriteFile(apiPath, apiJSON, 0644); err != nil {
		return fmt.Errorf("failed to write API documentation: %w", err)
	}

	return nil
}

// parsePackage parses a Go package and extracts documentation
func (g *DocumentationGenerator) parsePackage(fullPath, pkgPath string) (PackageDoc, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, fullPath, nil, parser.ParseComments)
	if err != nil {
		return PackageDoc{}, err
	}

	pkgDoc := PackageDoc{
		ImportPath: pkgPath,
	}

	for name, pkg := range pkgs {
		if strings.HasSuffix(name, "_test") {
			continue // Skip test packages
		}

		docPkg := doc.New(pkg, pkgPath, doc.AllDecls)

		pkgDoc.Name = docPkg.Name
		pkgDoc.Doc = docPkg.Doc
		pkgDoc.Synopsis = doc.Synopsis(docPkg.Doc)

		// Extract types
		for _, t := range docPkg.Types {
			typeDoc := TypeDoc{
				Name: t.Name,
				Doc:  t.Doc,
			}

			// Determine type kind
			if t.Decl != nil && len(t.Decl.Specs) > 0 {
				if ts, ok := t.Decl.Specs[0].(*ast.TypeSpec); ok {
					switch ts.Type.(type) {
					case *ast.StructType:
						typeDoc.Kind = "struct"
						// Extract fields
						if st, ok := ts.Type.(*ast.StructType); ok {
							for _, field := range st.Fields.List {
								for _, name := range field.Names {
									fieldDoc := FieldDoc{
										Name: name.Name,
										Type: g.typeToString(field.Type),
									}

									if field.Tag != nil {
										fieldDoc.Tag = field.Tag.Value
									}

									typeDoc.Fields = append(typeDoc.Fields, fieldDoc)
								}
							}
						}
					case *ast.InterfaceType:
						typeDoc.Kind = "interface"
					default:
						typeDoc.Kind = "type"
					}
				}
			}

			// Extract methods
			for _, m := range t.Methods {
				methodDoc := MethodDoc{
					Name:      m.Name,
					Doc:       m.Doc,
					Signature: g.funcToString(m.Decl),
				}
				typeDoc.Methods = append(typeDoc.Methods, methodDoc)
			}

			pkgDoc.Types = append(pkgDoc.Types, typeDoc)
		}

		// Extract functions
		for _, f := range docPkg.Funcs {
			funcDoc := FunctionDoc{
				Name:      f.Name,
				Doc:       f.Doc,
				Signature: g.funcToString(f.Decl),
				Package:   pkgDoc.Name,
			}
			pkgDoc.Functions = append(pkgDoc.Functions, funcDoc)
		}

		// Extract constants
		for _, c := range docPkg.Consts {
			for _, spec := range c.Decl.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, name := range vs.Names {
						constDoc := ConstantDoc{
							Name:    name.Name,
							Doc:     c.Doc,
							Package: pkgDoc.Name,
						}

						if vs.Type != nil {
							constDoc.Type = g.typeToString(vs.Type)
						}

						if i < len(vs.Values) {
							constDoc.Value = g.exprToString(vs.Values[i])
						}

						pkgDoc.Constants = append(pkgDoc.Constants, constDoc)
					}
				}
			}
		}

		break // Take the first non-test package
	}

	return pkgDoc, nil
}

// generateTemplateDocumentation generates policy template documentation
func (g *DocumentationGenerator) generateTemplateDocumentation() error {
	templateDoc := TemplateDocumentation{
		GeneratedAt: g.GeneratedAt,
		Templates:   []PolicyTemplateDoc{},
		Verticals:   []VerticalDoc{},
		Frameworks:  []FrameworkDoc{},
	}

	// Find all template files
	err := filepath.Walk(g.TemplatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			templateDocItem, err := g.parseTemplate(path)
			if err != nil {
				return nil // Skip templates that can't be parsed
			}

			templateDoc.Templates = append(templateDoc.Templates, templateDocItem)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk templates directory: %w", err)
	}

	// Generate vertical documentation
	templateDoc.Verticals = g.generateVerticalDocs(templateDoc.Templates)

	// Generate framework documentation
	templateDoc.Frameworks = g.generateFrameworkDocs(templateDoc.Templates)

	// Save template documentation
	templateJSON, err := json.MarshalIndent(templateDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal template documentation: %w", err)
	}

	templatePath := filepath.Join(g.OutputDir, "template-documentation.json")
	if err := ioutil.WriteFile(templatePath, templateJSON, 0644); err != nil {
		return fmt.Errorf("failed to write template documentation: %w", err)
	}

	return nil
}

// parseTemplate parses a single template file
func (g *DocumentationGenerator) parseTemplate(templatePath string) (PolicyTemplateDoc, error) {
	data, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return PolicyTemplateDoc{}, err
	}

	var template struct {
		Template struct {
			Name                string   `yaml:"name"`
			Version             string   `yaml:"version"`
			Jurisdiction        string   `yaml:"jurisdiction"`
			AssetClass          string   `yaml:"asset_class"`
			Description         string   `yaml:"description"`
			Author              string   `yaml:"author"`
			RegulatoryFramework []string `yaml:"regulatory_framework"`
			LastUpdated         string   `yaml:"last_updated"`
		} `yaml:"template"`
		Parameters map[string]struct {
			Type        string      `yaml:"type"`
			Default     interface{} `yaml:"default"`
			Min         interface{} `yaml:"min"`
			Max         interface{} `yaml:"max"`
			Description string      `yaml:"description"`
		} `yaml:"parameters"`
		Policy struct {
			Rules []struct {
				ID          string   `yaml:"id"`
				Name        string   `yaml:"name"`
				Description string   `yaml:"description"`
				Type        string   `yaml:"type"`
				Priority    string   `yaml:"priority"`
				Enabled     bool     `yaml:"enabled"`
				Conditions  []string `yaml:"conditions"`
				Actions     []string `yaml:"actions"`
			} `yaml:"rules"`
			Attestations []struct {
				ID          string   `yaml:"id"`
				Name        string   `yaml:"name"`
				Description string   `yaml:"description"`
				Type        string   `yaml:"type"`
				Required    bool     `yaml:"required"`
				Fields      []string `yaml:"fields"`
			} `yaml:"attestations"`
		} `yaml:"policy"`
	}

	if err := yaml.Unmarshal(data, &template); err != nil {
		return PolicyTemplateDoc{}, err
	}

	// Convert to documentation structure
	doc := PolicyTemplateDoc{
		Name:                template.Template.Name,
		FilePath:            templatePath,
		AssetClass:          template.Template.AssetClass,
		Jurisdiction:        template.Template.Jurisdiction,
		RegulatoryFramework: template.Template.RegulatoryFramework,
		Description:         template.Template.Description,
		LastUpdated:         template.Template.LastUpdated,
	}

	// Convert parameters
	for name, param := range template.Parameters {
		paramDoc := ParameterDoc{
			Name:        name,
			Type:        param.Type,
			Default:     param.Default,
			Min:         param.Min,
			Max:         param.Max,
			Description: param.Description,
			Required:    param.Default != nil, // Simple heuristic
		}
		doc.Parameters = append(doc.Parameters, paramDoc)
	}

	// Convert rules
	for _, rule := range template.Policy.Rules {
		ruleDoc := RuleDoc{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Type:        rule.Type,
			Priority:    rule.Priority,
			Enabled:     rule.Enabled,
			Conditions:  rule.Conditions,
			Actions:     rule.Actions,
		}
		doc.Rules = append(doc.Rules, ruleDoc)
	}

	// Convert attestations
	for _, att := range template.Policy.Attestations {
		attDoc := AttestationDoc{
			ID:          att.ID,
			Name:        att.Name,
			Description: att.Description,
			Type:        att.Type,
			Required:    att.Required,
			Fields:      att.Fields,
		}
		doc.Attestations = append(doc.Attestations, attDoc)
	}

	return doc, nil
}

// generateVerticalDocs generates documentation for finance verticals
func (g *DocumentationGenerator) generateVerticalDocs(templates []PolicyTemplateDoc) []VerticalDoc {
	verticals := map[string]*VerticalDoc{
		"CreditCard": {
			Name:         "Credit Card Receivables",
			Description:  "Credit card lending and receivables financing with comprehensive consumer protection compliance",
			AssetClasses: []string{"CreditCard"},
			UseCases:     []string{"Consumer credit cards", "Business credit cards", "Secured credit cards", "Balance transfers"},
		},
		"InstallmentLoan": {
			Name:         "Installment Loans",
			Description:  "Fixed-term installment lending with predictable payment schedules",
			AssetClasses: []string{"InstallmentLoan"},
			UseCases:     []string{"Personal loans", "Auto loans", "Home improvement loans", "Debt consolidation"},
		},
		"MerchantCashAdvance": {
			Name:         "Merchant Cash Advances",
			Description:  "Revenue-based financing providing upfront capital against future sales",
			AssetClasses: []string{"MerchantCashAdvance"},
			UseCases:     []string{"Working capital", "Inventory financing", "Equipment purchases", "Business expansion"},
		},
		"EquipmentLease": {
			Name:         "Equipment Leasing",
			Description:  "Asset-backed financing for business equipment with UCC Article 9 compliance",
			AssetClasses: []string{"EquipmentLease"},
			UseCases:     []string{"Manufacturing equipment", "Office equipment", "Medical equipment", "Transportation vehicles"},
		},
		"WorkingCapital": {
			Name:         "Working Capital Loans",
			Description:  "Short-term financing for business cash flow and operational needs",
			AssetClasses: []string{"WorkingCapital"},
			UseCases:     []string{"Cash flow financing", "Seasonal needs", "Invoice factoring", "Asset-based lending"},
		},
	}

	// Populate with templates
	for _, template := range templates {
		if vertical, exists := verticals[template.AssetClass]; exists {
			vertical.Templates = append(vertical.Templates, template.Name)

			// Add unique regulations
			for _, framework := range template.RegulatoryFramework {
				if !contains(vertical.Regulations, framework) {
					vertical.Regulations = append(vertical.Regulations, framework)
				}
			}
		}
	}

	// Convert map to slice
	var result []VerticalDoc
	for _, vertical := range verticals {
		result = append(result, *vertical)
	}

	return result
}

// generateFrameworkDocs generates regulatory framework documentation
func (g *DocumentationGenerator) generateFrameworkDocs(templates []PolicyTemplateDoc) []FrameworkDoc {
	frameworks := make(map[string]*FrameworkDoc)

	for _, template := range templates {
		for _, framework := range template.RegulatoryFramework {
			if _, exists := frameworks[framework]; !exists {
				frameworks[framework] = &FrameworkDoc{
					Name:         framework,
					Description:  g.getFrameworkDescription(framework),
					Jurisdiction: g.getFrameworkJurisdiction(framework),
					Requirements: g.getFrameworkRequirements(framework),
					References:   g.getFrameworkReferences(framework),
				}
			}

			frameworks[framework].Templates = append(frameworks[framework].Templates, template.Name)
		}
	}

	// Convert map to slice
	var result []FrameworkDoc
	for _, framework := range frameworks {
		result = append(result, *framework)
	}

	return result
}

// generateSchemaDocumentation generates schema documentation
func (g *DocumentationGenerator) generateSchemaDocumentation() error {
	// This would generate JSON Schema documentation for policy structures
	// For now, we'll create a basic schema structure

	schemas := []SchemaDoc{
		{
			Name:        "PolicyTemplate",
			Description: "Schema for compliance policy templates",
			Version:     "1.0.0",
			Properties: map[string]PropertyDoc{
				"template": {
					Type:        "object",
					Description: "Template metadata",
				},
				"parameters": {
					Type:        "object",
					Description: "Configurable parameters",
				},
				"policy": {
					Type:        "object",
					Description: "Policy implementation",
				},
			},
			Required: []string{"template", "policy"},
		},
	}

	schemaJSON, err := json.MarshalIndent(schemas, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal schema documentation: %w", err)
	}

	schemaPath := filepath.Join(g.OutputDir, "schema-documentation.json")
	if err := ioutil.WriteFile(schemaPath, schemaJSON, 0644); err != nil {
		return fmt.Errorf("failed to write schema documentation: %w", err)
	}

	return nil
}

// generateMarkdownDocumentation generates markdown documentation files
func (g *DocumentationGenerator) generateMarkdownDocumentation(config *DocumentationConfig) error {
	// Generate README.md
	if err := g.generateReadme(config); err != nil {
		return fmt.Errorf("failed to generate README: %w", err)
	}

	// Generate API reference
	if err := g.generateAPIReference(); err != nil {
		return fmt.Errorf("failed to generate API reference: %w", err)
	}

	// Generate CLI reference
	if err := g.generateCLIReference(); err != nil {
		return fmt.Errorf("failed to generate CLI reference: %w", err)
	}

	// Generate template reference
	if err := g.generateTemplateReference(); err != nil {
		return fmt.Errorf("failed to generate template reference: %w", err)
	}

	return nil
}

// loadConfig loads documentation configuration
func (g *DocumentationGenerator) loadConfig() (*DocumentationConfig, error) {
	configPath := filepath.Join(g.ProjectRoot, "docs", "config.yaml")

	// Create default config if not exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config := &DocumentationConfig{
			ProjectName:        "ArdaOS Compliance Compiler",
			ProjectDescription: "Policy compilation and validation tool for ArdaOS blockchain compliance engine",
			Version:            "1.0.0",
			Author:             "ArdaOS Team",
			License:            "Apache-2.0",
			Repository:         "https://github.com/ardaos/arda-os",
			Homepage:           "https://ardaos.com",
			DocsURL:            "https://docs.ardaos.com/compliance-compiler",
		}

		return config, nil
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config DocumentationConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Helper methods

func (g *DocumentationGenerator) typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return g.typeToString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + g.typeToString(t.X)
	case *ast.ArrayType:
		return "[]" + g.typeToString(t.Elt)
	default:
		return "unknown"
	}
}

func (g *DocumentationGenerator) funcToString(decl *ast.FuncDecl) string {
	var buf bytes.Buffer
	buf.WriteString(decl.Name.Name)
	buf.WriteString("(")

	if decl.Type.Params != nil {
		for i, param := range decl.Type.Params.List {
			if i > 0 {
				buf.WriteString(", ")
			}
			for j, name := range param.Names {
				if j > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(name.Name)
			}
			buf.WriteString(" ")
			buf.WriteString(g.typeToString(param.Type))
		}
	}

	buf.WriteString(")")

	if decl.Type.Results != nil {
		buf.WriteString(" ")
		if len(decl.Type.Results.List) == 1 {
			buf.WriteString(g.typeToString(decl.Type.Results.List[0].Type))
		} else {
			buf.WriteString("(")
			for i, result := range decl.Type.Results.List {
				if i > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(g.typeToString(result.Type))
			}
			buf.WriteString(")")
		}
	}

	return buf.String()
}

func (g *DocumentationGenerator) exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value
	case *ast.Ident:
		return e.Name
	default:
		return "unknown"
	}
}

func (g *DocumentationGenerator) getFrameworkDescription(framework string) string {
	descriptions := map[string]string{
		"CFPB":          "Consumer Financial Protection Bureau regulations for consumer financial products",
		"CARD Act":      "Credit Card Accountability Responsibility and Disclosure Act requirements",
		"TILA":          "Truth in Lending Act disclosure and calculation requirements",
		"FDCPA":         "Fair Debt Collection Practices Act compliance for debt collection",
		"UCC Article 9": "Uniform Commercial Code Article 9 for secured transactions",
		"NACHA Rules":   "National Automated Clearing House Association rules for ACH processing",
		"EU PSD2":       "European Union Payment Services Directive 2 requirements",
	}

	if desc, exists := descriptions[framework]; exists {
		return desc
	}
	return "Regulatory framework for financial compliance"
}

func (g *DocumentationGenerator) getFrameworkJurisdiction(framework string) string {
	jurisdictions := map[string]string{
		"CFPB":          "USA",
		"CARD Act":      "USA",
		"TILA":          "USA",
		"FDCPA":         "USA",
		"UCC Article 9": "USA",
		"NACHA Rules":   "USA",
		"EU PSD2":       "EU",
	}

	if jurisdiction, exists := jurisdictions[framework]; exists {
		return jurisdiction
	}
	return "Multiple"
}

func (g *DocumentationGenerator) getFrameworkRequirements(framework string) []string {
	// This would be populated with actual requirements
	return []string{"Compliance with regulatory standards", "Proper documentation", "Regular updates"}
}

func (g *DocumentationGenerator) getFrameworkReferences(framework string) []string {
	// This would be populated with actual reference URLs
	return []string{"https://example.com/framework-reference"}
}

func (g *DocumentationGenerator) generateReadme(config *DocumentationConfig) error {
	// Implementation would generate a comprehensive README.md
	return nil
}

func (g *DocumentationGenerator) generateAPIReference() error {
	// Implementation would generate API reference documentation
	return nil
}

func (g *DocumentationGenerator) generateCLIReference() error {
	// Implementation would generate CLI reference documentation
	return nil
}

func (g *DocumentationGenerator) generateTemplateReference() error {
	// Implementation would generate template reference documentation
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
