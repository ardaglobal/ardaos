package templates

import (
	"fmt"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
)

type Generator struct {
	templates map[string]TemplateDefinition
}

type TemplateDefinition struct {
	Name             string
	Description      string
	RequiredParams   []string
	OptionalParams   []string
	SupportedRegions []string
	SupportedAssets  []string
	Template         string
}

func NewGenerator() *Generator {
	g := &Generator{
		templates: make(map[string]TemplateDefinition),
	}
	g.initializeTemplates()
	return g
}

func (g *Generator) GenerateTemplate(config *types.GenerationConfig) (string, error) {
	logrus.Infof("Generating template: %s", config.Type)

	template, exists := g.templates[config.Type]
	if !exists {
		return "", fmt.Errorf("unknown template type: %s", config.Type)
	}

	// Validate required parameters
	if err := g.validateConfig(config, template); err != nil {
		return "", fmt.Errorf("configuration validation failed: %w", err)
	}

	// Generate template content
	content, err := g.renderTemplate(template, config)
	if err != nil {
		return "", fmt.Errorf("failed to render template: %w", err)
	}

	logrus.Debugf("Successfully generated %s template (%d characters)", config.Type, len(content))
	return content, nil
}

func (g *Generator) GetAvailableTypes() []types.TemplateType {
	templateTypes := make([]types.TemplateType, 0, len(g.templates))

	for _, template := range g.templates {
		templateTypes = append(templateTypes, types.TemplateType{
			Name:             template.Name,
			Description:      template.Description,
			RequiredParams:   template.RequiredParams,
			OptionalParams:   template.OptionalParams,
			SupportedRegions: template.SupportedRegions,
			SupportedAssets:  template.SupportedAssets,
		})
	}

	return templateTypes
}

func (g *Generator) ValidateConfig(config *types.GenerationConfig) error {
	template, exists := g.templates[config.Type]
	if !exists {
		return fmt.Errorf("unknown template type: %s", config.Type)
	}

	return g.validateConfig(config, template)
}

func (g *Generator) initializeTemplates() {
	g.templates["basic"] = TemplateDefinition{
		Name:             "basic",
		Description:      "Basic compliance policy template with common validation rules",
		RequiredParams:   []string{},
		OptionalParams:   []string{"region", "asset_type"},
		SupportedRegions: []string{"US", "EU", "APAC", "CA", "UK", "AU", "JP"},
		SupportedAssets:  []string{"loan", "equity", "bond", "derivative"},
		Template:         g.getBasicTemplate(),
	}

	g.templates["regional"] = TemplateDefinition{
		Name:             "regional",
		Description:      "Region-specific compliance template with local regulations",
		RequiredParams:   []string{"region"},
		OptionalParams:   []string{"asset_type", "business_type"},
		SupportedRegions: []string{"US", "EU", "APAC", "CA", "UK", "AU", "JP"},
		SupportedAssets:  []string{"loan", "equity", "bond", "derivative"},
		Template:         g.getRegionalTemplate(),
	}

	g.templates["asset"] = TemplateDefinition{
		Name:             "asset",
		Description:      "Asset-specific compliance template for financial instruments",
		RequiredParams:   []string{"asset_type"},
		OptionalParams:   []string{"region", "business_type"},
		SupportedRegions: []string{"US", "EU", "APAC", "CA", "UK", "AU", "JP"},
		SupportedAssets:  []string{"loan", "equity", "bond", "derivative", "commodity"},
		Template:         g.getAssetTemplate(),
	}

	g.templates["custom"] = TemplateDefinition{
		Name:             "custom",
		Description:      "Customizable compliance template for specific business requirements",
		RequiredParams:   []string{},
		OptionalParams:   []string{"region", "asset_type", "business_type", "features"},
		SupportedRegions: []string{},
		SupportedAssets:  []string{},
		Template:         g.getCustomTemplate(),
	}
}

func (g *Generator) validateConfig(config *types.GenerationConfig, template TemplateDefinition) error {
	// Check required parameters
	for _, param := range template.RequiredParams {
		switch param {
		case "region":
			if config.Region == "" {
				return fmt.Errorf("region is required for %s template", template.Name)
			}
			if len(template.SupportedRegions) > 0 && !g.contains(template.SupportedRegions, config.Region) {
				return fmt.Errorf("region '%s' is not supported for %s template", config.Region, template.Name)
			}
		case "asset_type":
			if config.AssetType == "" {
				return fmt.Errorf("asset_type is required for %s template", template.Name)
			}
			if len(template.SupportedAssets) > 0 && !g.contains(template.SupportedAssets, config.AssetType) {
				return fmt.Errorf("asset_type '%s' is not supported for %s template", config.AssetType, template.Name)
			}
		case "business_type":
			if config.BusinessType == "" {
				return fmt.Errorf("business_type is required for %s template", template.Name)
			}
		}
	}

	return nil
}

func (g *Generator) renderTemplate(template TemplateDefinition, config *types.GenerationConfig) (string, error) {
	content := template.Template

	// Replace template variables
	replacements := map[string]string{
		"{{.Name}}":         g.generatePolicyName(config),
		"{{.Version}}":      "1.0.0",
		"{{.Region}}":       config.Region,
		"{{.AssetType}}":    config.AssetType,
		"{{.BusinessType}}": config.BusinessType,
		"{{.Timestamp}}":    time.Now().UTC().Format(time.RFC3339),
		"{{.Description}}":  g.generateDescription(config),
	}

	for placeholder, value := range replacements {
		content = strings.ReplaceAll(content, placeholder, value)
	}

	// Handle conditional sections
	content = g.processConditionals(content, config)

	return content, nil
}

func (g *Generator) generatePolicyName(config *types.GenerationConfig) string {
	parts := []string{"compliance"}

	if config.Region != "" {
		parts = append(parts, strings.ToLower(config.Region))
	}

	if config.AssetType != "" {
		parts = append(parts, config.AssetType)
	}

	if config.BusinessType != "" {
		parts = append(parts, config.BusinessType)
	}

	return strings.Join(parts, "_")
}

func (g *Generator) generateDescription(config *types.GenerationConfig) string {
	desc := "Compliance policy"

	if config.Region != "" {
		desc += fmt.Sprintf(" for %s region", config.Region)
	}

	if config.AssetType != "" {
		desc += fmt.Sprintf(" covering %s assets", config.AssetType)
	}

	if config.BusinessType != "" {
		desc += fmt.Sprintf(" in %s business", config.BusinessType)
	}

	return desc
}

func (g *Generator) processConditionals(content string, config *types.GenerationConfig) string {
	// Process {{#if region}} blocks
	if config.Region != "" {
		content = g.processIfBlock(content, "region", true)
	} else {
		content = g.processIfBlock(content, "region", false)
	}

	// Process {{#if asset_type}} blocks
	if config.AssetType != "" {
		content = g.processIfBlock(content, "asset_type", true)
	} else {
		content = g.processIfBlock(content, "asset_type", false)
	}

	return content
}

func (g *Generator) processIfBlock(content, condition string, include bool) string {
	startTag := fmt.Sprintf("{{#if %s}}", condition)
	endTag := fmt.Sprintf("{{/if %s}}", condition)

	for {
		startIdx := strings.Index(content, startTag)
		if startIdx == -1 {
			break
		}

		endIdx := strings.Index(content[startIdx:], endTag)
		if endIdx == -1 {
			break
		}
		endIdx += startIdx

		if include {
			// Keep the content between tags, remove the tags
			content = content[:startIdx] + content[startIdx+len(startTag):endIdx] + content[endIdx+len(endTag):]
		} else {
			// Remove the entire block
			content = content[:startIdx] + content[endIdx+len(endTag):]
		}
	}

	return content
}

func (g *Generator) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Template definitions

func (g *Generator) getBasicTemplate() string {
	return `# {{.Name}} - {{.Description}}
# Generated at: {{.Timestamp}}

metadata:
  name: "{{.Name}}"
  version: "{{.Version}}"
  description: "{{.Description}}"
  region: "{{.Region}}"
  asset_type: "{{.AssetType}}"
  labels:
    generated: "true"
    template: "basic"

spec:
  rules:
    - id: "amount_validation"
      name: "Transaction Amount Validation"
      description: "Validate transaction amounts are within acceptable limits"
      type: "validation"
      condition: "amount > 0 && amount <= 1000000"
      action: "allow"
      priority: 100
      enabled: true
      parameters:
        - name: "max_amount"
          type: "float"
          value: 1000000
          required: true
          description: "Maximum allowed transaction amount"

    - id: "sender_validation"
      name: "Sender Validation"
      description: "Validate sender identity and status"
      type: "requirement"
      condition: "sender != null && sender != ''"
      action: "require"
      priority: 200
      enabled: true

    - id: "recipient_validation"
      name: "Recipient Validation"
      description: "Validate recipient identity and status"
      type: "requirement"
      condition: "recipient != null && recipient != ''"
      action: "require"
      priority: 200
      enabled: true

{{#if region}}
    - id: "regional_compliance"
      name: "Regional Compliance Check"
      description: "Ensure compliance with {{.Region}} regulations"
      type: "restriction"
      condition: "region == '{{.Region}}'"
      action: "allow"
      priority: 300
      enabled: true
{{/if region}}

  limits:
    daily_amount:
      type: "amount"
      value: 100000
      period: "1d"
      currency: "USD"

    daily_count:
      type: "count"
      value: 50
      period: "1d"

  settings:
    default_action: "deny"
    strict_mode: true
    continue_on_error: false
    log_level: "info"
    timeouts:
      validation: "30s"
      processing: "2m"
`
}

func (g *Generator) getRegionalTemplate() string {
	return `# {{.Name}} - {{.Description}}
# Generated at: {{.Timestamp}}
# Regional compliance template for {{.Region}}

metadata:
  name: "{{.Name}}"
  version: "{{.Version}}"
  description: "{{.Description}}"
  region: "{{.Region}}"
  asset_type: "{{.AssetType}}"
  labels:
    generated: "true"
    template: "regional"
    region: "{{.Region}}"

spec:
  rules:
    - id: "kyc_validation"
      name: "KYC Validation"
      description: "Know Your Customer validation for {{.Region}}"
      type: "requirement"
      condition: "kyc_status == 'verified'"
      action: "require"
      priority: 50
      enabled: true

    - id: "aml_screening"
      name: "AML Screening"
      description: "Anti-Money Laundering screening for {{.Region}}"
      type: "validation"
      condition: "aml_risk_score <= 5"
      action: "allow"
      priority: 60
      enabled: true
      parameters:
        - name: "max_risk_score"
          type: "int"
          value: 5
          required: true

{{#if region}}
    # Region-specific rules for {{.Region}}
    {{#if region == "US"}}
    - id: "usa_patriot_act"
      name: "USA PATRIOT Act Compliance"
      description: "Compliance with USA PATRIOT Act requirements"
      type: "requirement"
      condition: "ofac_check == 'clear' && patriot_act_check == 'pass'"
      action: "require"
      priority: 10
      enabled: true
    {{/if region}}

    {{#if region == "EU"}}
    - id: "gdpr_compliance"
      name: "GDPR Compliance"
      description: "General Data Protection Regulation compliance"
      type: "requirement"
      condition: "gdpr_consent == true && data_retention_compliant == true"
      action: "require"
      priority: 10
      enabled: true
    {{/if region}}
{{/if region}}

  limits:
    # Regional transaction limits
    {{#if region == "US"}}
    daily_amount:
      type: "amount"
      value: 10000  # BSA reporting threshold
      period: "1d"
      currency: "USD"
    {{/if region}}

    {{#if region == "EU"}}
    daily_amount:
      type: "amount"
      value: 15000  # EU AML directive threshold
      period: "1d"
      currency: "EUR"
    {{/if region}}

  settings:
    default_action: "deny"
    strict_mode: true
    continue_on_error: false
    log_level: "info"
    notification_urls:
      - "https://compliance.example.com/{{.Region}}/notifications"
`
}

func (g *Generator) getAssetTemplate() string {
	return `# {{.Name}} - {{.Description}}
# Generated at: {{.Timestamp}}
# Asset-specific compliance template for {{.AssetType}}

metadata:
  name: "{{.Name}}"
  version: "{{.Version}}"
  description: "{{.Description}}"
  region: "{{.Region}}"
  asset_type: "{{.AssetType}}"
  labels:
    generated: "true"
    template: "asset"
    asset_type: "{{.AssetType}}"

spec:
  rules:
    - id: "asset_type_validation"
      name: "Asset Type Validation"
      description: "Validate asset type matches policy"
      type: "validation"
      condition: "asset_type == '{{.AssetType}}'"
      action: "allow"
      priority: 100
      enabled: true

{{#if asset_type}}
    # Asset-specific rules for {{.AssetType}}
    {{#if asset_type == "loan"}}
    - id: "loan_to_value_ratio"
      name: "Loan-to-Value Ratio Check"
      description: "Ensure LTV ratio is within acceptable limits"
      type: "limit"
      condition: "ltv_ratio <= 0.8"
      action: "allow"
      priority: 200
      enabled: true
      parameters:
        - name: "max_ltv"
          type: "float"
          value: 0.8
          required: true

    - id: "credit_score_check"
      name: "Credit Score Validation"
      description: "Validate borrower credit score"
      type: "requirement"
      condition: "credit_score >= 650"
      action: "require"
      priority: 150
      enabled: true
    {{/if asset_type}}

    {{#if asset_type == "equity"}}
    - id: "accredited_investor"
      name: "Accredited Investor Check"
      description: "Verify investor accreditation status"
      type: "requirement"
      condition: "accredited_investor == true"
      action: "require"
      priority: 50
      enabled: true

    - id: "equity_concentration"
      name: "Equity Concentration Limit"
      description: "Prevent excessive concentration in single equity"
      type: "limit"
      condition: "concentration_percentage <= 0.1"
      action: "allow"
      priority: 200
      enabled: true
    {{/if asset_type}}
{{/if asset_type}}

  limits:
    # Asset-specific limits
    {{#if asset_type == "loan"}}
    max_loan_amount:
      type: "amount"
      value: 5000000
      currency: "USD"

    debt_to_income_ratio:
      type: "percentage"
      value: 0.43
    {{/if asset_type}}

    {{#if asset_type == "equity"}}
    max_investment_amount:
      type: "amount"
      value: 1000000
      currency: "USD"

    portfolio_concentration:
      type: "percentage"
      value: 0.1
    {{/if asset_type}}

  settings:
    default_action: "deny"
    strict_mode: true
    continue_on_error: false
    log_level: "info"
`
}

func (g *Generator) getCustomTemplate() string {
	return `# {{.Name}} - {{.Description}}
# Generated at: {{.Timestamp}}
# Custom compliance template - modify as needed

metadata:
  name: "{{.Name}}"
  version: "{{.Version}}"
  description: "{{.Description}}"
  region: "{{.Region}}"
  asset_type: "{{.AssetType}}"
  labels:
    generated: "true"
    template: "custom"

spec:
  rules:
    # Add your custom rules here
    - id: "custom_rule_1"
      name: "Custom Validation Rule"
      description: "Customize this rule for your specific requirements"
      type: "validation"
      condition: "true"  # Replace with your condition
      action: "allow"
      priority: 100
      enabled: false  # Enable when ready
      parameters: []

  conditions:
    # Define reusable conditions here
    - id: "business_hours"
      name: "Business Hours Check"
      expression: "hour >= 9 && hour <= 17"
      parameters:
        timezone: "UTC"

  actions:
    # Define custom actions here
    - id: "custom_notification"
      name: "Custom Notification Handler"
      type: "notify"
      handler: "webhook"
      parameters:
        url: "https://your-webhook.example.com/compliance"

  limits:
    # Define your limits here
    custom_limit:
      type: "amount"
      value: 10000
      period: "1d"
      currency: "USD"

  constraints:
    # Add business constraints here
    min_transaction_amount: "1.00"
    max_transaction_amount: "1000000.00"

  settings:
    default_action: "deny"
    strict_mode: false
    continue_on_error: true
    log_level: "debug"
    timeouts:
      validation: "30s"
      processing: "5m"
    notification_urls: []
`
}
