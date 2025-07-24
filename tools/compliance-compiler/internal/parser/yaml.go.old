package parser

import (
	"fmt"
	"io"
	"os"

	"github.com/arda-org/arda-os/tools/compliance-compiler/pkg/types"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type YAMLParser struct {
	strictMode bool
}

func NewYAMLParser() *YAMLParser {
	return &YAMLParser{
		strictMode: false,
	}
}

func (p *YAMLParser) SetStrictMode(strict bool) {
	p.strictMode = strict
}

func (p *YAMLParser) Parse(data []byte) (*types.Policy, error) {
	logrus.Debug("Parsing YAML policy from bytes")

	var policy types.Policy

	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	if err := p.validateBasicStructure(&policy); err != nil {
		return nil, fmt.Errorf("policy structure validation failed: %w", err)
	}

	logrus.Debugf("Successfully parsed policy: %s (version: %s)",
		policy.Metadata.Name, policy.Metadata.Version)

	return &policy, nil
}

func (p *YAMLParser) ParseFile(filename string) (*types.Policy, error) {
	logrus.Debugf("Parsing YAML policy from file: %s", filename)

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	return p.Parse(data)
}

func (p *YAMLParser) ParseReader(reader io.Reader) (*types.Policy, error) {
	logrus.Debug("Parsing YAML policy from reader")

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read from reader: %w", err)
	}

	return p.Parse(data)
}

func (p *YAMLParser) validateBasicStructure(policy *types.Policy) error {
	if policy.Metadata.Name == "" {
		return fmt.Errorf("policy metadata.name is required")
	}

	if policy.Metadata.Version == "" {
		return fmt.Errorf("policy metadata.version is required")
	}

	if policy.Metadata.Region == "" {
		return fmt.Errorf("policy metadata.region is required")
	}

	if len(policy.Spec.Rules) == 0 {
		return fmt.Errorf("policy must contain at least one rule")
	}

	// Validate each rule has required fields
	for i, rule := range policy.Spec.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule[%d].id is required", i)
		}

		if rule.Name == "" {
			return fmt.Errorf("rule[%d].name is required", i)
		}

		if rule.Type == "" {
			return fmt.Errorf("rule[%d].type is required", i)
		}

		if rule.Condition == "" {
			return fmt.Errorf("rule[%d].condition is required", i)
		}

		if rule.Action == "" {
			return fmt.Errorf("rule[%d].action is required", i)
		}

		// Validate rule type
		if !isValidRuleType(rule.Type) {
			return fmt.Errorf("rule[%d].type '%s' is not valid", i, rule.Type)
		}
	}

	// Validate conditions if present
	for i, condition := range policy.Spec.Conditions {
		if condition.ID == "" {
			return fmt.Errorf("condition[%d].id is required", i)
		}

		if condition.Expression == "" {
			return fmt.Errorf("condition[%d].expression is required", i)
		}
	}

	// Validate actions if present
	for i, action := range policy.Spec.Actions {
		if action.ID == "" {
			return fmt.Errorf("action[%d].id is required", i)
		}

		if action.Type == "" {
			return fmt.Errorf("action[%d].type is required", i)
		}

		if !isValidActionType(action.Type) {
			return fmt.Errorf("action[%d].type '%s' is not valid", i, action.Type)
		}
	}

	return nil
}

func isValidRuleType(ruleType types.RuleType) bool {
	switch ruleType {
	case types.RuleTypeValidation, types.RuleTypeLimit, types.RuleTypeRestriction,
		types.RuleTypeRequirement, types.RuleTypeNotification:
		return true
	default:
		return false
	}
}

func isValidActionType(actionType types.ActionType) bool {
	switch actionType {
	case types.ActionTypeAllow, types.ActionTypeDeny, types.ActionTypeRequire,
		types.ActionTypeNotify, types.ActionTypeLog, types.ActionTypeEscalate:
		return true
	default:
		return false
	}
}

func (p *YAMLParser) ParseMultiple(data []byte) ([]*types.Policy, error) {
	logrus.Debug("Parsing multiple YAML policies")

	var policies []*types.Policy

	// Handle multiple YAML documents
	documents := [][]byte{}

	// Simple split on "---" for now - more sophisticated parsing would be needed
	// for production use
	var currentDoc []byte
	for _, line := range [][]byte{data} {
		if string(line) == "---\n" {
			if len(currentDoc) > 0 {
				documents = append(documents, currentDoc)
				currentDoc = []byte{}
			}
		} else {
			currentDoc = append(currentDoc, line...)
		}
	}

	if len(currentDoc) > 0 {
		documents = append(documents, currentDoc)
	}

	if len(documents) == 0 {
		documents = [][]byte{data}
	}

	for i, doc := range documents {
		policy, err := p.Parse(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse document %d: %w", i, err)
		}
		policies = append(policies, policy)
	}

	logrus.Debugf("Successfully parsed %d policies", len(policies))
	return policies, nil
}
