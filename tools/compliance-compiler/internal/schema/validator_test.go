package schema

import (
	"flag"
	"testing"
)

var integrationTest = flag.Bool("integration", false, "run integration tests that require schema files")

func TestNewSchemaValidator(t *testing.T) {
	// Test basic constructor without schema file dependency
	if !*integrationTest {
		t.Skip("Skipping schema validator test - run with -integration flag to enable")
	}

	validator, err := NewSchemaValidator()
	if err != nil {
		t.Errorf("NewSchemaValidator() error = %v, want nil", err)
		return
	}
	if validator == nil {
		t.Error("NewSchemaValidator() returned nil validator")
	}
}

func TestSchemaValidator_ValidateYAML(t *testing.T) {
	if !*integrationTest {
		t.Skip("Skipping schema validation test - run with -integration flag to enable")
	}

	validator, err := NewSchemaValidator()
	if err != nil {
		t.Skipf("Skipping test due to schema setup issue: %v", err)
	}

	tests := []struct {
		name        string
		yamlContent string
		wantValid   bool
		wantErr     bool
	}{
		{
			name:        "empty yaml",
			yamlContent: "",
			wantValid:   false,
			wantErr:     false,
		},
		{
			name:        "invalid yaml syntax",
			yamlContent: "invalid: yaml: [",
			wantValid:   false,
			wantErr:     true,
		},
		{
			name: "missing required fields",
			yamlContent: `
name: "Test Policy"
description: "Missing required fields"
`,
			wantValid: false,
			wantErr:   false,
		},
		{
			name: "valid basic policy",
			yamlContent: `
policy_id: "test-policy-001"
version: "1.0.0"
jurisdiction: "US"
asset_class: "credit-card"
metadata:
  name: "Basic Credit Card Policy"
  description: "A basic policy for credit card compliance"
rules:
  - id: "min-amount-rule"
    name: "Minimum Amount Check"
    predicate:
      comparison:
        field:
          path: "application.requested_amount"
        operator: "GREATER_THAN_OR_EQUAL"
        value: 100
    actions:
      - type: "APPROVE"
        conditions: []
`,
			wantValid: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateYAML([]byte(tt.yamlContent))

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result != nil {
				if result.Valid != tt.wantValid {
					t.Errorf("ValidateYAML() valid = %v, want %v", result.Valid, tt.wantValid)
					if !result.Valid && len(result.Errors) > 0 {
						t.Logf("Validation errors: %+v", result.Errors)
					}
				}
			}
		})
	}
}

func TestValidationResult_ErrorHandling(t *testing.T) {
	if !*integrationTest {
		t.Skip("Skipping validation error handling test - run with -integration flag to enable")
	}

	validator, err := NewSchemaValidator()
	if err != nil {
		t.Skipf("Skipping test due to schema setup issue: %v", err)
	}

	// Test with intentionally invalid data to check error reporting
	invalidYAML := `
policy_id: 123  # Should be string
version: true   # Should be string
rules: "not-an-array"  # Should be array
`

	result, err := validator.ValidateYAML([]byte(invalidYAML))
	if err != nil {
		t.Errorf("ValidateYAML() should not return error for validation failures: %v", err)
		return
	}

	if result == nil {
		t.Error("ValidateYAML() returned nil result")
		return
	}

	if result.Valid {
		t.Error("ValidateYAML() should return invalid result for bad data")
	}

	if len(result.Errors) == 0 {
		t.Error("ValidateYAML() should return validation errors for bad data")
	}

	// Check that errors contain meaningful information
	for _, validationError := range result.Errors {
		if validationError.Field == "" {
			t.Error("Validation error should have a field specified")
		}
		if validationError.Message == "" {
			t.Error("Validation error should have a message")
		}
	}
}

func TestSchemaValidator_ValidateJSON(t *testing.T) {
	if !*integrationTest {
		t.Skip("Skipping JSON validation test - run with -integration flag to enable")
	}

	validator, err := NewSchemaValidator()
	if err != nil {
		t.Skipf("Skipping test due to schema setup issue: %v", err)
	}

	tests := []struct {
		name        string
		jsonContent string
		wantValid   bool
		wantErr     bool
	}{
		{
			name:        "empty json",
			jsonContent: "{}",
			wantValid:   false,
			wantErr:     false,
		},
		{
			name:        "invalid json syntax",
			jsonContent: "{invalid json",
			wantValid:   false,
			wantErr:     true,
		},
		{
			name: "valid json policy",
			jsonContent: `{
  "policy_id": "test-policy-json",
  "version": "1.0.0",
  "jurisdiction": "US",
  "asset_class": "credit-card",
  "metadata": {
    "name": "JSON Test Policy",
    "description": "Testing JSON validation"
  },
  "rules": [
    {
      "id": "test-rule",
      "name": "Test Rule",
      "predicate": {
        "comparison": {
          "field": {
            "path": "amount"
          },
          "operator": "GREATER_THAN",
          "value": 1000
        }
      },
      "actions": [
        {
          "type": "APPROVE"
        }
      ]
    }
  ]
}`,
			wantValid: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var originalData map[string]interface{}
			result, err := validator.ValidateJSON([]byte(tt.jsonContent), originalData)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result != nil {
				if result.Valid != tt.wantValid {
					t.Errorf("ValidateJSON() valid = %v, want %v", result.Valid, tt.wantValid)
					if !result.Valid && len(result.Errors) > 0 {
						t.Logf("Validation errors: %+v", result.Errors)
					}
				}
			}
		})
	}
}
