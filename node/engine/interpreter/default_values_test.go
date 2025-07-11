package interpreter

import (
	"testing"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
)

// TestDefaultValueEvaluation tests the default value evaluation system
func TestDefaultValueEvaluation(t *testing.T) {
	tests := []struct {
		name         string
		defaultValue *parse.DefaultValue
		expectedType *types.DataType
		expectError  bool
	}{
		{
			name: "Boolean literal default",
			defaultValue: &parse.DefaultValue{
				IsLiteral:    true,
				LiteralValue: true,
			},
			expectedType: types.BoolType,
			expectError:  false,
		},
		{
			name: "Integer literal default",
			defaultValue: &parse.DefaultValue{
				IsLiteral:    true,
				LiteralValue: int64(42),
			},
			expectedType: types.IntType,
			expectError:  false,
		},
		{
			name: "String literal default",
			defaultValue: &parse.DefaultValue{
				IsLiteral:    true,
				LiteralValue: "hello",
			},
			expectedType: types.TextType,
			expectError:  false,
		},
		{
			name: "Null literal default",
			defaultValue: &parse.DefaultValue{
				IsLiteral:    true,
				LiteralValue: nil,
			},
			expectedType: types.IntType,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluateDefaultValue(tt.defaultValue, tt.expectedType)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result == nil {
				t.Errorf("expected result, but got nil")
				return
			}

			// Basic type compatibility check
			if tt.defaultValue.LiteralValue != nil {
				switch tt.defaultValue.LiteralValue.(type) {
				case bool:
					if !result.Type().Equals(types.BoolType) {
						t.Errorf("expected bool type, got %s", result.Type())
					}
				case int64:
					if !result.Type().Equals(types.IntType) {
						t.Errorf("expected int type, got %s", result.Type())
					}
				case string:
					if !result.Type().Equals(types.TextType) {
						t.Errorf("expected text type, got %s", result.Type())
					}
				}
			}
		})
	}
}

// TestCreateValueFromLiteral tests the literal value creation
func TestCreateValueFromLiteral(t *testing.T) {
	tests := []struct {
		name         string
		literal      any
		expectedType *types.DataType
		expectError  bool
	}{
		{
			name:         "Boolean literal",
			literal:      true,
			expectedType: types.BoolType,
			expectError:  false,
		},
		{
			name:         "Integer literal",
			literal:      int64(123),
			expectedType: types.IntType,
			expectError:  false,
		},
		{
			name:         "String literal",
			literal:      "test",
			expectedType: types.TextType,
			expectError:  false,
		},
		{
			name:         "Null literal",
			literal:      nil,
			expectedType: types.IntType,
			expectError:  false,
		},
		{
			name:         "Unsupported type",
			literal:      make(map[string]any),
			expectedType: types.IntType,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := createValueFromLiteral(tt.literal, tt.expectedType)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result == nil {
				t.Errorf("expected result, but got nil")
				return
			}
		})
	}
}
