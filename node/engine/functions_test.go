package engine_test

import (
	"testing"

	"github.com/trufnetwork/kwil-db/node/engine"
)

// tests that we have implemented all functions
func Test_AllFunctionsImplemented(t *testing.T) {
	for name, fn := range engine.Functions {
		switch fnt := fn.(type) {
		case *engine.ScalarFunctionDefinition:
			if fnt.PGFormatFunc == nil {
				t.Errorf("function %s has no PGFormatFunc", name)
			}

			if fnt.ValidateArgsFunc == nil {
				t.Errorf("function %s has no ValidateArgsFunc", name)
			}
		case *engine.AggregateFunctionDefinition:
			if fnt.PGFormatFunc == nil {
				t.Errorf("function %s has no PGFormatFunc", name)
			}

			if fnt.ValidateArgsFunc == nil {
				t.Errorf("function %s has no ValidateArgsFunc", name)
			}
		case *engine.WindowFunctionDefinition:
			if fnt.PGFormatFunc == nil {
				t.Errorf("function %s has no PGFormatFunc", name)
			}

			if fnt.ValidateArgsFunc == nil {
				t.Errorf("function %s has no ValidateArgsFunc", name)
			}
		default:
			t.Errorf("function %s is not a scalar, aggregate, or window function", name)
		}
	}
}
