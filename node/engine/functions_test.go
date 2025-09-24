package engine_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/types"
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
		case *engine.TableValuedFunctionDefinition:
			if fnt.PGFormatFunc == nil {
				t.Errorf("function %s has no PGFormatFunc", name)
			}

			if fnt.ValidateArgsFunc == nil {
				t.Errorf("function %s has no ValidateArgsFunc", name)
			}
		default:
			t.Errorf("function %s is not a scalar, aggregate, window, or table-valued function", name)
		}
	}
}

func TestPgDatabaseSizeFunction(t *testing.T) {
	fn := engine.Functions["pg_database_size"]
	require.NotNil(t, fn, "pg_database_size function should exist")

	scalarFn, ok := fn.(*engine.ScalarFunctionDefinition)
	require.True(t, ok, "pg_database_size should be a ScalarFunctionDefinition")

	// Test valid arguments
	validArgs := []*types.DataType{types.TextType}
	returnType, err := scalarFn.ValidateArgs(validArgs)
	require.NoError(t, err)
	assert.True(t, returnType.Equals(types.IntType), "should return INT type")

	// Test invalid argument count - no arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{})
	assert.Error(t, err, "should error with no arguments")

	// Test invalid argument count - too many arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.TextType, types.TextType})
	assert.Error(t, err, "should error with too many arguments")

	// Test invalid argument type
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.IntType})
	assert.Error(t, err, "should error with wrong argument type")

	// Test PostgreSQL format
	result, err := scalarFn.PGFormatFunc([]string{"'database_name'"})
	require.NoError(t, err)
	assert.Equal(t, "pg_database_size('database_name')", result, "should format correctly")
}

func TestPgTotalRelationSizeFunction(t *testing.T) {
	fn := engine.Functions["pg_total_relation_size"]
	require.NotNil(t, fn, "pg_total_relation_size function should exist")

	scalarFn, ok := fn.(*engine.ScalarFunctionDefinition)
	require.True(t, ok, "pg_total_relation_size should be a ScalarFunctionDefinition")

	// Test valid arguments
	validArgs := []*types.DataType{types.TextType}
	returnType, err := scalarFn.ValidateArgs(validArgs)
	require.NoError(t, err)
	assert.True(t, returnType.Equals(types.IntType), "should return INT type")

	// Test invalid argument count - no arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{})
	assert.Error(t, err, "should error with no arguments")

	// Test invalid argument count - too many arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.TextType, types.TextType})
	assert.Error(t, err, "should error with too many arguments")

	// Test invalid argument type
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.IntType})
	assert.Error(t, err, "should error with wrong argument type")

	// Test PostgreSQL format
	result, err := scalarFn.PGFormatFunc([]string{"'table_name'"})
	require.NoError(t, err)
	assert.Equal(t, "pg_total_relation_size('table_name')", result, "should format correctly")
}

func TestPgRelationSizeFunction(t *testing.T) {
	fn := engine.Functions["pg_relation_size"]
	require.NotNil(t, fn, "pg_relation_size function should exist")

	scalarFn, ok := fn.(*engine.ScalarFunctionDefinition)
	require.True(t, ok, "pg_relation_size should be a ScalarFunctionDefinition")

	// Test valid arguments
	validArgs := []*types.DataType{types.TextType}
	returnType, err := scalarFn.ValidateArgs(validArgs)
	require.NoError(t, err)
	assert.True(t, returnType.Equals(types.IntType), "should return INT type")

	// Test invalid argument count - no arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{})
	assert.Error(t, err, "should error with no arguments")

	// Test invalid argument count - too many arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.TextType, types.TextType})
	assert.Error(t, err, "should error with too many arguments")

	// Test invalid argument type
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.IntType})
	assert.Error(t, err, "should error with wrong argument type")

	// Test PostgreSQL format
	result, err := scalarFn.PGFormatFunc([]string{"'table_name'"})
	require.NoError(t, err)
	assert.Equal(t, "pg_relation_size('table_name')", result, "should format correctly")
}

func TestPgSizePrettyFunction(t *testing.T) {
	fn := engine.Functions["pg_size_pretty"]
	require.NotNil(t, fn, "pg_size_pretty function should exist")

	scalarFn, ok := fn.(*engine.ScalarFunctionDefinition)
	require.True(t, ok, "pg_size_pretty should be a ScalarFunctionDefinition")

	// Test valid arguments
	validArgs := []*types.DataType{types.IntType}
	returnType, err := scalarFn.ValidateArgs(validArgs)
	require.NoError(t, err)
	assert.True(t, returnType.Equals(types.TextType), "should return TEXT type")

	// Test invalid argument count - no arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{})
	assert.Error(t, err, "should error with no arguments")

	// Test invalid argument count - too many arguments
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.IntType, types.IntType})
	assert.Error(t, err, "should error with too many arguments")

	// Test invalid argument type
	_, err = scalarFn.ValidateArgs([]*types.DataType{types.TextType})
	assert.Error(t, err, "should error with wrong argument type")

	// Test PostgreSQL format
	result, err := scalarFn.PGFormatFunc([]string{"1024"})
	require.NoError(t, err)
	assert.Equal(t, "pg_size_pretty(1024)", result, "should format correctly")
}
