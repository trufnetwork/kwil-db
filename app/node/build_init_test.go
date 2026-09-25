package node

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

type schemaMapExec struct {
	schemas map[string]bool
}

func (m *schemaMapExec) Execute(_ context.Context, stmt string, args ...any) (*sql.ResultSet, error) {
	if strings.Contains(stmt, "information_schema.schemata") {
		name, _ := args[0].(string)
		if m.schemas[name] {
			return &sql.ResultSet{Rows: [][]any{{1}}}, nil
		}
		return &sql.ResultSet{}, nil
	}
	return &sql.ResultSet{}, nil
}

func TestInspectInitSchemasRejectsPartialRestore(t *testing.T) {
	ctx := context.Background()

	complete, leftover, err := inspectInitSchemas(ctx, &schemaMapExec{
		schemas: map[string]bool{"kwild_voting": true},
	})
	require.NoError(t, err)
	require.False(t, complete)
	require.True(t, leftover)

	complete, leftover, err = inspectInitSchemas(ctx, &schemaMapExec{schemas: map[string]bool{}})
	require.NoError(t, err)
	require.False(t, complete)
	require.False(t, leftover)

	complete, leftover, err = inspectInitSchemas(ctx, &schemaMapExec{
		schemas: map[string]bool{
			"kwild_voting":   true,
			"kwild_internal": true,
			"kwild_accts":    true,
		},
	})
	require.NoError(t, err)
	require.True(t, complete)
	require.False(t, leftover)
}
