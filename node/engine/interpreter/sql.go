package interpreter

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/utils/order"
	"github.com/trufnetwork/kwil-db/extensions/precompiles"
	"github.com/trufnetwork/kwil-db/node/engine"
	"github.com/trufnetwork/kwil-db/node/engine/parse"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
)

var (
	//go:embed schema.sql
	schemaInitSQL string
)

// queryOneInt64 queries for a single int64 Value.
func queryOneInt64(ctx context.Context, db sql.DB, query string, args ...any) (int64, error) {
	var res *int64
	err := queryRowFunc(ctx, db, query, []any{&res}, func() error { return nil }, args...)
	if err != nil {
		return 0, err
	}
	if res == nil {
		return 0, errors.New("expected exactly one row")
	}

	return *res, nil
}

// createNamespace creates a new schema for a user.
func createNamespace(ctx context.Context, db sql.DB, name string, nsType namespaceType) (int64, error) {
	err := execute(ctx, db, `CREATE SCHEMA `+name)
	if err != nil {
		return 0, err
	}

	return queryOneInt64(ctx, db, `INSERT INTO kwild_engine.namespaces (name, type) VALUES ($1, $2) RETURNING id`, name, nsType)
}

// dropNamespace drops a schema for a user.
func dropNamespace(ctx context.Context, db sql.DB, name string) error {
	err := execute(ctx, db, `DROP SCHEMA `+name+` CASCADE`)
	if err != nil {
		return err
	}

	return execute(ctx, db, `DELETE FROM kwild_engine.namespaces WHERE name = $1`, name)
}

// storeAction stores an action in the database.
// It should always be called within a transaction.
func storeAction(ctx context.Context, db sql.DB, namespace string, action *action, builtin bool) error {
	returnsTable := false
	if action.Returns != nil {
		returnsTable = action.Returns.IsTable
	}

	modStrs := make([]string, len(action.Modifiers))
	for i, mod := range action.Modifiers {
		modStrs[i] = string(mod)
	}

	actionID, err := queryOneInt64(ctx, db, `INSERT INTO kwild_engine.actions (name, namespace, raw_statement, modifiers, returns_table, built_in)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		action.Name, namespace, action.RawStatement, modStrs, returnsTable, builtin)
	if err != nil {
		return err
	}

	for i, param := range action.Parameters {
		err = execute(ctx, db, `INSERT INTO kwild_engine.parameters (action_id, name, scalar_type, is_array, metadata, position)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			actionID, param.Name, strings.ToUpper(param.Type.Name), param.Type.IsArray, getTypeMetadata(param.Type), i+1)
		if err != nil {
			return err
		}
	}

	if action.Returns != nil {
		for i, field := range action.Returns.Fields {
			err = execute(ctx, db, `INSERT INTO kwild_engine.return_fields (action_id, name, scalar_type, is_array, metadata, position)
			VALUES ($1, $2, $3, $4, $5, $6)`,
				actionID, field.Name, strings.ToUpper(field.Type.Name), field.Type.IsArray, getTypeMetadata(field.Type), i+1)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// deleteAction deletes an action from the database.
func deleteAction(ctx context.Context, db sql.DB, namespace, actionName string) error {
	return execute(ctx, db, `DELETE FROM kwild_engine.actions WHERE namespace = $1 AND name = $2`, namespace, actionName)
}

// deleteActionIfBuiltin deletes an action from the database if it is a built-in action.
// It returns true if an action was found but not deleted
func deleteActionIfBuiltin(ctx context.Context, db sql.DB, namespace, actionName string) (bool, error) {
	var builtin bool
	found := false
	err := queryRowFunc(ctx, db, `SELECT built_in FROM kwild_engine.actions WHERE namespace = $1 AND name = $2`, []any{&builtin},
		func() error {
			found = true
			return nil
		}, namespace, actionName)
	if err != nil {
		return false, err
	}

	if builtin {
		return false, deleteAction(ctx, db, namespace, actionName)
	}

	return found, nil
}

// listNamespaces lists all namespaces that are created.
func listNamespaces(ctx context.Context, db sql.DB) ([]struct {
	Name string
	Type namespaceType
}, error) {
	var namespaces []struct {
		Name string
		Type namespaceType
	}
	var namespace string
	var nsType string
	err := queryRowFunc(ctx, db, `SELECT name, type::TEXT FROM kwild_engine.namespaces`, []any{&namespace, &nsType},
		func() error {
			nsT := namespaceType(nsType)
			if !nsT.valid() {
				return fmt.Errorf("unknown namespace type %s", nsType)
			}

			namespaces = append(namespaces, struct {
				Name string
				Type namespaceType
			}{Name: namespace, Type: nsT})
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return namespaces, nil
}

// listTablesInNamespace lists all tables in a namespace.
func listTablesInNamespace(ctx context.Context, db sql.DB, namespace string) ([]*engine.Table, error) {
	tables := make([]*engine.Table, 0)
	var schemaName string
	var tblName string
	var colNames, dataTypes, indexNames, constraintNames, constraintTypes, fkNames, fkOnUpdate, fkOnDelete []string
	var indexCols, constraintCols, fkCols [][]string
	var isNullables, isPrimaryKeys, isPKs, isUniques []bool
	scans := []any{
		&schemaName,
		&tblName,
		&colNames,
		&dataTypes,
		&isNullables,
		&isPrimaryKeys,
		&indexNames,
		&isPKs,
		&isUniques,
		&indexCols,
		&constraintNames,
		&constraintTypes,
		&constraintCols,
		&fkNames,
		&fkCols,
		&fkOnUpdate,
		&fkOnDelete,
	}
	// we use json_agg here instead of array_agg because we are aggregationg single dimensional arrays into
	// 2d arrays. Array agg requires all incoming 1d arrays to be of the same length, but json_agg does not.
	err := queryRowFunc(ctx, db, `
	WITH columns AS (
		SELECT c.namespace, c.table_name,
			json_agg(c.name ORDER BY c.ordinal_position) AS column_names,
			json_agg(c.data_type ORDER BY c.ordinal_position) AS data_types,
			json_agg(c.is_nullable ORDER BY c.ordinal_position) AS is_nullables,
			json_agg(c.is_primary_key ORDER BY c.ordinal_position) AS is_primary_keys
		FROM info.columns c
		GROUP BY c.namespace, c.table_name
	),
	indexes AS (
		SELECT i.namespace, i.table_name,
			json_agg(i.name ORDER BY i.name) AS names,
			json_agg(i.is_primary_key ORDER BY i.name) AS is_pks,
			json_agg(i.is_unique ORDER BY i.name) AS is_uniques,
			json_agg(i.columns ORDER BY i.name) AS column_names
		FROM info.indexes i
		GROUP BY i.namespace, i.table_name
	), constraints AS (
		SELECT c.namespace, c.table_name,
			json_agg(c.name ORDER BY c.name) AS constraint_names,
			json_agg(c.constraint_type ORDER BY c.name) AS constraint_types,
			json_agg(c.columns ORDER BY c.name) AS columns
		FROM info.constraints c
		GROUP BY c.namespace, c.table_name
	), foreign_keys AS (
		SELECT f.namespace, f.table_name,
			json_agg(f.name ORDER BY f.name) AS constraint_names,
			json_agg(f.columns ORDER BY f.name) AS columns,
			json_agg(f.on_update ORDER BY f.name) AS on_updates,
			json_agg(f.on_delete ORDER BY f.name) AS on_deletes
		FROM info.foreign_keys f
		GROUP BY f.namespace, f.table_name
	)
	SELECT
		t.namespace, t.name,
		c.column_names, c.data_types, c.is_nullables, c.is_primary_keys,
		i.names, i.is_pks, i.is_uniques, i.column_names,
		co.constraint_names, co.constraint_types, co.columns,
		f.constraint_names, f.columns, f.on_updates, f.on_deletes
	FROM info.tables t
	JOIN columns c ON t.name = c.table_name AND t.namespace = c.namespace
	LEFT JOIN indexes i ON t.name = i.table_name AND t.namespace = i.namespace
	LEFT JOIN constraints co ON t.name = co.table_name AND t.namespace = co.namespace
	LEFT JOIN foreign_keys f ON t.name = f.table_name AND t.namespace = f.namespace
	WHERE t.namespace = $1`, scans,
		func() error {
			tbl := &engine.Table{
				Name:        tblName,
				Constraints: make(map[string]*engine.Constraint),
			}

			tables = append(tables, tbl)

			// add columns
			for i, colName := range colNames {
				dt, err := types.ParseDataType(dataTypes[i])
				if err != nil {
					return err
				}

				tbl.Columns = append(tbl.Columns, &engine.Column{
					Name:         colName,
					DataType:     dt,
					Nullable:     isNullables[i],
					IsPrimaryKey: isPrimaryKeys[i],
				})
			}

			// add indexes
			for i, indexName := range indexNames {
				indexType := engine.BTREE
				if isPKs[i] {
					indexType = engine.PRIMARY
				} else if isUniques[i] {
					indexType = engine.UNIQUE_BTREE
				}

				tbl.Indexes = append(tbl.Indexes, &engine.Index{
					Name:    indexName,
					Columns: indexCols[i],
					Type:    indexType,
				})
			}

			// add constraints
			for i, constraintName := range constraintNames {
				var constraintType engine.ConstraintType
				switch strings.ToLower(constraintTypes[i]) {
				case "unique":
					constraintType = engine.ConstraintUnique
				case "check":
					constraintType = engine.ConstraintCheck
				default:
					return fmt.Errorf("unknown constraint type %s", constraintTypes[i])
				}

				_, ok := tbl.Constraints[constraintName]
				if ok {
					return fmt.Errorf("duplicate constraint %s", constraintName)
				}

				tbl.Constraints[constraintName] = &engine.Constraint{
					Type:    constraintType,
					Columns: constraintCols[i],
				}
			}

			// add foreign keys
			for i, fkName := range fkNames {
				_, ok := tbl.Constraints[fkName]
				if ok {
					return fmt.Errorf("duplicate foreign key %s", fkName)
				}

				fk := &engine.Constraint{
					Type:    engine.ConstraintFK,
					Columns: fkCols[i],
				}

				tbl.Constraints[fkName] = fk
			}
			return nil
		}, namespace,
	)
	if err != nil {
		return nil, err
	}

	return tables, nil
}

// listActionsInBuiltInNamespace lists all actions in a namespace.
// If the namespace is an extension, it wont return any actions.
func listActionsInBuiltInNamespace(ctx context.Context, db sql.DB, namespace string) ([]*action, error) {
	var actions []*action
	var rawStmt string
	scans := []any{
		&rawStmt,
	}

	stmt := `
	SELECT a.raw_statement
	FROM kwild_engine.actions a
	WHERE a.namespace = $1 AND a.built_in = false
	`

	err := queryRowFunc(ctx, db, stmt, scans,
		func() error {
			res, err := parse.Parse(rawStmt)
			if err != nil {
				return fmt.Errorf("%w: %w", engine.ErrParse, err)
			}

			if len(res) != 1 {
				return fmt.Errorf("expected exactly 1 statement, got %d", len(res))
			}

			createActionStmt, ok := res[0].(*parse.CreateActionStatement)
			if !ok {
				return fmt.Errorf("expected CreateActionStatement, got %T", res[0])
			}

			act := &action{}
			err = act.FromAST(createActionStmt)
			if err != nil {
				return err
			}

			actions = append(actions, act)
			return nil
		}, namespace,
	)
	if err != nil {
		return nil, err
	}

	return actions, nil
}

// RegisterExtensionInitialization registers that an extension was initialized with some values.
func RegisterExtensionInitialization(ctx context.Context, db sql.DB, name, baseExtName string, metadata map[string]Value) error {
	id, err := createNamespace(ctx, db, name, namespaceTypeExtension)
	if err != nil {
		return err
	}

	extId, err := queryOneInt64(ctx, db, `INSERT INTO kwild_engine.initialized_extensions (namespace_id, base_extension) VALUES (
		$1,
		$2
	) RETURNING id
	`, id, baseExtName)
	if err != nil {
		return err
	}

	if len(metadata) == 0 {
		return nil
	}

	insertMetaStmt := `INSERT INTO kwild_engine.extension_initialization_parameters (extension_id, key, Value, scalar_type, is_array, metadata) VALUES `
	i := 2
	rawVals := []any{extId}
	for k, v := range metadata {
		if i > 2 {
			insertMetaStmt += `,`
		}

		strVal, err := stringifyValue(v)
		if err != nil {
			return err
		}

		rawVals = append(rawVals, k, strVal, strings.ToUpper(v.Type().Name), v.Type().IsArray, getTypeMetadata(v.Type()))
		insertMetaStmt += fmt.Sprintf(`($1, $%d, $%d, $%d, $%d, $%d)`, i, i+1, i+2, i+3, i+4)
		i += 5
	}

	return execute(ctx, db, insertMetaStmt, rawVals...)
}

// UnregisterExtensionInitialization unregisters that an extension was initialized.
// It simply wraps dropNamespace, relying on foreign key constraints to delete all related data.
// I wrap it in case we need to do more in the future.
func UnregisterExtensionInitialization(ctx context.Context, db sql.DB, alias string) error {
	return dropNamespace(ctx, db, alias)
}

type StoredExtension struct {
	// ExtName is the name of the extension.
	ExtName string
	// Alias is the alias of the extension.
	Alias string
	// Metadata is the metadata of the extension.
	Metadata map[string]Value
}

// getExtensionInitializationMetadata gets all initialized extensions and their metadata.
func getExtensionInitializationMetadata(ctx context.Context, db sql.DB) ([]*StoredExtension, error) {
	extMap := make(map[string]*StoredExtension) // maps the alias to the extension, will be sorted later

	var extName, alias string
	var key, val, dt *string
	err := queryRowFunc(ctx, db, `
	SELECT n.name AS alias, ie.base_extension AS ext_name, eip.key, eip.Value, kwild_engine.format_type(eip.scalar_type, eip.is_array, eip.metadata) AS data_type
	FROM kwild_engine.initialized_extensions ie
	JOIN kwild_engine.namespaces n ON ie.namespace_id = n.id
	LEFT JOIN kwild_engine.extension_initialization_parameters eip ON ie.id = eip.extension_id`,
		[]any{&alias, &extName, &key, &val, &dt},
		func() error {
			ext, ok := extMap[alias]
			if !ok {
				ext = &StoredExtension{
					Alias:    alias,
					ExtName:  extName,
					Metadata: make(map[string]Value),
				}
				extMap[alias] = ext
			}

			// if key, val, and dt are all nil, then there is no metadata
			// If some are nil, it is an error
			if key == nil && val == nil && dt == nil {
				return nil
			}
			if key == nil || val == nil || dt == nil {
				return errors.New("expected all or none extension metadata values to be nil. this is an internal bug")
			}

			datatype, err := types.ParseDataType(*dt)
			if err != nil {
				return err
			}

			v, err := parseValue(*val, datatype)
			if err != nil {
				return err
			}

			ext.Metadata[*key] = v
			return nil
		})
	if err != nil {
		return nil, err
	}

	var fin []*StoredExtension
	ordered := order.OrderMap(extMap)
	for _, o := range ordered {
		fin = append(fin, o.Value)
	}

	return fin, nil
}

// ensureExtensionRegistered ensures that extension methods are registered as actions within the database.
// It is idempotent.
func ensureMethodsRegistered(ctx context.Context, db sql.DB, alias string, methods []precompiles.Method) error {
	for _, method := range methods {
		// if an action exists, we always want to delete and overwrite it.
		// This is only true if the action was built-in; if it was user-defined,
		// we should not delete it.
		foundButNotDeleted, err := deleteActionIfBuiltin(ctx, db, alias, method.Name)
		if err != nil {
			return err
		}
		if foundButNotDeleted {
			// if it was found but not deleted, then it is a user-defined action, and we
			// should not overwrite it.
			return nil
		}

		params := make([]*engine.NamedType, len(method.Parameters))
		for i, p := range method.Parameters {
			params[i] = &engine.NamedType{
				Name: "$param_" + strconv.Itoa(i+1),
				Type: p.Type,
			}
		}

		var returns *actionReturn
		if method.Returns != nil {
			returns = &actionReturn{
				IsTable: method.Returns.IsTable,
			}

			fields := make([]*engine.NamedType, len(method.Returns.Fields))
			for i, f := range method.Returns.Fields {
				fields[i] = &engine.NamedType{
					Name: f.Name,
					Type: f.Type,
				}
			}

			returns.Fields = fields
		}

		if err := storeAction(ctx, db, alias, &action{
			Name:       method.Name,
			Parameters: params,
			Modifiers:  method.AccessModifiers,
			Returns:    returns,
			// body and raw statement are not used
		}, true); err != nil {
			return err
		}
	}

	return nil
}

// getTypeMetadata gets the serialized type metadata.
// If there is none, it returns nil.
func getTypeMetadata(t *types.DataType) []byte {
	if !t.HasMetadata() {
		return nil
	}

	meta := make([]byte, 4)
	binary.BigEndian.PutUint16(meta[:2], t.Metadata[0])
	binary.BigEndian.PutUint16(meta[2:], t.Metadata[1])

	return meta
}

// query executes a SQL query with the given values.
// It is a utility function to help reduce boilerplate when executing
// SQL with Value types.
func query(ctx context.Context, db sql.DB, query string, scanVals []any, fn func() error, args []Value) error {
	argVals := make([]any, len(args))
	for i, v := range args {
		argVals[i] = v
	}

	// The scanVals slice must be the same slice used in the caller's fn.
	return queryRowFunc(ctx, db, query, scanVals, fn, argVals...)
}

// queryRowFunc executes a SQL query with the given values.
func queryRowFunc(ctx context.Context, tx sql.Executor, stmt string,
	scans []any, fn func() error, args ...any) error {
	return pg.QueryRowFunc(ctx, tx, stmt, scans, fn, append([]any{pg.QueryModeExec}, args...)...)
}

// execute executes a SQL statement with the given values.
func execute(ctx context.Context, db sql.DB, stmt string, args ...any) error {
	return queryRowFunc(ctx, db, stmt, nil, func() error { return nil }, args...)
}
