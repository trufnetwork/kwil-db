package logical

import (
	"fmt"
	"strings"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/engine"
)

// Relation is the current relation in the query plan.
type Relation struct {
	Fields []*Field
}

func (r *Relation) Copy() *Relation {
	var fields []*Field
	for _, f := range r.Fields {
		fields = append(fields, f.Copy())
	}
	return &Relation{
		Fields: fields,
	}
}

func (s *Relation) ColumnsByParent(name string) []*Field {
	var columns []*Field
	for _, c := range s.Fields {
		if c.Parent == name {
			columns = append(columns, c)
		}
	}
	return columns
}

// Search searches for a column by parent and name.
// If the column is not found, an error is returned.
// If no parent is specified and many columns have the same name,
// an error is returned.
func (s *Relation) Search(parent, name string) (*Field, error) {
	if parent == "" {
		var column *Field
		count := 0
		for _, c := range s.Fields {
			if c.Name == name {
				column = c
				count++
			}
		}
		if count == 0 {
			return nil, fmt.Errorf(`%w: "%s"`, ErrColumnNotFound, name)
		}
		if count > 1 {
			return nil, fmt.Errorf(`%w: "%s"`, ErrAmbiguousColumn, name)
		}

		// return a new instance since we are qualifying the column
		newCol := column.Copy()
		if newCol.Parent == "" {
			newCol.Parent = column.Parent
		}
		return newCol, nil
	}

	for _, c := range s.Fields {
		if c.Parent == parent && c.Name == name {
			return c.Copy(), nil
		}
	}

	return nil, fmt.Errorf(`%w: "%s.%s"`, ErrColumnNotFound, parent, name)
}

// FindReference finds a field by its reference ID.
// If there are many fields with the same reference ID, or no fields
// with the reference ID, an error is returned.
func (r *Relation) FindReference(id string) (*Field, error) {
	var found []*Field
	for _, f := range r.Fields {
		if f.ReferenceID == id {
			found = append(found, f)
		}
	}

	if len(found) == 0 {
		return nil, fmt.Errorf(`field with reference ID "%s" not found`, id)
	}

	if len(found) > 1 {
		return nil, fmt.Errorf(`field with reference ID "%s" is ambiguous`, id)
	}

	return found[0], nil
}

func relationFromTable(tbl *engine.Table) *Relation {
	s := &Relation{}
	for _, col := range tbl.Columns {
		s.Fields = append(s.Fields, &Field{
			Parent: tbl.Name,
			Name:   col.Name,
			val:    col.DataType.Copy(),
		})
	}
	return s
}

// equalShape checks that two relations have the same shape.
// This means that they have the same number of fields and that
// the fields have the same data types. The fields do NOT need
// to have the same names. If the relations do not have the same
// shape, an error is returned.
func equalShape(r1, r2 *Relation) error {
	if len(r1.Fields) != len(r2.Fields) {
		return fmt.Errorf("relations do not have the same number of fields")
	}

	for i, f := range r1.Fields {
		scalarR, err := f.Scalar()
		if err != nil {
			return err
		}

		scalarL, err := r2.Fields[i].Scalar()
		if err != nil {
			return err
		}

		if !scalarR.Equals(scalarL) {
			return fmt.Errorf("field %d (named %s and %s) does not have the same data type", i, f.Name, r2.Fields[i].Name)
		}
	}

	return nil
}

// Field is a field in a relation.
// Parent and Name can be empty, if the expression
// is a constant. If this is the last expression in a relation,
// the "Name" field will be the name of the column in the result.
type Field struct {
	Parent string // the parent relation name
	Name   string // the field name
	// val is the value of the field.
	// it can be either a single value or a map of values,
	// depending on the field type.
	// This value should be accessed using the Scalar() or Object()
	val any
	// ReferenceID is the ID with which this field can be referenced.
	// It can be empty if the field is not referenced.
	ReferenceID string
}

func (f *Field) String() string {
	if f.ReferenceID != "" {
		return fmt.Sprintf("[ref: %s]", f.ReferenceID)
	}

	str := strings.Builder{}
	if f.Parent != "" {
		str.WriteString(f.Parent)
		str.WriteString(".")
	}
	str.WriteString(f.Name)

	return str.String()
}

// ResultString returns a string representation of the field that contains information
// as to how the field will be represented as a user-facing column in the result.
func (f *Field) ResultString() string {
	str := strings.Builder{}
	str.WriteString(f.Name)

	str.WriteString(" [")
	scalar, err := f.Scalar()
	if err != nil {
		str.WriteString("object")
	} else {
		str.WriteString(scalar.String())
	}
	str.WriteString("]")

	return str.String()
}

func (f *Field) Copy() *Field {
	var val any
	switch v := f.val.(type) {
	case *types.DataType:
		val = v.Copy()
	case map[string]*types.DataType:
		val = make(map[string]*types.DataType)
		for k, v := range v {
			val.(map[string]*types.DataType)[k] = v.Copy()
		}
	}

	return &Field{
		Parent:      f.Parent,
		Name:        f.Name,
		val:         val,
		ReferenceID: f.ReferenceID,
	}
}

func (f *Field) Equals(other *Field) bool {
	if f.Parent != other.Parent {
		return false
	}
	if f.Name != other.Name {
		return false
	}
	if f.ReferenceID != other.ReferenceID {
		return false
	}

	if scalar1, err := f.Scalar(); err == nil {
		if scalar2, err := other.Scalar(); err == nil {
			return scalar1.Equals(scalar2)
		}

		return false
	} else {
		obj1, err := f.Object()
		if err != nil {
			return false
		}

		obj2, err := other.Object()
		if err != nil {
			return false
		}

		if len(obj1) != len(obj2) {
			return false
		}

		for k, v1 := range obj1 {
			v2, ok := obj2[k]
			if !ok {
				return false
			}

			if !v1.Equals(v2) {
				return false
			}
		}
	}

	return true
}

func (f *Field) Scalar() (*types.DataType, error) {
	dt, ok := f.val.(*types.DataType)
	if !ok {
		// can be triggered by a user if they try to directly use an object
		_, ok = f.val.(map[string]*types.DataType)
		if ok {
			return nil, fmt.Errorf("referenced field is an object, expected scalar or array. specify a field to access using the . operator")
		}

		// not user error
		panic(fmt.Sprintf("unexpected return type %T", f.val))
	}
	return dt, nil
}

func (f *Field) Object() (map[string]*types.DataType, error) {
	obj, ok := f.val.(map[string]*types.DataType)
	if !ok {
		// this can be triggered by a user if they try to use dot notation
		// on a scalar
		v, ok := f.val.(*types.DataType)
		if ok {
			if v.IsArray {
				return nil, fmt.Errorf("referenced expression is an array, expected object")
			}
			return nil, fmt.Errorf("referenced expression is a scalar, expected object")
		}

		// this is an internal bug
		panic(fmt.Sprintf("unexpected return type %T", f.val))
	}
	return obj, nil
}

// joinRels joins multiple relations into a single relation.
func joinRels(rels ...*Relation) *Relation {
	joined := &Relation{}
	for _, rel := range rels {
		rel2 := rel.Copy()
		joined.Fields = append(joined.Fields, rel2.Fields...)
	}
	return joined
}

// dataTypes returns a slice of data types from a slice of fields.
func dataTypes(fields []*Field) ([]*types.DataType, error) {
	var types1 []*types.DataType
	for _, f := range fields {
		dt, err := f.Scalar()
		if err != nil {
			return nil, err
		}
		types1 = append(types1, dt)
	}
	return types1, nil
}
