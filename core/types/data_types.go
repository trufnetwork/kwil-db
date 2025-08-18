package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DataType is a data type.
// It includes both built-in types and user-defined types.
type DataType struct {
	// Name is the name of the type.
	Name string `json:"name"`
	// IsArray is true if the type is an array.
	IsArray bool `json:"is_array"`
	// Metadata is the metadata of the type.
	Metadata [2]uint16 `json:"metadata"`
}

func (c DataType) SerializeSize() int {
	// uint16 version + uint32 name length + name + uint8 is_array +
	//   2 x uint16 metadata
	return 2 + 4 + len(c.Name) + 1 + 4
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (c DataType) MarshalBinary() ([]byte, error) {
	b := make([]byte, c.SerializeSize())
	const ver uint16 = 0
	binary.BigEndian.PutUint16(b, ver)
	offset := 2
	binary.BigEndian.PutUint32(b[offset:], uint32(len(c.Name)))
	offset += 4
	copy(b[offset:], c.Name)
	offset += len(c.Name)
	b[offset] = boolToByte(c.IsArray)
	offset++
	binary.BigEndian.PutUint16(b[offset:], c.Metadata[0])
	offset += 2
	binary.BigEndian.PutUint16(b[offset:], c.Metadata[1])
	return b, nil
}

func (c *DataType) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	ver := binary.BigEndian.Uint16(data)
	if ver != 0 {
		return fmt.Errorf("invalid tuple data, unknown version %d", ver)
	}
	offset := 2
	nameLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if len(data) < offset+nameLen+1+2*2 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	c.Name = string(data[offset : offset+nameLen])
	offset += nameLen

	switch data[offset] {
	case 0:
	case 1:
		c.IsArray = true
	default:
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	offset++

	c.Metadata[0] = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	c.Metadata[1] = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if offset != c.SerializeSize() { // bug, must match
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	return nil
}

// String returns the string representation of the type.
func (c *DataType) String() string {
	str := strings.Builder{}
	aliased, ok := typeAlias[c.Name]
	if !ok {
		aliased = "[!invalid!]" + c.Name
	}

	str.WriteString(aliased)

	if aliased == NumericStr {
		str.WriteString("(")
		str.WriteString(strconv.FormatUint(uint64(c.Metadata[0]), 10))
		str.WriteString(",")
		str.WriteString(strconv.FormatUint(uint64(c.Metadata[1]), 10))
		str.WriteString(")")
	}

	if c.IsArray {
		return str.String() + "[]"
	}

	return str.String()
}

func (c *DataType) HasMetadata() bool {
	return c.Metadata != [2]uint16{}
}

// PGString returns the string representation of the type in Postgres.
func (c *DataType) PGString() (string, error) {
	scalar, err := c.PGScalar()
	if err != nil {
		return "", err
	}

	if c.IsArray {
		return scalar + "[]", nil
	}

	return scalar, nil
}

// PGScalar returns the scalar representation of the type in Postgres.
// For example, if this is of type DECIMAL(100,5)[], it will return NUMERIC(100,5).
func (c *DataType) PGScalar() (string, error) {
	var scalar string
	switch strings.ToLower(c.Name) {
	case intStr:
		scalar = "INT8"
	case int4Str:
		scalar = "INT4"
	case textStr:
		scalar = "TEXT"
	case boolStr:
		scalar = "BOOL"
	case byteaStr:
		scalar = "BYTEA"
	case uuidStr:
		scalar = "UUID"
	case NumericStr:
		if !c.HasMetadata() {
			return "", errors.New("numeric type requires metadata")
		} else {
			scalar = fmt.Sprintf("NUMERIC(%d,%d)", c.Metadata[0], c.Metadata[1])
		}
	case nullStr:
		return "", errors.New("cannot have null column type")
	default:
		return "", fmt.Errorf("unknown column type: %s", c.Name)
	}

	return scalar, nil
}

func (c *DataType) Clean() error {
	lName := strings.ToLower(c.Name)

	referencedType, ok := typeAlias[lName]
	if !ok {
		return fmt.Errorf("unknown type: %s", c.Name)
	}

	switch referencedType {
	case intStr, int4Str, textStr, boolStr, byteaStr, uuidStr: // ok
		if c.HasMetadata() {
			return fmt.Errorf("type %s cannot have metadata", c.Name)
		}
	case NumericStr:
		if !c.HasMetadata() {
			return fmt.Errorf("type %s requires metadata", c.Name)
		}
		err := CheckDecimalPrecisionAndScale(c.Metadata[0], c.Metadata[1])
		if err != nil {
			return err
		}

	case nullStr:
		if c.IsArray {
			return fmt.Errorf("type %s cannot be an array", c.Name)
		}

		if c.HasMetadata() {
			return fmt.Errorf("type %s cannot have metadata", c.Name)
		}
	default:
		return fmt.Errorf("unknown type: %s", c.Name)
	}

	c.Name = referencedType

	return nil
}

// Copy returns a copy of the type.
func (c *DataType) Copy() *DataType {
	d := &DataType{
		Name:     c.Name,
		IsArray:  c.IsArray,
		Metadata: c.Metadata,
	}

	return d
}

// EqualsStrict returns true if the type is equal to the other type.
// The types must be exactly the same, including metadata.
// Unlike Equals, it will return false if one of the types is null
// and the other is not.
func (c *DataType) EqualsStrict(other *DataType) bool {
	if c.IsArray != other.IsArray {
		return false
	}

	if c.Metadata[0] != other.Metadata[0] || c.Metadata[1] != other.Metadata[1] {
		return false
	}

	return strings.EqualFold(c.Name, other.Name)
}

// Equals returns true if the type is equal to the other type, or if either type is null.
func (c *DataType) Equals(other *DataType) bool {
	// we have a special case for null here because null can be any type.
	// Null can be assigned to any type.
	// A null array (which itself is not null) can be assigned to any array.
	if (c.Name == nullStr && !c.IsArray) || (other.Name == nullStr && !other.IsArray) {
		// if either is a scalar null, always true
		return true
	}
	if (c.Name == nullStr && c.IsArray) && other.IsArray {
		return true
	}
	if (other.Name == nullStr && other.IsArray) && c.IsArray {
		return true
	}

	return c.EqualsStrict(other)
}

func (c *DataType) IsNumeric() bool {
	if c.IsArray {
		return false
	}

	return c.Name == intStr || c.Name == int4Str || c.Name == NumericStr || c.Name == nullStr
}

// declared DataType constants.
// We do not have one for fixed because fixed types require metadata.
var (
	IntType = &DataType{
		Name: intStr,
	}
	IntArrayType = ArrayType(IntType)
	Int4Type     = &DataType{
		Name: int4Str,
	}
	Int4ArrayType = ArrayType(Int4Type)
	TextType      = &DataType{
		Name: textStr,
	}
	TextArrayType = ArrayType(TextType)
	BoolType      = &DataType{
		Name: boolStr,
	}
	BoolArrayType = ArrayType(BoolType)
	ByteaType     = &DataType{
		Name: byteaStr,
	}
	ByteaArrayType = ArrayType(ByteaType)
	UUIDType       = &DataType{
		Name: uuidStr,
	}
	UUIDArrayType = ArrayType(UUIDType)
	// NumericType contains 1,0 metadata.
	// For type detection, users should prefer compare a datatype
	// name with the NumericStr constant.
	NumericType = &DataType{
		Name:     NumericStr,
		Metadata: [2]uint16{0, 0}, // unspecified precision and scale
	}
	NumericArrayType = ArrayType(NumericType)
	// NullType is a special type used to denote a null value where
	// we do not yet know the type.
	NullType = &DataType{
		Name: nullStr,
	}
	NullArrayType = ArrayType(NullType)
)

// ArrayType creates an array type of the given type.
// It panics if the type is already an array.
func ArrayType(t *DataType) *DataType {
	if t.IsArray {
		panic("cannot create an array of an array")
	}
	return &DataType{
		Name:     t.Name,
		IsArray:  true,
		Metadata: t.Metadata,
	}
}

const (
	textStr  = "text"
	intStr   = "int8"
	int4Str  = "int4"
	boolStr  = "bool"
	byteaStr = "bytea"
	uuidStr  = "uuid"
	// NumericStr is a fixed point number.
	NumericStr = "numeric"
	nullStr    = "null"
)

// NewNumericType creates a new fixed point numeric type.
func NewNumericType(precision, scale uint16) (*DataType, error) {
	err := CheckDecimalPrecisionAndScale(precision, scale)
	if err != nil {
		return nil, err
	}

	return &DataType{
		Name:     NumericStr,
		Metadata: [2]uint16{precision, scale},
	}, nil
}

// ParseDataType parses a string into a data type.
func ParseDataType(s string) (*DataType, error) {
	// four cases: TEXT, TEXT[], TEXT(1,2), TEXT(1,2)[]
	// we will parse the type first, then the array, then the metadata
	// we will not allow metadata without an array

	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return nil, errors.New("empty data type")
	}

	// Regular expression to parse the data type
	re := regexp.MustCompile(`^([a-z0-9]+)(\(([\d, ]+)\))?(\[\])?$`)
	matches := re.FindStringSubmatch(s)

	if len(matches) == 0 {
		return nil, fmt.Errorf("invalid data type format: %s", s)
	}

	baseType := matches[1]
	rawMetadata := matches[3]
	isArray := matches[4] == "[]"

	baseName, ok := typeAlias[baseType]
	if !ok {
		return nil, fmt.Errorf("unknown data type: %s", baseType)
	}

	var metadata [2]uint16
	if rawMetadata != "" {
		metadata = [2]uint16{}
		// only numeric types can have metadata
		if baseName != NumericStr {
			return nil, fmt.Errorf("metadata is only allowed for numeric type")
		}

		parts := strings.Split(rawMetadata, ",")
		// must be either NUMERIC(10,5)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid metadata format: %s", rawMetadata)
		}
		for i, part := range parts {
			num, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, fmt.Errorf("invalid metadata value: %s", part)
			}
			if num > int(maxPrecision) {
				return nil, fmt.Errorf("precision must be less than %d", maxPrecision)
			}
			metadata[i] = uint16(num)
		}
	}

	dt := &DataType{
		Name:     baseName,
		Metadata: metadata,
		IsArray:  isArray,
	}

	return dt, dt.Clean()
}

// maps type names to their base names.
// null is not included here because it is a special type.
var typeAlias = map[string]string{
	"string":   textStr,
	"text":     textStr,
	"int":      intStr,
	"integer":  intStr,
	"bigint":   intStr,
	"int8":     intStr,
	"int4":     int4Str,
	"smallint": int4Str,
	"bool":     boolStr,
	"boolean":  boolStr,
	"blob":     byteaStr,
	"bytea":    byteaStr,
	"uuid":     uuidStr,
	"decimal":  NumericStr,
	"numeric":  NumericStr,
}
