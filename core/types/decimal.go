// package Decimal implements a fixed-point decimal number.
// It is mostly a wrapper around github.com/cockroachdb/apd/v3, with some
// functionality that makes it easier to use in the context of Kwil. It enforces
// certain semantics of Postgres's decimal, such as precision and scale.
package types

import (
	"database/sql"
	"database/sql/driver"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/cockroachdb/apd/v3"
)

var (
	// context is the default context for the decimal.
	// We can change this to have different precision/speed properties,
	// but for now have it set to favor precision.
	context = apd.Context{
		Precision:   uint32(maxPrecision),
		MaxExponent: 2000,
		MinExponent: -2000,
		Traps:       apd.DefaultTraps,
		Rounding:    apd.RoundHalfUp,
	}

	// maxPrecision is the maximum supported precision.
	maxPrecision = uint16(1000)
)

// Decimal is a decimal number. It has a set precision and scale that
// will be used on all mathematical operations that are methods of the
// Decimal type. To perform mathematical operations with maximum precision
// and scale, use the math functions in this package instead of the methods.
type Decimal struct {
	dec       apd.Decimal
	scale     uint16
	precision uint16
}

// ParseDecimal creates a new Decimal from a string. It automatically infers the precision and scale.
func ParseDecimal(s string) (*Decimal, error) {
	inferredPrecision, inferredScale, err := inferPrecisionAndScale(s)
	if err != nil {
		return nil, err
	}

	return ParseDecimalExplicit(s, inferredPrecision, inferredScale)
}

// MustParseDecimal is like ParseDecimal but panics if the string cannot be parsed.
func MustParseDecimal(s string) *Decimal {
	dec, err := ParseDecimal(s)
	if err != nil {
		panic(err)
	}
	return dec
}

// ParseDecimalExplicit creates a new Decimal from a string, with an explicit precision and scale.
// The precision must be between 1 and 1000, and the scale must be between 0 and precision.
func ParseDecimalExplicit(s string, precision, scale uint16) (*Decimal, error) {
	dec := &Decimal{}

	if err := dec.SetPrecisionAndScale(precision, scale); err != nil {
		return nil, err
	}

	if err := dec.SetString(s); err != nil {
		return nil, err
	}

	return dec, nil
}

// MustParseDecimalExplicit is like ParseDecimalExplicit but panics if the string cannot be parsed.
func MustParseDecimalExplicit(s string, precision, scale uint16) *Decimal {
	dec, err := ParseDecimalExplicit(s, precision, scale)
	if err != nil {
		panic(err)
	}
	return dec
}

func NewDecimalFromInt(i int64) *Decimal {
	b, err := NewDecimalFromBigInt(big.NewInt(i), 0)
	if err != nil {
		// wont panic because exp is 0
		panic(err)
	}

	return b
}

// NewDecimalFromBigInt creates a new Decimal from a big.Int and an exponent.
// The negative of the exponent is the scale of the decimal.
func NewDecimalFromBigInt(i *big.Int, exp int32) (*Decimal, error) {
	if exp > 0 {
		i2 := big.NewInt(10)
		i2.Exp(i2, big.NewInt(int64(exp)), nil)
		i2.Mul(i, i2)
		i = i2
		exp = 0
	}

	b := &apd.BigInt{}
	b.SetMathBigInt(i)

	apdDec := apd.NewWithBigInt(b, exp)

	dec := &Decimal{
		dec:   *apdDec,
		scale: uint16(-apdDec.Exponent),
		// to get the scale, we need to remove + or -
		precision: uint16(len(strings.TrimLeft(i.String(), "-+"))),
	}

	// It is possible for scale to be greater than precision here, if for example
	// we were given the number .0001, which would be big int 1 and exponent -4.
	// To account for this, if the scale is greater than the precision, we set the
	// precision to the scale.
	if dec.scale > dec.precision {
		dec.precision = dec.scale
	}

	if err := CheckDecimalPrecisionAndScale(dec.precision, dec.scale); err != nil {
		return nil, err
	}

	return dec, nil
}

// NewNaNDecimal creates a new NaN Decimal.
func NewNaNDecimal() *Decimal {
	return &Decimal{
		dec: apd.Decimal{
			Form: apd.NaN,
		},
	}
}

// SetString sets the value of the decimal from a string.
func (d *Decimal) SetString(s string) error {
	if s != "" {
		// Validate s before parsing.
		if _, err := strconv.ParseFloat(s, 64); err != nil && !errors.Is(err, strconv.ErrRange) { // we can handle large numbers
			return fmt.Errorf("invalid decimal string: %s, error: %w", s, err)
		}
	}

	res, _, err := d.context().NewFromString(s)
	if err != nil {
		return err
	}

	d.dec = *res

	if err := d.enforceScale(); err != nil {
		return err
	}

	return nil
}

// inferPrecisionAndScale infers the precision and scale from a string.
func inferPrecisionAndScale(s string) (precision, scale uint16, err error) {
	// Validate if the input is a proper number
	if _, err = strconv.ParseFloat(s, 64); err != nil && !errors.Is(err, strconv.ErrRange) { // we can handle large numbers
		return 0, 0, fmt.Errorf("invalid decimal string: %s, error: %w", s, err)
	}

	s = strings.TrimLeft(s, "-+")
	parts := strings.Split(s, ".")

	// remove 0s from the left part, since 001.23 is the same as 1.23
	parts[0] = strings.TrimLeft(parts[0], "0")

	intPart := uint16(len(parts[0]))
	if len(parts) == 1 {
		return max(1, intPart), 0, nil // at least 1 for precision with 0 scale
	}

	scale = uint16(len(parts[1]))
	return intPart + scale, scale, nil // precision is the sum of the two
}

// Scale returns the scale of the decimal.
// This is the number of digits to the right of the decimal point.
// It will be a value between 0 and 1000
func (d *Decimal) Scale() uint16 {
	return d.scale
}

// Precision returns the precision of the decimal.
// This is the number of significant digits in the decimal.
// It will be a value between 1 and 1000
func (d *Decimal) Precision() uint16 {
	return d.precision
}

// Exp is the exponent of the decimal.
func (d *Decimal) Exp() int32 {
	return d.dec.Exponent
}

// IsNegative returns true if the decimal is negative.
func (d *Decimal) IsNegative() bool {
	return d.dec.Negative
}

// IsZero returns true if the decimal is zero.
func (d *Decimal) IsZero() bool {
	return d.dec.IsZero()
}

// IsPositive returns true if the decimal is positive.
func (d *Decimal) IsPositive() bool {
	return !d.IsNegative() && !d.IsZero()
}

// String returns the string representation of the decimal.
func (d *Decimal) String() string {
	return d.dec.String()
}

// FullString returns the full string representation of the decimal.
// It will never return scientific notation.
func (d *Decimal) FullString() string {
	bigint := d.dec.Coeff.MathBigInt()
	str := formatBigInt(bigint, int(d.scale))
	if d.dec.Negative {
		str = "-" + str
	}
	return str
}

// FormatBigInt formats a big integer according to precision and scale
func formatBigInt(n *big.Int, scale int) string {
	str := n.String() // Convert big.Int to string

	// Handle negative numbers
	isNegative := false
	if str[0] == '-' {
		isNegative = true
		str = str[1:] // Remove the negative sign for now
	}

	// Ensure the number is at least scale+1 digits long
	for len(str) <= scale {
		str = "0" + str
	}

	// Insert decimal point at the correct place
	intPart := str[:len(str)-scale]
	fracPart := str[len(str)-scale:]

	// Ensure correct scale by padding with trailing zeros if necessary
	for len(fracPart) < scale {
		fracPart += "0"
	}

	// Trim unnecessary leading zeros from the integer part
	if intPart == "" {
		intPart = "0"
	}

	// Construct the final formatted number
	result := intPart
	if scale > 0 {
		result += "." + fracPart
	}

	if isNegative {
		result = "-" + result
	}

	return result
}

// setPrecision sets the precision of the decimal.
// The precision must be between 1 and 1000.
func (d *Decimal) setPrecision(precision uint16) error {
	d.precision = precision
	return nil
}

// setScale sets the scale of the decimal.
// The scale must be between 0 and the precision.
func (d *Decimal) setScale(scale uint16) error {
	d.scale = scale
	return d.enforceScale()
}

// SetPrecisionAndScale sets the precision and scale of the decimal.
// The precision must be between 1 and 1000, and the scale must be between 0 and precision.
func (d *Decimal) SetPrecisionAndScale(precision, scale uint16) error {
	if err := CheckDecimalPrecisionAndScale(precision, scale); err != nil {
		return err
	}

	if err := d.setPrecision(precision); err != nil {
		return err
	}

	return d.setScale(scale)
}

// mathOp is a helper function for performing math operations on decimals.
// It will return a decimal with maximum precision and scale.
func mathOp(x, y *Decimal, op func(z, x, y *apd.Decimal) (apd.Condition, error)) (*Decimal, error) {
	z := apd.New(0, 0)
	_, err := op(z, &x.dec, &y.dec)
	if err != nil {
		return nil, err
	}

	dec := &Decimal{
		dec:       *z,
		scale:     uint16(-z.Exponent),
		precision: maxPrecision,
	}

	return dec, nil
}

// scaledMathOp is a helper function for performing math operations on decimals.
// It will enforce the scale of the result to the allotted scale of z.
func (z *Decimal) scaledMathOp(x, y *Decimal, op func(z, x, y *apd.Decimal) (apd.Condition, error)) (*Decimal, error) {
	_, err := op(&z.dec, &x.dec, &y.dec)
	if err != nil {
		return nil, err
	}

	if err := z.enforceScale(); err != nil {
		return nil, err
	}

	return z, nil
}

// Add adds two decimals together.
// It stores the result in z, and returns it.
// It will use the precision and scale of z.
func (z *Decimal) Add(x, y *Decimal) (*Decimal, error) {
	return z.scaledMathOp(x, y, z.context().Add)
}

// Sub subtracts y from x.
// It stores the result in z, and returns it.
// It will use the precision and scale of z.
func (z *Decimal) Sub(x, y *Decimal) (*Decimal, error) {
	return z.scaledMathOp(x, y, z.context().Sub)
}

// Mul multiplies two decimals together.
// It stores the result in z, and returns it.
// It will use the precision and scale of z.
func (z *Decimal) Mul(x, y *Decimal) (*Decimal, error) {
	return z.scaledMathOp(x, y, z.context().Mul)
}

// Div divides x by y.
// It stores the result in z, and returns it.
// It will use the precision and scale of z.
func (z *Decimal) Div(x, y *Decimal) (*Decimal, error) {
	return z.scaledMathOp(x, y, z.context().Quo)
}

// Mod returns the remainder of x divided by y.
// It stores the result in z, and returns it.
// It will use the precision and scale of z.
func (z *Decimal) Mod(x, y *Decimal) (*Decimal, error) {
	return z.scaledMathOp(x, y, z.context().Rem)
}

// Cmp compares two decimals.
// It returns -1 if z < x, 0 if z == x, and 1 if z > x.
func (z *Decimal) Cmp(x *Decimal) (int, error) {
	d := apd.New(0, 0)
	_, err := z.context().Cmp(d, &z.dec, &x.dec)
	if err != nil {
		return 0, err
	}

	i64, err := d.Int64()
	if err != nil {
		return 0, err
	}

	return int(i64), nil
}

// Sign returns the sign of the decimal.
// It returns -1 if the decimal is negative, 0 if it is zero, and 1 if it is positive.
func (d *Decimal) Sign() int {
	return d.dec.Sign()
}

func (d Decimal) NaN() bool {
	switch d.dec.Form {
	case apd.NaN, apd.NaNSignaling:
		return true
	}
	return false
}

func (d Decimal) Inf() bool {
	return d.dec.Form == apd.Infinite
}

// Value implements the database/sql/driver.Valuer interface. It converts d to a
// string.
func (d Decimal) Value() (driver.Value, error) {
	// NOTE: we're currently (ab)using the NaN case to handle scanning of NULL
	// values. Match that here. We may want something different though.
	if d.dec.Form == apd.NaN {
		return nil, nil
	}
	return d.dec.Value()
}

var _ driver.Valuer = &Decimal{}

// Scan implements the database/sql.Scanner interface.
func (d *Decimal) Scan(src interface{}) error {
	if src == nil {
		*d = Decimal{
			dec: apd.Decimal{Form: apd.NaN},
		}
		return nil
	}

	s, ok := src.(string)
	if !ok {
		var dec apd.Decimal
		err := dec.Scan(src)
		if err != nil {
			return err
		}
		s = dec.String()
	}

	// set scale and prec from the string
	d2, err := ParseDecimal(s)
	if err != nil {
		return err
	}
	*d = *d2
	return nil
}

var _ sql.Scanner = &Decimal{}

// Abs returns the absolute value of the decimal.
func (d *Decimal) Abs() (*Decimal, error) {
	_, err := d.context().Abs(&d.dec, &d.dec)
	return d, err
}

// Neg negates the decimal.
func (d *Decimal) Neg() error {
	_, err := d.context().Neg(&d.dec, &d.dec)
	return err
}

// Round rounds the decimal to the specified scale.
func (d *Decimal) Round(scale uint16) error {
	if scale > maxPrecision {
		return fmt.Errorf("scale too large: %d", scale)
	}

	// if the scale is greater than the current scale,
	// we need to increase the precision to accommodate the scale
	if scale > d.scale {
		err := d.SetPrecisionAndScale(d.precision+(scale-d.scale), scale)
		if err != nil {
			return err
		}
	}

	_, err := d.context().Quantize(&d.dec, &d.dec, -int32(scale))
	return err
}

// Int64 returns the decimal as an int64.
// If it cannot be represented as an int64, it will return an error.
func (d *Decimal) Int64() (int64, error) {
	return d.dec.Int64()
}

// BigInt returns the underlying big int of the decimal.
// This is the unscaled value of the decimal.
func (d *Decimal) BigInt() *big.Int {
	return d.dec.Coeff.MathBigInt()
}

// Float64 returns the decimal as a float64.
func (d *Decimal) Float64() (float64, error) {
	return d.dec.Float64()
}

var _ json.Marshaler = Decimal{}
var _ json.Marshaler = (*Decimal)(nil)

// MarshalJSON implements the json.Marshaler interface.
func (d Decimal) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.dec.String() + `"`), nil // faster than json.Marshal(str)
}

var _ json.Unmarshaler = (*Decimal)(nil)

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *Decimal) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	precision, scale, err := inferPrecisionAndScale(str)
	if err != nil {
		return err
	}
	if err := d.SetPrecisionAndScale(precision, scale); err != nil {
		return err
	}
	return d.SetString(str)
}

var _ encoding.BinaryMarshaler = Decimal{}
var _ encoding.BinaryMarshaler = (*Decimal)(nil)

// MarshalBinary implements the encoding.BinaryMarshaler interface. This
// supports a variety of standard library functionality, include Gob encoding.
func (d Decimal) MarshalBinary() ([]byte, error) {
	bts, err := d.dec.MarshalText()
	if err != nil {
		return nil, err
	}

	var b [4]byte
	binary.BigEndian.PutUint16(b[:2], d.precision)
	binary.BigEndian.PutUint16(b[2:], d.scale)

	return append(b[:], bts...), nil
}

var _ encoding.BinaryUnmarshaler = (*Decimal)(nil)

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (d *Decimal) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("invalid binary data")
	}

	d.precision = binary.BigEndian.Uint16(data[:2])
	d.scale = binary.BigEndian.Uint16(data[2:4])

	return d.dec.UnmarshalText(data[4:])
}

var ErrOverflow = errors.New("overflow")

// context returns the context of the decimal.
func (d *Decimal) context() *apd.Context {
	ctx := context.WithPrecision(uint32(d.precision))

	// do we need to set the exponent here?
	return ctx
}

// enforceScale enforces scale on a decimal.
func (d *Decimal) enforceScale() error {
	_, err := d.context().Quantize(&d.dec, &d.dec, -int32(d.scale))
	return err
}

// DecimalAdd adds two decimals together.
// It will return a decimal with maximum precision and scale.
func DecimalAdd(x, y *Decimal) (*Decimal, error) {
	return mathOp(x, y, context.Add)
}

// DecimalSub subtracts y from x.
// It will return a decimal with maximum precision and scale.
func DecimalSub(x, y *Decimal) (*Decimal, error) {
	return mathOp(x, y, context.Sub)
}

// DecimalMul multiplies two decimals together.
// It will return a decimal with maximum precision and scale.
func DecimalMul(x, y *Decimal) (*Decimal, error) {
	return mathOp(x, y, context.Mul)
}

// DecimalDiv divides x by y.
// It will return a decimal with maximum precision and scale.
func DecimalDiv(x, y *Decimal) (*Decimal, error) {
	return mathOp(x, y, context.Quo)
}

// DecimalMod returns the remainder of x divided by y.
// It will return a decimal with maximum precision and scale.
func DecimalMod(x, y *Decimal) (*Decimal, error) {
	return mathOp(x, y, context.Rem)
}

// DecimalPow raises x to the power of y.
func DecimalPow(x, y *Decimal) (*Decimal, error) {
	return mathOp(x, y, context.Pow)
}

// DecimalCmp compares two decimals.
// It returns -1 if x < y, 0 if x == y, and 1 if x > y.
func DecimalCmp(x, y *Decimal) (int64, error) {
	z := apd.New(0, 0)
	_, err := context.Cmp(z, &x.dec, &y.dec)
	if err != nil {
		return 0, err
	}

	return z.Int64()
	// return x.dec.Cmp(&y.dec)
}

// CheckDecimalPrecisionAndScale checks if the precision and scale are valid.
func CheckDecimalPrecisionAndScale(precision, scale uint16) error {
	if precision < 1 {
		return fmt.Errorf("precision must be at least 1: %d", precision)
	}

	if precision > maxPrecision {
		return fmt.Errorf("precision too large: %d", precision)
	}

	if scale > precision {
		return fmt.Errorf("scale must be less than or equal to precision: %d > %d", scale, precision)
	}

	return nil
}

// DecimalArray is an array of decimals.
// It is primarily used to store arrays of decimals in Postgres.
type DecimalArray []*Decimal

// Value implements the driver.Valuer interface.
func (da DecimalArray) Value() (driver.Value, error) {
	var res []string
	for _, d := range da {
		var val string
		if d.dec.Form == apd.NaN {
			val = `NULL`
		} else {
			val = d.dec.String()
		}
		res = append(res, val)
	}

	return res, nil
}

var _ driver.Valuer = (*DecimalArray)(nil)
