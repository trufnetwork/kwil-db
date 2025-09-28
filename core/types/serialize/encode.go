package serialize

import (
	"encoding"
	"errors"
	"fmt"
	"reflect"
)

// EncodingType is the type used to enumerate different codecs for binary data.
type EncodingType = uint16

const EncodingTypeCustom = 1 << 12 // 4096 codecs reserved for kwild

const (
	// it is very important that the order of the encoding types is not changed
	EncodingTypeInvalid EncodingType = iota
	EncodingTypeBinary               // type must implement BinaryMarshaler and BinaryUnmarshaler
)

// Codec contains the encoding and decoding functionality for a certain
// serialization scheme that may be used in the Encode, Decode, and Decode
// methods for payloads with the matching EncodingType.
type Codec struct {
	Type   EncodingType
	Name   string
	Encode func(any) ([]byte, error)
	Decode func([]byte, any) error
}

var (
	// BinaryCodec is the default codec for encoding and decoding binary data.
	// The type must implement BinaryMarshaler and BinaryUnmarshaler. The
	// implementations of BinaryMarshaler and BinaryUnmarshaler must not be
	// defined in terms of serialize.Encode and serialize.Decode to avoid
	// infinite recursion.
	BinaryCodec = Codec{
		Type: EncodingTypeBinary,
		Name: "Binary",
		Encode: func(val any) ([]byte, error) {
			if val == nil {
				return nil, nil
			}
			v := reflect.ValueOf(val)
			if v.IsNil() {
				return nil, nil
			}
			bm, ok := val.(encoding.BinaryMarshaler)
			if !ok {
				return nil, fmt.Errorf("not a binary marshaler: %T", val)
			}
			return bm.MarshalBinary()
		},
		Decode: func(bts []byte, val any) error {
			if val == nil {
				return errors.New("must not be a nil interface")
			}
			err := requireNonNilPointer(val)
			if err != nil {
				return err
			}
			if bts == nil { // to match the exception in Encode
				// set what v points to the zero value
				v := reflect.ValueOf(val)
				// v.CanSet() // ?
				v.Elem().Set(reflect.Zero(v.Elem().Type()))
				return nil
			}
			bu, ok := val.(encoding.BinaryUnmarshaler)
			if !ok {
				return fmt.Errorf("not a binary unmarshaler: %T", val)
			}
			return bu.UnmarshalBinary(bts)
		},
	}
)

var encodings = map[EncodingType]Codec{
	EncodingTypeBinary: BinaryCodec,
}

// RegisterCodec installs a new external codec. The codec extension
// implementation should choose a Type that does not collide with other codecs.
// The EncodingTypeCustom offset should be used as the first possible external
// codec's type to leave space for more kwild canonical codecs in the future.
//
// core cannot require main module, only reverse, so registry is here, and
// extensions/consensus.RegisterCodec is provided to ensure the same registry
// used by kwild is used when extension authors define a new codec.
func RegisterCodec(c *Codec) {
	encType := c.Type
	if encType <= EncodingTypeCustom {
		panic(fmt.Sprintf("reserved codec type %d", encType))
	}
	if c0, have := encodings[encType]; have {
		panic(fmt.Sprintf("already have codec %d (%v)", encType, c0.Name))
	}
	encodings[encType] = *c
}

// Encode encodes the given value. The value must be an
// encoding.BinaryMarshaler.
func Encode(val any) ([]byte, error) {
	return EncodeWithCodec(val, BinaryCodec)
}

// EncodeWithCodec encodes the given value into a serialized data format with
// the provided Codec.
func EncodeWithCodec(val any, enc Codec) ([]byte, error) {
	btsVal, err := enc.Encode(val)
	if err != nil {
		return nil, err
	}

	return addSerializedTypePrefix(enc.Type, btsVal), nil
}

func EncodeWithEncodingType(val any, encodingType EncodingType) ([]byte, error) {
	codec, ok := encodings[encodingType]
	if !ok {
		return nil, fmt.Errorf("unregistered encoding type: %d", encodingType)
	}
	return EncodeWithCodec(val, codec)
}

func requireNonNilPointer(v any) error {
	rVal := reflect.ValueOf(v)
	if rType := rVal.Type(); rType.Kind() != reflect.Ptr {
		return fmt.Errorf("not a pointer: %s / %T", rType.Kind(), v)
	}
	if rVal.IsNil() {
		return errors.New("cannot decode into nil pointer")
	}
	return nil
}

// Decode decodes the data into a value, which should be passed as a pointer. If
// the value is an encoding.BinaryUnmarshaler, its UnmarshalBinary method is
// used, otherwise it will attempt to decode the data using as if it were
// encoded with EncodeWithCodec (checking for a serialized type prefix).
func Decode(bts []byte, v any) error {
	if err := requireNonNilPointer(v); err != nil {
		return err
	}

	encType, val, err := removeSerializedTypePrefix(bts)
	if err != nil {
		return err
	}

	codec, have := encodings[encType]
	if !have {
		return fmt.Errorf("unknown encoding type %v", encType)
	}

	return codec.Decode(val, v)
}

// DecodeGeneric decodes the given serialized data into the given value. See
// also Decode for use with an existing instance. This is generally no more
// useful than Decode; it is syntactic sugar that requires no existing instance
// of the type, and returns a pointer to the declared type.
func DecodeGeneric[T any](bts []byte) (*T, error) {
	var val T
	if err := Decode(bts, &val); err != nil {
		return nil, err
	}
	return &val, nil
}

// TODO: probably remove all the below slice stuff if we don't use it

func EncodeSlice[T any](kvs []T) ([]byte, error) {
	marshaller := make([]*serialBinaryMarshaller[T], len(kvs))
	for i, kv := range kvs {
		marshaller[i] = &serialBinaryMarshaller[T]{kv}
	}
	return serializeSlice[*serialBinaryMarshaller[T]](marshaller)
}

func DecodeSlice[T any](bts []byte) ([]*T, error) {
	marshaller, err := deserializeSlice[*serialBinaryMarshaller[T]](bts, func() *serialBinaryMarshaller[T] {
		return &serialBinaryMarshaller[T]{}
	})
	if err != nil {
		return nil, err
	}

	result := make([]*T, len(marshaller))
	for i, m := range marshaller {
		result[i] = &m.val
	}

	return result, nil
}

// serialBinaryMarshaller is a helper struct that implements the BinaryMarshaler and BinaryUnmarshaler interfaces
type serialBinaryMarshaller[T any] struct {
	val T
}

func (m *serialBinaryMarshaller[T]) MarshalBinary() ([]byte, error) {
	return Encode(m.val)
}

func (m *serialBinaryMarshaller[T]) UnmarshalBinary(bts []byte) error {
	return Decode(bts, &m.val)
}
