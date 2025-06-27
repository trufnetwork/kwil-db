package main

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/trufnetwork/kwil-db/core/types/serialize"
	"github.com/trufnetwork/kwil-db/extensions/encoding/borsh"
	"github.com/trufnetwork/kwil-db/extensions/encoding/rlp"
)

type example1 struct {
	Field1 string
	Field2 uint32
	Field3 bool
	Field4 []byte
	Field5 exampleInner
	Field6 uint64
	Field7 *string
}

type exampleInner struct {
	Field1 string
	Field2 uint32
	Field3 bool
	Field4 []byte
}

type example2 struct { // this is not RLP-encodable for several reasons
	Field1 string
	Field2 int // not RLP-encodable
	Field3 bool
	Field4 []byte
	Field5 exampleInner
	Field6 map[string]string // not RLP-encodable
	Field7 int64             // not RLP-encodable
	Field8 *string
}

func main() {
	// example struct
	fp := "hello from pointer"
	e1 := example1{
		Field1: "hi",
		Field2: 1,
		Field3: true,
		Field4: []byte("hello"),
		Field5: exampleInner{
			Field1: "hi",
			Field2: 1,
			Field3: true,
			Field4: []byte("hello from inside"),
		},
		Field7: &fp,
	}

	// RLP
	bts, err := serialize.EncodeWithEncodingType(e1, rlp.EncodingTypeRLP)
	if err != nil {
		panic(err)
	}

	bts2, err := serialize.EncodeWithCodec(e1, *rlp.Codec)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(bts, bts2) {
		panic("not equal")
	}

	var eRLP example1
	err = serialize.Decode(bts, &eRLP)
	if err != nil {
		panic(err)
	}

	if !reflect.DeepEqual(e1, eRLP) {
		panic("not equal")
	}

	// Borsh
	e2 := example2{
		Field1: "hi",
		Field2: 1,
		Field3: true,
		Field4: []byte("hello"),
		Field5: exampleInner{
			Field1: "hi",
			Field2: 1,
			Field3: true,
			Field4: []byte("hello from inside"),
		},
		Field6: map[string]string{
			"hi map key": "hello map value",
		},
		Field7: 1,
		Field8: &fp,
	}

	bts, err = serialize.EncodeWithEncodingType(e2, borsh.EncodingTypeBorsh)
	if err != nil {
		panic(err)
	}
	bts2, err = serialize.EncodeWithCodec(e2, *borsh.Codec)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(bts, bts2) {
		panic("not equal")
	}

	var eBorsch example2
	err = serialize.Decode(bts, &eBorsch)
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(e2, eBorsch) {
		panic("not equal")
	}

	fmt.Println(e2.Field1, "from borsh")
}
