package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/trufnetwork/kwil-db/core/utils"
)

// KeyType is the type of key, which may be public or private depending on context.
type KeyType string

// The native key types are secp256k1 and ed25519.
const (
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeEd25519   KeyType = "ed25519"
)

const (
	keyIDSecp256k1 = iota
	keyIDEd25519
)

func (kt KeyType) String() string {
	return string(kt)
}

func (kt KeyType) Bytes() []byte {
	bts, _ := kt.MarshalBinary()
	return bts
}

func (kt KeyType) WriteTo(w io.Writer) (int64, error) {
	cw := utils.NewCountingWriter(w)
	// We can encode as a string, but we'll use a uint16 to save space.
	// binary.Write(cw, binary.LittleEndian, uint16(len(kt)))
	// _, err := cw.Write([]byte(kt))
	// if err != nil {
	// 	return cw.Written(), err
	// }

	// NOTE: if KeyType changes type, we change this method, not consumer code
	//
	kd, ok := KeyTypeDefinition(kt)
	if !ok {
		return 0, fmt.Errorf("invalid key type: %s", kt)
	}
	err := binary.Write(cw, binary.LittleEndian, kd.EncodeFlag())
	return cw.Written(), err
}

func (kt KeyType) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}
	kt.WriteTo(buf)
	return buf.Bytes(), nil
}

func (kt *KeyType) ReadFrom(r io.Reader) (int64, error) {
	cr := utils.NewCountingReader(r)
	// We can encode as a string, but we'll use a uint16 to save space.
	/*var typeLen uint16
	err := binary.Read(cr, binary.LittleEndian, &typeLen)
	if err != nil {
		return cr.ReadCount(), err
	}
	var keyTypeStr strings.Builder
	_, err = io.CopyN(&keyTypeStr, cr, int64(typeLen))
	if err != nil {
		return cr.ReadCount(), fmt.Errorf("failed to read signature data: %w", err)
	}
	keyType, err := ParseKeyType(keyTypeStr.String())
	if err != nil {
		return cr.ReadCount(), err
	}
	*kt = keyType*/

	// NOTE: if KeyType changes type, we change this method, not consumer code
	//
	var ktInt uint32
	err := binary.Read(cr, binary.LittleEndian, &ktInt)
	if err != nil {
		return cr.ReadCount(), err
	}

	keyType, ok := encodingIDs[ktInt]
	if !ok {
		return cr.ReadCount(), fmt.Errorf("invalid key type encoding flag %d", ktInt)
	}

	*kt = keyType

	return cr.ReadCount(), nil
}

func (kt *KeyType) UnmarshalBinary(data []byte) error {
	_, err := kt.ReadFrom(bytes.NewReader(data))
	return err
}
