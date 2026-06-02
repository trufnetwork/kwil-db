package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The MAAExec wire layout is a consensus contract: the node, kwil-js, and the
// language SDKs must all serialize it identically (a single byte of divergence
// rewrites which action runs, or under whose identity). These tests freeze that
// layout. The golden vector below uses ZERO arguments so its bytes are fully
// determined by the MAA-specific framing (version + maa_address + namespace +
// action + count); argument encoding reuses the shared EncodedValue format that
// every SDK already implements for ActionExecution and is covered by round-trip.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestMAAExec_Type(t *testing.T) {
	var p Payload = &MAAExec{}
	if p.Type() != PayloadTypeMAAExec {
		t.Fatalf("Type() = %q, want %q", p.Type(), PayloadTypeMAAExec)
	}
	if !PayloadTypeMAAExec.Valid() {
		t.Fatal("PayloadTypeMAAExec should be Valid()")
	}
	// UnmarshalPayload must be able to instantiate it (i.e. it is in
	// payloadConcreteTypes), otherwise broadcast txs can't be decoded.
	got, err := UnmarshalPayload(PayloadTypeMAAExec, mustHex(t, goldenMAAExecHex))
	if err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if _, ok := got.(*MAAExec); !ok {
		t.Fatalf("UnmarshalPayload returned %T, want *MAAExec", got)
	}
}

// goldenMAAExecHex is the frozen serialization of the zero-argument vector in
// TestMAAExec_GoldenVector. SDKs assert byte-equality against this value.
const goldenMAAExecHex = "0000" + // uint16 version = 0 (little-endian)
	"14000000" + "1111111111111111111111111111111111111111" + // WriteBytes(maa_address): len=20, then 20 bytes
	"04000000" + "6d61696e" + // WriteString("main"): len=4, then "main"
	"0e000000" + "6f625f706c6163655f6f72646572" + // WriteString("ob_place_order"): len=14, then bytes
	"0000" // uint16 numArgs = 0

func TestMAAExec_GoldenVector(t *testing.T) {
	m := MAAExec{
		MAAAddress: bytes.Repeat([]byte{0x11}, 20),
		Namespace:  "main",
		Action:     "ob_place_order",
		Arguments:  nil,
	}
	got, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	want := mustHex(t, goldenMAAExecHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("MAAExec golden vector\n got %x\nwant %x", got, want)
	}

	var m2 MAAExec
	if err := m2.UnmarshalBinary(got); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !bytes.Equal(m2.MAAAddress, m.MAAAddress) {
		t.Fatalf("MAAAddress round-trip: got %x want %x", m2.MAAAddress, m.MAAAddress)
	}
	if m2.Namespace != m.Namespace || m2.Action != m.Action {
		t.Fatalf("ns/action round-trip: got %q/%q want %q/%q", m2.Namespace, m2.Action, m.Namespace, m.Action)
	}
	if len(m2.Arguments) != 0 {
		t.Fatalf("expected 0 args, got %d", len(m2.Arguments))
	}
}

func TestMAAExec_RoundTripWithArgs(t *testing.T) {
	arg0, err := EncodeValue("0xabc")
	if err != nil {
		t.Fatalf("EncodeValue(string): %v", err)
	}
	arg1, err := EncodeValue(int64(42))
	if err != nil {
		t.Fatalf("EncodeValue(int64): %v", err)
	}
	m := MAAExec{
		MAAAddress: bytes.Repeat([]byte{0x22}, 20),
		Namespace:  "main",
		Action:     "maa_record_event",
		Arguments:  []*EncodedValue{arg0, arg1},
	}
	bts, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	var m2 MAAExec
	if err := m2.UnmarshalBinary(bts); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !bytes.Equal(m2.MAAAddress, m.MAAAddress) || m2.Namespace != m.Namespace || m2.Action != m.Action {
		t.Fatalf("scalar fields diverged after round-trip")
	}
	if len(m2.Arguments) != 2 {
		t.Fatalf("expected 2 args, got %d", len(m2.Arguments))
	}
	// Re-marshalling must be byte-stable (the strongest equality check for the
	// nested EncodedValue args without depending on their internal layout).
	bts2, err := m2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary: %v", err)
	}
	if !bytes.Equal(bts, bts2) {
		t.Fatalf("round-trip not byte-stable\n first %x\nsecond %x", bts, bts2)
	}
}

func TestMAAExec_NilAndEmptyAddress(t *testing.T) {
	// A nil MAAAddress must survive the WriteBytes(nil)=MaxUint32 sentinel and
	// come back nil (distinct from an empty, present address).
	m := MAAExec{MAAAddress: nil, Namespace: "", Action: "x"}
	bts, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var m2 MAAExec
	if err := m2.UnmarshalBinary(bts); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if m2.MAAAddress != nil {
		t.Fatalf("nil MAAAddress round-tripped to %x, want nil", m2.MAAAddress)
	}
	if m2.Namespace != "" || m2.Action != "x" {
		t.Fatalf("ns/action diverged: %q/%q", m2.Namespace, m2.Action)
	}
}

func TestMAAExec_RejectsBadVersion(t *testing.T) {
	// Flip the leading version word to a value the decoder must reject.
	bts := mustHex(t, goldenMAAExecHex)
	binary.LittleEndian.PutUint16(bts[:2], 1)
	var m MAAExec
	if err := m.UnmarshalBinary(bts); err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
}
