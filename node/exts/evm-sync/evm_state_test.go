package evmsync

import (
	"bytes"
	"testing"
)

func Test_PolledEventRoundTrip(t *testing.T) {
	original := polledEvent{
		UniqueName:     "TestPoll",
		Data:           []byte("Hello, Blockchain"),
		ResolutionName: "TestResolution",
	}

	// Marshal
	encoded, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// Unmarshal
	var decoded polledEvent
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	// Check fields match
	if original.UniqueName != decoded.UniqueName {
		t.Errorf("UniqueName mismatch: got %q, want %q",
			decoded.UniqueName, original.UniqueName)
	}
	if !bytes.Equal(original.Data, decoded.Data) {
		t.Errorf("Data mismatch: got %v, want %v",
			decoded.Data, original.Data)
	}

	var hostile polledEvent
	if err := hostile.UnmarshalBinary([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("oversized length must return an error")
	}
}
