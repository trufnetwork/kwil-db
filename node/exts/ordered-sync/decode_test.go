package orderedsync

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestResolutionMessageUnmarshalBinary(t *testing.T) {
	in := ResolutionMessage{Topic: "t", PointInTime: 7, Data: []byte{1, 2}}
	b, err := in.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got ResolutionMessage
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if got.Topic != in.Topic || got.PointInTime != in.PointInTime || !bytes.Equal(got.Data, in.Data) {
		t.Fatalf("round trip: got %+v", got)
	}

	var msg ResolutionMessage
	if err := msg.UnmarshalBinary([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("negative topic length must return an error")
	}

	// topic length 0, no previous point, point 0, data length -1
	body := make([]byte, 4+1+8+4)
	binary.BigEndian.PutUint32(body[4+1+8:], 0xffffffff)
	if err := msg.UnmarshalBinary(body); err == nil {
		t.Fatal("negative data length must return an error")
	}
}
