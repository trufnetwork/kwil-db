package node

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/trufnetwork/kwil-db/node/snapshotter"
)

func TestCopyLimited(t *testing.T) {
	body := bytes.Repeat([]byte("x"), int(snapshotter.ChunkSize)+100)
	var dst bytes.Buffer
	n, err := copyLimited(&dst, bytes.NewReader(body), snapshotter.ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if n != snapshotter.ChunkSize || int64(dst.Len()) != snapshotter.ChunkSize {
		t.Fatalf("wrote %d bytes, want %d", dst.Len(), snapshotter.ChunkSize)
	}

	var short bytes.Buffer
	n, err = copyLimited(&short, strings.NewReader("ok"), snapshotter.ChunkSize)
	if err != nil || n != 2 || short.String() != "ok" {
		t.Fatalf("short copy: n=%d err=%v body=%q", n, err, short.String())
	}

	if _, err := copyLimited(io.Discard, strings.NewReader("x"), -1); err == nil {
		t.Fatal("expected error for negative limit")
	}
}
