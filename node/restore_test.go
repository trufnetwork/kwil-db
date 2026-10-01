package node

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyForPsqlDropsOnlyRestrictLines(t *testing.T) {
	longRow := strings.Repeat("x", 3<<20) // longer than the reader's buffer
	dump := "\\restrict key1\n" +
		"\\unrestrict key1\n" +
		"\\restrict key1\n" +
		"CREATE TABLE t (v text);\n" +
		"COPY t (v) FROM stdin;\n" +
		"\\\\restrict not a command\n" + // COPY data: an escaped backslash
		longRow + "\n" +
		"\\.\n" +
		"\\unrestrict key1\n" +
		"SELECT 1;" // no trailing newline

	var out bytes.Buffer
	require.NoError(t, copyForPsql(&out, strings.NewReader(dump)))

	want := "CREATE TABLE t (v text);\n" +
		"COPY t (v) FROM stdin;\n" +
		"\\\\restrict not a command\n" +
		longRow + "\n" +
		"\\.\n" +
		"SELECT 1;"
	require.Equal(t, want, out.String())
}

func TestSnapshotHashCoversTheLinesPsqlDoesNotGet(t *testing.T) {
	dump := "\\restrict key1\nSELECT 1;\n\\unrestrict key1\n"
	sum := sha256.Sum256([]byte(dump))

	var out bytes.Buffer
	require.NoError(t, decompressAndValidateSnapshotHash(&out, strings.NewReader(dump), sum[:]))
	require.Equal(t, "SELECT 1;\n", out.String())

	filtered := sha256.Sum256([]byte("SELECT 1;\n"))
	err := decompressAndValidateSnapshotHash(&bytes.Buffer{}, strings.NewReader(dump), filtered[:])
	require.ErrorContains(t, err, "invalid snapshot hash")
}

func TestHeadBufferKeepsTheStart(t *testing.T) {
	h := &headBuffer{max: 5}
	n, err := h.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	n, err = h.Write([]byte("defgh"))
	require.NoError(t, err)
	require.Equal(t, 5, n) // reports everything written, so the writer never fails
	require.Equal(t, "abcde", h.String())
}
