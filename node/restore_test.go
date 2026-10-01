package node

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fnWithRestrictText is a function whose body holds a line that reads like a
// \restrict command. psql sends it to the server as part of the body.
const fnWithRestrictText = "CREATE FUNCTION restored.f() RETURNS text\n" +
	"LANGUAGE sql AS $fn$\n" +
	"SELECT $value$\n" +
	"\\restrict key1\n" +
	"$value$;\n" +
	"$fn$;\n"

func TestCopyForPsqlDropsOnlyTheDumpsOwnRestrictLines(t *testing.T) {
	longRow := strings.Repeat("x", 3<<20) // longer than the reader's buffer
	dump := "\\restrict wrapkey\n" +
		"\\unrestrict wrapkey\n" +
		"\\restrict wrapkey\n" +
		"CREATE TABLE t (v text);\n" +
		fnWithRestrictText +
		"COPY t (v) FROM stdin;\n" +
		"\\\\restrict wrapkey\n" + // COPY data: an escaped backslash
		longRow + "\n" +
		"\\.\n" +
		"\\unrestrict wrapkey\n" +
		"SELECT 1;" // no trailing newline

	var out bytes.Buffer
	require.NoError(t, copyForPsql(&out, strings.NewReader(dump)))

	want := "CREATE TABLE t (v text);\n" +
		fnWithRestrictText +
		"COPY t (v) FROM stdin;\n" +
		"\\\\restrict wrapkey\n" +
		longRow + "\n" +
		"\\.\n" +
		"SELECT 1;"
	require.Equal(t, want, out.String())
}

func TestCopyForPsqlPassesADumpThatDoesNotOpenWithRestrict(t *testing.T) {
	dump := "CREATE SCHEMA restored;\n" + fnWithRestrictText + "\\unrestrict key1\n"

	var out bytes.Buffer
	require.NoError(t, copyForPsql(&out, strings.NewReader(dump)))
	require.Equal(t, dump, out.String())
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
