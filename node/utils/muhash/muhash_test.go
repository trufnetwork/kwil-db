package muhash_test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/node/utils/muhash"
)

func TestMuHash_Add(t *testing.T) {
	// mustHash := func(hexbts string) []byte {
	// 	bts, err := hex.DecodeString(hexbts)
	// 	if err != nil {
	// 		t.Fatal(err)
	// 	}
	// 	return bts
	// }
	mustBig := func(base10Str string) *big.Int {
		big, ok := new(big.Int).SetString(base10Str, 10)
		if !ok {
			t.Fatal("failed to parse big int")
		}
		return big
	}
	tests := []struct {
		name     string
		inputs   [][]byte
		expected *big.Int
	}{
		{
			name:     "no inputs",
			inputs:   [][]byte{},
			expected: mustBig("1"),
		},
		{
			name:     "one empty input",
			inputs:   [][]byte{{}},
			expected: mustBig("102987336249554097029535212322581322789799900648198034993379397001115665086549"),
		},
		{
			name:     "single input",
			inputs:   [][]byte{[]byte("test")},
			expected: mustBig("72155939486846849509759369733266486982821795810448245423168957390607644363272"),
		},
		{
			name:     "multiple inputs",
			inputs:   [][]byte{[]byte("test1"), []byte("test2")},
			expected: mustBig("112299860580340124781952370189281091018952953959145337159073612452906860955362"),
		},
		{
			name:     "large input",
			inputs:   [][]byte{make([]byte, 1000)},
			expected: mustBig("38042416310635598836882041127054290943028379406684639512831659644105113438803"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := muhash.New()
			for _, input := range tt.inputs {
				mh.Add(input)
			}
			result := mh.Digest()
			resultHash := mh.DigestHash()

			assert.Equal(t, tt.expected, result)
			expectedHash := sha256.Sum256(tt.expected.Bytes())
			assert.Equal(t, expectedHash, resultHash)

			// NOTE: 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a is the "zero hash"
			// t.Logf("result hash %x", resultHash)
		})
	}
}

func TestMuHash_DigestConsistency(t *testing.T) {
	mh := muhash.New()
	data := []byte("test data")

	mh.Add(data)
	digest1 := mh.Digest()

	// Verify that multiple calls to Digest() return equal but distinct objects
	digest2 := mh.Digest()
	require.Equal(t, digest1, digest2)
	require.NotSame(t, digest1, digest2)

	// Verify that modifying the returned digest doesn't affect the internal state
	digest1.Add(digest1, big.NewInt(1))
	digest3 := mh.Digest()
	require.Equal(t, digest2, digest3)
	require.NotEqual(t, digest1, digest3)
}

func TestMuHash_AddMultiple(t *testing.T) {
	mh1 := muhash.New()
	var mh2 muhash.MuHash // functional zero value

	// Add same data in different order
	data1 := []byte("first")
	data2 := []byte("second")

	mh1.Add(data1)
	mh1.Add(data2)
	mh1.Add(data1)

	mh2.Add(data2)
	mh2.Add(data1)
	mh2.Add(data1)

	// Results should be equal regardless of order
	assert.Equal(t, mh1.Digest(), mh2.Digest())

	// DigestHash
	digest1 := mh1.DigestHash()
	digest2 := mh2.DigestHash()
	assert.Equal(t, digest1, digest2)

	// non-equal without a duplicate
	mh3 := muhash.New()
	mh3.Add(data1)
	mh3.Add(data2)

	digest3 := mh3.DigestHash()
	assert.NotEqual(t, digest1, digest3)
}

func TestMuHash_Reset(t *testing.T) {
	mh := muhash.New()
	mh.Add([]byte("data1"))
	mh.Add([]byte("data2"))
	mh.Add([]byte("data3"))
	mh.Reset()

	expected := muhash.New().Digest()
	actual := mh.Digest()
	assert.Equal(t, expected, actual)

	fresh := muhash.New()
	fresh.Add([]byte("data4"))
	expected = fresh.Digest()
	mh.Add([]byte("data4"))
	actual = mh.Digest()
	assert.Equal(t, expected, actual)
}
