package pg

import (
	"bytes"
	"testing"
)

func TestAggregateCommitIDs(t *testing.T) {
	idA := bytes.Repeat([]byte{0xAA}, 32)
	idB := bytes.Repeat([]byte{0xBB}, 32)

	t.Run("single_id_deterministic", func(t *testing.T) {
		h1 := aggregateCommitIDs([][]byte{idA})
		h2 := aggregateCommitIDs([][]byte{idA})
		if !bytes.Equal(h1, h2) {
			t.Errorf("same input produced different hashes: %x vs %x", h1, h2)
		}
		if len(h1) != 32 {
			t.Errorf("expected 32-byte hash, got %d", len(h1))
		}
	})

	t.Run("order_matters", func(t *testing.T) {
		ab := aggregateCommitIDs([][]byte{idA, idB})
		ba := aggregateCommitIDs([][]byte{idB, idA})
		if bytes.Equal(ab, ba) {
			t.Error("Aggregate([A,B]) should differ from Aggregate([B,A])")
		}
	})

	t.Run("different_inputs_different_outputs", func(t *testing.T) {
		ha := aggregateCommitIDs([][]byte{idA})
		hb := aggregateCommitIDs([][]byte{idB})
		if bytes.Equal(ha, hb) {
			t.Error("different inputs should produce different hashes")
		}
	})

	t.Run("deterministic_across_calls", func(t *testing.T) {
		h1 := aggregateCommitIDs([][]byte{idA, idB})
		h2 := aggregateCommitIDs([][]byte{idA, idB})
		if !bytes.Equal(h1, h2) {
			t.Errorf("same inputs produced different hashes across calls: %x vs %x", h1, h2)
		}
	})

	t.Run("not_equal_to_raw_id", func(t *testing.T) {
		// aggregateCommitIDs([A]) = SHA256(A), which differs from A itself.
		// This verifies the aggregation always hashes, even for a single ID.
		h := aggregateCommitIDs([][]byte{idA})
		if bytes.Equal(h, idA) {
			t.Error("aggregated single ID should not equal the raw ID")
		}
	})
}
