package precompiles

import "testing"

func TestNestedCallChecksHeight(t *testing.T) {
	const chain = "nested-call-checks-test-chain"
	t.Cleanup(func() { SetNestedCallChecksHeight(chain, 0) })

	check := func(wantHeight int64, wantSet bool) {
		t.Helper()
		height, ok := NestedCallChecksHeight(chain)
		if height != wantHeight || ok != wantSet {
			t.Fatalf("NestedCallChecksHeight(%q) = %d, %v; want %d, %v", chain, height, ok, wantHeight, wantSet)
		}
	}

	// a chain starts with no height, so the checks are off
	check(0, false)

	SetNestedCallChecksHeight(chain, 100)
	check(100, true)

	SetNestedCallChecksHeight(chain, 50)
	check(50, true)

	// other chains are not affected
	if _, ok := NestedCallChecksHeight(chain + "-other"); ok {
		t.Fatal("another chain has a height")
	}

	SetNestedCallChecksHeight(chain, 0)
	check(0, false)

	SetNestedCallChecksHeight(chain, 7)
	SetNestedCallChecksHeight(chain, -1)
	check(0, false)
}
