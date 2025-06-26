package types_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufnetwork/kwil-db/core/types"
)

func Test_UUID(t *testing.T) {
	seed := []byte("test")

	uuid := types.NewUUIDV5(seed)

	if uuid.String() != "24aa70cf-0e18-57c9-b449-da8c9db37821" {
		t.Errorf("expected uuid to be 24aa70cf-0e18-57c9-b449-da8c9db37821, got %s", uuid.String())
	}
}

func Test_UUIDJSONRoundTrip(t *testing.T) {
	seed := []byte("test")

	uuid := types.NewUUIDV5(seed)

	b, err := json.Marshal(uuid)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, `"24aa70cf-0e18-57c9-b449-da8c9db37821"`, string(b))

	var uuidBack types.UUID
	err = json.Unmarshal(b, &uuidBack)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, *uuid, uuidBack)
}
