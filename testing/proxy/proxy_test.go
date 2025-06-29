//go:build pglive

// package proxy is an example of how the testing package can be used. It tests
// three contracts that are used to form a proxy pattern. An explanation of
// proxy contracts in Solidity can be found here:
// https://www.cyfrin.io/blog/upgradeable-proxy-smart-contract-pattern
package proxy

import (
	_ "embed"
	"testing"

	kwilTesting "github.com/trufnetwork/kwil-db/testing"
)

// Test_Impl_1 tests the impl_1.kf file.
func Test_Impl_1(t *testing.T) {
	kwilTesting.RunSchemaTest(t, kwilTesting.SchemaTest{
		Name:        "impl_1",
		SeedScripts: []string{"./seed_1.sql"},
		SeedStatements: []string{
			"{users}INSERT INTO users (id, name, owner_address) VALUES (-1, 'satoshi', '0xAddress');",
		},
		TestCases: []kwilTesting.TestCase{
			{
				// should create a user - happy case
				Name:      "create user - success",
				Namespace: "users",
				Action:    "create_user",
				Args:      []any{1, "gilgamesh"},
				Caller:    "0xOtherAddress",
			},
			{
				// conflicting with the name "satoshi" in the "name" column,
				// which is unique.
				Name:      "conflicting username - failure",
				Namespace: "users",
				Action:    "create_user",
				Args:      []any{1, "satoshi"},
				ErrMsg:    "duplicate key value",
			},
			{
				// conflicting with the wallet address provided by @caller
				// in the "address" column, which is unique
				Name:      "conflicting wallet address - failure",
				Namespace: "users",
				Action:    "create_user",
				Args:      []any{1, "poseidon"},
				Caller:    "0xAddress", // same address as satoshi
				ErrMsg:    "duplicate key value",
			},
			{
				// tests get_users, expecting the users that were seeded.
				Name:      "reading a table of users - success",
				Namespace: "users",
				Action:    "get_users",
				Returns: [][]any{
					{
						"satoshi", "0xAddress",
					},
				},
			},
		},
	}, &kwilTesting.Options{
		Conn: &kwilTesting.ConnConfig{
			Host:   "127.0.0.1",
			Port:   "5432",
			User:   "kwild",
			Pass:   "kwild", // would be ignored if pg_hba.conf set with trust
			DBName: "kwil_test_db",
		},
		Logger: t,
	})
}
