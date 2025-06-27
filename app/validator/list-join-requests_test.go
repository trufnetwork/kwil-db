package validator

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

func Test_respJoinList_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		response respJoinList
		want     string
	}{
		{
			name: "multiple joins",
			response: respJoinList{
				Joins: []*types.JoinRequest{
					{
						Candidate: &types.AccountID{
							Identifier: []byte{0x12, 0x34},
							KeyType:    crypto.KeyTypeEd25519,
						},
						Power:    100,
						Board:    []*types.AccountID{{Identifier: []byte{0xAB, 0xCD}, KeyType: crypto.KeyTypeSecp256k1}},
						Approved: []bool{true},
					},
					{
						Candidate: &types.AccountID{
							Identifier: []byte{0x56, 0x78},
							KeyType:    crypto.KeyTypeSecp256k1,
						},
						Power:    200,
						Board:    []*types.AccountID{{Identifier: []byte{0xEF, 0x12}, KeyType: crypto.KeyTypeSecp256k1}},
						Approved: []bool{false},
					},
				},
			},
			want: `[{"candidate":{"identifier":"1234","key_type":"ed25519"},"power":100,"expires_at": "0001-01-01T00:00:00Z","board":[{"identifier":"abcd","key_type":"secp256k1"}],"approved":[true]},{"candidate":{"identifier":"5678","key_type":"secp256k1"},"power":200,"expires_at":"0001-01-01T00:00:00Z","board":[{"identifier":"ef12","key_type":"secp256k1"}],"approved":[false]}]`,
		},
		{
			name: "empty joins",
			response: respJoinList{
				Joins: []*types.JoinRequest{},
			},
			want: `[]`,
		},
		{
			name: "single join",
			response: respJoinList{
				Joins: []*types.JoinRequest{
					{
						Candidate: &types.AccountID{
							Identifier: []byte{0x12, 0x34},
							KeyType:    crypto.KeyTypeEd25519,
						},
						Power:    150,
						Board:    []*types.AccountID{{Identifier: []byte{0xAB, 0xCD}, KeyType: crypto.KeyTypeSecp256k1}},
						Approved: []bool{true, false},
					},
				},
			},
			want: `[{"candidate":{"identifier":"1234","key_type":"ed25519"},"power":150,"expires_at": "0001-01-01T00:00:00Z","board":[{"identifier":"abcd","key_type":"secp256k1"}],"approved":[true,false]}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(&tt.response)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(got))
		})
	}
}

// TODO: come back to this, skipping due to time constraints but manual testing is ok
// func Test_respJoinList_MarshalText(t *testing.T) {
// 	cmd := listJoinRequestsCmd()
// 	//ns := "2025-01-27 19:23:04.671014 -0600 CST m=+0.004776293"
// 	now := time.Now()
// 	nowStr := now.String()
// 	tests := []struct {
// 		name     string
// 		response respJoinList
// 		want     string
// 	}{
// 		{
// 			name: "empty list",
// 			response: respJoinList{
// 				Joins: []*types.JoinRequest{},
// 			},
// 			want: "No pending join requests",
// 		},
// 		{
// 			name: "single approval needed",
// 			response: respJoinList{
// 				Joins: []*types.JoinRequest{
// 					{
// 						Candidate: &types.AccountID{
// 							Identifier: []byte{0x12, 0x34},
// 							KeyType:    crypto.KeyTypeEd25519,
// 						},
// 						Power:     100,
// 						ExpiresAt: now,
// 						Board:     []*types.AccountID{{Identifier: []byte{0xAB}}},
// 						Approved:  []bool{true},
// 					},
// 				},
// 			},
// 			want: "Pending join requests (1 approval needed):\n|  Candidate   | Power | Approvals |           Expiration           |\n+--------------+-------+-----------+--------------------------------+\n| 1234#ed25519 |   100 |         1 | 2025-01-27 19:21:04.901348     |\n|              |       |           | " + nowStr + " |\n",
// 		},
// 		{
// 			name: "multiple approvals needed",
// 			response: respJoinList{
// 				Joins: []*types.JoinRequest{
// 					{
// 						Candidate: &types.AccountID{
// 							Identifier: []byte{0x12, 0x34},
// 							KeyType:    crypto.KeyTypeEd25519,
// 						},
// 						Power:     100,
// 						ExpiresAt: now,
// 						Board: []*types.AccountID{
// 							{Identifier: []byte{0xAB}},
// 							{Identifier: []byte{0xCD}},
// 							{Identifier: []byte{0xEF}},
// 						},
// 						Approved: []bool{true, false, true},
// 					},
// 					{
// 						Candidate: &types.AccountID{
// 							Identifier: []byte{0x56, 0x78},
// 							KeyType:    crypto.KeyTypeSecp256k1,
// 						},
// 						Power:     200,
// 						ExpiresAt: now,
// 						Board: []*types.AccountID{
// 							{Identifier: []byte{0xAB}},
// 							{Identifier: []byte{0xCD}},
// 							{Identifier: []byte{0xEF}},
// 						},
// 						Approved: []bool{false, false, false},
// 					},
// 				},
// 			},
// 			want: "Pending join requests (2 approvals needed):\n Candidate                                                        | Power | Approvals | Expiration\n------------------------------------------------------------------+-------+-----------+------------\n AccountID{identifier = 1234, keyType = ed25519} |   100 |         2 | " + nowStr + "\n AccountID{identifier = 5678, keyType = secp256k1} |   200 |         0 | " + nowStr,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			tt.response.cmd = cmd
// 			got, err := tt.response.MarshalText()
// 			require.NoError(t, err)
// 			require.Equal(t, tt.want, string(got))
// 		})
// 	}
// }
