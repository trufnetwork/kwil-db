package account

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
)

func balanceCmd() *cobra.Command {
	var pending bool
	var keyTypeStr string
	cmd := &cobra.Command{
		Use:   "balance accountID keyType",
		Short: "Gets an account's balance and nonce",
		Long:  `Gets an account's balance and nonce.`,
		Args:  cobra.MaximumNArgs(1), // no args means own account
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var acctID *types.AccountID
			var clientFlags uint8

			if len(args) > 0 {
				clientFlags = client.WithoutPrivateKey

				// Recognize 0x prefix to permit ethereum address format rather
				// than compact ID hex bytes.
				idStr := strings.TrimPrefix(args[0], "0x")
				id, err := hex.DecodeString(idStr)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("failed to decode account ID: %w", err))
				}

				acctID = &types.AccountID{
					Identifier: id,
					KeyType:    crypto.KeyType(keyTypeStr),
				}
			} // else use our account from the signer

			return client.DialClient(cmd.Context(), cmd, clientFlags, func(ctx context.Context, cl clientType.Client, conf *config.KwilCliConfig) error {
				if len(args) == 0 {
					if cl.Signer() == nil {
						return display.PrintErr(cmd, errors.New("no account ID provided and no signer set"))
					}

					acctID, err = types.GetSignerAccount(cl.Signer())
					if err != nil {
						return display.PrintErr(cmd, fmt.Errorf("failed to get signer account: %w", err))
					}

				}
				status := types.AccountStatusLatest
				if pending {
					status = types.AccountStatusPending
				}
				acct, err := cl.GetAccount(ctx, acctID, status)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("get account failed: %w", err))
				}
				// NOTE: empty acct.Identifier means it doesn't even have a record
				// on the network. We now convey that to the caller.

				resp := &respAccount{
					Balance: acct.Balance.String(),
					Nonce:   acct.Nonce,
				}

				if acct.ID != nil { // only add identifier for the existing accounts
					resp.Identifier = acct.ID.Identifier
					resp.KeyType = acct.ID.KeyType.String()
				}

				return display.PrintCmd(cmd, resp)
			})

		},
	}

	cmd.Flags().BoolVar(&pending, "pending", false, "reflect pending updates from mempool (default is confirmed only)")
	cmd.Flags().StringVarP(&keyTypeStr, "keytype", "t", crypto.KeyTypeSecp256k1.String(), "key type of account ID (default secp256k1 for Ethereum)")

	return cmd
}
