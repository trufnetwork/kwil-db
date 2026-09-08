package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	cliclient "github.com/trufnetwork/kwil-db/cmd/kwil-cli/client"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/config"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	chainrpc "github.com/trufnetwork/kwil-db/core/rpc/client/chain"
	"github.com/trufnetwork/kwil-db/core/types"
	chaintypes "github.com/trufnetwork/kwil-db/core/types/chain"
)

func blockMixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "block-mix <height>",
		Short: "Summarize the transaction and action mix of a committed block.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			height, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || height <= 0 {
				return display.PrintErr(cmd, fmt.Errorf("block height must be a positive integer"))
			}

			return cliclient.DialClient(cmd.Context(), cmd, cliclient.WithoutPrivateKey, func(
				ctx context.Context,
				client clientType.Client,
				_ *config.KwilCliConfig,
			) error {
				chainProvider, ok := client.(interface {
					ChainClient() chainrpc.Client
				})
				if !ok {
					return display.PrintErr(cmd, fmt.Errorf("block-mix requires a direct Kwil provider"))
				}

				block, _, err := chainProvider.ChainClient().BlockByHeight(ctx, height)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("get block %d: %w", height, err))
				}
				result, err := chainProvider.ChainClient().BlockResultByHeight(ctx, height)
				if err != nil {
					return display.PrintErr(cmd, fmt.Errorf("get block %d result: %w", height, err))
				}

				mix, err := buildBlockMix(block, result)
				if err != nil {
					return display.PrintErr(cmd, err)
				}
				return display.PrintCmd(cmd, &blockMixResponse{cmd: cmd, mix: mix})
			})
		},
	}
	display.BindTableFlags(cmd)
	return cmd
}

type blockMix struct {
	Height       int64                 `json:"height"`
	Hash         string                `json:"hash"`
	Transactions int                   `json:"transactions"`
	Actions      []blockActionMix      `json:"actions"`
	Txs          []blockTransactionMix `json:"txs"`
}

type blockActionMix struct {
	PayloadType  string `json:"payload_type"`
	Namespace    string `json:"namespace,omitempty"`
	Action       string `json:"action,omitempty"`
	Transactions int    `json:"transactions"`
	Calls        int    `json:"calls"`
	Failures     int    `json:"failures"`
	TotalSpend   int64  `json:"total_spend"`
}

type blockTransactionMix struct {
	Index       int    `json:"index"`
	Hash        string `json:"hash"`
	PayloadType string `json:"payload_type"`
	Namespace   string `json:"namespace,omitempty"`
	Action      string `json:"action,omitempty"`
	Calls       int    `json:"calls"`
	Code        uint32 `json:"code"`
	Spend       int64  `json:"spend"`
	DecodeError string `json:"decode_error,omitempty"`
}

type blockMixKey struct {
	payloadType string
	namespace   string
	action      string
}

func buildBlockMix(block *chaintypes.Block, result *chaintypes.BlockResult) (*blockMix, error) {
	if block == nil || block.Header == nil {
		return nil, fmt.Errorf("block is missing its header")
	}
	if result == nil {
		return nil, fmt.Errorf("block result is missing")
	}
	if len(block.Txns) != len(result.TxResults) {
		return nil, fmt.Errorf(
			"block %d has %d transactions but %d results",
			block.Header.Height,
			len(block.Txns),
			len(result.TxResults),
		)
	}

	mix := &blockMix{
		Height:       block.Header.Height,
		Hash:         result.Hash.String(),
		Transactions: len(block.Txns),
		Txs:          make([]blockTransactionMix, 0, len(block.Txns)),
	}
	actions := make(map[blockMixKey]*blockActionMix)
	for i, tx := range block.Txns {
		if tx == nil || tx.Body == nil {
			return nil, fmt.Errorf("block %d transaction %d is missing its body", block.Header.Height, i)
		}
		txResult := result.TxResults[i]
		namespace, action, calls, decodeErr := transactionAction(tx)
		key := blockMixKey{
			payloadType: tx.Body.PayloadType.String(),
			namespace:   namespace,
			action:      action,
		}
		actionMix := actions[key]
		if actionMix == nil {
			actionMix = &blockActionMix{
				PayloadType: key.payloadType,
				Namespace:   namespace,
				Action:      action,
			}
			actions[key] = actionMix
		}
		actionMix.Transactions++
		actionMix.Calls += calls
		actionMix.TotalSpend += txResult.Gas
		if txResult.Code != uint32(types.CodeOk) {
			actionMix.Failures++
		}
		mix.Txs = append(mix.Txs, blockTransactionMix{
			Index:       i,
			Hash:        tx.Hash().String(),
			PayloadType: key.payloadType,
			Namespace:   namespace,
			Action:      action,
			Calls:       calls,
			Code:        txResult.Code,
			Spend:       txResult.Gas,
			DecodeError: decodeErr,
		})
	}

	mix.Actions = make([]blockActionMix, 0, len(actions))
	for _, action := range actions {
		mix.Actions = append(mix.Actions, *action)
	}
	sort.Slice(mix.Actions, func(i, j int) bool {
		left, right := mix.Actions[i], mix.Actions[j]
		if left.Transactions != right.Transactions {
			return left.Transactions > right.Transactions
		}
		if left.PayloadType != right.PayloadType {
			return left.PayloadType < right.PayloadType
		}
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		return left.Action < right.Action
	})
	return mix, nil
}

func transactionAction(tx *types.Transaction) (namespace, action string, calls int, decodeErr string) {
	calls = 1
	if tx.Body.PayloadType != types.PayloadTypeExecute {
		return "", "", calls, ""
	}
	payload, err := types.UnmarshalPayload(tx.Body.PayloadType, tx.Body.Payload)
	if err != nil {
		return "", "", calls, err.Error()
	}
	execution, ok := payload.(*types.ActionExecution)
	if !ok {
		return "", "", calls, fmt.Sprintf("unexpected execute payload %T", payload)
	}
	if len(execution.Arguments) > 0 {
		calls = len(execution.Arguments)
	}
	return execution.Namespace, execution.Action, calls, ""
}

type blockMixResponse struct {
	cmd *cobra.Command
	mix *blockMix
}

func (r *blockMixResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.mix)
}

func (r *blockMixResponse) MarshalText() ([]byte, error) {
	rows := make([][]string, 0, len(r.mix.Actions))
	for _, action := range r.mix.Actions {
		rows = append(rows, []string{
			action.PayloadType,
			action.Namespace,
			action.Action,
			strconv.Itoa(action.Transactions),
			strconv.Itoa(action.Calls),
			strconv.Itoa(action.Failures),
			strconv.FormatInt(action.TotalSpend, 10),
		})
	}
	table, err := display.FormatTable(
		r.cmd,
		[]string{"Payload type", "Namespace", "Action", "Transactions", "Calls", "Failures", "Total spend"},
		rows,
	)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf(
		"Height: %d\nHash: %s\nTransactions: %d\n\n",
		r.mix.Height,
		r.mix.Hash,
		r.mix.Transactions,
	)
	return append([]byte(header), table...), nil
}
