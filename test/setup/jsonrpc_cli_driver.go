package setup

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/cmds"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/cmds/database"
	clientImpl "github.com/trufnetwork/kwil-db/core/client"
	client "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
)

type jsonRPCCLIDriver struct {
	provider     string
	privateKey   crypto.PrivateKey // CLI driver currently only supports secp256k1
	chainID      string
	usingGateway bool
	logFunc      logFunc
	testCtx      *testingContext
}

func newKwilCI(ctx context.Context, endpoint string, l logFunc, testCtx *testingContext, opts *ClientOptions) (JSONRPCClient, error) {
	if opts == nil {
		opts = &ClientOptions{}
	}
	opts.ensureDefaults()

	// CLI driver currently only supports secp256k1 keys
	secpKey, ok := opts.PrivateKey.(*crypto.Secp256k1PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CLI driver only supports secp256k1 private keys, got %T", opts.PrivateKey)
	}

	return &jsonRPCCLIDriver{
		provider:     endpoint,
		privateKey:   secpKey,
		chainID:      opts.ChainID,
		usingGateway: opts.UsingKGW,
		logFunc:      l,
		testCtx:      testCtx,
	}, nil
}

// cmd executes a kwil-cli command and unmarshals the result into res.
// It logically should be a method on jsonRPCCLIDriver, but it can't because of the generic type T.
func cmd[T any](j *jsonRPCCLIDriver, ctx context.Context, res T, args ...string) error {
	flags := []string{"--provider", j.provider, "--private-key", hex.EncodeToString(j.privateKey.Bytes()), "--output", "json", "--assume-yes", "--silence", "--chain-id", j.chainID}

	buf := new(bytes.Buffer)

	cmd := cmds.NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetArgs(append(flags, args...))
	err := cmd.ExecuteContext(ctx)
	if err != nil {
		return err
	}

	if buf.Len() == 0 {
		return fmt.Errorf("no output from command")
	}

	j.logFunc("Running Command /app/kwil-cli " + strings.Join(args, " ") + " with output " + buf.String())

	d := display.MessageReader[T]{
		Result: res,
	}

	bts := buf.Bytes()
	err = json.Unmarshal(bts, &d)
	if err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	if d.Error != "" {
		return fmt.Errorf("error in command: %s", d.Error)
	}

	return nil
}

func (j *jsonRPCCLIDriver) PrivateKey() crypto.PrivateKey {
	return j.privateKey
}

func (j *jsonRPCCLIDriver) PublicKey() crypto.PublicKey {
	return j.privateKey.Public()
}

func (j *jsonRPCCLIDriver) Signer() auth.Signer {
	return &auth.Secp256k1Signer{Secp256k1PrivateKey: *j.privateKey.(*crypto.Secp256k1PrivateKey)}
}

func (j *jsonRPCCLIDriver) Identifier() string {
	ident, err := auth.Secp25k1Authenticator{}.Identifier(j.privateKey.Public().Bytes())
	if err != nil {
		panic(err)
	}

	return ident
}

func (j *jsonRPCCLIDriver) Call(ctx context.Context, namespace string, action string, inputs []any) (*types.CallResult, error) {
	args := []string{"call-action", "--logs", "--rpc-auth"} // always assume private RPC mode
	if j.usingGateway {
		args = append(args, "--gateway-auth")
	}

	if namespace != "" {
		args = append(args, "--namespace", namespace)
	}
	args = append(args, action)

	params, err := formatActionParams(inputs)
	if err != nil {
		return nil, err
	}

	args = append(args, params...)

	r := &types.CallResult{}
	err = cmd(j, ctx, r, args...)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// formatActionParams formats positional args for the kwil-cli call-action and exec-action commands
func formatActionParams(inputs []any) ([]string, error) {
	var res []string
	for _, in := range inputs {
		if in == nil {
			// special case: if a positional arg is "null", cli does not need a type
			res = append(res, cmds.NullLiteral)
			continue
		}

		// sort've a hack where I am relying on the EncodeValue type to detect the data
		// type instead of writing a switch myself
		encoded, err := types.EncodeValue(in)
		if err != nil {
			return nil, err
		}

		// res = append(res, "--param")
		res = append(res, encoded.Type.String()+":"+stringifyCLIArg(in))
	}

	return res, nil
}

func (j *jsonRPCCLIDriver) ChainID() string {
	i, err := j.ChainInfo(context.Background())
	if err != nil {
		panic(err)
	}

	return i.ChainID
}

func (j *jsonRPCCLIDriver) ChainInfo(ctx context.Context) (*types.ChainInfo, error) {
	r := &types.ChainInfo{}
	err := cmd(j, ctx, r, "utils", "chain-info")
	if err != nil {
		return nil, err
	}

	return r, nil
}

func randomName() string {
	return fmt.Sprintf("file-%d", time.Now().UnixNano())
}

// WriteCSV writes a 2D array of strings to a CSV file with the given column names.
func writeCSV(filePath string, columnNames []string, data [][]string) error {
	// Open the file for writing
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Create a CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write the column names as the header row
	if err := writer.Write(columnNames); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write the data rows
	if err := writer.WriteAll(data); err != nil {
		return fmt.Errorf("failed to write data rows: %w", err)
	}

	return nil
}

func (j *jsonRPCCLIDriver) Execute(ctx context.Context, namespace string, action string, tuples [][]any, opts ...client.TxOpt) (types.Hash, error) {
	if len(tuples) > 1 {
		// if more than 1 tuple, we will use batch execution with a csv
		fp := filepath.Join(j.testCtx.tmpdir, randomName())

		var columnNames []string
		for i := range tuples[0] {
			columnNames = append(columnNames, fmt.Sprintf("param%d", i))
		}

		var data [][]string
		for _, tuple := range tuples {
			var row []string
			for _, val := range tuple {
				row = append(row, stringifyCLIArg(val))
			}
			data = append(data, row)
		}

		err := writeCSV(fp, columnNames, data)
		if err != nil {
			return types.Hash{}, err
		}

		args := []string{"exec-action", action, "--csv", fp}
		if namespace != "" {
			args = append(args, "--namespace", namespace)
		}

		// now, I need to create the mappings that map the csv columns to the action params.
		// I can simply use 1-based indexing for the action's params
		for i, colName := range columnNames {
			args = append(args, "--csv-mapping", fmt.Sprintf("%s:%d", colName, i+1))
		}

		return j.exec(ctx, args, opts...)
	}

	// first arg is the action
	args := []string{"exec-action", action}
	if len(tuples) == 1 {
		res, err := formatActionParams(tuples[0])
		if err != nil {
			return types.Hash{}, err
		}
		args = append(args, res...)
	}
	// if 0 len tuples, no args are needed

	if namespace != "" {
		args = append(args, "--namespace", namespace)
	}

	return j.exec(ctx, args, opts...)
}

func stringifyCLIArg(a any) string {
	if a == nil {
		return cmds.NullLiteral
	}

	// if it is an array, we need to delimit it with commas
	typeof := reflect.TypeOf(a)
	if typeof.Kind() == reflect.Slice && typeof.Elem().Kind() != reflect.Uint8 {
		slice := reflect.ValueOf(a)
		args := make([]string, slice.Len())
		for i := range slice.Len() {
			idx := slice.Index(i)
			// it might be nil
			if idx.IsNil() {
				args[i] = cmds.NullLiteral
				continue
			}

			args[i] = stringifyCLIArg(slice.Index(i).Interface())
		}
		return "[" + strings.Join(args, ",") + "]"
	}

	switch t := a.(type) {
	case string:
		return t
	case []byte:
		return database.FormatByteEncoding(t)
		// we check against the non-pointer types for decimal and uuid since
		// the String() method for both has a pointer receiver
	case types.Decimal:
		return t.String()
	case types.UUID:
		return t.String()
	case fmt.Stringer:
		return t.String()
	default:
		// if it is a pointer, we should dereference it
		if typeof.Kind() == reflect.Ptr {
			return stringifyCLIArg(reflect.ValueOf(a).Elem().Interface())
		}
		return fmt.Sprintf("%v", t)
	}
}

func (j *jsonRPCCLIDriver) ExecuteSQL(ctx context.Context, sql string, params map[string]any, opts ...client.TxOpt) (types.Hash, error) {
	args := append([]string{"exec-sql"}, "--stmt", sql)
	for k, v := range params {
		encoded, err := types.EncodeValue(v)
		if err != nil {
			return types.Hash{}, err
		}

		args = append(args, "--param", k+":"+encoded.Type.String()+"="+stringifyCLIArg(v))
	}

	return j.exec(ctx, args, opts...)
}

// exec executes a kwil-cli command that issues a transaction and returns the hash.
func (j *jsonRPCCLIDriver) exec(ctx context.Context, args []string, opts ...client.TxOpt) (types.Hash, error) {
	opts2 := client.GetTxOpts(opts)
	if opts2.Fee != nil {
		return types.Hash{}, fmt.Errorf("fee tx opts is not supported in cli driver")
	}
	if opts2.Nonce != 0 {
		args = append(args, "--nonce", strconv.FormatInt(opts2.Nonce, 10))
	}

	if opts2.SyncBcast {
		r := &display.TxHashResponse{}
		err := cmd(j, ctx, r, append(args, "--sync")...)
		if err != nil {
			return types.Hash{}, err
		}

		return r.TxHash, nil
	}

	// otherwise, we have a different structure
	r := display.TxHashResponse{}
	err := cmd(j, ctx, &r, args...)
	if err != nil {
		return types.Hash{}, err
	}

	return r.TxHash, nil
}

// printWithSync will
type respAccount struct {
	Identifier types.HexBytes `json:"identifier"`
	KeyType    string         `json:"key_type"`
	Balance    string         `json:"balance"`
	Nonce      int64          `json:"nonce"`
}

func (j *jsonRPCCLIDriver) GetAccount(ctx context.Context, acct *types.AccountID, status types.AccountStatus) (*types.Account, error) {
	r := &respAccount{}

	args := []string{"account", "balance", hex.EncodeToString(acct.Identifier), "--keytype", acct.KeyType.String()}
	if status == types.AccountStatusPending {
		args = append(args, "--pending")
	}

	err := cmd(j, ctx, r, args...)
	if err != nil {
		return nil, err
	}

	bal, ok := big.NewInt(0).SetString(r.Balance, 10)
	if !ok {
		return nil, errors.New("invalid decimal string balance")
	}

	return &types.Account{
		ID:      acct,
		Balance: bal,
		Nonce:   r.Nonce,
	}, nil
}

func (j *jsonRPCCLIDriver) Ping(ctx context.Context) (string, error) {
	var r string
	err := cmd(j, ctx, &r, "utils", "ping")
	return r, err
}

func (j *jsonRPCCLIDriver) Query(ctx context.Context, query string, params map[string]any, _ bool) (*types.QueryResult, error) {
	args := []string{"query", query}
	for k, v := range params {
		encoded, err := types.EncodeValue(v)
		if err != nil {
			return nil, err
		}

		args = append(args, "--param", k+":"+encoded.Type.String()+"="+stringifyCLIArg(v))
	}

	r := &types.QueryResult{}
	err := cmd(j, ctx, r, args...)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (j *jsonRPCCLIDriver) TxQuery(ctx context.Context, txHash types.Hash) (*types.TxQueryResponse, error) {
	r := &types.TxQueryResponse{}
	err := cmd(j, ctx, r, "utils", "query-tx", txHash.String())
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (j *jsonRPCCLIDriver) TxSuccess(ctx context.Context, txHash types.Hash) error {
	res, err := j.TxQuery(ctx, txHash)
	if err != nil {
		return err
	}

	if res.Height < 0 {
		return ErrTxNotConfirmed
	}

	if res.Result != nil && res.Result.Code != 0 {
		return fmt.Errorf("tx failed: %v", res.Result)
	}

	return nil
}

func (j *jsonRPCCLIDriver) WaitTx(ctx context.Context, txHash types.Hash, interval time.Duration) (*types.TxQueryResponse, error) {
	return clientImpl.WaitForTx(ctx, j.TxQuery, txHash, interval)
}

func (j *jsonRPCCLIDriver) Transfer(ctx context.Context, to *types.AccountID, amount *big.Int, opts ...client.TxOpt) (types.Hash, error) {
	return j.exec(ctx, []string{"account", "transfer", to.Identifier.String(), amount.String(), "--keytype", to.KeyType.String()}, opts...)
}
