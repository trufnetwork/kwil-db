package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"

	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/gatewayclient"
	"github.com/trufnetwork/kwil-db/core/types"
	clientType "github.com/trufnetwork/kwil-db/core/types/client"
	"github.com/trufnetwork/kwil-db/core/types/transactions"
	"github.com/trufnetwork/kwil-db/core/utils"
)

const (
	kgwProvider = "http://localhost:8090"

	privKey = "0000000000000000000000000000000000000000000000000000000000000001"
)

var testKF = `database test_kgw;

action hello() public view {
	select 'Hello, world!';
}

@kgw(authn='true')
action auth_only() public view {
    select 'Hello, authorized user!';
`

//go:embed kf.json
var testKFJSON []byte // testKF compiled to JSON

func main() {
	ctx := context.Background()

	pk, err := crypto.Secp256k1PrivateKeyFromHex(privKey)
	if err != nil {
		log.Fatal(err)
	}

	signer := &auth.EthPersonalSigner{Key: *pk}
	acctID := signer.Identity()

	// Create the client
	clt, err := gatewayclient.NewClient(ctx, kgwProvider, &gatewayclient.GatewayOptions{
		Options: clientType.Options{
			Signer: signer,
		},
		AuthSignFunc: func(message string, signer auth.Signer) (*auth.Signature, error) {
			// Here we just print the message to be signed
			fmt.Println(message)
			return signer.Sign([]byte(message))
		},
		AuthCookieHandler: func(c *http.Cookie) error {
			// Here we just print the cookie
			fmt.Println("You've got a cookie:", c.Name)
			return nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// After broadcast, we get a transaction hash that uniquely identifies the
	// transaction. Use the TxQuery method to get the execution result.
	checkTx := func(txHash []byte, attempt string) {
		res, err := clt.TxQuery(ctx, txHash)
		if err != nil {
			log.Fatal(err)
		}
		if res.TxResult.Code == transactions.CodeOk.Uint32() {
			fmt.Printf("Success: %q in transaction %x\n", attempt, txHash)
		} else {
			log.Fatalf("Fail: %q in transaction %x, Result code %d, log: %q",
				attempt, txHash, res.TxResult.Code, res.TxResult.Log)
		}
	}

	chainInfo, err := clt.ChainInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Connected to Kwil chain %q, block height %d\n",
		chainInfo.ChainID, chainInfo.BlockHeight)

	// List previously deployed database owned by us.
	datasets, err := clt.ListDatabases(ctx, acctID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d database(s) owned by me.\n", len(datasets))

	// Deploy the schema
	var schema types.Schema
	if err := json.Unmarshal(testKFJSON, &schema); err != nil {
		log.Fatal(err)
	}
	dbid := utils.GenerateDBID(schema.Name, acctID)

	// See if it already deployed.
	deployed := slices.ContainsFunc(datasets, func(d *types.DatasetIdentifier) bool {
		return d.Name == schema.Name
	})

	if !deployed {
		// When broadcasting a transaction, wait until it is included in a block.
		txOpts := []clientType.TxOpt{clientType.WithSyncBroadcast(true)}
		txHash, err := clt.DeployDatabase(ctx, &schema, txOpts...)
		if err != nil {
			log.Fatal(err)
		}

		checkTx(txHash, "deploy database")
	}

	fmt.Println("call hello")
	// no signing required, i.e. no message will be printed
	result1, err := clt.Call(ctx, dbid, "hello", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Result hello: ", result1.Records.ExportString())

	fmt.Println("call auth_only")
	// signing required, i.e. message will be printed
	// NOTE: you need to wait until the transaction is included in a block, so
	// Kwil Gateway will know which action needs authn, and then it will work as
	// expected
	result2, err := clt.Call(ctx, dbid, "auth_only", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Result auth_only: ", result2.Records.ExportString())

	// NOTE: the message will be printed every time you call this action for the
	// first time of current HTTP connection, but the following calls will not
	// print as the cookie jar has the authn cookie
	fmt.Println("call auth_only again, not need to sign again")
	result3, err := clt.Call(ctx, dbid, "auth_only", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Result auth_only again: ", result3.Records.ExportString())
}
