package main

// This is an example Kwil client application that demonstrates the use of the
// core/client.Client type to interact with a Kwil chain via an RPC provider.

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/trufnetwork/kwil-db/core/client"
	ctypes "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	klog "github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
)

const (
	chainID  = "kwil-testnet"          // "longhorn-2"
	provider = "http://127.0.0.1:8484" // "https://longhorn.kwil.com"
)

var (
	// For the client, this is a secp256k1 private key. This is the same type of
	// key used by Ethereum wallets. The `kwil-cli utils generate-key` command
	// may be used to generate a new client key (the client's identity) if one
	// is not already available.
	// If left empty, this example app will generate an ephemeral private key.
	privKey = "" // empty or 64 hexadecimal characters of a secp256k1 private key
)

func main() {
	flag.StringVar(&privKey, "key", privKey, "private key to use for the client (TIP: set to match db_owner!)")
	flag.Parse()

	ctx := context.Background()

	var signer auth.Signer
	var addr string
	if privKey == "" {
		var key crypto.PrivateKey
		key, signer, addr = genEthKey()
		fmt.Printf("generated private key: %x\n", key.Bytes())
		fmt.Printf("public key: %x\n", key.Public().Bytes())
	} else {
		signer, addr = makeEthSigner(privKey)
	}
	fmt.Printf("address: %s\n", addr)

	acctID := &types.AccountID{
		Identifier: signer.CompactID(),
		KeyType:    signer.PubKey().Type(),
	}

	opts := &ctypes.Options{
		Logger:  klog.NewStdoutLogger(),
		ChainID: chainID,
		Signer:  signer, // required only transactions and auth
	}

	// Create the client and connect to the RPC provider.
	cl, err := client.NewClient(ctx, provider, opts)
	if err != nil {
		log.Fatal(err)
	}

	// Report the chain ID and block height of the provider.
	chainInfo, err := cl.ChainInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Connected to Kwil chain %q, block height %d\n",
		chainInfo.ChainID, chainInfo.BlockHeight)

	// Check our account's balance.
	acctInfo, err := cl.GetAccount(ctx, acctID, types.AccountStatusLatest)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Account %s balance = %v, nonce = %d\n", acctID, acctInfo.Balance, acctInfo.Nonce)

	// List previously deployed namespaces.
	qr, err := cl.Query(ctx, "select name from info.namespaces", nil, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("All namespaces: %v\n", qr.Values)

	// When broadcasting a transaction, wait until it is included in a block.
	txOpts := []ctypes.TxOpt{ctypes.WithSyncBroadcast(true)}

	// After broadcast, we get a transaction hash that uniquely identifies the
	// transaction. Use the TxQuery method to get the execution result.
	checkTx := func(txHash types.Hash, attempt string) {
		res, err := cl.TxQuery(ctx, txHash)
		if err != nil {
			log.Fatal(err)
		}
		if res.Result.Code == uint32(types.CodeOk) {
			fmt.Printf("Success: %q in transaction %v\n", attempt, txHash)
		} else {
			log.Fatalf("Fail: %q in transaction %v, Result code %d, log: %q",
				attempt, txHash, res.Result.Code, res.Result.Log)
		}
	}

	const minBal int64 = 1e6 // dust
	if chainInfo.Gas && acctInfo.Balance.Cmp(big.NewInt(minBal)) < 0 {
		fmt.Println("Account lacks sufficient funds for transaction gas. Requesting funds.")
		os.Exit(1)
	}

	namespace := "kwilapp"

	// Define tables and actions in the 'kwilapp' namespace.
	txHash, err := cl.ExecuteSQL(ctx, testSQLSchema, nil, txOpts...)
	if err != nil {
		log.Fatalf("failed to define namespace: %v", err)
	}
	checkTx(txHash, "define namespace")

	// Insert some data with this schema's "tag" action. Two in the same block,
	const tagAction = "tag"
	fmt.Printf("Executing action %q to insert data...\n", tagAction)
	// This one without the "sync" option.
	txHash, err = cl.Execute(ctx, namespace, tagAction, [][]any{{"jon was here", 12}})
	if err != nil {
		log.Fatal(err)
	}
	// This one with the "sync" option.
	txHash2, err := cl.Execute(ctx, namespace, tagAction, [][]any{{"jon was here AGAIN", 99}}, txOpts...)
	if err != nil {
		log.Fatal(err)
	}
	checkTx(txHash, "execute action "+tagAction)
	checkTx(txHash2, "execute action "+tagAction)

	// Use a read-only view call (no blockchain transaction) to list all entries
	const getAllAction = "get_all"
	results, err := cl.Call(ctx, namespace, getAllAction, nil)
	if err != nil {
		log.Fatal(err)
	}
	headers, vals := results.QueryResult.ColumnNames, results.QueryResult.Values
	if len(vals) == 0 {
		log.Fatal("No data records in table.")
	}

	fmt.Println("All entries in tags table:")
	fmt.Printf("column names: %#v\n"+"values:\n", headers)
	for _, row := range vals {
		fmt.Printf("%#v\n", row)
	}

	const getMineAction = "get_my_tags"
	results, err = cl.Call(ctx, namespace, getMineAction, nil)
	if err != nil {
		log.Fatal(err)
	}
	vals = results.QueryResult.Values
	if len(vals) != 2 {
		log.Fatal("Did not find two entries for me!")
	}

	txHash, err = cl.Execute(ctx, namespace, "delete_all", nil, txOpts...)
	if err != nil {
		log.Fatal(err)
	}
	checkTx(txHash, "delete all")

	// get mine, ensure none
	results, err = cl.Call(ctx, namespace, getMineAction, nil)
	if err != nil {
		log.Fatal(err)
	}
	_, vals = results.QueryResult.ColumnNames, results.QueryResult.Values
	if len(vals) != 0 {
		log.Fatalf("expected no results for %v, got %d", getMineAction, len(vals))
	}
	log.Println("deleted all!")
}

func makeEthSigner(keyHex string) (auth.Signer, string) {
	key, err := crypto.Secp256k1PrivateKeyFromHex(keyHex)
	if err != nil {
		panic(fmt.Sprintf("bad private key: %v", err))
	}
	signer := &auth.EthPersonalSigner{Key: *key}
	addr, _ := auth.EthSecp256k1Authenticator{}.Identifier(signer.CompactID())
	return signer, addr
}

func genEthKey() (crypto.PrivateKey, auth.Signer, string) {
	key, _, _ := crypto.GenerateSecp256k1Key(nil)
	secKey := key.(*crypto.Secp256k1PrivateKey)
	signer := &auth.EthPersonalSigner{Key: *secKey}
	addr, _ := auth.EthSecp256k1Authenticator{}.Identifier(signer.CompactID())
	return key, signer, addr
}

var testSQLSchema = `
DROP NAMESPACE IF EXISTS kwilapp;
CREATE NAMESPACE kwilapp;

{kwilapp}CREATE TABLE tags (
	id UUID PRIMARY KEY,
    author TEXT NOT NULL,
    val INT DEFAULT 42,
    msg TEXT NOT NULL
);

{kwilapp}CREATE ACTION tag($msg text, $val int) public returns (UUID) {
	$id = uuid_generate_kwil(@txid||@caller);
	INSERT INTO "tags" (id, author, msg, val) VALUES ($id, @caller, $msg, $val);
	return $id;
};

{kwilapp}CREATE ACTION delete_mine() public {
	DELETE FROM "tags" WHERE "author" = @caller;
};

{kwilapp}CREATE ACTION delete_tag_id ($id UUID) public owner {
	DELETE FROM "tags" WHERE "id" = $id;
};

{kwilapp}CREATE ACTION delete_all() public owner {
	DELETE FROM "tags";
};

{kwilapp}CREATE ACTION get_user_tags($author text) public view returns TABLE(id UUID, msg text, val int) {
	return SELECT id, msg, val FROM "tags" WHERE "author" = $author;
};

{kwilapp}CREATE ACTION get_my_tags() public view returns TABLE(id UUID, msg text, val int) {
	return SELECT id, msg, val FROM "tags" WHERE "author" = @caller;
};

{kwilapp}CREATE ACTION get_all() public view returns TABLE(id UUID, author text, msg text, val int) {
	return SELECT id, author, msg, val FROM "tags";
};
`
