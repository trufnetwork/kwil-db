# Kwil Go Client

This folder contains the Go language client for interacting with a Kwil RPC
provider. Package `client` may be used to build a third-party application with
the ability to:

- Retrieve the status of a Kwil network, which is a deployed database.
- List and retrieve namespaces and other components of the database.
- Create and drop namespaces, if the account is also the network "DB Owner".
- Execute mutative actions.
- Call read-only actions without a network transaction.
- Run ad-hoc SQL queries.
- Retrieve account information, such as balance and nonce.
- Check the status and execution outcome of a network transaction.

The `client` package is used by the `kwil-cli` application to provide these
functions on the command line. Go applications may use the package directly.

## Get the `core` Go Module

The `client` package is part of the `core` Go sub-module of the `kwil-db` repository. To use the package in your Go application, add it as a `require` in your project's `go.mod`:

```sh
go get github.com/trufnetwork/kwil-db/core
go mod tidy
```

If you did not already have a `go.mod` for your project, create one with `go mod init mykwilapp`, replacing `mykwilapp` with the module name for your project, which is typically a remote git repository location.

Alternatively, can also manually edit your `go.mod` and then run `go mod tidy`.

Your `go.mod` should be similar to the following:

```go
module mykwilapp

go 1.23

require (
    github.com/trufnetwork/kwil-db/core v0.4.0
)
```

## Import the `client` package

With the Kwil `core` module added to your `go.mod`, you can use the `client` package in your code by importing it:

```go
import "github.com/trufnetwork/kwil-db/core/client"
```

## Using the `Client` type

### Basic functionality

The main functionality is provided by the `Client` type. The `NewClient` function constructs a new `Client` instance from the URL of a Kwil RPC provider, and a set of options in the `core/client/types.Options` type.

For example:

```go
package main

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/client"
	klog "github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	ctypes "github.com/trufnetwork/kwil-db/core/client/types"
)

const (
	provider = "http://127.0.0.1:8484"
)

func main() {
	ctx := context.Background()

	// Create the client and connect to the RPC provider.
	cl, err := client.NewClient(ctx, provider, ctypes.DefaultOptions())
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
}
```

With a `kwild` instance running at `http://127.0.0.1:8484`, the above code will print something similar to:

```plain
Connected to Kwil chain "kwil-testnet", block height 21
```

**WARNING:** This guide assumes a Kwil network is deployed with **gas disabled**. If gas is enabled on the network, your account will need sufficient balance to pay for the gas used by the network transactions. Further, this also assumes that you are the "DB owner" with privileges to create and drop namespaces, as specified in the network's `genesis.json`.

### Wallet Setup

In the above example, we used `ctypes.DefaultOptions()`, which includes no
logger, signer (wallet), or expected chain ID. To work with a Kwil account, use
the `crypto` and `crypto/auth` packages to create and load private keys. For
example, we can create and load a secp256k1 private key plus an Ethereum
"personal" signer with the following functions:

```go
import (
   	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
)

func genKey() crypto.PrivateKey {
	key, _, _ := crypto.GenerateSecp256k1Key(nil)
	return key
} // can print key.Bytes() as hex string

func makeSigner(keyHex string) (auth.Signer, string) {
	key, err := crypto.Secp256k1PrivateKeyFromHex(keyHex)
	if err != nil {
		panic(fmt.Sprintf("bad private key: %v", err))
	}
	signer := &auth.EthPersonalSigner{Key: *key}
	addr, _ := auth.EthSecp256k1Authenticator{}.Identifier(signer.CompactID())
	return signer, addr
}
```

Now we can expand our example application to work with our account and create signed transactions on the specified Kwil network.

```go
const (
	chainID  = "kwil-testnet" // expect provider to report this chain ID
	provider = "http://127.0.0.1:8484"
	privKey  = "..." // db owner secp256k1 private key in hexadecimal
)

func main() {
	ctx := context.Background()
	signer, addr := makeSigner(privKey)
	fmt.Printf("My address: %s\n", addr)
	acctID := &types.AccountID{
		Identifier: signer.CompactID(),
		KeyType:    signer.PubKey().Type(),
	}

	opts := &ctypes.Options{
		Logger:  klog.NewStdoutLogger(),
		ChainID: chainID, // ensure the provider matches
		Signer:  signer,  // required for transactions and auth
	}

	// Create the client and connect to the RPC provider.
	cl, err := client.NewClient(ctx, provider, opts)
	if err != nil {
		log.Fatal(err)
	}

	// Check our account's balance.
	acctInfo, err := cl.GetAccount(ctx, acctID, types.AccountStatusLatest)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("My balance = %v, nonce = %d\n", acctInfo.Balance, acctInfo.Nonce)
}
```

### Database Discovery

Now that we are able to communicate with the Kwil network, and our client is
configured with the DB owner account, we are ready to start working with the
database, which is defined using the Kwil database language.

The Kwil language is a SQL smart contract language that combines standard SQL
syntax, such as `SELECT`, `INSERT`, `UPDATE`, and `DELETE` statements, with the
ability to define procedural logic using "actions".
See the [Kwil Language Introduction](/docs/language/introduction) for more
information about the Kwil database language.

A Kwil database is organized into **namespaces** that are conceptually similar
to postgres schemas, giving scope to tables and actions.
To list namespaces, perform a query on the `namespaces` table in the `info` schema.
See the [Namespaces](/docs/language/info-namespace) documentation for more information
about the `info` namespace.

```go
// List existing database namespaces.
qr, err := cl.Query(ctx, "SELECT name FROM info.namespaces", nil)
if err != nil {
	log.Fatal(err)
}
fmt.Printf("All namespaces: %v\n", qr.Values)
```

Initially there are only a handful of special namespaces: `info`, `main`, and any namespaces created by an extension.
For example the above code will print something similar to:

```plain
All namespaces: [[info] [kwil_erc20_meta] [kwil_ordered_sync] [main]]
```

Additional queries in the `info` namespace may be used to discover more about the Kwil network.
For instance, so summarize the actions available in the `main` (default) namespace, we can use the following query:

```sql
SELECT name,parameter_names,parameter_types, return_types FROM info.actions WHERE namespace = 'main';
```

### Defining your Database

Now that we have a `Client` with a working RPC provider connection, we can
create a new namespace containing tables and actions with the `ExecuteSQL`
method. This will execute Kwil SQL language statements, which may contain DDL
statements that work with tables, indexes, and actions. Only the DB owner can
create a new namespace, while user roles can be defined per-namespace with privileges such as
`CREATE`, `INSERT`, `UPDATE`, and `DELETE`. See the [Kwil Language Introduction](/docs/language/introduction) for more information about the Kwil database language.

Unlike the methods we have used so far, `ExecuteSQL` will create, sign, and
broadcast a blockchain transaction on a Kwil network. Once the transaction is
included in a block and executed, the database will become available for use.

The most direct way to initialize your database is by combining multiple
`CREATE` statements into a single string to execute in one transaction.
Our example application defines a `var testSQLDefinitions string` that contains a set
of DDL statements to create a new `kwilapp` namespace and the tables and actions within it.

```go
var testSQLDefinitions = `
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
};`

...
```

See the code in `core/client/example` for the full contents.

The following code will create the `kwilapp` namespace, wait for the transaction
to be included in a block, and then print the result of the transaction.

```go
// Define the 'kwilapp' namespace.
txHash, err := cl.ExecuteSQL(ctx, testSQLSchema, nil, txOpts...)
if err != nil {
	log.Fatalf("failed to define namespace: %v", err)
}
checkTx(txHash, "define namespace")
```

If that succeeded, the transaction was successfully broadcasted. The `txHash` is this transaction's identifier. However, the changes are not yet committed.

First we have to wait for the next block for the transaction to be executed. To
ensure that the transaction is included in a block before the method returns, we
may specify an option as follows:

```go
// When broadcasting a transaction, wait until it is included in a block.
txOpts := []ctypes.TxOpt{ctypes.WithSyncBroadcast(true)}
txHash, err := cl.ExecuteSQL(ctx, testSQLSchema, nil, txOpts...) // wait
```

In addition to broadcasting the transaction, this ensures the transaction was
included in a block. The next section describes how to check the outcome of a
transaction's *execution*.

### Transaction Status

After being broadcasted to a Kwil node, a transaction must be included in a
block *and* execute without error for the change to go into effect. Use
the `TxQuery` method to check.

In our example app, we can define the following closure to use after every
transaction we broadcast:

```go
// After broadcast, we get a transaction hash that uniquely identifies the
// transaction. Use the TxQuery method to verify the execution succeeded.
checkTx := func(txHash types.Hash, desc string) {
	res, err := cl.TxQuery(ctx, txHash)
	if err != nil {
		log.Fatal(err)
	}
	if res.Result.Code == uint32(types.CodeOk) {
		fmt.Printf("Success: %q in transaction %v\n", desc, txHash)
	} else {
		log.Fatalf("Fail: %q in transaction %v, Result code %d, log: %q",
			desc, txHash, res.Result.Code, res.Result.Log)
	}
}
```

Combined the `WithSyncBroadcast` option in `txOpts`, this use of `TxQuery` will
ensure the transaction executed without error, otherwise the application will exit.

### Action Execution

As with the database table and action creation, action *execution* requires a
transaction since it is used to modify data.  Use the
`Execute` method.

Within the `kwilapp` namespace created by our example app, the action called `"tag"` will insert data:

```go
const namespace = "kwilapp"
const actionName = "tag"
args := [][]any{{"jon was here", 12}} // one execution, two arguments
txHash, err := cl.Execute(ctx, namespace, actionName, args, txOpts...)
if err != nil {
	log.Fatal(err)
}
checkTx(txHash, "execute action")
```

In the above example, the `"tag"` action in the `"kwilapp"` namespace is defined as:

```sql
{kwilapp}CREATE ACTION tag($msg text, $val int) public returns (UUID) {
	$id = uuid_generate_kwil(@txid||@caller);
	INSERT INTO "tags" (id, author, msg, val) VALUES ($id, @caller, $msg, $val);
	return $id;
};
```

We called the `"tag"` action with arguments `[][]any{{"jon was here", 12}}`. This is
a `[][]any` to support batched action execution. In this example, we execute the
action once, using `"jon was here"` as the `$msg` argument and `12` as the `$val` argument.

For example, a batch of two executions of an action that requires three inputs,
such as `action multi_tag($msg1, $msg2, $msg3) public`, might look like:

```go
args := [][]any{
	{"first1", "first2", "first3"},    // first execution
	{"second1", "second2", "second3"}, // second execution
}
```

NOTE: To execute an action with no input arguments, provide `nil`.

### View (read-only) Action Calls

To run a read-only action, which is defined with the `view` modifier, use the
`Call` method.

For example, to call the `get_all` method that returns all records in the `tags` table:

```go
// Use a read-only view call (no blockchain transaction) to list all entries
results, err := cl.Call(ctx, namespace, "get_all", nil)
if err != nil {
	log.Fatal(err)
}
```

The `Call` method returns the data in the `core/types.CallResult`
type. See the [godocs](https://pkg.go.dev/github.com/trufnetwork/kwil-db/core/types#CallResult)
for this type to see the methods available for accessing the records.

## Complete Example

For a complete example with the SQL used in the sections above, see the code
in [`core/client/example`](./example/main.go).

The `kwil-cli` CLI app is also built on the `Client` type, and
[its code](https://github.com/trufnetwork/kwil-db/tree/main/cmd/kwil-cli)
can be used as a reference.
