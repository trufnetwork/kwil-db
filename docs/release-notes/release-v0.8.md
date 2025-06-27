# Kwil v0.8

This is a major new release of Kwil DB.

The highlights are:

- A new Kuneiform element called "procedures" that uses a procedural language for building logic into schemas.
- Added a JSON-RPC server.
- Network migration support.
- Enable state sync mode and snapshot creation.
- Absorb the `kuneiform` and dependent repositories into the `parse` module in the `kwil-db` repository.

Note that v0.8.0 was not published due to issues with the upgrade procedures.

## Important Upgrading Notes

Nodes running `kwild` v0.8 are not compatible with nodes running `kwild` v0.7.

Upgrading to this release requires a network migration. See the [network migration documents](https://docs.kwil.com/docs/node/network-migrations) for instructions on how to perform a network migration. Only upgrading from v0.7 is supported.

In certain cases, deployed schemas on a v0.7 network may not be compatible with v0.8. See [Kuneiform Breaking Changes](#kuneiform-breaking-changes) for details.

To check if your schema is compatible with v0.8, use the `kwil-cli utils parse` command in the v0.8 Kwil CLI to parse the schema files and output the schema as JSON. If the command fails, the schema is not compatible with v0.8.

## Notable Changes

### Procedures

In previous releases, SQL queries were specified entirely within Kuneiform "actions".  This release introduces the concept of "procedures", which use a basic procedural language for building logic into schemas. Procedures can be used for building access control logic, performing arithmetic, and managing control flow.

Procedures are declared using the `procedure` keyword. A procedure may `return` either a single record (a tuple) or a `table`.

A procedure body may contain variable declarations, basic arithmetic operations, calls to various built-in functions, control flow (e.g. `if`/`then`/`for`), and SQL queries.

See the [procedure docs](https://docs.kwil.com/docs/kuneiform/procedures) for more information.

#### Variable Types

Procedures are strongly typed. The parameters, returns, and variables declared within a procedure must be assigned a type. The recognized types are:

- `int` is a 64-bit signed integer
- `text` is a variable length character array (a string)
- `bool` is a boolean (true or false)
- `blob` is a byte array
- `uint256` is a 256-bit unsigned integer
- `decimal` is a fixed precision type based
- `uuid` is 128-bit universally unique identifier (UUID)

Arrays of any of the above types are also permitted.

Legacy actions only support `int` and `text` in table declarations, and use no types in their signatures or bodies.

#### Foreign Procedure Calls

It is now possible to interact with procedures in a different database using `foreign` procedure declarations.  For instance, to use a procedure called `target_procedure` in the database `'x_target_dbid'`, declare a foreign procedure in your database and specify the target database and procedure name when calling:

```js
foreign procedure get_user($id uuid) returns (text, int)

procedure call_get_user($id uuid) public  {
    $username, $age = get_user['x_target_dbid', 'target_procedure']($id);
    // $username is a text and $age is an int
}
```

### JSON-RPC Server and gRPC Gateway Deprecation

This release of `kwild` adds a [JSON-RPC](https://www.jsonrpc.org/specification) server. It listens on TCP port 8484 of all network interfaces by default. JSON-RPC requests are handled by the `/rpc/v1` path.

The CLI utilities, the Go SDK client, and the JS SDK now use the JSON-RPC server by default. RPC providers should expose TCP port 8484, and client configuration should be updated to use port 8484.

The HTTP API, which is a REST gateway for the gRPC server, is now deprecated, although it listens on all network interfaces on port 8080 by default. The gRPC server, which was previously deprecated, now listens only on a loopback address to support the internal HTTP gateway (Swagger). The gRPC and the HTTP gateway will be removed in the next release.

The OpenRPC specification document for the "user" RPC service may be found in the [source code repository](https://github.com/trufnetwork/kwil-db/blob/release-v0.8/internal/services/jsonrpc/usersvc/user.openrpc.json). The server itself will also provide the server's active service specification at the `/spec/v1` HTTP endpoint and in the response to the `rpc.discover` JSON-RPC methods.

The `"params"` value in all requests are *named* rather than *positional*. This means that the JSON-RPC 1.0 calling convention with an array `[]` for the parameters is not supported, only the JSON-RPC convention using an object `{}`. However, this is a detail that the Kwil clients hide from users. Only if doing manual HTTP POST requests, such as with `curl` or Postman, is this important.

The "admin" service and the `kwil-admin` tool are also updated to use JSON-RPC.

### SQL Syntax

- Support for more built-in functions. See [Supported Functions](https://docs.kwil.com/docs/kuneiform/functions).
- Conflicting column names in the returned values from a query are disallowed.
  For example, this means that it is now an error if a `SELECT *` is used with a
  `JOIN` between tables with an identical column name.
- There is now a requirement that at least one side of a `JOIN` must be a
  table's column. It is an error to have literal or computed values on both sides.

#### Kuneiform Breaking Changes

- SQL statements that are valid SQL but have invalid predicates will fail during parse, instead of at runtime.
- Fixed edge cases where users could perform cartesian joins. Now, one side of a join must be a column of unique values.
- Fixed a handful of cases that could lead to non-deterministic query results:
    - Disallowing conflicting column names when returned from a query (as mentioned above).
    - Disallowing unnamed columns in query results.
    - Applying deterministic ordering for joins against subqueries.

### Snapshots and State Sync

State sync is a feature that allows a new node to bootstrap directly from a snapshot of the blockchain state instead of replaying all the blocks from the genesis. This reduces the time needed to sync a new node to a network. However, the node will only be aware of transactions after the snapshot height.

`kwild` may now be configured to periodically generate state snapshots, which are provided to nodes that are joining the network. The `app.snapshots` config section adjust this functionality.

To enable the use of state sync on a new node, trusted snapshot providers must be configured. The `chain.statesync` config section adjust this functionality.

State sync is only used for a new node. Catch up after a previously-running node has restarted uses the standard "block sync" technique, which fully validates and executes all blockchain transactions to rebuild state.

See the [State Sync docs](https://docs.kwil.com/docs/node/statesync) for details.

### Network Migrations

To launch a new network with an initial genesis state, special state snapshots may be generated using the `kwil-admin snapshot create` command.

When launching a network from this genesis state, the `app_hash` field of the new genesis.json file will be non-`null`. The initial validator nodes must use the `genesis_state` config.toml setting to specify the snapshot that corresponds to the `app_hash` value. Once a trusted snapshot provider has generated an initial snapshot for the new running network, other nodes may rely on the state sync mechanism to join the network without having to manually distribute the `genesis_state` file.

See [Network Migration documents](https://docs.kwil.com/docs/node/network-migrations) for details.

### Coordinated Upgrades

This release includes an experimental system for specifying planned changes to code that affects consensus.  This is an experimental system that is being evaluated to help avoid the need for network migrations when important fixes and updates might otherwise break consensus. See the [documentation](https://docs.kwil.com/docs/extensions/fork-background) for details.

### Command Line Application Changes

#### User CLI (`kwil-cli`) Changes

##### Moved `kwil-cli` Configuration Folder

The default config folder for `kwil-cli` is now called `kwil-cli` in the user's home directory.  It was previously called `kwil_cli`.

##### New RPC Provider Setting

Within `config.json`, the RPC provider is specified with a `"provider"` field. This was previously called `"grpc_url"`.

The `--kwil-provider` command line flag is DEPRECATED and will be removed in the subsequent release. Use the `--provider` flag instead.

When updating for the new `provider` setting, ensure it corresponds to the JSON-RPC server at port 8484 instead of the REST API at port 8080. Otherwise, ensure that the chosen RPC provider is updated to direct to the JSON-RPC server.

#### Command Changes

The result from the `utils query-tx` command no longer includes the transaction details for an unconfirmed transaction. Confirmed transactions will still include the decoded transaction. Using older versions of `kwil-cli` to query unconfirmed transactions may have unexpected behavior. A new `--raw` flag may be provided with this command to retrieve the serialized transaction data given a transaction hash.

Added the `utils parse` command to parse a Kuneiform file and output the schema as JSON.

Added the `utils decode-tx` command to decode a serialized transaction provided as a base64 string.

Many of the fields in the JSON objects returned by `query-tx` and other commands with the `--output json` option are renamed with consistent snake case formatting. See the See [UPGRADING.md](https://github.com/trufnetwork/kwil-db/blob/release-v0.8/UPGRADING.md) for details on changes to the `core` module types and their JSON tags.

The `account balance` command may now be given a `--pending` flag to return account information that includes changes that consider any unconfirmed transactions. This is useful for determining the next nonce for an account when broadcasting multiple transaction per block.

#### Node Application (`kwild`) Changes

The default setting for the admin service (`admin_listen_addr`) is now `"/tmp/kwild.socket"`.

The `jsonrpc_listen_addr` setting replaces the `grpc_listen_addr` setting. The default value for `jsonrpc_listen_addr` is `0.0.0.0:8484` (listen on port 8484 on all network interfaces).

In addition to standard output, `kwild` also writes the log to `"kwild.log"` in the application's root directory by default. The `output_paths` setting is used to change this.

Two new timeouts are added:

- `rpc_timeout` sets a timeout on requests on the user RPC servers
- `db_read_timeout` sets a timeout on database reads initiated by the user RPC service

To support [network migrations](#network-migrations), the `genesis_state` setting is added to specify the path to the snapshot file to restore the database from.

A new `app.snapshots` section is added to configure snapshot creation, which supports other nodes using "state sync" when joining a network.

A new `chain.statesync` section is added to configure the use of "state sync" if the node is joining a network.

A new `broadcast_tx_timeout` setting is added to control the timeout used when a transaction is broadcast with the `--sync` flag to wait for it to be mined. If the timeout is exceeded, the RPC user should query the transaction status until it is confirmed. The default timeout is 15 seconds.

See the [Node documentation](https://docs.kwil.com/docs/daemon/config/settings) for more information on the added and changed settings.

### SDK (`core` module)

This release of Kwil DB uses version 0.2.1 of the `core` Go module.

A Go application that supports Kwil DB v0.8.0 should be developed using the `core` module specified in the go.mod as follows:

```go
require github.com/trufnetwork/kwil-db/core v0.2.1
require github.com/trufnetwork/kwil-db/parse v0.2.1 // to parse Kuneiform files
```

See the example application in [`client/core/example`](https://github.com/trufnetwork/kwil-db/tree/release-v0.8/core/client/example) for a demonstration.

Below discusses the breaking changes to the `core` module, which provides the SDK and client for Kwil. If you do not use the Go SDK, you can skip this section.

#### `core/crypto/auth`

##### Breaking Changes

- The JSON tags on the `Signature` struct have changed:

```go
type Signature struct {
    Signature []byte `json:"sig"` // was `json:"signature_bytes"`
    Type string `json:"type"` // was `json:"signature_type"`
}
```

#### `core/types`

- The `Schema` struct and all of its composing types are now mirrored in `core/types.Schema`.
- Added many new type definitions to support procedures and strongly typed values. See `core/types/transactions/payload_schema.go`.

##### Breaking Changes

- There are many new types and fields on the `Schema` struct to support procedures and strongly typed values. Changes include:
    - `Owner` is now `HexBytes` instead of `byte[]`. `HexBytes` is an alias for `byte[]`; however, when marshaled to JSON, it is represented as a hex string.
    - `Table.Column.Type` now uses the `DataType` struct instead of a `string` to support strongly typed values.
    - Added the `Procedures` field to the `Schema` struct to support procedures.
    - Added the `ForeignProcedures` field to the `Schema` struct to support calling procedures that are defined in other schemas.

#### `core/types/transactions`

- **Note**: Most users do not need to be concerned with these changes as the `core/client` and `core/rpc/...` packages handle their use.
- Added the helper function `UnmarshalPayload` to assist in unmarshaling payloads from `byte[]` give its `PayloadType`.
- Added new `TxCode` values:

```go
    // engine-related error codes
    CodeInvalidSchema  TxCode = 100
    CodeDatasetMissing TxCode = 110
    CodeDatasetExists  TxCode = 120
```

##### Breaking Changes

- The `CallMessage`, `CallMessageBody`, and `Transaction` structs are now JSON-tagged for consistent snake-case marshaling.
- `CallMessage.Sender` and `Transaction.Sender` are now `HexBytes` instead of `byte[]`. This change was made because "senders" are usually hexadecimal Ethereum addresses.
- The `PayloadTypeExecuteAction` payload type is renamed to `PayloadTypeExecute` to reflect that it is used for executing procedures as well as actions.

#### `core/types/validation`

- Added the `validation` package to handle global limits and reserved keywords.

#### `core/types/transactions/payload_schema.go`

- Added `Call` and `Execute` to the `Client` interface to support calling procedures and actions.
- `CallAction` is DEPRECATED and will be removed in the subsequent release. Use `Call` instead.
- `ExecuteAction` is DEPRECATED and will be removed in the subsequent release. Use `Execute` instead.

##### Breaking Changes

- The `DeployDatabase` method's payload parameter is now `*types.Schema`. It was previously `*transactions.Schema`.
- The `GetSchema` method's return type is now `*types.Schema`. It was previously `*transactions.Schema`.

#### `core/client`

- Added detailed documentation in a `README.md` file.
- An example app in `core/client/example`.

##### Breaking Changes

- The `Client` type now uses the JSON-RPC server instead of the HTTP gateway to the gRPC server. This means that the `Client` only works with v0.8 nodes.

#### `core/rpc/client/...`

- **Note**: The packages unders `core/rpc/...` are relatively low-lvel and most users do not need to be concerned with these changes.
- Added the `core/rpc/client.JSONRPCClient` type to provider infrastructure for the "user", "admin", and "kgw" RPC services implemented in the `core/rpc/client/user/jsonrpc`, `core/rpc/client/admin/jsonrpc`, and `core/rpc/client/gateway/jsonrpc` packages.
- Added the `core/rpc/jsonrpc` package to define the common JSON-RPC types and methods.
- DEPRECATED the `core/rpc/http` package and its contents. This package will be removed in the subsequent release.

### Unified Parsing Module

The `parse` module contains the new unified parser for Kuneiform and SQL.

Previously there were separate repositories for parsing Kuneiform, action bodies, and SQL statements within actions and procedures. These are now combined into the `parse` module, which contains:

1. ANTLR grammar definitions in `parse/grammar`
2. Low-level Kuneiform parser and lexer Go package in `parse/gen`, generated from the ANTLR files
3. Top-level parsers in `parse` that return `kwil-db` types and apply Kwil rules and analysis
4. A WASM wrapper in `parse/wasm` for the top-level `parse.ParseAndValidate` function

For testing purposes, the `parse/postgres` package provides SQL syntax checking when built with CGO.

To build the WASM file, use the `kuneiform:wasm` [task](https://taskfile.dev/), which will create a `parse/wasm/kuneiform_wasm.tar.gz` file containing the .wasm file.

### PostgreSQL Docker Image

The latest `kwildb/postgres` Docker image is now version [`16.2-1`](https://hub.docker.com/r/kwildb/postgres/tags).

- Updates the base `postgres` image from 16.1 to 16.2
- Disables the default 60s timeout on the logical replication sender connections (`wal_sender_timeout=0`).

To update or download the image, run `docker pull kwildb/postgres:16.2-1`.

### Build System and CI

Kwil Gateway (KGW) integration tests are now run for all changes in the `kwil-db` repository.

The `golangci-lint` linter is updated to version 1.58.0.

## Build Requirements

This release requires Go version 1.21 or 1.22.

## Code Change Summary

This release consists of 164 commits changing 583 files, with a total of 67,719 lines of code added and 31,945 lines deleted.

See the full list of changes since v0.7 at https://github.com/trufnetwork/kwil-db/compare/v0.7.6...v0.8.1
