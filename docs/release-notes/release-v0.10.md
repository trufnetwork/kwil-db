# Kwil v0.10

This is the largest release of Kwil DB to-date. Much of the protocol has been redesigned from the ground up to dramatically improve throughput and scalability.

The highlights are:

* New in-house consensus engine (Roadrunner) prioritizing high throughput and fast transaction finality
* New SQL smart contract language
* New action execution engine using an interpreter in Kwil rather than prepared procedures within PostgreSQL
* A network-wide database owner rather than an open multi-tenant database
* A native ERC20 bridge and rewards system (experimental)
* New peer-to-peer (P2P) layer using `libp2p` protocols
* New block store
* Removed the `kwil-admin` tool, merging its functionality with `kwild` in new sub-commands
* New `'chain'` RPC service for querying blockchain data
* OpenTelemetry metrics (experimental)

## Contents

* [Important Upgrading Notes](#important-upgrading-notes)
* [Requirements and Dependencies](#requirements-and-dependencies)
* [Security Policy](#security-policy)
* [Notable Features and Changes](#notable-features-and-changes)
  * [New consensus engine (Roadrunner)](#new-consensus-engine-roadrunner)
  * [New SQL smart contract language](#new-sql-smart-contract-language)
  * [Native ERC20 bridge and reward system](#native-erc20-bridge-and-reward-system)
  * [New peer-to-peer (P2P) layer using `libp2p` protocols](#new-peer-to-peer-p2p-layer-using-libp2p-protocols)
  * [New block store](#new-block-store)
  * [New `'chain'` RPC service for querying blockchain data](#new-chain-rpc-service-for-querying-blockchain-data)
* [Breaking Changes](#breaking-changes)
* [Minor Features and Changes](#minor-features-and-changes)
* [Diff summary](#diff-summary)

## Important Upgrading Notes

This release has redesigned most aspects of the Kwil DB node. As such, there are major breaking changes in several areas that require: (a) rewriting database schema definitions into the new SQL language, (b) redeploying new chains, and (c) updating client code for the new SDK APIs and `kwil-cli` commands.

For information on the new SQL smart contract language, see the [Kwil database language](https://docs.kwil.com/docs/language/introduction) documentation.

For the new clients, see both the [SDK](https://docs.kwil.com/docs/category/sdks) and [CLI](https://docs.kwil.com/docs/category/cli) documentation.

For node configuration and deployment, see the [Kwil DB Node](https://docs.kwil.com/docs/category/node) documentation pages. The database schema formats are entirely incompatible both in terms of the schema definition language and the data layout within PostgreSQL. As such, no native migration process is possible at present; the DB owner must repopulate the database via batch insert transactions after genesis.

## Requirements and Dependencies

* The minimum required Go version is now 1.23.
* Builds and tests use Go 1.23.
* Supported versions of PostgreSQL are 16.x. The recommended version is 16.8.
* Supported architectures are `amd64` and `arm64`.
* Supported operating systems are `linux` and `darwin`.

## Security Policy

The supported versions of Kwil are now as follows:

| Version | Supported |
| ------- | --------- |
| Latest beta or release candidate    | ✓        |
| v0.10.x  | ✓        |
| v0.9.x  | ✓        |
| < v0.9  | ❌        |

See [SECURITY.md](https://github.com/trufnetwork/kwil-db/blob/main/SECURITY.md) for details.

## Notable Features and Changes

### New consensus engine (Roadrunner)

To overcome the throughput limitations and long transaction finality times of the previous consensus engine, a new in-house consensus engine called "Roadrunner" has been developed.

Most notably, Roadrunner is designed for quick block production and validation in a federated network. It involves a "leader" node that is responsible for proposing blocks, and validators that are used to confirm the execution results of the proposed blocks.

For details, see the [Roadrunner](https://docs.kwil.com/docs/roadrunner/introduction) documentation.

### New SQL smart contract language

Kwil's SQL language and execution engine have been redesigned from the ground up to be more flexible and performant.

In terms of the language itself, it now looks and feels more similar to SQL. Kwil database administrators still define tables and actions, but instead of discrete and immutable "schemas", actions and tables can be created and deleted piecemeal.
A "namespace" is used to group related actions and tables.

Whereas deploying a schema previously meant specifying the schema as a whole in a structured format, now the schema is defined *implicitly* by a set of Kwil SQL statements.

Statement parsing is now part of the Kwil node's execution engine, rather than a client-side operation that previously translated a Kuneiform text file into the structured format before being sent to the node.
As such, deploying (or dropping) a schema is now part of a more general purpose `'raw_statement'` transaction payload, where the statements contain various `CREATE` directives. Such a transaction can contain multiple statements that are executed atomically.

Permissions for what kinds of statements may be executed by a user are dictated by a `ROLE`, which is a new concept in Kwil. Roles are assigned to users by the database owner, which is itself the special `'owner'` role. Various permissions are granted to roles, and users can be assigned to one or more roles.

As before, executing a mutable action uses an `'execute'` *transaction* type, and a read-only action with the `view` modifier is called with the `'user.call'` *RPC request* rather than a transaction.

This feature was introduced in commit [c21d062](https://github.com/trufnetwork/kwil-db/commit/c21d06222a8e98d841ae8435f9be87d0a569b1b2).

### Native ERC20 bridge and reward system

Kwil now has a native ERC20 bridge, allowing protocols to transfer ERC20 tokens to, from, and within a Kwil database. Tokens are deposited into a database by locking them up in an escrow contract. Tokens are released from the escrow contract by a multisig. Each key in the multisig runs a Kwil node to listen to the network and authorize withdrawals from the bridge. Each Kwil network has its own multisig and escrow contract, and thus can choose its own token, threshold, and EVM chain.

See commits: [577a1c9](https://github.com/trufnetwork/kwil-db/commit/577a1c9918b180323719480ab500e4480cc87765), [c812c47](https://github.com/trufnetwork/kwil-db/commit/c812c4745546b354aec99a9050f299746a9e2b38), [2a7bdce](https://github.com/trufnetwork/kwil-db/commit/2a7bdce1c7fc7a1c9b00814fde37f7bfb7354e47), [5ba8870](https://github.com/trufnetwork/kwil-db/commit/5ba8870368fb6e24448bce34fbfb0da2819122e3), [8891cc7](https://github.com/trufnetwork/kwil-db/commit/8891cc7f2f2d467b098176c7d49263be588d65f5), and [3f95602](https://github.com/trufnetwork/kwil-db/commit/3f95602b27ab283c25c97d1a7da1914242613804).

### New peer-to-peer (P2P) layer using `libp2p` protocols

Nodes now communicate with each other using the `libp2p` protocol stack.

Custom protocols are defined for:

* the new consensus messages used by the Roadrunner consensus mechanism
* retrieval and gossip of block and transaction data
* peer exchange
* snapshot advertisement and retrieval

The protocols are individually versioned, but are considered internal details of the Kwil node implementation, which are not intended for external use.

As a consequence of the new peer-to-peer layer, a new network crawler has been developed to replace the `cometseed` application. The crawler is usable via the `node/peers/seeder` package or the `kwild seed` command.

A new address book format is also defined to support dynamic peer discovery as well as peer filtering.

### New block store

The serialization format of block data and outcomes of the consensus process are now defined by Kwil.
Thus, the Kwil node now has a new block store, which is an embedded database containing the raw block data (as opposed to the state DB, which is the role of PostgreSQL).
This is the `'blockstore'` directory in the node's root directory.

### New `'chain'` RPC service for querying blockchain data

To query blockchain data, a `'chain'` RPC service (a set of methods in the `'chain'` namespace) has been added.
By default this service's methods are available alongside the existing `'user'` methods on the node's public RPC server on port 8484.

## Breaking Changes

As described above, much of Kwil's core functionality has been redesigned. This translates to a number of breaking changes:

* Kwil's SQL language is new. Previous Kuneiform schemas must be rewritten in the new SQL language. In most cases, this is straightforward and intuitive. Note the new concepts and syntax documented in the [SQL language documentation](https://docs.kwil.com/docs/language/introduction).
* For the new consensus engine, it is now required to designate a network leader in the `genesis.json` file. See the genesis file documentation for details. The leader is part of the validator set, and the `setup testnet` command makes the first validator the leader.
* The entire `config.toml` file has new sections and fields. This is on account of the new consensus engine, p2p layer, block store, mempool, logger, and telemetry. See the `config.toml` documentation for details.
* The Go SDK and `Client` types have been updated with new methods to interact with the new DB engine. In particular, there are no longer deploy or drop methods; these are now part of the `'raw_statement'` transaction type that is created and broadcast by the `ExecuteSQL` method.
* An important conceptual change is that regular users are no longer able to deploy schemas. This is now done by the database owner. Users may be assigned to roles that are granted `CREATE` permissions, but only the DB owner has this permission by default.
* The `kwil-admin` tool's functionality has been merged into sub-commands of the `kwild` application, and the `kwil-admin` tool has been removed.
* Although both offline and zero-downtime (ZDT) migration functionality is available, it is not possible to migrate in this way from a previous version such as v0.9. This functionality is in place for possible use in future versions with compatible genesis state snapshots.
* The `uint256` type is removed. Instead, use `numeric` with the required precision and scale.
* In the action call structure, `CallMessage`, the `Signature *auth.Signature` field is replaced by `SignatureData []data` to avoid duplicating the sender's public key or identity, which was already in the `Sender` field.
* The `Transactions` and the various payload types are now found in the `core/types` package.  The `core/types/transactions` package is removed.
* The `parse` module has been removed. Statement parsing functionality is internalized into the `node/engine` packages, which reflects the fact that parsing is now part of the Kwil engine's interpreter-based execution model.

## Minor Features and Changes

* New logger backend and a "plain" subsystem logger. The backend for structured logging is now the standard library `log/slog` package. This supports both JSON and key-value text output formats. A "plain" subsystem leveled log format is also available. See the documentation for the `core/log` package for details.
* OpenTelemetry support for metrics and tracing.
* Empty block timeout is now configurable. The default is 1 minute if there are no transactions waiting in mempool to be included in a block (`consensus.empty_block_timeout`), and 1 second if there are transactions in the mempool (`consensus.propose_timeout`). See the `config.toml` documentation for details.
* When the leader's mempool has enough transactions to fill a block, the leader will immediately prepare a new block and broadcast it to the network without waiting for either timeout.
* The extension system now supports custom key types. See `core/crypto/keys.go`.
* Unknown settings in `config.toml` are now an error. This will catch obsolete or misspelled settings.
* The `core` module no longer requires the `go-ethereum` or `zap` modules. All dependencies are under permissive licenses.
* Added a blockchain statistics [collection tool](https://github.com/trufnetwork/kwil-db/commit/b7ba978a3c3afa9011d5628a4ff3407b3a6e3935) for use with an offline block store.

## Diff summary

<https://github.com/trufnetwork/kwil-db/compare/41aa8672ce320573b303384f26d528e16f92f9ed^...v0.10.0>

857 changed files with 122,633 additions and 64,846 deletions
