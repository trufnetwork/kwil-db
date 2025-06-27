# Kwil v0.9

This is a major release of Kwil DB with several new features.

The highlights are:

* Zero downtime migrations
* Data privacy modes: node peer filtering, and private RPC mode with authenticated calls
* Support builds with customizable branding
* Genesis and end-block hooks for extension authors
* Kuneiform updates: many new functions and syntax improvements
* A framework for testing Kuneiform schemas before deployment
* Improved node monitoring
* Removal of the previously-deprecated gRPC server and the legacy HTTP gateway

## Contents

* [Contents](#contents)
* [Important Upgrading Notes](#important-upgrading-notes)
* [Build Requirements and Dependencies](#build-requirements-and-dependencies)
* [Security Policy](#security-policy)
* [Notable Features and Changes](#notable-features-and-changes)
  * [Zero Downtime Migrations](#zero-downtime-migrations)
  * [Data Privacy Modes](#data-privacy-modes)
    * [Node Peer Filtering Capability](#node-peer-filtering-capability)
    * [Private RPCs and Authenticated Calls](#private-rpcs-and-authenticated-calls)
  * [Ability to Rebrand Customized Binary Builds](#ability-to-rebrand-customized-binary-builds)
  * [Extension Hooks for Genesis Initialization and End-Block Actions](#extension-hooks-for-genesis-initialization-and-end-block-actions)
  * [Kuneiform Language](#kuneiform-language)
    * [Kuneiform Additions](#kuneiform-additions)
    * [Kuneiform Changes](#kuneiform-changes)
  * [New Kuneiform Testing Framework](#new-kuneiform-testing-framework)
  * [Health Check Endpoint and JSON-RPC Methods](#health-check-endpoint-and-json-rpc-methods)
  * [Log Rotation and Archival](#log-rotation-and-archival)
  * [Expose CometBFT Prometheus Metrics](#expose-cometbft-prometheus-metrics)
  * [Extension Interfaces](#extension-interfaces)
* [Breaking Changes](#breaking-changes)
  * [Removal of the gRPC service and its HTTP API gateway](#removal-of-the-grpc-service-and-its-http-api-gateway)
  * [Breaking Changes and Deprecations in CLI Applications](#breaking-changes-and-deprecations-in-cli-applications)
  * [Breaking Changes to Kuneiform and SQL Rules](#breaking-changes-to-kuneiform-and-sql-rules)
  * [Breaking Changes to Transaction Execution](#breaking-changes-to-transaction-execution)
  * [Breaking Changes to Extension Interfaces](#breaking-changes-to-extension-interfaces)
* [Minor Features and Changes](#minor-features-and-changes)
  * [Minor New Features](#minor-new-features)
    * [CLI Apps](#cli-apps)
    * [Go SDK](#go-sdk)
    * [Parser](#parser)
    * [Node Internals](#node-internals)
  * [Minor Changes](#minor-changes)
* [Fixes](#fixes)
  * [Backported to v0.8](#backported-to-v08)
* [Testing](#testing)
* [Diff summary](#diff-summary)

## Important Upgrading Notes

Upgrading to this release requires a network migration. See the [network migration documents](https://docs.kwil.com/docs/node/network-migrations) for instructions on how to perform a network migration. Only upgrading from v0.8 is supported.

The application's protocol version is [bumped from 0 to 1](https://github.com/trufnetwork/kwil-db/commit/be7bd1e5e0a1c4ca4901d0a3342c46bd786df04e). This prevents nodes that are running different versions of Kwil from operating on the same network. The genesis file no longer includes a "version" section since this is determined by the application logic.

In certain cases, deployed schemas may not be compatible with v0.9. See the [Kuneiform Language](#kuneiform-language) section for details.

## Build Requirements and Dependencies

* The minimum required Go version is now 1.22. ([724fe4f](https://github.com/trufnetwork/kwil-db/commit/724fe4f2b2824befc5d21f4007a0b1cb6194244d))
* Builds and tests use Go 1.23. ([3aecf89](https://github.com/trufnetwork/kwil-db/commit/3aecf89a1ac1712d2a67b3a92568d24435fe11d9), [d50159e](https://github.com/trufnetwork/kwil-db/commit/d50159ea5cce1f12d6db09ec358dfd8591c1ef11))
* Update the consensus engine (CometBFT) to v0.38.12. ([89bad53](https://github.com/trufnetwork/kwil-db/commit/89bad530e49a4d6a573e4f3db896688bbfb482db))

## Security Policy

The supported versions are now as follows:

| Version | Supported |
| ------- | --------- |
| Latest beta or release candidate    | ✓        |
| v0.9.x  | ✓        |
| v0.8.x  | ✓        |
| < v0.8  | ❌        |

See [SECURITY.md](https://github.com/KwilLuke/kwil-db/blob/main/SECURITY.md) for details.

## Notable Features and Changes

### Zero Downtime Migrations

This release adds a new type of migration called a Zero Downtime (ZDT) migration. Unlike the existing offline process, ZDT migrations launch the new network prior to terminating the existing network. There is a migration period during which changes on the existing network are replicated on the new network. See the [docs](https://docs.kwil.com/docs/node/migrations/zero-downtime-migrations) for more information.

Note that the existing network must also support ZDT migrations. Since this is the first release of Kwil that supports such migrations, it cannot be used to go from a v0.8 network to a new v0.9 network. Future major releases will support ZDT migrations allowing this.

These changes also introduced two new transaction types: create resolution and approve resolution. These support generalized resolution processing, migration proposals being one such type.

Relevant code changes: [f290d6c](https://github.com/trufnetwork/kwil-db/commit/f290d6c7fa1545ebf11cb0f51eb0d1d815508400), [2f24aae](https://github.com/trufnetwork/kwil-db/commit/2f24aae2074f4e1aa11b9a87a95de8e6de818fe7), [0706798](https://github.com/trufnetwork/kwil-db/commit/0706798fa1ce4b912b84a6ef348c2ed39dd65cbb), [ba6e3e](https://github.com/trufnetwork/kwil-db/commit/ba6e3ea170e904ea7eb289f1cf83eb98c3e15d13), [d175b7f](https://github.com/trufnetwork/kwil-db/commit/d175b7f1bf11f2714634d033faa07e821a3b35fd)

To support changeset creation from the logical replication stream from PostgreSQL, the type system in the `pg` package was reworked. See the following relevant changes to the DB internals and exported types in `core/types`: [c983b22](https://github.com/trufnetwork/kwil-db/commit/c983b22b8c6f8b7b5a573a9827356d360adfe14a), [dfa1d8a](https://github.com/trufnetwork/kwil-db/commit/dfa1d8a50b1b19122b711519fc1d7c3af9c67fb8), [1a16488](https://github.com/trufnetwork/kwil-db/commit/1a16488b6ebc514c38361f52ad706034da10ed20), [4ece583](https://github.com/trufnetwork/kwil-db/commit/4ece58320c1437338daa055a4e574f9ac863476f)

**NOTE:** To support creation of changesets that enable detection and resolution of conflicts between the networks, all tables are now created with "full" replica identity". This changes "apphash" computation, so Kwil v0.9 cannot be installed in place over a v0.8 deployment's data.

### Data Privacy Modes

To support use cases where a network needs to maintain data privacy, this release adds two main access control functionalities at both the P2P layer and in the RPC service.

#### Node Peer Filtering Capability

To run a private network of nodes that only permits inbound P2P connections from certain peers, there is now a private mode that uses peer filtering to only allow certain nodes to connect. The filtering is based on Node ID, which cryptographically ensures the identity of the peer.

A node's whitelist is composed of the current validator set, nodes with active join requests with an approval from the operator, configured seed nodes and persistent peers, and any manually whitelisted peers. This latter case is used to support the addition of authorized sentry (non-validator) nodes to support other functions such as RPC providers, indexers, and seeders.

It is enabled in `config.toml` with the `chain.p2p.private_mode` setting. Whitelisted peers may be set in `config.toml` with `chain.p2p.whitelist_peers`, or managed at runtime with the `kwil-admin whitelist` subcommands.
This functionality was added in [559b027](https://github.com/trufnetwork/kwil-db/commit/559b0279eb10f04a331b4773fd3f0a785a035712).

#### Private RPCs and Authenticated Calls

A "private" RPC mode has been [added](https://github.com/trufnetwork/kwil-db/commit/6537114163397b94e4a1aa91513b78a9d45e35c9) with the following features:

* All call requests are authenticated. The Kwil clients handle this automatically when communicating with an RPC provider in private mode. A private key must be configured with the client in order to sign the call requests.
* Ad hoc SQL queries are prohibited.
* Transaction status query responses do not include the full transaction, which could potentially contain data that the user is not authorized to access.

For Go SDK users, note that this adds a signature field to the `core/client.CallMessage` type.

Related commits: [6537114](https://github.com/trufnetwork/kwil-db/commit/6537114163397b94e4a1aa91513b78a9d45e35c9), [559b027](https://github.com/trufnetwork/kwil-db/commit/559b0279eb10f04a331b4773fd3f0a785a035712), [177891a](https://github.com/trufnetwork/kwil-db/commit/177891a1498587e133959a10de475271d91b5e96)

### Ability to Rebrand Customized Binary Builds

Projects now have the ability to build custom-branded binaries that group in `kwild`, `kwil-cli`, and `kwil-admin`. These binaries can be given customized default configurations.

The global `cmd.BinaryConfig` structure is added to allow changing the project name and other details. Projects should set their configuration in an instance of the `cmd/custom.CommonCmdConfig` and then create their application's root command with the `NewCustomCmd` function.

This was added in [2aee07c](https://github.com/trufnetwork/kwil-db/commit/2aee07c3c0de5475aa601dd3627463f04c4bb18a) and [efc3af4](https://github.com/trufnetwork/kwil-db/commit/efc3af44798b8f3b7373e4500086af9466d7878f).

### Extension Hooks for Genesis Initialization and End-Block Actions

There are now hooks for extension authors to perform arbitrary actions:

* `GenesisHook` is a function that is run exactly once, at network genesis. It can be used to create initial state or perform other setup tasks.
  Any state changed or error returned should be deterministic, as all nodes will run the same genesis hooks in the same order.
  Named genesis hooks are registered with the `extensions/hooks.RegisterGenesisHook` function.
* `EndBlockHook` is a function that is run at the end of each block, after all of the transactions in the block have been processed, but before the any state has been committed.
  It is meant to be used to alter state, send data to external services, or perform cleanup tasks for other extensions.
  All state changes and errors should be deterministic, as all nodes will run the same end-block hooks in the same order.
  Extensions register named end-block hooks with the `extensions/hooks.RegisterEndBlockHook` function.

These changes were made in [79a1e9d](https://github.com/trufnetwork/kwil-db/commit/79a1e9d07b96b504804f138399b9ccc738ac223a).

### Kuneiform Language

There are several additions and changes to the Kuneiform language and SQL statement parsing rules. Review this section carefully and use the `kwil-cli utils parse` to identify changes in the validity of an existing Kuneiform schema prior to starting a network migration. Some schemas that were previously invalid may now be valid, and vice versa.

#### Kuneiform Additions

* Support array variable assignment to an existing array like `$arr[2] := 5;`. ([4ea9379](https://github.com/trufnetwork/kwil-db/commit/4ea9379752af786bb6c310ad2c06e7be89326bfb))
* Add the `@foreign_caller` contextual variable, which carries the name of the schema that called into another schema's procedure. This is empty for the outermost (direct) call. ([714a1b9](https://github.com/trufnetwork/kwil-db/commit/714a1b9f3f5fcf02fa5c71d1efe59841d79ff0a6))
* Add the `parse_unix_timestamp` and `format_unix_timestamp` functions, whose formatting rules match PostgreSQL `to_timestamp` formatting. ([5a5f36d](https://github.com/trufnetwork/kwil-db/commit/5a5f36dc427d4954e86190520582251a5d783aee))
* Add the `notice` function, which can be used to emit transaction logs. **NOTE:** In addition to being a Kuneiform change, this affects consensus as all nodes must handle and record these logged messages faithfully. ([8e8e09c](https://github.com/trufnetwork/kwil-db/commit/8e8e09cd79d5e5869323f53c3b96d8bc41f34056))
* Add the `@block_timestamp` variable, which contains the UNIX epoch time stamp of the block that is processing the transaction. It is 0 if not in a transaction. ([f684fd2](https://github.com/trufnetwork/kwil-db/commit/f684fd2b8128b6fcb2fc6b90bac723aa803be710))
* Add the `@authenticator` variable, which prints the name of the type of authenticator used to sign the transaction. For example, `"secp256k1_ep"`. ([0f7de25](https://github.com/trufnetwork/kwil-db/commit/0f7de25b533b20bf4b7174e20d1832f21f0d76f9))
* Add the `array_remove` function, and array slicing. For example, `$my_arr[1:3], $my_arr[1:], $my_arr[3]`. [c08b6c3](https://github.com/trufnetwork/kwil-db/commit/c08b6c333c911e0cda298a41d668c56567710fd2)
* Add the `array_agg` function. ([55caa0e](https://github.com/trufnetwork/kwil-db/commit/55caa0ea629545aa6aa7535b189d274284a273e7))

#### Kuneiform Changes

In addition to the newly added Kuneiform functionality, there are several notable changes to Kuneiform parsing and SQL rules that have the potential to change how procedures from previous release are executed with this version. Some of these are merely fixes, but may change execution regardless:

* A reserved delimiter, `$kwil_reserved_delim$`, is now prohibited in procedures. ([48d8f65](https://github.com/trufnetwork/kwil-db/commit/48d8f6515ad16e030027846efbb7aed706de508e))
* Equality and assignment operators take a higher precedence than arithmetic operators. ([2e1507d](https://github.com/trufnetwork/kwil-db/commit/2e1507d8093daa23eddb03b7caaace3d3397177c))
* A bare `JOIN` now defaults to `INNER JOIN`. Previously it was required to specify the join type. ([ce85f23](https://github.com/trufnetwork/kwil-db/commit/ce85f230dab3090dabcde64e2f80f30fd1fb1903)).
* The common table expression (CTE) syntax no longer requires users to specify their return columns. For example, the following is now acceptable: `WITH cte AS (SELECT id FROM users) SELECT * FROM cte;` ([22bdf85](https://github.com/trufnetwork/kwil-db/commit/22bdf85f41cb221107eaccc34a05d06d3377ebd3))

### New Kuneiform Testing Framework

A new testing framework for validating a Kuneiform schema prior to validation was added in [3893313](https://github.com/trufnetwork/kwil-db/commit/38933131ade2521fef2a47591c070ee1dad91b66). The use case is for Kwil users who want to set up tests for their schemas that can run locally, avoiding the need to wait for consensus or create unnecessary network utilization.

There are two ways to use it:

1. `testing` package: Users can import the testing package to write their own tests in Go. This gives a lot of flexibility, as they can code any sort of function they want against the engine.
2. `kwil-cli utils test` command: Users can use `kwil-cli` to run tests. Tests can be defined in JSON, where users can specify the schemas to deploy, seed data, and execute actions/procedures and check the results.

The tests can be configured to talk to any Postgres connection, or users can tell the test to setup and teardown a test container.

See the [docs](https://docs.kwil.com/docs/kuneiform/testing/intro) for more information.

Related git commits: [3893313](https://github.com/trufnetwork/kwil-db/commit/38933131ade2521fef2a47591c070ee1dad91b66), [a2d2fd8](https://github.com/trufnetwork/kwil-db/commit/a2d2fd856badc18f96aafd9ce3c4535156e03708), [3062a33](https://github.com/trufnetwork/kwil-db/commit/3062a33519f97687ef4fb7ad8d1390da81118bff), [7ff2536](https://github.com/trufnetwork/kwil-db/commit/7ff2536b352a607da3e1539ca0b4fb267eb02f37)

### Health Check Endpoint and JSON-RPC Methods

This release [adds new health checks](https://github.com/trufnetwork/kwil-db/commit/7d5bc366f48e9d3e7ab770bddad9f729e9a2b6e1) for `kwild`. These are added to support common generic health checks services that have limited configuration i.e. only the http status code is considered.

* `GET /api/v1/health/{svc}`

  This endpoint returns the health status of the service in {svc}. For example, `"/api/v1/health/user".`
  The response code is 200 if healthy, otherwise 503 (unavailable).
  The response body is JSON serialization of a HealthResponse type in the corresponding `core/rpc/{svc}` Go package.

* `GET /api/v1/health`

  This RESTish endpoint returns a `core/rpc/json.HealthResponse`.
  The code is 200 if all registered services report healthy and
  503 if any of the services are not healthy.
  This response body includes a fingerprint boolean (`"kwil_alive"`)
  and the aggregate health (`"healthy"`), which corresponds to the response code.
  There is a "services" field that is an object keyed by service
  names. The individual service health status objects are those
  returned by the service-specific `"/api/v1/health/{svc}"` endpoint described above.

* `rpc.health` JSON-RPC method. This method in the reserved `rpc` namespace corresponds to the aggregate health endpoint.

* `user.health` and `admin.health` JSON-RPC methods. These correspond to the `/api/v1/health/user` and `/api/v1/health/admin` endpoints.

Reminder: The HTTP server on port 8484, which is used for user facing RPCs, has only the "user" and "function" services registered. Thus, a request for "admin" health on this server will result in a 404 or method not found. The admin server, which is on a unix socket by default or TCP port 8485, will have all of "user", "function", and "admin" health statuses reported. While it is less likely to have a health check from a cloud provider for this secure server, it is available for secure monitoring setups on the host machine.

### Log Rotation and Archival

Rotation and archival of log file segments now happens automatically. Any configured log file, such as the default `kwild.log`, will be compressed into a sequenced gzip file, and a new empty log file will begin.

The new setting `--log.file-roll-size` is a number in KB at which the current log file will be compressed, named the next gz in the sequence, and a new uncompressed log file started.

For example, when an uncompressed `kwild.log` file reaches the configured size threshold, it will create "kwild.log.1.gz", and kwild.log be cleared. When it reaches the threshold again, it will create "kwild.log.2.gz" and so on.

```plain
-rw-r--r--   1 usr grp   18433 Sep 12 11:43 kwild.log
-rw-r--r--   1 usr grp    3296 Sep 11 17:50 kwild.log.1.gz
-rw-r--r--   1 usr grp    3596 Sep 11 17:52 kwild.log.2.gz
```

The default threshold is 100MB.

This was added in [b9e424a](https://github.com/trufnetwork/kwil-db/commit/b9e424acf185f1ed4793d1e1119d1c669f07b5ec).

### Expose CometBFT Prometheus Metrics

A [prometheus metrics server](https://github.com/trufnetwork/kwil-db/commit/162cabe6306b9951bee88e31138f1dced83c1fc3) may now be enabled with `kwild` by setting `instrumentation.prometheus = true` in the new `[instrumentation]` setting of the config file.

The default listen address is `"0.0.0.0:26660"`, but may be configured with `instrumentation.prometheus_listen_addr`.

Presently this only includes metrics with the "cometbft" and "go" namespaces. In future releases, this will be expanded with additional metrics in the "kwild" namespace for application related data.

### Extension Interfaces

There are several changes and improvements to extension interface.

The context structures accepted by several functions have been reworked. ([c55b5f4](https://github.com/trufnetwork/kwil-db/commit/c55b5f4056f99dbf71d9a5803b37bb8feedfcce4))

The node configuration packages have been reorganized and partially exposed to extension authors. ([efc3af4](https://github.com/trufnetwork/kwil-db/commit/efc3af44798b8f3b7373e4500086af9466d7878f))

See [the corresponding section](#breaking-changes-to-extension-interfaces) on breaking changes for guidance on upgrading.

## Breaking Changes

### Removal of the gRPC service and its HTTP API gateway

The gRPC service and the HTTP (REST) gateway server that were deprecated in v0.8 in favor of a JSON-RPC service are now removed with [c5d0127](https://github.com/trufnetwork/kwil-db/commit/c5d01276b9d86252e4cd9b6de3efca5d8c6a4a0d) and [5e91c02](https://github.com/trufnetwork/kwil-db/commit/5e91c02dec66ac038a828674c60307caaa96c456).

* removed the `proto` git submodule
* removed the generated types and service code from `core/rpc/protobuf`
* removed the gRPC "txsvc" implementation and server from `internal/services/grpc{,_server}`
* removed the gRPC gateway from `internal/services/grpc_gateway`
* removed the generated client for the http gateway from `core/rpc/http`
* removed the wrapper client for the http gateway from `core/rpc/client`
* cleaned out the `Taskfile.yml` and remove `Taskfile-pb.yml`
* updated CI and other scripts
* updated Dockerfiles and compose definitions
* updated cmd apps and their config
* `go mod tidy` all modules (`task tidy`)
* updated integration and acceptance test framework

### Breaking Changes and Deprecations in CLI Applications

* The `kwil-admin peer` command is deprecated, which, like the `init` command, initializes the configuration for a new node. The equivalent functionality of the `peer` command is now achieved with the `init` command by using the `--genesis` flag to provide a genesis.json file to use. In addition, the `init` command now accepts all of the node's flags to specify settings to use in the generated `config.toml`. ([d1cf754](https://github.com/trufnetwork/kwil-db/commit/d1cf754c6be8c8a785487c36d7d21155a0a83033)

* With `kwil-cli`, the `--action` flag used with the `database execute` and `database call` commands is now deprecated. Since this is a required input, it is now a positional argument (just omit `--action`). ([852df6a](https://github.com/trufnetwork/kwil-db/commit/852df6a34cb14c9cb43e6bfb2f8e087cf6154798))

* With `kwild`, the `rpc_req_limit` setting has been renamed to `rpc_max_req_size` to reflect that it is a size limit rather than a rate limit. `rpc_req_limit` is now deprecated. ([56a765d](https://github.com/trufnetwork/kwil-db/commit/56a765d414aed37d183cbe8dc70f9ef7e74793d2))

* The `reset` and `reset-state` subcommands of `kwil-admin setup` are reworked to also reset the PostgreSQL database. The `reset-state` command only resets PostgreSQL, while `reset` also deletes the data folders in the application's root directory. ([2f6b18e](https://github.com/trufnetwork/kwil-db/commit/2f6b18ed1c08ddfc255542631ed9f23bbee3b6b0), [e876a07](https://github.com/trufnetwork/kwil-db/commit/e876a07460e453642a1353d76e096b5a0cbf0175))

* The `kwil-admin migrate genesis-state` command's `--root-dir` flag is renamed to `--out-dir`, and the default is now `~/.genesis-state` so as not to accidentally overwrite an existing genesis file if node is running locally. ([5dc5f27](https://github.com/trufnetwork/kwil-db/commit/5dc5f2727928c46c289beb04d731196bd5e807f9))

### Breaking Changes to Kuneiform and SQL Rules

Please note the changes to Kuneiform and the parser in [Kuneiform Changes](#kuneiform-changes). Existing schemas that are migrated from an older version of kwild may have functional changes.

### Breaking Changes to Transaction Execution

* If a validator remove transaction targets a public key that is not in the validator set, the transaction fails (non-zero result code) rather than silently doing nothing. Integration tests were already designed with this behavior in mind, but did not query status of the removal transaction on a node where it was executed. This is a breaking change to applications the expected the previous outcome. ([b8a52a3](https://github.com/trufnetwork/kwil-db/commit/b8a52a3445e60052d3e6cb809cff3bf682aa9f9a))

### Breaking Changes to Extension Interfaces

* Removed the transaction-specific information from `common.ExecutionData` to avoid duplication with `common.TxContext`. Changed the `common/Engine.CreateDataset()` and `common/Engine.DeleteDataset()` methods to take a transaction context as the first parameter, replacing the `context.Context` and removing the fourth parameter `common.TransactionData` which previously contained the transaction data. Changed the `common/Engine.Procedure()` and `common/Engine.Execute()` methods to take a transaction context as the first parameter, replacing the `context.Context`. Extensions that previously passed transaction information to any of the above methods using either `common.TransactionData` or `common.ExecutionData` should now pass the information to each methods' first parameter `common.TxContext`. `common.Route.PreTx()` and `common.Route.InTx()` methods now use `common.TxContext` as the first parameter, instead of `context.Context`.
([c55b5f4](<https://github.com/trufnetwork/kwil-db/commit/c55b5f4056f99dbf71d9a5803b37bb8feedfcce4>)).

## Minor Features and Changes

### Minor New Features

#### CLI Apps

* Add the `kwil-cli utils dbid` command to generate a DBID for a given schema name and deployer. ([2214f45](https://github.com/trufnetwork/kwil-db/commit/2214f45a672af35f758a40ef3ecbb5f2c30d3e4d))

* Enable setting and providing a password for the admin RPC service with `kwil-admin`. This must be used with a secure transport layer (either TLS, a secure UNIX or loopback TCP socket). If the service is listening on a non-loopback TCP address, TLS is automatically enabled unless the `admin_notls` setting is provided to override that behavior. ([898430e](https://github.com/trufnetwork/kwil-db/commit/898430e7bae5f394170f25a720a71b77e631f55a))

* Add a configurable request size limit to `kwild`: `app.rpc_req_limit`. The default is 4,200,000 bytes. If the network's genesis config sets max transaction size larger
than this limit, kwild warns on startup. ([a0ac88c](https://github.com/trufnetwork/kwil-db/commit/a0ac88ced240dd2ba7957080dae6fd624d9aa35f))

* Add the `kwil-cli utils generate-key` command, which generates a new secp256k1 private key and displays the corresponding public key and identifier. ([c059786](https://github.com/trufnetwork/kwil-db/commit/c05978694513b890b19e95f09b71ef4445a779dd))

* Add the `--genesis-state` flag to `kwil-admin init` to load a snapshot file into the root directory and set `genesis_state` in the generated config file to the snapshot file. ([8974481](https://github.com/trufnetwork/kwil-db/commit/8974481305712aefc174c9a2fd6f42a59e3c49cd))

#### Go SDK

* Add the ability for the Go client in `core/client` to skip the initial remote chain ID verification step. This can be used to reduce repeated `chain_info` requests with KGW. ([8c2e545](https://github.com/trufnetwork/kwil-db/commit/8c2e545df81684567b4dd124320f432490d9f671))

#### Parser

* Add the `parse.ParseSQLWithoutValidation` function to allow parsing raw SQL without validation against schema-context. ([b494977](https://github.com/trufnetwork/kwil-db/commit/b49497759d3acef7b38607492833633d6be00804))

#### Node Internals

* Give the ABCI application the ability to remember various consensus variables that are specific to the Kwil blockchain application. This also improves the ability to pass important contextual information to the internal execution engine as well as registered extensions. (TODO: Cross reference the final state of context structs elsewhere in this doc.) ([dd5719a](https://github.com/trufnetwork/kwil-db/commit/dd5719a7b8f16949375d06a782aa646d30f6d165)), ([9997f24](https://github.com/trufnetwork/kwil-db/commit/9997f2409e376ff1ac254fdbf469e87609265f67)), ([2ee5b21](https://github.com/trufnetwork/kwil-db/commit/2ee5b21b1ac95473cbaf80a366304e11a854ab02))

* The internal `pg` package has new functions and methods to allow pre-instantiating variables for scan targets. There are several corresponding updates to types in `core/types` to support scanning and valuing with SQL queries. ([3aecf89](https://github.com/trufnetwork/kwil-db/commit/3aecf89a1ac1712d2a67b3a92568d24435fe11d9))

* The foundation for SQL cost estimation has been added, although it does not affect users of this Kwil release. See [e7ac91f](https://github.com/trufnetwork/kwil-db/commit/e7ac91f2f1af2bae82da4345d748a8f0dd42b1f2) and [559b027](https://github.com/trufnetwork/kwil-db/commit/559b0279eb10f04a331b4773fd3f0a785a035712).

### Minor Changes

* The Kwil version is now written to the configured log file in addition to standard out on node startup. ([4c84ae8](https://github.com/trufnetwork/kwil-db/commit/4c84ae84de075ce7ea50f31524a110ac346f24fb))
* Update SQL railroad diagrams ([6a93517](https://github.com/trufnetwork/kwil-db/commit/6a93517440dbeae44bb17ccc2edcd2be79927346), [8e061a7](https://github.com/trufnetwork/kwil-db/commit/8e061a75413bd445b28f93c44907a096e20a0d61))
* Change the default mempool size limit to 50,000 KB, and the default mempool cache size to 60,000 KB. ([c32cf80](https://github.com/trufnetwork/kwil-db/commit/c32cf807897ad4bb183fb4c44b55672cdafe29b4))
* Silence the logging of errors in user dataset queries, which are not application logic errors. ([23a1832](https://github.com/trufnetwork/kwil-db/commit/23a18328b66a1dc7f7ae3e2fbf39c4da7300c51c))
* The help output from `kwild -h` no longer reports default durations as are actually not known when displaying usage for CLI flags. ([3613af5](https://github.com/trufnetwork/kwil-db/commit/3613af5f033ae0946e6b8be5f6470c31b3018fb9))
* Add a 10 sec timeout during statesync when requesting a header from the configured RPC provider. This prevents an possible infinite hang if the provider is misconfigured. ([af55d9c](https://github.com/trufnetwork/kwil-db/commit/af55d9c896743a6f3e54556c7cf384199e4b3085))
* Suggest a 4 character tab width in `.editorconfig`. ([4702a91](https://github.com/trufnetwork/kwil-db/commit/4702a91e5f5f99e4cc4f4491ba5013d59178e7ef))
* Go Extension authors executing procedures no longer need to prefix the variable names with a dollar sign (`$`). For example, when inserting an entry into the arguments map, you may do `params["id"] = "me"` in addition to `params["$id"] = "me"`. ([51cecdc](https://github.com/trufnetwork/kwil-db/commit/51cecdc8b01fc35b9930adedef3e46b855042e1a))
* If snapshot creation is enabled, a snapshot is now created immediately on startup in any of the following cases: none exists, it is height 1, or blocksync is done. Subsequent snapshots are still created when the height is a multiple of the configured `app.snapshots.recurring_height` setting. [b4da094](https://github.com/trufnetwork/kwil-db/commit/b4da094c333987207a75832a5fd5b181bb307943)
* An `ActionCall` is no longer enumerated as a valid transaction payload since they should never appear in a blockchain transaction, only in a `CallMessage`. [9f4cf81](https://github.com/trufnetwork/kwil-db/commit/9f4cf816bd1f4ed81d6bb2ceff733002efde5724)
* With `kwil-cli database call` when using `--output json`, if the call execution has an error, the empty `"result"` field will be set to `null` instead of `""`. This is done to resolve cryptic errors in the testing framework, but it is also more correct as the result type is not universally a string. [355b77](https://github.com/trufnetwork/kwil-db/commit/355b772033567f7c24ccd3c936e9ed5f99ab0ca8)
* Discrepancies between configured resolutions and compiled-in resolution support is now detected. This prevents situations where an existing deployment contains resolutions that may not exist in a different Kwil version. [bcf9592](https://github.com/trufnetwork/kwil-db/commit/bcf9592d203e53ccd24450226cee7ab0db06a705)
* A sanity check is added at the beginning of statesync to ensure the local database is fresh before restoring a snapshot. The presence and versions of the `psql` and `pg_dump` tools are also checked. ([24addc7](https://github.com/trufnetwork/kwil-db/commit/24addc74ed5cf4814652b491a0b9b4220c5d0ca5))
* The default validator join expiry (a genesis parameter) is changed to 1 week (about 100800 blocks for 6 second blocks). This default is written by the `kwil-admin setup` commands. ([8271fae](https://github.com/trufnetwork/kwil-db/commit/8271fae3f801adade399f9004da804d1ec361c58))
* The client example application in `core/client/example` is updated to work with networks with or without gas enabled. A faucet URL may also be set to automatically request funds if needed. Finally, if a private key is not specified, it will generate one. These changes are meant to make example application easier to run, although they are not realistic situations on most production networks. ([bd3be25](https://github.com/trufnetwork/kwil-db/commit/bd3be258856b786d06b6b939f4d4d8afa420df6f))

## Fixes

* Repeated validator misbehavior in consecutive blocks is handled more gracefully, avoiding a consensus failure. ([0538e2](https://github.com/trufnetwork/kwil-db/commit/0538e200c3953a3d7b05a586752bca9f3d67e2ae))
* Snapshots no longer incorrectly remove certain statements from procedure bodies. ([51cfe56](https://github.com/trufnetwork/kwil-db/commit/51cfe56c90408ab6368aec6dbfd733b5573bc3bf))
* Improve errors returned by parser to improve error messages on the CLI and web IDE. ([0fd8e09](https://github.com/trufnetwork/kwil-db/commit/0fd8e09d5d931983927f73ab644073cb42b18349))
* Numerous other parser error fixes. ([fcde95c](https://github.com/trufnetwork/kwil-db/commit/fcde95cbdb132c2722d5bee0e1191c7df9172536), [09d647c](https://github.com/trufnetwork/kwil-db/commit/09d647c8bfb2c717448b9cb474989c03e839edd2)) @brennanjl: call out any of these in kuneiform breaking changes?
* The `decimal.(*Decimal).Cmp` method no longer modifies the receiver. ([a96d108](https://github.com/trufnetwork/kwil-db/commit/a96d10816726aa95a651225627078cc2fe5c91f3))
* Properly fail to start up if the configured trusted snapshot providers are invalid. This avoids a confusing `trusted_height is required` error message on startup. ([096043f](https://github.com/trufnetwork/kwil-db/commit/096043f08f1747c730c0df6efcabadf71190ed70))
* Allow the `generate_dbid` function to be used in procedures with the assignment operator. For example, `$dbid := generate_dbid('aa', decode('B7E2d6DABaf3B0038cFAaf09688Fa104f4409697', 'hex'));`. ([8553f23](https://github.com/trufnetwork/kwil-db/commit/8553f23178fb0e179d4b13f587d57af10f33bd63))
* Remove inaccurate documentation for a non-existent `--peer` flag with the `setup peer` command. The `--chain.p2p.persistent-peers` flag should be used. ([a499074](https://github.com/trufnetwork/kwil-db/commit/a4990748fb08699f21e23d0f34f0c743d64bee75))
* The `kwil-admin setup testnet` command no longer incorrectly overrides defaults for validator join and vote expiries. [cc87c18](https://github.com/trufnetwork/kwil-db/commit/cc87c18075e8814fc1344bc3d2414533991a9e4d)

### Backported to v0.8

* Prevent creating a decimal type where the exponent is greater than precision. ([9ecbbcd](https://github.com/trufnetwork/kwil-db/commit/9ecbbcd809903e42b92ff3dda044028f13594863))
* Fix parsing of SQL expressions with `LIMIT` and `ORDER`. This was a regression in the v0.8 release that was fixed in a patch release. ([412791f](https://github.com/trufnetwork/kwil-db/commit/412791f638989bfe117007b30f9acef928ea4067))
* Prevent execution errors in resolution functions from halting the node. (([412791f](https://github.com/trufnetwork/kwil-db/commit/412791f638989bfe117007b30f9acef928ea4067)), ([d259784](https://github.com/trufnetwork/kwil-db/commit/d2597840320038b3e09711f47915fe674b1c5682)))
* Various fixes to statesync, most notably, preventing node halt in the case of failure to apply a snapshot chunk. ([a02ee22](https://github.com/trufnetwork/kwil-db/commit/a02ee22679b36b9635e8592ee3a62946e5b07e8b))
* Allow configuring extensions via flags. ([87d45cc](https://github.com/trufnetwork/kwil-db/commit/87d45cc8763d6f06e39b0f0d85d055be00cac35b))
* In the internal voting store, fix a unique index erroneously including resolution body, which need not be unique. ([60d8e6d](https://github.com/trufnetwork/kwil-db/commit/60d8e6dae9d401e55221cf52618682d8acaf5513))
* Pass a cancellable context into an internal function in the PostgreSQL logical replication system. ([2dbb725](https://github.com/trufnetwork/kwil-db/commit/2dbb7258ce1bd878c72349a9d7590750c6f35105))
* Properly set various configurable file paths to be relative to the root directory if not absolute paths. ([3785397](https://github.com/trufnetwork/kwil-db/commit/37853971a189e67f02e66bd4e570cf9ca9ae8152))
* Remove a duplicate log output path for "kwild.log" from the config generated by `kwil-admin`. ([f6c471b](https://github.com/trufnetwork/kwil-db/commit/f6c471b9b1c4576a29339f7d636f9d52c964f70d))
* Fix a parser panic found when parsing a procedure that expects a return but does not return anything. ([2d85b4c](https://github.com/trufnetwork/kwil-db/commit/2d85b4c32a5b1e3ffc3d41fd1398e3cff6482ff0))
* Fix a parser bug in generation of unary expressions that lacked a space. ([5ef667b](https://github.com/trufnetwork/kwil-db/commit/5ef667be4b0e7f37b215fe70793eac8ab08922b1))
* Remove incorrect handling of unsupported UUID types in the parser. ([99ea751](https://github.com/trufnetwork/kwil-db/commit/99ea751131a70fe027d6f0515ea1bb188e0bdd14))
* Give the parser the ability to gracefully handle and report unknown columns in indexes and foreign keys ([e2f6708](https://github.com/trufnetwork/kwil-db/commit/e2f67088edf59bb8959354c0248ab5de715b435b)).
* Allow the parser to work with parameterized SQL (containing `$var` placeholders). ([fd23ff7](https://github.com/trufnetwork/kwil-db/commit/fd23ff701fab945d18241b67200ea31f38316ac8))
* Graceful handling of failed snapshot creation. ([77b08dd](https://github.com/trufnetwork/kwil-db/commit/77b08dd90635c2ebd97034c71530c2cdc4feef10))
* Fix an inadequate internal buffer in both snapshot creation and statesync. ([c674ee9](https://github.com/trufnetwork/kwil-db/commit/c674ee925e54a8d23682ec9f0384869cd0643cc8))
* Fix incorrect SQL generation for actions with inline statements with typecasts for ambiguous types. ([90f8b05](https://github.com/trufnetwork/kwil-db/commit/90f8b0534d313d70bb72d3b33ef50f3de02611e7))
* Fix whitespace handling ([c067834](https://github.com/trufnetwork/kwil-db/commit/c067834f114037377921fcf1753d358a3088dce7))
* Prevent adding a stray semicolon at the end of statements that end in spaces. ([c067834](https://github.com/trufnetwork/kwil-db/commit/c067834f114037377921fcf1753d358a3088dce7))
* During statesync, query for the latest snapshot height instead of the chain height when determining a trusted height to use. ([d155a3f](https://github.com/trufnetwork/kwil-db/commit/d155a3f145f10838f1ece6a44c99adb21150dc18))

## Testing

* Include procedures in the `stress` tool. ([6502e30](https://github.com/trufnetwork/kwil-db/commit/6502e304e51517b1fbb8135a7e7f2f4ac49cd9ae))
* More strict type assertions in acceptance tests. ([65d268c](https://github.com/trufnetwork/kwil-db/commit/65d268cb248996a74a418024cae15c60cd69e7aa))
* Integration tests now include scenarios including node restarts. ([8974481](https://github.com/trufnetwork/kwil-db/commit/8974481305712aefc174c9a2fd6f42a59e3c49cd))
* The network migration tests now expose the user and admin RPC services to the host machine on unique TCP ports. ([65f74c8](https://github.com/trufnetwork/kwil-db/commit/65f74c8fe5a8829a3ed5b47b625e929bea24102e))
* The Docker networks generated by integration tests now specify a subnet that is believed to not overlap with subnets already in used by the Github Actions runner. ([bd49a7b](https://github.com/trufnetwork/kwil-db/commit/bd49a7bdad243f454ba5fa430c29af51df58e8d8))
* The release CI workflow is updated for v0.9. ([e39483c](https://github.com/trufnetwork/kwil-db/commit/e39483c271639e2edec68963220875a711ba83fc) and [ae1129b](https://github.com/trufnetwork/kwil-db/commit/ae1129b91b8f0ce9a9b9bea2ac8bd3a04577837f))

## Diff summary

<https://github.com/trufnetwork/kwil-db/compare/v0.8.1...v0.9.0>

519 changed files with 33,853 additions and 24,856 deletions
