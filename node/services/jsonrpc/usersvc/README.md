# User Service Tests

This directory contains tests for the JSON-RPC user service, including withdrawal proof functionality.

## GetWithdrawalProof Tests

### Overview

The `GetWithdrawalProof` tests (`service_withdrawal_test.go`) validate the withdrawal proof generation for the ERC20 bridge. These tests use the `//go:build kwiltest` build tag to separate them from regular unit tests.

### Running the Tests

Tests can be run using standard Go test commands:

```bash
# Run all withdrawal proof tests
go test ./node/services/jsonrpc/usersvc -tags=kwiltest -run "^TestGetWithdrawalProof" -v

# Run a specific test
go test ./node/services/jsonrpc/usersvc -tags=kwiltest -run "^TestGetWithdrawalProof_ValidRequest$" -v
```

Available tests (11 total):
- `TestGetWithdrawalProof_ValidRequest`
- `TestGetWithdrawalProof_InvalidEpochID`
- `TestGetWithdrawalProof_InvalidRecipientFormat`
- `TestGetWithdrawalProof_EpochNotFound`
- `TestGetWithdrawalProof_RecipientNotInEpoch`
- `TestGetWithdrawalProof_PendingEpoch_NotEnded`
- `TestGetWithdrawalProof_PendingEpoch_NotConfirmed`
- `TestGetWithdrawalProof_StatusTracking_DefaultReady`
- `TestGetWithdrawalProof_StatusTracking_Ready`
- `TestGetWithdrawalProof_StatusTracking_Claimed`
- `TestGetWithdrawalProof_StatusTracking_Pending`

### Prerequisites

1. **PostgreSQL must be running**:
   ```bash
   task pg
   ```

2. **Test database must exist**:
   The tests use database `kwil_test_db` with user `kwild` and password `kwild`.

### Withdrawal Status Tracking

The `withdrawals` table tracks withdrawal claim status across multiple blockchains (Ethereum, Polygon, Arbitrum, etc.). This allows `GetWithdrawalProof` to return accurate status information about whether a withdrawal has been claimed on the external blockchain.

#### Status Flow

- **`pending`**: Epoch not finalized yet, withdrawal cannot be claimed
- **`ready`**: Epoch finalized, user can claim withdrawal on blockchain (default if no tracking record exists)
- **`claimed`**: User has claimed withdrawal on blockchain, `eth_tx_hash` contains the transaction hash

#### Multi-Chain Support

Chain information is determined through the epoch relationship:
```text
withdrawals → epochs → reward_instances → chain_id
```

This design allows a single `withdrawals` table to track claims across all supported chains without storing chain information redundantly.

#### Response Format

The `GetWithdrawalProof` JSON-RPC response includes:
```json
{
  "status": "ready|claimed|pending",
  "eth_tx_hash": "0xabc123..." // null if not claimed
  // ... other fields (merkle proof, signatures, etc.)
}
```

#### Manual Testing

You can manually test status tracking by inserting records into the `withdrawals` table:

```bash
# 1. Get a valid epoch_id and recipient from an existing epoch
PGPASSWORD=kwild psql -h localhost -p 5432 -U kwild -d kwil_test_db -c \
  "SELECT encode(e.id, 'hex') as epoch_id, encode(r.recipient, 'hex') as recipient
   FROM kwil_erc20_meta.epochs e
   JOIN kwil_erc20_meta.epoch_rewards r ON e.id = r.epoch_id
   WHERE e.confirmed = true
   LIMIT 1;"

# 2. Test default "ready" status (no record exists)
curl -X POST http://localhost:8484/rpc/v1 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "user.get_withdrawal_proof",
    "params": {
      "epoch_id": "<epoch_id_from_step_1>",
      "recipient": "0x<recipient_hex_from_step_1>"
    },
    "id": 1
  }'
# Response: {"status": "ready", "eth_tx_hash": null, ...}

# 3. Insert a "ready" status record
PGPASSWORD=kwild psql -h localhost -p 5432 -U kwild -d kwil_test_db -c \
  "INSERT INTO kwil_erc20_meta.withdrawals (epoch_id, recipient, status, created_at, updated_at)
   VALUES (decode('<epoch_id>', 'hex'), decode('<recipient_hex>', 'hex'), 'ready',
           extract(epoch from now())::int8, extract(epoch from now())::int8);"

# 4. Call GetWithdrawalProof again
# Response: {"status": "ready", "eth_tx_hash": null, ...}

# 5. Update to "claimed" with transaction hash
PGPASSWORD=kwild psql -h localhost -p 5432 -U kwild -d kwil_test_db -c \
  "UPDATE kwil_erc20_meta.withdrawals
   SET status = 'claimed',
       tx_hash = decode('abc123def456abc123def456abc123def456abc123def456abc123def456abc1', 'hex'),
       block_number = 12345678,
       claimed_at = extract(epoch from now())::int8,
       updated_at = extract(epoch from now())::int8
   WHERE epoch_id = decode('<epoch_id>', 'hex')
     AND recipient = decode('<recipient_hex>', 'hex');"

# 6. Call GetWithdrawalProof again
# Response: {"status": "claimed", "eth_tx_hash": "0xabc123def456...", ...}
```

**Note**: In production, the `withdrawals` table will be automatically populated by a blockchain event monitor (Phase 2). For now (Phase 1 MVP), status tracking can be manually tested using the commands above.

### Test Architecture

The tests use several strategies to manage singleton state:

1. **Shared Database**: Single `pg.DB` instance created once with `sync.Once`
2. **Schema Initialization**: Schema created exactly once across all tests via `initSchemaOnce()`
3. **Test Setup**: `setupTest()` cleans database and resets singletons before each test
4. **Automatic Cleanup**: Tests clean up data at start to prevent interference from previous runs

Key components:

- **`getTestDB(t *testing.T)`**: Returns shared database connection
- **`initSchemaOnce(t *testing.T)`**: Creates ERC20 schema exactly once
- **`setupTest(t *testing.T)`**: Cleans database and resets singleton state before each test
- **`resetTestSingletons()`**: Resets extension singleton state
- **`cleanupTestData(t, db)`**: Removes test data with retry logic for transaction conflicts
- **`setupTestService(t, db, engine)`**: Creates service with 30s timeout
- **`setupTestEpochData(t, ctx, app, suffix)`**: Creates test epochs and rewards

### CI Integration

These tests are included in CI as part of the standard test suite with the `kwiltest` build tag.

### Legacy Script

The `run_withdrawal_tests.sh` script is provided for historical compatibility and runs each test individually with database cleanup between tests. However, **tests can now run together using standard Go test commands** thanks to improved cleanup and singleton management.

```bash
# Legacy script (optional, but still works)
./node/services/jsonrpc/usersvc/run_withdrawal_tests.sh
```
