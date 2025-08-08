# Blacklist CLI Testing Guide

This guide provides testing instructions for the blacklist CLI commands and validates the blacklist-only mode fix that allows peer blacklisting without requiring private mode.

## Overview

The blacklist functionality enables node operators to:
- Block connections from specific peers (temporary or permanent)
- Remove peers from blacklist to restore connections
- List all blacklisted peers with details

**Critical Fix**: This guide validates that blacklist functionality works without private mode, preventing the nil pointer crashes that occurred when `blacklist.enable=true` but `private_mode=false`.

## Prerequisites

### Build kwild Binary
```bash
go build -o kwild ./cmd/kwild
```

### Start PostgreSQL
Use the official Kwil PostgreSQL Docker image for testing:
```bash
# Single node testing
docker run -d -p 5440:5432 --name kwil-postgres-test \
  -e "POSTGRES_HOST_AUTH_METHOD=trust" kwildb/postgres:latest

# Multi-node testing  
docker run -d -p 5440:5432 --name kwil-postgres-node0 \
  -e "POSTGRES_HOST_AUTH_METHOD=trust" kwildb/postgres:latest
docker run -d -p 5441:5432 --name kwil-postgres-node1 \
  -e "POSTGRES_HOST_AUTH_METHOD=trust" kwildb/postgres:latest
```

### Generate Test Network
```bash
./kwild setup testnet -v 2 -u --out-dir testnet-blacklist \
  --db-owner 0x742d35Cc6635C0532925a3b8D401E6E0985F5C07
```

## Test Scenarios

### 1. Blacklist-Only Mode Startup Test

**Objective**: Verify node starts without crashes when blacklist enabled without private mode.

**Setup Configuration**:
First, enable blacklist and disable private mode in the config file:
```bash
# Edit the config file
vim ./testnet-blacklist/node0/config.toml

# Add these configuration sections:
[p2p]
private = false

[p2p.blacklist]
enable = true
```

```bash
# Start node with blacklist enabled, private mode disabled
./kwild start --root ./testnet-blacklist/node0 \
  --db.port 5440 --admin.listen 127.0.0.1:8585
```

**Expected Results**:
- ✅ Node starts without nil pointer crashes
- ✅ Log shows: `[INF] P2P: Blacklist enabled - creating connection gater`
- ✅ Admin RPC accessible at 127.0.0.1:8585

### 2. Multi-Node Connectivity Test

**Objective**: Test peer connections work in blacklist-only mode.

**Terminal 1 - Node 0:**
```bash
./kwild start --root ./testnet-blacklist/node0 \
  --db.port 5440 --admin.listen 127.0.0.1:8585
```

**Terminal 2 - Node 1:**
```bash
./kwild start --root ./testnet-blacklist/node1 \
  --db.port 5441 --admin.listen 127.0.0.1:8586
```

**Expected Results**:
- ✅ Both nodes start successfully
- ✅ Nodes discover and connect to each other
- ✅ No connection blocking due to empty whitelist

### 3. CLI Commands Test

**Objective**: Validate all blacklist CLI commands work correctly.

#### Get Node IDs
```bash
# Get node ID from status command
./kwild admin status -s 127.0.0.1:8585 | jq -r '.node.node_id'
./kwild admin status -s 127.0.0.1:8586 | jq -r '.node.node_id'

# Alternative: extract from full status output
./kwild admin status -s 127.0.0.1:8585
./kwild admin status -s 127.0.0.1:8586
```

#### Test blacklist list
```bash
# Should show empty blacklist initially
./kwild blacklist list -s 127.0.0.1:8585

# Test JSON output
./kwild blacklist list --output json -s 127.0.0.1:8585
```

#### Test blacklist add
```bash
# Add node with reason and duration (use Node ID format: HEX#secp256k1)
./kwild blacklist add <Node ID> \
  --reason "Testing CLI functionality" \
  --duration "5m" \
  -s 127.0.0.1:8585

# Add permanent blacklist (no duration)
./kwild blacklist add <Node ID> \
  --reason "Permanent test blacklist" \
  -s 127.0.0.1:8585
```

#### Test blacklist remove
```bash
# Remove node from blacklist (use Node ID format: HEX#secp256k1)
./kwild blacklist remove <Node ID> -s 127.0.0.1:8585
```

### 4. Connection Blocking Validation

**Objective**: Verify blacklisted peers are actually blocked.

```bash
# 1. Verify initial connection between nodes
./kwild admin peers -s 127.0.0.1:8585  # Should show node1

# 2. Blacklist node1 from node0 (use Node ID from status command)
./kwild blacklist add <Node ID> \
  --reason "Testing connection blocking" \
  --duration "2m" \
  -s 127.0.0.1:8585

# 3. Monitor logs for blocking messages
# Expected: "Blocking OUTBOUND dial to blacklisted peer <libp2p_peer_id>" (logs show libp2p peer IDs)

# 4. Verify peer is no longer connected
./kwild admin peers -s 127.0.0.1:8585  # Should not show node1

# 5. Remove from blacklist
./kwild blacklist remove <Node ID> -s 127.0.0.1:8585

# 6. Verify connection restored
./kwild admin peers -s 127.0.0.1:8585  # Should show node1 again
```

## CLI Command Reference

### blacklist list
```bash
# Text format (default)
./kwild blacklist list -s <ADMIN_ADDRESS>

# JSON format
./kwild blacklist list --output json -s <ADMIN_ADDRESS>
```

**Expected Output**:
```text
Blacklisted Nodes:

NODE ID                                                              REASON               BLACKLISTED          TYPE       EXPIRES AT
------------------------------------------------------------------------------------------------------------------------------------------------------
0226b3ff29216dac187cea393f8af685ad419ac9644e55dce83d145c8b1af213bd#...   test reason          2025-01-08T14:30:00Z Temporary  2025-01-08T14:35:00Z
```

### blacklist add
```bash
# Temporary blacklist
./kwild blacklist add <Node ID> \
  --reason "<reason>" \
  --duration "<duration>" \
  -s <ADMIN_ADDRESS>

# Permanent blacklist (no duration)
./kwild blacklist add <Node ID> \
  --reason "<reason>" \
  -s <ADMIN_ADDRESS>
```

**Duration formats**: `30s`, `5m`, `1h`, `2h30m`, etc.

### blacklist remove
```bash
./kwild blacklist remove <Node ID> -s <ADMIN_ADDRESS>
```

## Validation Checklist

### ✅ Core Functionality
- [ ] Node startup with blacklist-only mode (no crashes)
- [ ] P2P service initialization successful
- [ ] Admin RPC server accessible

### ✅ CLI Commands
- [ ] `blacklist list` displays correctly (text and JSON)
- [ ] `blacklist add` works with reason and duration
- [ ] `blacklist add` works without duration (permanent)
- [ ] `blacklist remove` successfully removes peers
- [ ] Commands work with different admin server addresses

### ✅ Network Behavior
- [ ] Non-blacklisted peers can connect
- [ ] Blacklisted peers are blocked from connecting
- [ ] Connection blocking logged appropriately
- [ ] Connections restored after removing from blacklist

### ✅ Edge Cases
- [ ] Empty blacklist handled correctly
- [ ] Invalid peer IDs handled gracefully
- [ ] Network disconnections don't cause crashes
- [ ] Multiple simultaneous blacklist operations

## Troubleshooting

### Common Issues

**Command fails with "unknown flag"**:
- Verify admin server address: `-s 127.0.0.1:8585`
- Check if node is running and admin RPC accessible

**"Node ID not found" errors**:
- Use `./kwild admin status -s <ADMIN_ADDRESS> | jq -r '.node.node_id'` to get valid node IDs
- Ensure node ID format is `HEX#secp256k1` or `HEX#ed25519` (not libp2p peer ID format)

**Connection blocking not visible**:
- Check logs for `"Blocking OUTBOUND dial to blacklisted peer"`
- Verify peer was actually connected before blacklisting
- Monitor both node logs for connection attempts

**Node startup crashes**:
- If node crashes with nil pointer errors, the fix may not be applied
- Check for `"P2P: Blacklist enabled - creating connection gater"` log message

### Debug Commands

```bash
# Check node status
./kwild admin status -s 127.0.0.1:8585

# View connected peers
./kwild admin peers -s 127.0.0.1:8585

# Test admin RPC connectivity
curl -X POST http://127.0.0.1:8585 \
  -H "Content-Type: application/json" \
  -d '{"method":"admin.status","params":{},"id":1}'
```

## Expected Outcomes

After successful testing:

1. **✅ Blacklist-Only Mode Works**: Nodes operate with blacklist enabled, private mode disabled
2. **✅ CLI Integration Complete**: All blacklist commands function correctly
3. **✅ Connection Management**: Proper blocking/allowing of peers based on blacklist status
4. **✅ Production Ready**: Blacklist functionality available without private mode constraints

This validates that the blacklist CLI provides full peer management capabilities for production Kwil networks without requiring the restrictions of private mode operation.