#!/bin/bash
# Script to run GetWithdrawalProof tests individually with cleanup between each test
# These tests require manual cleanup due to extension singleton state limitations
#
# This script is used both locally and in CI. Configure via environment variables:
#   DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME
#
# CI runs this automatically after unit tests in .github/workflows/pr.yaml

set -e

# Database configuration (use environment variables with defaults)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-kwild}"
DB_PASS="${DB_PASS:-kwild}"
DB_NAME="${DB_NAME:-kwil_test_db}"

# Test names
TESTS=(
    "TestGetWithdrawalProof_ValidRequest"
    "TestGetWithdrawalProof_InvalidEpochID"
    "TestGetWithdrawalProof_InvalidRecipientFormat"
    "TestGetWithdrawalProof_EpochNotFound"
    "TestGetWithdrawalProof_RecipientNotInEpoch"
    "TestGetWithdrawalProof_PendingEpoch_NotEnded"
    "TestGetWithdrawalProof_PendingEpoch_NotConfirmed"
)

# Cleanup function
cleanup_db() {
    echo "🧹 Cleaning up test data..."

    # Check if schema exists first
    SCHEMA_EXISTS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = 'kwil_erc20_meta');" 2>/dev/null)

    if [ "$SCHEMA_EXISTS" = "t" ]; then
        # Schema exists, clean up the tables
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
            "DELETE FROM kwil_erc20_meta.epoch_votes; \
             DELETE FROM kwil_erc20_meta.epoch_rewards; \
             DELETE FROM kwil_erc20_meta.epochs; \
             DELETE FROM kwil_erc20_meta.reward_instances;" \
            >/dev/null 2>&1 || {
            echo "⚠️  Warning: Failed to cleanup some tables (they may not exist yet)"
        }
    else
        echo "ℹ️  Schema doesn't exist yet, skipping cleanup"
    fi
}

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "GetWithdrawalProof Test Suite Runner"
echo "========================================="
echo ""
echo "This script runs each test individually with database cleanup between runs."
echo "Total tests: ${#TESTS[@]}"
echo ""

# Check if PostgreSQL is running
echo "🔍 Checking PostgreSQL connection..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "\q" >/dev/null 2>&1 || {
    echo -e "${RED}❌ Cannot connect to PostgreSQL${NC}"
    echo "Please start PostgreSQL with: task pg"
    exit 1
}
echo -e "${GREEN}✅ PostgreSQL is running${NC}"
echo ""

# Track results
PASSED=0
FAILED=0
FAILED_TESTS=()

# Run each test
for test in "${TESTS[@]}"; do
    echo "----------------------------------------"
    echo "Running: $test"
    echo "----------------------------------------"

    # Cleanup before test
    cleanup_db

    # Run the test (use -count=1 to disable caching)
    if go test ./node/services/jsonrpc/usersvc -tags=kwiltest -run "^${test}$" -count=1 -v; then
        echo -e "${GREEN}✅ PASSED: $test${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌ FAILED: $test${NC}"
        FAILED=$((FAILED + 1))
        FAILED_TESTS+=("$test")
    fi
    echo ""
done

# Final cleanup
cleanup_db

# Print summary
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "Total:  ${#TESTS[@]}"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Failed tests:${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    exit 1
fi
