SET CURRENT NAMESPACE TO kwil_erc20_meta;

-- reward_instances tracks all reward extensions that have been created.
-- it includes reward_instances that have synced data from the chain, as
-- well as reward_instances that have been created but not yet synced.
CREATE TABLE reward_instances (
    -- the following columns are set when the reward is created
    id UUID PRIMARY KEY,
    chain_id TEXT NOT NULL,
    escrow_address BYTEA NOT NULL,
    distribution_period INT8 NOT NULL, -- interval (in seconds)
    -- synced tells us whether we have synced the metadata associated
    -- with the escrow address (e.g. the erc20 address, decimals, etc.).
    -- This happens exactly once at the beginning of an instance.
    synced BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE, -- whether the reward is active
    -- the following columns are set when the on-chain
    -- info is synced from the escrow contract
    erc20_address BYTEA,
    erc20_decimals INT8,
    synced_at INT8, -- the unix timestamp (in seconds) when the reward was synced
    balance NUMERIC(78, 0) NOT NULL DEFAULT 0 CHECK(balance >= 0), -- the total balance owned by the database that can be distributed
    UNIQUE (chain_id, escrow_address) -- unique per chain and escrow
);

-- balances tracks the balance of each user in a given reward instance.
CREATE TABLE balances (
    id UUID PRIMARY KEY,
    reward_id UUID NOT NULL REFERENCES reward_instances(id) ON UPDATE CASCADE ON DELETE CASCADE,
    address BYTEA NOT NULL, -- wallet address of the user
    balance NUMERIC(78, 0) NOT NULL DEFAULT 0, -- the balance owned by the user on this network
    CONSTRAINT balance_must_be_positive CHECK (balance >= 0)
);

-- epochs holds the epoch information.
-- An epoch is a group of rewards that are issued in a given time/block range.
-- Epochs have 3 states:
-- 1. Created: the epoch is created and the rewards are being distributed
-- 2. Ended: the epoch has ended and the rewards are finalized
-- 3. Confirmed: the epoch has been confirmed on chain
-- Ideally, Kwil would have a unique indexes on this table where "confirmed" is null (to enforce only one active epoch at a time),
-- but this requires partial indexes which are not yet supported in Kwil
-- We'll always have two active epochs at the same time(except the very first epoch),
-- one is finalized and waiting to be confirmed, the other is collecting new rewards.
CREATE TABLE epochs (
	id UUID PRIMARY KEY,
    created_at_block INT8 NOT NULL, -- kwil block height
    created_at_unix INT8 NOT NULL, -- unix timestamp (in seconds)
    instance_id UUID NOT NULL REFERENCES reward_instances(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
	reward_root BYTEA UNIQUE, -- the root of the merkle tree of rewards, it's unique per contract
    reward_amount NUMERIC(78, 0), -- the total amount in current epoch
    ended_at INT8, -- kwil block height
    block_hash BYTEA, -- the hash of the block that is used in merkle tree leaf, which is the last block of the epoch
    confirmed BOOLEAN NOT NULL DEFAULT FALSE -- whether the epoch has been confirmed on chain
);

-- index helps us query for unconfirmed epochs, which is very common
CREATE INDEX idx_epochs_confirmed ON epochs(instance_id, confirmed);

-- epoch_rewards holds information about the rewards in a given epoch
CREATE TABLE epoch_rewards (
    epoch_id UUID NOT NULL REFERENCES epochs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    recipient BYTEA NOT NULL,
    amount NUMERIC(78,0) NOT NULL, -- allows uint256
    PRIMARY KEY (epoch_id, recipient)
);

CREATE INDEX idx_epoch_rewards_epoch_id ON epoch_rewards(epoch_id);

CREATE TABLE meta
(
    version INT8 PRIMARY KEY
);

-- epoch_votes holds the votes from signer
-- A signer can vote multiple times with different safe_nonce
-- After an epoch is confirmed, we can delete all related votes.
CREATE TABLE epoch_votes (
    epoch_id UUID NOT NULL REFERENCES epochs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    voter BYTEA NOT NULL,
    nonce INT8 NOT NULL, -- safe nonce; this helps to skip unnecessary dup votes
    signature BYTEA NOT NULL,
    PRIMARY KEY (epoch_id, voter, nonce)
);

-- withdrawals tracks withdrawal claims on the blockchain (multi-chain support)
-- Chain information is determined through: withdrawals -> epochs -> reward_instances -> chain_id
-- This allows GetWithdrawalProof to return accurate status information
CREATE TABLE withdrawals (
    epoch_id UUID NOT NULL,
    recipient BYTEA NOT NULL,
    tx_hash BYTEA,               -- Blockchain transaction hash (NULL until claimed)
    block_number INT8,           -- Blockchain block number
    claimed_at INT8,             -- Unix timestamp when claimed
    updated_at INT8,             -- Last update timestamp
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'claimed')),
    PRIMARY KEY (epoch_id, recipient),
    FOREIGN KEY (epoch_id) REFERENCES epochs(id) ON DELETE CASCADE
);

CREATE INDEX idx_withdrawals_status ON withdrawals(status);
CREATE INDEX idx_withdrawals_tx_hash ON withdrawals(tx_hash);
CREATE INDEX idx_withdrawals_recipient ON withdrawals(recipient);