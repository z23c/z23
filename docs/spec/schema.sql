-- ZClassic C23 Node - Database Schema
-- Copyright 2026 Rhett Creighton - Apache License 2.0
-- Schema version: 1
--
-- REFERENCE DUMP ONLY — this file is never read or executed at runtime.
-- The live schema is created by embedded C migrations in
-- engine/models/src/database_migrate.c. Kept as human-readable documentation
-- (cited by contexts/wallet/modules/wallet/src/wallet_sqlite.c and power-node-contract.md).

-- Blockchain
CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    prev_hash BLOB NOT NULL,
    version INTEGER NOT NULL,
    merkle_root BLOB NOT NULL,
    time INTEGER NOT NULL,
    bits INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    solution BLOB NOT NULL,
    chain_work BLOB NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    file_num INTEGER,
    data_pos INTEGER,
    undo_pos INTEGER,
    num_tx INTEGER NOT NULL DEFAULT 0,
    sapling_root BLOB,
    sprout_root BLOB,
    sapling_value INTEGER DEFAULT 0,
    sprout_value INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height) WHERE status >= 3;
CREATE INDEX IF NOT EXISTS idx_blocks_prev ON blocks(prev_hash);
CREATE INDEX IF NOT EXISTS idx_blocks_chainwork ON blocks(chain_work DESC);

-- Transaction index
CREATE TABLE IF NOT EXISTS transactions (
    txid BLOB PRIMARY KEY,
    block_hash BLOB NOT NULL,
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    file_num INTEGER NOT NULL,
    file_pos INTEGER NOT NULL,
    is_coinbase INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_hash);
CREATE INDEX IF NOT EXISTS idx_tx_height ON transactions(block_height);

-- UTXO set
CREATE TABLE IF NOT EXISTS utxos (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    value INTEGER NOT NULL,
    script BLOB NOT NULL,
    script_type INTEGER NOT NULL DEFAULT 0,
    address_hash BLOB,
    height INTEGER NOT NULL,
    is_coinbase INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (txid, vout)
);

CREATE INDEX IF NOT EXISTS idx_utxo_address ON utxos(address_hash) WHERE address_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_utxo_value ON utxos(value DESC);
CREATE INDEX IF NOT EXISTS idx_utxo_height ON utxos(height);

-- Sapling nullifiers & anchors
CREATE TABLE IF NOT EXISTS sapling_nullifiers (nullifier BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS sapling_anchors (anchor BLOB PRIMARY KEY, height INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sapling_anchor_height ON sapling_anchors(height);

-- Wallet keys
CREATE TABLE IF NOT EXISTS wallet_keys (
    pubkey_hash BLOB PRIMARY KEY,
    pubkey BLOB NOT NULL,
    privkey BLOB NOT NULL,
    compressed INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wallet_key_encryption (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    wrapped_dek BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_watch_only (
    address_hash BLOB PRIMARY KEY,
    address TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wallet_sapling_keys (
    ivk BLOB PRIMARY KEY,
    xsk BLOB NOT NULL,
    xfvk BLOB NOT NULL,
    diversifier BLOB NOT NULL,
    pk_d BLOB NOT NULL,
    child_index INTEGER NOT NULL,
    address TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sapling_key_addr ON wallet_sapling_keys(address);

CREATE TABLE IF NOT EXISTS wallet_scripts (
    script_hash BLOB PRIMARY KEY,
    redeem_script BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_seed (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seed BLOB NOT NULL,
    next_child INTEGER NOT NULL DEFAULT 0
);

-- Wallet transactions & notes
CREATE TABLE IF NOT EXISTS wallet_transactions (
    txid BLOB PRIMARY KEY,
    raw_tx BLOB NOT NULL,
    block_hash BLOB,
    block_height INTEGER,
    time_received INTEGER NOT NULL,
    from_me INTEGER NOT NULL DEFAULT 0,
    fee INTEGER
);

CREATE INDEX IF NOT EXISTS idx_wtx_height ON wallet_transactions(block_height);
CREATE INDEX IF NOT EXISTS idx_wtx_time ON wallet_transactions(time_received DESC);

CREATE TABLE IF NOT EXISTS wallet_utxos (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    value INTEGER NOT NULL,
    address_hash BLOB NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    spent_txid BLOB,
    spent_vin INTEGER,
    is_coinbase INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (txid, vout)
);

CREATE INDEX IF NOT EXISTS idx_wutxo_unspent ON wallet_utxos(address_hash) WHERE spent_txid IS NULL;
CREATE INDEX IF NOT EXISTS idx_wutxo_spent ON wallet_utxos(spent_txid) WHERE spent_txid IS NOT NULL;

CREATE TABLE IF NOT EXISTS wallet_sapling_notes (
    txid BLOB NOT NULL,
    output_index INTEGER NOT NULL,
    value INTEGER NOT NULL,
    rcm BLOB NOT NULL,
    memo BLOB,
    ivk BLOB NOT NULL,
    diversifier BLOB NOT NULL,
    pk_d BLOB NOT NULL,
    cm BLOB NOT NULL,
    nullifier BLOB NOT NULL UNIQUE,
    block_height INTEGER,
    spent_txid BLOB,
    address TEXT,
    PRIMARY KEY (txid, output_index)
);

CREATE INDEX IF NOT EXISTS idx_snote_unspent ON wallet_sapling_notes(ivk) WHERE spent_txid IS NULL;
CREATE INDEX IF NOT EXISTS idx_snote_nullifier ON wallet_sapling_notes(nullifier);
CREATE INDEX IF NOT EXISTS idx_snote_address ON wallet_sapling_notes(address) WHERE spent_txid IS NULL;

-- Mempool
CREATE TABLE IF NOT EXISTS mempool (
    txid BLOB PRIMARY KEY,
    raw_tx BLOB NOT NULL,
    fee INTEGER NOT NULL,
    size INTEGER NOT NULL,
    time_added INTEGER NOT NULL,
    height_added INTEGER NOT NULL,
    spends_coinbase INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_mempool_fee ON mempool(fee DESC);

CREATE TABLE IF NOT EXISTS mempool_spends (
    txid BLOB NOT NULL,
    spent_txid BLOB NOT NULL,
    spent_vout INTEGER NOT NULL,
    PRIMARY KEY (spent_txid, spent_vout)
);

-- Peers
CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip BLOB NOT NULL,
    port INTEGER NOT NULL,
    services INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER NOT NULL,
    last_try INTEGER DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    source BLOB,
    UNIQUE(ip, port)
);

CREATE INDEX IF NOT EXISTS idx_peers_seen ON peers(last_seen DESC);

-- Node state (key-value store for runtime config)
CREATE TABLE IF NOT EXISTS node_state (
    key TEXT PRIMARY KEY,
    value BLOB
);

INSERT OR IGNORE INTO node_state(key, value) VALUES('schema_version', X'01000000');
