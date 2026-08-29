/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ar-validate-skip:schema-ddl-not-a-row
 *   Baseline schema DDL array (SCHEMA[]) plus create_schema(), split out
 *   of database.c to keep that file under the framework file-size ceiling.
 *   The DDL is not a row record, so the validates_* / AR_BEGIN_SAVE
 *   lifecycle does not apply. */

#include "models/database.h"
#include "models/database_internal.h"

#include <sqlite3.h>
#include <stdio.h>

static const char *SCHEMA[] = {
    /* Blockchain */
    "CREATE TABLE IF NOT EXISTS blocks ("
    "hash BLOB PRIMARY KEY,height INTEGER NOT NULL,"
    "prev_hash BLOB NOT NULL,version INTEGER NOT NULL,"
    "merkle_root BLOB NOT NULL,time INTEGER NOT NULL,"
    "bits INTEGER NOT NULL,nonce BLOB NOT NULL,"
    "solution BLOB NOT NULL,chain_work BLOB NOT NULL,"
    "status INTEGER NOT NULL DEFAULT 0,"
    "file_num INTEGER,data_pos INTEGER,undo_pos INTEGER,"
    "num_tx INTEGER NOT NULL DEFAULT 0,"
    "sapling_root BLOB,sprout_root BLOB,"
    "sapling_value INTEGER DEFAULT 0,"
    "sprout_value INTEGER DEFAULT 0)",

    "CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_height"
    " ON blocks(height) WHERE status >= 3",

    "CREATE INDEX IF NOT EXISTS idx_blocks_prev"
    " ON blocks(prev_hash)",

    "CREATE INDEX IF NOT EXISTS idx_blocks_chainwork"
    " ON blocks(chain_work DESC)",

    /* Private local mesh authority. Public identities are stored only after
     * explicit operator confirmation; no key material or remote content root
     * belongs in this table. */
    "CREATE TABLE IF NOT EXISTS mesh_pairings("
    "pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id)=64),"
    "network_genesis BLOB NOT NULL CHECK(length(network_genesis)=32),"
    "peer_master_pubkey BLOB NOT NULL CHECK(length(peer_master_pubkey)=32),"
    "peer_noise_pubkey BLOB NOT NULL CHECK(length(peer_noise_pubkey)=32),"
    "capability_mask INTEGER NOT NULL CHECK(capability_mask>0),"
    "delegation_sequence INTEGER NOT NULL CHECK(delegation_sequence>0),"
    "paired_at INTEGER NOT NULL CHECK(paired_at>0),"
    "expires_at INTEGER NOT NULL CHECK(expires_at>paired_at),"
    "revoked_at INTEGER NOT NULL DEFAULT 0 CHECK(revoked_at>=0),"
    "revocation_generation INTEGER NOT NULL DEFAULT 0 "
    "CHECK(revocation_generation>=0),"
    "UNIQUE(network_genesis,peer_master_pubkey,peer_noise_pubkey))",

    "CREATE INDEX IF NOT EXISTS idx_mesh_pairings_active"
    " ON mesh_pairings(revoked_at,expires_at)",

    /* Private-object grants bind both machines and move monotonically from
     * available to claimed to completed. Sealed chunks are canonical 64 KiB
     * records with 65,520 plaintext bytes and a 16-byte authentication tag. */
    "CREATE TABLE IF NOT EXISTS mesh_capability_grants("
    "grant_id TEXT PRIMARY KEY CHECK(length(grant_id)=64),"
    "pairing_id TEXT NOT NULL REFERENCES mesh_pairings(pairing_id) "
    "ON DELETE CASCADE CHECK(length(pairing_id)=64),"
    "target_master_pubkey BLOB NOT NULL CHECK(length(target_master_pubkey)=32),"
    "target_noise_static BLOB NOT NULL CHECK(length(target_noise_static)=32),"
    "operation INTEGER NOT NULL CHECK(operation=1),"
    "plaintext_root BLOB NOT NULL CHECK(length(plaintext_root)=32),"
    "ciphertext_root BLOB NOT NULL CHECK(length(ciphertext_root)=32),"
    "object_size_bytes INTEGER NOT NULL CHECK(object_size_bytes BETWEEN 1 AND 1073741824),"
    "ciphertext_size_bytes INTEGER NOT NULL CHECK(ciphertext_size_bytes<=2147483648),"
    "storage_limit_bytes INTEGER NOT NULL CHECK(storage_limit_bytes>=ciphertext_size_bytes+object_size_bytes AND storage_limit_bytes<=3221225472),"
    "transfer_limit_bytes INTEGER NOT NULL CHECK(transfer_limit_bytes>=ciphertext_size_bytes AND transfer_limit_bytes<=2147483648),"
    "max_chunk_bytes INTEGER NOT NULL CHECK(max_chunk_bytes=65536),"
    "chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 16389),"
    "wall_limit_seconds INTEGER NOT NULL CHECK(wall_limit_seconds BETWEEN 1 AND 600),"
    "nonce BLOB NOT NULL CHECK(length(nonce)=32),"
    "deny_mask INTEGER NOT NULL CHECK(deny_mask=255),"
    "issued_at INTEGER NOT NULL CHECK(issued_at>0),"
    "not_before INTEGER NOT NULL CHECK(not_before>=issued_at),"
    "expires_at INTEGER NOT NULL CHECK(expires_at>not_before AND expires_at-issued_at<=2592000),"
    "transfer_id BLOB NOT NULL DEFAULT X'' CHECK(length(transfer_id) IN (0,32)),"
    "claimed_at INTEGER NOT NULL DEFAULT 0 CHECK(claimed_at>=0),"
    "consumed_at INTEGER NOT NULL DEFAULT 0 CHECK(consumed_at>=0),"
    "revoked_at INTEGER NOT NULL DEFAULT 0 CHECK(revoked_at=0 OR revoked_at>=issued_at),"
    "revocation_generation INTEGER NOT NULL DEFAULT 0 CHECK((revoked_at=0 AND revocation_generation=0) OR (revoked_at>0 AND revocation_generation>0)),"
    "CHECK(chunk_count=(object_size_bytes+65519)/65520),"
    "CHECK(ciphertext_size_bytes=object_size_bytes+16*chunk_count),"
    "CHECK((claimed_at=0 AND length(transfer_id)=0 AND consumed_at=0) OR "
    "(claimed_at>=not_before AND claimed_at<expires_at AND length(transfer_id)=32 "
    "AND (consumed_at=0 OR (consumed_at>=claimed_at AND consumed_at<expires_at)))))",

    "CREATE INDEX IF NOT EXISTS idx_mesh_capability_grants_pairing_state"
    " ON mesh_capability_grants(pairing_id,revoked_at,consumed_at,expires_at)",

    /* Latest exact signed status evidence. This rebuildable projection never
     * grants pairing or capability authority; stale evidence remains stored
     * so readers can distinguish it from a machine never observed. */
    "CREATE TABLE IF NOT EXISTS mesh_machine_observations("
    "pairing_id TEXT PRIMARY KEY REFERENCES mesh_pairings(pairing_id) "
    "ON DELETE CASCADE CHECK(length(pairing_id)=64),"
    "receipt_wire BLOB NOT NULL CHECK(length(receipt_wire) BETWEEN 400 AND 4496),"
    "receipt_root BLOB NOT NULL CHECK(length(receipt_root)=32),"
    "status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 9),"
    "observed_unix INTEGER NOT NULL CHECK(observed_unix>0),"
    "expires_unix INTEGER NOT NULL CHECK(expires_unix>observed_unix),"
    "received_unix INTEGER NOT NULL CHECK(received_unix>0))",

    /* Transaction index */
    "CREATE TABLE IF NOT EXISTS transactions ("
    "txid BLOB PRIMARY KEY,block_hash BLOB NOT NULL,"
    "block_height INTEGER NOT NULL,tx_index INTEGER NOT NULL,"
    "file_num INTEGER NOT NULL,file_pos INTEGER NOT NULL,"
    "is_coinbase INTEGER NOT NULL DEFAULT 0)",

    "CREATE INDEX IF NOT EXISTS idx_tx_block"
    " ON transactions(block_hash)",

    "CREATE INDEX IF NOT EXISTS idx_tx_height"
    " ON transactions(block_height)",

    /* UTXO set — PROJECTION (rebuildable cache) of progress.kv `coins`
     * (coins_kv, the canonical store co-committed with the stage cursor).
     * Read by explorer/RPC/wallet and the fast-sync SERVE path (until
     * canonical-plan step 5). NEVER consulted by consensus/recovery
     * decisions — authority is coins_kv + reducer_frontier_derive_coins_best
     * (wave 2, docs/work/canonical-frontier-derived-state-plan.md). */
    "CREATE TABLE IF NOT EXISTS utxos ("
    "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
    "value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2100000000000000),"
    "script BLOB NOT NULL,"
    "script_type INTEGER NOT NULL DEFAULT 0,"
    "address_hash BLOB,height INTEGER NOT NULL CHECK(height >= 0),"
    "is_coinbase INTEGER NOT NULL DEFAULT 0,"
    "PRIMARY KEY (txid,vout))",

    "CREATE INDEX IF NOT EXISTS idx_utxo_address"
    " ON utxos(address_hash) WHERE address_hash IS NOT NULL",

    "CREATE INDEX IF NOT EXISTS idx_utxo_value"
    " ON utxos(value DESC)",

    "CREATE INDEX IF NOT EXISTS idx_utxo_height"
    " ON utxos(height)",

    /* Snapshot receive staging.
     * P2P snapshot sync must never write directly to active utxos before
     * FlyClient and SHA3 verification pass. This table is cleared at boot
     * and on every receive begin/failure, then atomically promoted. */
    "CREATE TABLE IF NOT EXISTS snapshot_staging_utxos ("
    "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
    "value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2100000000000000),"
    "script BLOB NOT NULL,"
    "script_type INTEGER NOT NULL DEFAULT 0,"
    "address_hash BLOB,height INTEGER NOT NULL CHECK(height >= 0),"
    "is_coinbase INTEGER NOT NULL DEFAULT 0,"
    "PRIMARY KEY (txid,vout))",

    "CREATE INDEX IF NOT EXISTS idx_snapshot_staging_height"
    " ON snapshot_staging_utxos(height)",

    /* Sapling nullifiers & anchors */
    "CREATE TABLE IF NOT EXISTS sapling_nullifiers ("
    "nullifier BLOB PRIMARY KEY)",

    "CREATE TABLE IF NOT EXISTS sapling_anchors ("
    "anchor BLOB PRIMARY KEY,height INTEGER NOT NULL)",

    "CREATE INDEX IF NOT EXISTS idx_sapling_anchor_height"
    " ON sapling_anchors(height)",

    /* Wallet keys */
    "CREATE TABLE IF NOT EXISTS wallet_keys ("
    "pubkey_hash BLOB PRIMARY KEY,pubkey BLOB NOT NULL,"
    "privkey BLOB NOT NULL,compressed INTEGER NOT NULL DEFAULT 1,"
    "created_at INTEGER NOT NULL DEFAULT 0)",

    "CREATE TABLE IF NOT EXISTS wallet_keypool ("
    "pubkey_hash BLOB PRIMARY KEY CHECK(length(pubkey_hash)=20),"
    "generation INTEGER NOT NULL UNIQUE CHECK(generation>=0),"
    "FOREIGN KEY(pubkey_hash) REFERENCES wallet_keys(pubkey_hash) "
    "ON DELETE CASCADE)",

    "CREATE TABLE IF NOT EXISTS wallet_key_encryption ("
    "id INTEGER PRIMARY KEY CHECK (id=1),"
    "wrapped_dek BLOB NOT NULL)",

    "CREATE TABLE IF NOT EXISTS wallet_sapling_keys ("
    "ivk BLOB PRIMARY KEY,xsk BLOB NOT NULL,xfvk BLOB NOT NULL,"
    "diversifier BLOB NOT NULL,pk_d BLOB NOT NULL,"
    "child_index INTEGER NOT NULL,"
    "address TEXT NOT NULL DEFAULT '')",

    "CREATE INDEX IF NOT EXISTS idx_sapling_key_addr"
    " ON wallet_sapling_keys(address)",

    "CREATE TABLE IF NOT EXISTS wallet_scripts ("
    "script_hash BLOB PRIMARY KEY,redeem_script BLOB NOT NULL)",

    "CREATE TABLE IF NOT EXISTS wallet_seed ("
    "id INTEGER PRIMARY KEY CHECK (id=1),"
    "seed BLOB NOT NULL,next_child INTEGER NOT NULL DEFAULT 0)",

    /* Watch-only addresses (importaddress) MUST be in the baseline
     * schema — if missing, wallet_sqlite_open() silently fails preparing
     * its watch_only statements and every restart regenerates the
     * keypool against empty memory. See WALLET_PERSISTENCE_PLAN §2. */
    "CREATE TABLE IF NOT EXISTS wallet_watch_only ("
    "address_hash BLOB PRIMARY KEY,address TEXT NOT NULL,"
    "created_at INTEGER NOT NULL)",

    /* Wallet transactions & notes */
    "CREATE TABLE IF NOT EXISTS wallet_transactions ("
    "txid BLOB PRIMARY KEY,raw_tx BLOB NOT NULL,"
    "block_hash BLOB,block_height INTEGER,"
    "time_received INTEGER NOT NULL,"
    "from_me INTEGER NOT NULL DEFAULT 0,fee INTEGER)",

    "CREATE INDEX IF NOT EXISTS idx_wtx_height"
    " ON wallet_transactions(block_height)",

    "CREATE INDEX IF NOT EXISTS idx_wtx_time"
    " ON wallet_transactions(time_received DESC)",

    "CREATE TABLE IF NOT EXISTS wallet_utxos ("
    "txid BLOB NOT NULL,vout INTEGER NOT NULL,"
    "value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2100000000000000),"
    "address_hash BLOB NOT NULL,"
    "script BLOB NOT NULL,height INTEGER NOT NULL CHECK(height >= 0),"
    "spent_txid BLOB,spent_vin INTEGER,"
    "is_coinbase INTEGER NOT NULL DEFAULT 0,"
    "PRIMARY KEY (txid,vout))",

    "CREATE INDEX IF NOT EXISTS idx_wutxo_unspent"
    " ON wallet_utxos(address_hash) WHERE spent_txid IS NULL",

    "CREATE INDEX IF NOT EXISTS idx_wutxo_spent"
    " ON wallet_utxos(spent_txid) WHERE spent_txid IS NOT NULL",

    "CREATE TABLE IF NOT EXISTS wallet_sapling_notes ("
    "txid BLOB NOT NULL,output_index INTEGER NOT NULL,"
    "value INTEGER NOT NULL,rcm BLOB NOT NULL,memo BLOB,"
    "ivk BLOB NOT NULL,diversifier BLOB NOT NULL,"
    "pk_d BLOB NOT NULL,cm BLOB NOT NULL,"
    "nullifier BLOB NOT NULL UNIQUE,"
    "block_height INTEGER,spent_txid BLOB,"
    "address TEXT,"
    "source TEXT NOT NULL DEFAULT 'local',"
    "PRIMARY KEY (txid,output_index))",

    "CREATE INDEX IF NOT EXISTS idx_snote_unspent"
    " ON wallet_sapling_notes(ivk) WHERE spent_txid IS NULL",

    "CREATE INDEX IF NOT EXISTS idx_snote_nullifier"
    " ON wallet_sapling_notes(nullifier)",

    "CREATE INDEX IF NOT EXISTS idx_snote_address"
    " ON wallet_sapling_notes(address) WHERE spent_txid IS NULL",

    /* Wallet persistence canary (boot-time self-test; see
     * lib/wallet/include/wallet/wallet_canary.h). */
    "CREATE TABLE IF NOT EXISTS wallet_canary ("
    "id INTEGER PRIMARY KEY CHECK (id=1),"
    "probe BLOB NOT NULL,"
    "ts INTEGER NOT NULL)",

    /* Mempool */
    "CREATE TABLE IF NOT EXISTS mempool ("
    "txid BLOB PRIMARY KEY,raw_tx BLOB NOT NULL,"
    "fee INTEGER NOT NULL,size INTEGER NOT NULL,"
    "time_added INTEGER NOT NULL,height_added INTEGER NOT NULL,"
    "spends_coinbase INTEGER NOT NULL DEFAULT 0)",

    "CREATE INDEX IF NOT EXISTS idx_mempool_fee"
    " ON mempool(fee DESC)",

    "CREATE TABLE IF NOT EXISTS mempool_spends ("
    "txid BLOB NOT NULL,spent_txid BLOB NOT NULL,"
    "spent_vout INTEGER NOT NULL,"
    "PRIMARY KEY (spent_txid,spent_vout))",

    /* Peers */
    "CREATE TABLE IF NOT EXISTS peers ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "ip BLOB NOT NULL,port INTEGER NOT NULL,"
    "services INTEGER NOT NULL DEFAULT 0,"
    "last_seen INTEGER NOT NULL,last_try INTEGER DEFAULT 0,"
    "attempts INTEGER DEFAULT 0,source BLOB,"
    "bandwidth_score INTEGER NOT NULL DEFAULT 0,"
    "is_zcl23 INTEGER NOT NULL DEFAULT 0,"
    "UNIQUE(ip,port))",

    "CREATE INDEX IF NOT EXISTS idx_peers_seen"
    " ON peers(last_seen DESC)",

    "CREATE INDEX IF NOT EXISTS idx_peers_zcl23_score"
    " ON peers(is_zcl23 DESC, bandwidth_score DESC)",

    /* File services */
    "CREATE TABLE IF NOT EXISTS file_services ("
    "ip BLOB NOT NULL,port INTEGER NOT NULL,"
    "p2p_port INTEGER,last_seen INTEGER,"
    "is_zcl23 INTEGER DEFAULT 1,"
    "UNIQUE(ip,port))",

    /* Explorer projection tables — the full per-block indexer (node.db
     * only). Mirrors the migration DDL (database_migrate.c v7 op_returns +
     * v9 tx_outputs/inputs/sapling/joinsplits/sprout/view_integrity) so a
     * FRESH db has them at prepare_statements() time (the explorer-index
     * cached statements are prepared before migrations run). The migration
     * blocks stay for upgrading pre-v9 databases; CREATE TABLE IF NOT EXISTS
     * is idempotent so there is no conflict. */
    "CREATE TABLE IF NOT EXISTS op_returns ("
    "txid BLOB PRIMARY KEY,"
    "block_height INTEGER NOT NULL,"
    "script BLOB NOT NULL,"
    "is_slp INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS idx_opret_height ON op_returns(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_opret_slp"
    " ON op_returns(is_slp) WHERE is_slp = 1",

    "CREATE TABLE IF NOT EXISTS tx_outputs ("
    "txid BLOB NOT NULL, vout INTEGER NOT NULL,"
    "value INTEGER NOT NULL, script_type INTEGER NOT NULL DEFAULT 0,"
    "address_hash BLOB, block_height INTEGER NOT NULL,"
    "PRIMARY KEY (txid, vout))",
    "CREATE INDEX IF NOT EXISTS idx_txo_addr"
    " ON tx_outputs(address_hash) WHERE address_hash IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_txo_height ON tx_outputs(block_height)",
    "CREATE INDEX IF NOT EXISTS idx_txo_hodl_scan"
    " ON tx_outputs(block_height, value, txid, vout)",

    "CREATE TABLE IF NOT EXISTS tx_inputs ("
    "txid BLOB NOT NULL, vin_index INTEGER NOT NULL,"
    "prev_txid BLOB NOT NULL, prev_vout INTEGER NOT NULL,"
    "block_height INTEGER NOT NULL,"
    "PRIMARY KEY (txid, vin_index))",
    "CREATE INDEX IF NOT EXISTS idx_txi_prev ON tx_inputs(prev_txid, prev_vout)",
    "CREATE INDEX IF NOT EXISTS idx_txi_prev_height"
    " ON tx_inputs(prev_txid, prev_vout, block_height)",
    "CREATE INDEX IF NOT EXISTS idx_txi_height ON tx_inputs(block_height)",

    "CREATE TABLE IF NOT EXISTS sapling_spends ("
    "txid BLOB NOT NULL, spend_index INTEGER NOT NULL,"
    "cv BLOB NOT NULL, anchor BLOB NOT NULL,"
    "nullifier BLOB NOT NULL, rk BLOB NOT NULL,"
    "block_height INTEGER NOT NULL,"
    "PRIMARY KEY (txid, spend_index))",
    "CREATE INDEX IF NOT EXISTS idx_ss_nf ON sapling_spends(nullifier)",
    "CREATE INDEX IF NOT EXISTS idx_ss_height ON sapling_spends(block_height)",

    "CREATE TABLE IF NOT EXISTS sapling_outputs ("
    "txid BLOB NOT NULL, output_index INTEGER NOT NULL,"
    "cv BLOB NOT NULL, cm BLOB NOT NULL,"
    "ephemeral_key BLOB NOT NULL, block_height INTEGER NOT NULL,"
    "PRIMARY KEY (txid, output_index))",
    "CREATE INDEX IF NOT EXISTS idx_so_height ON sapling_outputs(block_height)",

    "CREATE TABLE IF NOT EXISTS joinsplits ("
    "txid BLOB NOT NULL, js_index INTEGER NOT NULL,"
    "vpub_old INTEGER NOT NULL, vpub_new INTEGER NOT NULL,"
    "anchor BLOB NOT NULL, block_height INTEGER NOT NULL,"
    "PRIMARY KEY (txid, js_index))",
    "CREATE INDEX IF NOT EXISTS idx_js_height ON joinsplits(block_height)",

    "CREATE TABLE IF NOT EXISTS sprout_nullifiers ("
    "nullifier BLOB PRIMARY KEY,"
    "txid BLOB NOT NULL, block_height INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_spnf_height"
    " ON sprout_nullifiers(block_height)",

    "CREATE TABLE IF NOT EXISTS view_integrity ("
    "height INTEGER PRIMARY KEY,"
    "sha3_hash BLOB NOT NULL)",

    /* Node state */
    "CREATE TABLE IF NOT EXISTS node_state ("
    "key TEXT PRIMARY KEY,value BLOB)",

    "INSERT OR IGNORE INTO node_state(key,value)"
    " VALUES('schema_version',X'01000000')",

    NULL
};

bool create_schema(struct node_db *ndb)
{
    /* Every statement in SCHEMA[] is either CREATE TABLE IF NOT EXISTS,
     * CREATE INDEX IF NOT EXISTS, or INSERT OR IGNORE — all idempotent.
     * ALTER TABLE statements belong in versioned migration blocks in
     * node_db_migrate(), not here.  Any failure at this layer is a real
     * schema regression and must halt boot. */
    for (int i = 0; SCHEMA[i] != NULL; i++) {
        char buf[48];
        snprintf(buf, sizeof(buf), "schema[%d]", i);
        if (db_exec_checked(ndb->db, SCHEMA[i], buf) != SQLITE_OK)
            return false;
    }
    return true;
}
