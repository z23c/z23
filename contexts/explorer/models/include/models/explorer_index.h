/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_EXPLORER_INDEX_H
#define ZCL_DB_MODEL_EXPLORER_INDEX_H

/* Explorer projection writers — the full per-block indexer.
 *
 * These eight db_*_save functions populate the read-derived explorer
 * projection tables (tx_outputs, tx_inputs, op_returns, sapling_spends,
 * sapling_outputs, joinsplits, sprout_nullifiers, view_integrity) from
 * already-validated on-disk block bodies. They are the only writers for
 * those tables and are driven by index_tx_projections() in
 * node_db_catchup_service.c (the single per-block write unit, on both the
 * forward-sync and -reindex-explorer paths).
 *
 * node.db ONLY. None of these reach coins_kv / progress.kv / the reducer /
 * the block index / any consensus predicate. A save failure degrades an
 * explorer row; it never gates block acceptance.
 *
 * Idempotent: every statement is INSERT OR REPLACE keyed on the table PK,
 * so a reindex / restart re-walk overwrites the existing row rather than
 * double-inserting. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct block;
struct block_index;
struct transaction;
struct spend_description;
struct output_description;
struct js_description;
struct ar_errors;
struct slp_message;

/* Index every projection for one already-validated block: per-tx outputs,
 * inputs, op_returns (+ ZSLP flag / ZNAM apply), sapling spends/outputs,
 * joinsplits, sprout nullifiers, then the per-height SHA3 chained
 * view_integrity receipt. This is the single per-block hook called once
 * from sync_block_lean (both the forward-sync and -reindex-explorer paths).
 *
 *   prev_receipt   the previous height's 32-byte receipt (32 zero bytes at
 *                  genesis). Carried across the ascending catchup walk.
 *   out_receipt    receives this height's receipt (chain it forward).
 *   out_sprout     receives Σ(vpub_old - vpub_new) for the block.
 *   out_sapling    receives Σ value_balance for the block.
 *
 * Returns false only on a catastrophic argument error (logged). An
 * individual projection save failure is logged and skipped (a degraded
 * explorer row) — it never aborts the block or gates acceptance. */
bool explorer_index_block(struct node_db *ndb, const struct block *blk,
                          const struct block_index *pindex,
                          const uint8_t prev_receipt[32],
                          uint8_t out_receipt[32],
                          int64_t *out_sprout, int64_t *out_sapling);

/* Transparent output: txid/vout PK, value, script_type (enum script_type),
 * optional 20-byte address hash (NULL → SQL NULL), block height. */
bool db_tx_output_save(struct node_db *ndb, const uint8_t txid[32],
                       uint32_t vout, int64_t value, int script_type,
                       const uint8_t *address_hash /* 20B or NULL */,
                       int block_height);

/* Transparent input: txid/vin_index PK, the spent prevout, block height.
 * Coinbase null prevouts are skipped by the caller, not here. */
bool db_tx_input_save(struct node_db *ndb, const uint8_t txid[32],
                      uint32_t vin_index, const uint8_t prev_txid[32],
                      uint32_t prev_vout, int block_height);

/* OP_RETURN: txid PK (one row per tx), raw scriptPubKey (incl. leading
 * 0x6a), block height, is_slp flag (true when slp_parse matched). */
bool db_op_return_save(struct node_db *ndb, const uint8_t txid[32],
                       int block_height, const uint8_t *script,
                       size_t script_len, bool is_slp);

/* Sapling spend: stores cv/anchor/nullifier/rk (32B each). */
bool db_sapling_spend_save(struct node_db *ndb, const uint8_t txid[32],
                           uint32_t spend_index,
                           const struct spend_description *sd,
                           int block_height);

/* Sapling output: stores cv/cm/ephemeral_key (32B each) only — NOT the
 * enc/out ciphertext or zkproof. */
bool db_sapling_output_save(struct node_db *ndb, const uint8_t txid[32],
                            uint32_t output_index,
                            const struct output_description *od,
                            int block_height);

/* Sprout JoinSplit: vpub_old/vpub_new (i64), anchor (32B). */
bool db_joinsplit_save(struct node_db *ndb, const uint8_t txid[32],
                       uint32_t js_index, const struct js_description *jsd,
                       int block_height);

/* Sprout nullifier: nullifier PK, the spending txid, block height. */
bool db_sprout_nullifier_save(struct node_db *ndb, const uint8_t nullifier[32],
                              const uint8_t txid[32], int block_height);

/* Per-height SHA3 chained integrity receipt: height PK, 32-byte hash. */
bool db_view_integrity_save(struct node_db *ndb, int64_t height,
                            const uint8_t sha3[32]);

/* Read the receipt recorded at exactly `height`. Returns false for invalid
 * arguments, a closed db, a missing row, or a malformed blob whose length is
 * not exactly 32 bytes. On every false return, `sha3_out` is left untouched. */
bool db_view_integrity_get(struct node_db *ndb, int64_t height,
                           uint8_t sha3_out[32]);

/* Highest height with a recorded view_integrity receipt, or -1 when the db
 * is closed. Mirrors db_utxo_max_height(): an empty table yields 0 (the "no
 * receipts yet" floor, SQLite's MAX() over zero rows), the same quirk
 * db_utxo_max_height/db_block_max_height already carry — single source of
 * truth for "SELECT MAX(height) FROM view_integrity". Read-only — used by
 * catalog_completeness (engine/modules/storage/catalog_completeness.c, reached via a
 * forward declaration, never an #include, to stay clean under the lib/
 * layering gate) to report explorer-projection catch-up lag. */
int64_t db_view_integrity_max_height(struct node_db *ndb);

/* Read the 20-byte address hash recorded for a spent prevout (used to
 * derive a ZNAM op's owner from its first input). Returns false when the
 * prevout row is absent or carries no address (non-P2PKH). */
bool db_tx_output_addr(struct node_db *ndb, const uint8_t txid[32],
                       uint32_t vout, uint8_t addr20[20]);

/* Truncate every explorer projection + on-chain ZNAM table. Used by the
 * -reindex-explorer driver before the genesis..tip re-walk (ZNAM FCFS /
 * TRANSFER are not partial-replay safe, so they MUST be cleared too).
 * node.db only. Returns false (logged) on the first DELETE failure. */
bool db_explorer_index_truncate(struct node_db *ndb);

/* ── The overlay registry (models/explorer_index_overlays.c) ────────
 *
 * index_op_return dispatches every OP_RETURN through ONE registry rather
 * than a hand-rolled if-chain: peek the 4-byte lokad, find its descriptor,
 * run its apply. Adding an overlay is a registration in
 * explorer_index_overlays.c, not an edit to the dispatcher.
 *
 * The registry is process-wide, built once (pthread_once) on first use, and
 * read-only thereafter — never rebuilt per block. Returns NULL only if the
 * one-time build failed to register anything (logged). */
struct overlay_registry;
const struct overlay_registry *explorer_index_overlays(void);

/* Encode a tx's first-input P2PKH signer as a t-address string. This is the
 * ownership rule every OP_RETURN overlay authorizes against (ZNAM ownership =
 * first input's P2PKH signer; znam.h). Resolves the spent prevout's
 * address_hash from tx_outputs — already written because the catchup walk
 * ascends heights. Returns false (→ the caller skips the op) when the first
 * input is non-P2PKH, is a coinbase null prevout, or its prevout row is
 * missing. */
bool explorer_index_owner_address(struct node_db *ndb,
                                  const struct transaction *tx,
                                  char *out, size_t outsize);

/* ── ZID identity feeds (models/explorer_index_zid.c) ───────────────
 *
 * The zid_identities projection has TWO on-chain feeds, per
 * docs/spec/sovereign-identity-layer.md:
 *
 *   1. the ZNAM text convention — SET_TEXT key "zid", value a 64-hex
 *      ed25519 master pubkey (source "znam_text", carries the name), and
 *   2. the dedicated `ZID\0` OP_RETURN overlay — ANCHOR / ROTATE / REVOKE
 *      (source "zid_overlay", unnamed).
 *
 * Both are rebuildable, idempotent, and never fatal: an unauthorized or
 * malformed op is a logged no-op. */

/* Feed 2: project a confirmed `ZID\0` OP_RETURN. Re-parses `script` with
 * zid_anchor_parse (the registry's decoupling contract). ROTATE and REVOKE
 * are refused unless the tx's first-input signer matches the owner_address
 * recorded on the existing row. Returns true iff a row was written. */
bool explorer_index_apply_zid_overlay(struct node_db *ndb,
                                      const struct transaction *tx,
                                      const uint8_t *script, size_t script_len,
                                      int height);

/* Feed 1: called from apply_znam's SET_TEXT case AFTER the upstream owner
 * check and the db_znam_text_save. A key other than "zid", or a value that is
 * not exactly 64 hex chars, is simply not an identity — the text record is
 * stored as usual and nothing is projected. An empty value revokes.
 * `owner` is the verified current owner of `name`. */
void explorer_index_apply_znam_zid_text(struct node_db *ndb,
                                        const struct transaction *tx,
                                        const char *name, const char *key,
                                        const char *value, const char *owner,
                                        int height);

/* ── ZDIR node directory (models/explorer_index_zdir.c) ─────────────
 *
 * Project a confirmed `ZDIR` OP_RETURN into onion_directory — the node's ONLY
 * chain-fed source of other nodes' .onion hostnames. Re-parses `script` with
 * zdir_parse (the registry's decoupling contract). REGISTER is
 * first-come-first-served on the hostname and then owner-locked; DEREGISTER is
 * refused unless the tx's first-input signer matches the owner_address
 * recorded on the existing row. Pure: no network, no clock. Returns true iff a
 * row was written. */
bool explorer_index_apply_zdir_overlay(struct node_db *ndb,
                                       const struct transaction *tx,
                                       const uint8_t *script,
                                       size_t script_len, int height);

/* Apply one parsed SLP Type-1 message (GENESIS/MINT/SEND) to the zslp_tokens
 * + zslp_transfers projection, given the live block's full transaction.
 * Implemented in explorer_index_zslp.c; called from index_op_return on the
 * forward-sync and -reindex-explorer paths. node.db only; never gates a
 * block. zslp_balances is intentionally not written. */
void explorer_index_apply_slp(struct node_db *ndb, const struct transaction *tx,
                              const struct slp_message *m, int height);

/* Fast one-shot ZSLP backfill: re-derive zslp_tokens + zslp_transfers from
 * the existing op_returns rows (is_slp=1), resolving each transfer's
 * recipient from tx_outputs — WITHOUT a full genesis..tip block re-walk.
 * Clears stale zslp_* rows first. zslp_balances is left empty (a credit-only
 * ledger cannot debit SEND inputs). node.db only. Returns the number of SLP
 * op_returns processed (>= 0), or -1 on a fatal error (logged). */
int64_t db_zslp_backfill(struct node_db *ndb);

#endif
