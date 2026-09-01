/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * anchor_selfmint — SELF-MINT the SHA3-verified anchor snapshot during a
 * NORMAL fold, so a verified <datadir>/utxo-anchor.snapshot becomes reachable
 * WITHOUT an operator running the offline `-mint-anchor` ceremony.
 *
 * WHY: the torn-import auto-arm self-heal (boot_anchor_seed_from_snapshot,
 * engine/composition/src/boot_refold_staged.c) re-seeds coins_kv from the MINTED snapshot
 * artifact when a durable cold-import tear is detected. On a plain install no
 * such snapshot exists at the path mint_snapshot_path resolves
 * ($ZCL_MINT_ANCHOR_OUT, else <datadir>/utxo-anchor.snapshot), so the self-heal
 * has nothing to re-seed from. The project vision is a ~15 MB self-contained
 * binary, so the 101 MB snapshot CANNOT be baked in-binary; instead the node
 * mints it from its OWN already-validated fold the first time the fold lands the
 * compiled checkpoint height.
 *
 * CONTRACT (OBSERVE-ONLY, BEST-EFFORT — exactly like seal_service):
 *   - This NEVER changes any consensus predicate or the fold result. It only
 *     PERSISTS a snapshot of already-validated state (coins_kv at the moment it
 *     provably holds the applied-through-anchor set).
 *   - void return: a write/verify failure MUST NOT fail the block. It is logged
 *     (LOG_WARN) and dropped, never propagated.
 *   - One-shot at the EXACT checkpoint height: fires only when
 *     next_cursor == get_sha3_utxo_checkpoint()->height (the apply that lands the
 *     anchor; next_cursor == cursor_in + 1). At that instant coins_kv holds the
 *     applied-through-anchor set inside the caller's stage txn.
 *   - Idempotent: if a valid SHA3-verified snapshot already exists at the path,
 *     it is left untouched (no rewrite).
 *   - HARD-VERIFY before trust: the writer streams atomically (tmp + rename);
 *     after the write the body SHA3 + count are checked against the compiled
 *     checkpoint, and a MISMATCH unlinks the file (never leaves an unverified
 *     artifact a later -refold-from-anchor could load).
 *
 * The hook runs INSIDE the utxo_apply step_apply BEGIN IMMEDIATE (beside the
 * seal candidate hook), so the coins it scans are exactly the committed
 * anchor set. The one-time ~1 s 101 MB scan happens once per node lifetime at
 * the single anchor-crossing height (the seal hook already does a ~1 s in-txn
 * coins scan at its grid points), and only when no verified snapshot exists yet.
 */

#ifndef ZCL_SERVICES_ANCHOR_SELFMINT_H
#define ZCL_SERVICES_ANCHOR_SELFMINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;

#define ANCHOR_SELFMINT_PATH_MAX 1100

struct anchor_snapshot_status {
    bool path_resolved;
    char path_source[32];
    char path[ANCHOR_SELFMINT_PATH_MAX];

    bool stat_present;
    int64_t stat_size;

    bool checkpoint_present;
    int32_t checkpoint_height;
    uint64_t checkpoint_utxo_count;
    int64_t checkpoint_total_supply;
    char checkpoint_sha3_hex[65];
    char checkpoint_block_hash_hex[65];

    bool header_read;
    uint32_t snapshot_height;
    uint64_t snapshot_count;
    int64_t snapshot_total_supply;
    char snapshot_sha3_hex[65];
    char snapshot_block_hash_hex[65];

    bool height_match;
    bool count_match;
    bool sha3_match;
    bool block_hash_match;
    bool verified;
    char verification[96];
    char error[256];
    char next_action[256];
};

/* Self-mint hook. Call from the utxo_apply step_apply txn after the cursor +
 * applied-height are stamped (beside seal_candidate_hook_in_tx). `datadir` is
 * the node's data directory (used to resolve <datadir>/utxo-anchor.snapshot when
 * $ZCL_MINT_ANCHOR_OUT is unset); may be NULL/empty (then "." is used).
 * `next_cursor` is the just-applied frontier (cursor_in + 1). No-op unless
 * next_cursor == the compiled SHA3 checkpoint height. Best-effort, void. */
void anchor_selfmint_hook_in_tx(struct sqlite3 *db, const char *datadir,
                                int32_t next_cursor);

/* Pure path resolver, shared with the boot reachability probe and the test:
 * $ZCL_MINT_ANCHOR_OUT, else <datadir>/utxo-anchor.snapshot (datadir NULL/empty
 * -> "."). Returns true and fills buf on success. */
bool anchor_selfmint_resolve_path(const char *datadir, char *buf, size_t cap);

/* Read-only readiness probe for the self-verified UTXO anchor rebuild. This is
 * the same predicate used before trusting a snapshot (and the same one
 * boot_legacy_uss_matches_checkpoint applies on the cold path): stat the
 * resolved candidate, inspect its header, uss_open(verify_full_sha3=true,
 * expected_sha3=NULL) to bind the whole artifact to its own header hash, then
 * uss_utxo_component_compute() to bind the COINS-ONLY commitment to the compiled
 * checkpoint. This accepts a v1 (coins-only) OR v3 (coins+shielded) artifact —
 * the checkpoint pins the coins commitment, never the v3 full-body hash. No
 * coins_kv mutation. */
bool anchor_selfmint_snapshot_status(const char *datadir,
                                     struct anchor_snapshot_status *out);

#endif /* ZCL_SERVICES_ANCHOR_SELFMINT_H */
