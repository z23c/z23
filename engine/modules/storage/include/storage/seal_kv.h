/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seal_kv — the state-seal ring, the OUTPUT companion to rolling_anchor's
 * INPUT (block-bytes) windows. A seal pins the reducer's coins_kv UTXO set
 * at a 1000-block grid point G: its SHA3 commitment, count, supply, and the
 * active-chain block hash it was computed against. Seals let a future
 * window_rebuild reset to a verified checkpoint and replay forward (the
 * tenacity-roadmap §4 "recompute, never repair" verb) instead of falling
 * all the way back to the compiled checkpoint.
 *
 * STORAGE: a fixed 4-slot ring lives in progress_meta (NOT a new table) so a
 * candidate seal co-commits in the SAME BEGIN IMMEDIATE as the coin mutation
 * + cursor that produced it (the coins_kv co-commit theorem extends to it).
 * Zero migration; one blob per slot key "seal_slot_0".."seal_slot_3" + a head
 * index "seal_ring_head". RAISE-ONLY by height: a candidate at G <= the
 * newest existing seal height is a no-op. A corrupt latest slot steps the
 * ring back one slot rather than paging — the whole point of the ring.
 *
 * The seal RECORDS consensus state; it never changes validity (no E13
 * surface). Every function operates on the passed progress.kv handle and
 * participates in whatever transaction the caller already holds open; the
 * _in_tx variants require the caller to hold progress_store_tx_lock + an
 * open BEGIN IMMEDIATE, the read helpers acquire the recursive lock
 * themselves. */

#ifndef ZCL_STORAGE_SEAL_KV_H
#define ZCL_STORAGE_SEAL_KV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;
struct json_value;

#define SEAL_RING_SLOTS      4
#define SEAL_RECORD_VERSION  1u

/* progress_meta keys. */
#define SEAL_SLOT_KEY_PREFIX "seal_slot_"   /* + "0".."3" */
#define SEAL_HEAD_KEY        "seal_ring_head" /* 8-byte LE int; index of the
                                              * newest slot. -1 / absent = empty */

/* Canonical serialized size, fixed per slot. See seal_serialize for the
 * exact byte layout:
 *   [1 version][4 height][32 block_hash][32 coins_sha3][32 nullifier_sha3]
 *   [32 anchor_window_sha3][8 utxo_count][8 supply][1 ratified][8 sealed_at]
 *   [32 self_sha3]  = 158 prefix + 32 self_sha3 = 190 bytes. */
#define SEAL_RECORD_BYTES    190

/* In-memory seal record. */
struct seal_record {
    int32_t  height;                 /* grid point G (multiple of 1000) */
    uint8_t  block_hash[32];         /* active-chain hash at G at candidate time */
    uint8_t  coins_sha3[32];         /* coins_kv_commitment over the set at G */
    uint8_t  nullifier_sha3[32];     /* RECORDED, all-zero in M1 (see below) */
    uint8_t  anchor_window_sha3[32]; /* rolling_anchor window hash ending at G-1,
                                      * or zero if no such window committed */
    int64_t  utxo_count;             /* coins_kv_setinfo num_txouts */
    int64_t  supply;                 /* coins_kv_setinfo total_amount */
    uint8_t  ratified;               /* 0 candidate, 1 ratified */
    int64_t  sealed_at;              /* wall seconds when the candidate was inserted */
    uint8_t  self_sha3[32];          /* SHA3 over all preceding fields, canonical LE */
};

/* nullifier_sha3 is all-zero in M1 — the nullifier set is incomplete on every
 * cold-synced datadir (storage/nullifier_kv.h:33-44 ACTIVATION GAP), so a
 * nullifier commitment cannot be a ratify gate without false-paging. The field
 * exists so a future from-genesis-only tightening can populate it without a
 * schema change. */

/* No-op besides progress_meta_table_ensure(db). Kept for symmetry/idempotence;
 * call once in seal_service_init. */
bool seal_kv_ensure_schema(struct sqlite3 *db);

/* Serialize r into out[190], filling out's last 32 bytes with self_sha3 =
 * sha3_256(out[0 .. 158)). Returns false on NULL args. */
bool seal_serialize(const struct seal_record *r, uint8_t out[SEAL_RECORD_BYTES]);

/* Deserialize in[len] into *out. len must == SEAL_RECORD_BYTES and version must
 * match. *self_ok (non-NULL) is set true iff the recomputed self_sha3 matches
 * the stored one. Returns false on a hard parse failure (bad len/version); a
 * version/len-valid record with a self_sha3 mismatch still returns true with
 * *self_ok=false so the ring can step over it. */
bool seal_deserialize(const uint8_t *in, size_t len, struct seal_record *out,
                      bool *self_ok);

/* Insert a candidate (forces ratified=0) into the next ring slot, IN the
 * caller's open txn (no inner BEGIN/COMMIT). RAISE-ONLY: returns true as a
 * no-op if r->height <= the newest existing self-valid seal height. */
bool seal_kv_insert_candidate_in_tx(struct sqlite3 *db,
                                    const struct seal_record *r);

/* Read the newest seal (ratified or not). *found=false on an empty ring.
 * Skips any slot whose self_sha3 is invalid. SELECT-only (acquires the
 * recursive tx lock). */
bool seal_kv_newest(struct sqlite3 *db, struct seal_record *out, bool *found);

/* Read the newest RATIFIED seal. *found=false if none. Skips corrupt slots. */
bool seal_kv_newest_ratified(struct sqlite3 *db, struct seal_record *out,
                             bool *found);

/* Find the (self-valid) seal at exactly height g and report its slot index.
 * *found=false if no such slot. */
bool seal_kv_get_at_height(struct sqlite3 *db, int32_t g,
                           struct seal_record *out, bool *found, int *out_slot);

/* Select the NEAREST self-valid rewind base at or below target height H: the
 * self-valid seal with the HIGHEST height <= H. This is the O(delta) recovery
 * entry point — a torn/deep rewind resets the reducer to THIS seal instead of
 * the single compiled SHA3 checkpoint, so re-derivation folds only [G, H]
 * rather than [checkpoint, H]. Returns true on a clean scan; *found=false when
 * the ring holds no self-valid seal at/below H (the caller then falls back to
 * the compiled checkpoint). On found, *out is the base record: its `height` is
 * the rewind target G and its `coins_sha3` is the commitment the executor must
 * REPRODUCE by re-deriving the coins set at G — never trust the stored value
 * alone. Skips any slot whose self_sha3 is invalid. SELECT-only (acquires the
 * recursive tx lock). */
bool seal_kv_nearest_rewind_base(struct sqlite3 *db, int32_t H,
                                 struct seal_record *out, bool *found);

/* Mark slot ratified=1 IN the caller's open txn: sets r->ratified=1,
 * re-serializes, rewrites the slot key. Returns false on a write error. */
bool seal_kv_mark_ratified_in_tx(struct sqlite3 *db, int slot,
                                 struct seal_record *r);

/* `z23 dumpstate seal` dumps the whole ring (4 slots + head) as JSON. */
bool seal_kv_dump_state_json(struct json_value *out, const char *key);

/* ── prune on ratify — seal advance IS retention (M1 LANDS DARK) ──
 *
 * SEAL_PRUNE_ENABLED is 0 in M1: the ratifier does NOT call the prune, so M1
 * is zero-behavior-change and proves itself purely by ACCUMULATING ratified
 * seals. The function + the dark call site are wired so a follow-up flips the
 * flag to 1 once seals demonstrably accumulate on a copy. Until then no rows
 * are ever deleted. */
#define SEAL_PRUNE_ENABLED 0
/* Keep stage *_log tails generous: utxo_apply_log is the boot resolver's
 * contiguity witness, so prune only far below the seal. */
#define SEAL_LOG_RETENTION 10000

/* Prune sealed history below grid point G, IN the caller's open txn:
 *   - DELETE utxo_apply_delta WHERE height <= G (the inverse-delta is only
 *     needed to unwind ABOVE the seal; below S it is sealed-domain, unwindable
 *     only by recompute).
 *   - DELETE stage *_log rows (validate_headers_log, body_persist_log,
 *     script_validate_log, proof_validate_log, utxo_apply_log)
 *     WHERE height <= G - SEAL_LOG_RETENTION.
 * NEVER touches tip_finalize_log (the trusted-base/anchor row source) and
 * NEVER touches nullifiers (permanent consensus state). Returns false on any
 * delete error so the caller can ROLLBACK. */
bool seal_prune_below_in_tx(struct sqlite3 *db, int32_t G);

#endif /* ZCL_STORAGE_SEAL_KV_H */
