/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_shielded — the frozen legacy USS v3 SHIELDED section.
 *
 * A v1 snapshot carries only the UTXO records; a v2 snapshot appends a single
 * Sapling commitment-tree frontier ([u32 len][blob]).  A v3 snapshot extends
 * that to also carry the SPROUT commitment-tree frontier and the complete
 * current NULLIFIER set. This can seed a useful current frontier while an
 * explicit historical gap remains: the format does not carry historical
 * anchor rows and must never be labeled a sovereign complete-state cure. The
 * original birth defect was a
 * seed that reset the anchor adoption cursor above genesis over an EMPTY
 * sapling_anchors table, so the first shielded spend fails closed forever).
 *
 * The whole section lives AFTER the UTXO records and INSIDE the body-SHA3
 * region, so it inherits the snapshot's single-hash verifiability.  Byte
 * layout (all integers little-endian):
 *
 *   [u32 sapling_len][sapling_frontier bytes]
 *   [u32 sprout_len ][sprout_frontier  bytes]
 *   [u64 nf_count   ][ nf_count × nullifier record ]
 *
 * nullifier record (SNAPSHOT_NF_RECORD_BYTES bytes):
 *   [u8 pool][u8 nf[32]][i64 height LE]
 *
 * TRUST SCOPE (honest):
 *   - The SAPLING frontier is self-verifiable end-to-end: its computed root is
 *     checked against the PoW-committed hashFinalSaplingRoot at the seed
 *     height before it is ever installed (anchor_kv_seed_frontier_row).  A
 *     mismatch installs nothing (fail-closed).
 *   - The SPROUT frontier and the NULLIFIER set have NO header commitment in
 *     the ZClassic block header, so their trust bottoms out at the snapshot's
 *     overall body SHA3.  They are fully cured later by self-derivation (a
 *     from-genesis / body-replay backfill), not by a header check here.
 */

#ifndef STORAGE_SNAPSHOT_SHIELDED_H
#define STORAGE_SNAPSHOT_SHIELDED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct sha3_256_ctx;
struct sqlite3;

/* 1 pool byte + 32 nullifier bytes + 8 height bytes. */
#define SNAPSHOT_NF_RECORD_BYTES 41

/* One shielded section, as the caller has already serialized the frontiers and
 * packed the nullifier records.  Any region may be empty (len/count 0). */
struct snapshot_shielded {
    const uint8_t *sapling;     uint32_t sapling_len;
    const uint8_t *sprout;      uint32_t sprout_len;
    const uint8_t *nf_records;  uint64_t nf_count;   /* nf_count*41 bytes */
};

/* Serialize `s` to `out` (already positioned after the UTXO records) AND fold
 * the identical bytes into `ctx` so the body SHA3 commits the section.  Returns
 * false on a null required arg or a short write (caller then aborts the temp
 * file). */
bool snapshot_shielded_write(FILE *out, struct sha3_256_ctx *ctx,
                             const struct snapshot_shielded *s);

/* Collect the live SHIELDED consensus state at `height` from the reducer's
 * progress.kv handle into `*out` (the producer half of the sovereign cure):
 *   - the Sapling active-chain frontier (anchor_kv_latest_tree SAPLING),
 *   - the Sprout active-chain frontier (anchor_kv_latest_tree SPROUT),
 *   - every nullifier revealed at height <= `height` (both pools),
 * all in freshly-malloc'd buffers OWNED by `*out`. Pass the result straight to
 * coins_kv_snapshot_write to emit a legacy v3 current-state artifact, then
 * release the buffers with snapshot_shielded_free_collected.
 *
 * FAILS LOUD (returns false, logs, writes nothing to *out) when a frontier is
 * unavailable or a store read errors — a seed that cannot present its shielded
 * frontier must never be written as a coins-only snapshot mislabeled shielded.
 * An absent nullifier table is a clean empty set (fail-open, no wedge). */
bool snapshot_shielded_collect_from_db(struct sqlite3 *db, int64_t height,
                                       struct snapshot_shielded *out);

/* Free the buffers snapshot_shielded_collect_from_db allocated into `s` and
 * zero the struct. Safe on a NULL or already-zeroed struct. */
void snapshot_shielded_free_collected(struct snapshot_shielded *s);

/* Pack ONE nullifier record into rec[SNAPSHOT_NF_RECORD_BYTES]. */
void snapshot_shielded_pack_nf(uint8_t rec[SNAPSHOT_NF_RECORD_BYTES],
                               uint8_t pool, const uint8_t nf[32],
                               int64_t height);

/* Decode ONE nullifier record.  Any out-pointer may be NULL. */
void snapshot_shielded_unpack_nf(const uint8_t rec[SNAPSHOT_NF_RECORD_BYTES],
                                 uint8_t *pool, uint8_t nf[32],
                                 int64_t *height);

#endif /* STORAGE_SNAPSHOT_SHIELDED_H */
