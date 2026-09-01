/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chainstate_legacy_reader: streaming reader for a Bitcoin Core /
 * zclassicd "chainstate" LevelDB.  Walks the entire 'c'-prefixed
 * keyspace (txid -> CCoins record), decodes each record per the
 * Bitcoin Core 0.8+ on-disk format, and emits a struct legacy_coins
 * via callback.
 *
 * Foundation for Option B in plans/make-a-full-detailed-nifty-melody.md:
 * UTXO-snapshot import from a co-located zclassicd.
 *
 * Reentrant-safe: each open handle owns its own LevelDB wrapper +
 * snapshot.  The callback runs on the caller's thread.
 */

#ifndef ZCL_STORAGE_CHAINSTATE_LEGACY_READER_H
#define ZCL_STORAGE_CHAINSTATE_LEGACY_READER_H

#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct legacy_coins_vout {
    unsigned int n;        /* original vout index (some are skipped, "spent") */
    int64_t      value;    /* satoshis */
    const uint8_t *script; /* decompressed scriptPubKey bytes */
    size_t       script_len;
};

struct legacy_coins {
    int      height;       /* block height that included the funding tx */
    bool     coinbase;
    int      version;
    /* One entry per non-spent output, in ascending vout-index order.
     * Spent outputs are absent. */
    struct legacy_coins_vout *vouts;
    size_t   num_vouts;
};

typedef bool (*legacy_chainstate_cb)(const struct uint256 *txid,
                                     const struct legacy_coins *coins,
                                     void *ctx);

/* Open the chainstate LevelDB at `chainstate_path`.  On success
 * stores an opaque handle in *out_handle and returns true.  The
 * directory must not be locked by another process (copy it first if
 * zclassicd is running). */
bool chainstate_legacy_open(const char *chainstate_path, void **out_handle);

/* Release every resource owned by the handle. */
void chainstate_legacy_close(void *handle);

/* Walk every 'c'-prefixed record.  Invokes `cb` exactly once per
 * record (in LevelDB key order).  If the callback returns false,
 * iteration stops early and the count emitted up to that point is
 * returned.  Returns -1 on a fatal decode error.  The legacy_coins
 * pointer and all of its nested buffers (vouts, script) are owned by
 * the reader and remain valid only for the duration of the callback. */
int64_t chainstate_legacy_iter(void *handle,
                               legacy_chainstate_cb cb,
                               void *ctx);

/* Read the best-block hash stored under the single-byte key 'B'. */
bool chainstate_legacy_get_best_block(void *handle, struct uint256 *out);

/* ── Historical Sapling anchor lookup ─────────────────────────────────
 *
 * A zcashd-lineage chainstate persists every historical Sapling
 * note-commitment tree along the active chain, keyed by its root:
 *   key:   'Z' || <32-byte anchor root, raw byte order>
 *   value: serialized SaplingMerkleTree (the IncrementalMerkleTree
 *          boost::optional wire format: optional<left>, optional<right>,
 *          vector<optional<parent>>)
 * The key-schema knowledge (DB_SAPLING_ANCHOR = 'Z') is ported from the
 * Zcash reference — see the ATTRIBUTION block in the .c file. */
struct incremental_merkle_tree;

enum chainstate_anchor_result {
    CHAINSTATE_ANCHOR_ERROR   = -1, /* read / deserialize / verify failure */
    CHAINSTATE_ANCHOR_MISSING =  0, /* no row for this root */
    CHAINSTATE_ANCHOR_FOUND   =  1, /* tree_out valid, root re-verified */
};

/* Look up the Sapling anchor tree stored under ('Z' || root) and
 * deserialize it into *tree_out (which the caller need not pre-init; this
 * calls sapling_tree_init).  FAIL-CLOSED: recomputes the deserialized
 * tree's own root and returns CHAINSTATE_ANCHOR_ERROR (writing nothing
 * usable) on ANY mismatch against the lookup `root` — a borrowed tree is
 * never returned unverified.  Returns CHAINSTATE_ANCHOR_MISSING when the
 * key is absent. */
enum chainstate_anchor_result chainstate_legacy_get_sapling_anchor(
    void *handle, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out);

/* ── Bulk historical iteration (complete anchor + nullifier import) ────
 *
 * These stream the FULL historical Sprout/Sapling anchor and nullifier
 * keyspaces a zclassicd chainstate persists on the active chain, so a wedged
 * C23 store can be filled with the complete set below its reducer cursor in one
 * atomic transaction (see shielded_history_import_service). The key schema is
 * ported from the Zcash reference (txdb.cpp DB_SPROUT_ANCHOR='A',
 * DB_SAPLING_ANCHOR='Z', DB_NULLIFIER='s', DB_SAPLING_NULLIFIER='S',
 * DB_BEST_SPROUT_ANCHOR='a', DB_BEST_SAPLING_ANCHOR='z') — see the ATTRIBUTION
 * block in the .c file. Clean-room over our own dbwrapper + the
 * boost::optional-compatible incremental tree codec; the reference C++ is a
 * format oracle only and is never linked.
 *
 * FAIL-CLOSED / ALL-OR-NOTHING: the anchor iterators re-hash every
 * deserialized tree and ABORT the whole scan (return -1) on ANY anomaly (short
 * key, deserialize failure, trailing bytes, root != key, or a torn-SST /
 * LevelDB status error). A caller treating the range as a COMPLETE set can
 * therefore trust: either every historical record was delivered verified, or
 * the scan returned -1 and nothing may be committed. */
typedef bool (*legacy_anchor_cb)(const struct uint256 *root,
                                 const struct incremental_merkle_tree *tree,
                                 void *ctx);

/* Iterate every Sapling ('Z') / Sprout ('A') anchor. The callback receives the
 * anchor root and the deserialized+root-verified frontier tree (owned by the
 * reader, valid only for the callback). Returning false from the callback
 * aborts the scan and is reported as -1 (a consuming import must be complete).
 * Returns the number of records delivered, or -1 on any anomaly. */
int64_t chainstate_legacy_iter_sapling_anchors(void *handle,
                                               legacy_anchor_cb cb, void *ctx);
int64_t chainstate_legacy_iter_sprout_anchors(void *handle,
                                              legacy_anchor_cb cb, void *ctx);

/* Bulk-import variants of the anchor iterators: identical byte-integrity
 * enforcement (leveldb block-CRC, deserialize success, no trailing bytes) but
 * WITHOUT the per-anchor Pedersen root recompute, whose O(anchors × Pedersen)
 * cost is intractable on the real mainnet historical anchor set. Use ONLY for
 * the complete-shielded import, and ONLY when the caller separately
 * Pedersen-verifies the tip frontier against the header-committed
 * hashFinalSaplingRoot. Same return contract as the verifying variants. */
int64_t chainstate_legacy_iter_sapling_anchors_bulk(void *handle,
                                                    legacy_anchor_cb cb, void *ctx);
int64_t chainstate_legacy_iter_sprout_anchors_bulk(void *handle,
                                                    legacy_anchor_cb cb, void *ctx);

/* Iterate every Sapling ('S') / Sprout ('s') nullifier. The chainstate value
 * is presence-only (a single serialized `true` byte); the 32-byte key IS the
 * spent marker, so the callback receives only the nf bytes. Returns the count,
 * or -1 on a short key, a torn-SST / status error, or a false callback. */
typedef bool (*legacy_nullifier_cb)(const uint8_t nf[32], void *ctx);
int64_t chainstate_legacy_iter_sapling_nullifiers(void *handle,
                                                  legacy_nullifier_cb cb,
                                                  void *ctx);
int64_t chainstate_legacy_iter_sprout_nullifiers(void *handle,
                                                 legacy_nullifier_cb cb,
                                                 void *ctx);

/* Read the current best-anchor pointer: DB_BEST_SAPLING_ANCHOR='z' /
 * DB_BEST_SPROUT_ANCHOR='a' (a bare 1-byte key whose value is the 32-byte
 * active-chain tip root). Returns true and fills *root_out only when the key
 * exists and is exactly 32 bytes; false (with *root_out zeroed) when the key is
 * absent (an empty pool) or on read error. */
bool chainstate_legacy_get_best_sapling_anchor(void *handle,
                                               struct uint256 *root_out);
bool chainstate_legacy_get_best_sprout_anchor(void *handle,
                                              struct uint256 *root_out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_STORAGE_CHAINSTATE_LEGACY_READER_H */
