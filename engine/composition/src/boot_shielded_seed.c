/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_shielded_seed — implementation. See config/boot_shielded_seed.h. */

#include "config/boot_shielded_seed.h"

#include "chain/chain.h"                     /* struct block_index */
#include "chain/utxo_snapshot_loader.h"      /* uss_version/uss_shielded */
#include "core/serialize.h"                  /* struct byte_stream */
#include "core/uint256.h"
#include "sapling/incremental_merkle_tree.h" /* sapling/sprout tree */
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/snapshot_shielded.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"           /* active_chain_at */
#include "validation/main_state.h"           /* struct main_state */

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static bool g_interrupt_after_boundary;

void boot_shielded_interrupt_after_boundary_for_test(bool enabled)
{
    g_interrupt_after_boundary = enabled;
}

bool boot_shielded_consume_boundary_interrupt_for_test(void)
{
    bool interrupt = g_interrupt_after_boundary;
    g_interrupt_after_boundary = false;
    return interrupt;
}
#endif

bool boot_shielded_prepare_assisted_boundary(sqlite3 *db, int seed_h)
{
    int64_t boundary = seed_h > 0 ? (int64_t)seed_h : 1;
    return shielded_history_reset_to_boundary(db, boundary);
}

void boot_capture_shielded(struct uss_handle *h, bool load_ok,
                           uint8_t **sapling, uint32_t *sapling_len,
                           bool *shielded_v3,
                           uint8_t **sprout, uint32_t *sprout_len,
                           uint8_t **nfs, uint64_t *nf_count)
{
    if (!h || !load_ok)
        return;

    /* v2: Sapling frontier only. Capture it and return — no Sprout/nullifiers,
     * so the v3 current-state adapter does NOT engage. */
    if (uss_version(h) == 2) {
        const uint8_t *fblob = NULL;
        uint32_t flen = 0;
        if (uss_frontier(h, &fblob, &flen) && fblob && flen > 0 && !*sapling) {
            *sapling = zcl_malloc(flen, "boot.embedded_frontier");
            if (*sapling) {
                memcpy(*sapling, fblob, flen);
                *sapling_len = flen;
                LOG_INFO("boot", "[boot] -load-snapshot-at-own-height: v2 "
                         "snapshot carries a %u-byte Sapling frontier", flen);
            } else {
                LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: OOM "
                         "copying the embedded frontier (%u B) — falling back to "
                         "the block-replay rebuild", flen);
            }
        } else if (!(fblob && flen > 0)) {
            LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: v2 header but "
                     "no readable frontier section — falling back to the "
                     "block-replay rebuild");
        }
        return;
    }

    if (uss_version(h) != 3)
        return;

    const uint8_t *sap = NULL, *spr = NULL, *nf = NULL;
    uint32_t sap_len = 0, spr_len = 0;
    uint64_t nfc = 0;
    if (!uss_shielded(h, &sap, &sap_len, &spr, &spr_len, &nf, &nfc)) {
        LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: v3 header but no "
                 "readable shielded section — falling back to the block-replay "
                 "rebuild");
        return;
    }

    bool cap_ok = true;
    if (sap_len > 0 && !*sapling) {
        *sapling = zcl_malloc(sap_len, "boot.embedded_frontier");
        if (*sapling) { memcpy(*sapling, sap, sap_len); *sapling_len = sap_len; }
        else cap_ok = false;
    }
    if (cap_ok && spr_len > 0) {
        *sprout = zcl_malloc(spr_len, "boot.embedded_sprout");
        if (*sprout) { memcpy(*sprout, spr, spr_len); *sprout_len = spr_len; }
        else cap_ok = false;
    }
    if (cap_ok && nfc > 0) {
        size_t nf_bytes = (size_t)nfc * SNAPSHOT_NF_RECORD_BYTES;
        *nfs = zcl_malloc(nf_bytes, "boot.embedded_nfs");
        if (*nfs) { memcpy(*nfs, nf, nf_bytes); *nf_count = nfc; }
        else cap_ok = false;
    }
    if (cap_ok) {
        *shielded_v3 = true;
        LOG_INFO("boot", "[boot] -load-snapshot-at-own-height: v3 snapshot "
                 "carries Sapling(%uB)+Sprout(%uB) frontiers + %llu nullifiers",
                 sap_len, spr_len, (unsigned long long)nfc);
    } else {
        LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: OOM copying the "
                 "v3 shielded section — falling back to the cursor-reset "
                 "(block-replay backfill) path");
        free(*sprout); *sprout = NULL; *sprout_len = 0;
        free(*nfs);    *nfs = NULL;    *nf_count = 0;
    }
}

static bool reset_shielded_history_incomplete_in_tx(struct sqlite3 *db,
                                                     int seed_h)
{
    return anchor_kv_reset_mark_empty_below_in_tx(db, seed_h) &&
           nullifier_kv_reset_mark_empty_below_in_tx(db, seed_h);
}

/* Co-commit the initial Sapling frontier row for a v2 snapshot (Sapling
 * frontier only — no v3 Sprout/nullifier section) in the SAME transaction as
 * reset_shielded_history_incomplete_in_tx above.  This closes the birth-defect
 * gap the sapling_anchor_frontier_unavailable condition guards: without it the
 * v2 path committed anchor_kv_reset_mark_empty_below_in_tx(seed_h) with an
 * EMPTY sapling_anchors table, so the reset and the frontier row lived in two
 * different transactions (the row was only seeded later by the separate
 * boot_seed_sapling_anchor_frontier_after_reset backstop) — an interruption
 * between them, or an unloaded in-RAM tree, left the empty-below cursor over an
 * empty table and the first shielded-output block above the seed wedged
 * fail-closed.  Seeding it here makes the invariant "reset-mark-empty-below
 * always co-commits the frontier row it marks-empty-below" hold atomically.
 *
 * Fail-SAFE and consensus-neutral: anchor_kv_seed_frontier_row recomputes the
 * frontier's own root and REFUSES (writes nothing, logs) unless it equals the
 * header-committed hashFinalSaplingRoot at seed_h, so an absent / unparseable /
 * misaligned frontier is a clean no-op that defers to the existing
 * after-reset + runtime-condition backstop.  Best-effort by contract: a false
 * return here never fails the outer seed (the reset already succeeded and the
 * backstops remain), so callers ignore it. */
static void seed_v2_sapling_frontier_row_in_tx(
    struct sqlite3 *rpdb, struct main_state *ms, int seed_h,
    const uint8_t *sapling, uint32_t sapling_len)
{
    if (!rpdb || !ms || !sapling || sapling_len == 0)
        return;
    const struct block_index *seed_bi = active_chain_at(&ms->chain_active,
                                                        seed_h);
    static const uint8_t zeros32[32] = {0};
    if (!seed_bi ||
        memcmp(seed_bi->hashFinalSaplingRoot.data, zeros32, 32) == 0)
        return;   /* header root unknown at seed_h — cannot verify; defer */

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct byte_stream ss;
    stream_init_from_data(&ss, sapling, sapling_len);
    if (!incremental_tree_deserialize(&tree, &ss))
        return;   /* unparseable frontier — defer to the backstop */

    if (anchor_kv_seed_frontier_row(rpdb, ANCHOR_POOL_SAPLING, &tree, seed_h,
                                    &seed_bi->hashFinalSaplingRoot))
        LOG_INFO("boot", "[boot] seed_shielded: co-committed the root-verified "
                 "v2 Sapling frontier row at seed h=%d (reset + frontier atomic "
                 "— no empty-table stall on the first shielded block above the "
                 "seed)", seed_h);
    /* On any mismatch anchor_kv_seed_frontier_row already logged and wrote
     * nothing; the after-reset seed / runtime condition stay the backstop. */
}

/* Install v3's current frontiers/nullifier rows in the caller's transaction.
 * v3 contains no proof that its historical anchor set or nullifier prefix is
 * complete: the Sapling frontier root is checked against the local header, but
 * ZClassic headers commit neither old anchors nor nullifiers, and Sprout may be
 * omitted. Keep both completeness cursors at seed_h so every spend/JoinSplit
 * holds until local body backfill (or a later complete-state format) proves the
 * historical prefix. Current frontiers still let output-only blocks fold. */
static bool seed_shielded_from_snapshot(
    struct sqlite3 *rpdb, int seed_h,
    const uint8_t *sap, uint32_t sap_len,
    const struct uint256 *sap_expected_root,
    const uint8_t *spr, uint32_t spr_len,
    const uint8_t *nfs, uint64_t nf_count)
{
    if (!rpdb || !sap || sap_len == 0 || !sap_expected_root) {
        LOG_WARN("boot", "[boot] seed_shielded: missing Sapling frontier args");
        return false;
    }
    if (!reset_shielded_history_incomplete_in_tx(rpdb, seed_h))
        return false;

    /* Sapling — verified against the header-committed root; fail-closed. */
    struct incremental_merkle_tree sap_tree;
    sapling_tree_init(&sap_tree);
    struct byte_stream ss;
    stream_init_from_data(&ss, sap, sap_len);
    if (!incremental_tree_deserialize(&sap_tree, &ss)) {
        LOG_WARN("boot", "[boot] seed_shielded: Sapling frontier decode failed");
        return false;
    }
    if (!anchor_kv_seed_frontier_row(rpdb, ANCHOR_POOL_SAPLING, &sap_tree,
                                     seed_h, sap_expected_root)) {
        LOG_WARN("boot", "[boot] seed_shielded: Sapling frontier REFUSED "
                 "(root mismatch vs hashFinalSaplingRoot) — fail-closed");
        return false;
    }

    /* Sprout — no header commitment; trust bottoms at the snapshot SHA3. */
    if (spr && spr_len > 0) {
        struct incremental_merkle_tree spr_tree;
        sprout_tree_init(&spr_tree);
        struct byte_stream ps;
        stream_init_from_data(&ps, spr, spr_len);
        if (!incremental_tree_deserialize(&spr_tree, &ps)) {
            LOG_WARN("boot", "[boot] seed_shielded: Sprout frontier decode "
                     "failed");
            return false;
        }
        if (!anchor_kv_add_tree(rpdb, ANCHOR_POOL_SPROUT, &spr_tree, seed_h)) {
            LOG_WARN("boot", "[boot] seed_shielded: Sprout frontier add failed");
            return false;
        }
    }

    /* Rows are useful for eventual parity/copy proof, but v3 alone cannot prove
     * they are complete. Persist the positive history-gap marker even when the
     * section is empty; this co-commits with the outer staged install. */
    if (nfs && nf_count > 0) {
        for (uint64_t i = 0; i < nf_count; i++) {
            const uint8_t *rec = nfs + i * SNAPSHOT_NF_RECORD_BYTES;
            uint8_t pool = 0, nf[32];
            int64_t hgt = 0;
            snapshot_shielded_unpack_nf(rec, &pool, nf, &hgt);
            int kvpool = (pool == 0) ? NULLIFIER_POOL_SPROUT
                                     : NULLIFIER_POOL_SAPLING;
            if (hgt < 0) hgt = 0;
            if (!nullifier_kv_add(rpdb, nf, kvpool, hgt)) {
                LOG_WARN("boot", "[boot] seed_shielded: nullifier_kv_add failed "
                         "at record %llu", (unsigned long long)i);
                return false;
            }
        }
    }
    return true;
}

bool boot_shielded_cure_or_reset_in_tx(
    struct sqlite3 *rpdb, struct main_state *ms, int seed_h,
    bool sapling_verified, bool shielded_v3,
    const uint8_t *sapling, uint32_t sapling_len,
    const uint8_t *sprout, uint32_t sprout_len,
    const uint8_t *nfs, uint64_t nf_count)
{
    bool seed_current = shielded_v3 && sapling_verified && sapling &&
                        sapling_len > 0;
    if (!seed_current) {
        if (!reset_shielded_history_incomplete_in_tx(rpdb, seed_h))
            return false;
        /* v2 snapshot (Sapling frontier only): co-commit the verified frontier
         * row in THIS transaction so the empty-below cursor is never committed
         * without its initial frontier row.  Fail-safe no-op when the frontier
         * is absent/unaligned (see seed_v2_sapling_frontier_row_in_tx). */
        seed_v2_sapling_frontier_row_in_tx(rpdb, ms, seed_h, sapling,
                                           sapling_len);
        return true;
    }

    const struct block_index *seed_bi =
        ms ? active_chain_at(&ms->chain_active, seed_h) : NULL;
    if (!seed_bi) {
        LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: v3 shielded seed wanted "
                 "but seed block_index missing at h=%d — falling back to cursor "
                 "reset", seed_h);
        return reset_shielded_history_incomplete_in_tx(rpdb, seed_h);
    }
    if (!seed_shielded_from_snapshot(rpdb, seed_h, sapling, sapling_len,
                                     &seed_bi->hashFinalSaplingRoot,
                                     sprout, sprout_len, nfs, nf_count)) {
        /* Fail-closed: refuse so boot rolls back rather than publish a partial
         * current-state install with inconsistent gap provenance. */
        LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: v3 shielded seed "
                 "FAILED — refusing to arm the fold");
        return false;
    }
    fprintf(stderr,
            "[boot] -load-snapshot-at-own-height: v3 SHIELDED seed installed at "
            "h=%d (Sapling frontier root-verified, Sprout%s, %llu nullifiers, "
            "history incomplete through activation_cursor=%d)\n",
            seed_h, sprout_len ? " installed" : " absent",
            (unsigned long long)nf_count, seed_h);
    return true;
}
