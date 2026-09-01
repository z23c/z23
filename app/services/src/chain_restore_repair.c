// one-result-type-ok:atomic-flag-getter — chain_restore_trust_index_fastpath is a lock-free atomic read with no failure path; chain_restore_finalize already returns zcl_result.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Repair - post-restore block index and active-chain repair.
 * This seam rebuilds the active chain from disk-backed candidates and keeps
 * repair decisions separate from restore-plan execution. */

#include "services/chain_restore_repair.h"
#include "chain_restore_repair_internal.h"
#include "services/chain_restore_boot_snapshot.h"
#include "services/chain_restore_disk_repair.h"
#include "services/chain_restore_executor.h"
#include "services/chain_restore_integrity.h"
#include "services/chain_state_service.h"
#include "services/block_index_integrity.h"
#include "services/utxo_recovery_service.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "primitives/block.h"
#include "storage/boot_auto_reindex.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "net/snapshot_sync_contract.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>

/* ── Post-restore repair ────────────────── */

/* Tier-2 P2 fast restart (see header). Boot-time toggle. */
static _Atomic bool g_trust_index_fastpath = false;

void chain_restore_set_trust_index_fastpath(bool on)
{
    atomic_store(&g_trust_index_fastpath, on);
}

bool chain_restore_trust_index_fastpath(void)
{
    return atomic_load(&g_trust_index_fastpath);
}

static bool chain_restore_candidate_matches_disk(
    const struct block_index *cand,
    const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;
    return chain_restore_block_is_consensus_backed_on_disk(cand, datadir);
}

static int chain_restore_block_index_height_cmp(const void *a, const void *b)
{
    const struct block_index *ia = *(const struct block_index * const *)a;
    const struct block_index *ib = *(const struct block_index * const *)b;
    int ha = ia ? ia->nHeight : -1;
    int hb = ib ? ib->nHeight : -1;
    return (ha > hb) - (ha < hb);
}

static bool chain_restore_fixed_list_push(struct block_index ***items,
                                          size_t *count,
                                          size_t *cap,
                                          struct block_index *p)
{
    if (!items || !count || !cap || !p)
        return false;
    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 64;
        if (new_cap < *cap ||
            new_cap > ((size_t)-1) / sizeof(struct block_index *))
            return false;
        struct block_index **grown = zcl_realloc(
            *items, new_cap * sizeof(struct block_index *),
            "chain_restore/fixed_nbits");
        if (!grown)
            return false;
        *items = grown;
        *cap = new_cap;
    }
    (*items)[(*count)++] = p;
    return true;
}

static void chain_restore_recompute_chainwork_sorted(
    struct block_index **items,
    size_t count)
{
    if (!items || count == 0)
        return;
    qsort(items, count, sizeof(*items), chain_restore_block_index_height_cmp);
    for (size_t i = 0; i < count; i++) {
        struct block_index *p = items[i];
        if (!p)
            continue;
        if (p->pprev) {
            block_index_build_skip(p);
            struct arith_uint256 proof = GetBlockProof(p);
            arith_uint256_add(&p->nChainWork, &p->pprev->nChainWork, &proof);
        } else {
            p->nChainWork = GetBlockProof(p);
        }
    }
}

/* Slot store under the active_chain writer lock: a concurrent window grow
 * republishes c->chain, so an unlocked store could land in a just-retired
 * array and be lost. The store itself stays a plain pointer write per the
 * active_chain contract. */
static void chain_restore_store_slot(struct active_chain *c, int h,
                                     struct block_index *bi)
{
    zcl_mutex_lock(&c->write_lock);
    c->chain[h] = bi;
    zcl_mutex_unlock(&c->write_lock);
}

static bool chain_restore_active_slot_is_canonical(
    const struct active_chain *c,
    int h)
{
    struct block_index *slot = active_chain_at(c, h);
    if (!slot || slot->nHeight != h)
        return false;
    if (h == 0)
        return true;
    return slot->pprev == active_chain_at(c, h - 1);
}

static void chain_restore_log_first_mismatch(
    const struct active_chain *c,
    int h)
{
    if (!c || h < 0)
        return;

    struct block_index *at = active_chain_at(c, h);
    struct block_index *prev_slot = h > 0 ? active_chain_at(c, h - 1) : NULL;
    char at_hash[65] = {0};
    char pprev_hash[65] = {0};
    char prev_slot_hash[65] = {0};
    if (at && at->phashBlock)
        uint256_get_hex(at->phashBlock, at_hash);
    if (at && at->pprev && at->pprev->phashBlock)
        uint256_get_hex(at->pprev->phashBlock, pprev_hash);
    if (prev_slot && prev_slot->phashBlock)
        uint256_get_hex(prev_slot->phashBlock, prev_slot_hash);
    LOG_WARN("chain", "[chain-integrity] first mismatch detail: h=%d at=%p " "at_h=%d at_hash=%s pprev=%p pprev_h=%d pprev_hash=%s " "prev_slot=%p prev_slot_h=%d prev_slot_hash=%s", h, (void *)at, at ? at->nHeight : -1, at_hash[0] ? at_hash : "<null>", at ? (void *)at->pprev : NULL, (at && at->pprev) ? at->pprev->nHeight : -1, pprev_hash[0] ? pprev_hash : "<null>", (void *)prev_slot, prev_slot ? prev_slot->nHeight : -1, prev_slot_hash[0] ? prev_slot_hash : "<null>");
}

/* Publish the container tip after a successful full ancestry rebuild: the
 * rebuilds store slots directly into c->chain[] (bypassing the height bound)
 * and may have REPLACED the tip entry with the disk-verified one, but only
 * active_chain_install_tip_slot raises c->height. Without this, a rebuild
 * that healed every slot can still leave c->height low, so every reader
 * bounded by it (active_chain_at) sees a phantom hole at the tip. Container
 * repair only — never publishes the durable authority. Idempotent. */
static void chain_restore_publish_rebuilt_tip(struct active_chain *c,
                                              int tip_h)
{
    if (!c || tip_h < 0 || tip_h >= c->capacity || !c->chain)
        return;
    /* RAISE-ONLY: at runtime (chain_integrity_failed remedy path) the window
     * is routinely EXTENDED above the finalized tip (c->height = tip_h + K)
     * for tip_finalize's one-block lookahead; install_tip_slot would SHRINK
     * it to tip_h and kneecap the lookahead mid-tick. A window at or above
     * tip_h already exposes the rebuilt slot to every reader — nothing to
     * publish. */
    if (c->height > tip_h)
        return;
    struct block_index *slot = c->chain[tip_h];
    if (!slot)
        return;
    if (c->height == tip_h && active_chain_cached_tip(c) == slot)
        return;
    (void)active_chain_install_tip_slot(c, slot);
}

int chain_restore_rebuild_active_chain(struct main_state *ms,
                                       struct block_index *tip,
                                       const char *datadir)
{
    if (!ms || !tip || tip->nHeight < 0)
        return 0;

    /* Tier-2 P2: under a verified-clean binding, drop the datadir so the
     * disk-backed rebuilds are skipped and only the in-memory pprev walk runs
     * (integrity check downstream stays the fail-safe). */
    if (chain_restore_trust_index_fastpath())
        datadir = NULL;

    struct active_chain *c = &ms->chain_active;
    const int tip_h = tip->nHeight;

    /* The tip must already be installed as the chain tip (so
     * active_chain's capacity covers [0..tip_h]); if a caller hands us
     * a tip that isn't installed, install it via the standard path
     * first. Idempotent when already set.
     *
     * Compare RAW container state (c->height + the raw tip slot), NOT
     * active_chain_tip()/active_chain_height(): those resolve through the
     * tip_finalize AUTHORITY (durable cursor -> block-map hash lookup), so
     * when the container lags the authority (a placeholder-tip rewind left
     * c->height at tip_h-1) they echo the authority's answer, this guard
     * reads "already installed" and never fires, the rebuilds below fill
     * arr[0..tip_h] but nothing raises c->height, and every
     * active_chain_at(tip_h) stays NULL (bounded by c->height) — the
     * post-restore integrity check then fails with a phantom tip-window
     * hole and the node boots DEGRADED until the NEXT process start.
     *
     * RAISE-ONLY: c->height > tip_h is the normal RUNTIME shape (the
     * window is extended above the finalized tip for tip_finalize's
     * lookahead, and this function also runs as the chain_integrity_failed
     * remedy) — installing there would SHRINK the window and starve the
     * lookahead. Only fire when the container is BEHIND the tip or the
     * exact tip slot is wrong. */
    if (c->height < tip_h ||
        (c->height == tip_h && active_chain_cached_tip(c) != tip)) {
        if (tip_h > 1000000) {
            /* The grow must go through the chainstate retire-not-free
             * helper — an in-place realloc here would free an array that
             * lock-free readers (RPC is already serving) may still hold. */
            if (!active_chain_install_tip_slot(c, tip))
                LOG_RETURN(0, "chain_restore",
                           "live tip install failed (tip_h=%d)", tip_h);
            LOG_INFO("chain_restore",
                     "[chain-restore] installed live tip without full "
                     "active_chain walk: h=%d", tip_h);
        } else {
            struct zcl_result cr = chain_restore_commit_tip_via_csr(
                    ms, tip, false, "rebuild_active_chain_full");
            if (!cr.ok)
                return 0;
        }
    }

    int populated = 0;

    if (datadir && datadir[0]) {
        populated = chain_restore_rebuild_active_chain_from_disk(ms, tip,
                                                                datadir);
        if (populated == tip_h + 1) {
            chain_restore_publish_rebuilt_tip(c, tip_h);
            struct chain_integrity_result r;
            chain_integrity_check_post_restore(&r, ms);
            if (r.active_chain_mismatches == 0 &&
                r.tip_window_holes == 0)
                return populated;
            populated = chain_restore_rebuild_active_chain_from_block_files(
                ms, tip, datadir);
            if (populated == tip_h + 1) {
                chain_restore_publish_rebuilt_tip(c, tip_h);
                return populated;
            }
        } else {
            populated = chain_restore_rebuild_active_chain_from_block_files(
                ms, tip, datadir);
            if (populated == tip_h + 1) {
                chain_restore_publish_rebuilt_tip(c, tip_h);
                return populated;
            }
        }
    }

    /* Fast path — walk pprev from tip and slot each ancestor. Covers
     * the happy case (real chain, pprev intact) in O(tip_h). */
    int deepest = tip_h + 1;
    int pprev_walk_budget = tip_h + 1;
    for (struct block_index *p = tip; p != NULL; p = p->pprev) {
        if (--pprev_walk_budget < 0) {
            LOG_WARN("chain_restore",
                     "[chain-restore] stopped cyclic pprev walk during live boot: "
                     "tip_h=%d deepest=%d populated=%d",
                     tip_h, deepest, populated);
            break;
        }
        int h = p->nHeight;
        if (h < 0 || h > tip_h) break;
        bool disk_ok = true;
        if (datadir && datadir[0] &&
            (p->nStatus & BLOCK_HAVE_DATA) && p->nDataPos != 0)
            disk_ok = chain_restore_candidate_matches_disk(p, datadir);
        if (disk_ok) {
            if (c->chain[h] != p) chain_restore_store_slot(c, h, p);
        } else if (c->chain[h] == p) {
            chain_restore_store_slot(c, h, NULL);
        }
        if (h < deepest) deepest = h;
        populated++;
    }

    /* If the pprev walk reached genesis, no residual slot work remains,
     * but flat-file loads may still have left pskip empty. Rebuild
     * missing skip pointers bottom-up so ancestor lookups stay O(log N). */
    if (deepest == 0) {
        for (int h = 1; h <= tip_h; h++) {
            struct block_index *cur = c->chain[h];
            if (cur && cur->pprev && cur->pskip == NULL)
                block_index_build_skip(cur);
        }
        return populated;
    }

    /* Residual holes/mismatches. The capped pprev walk fixes the common
     * high-tip path, but a stale chain_active slot can still contain a
     * non-NULL block_index from a different height. Scan the block_map
     * once across the full active range, then repair every invalid slot
     * in one sweep. This keeps boot O(N) while guaranteeing a bad pointer
     * is not left behind as canonical state. */
    struct block_index **by_height =
        zcl_calloc((size_t)(tip_h + 1), sizeof(struct block_index *),
                   "chain_restore/by_height");
    if (!by_height) {
        LOG_RETURN(populated, "chain_restore",
                   "rebuild_active_chain: by_height calloc failed (tip_h=%d)",
                   tip_h);
    }

    struct block_index **map_indices = NULL;
    size_t map_count = 0;
    if (!block_map_snapshot_indices(&ms->map_block_index, &map_indices,
                                    &map_count)) {
        free(by_height);
        LOG_RETURN(populated, "chain_restore",
                   "rebuild_active_chain: block-map snapshot failed");
    }
    for (size_t i = 0; i < map_count; i++) {
        struct block_index *cand = map_indices[i];
        if (!cand) continue;
        int h = cand->nHeight;
        if (h < 0 || h > tip_h) continue;
        if (chain_restore_active_slot_is_canonical(c, h))
            continue;
        if (cand->nStatus & BLOCK_FAILED_MASK) continue;

        struct block_index *best = by_height[h];
        if (!best) { by_height[h] = cand; continue; }

        /* Prefer BLOCK_HAVE_DATA, then highest nChainWork — matches
         * the tie-break rules so we don't slot a stale
         * fork over a real ancestor. */
        bool best_data = (best->nStatus & BLOCK_HAVE_DATA) != 0;
        bool cand_data = (cand->nStatus & BLOCK_HAVE_DATA) != 0;
        if (cand_data && !best_data) { by_height[h] = cand; continue; }
        if (best_data && !cand_data) continue;

        if (datadir && datadir[0] && cand_data && best_data) {
            bool cand_disk = chain_restore_candidate_matches_disk(cand, datadir);
            bool best_disk = chain_restore_candidate_matches_disk(best, datadir);
            if (cand_disk && !best_disk) { by_height[h] = cand; continue; }
            if (best_disk && !cand_disk) continue;
        }

        if (arith_uint256_compare(&cand->nChainWork,
                                  &best->nChainWork) > 0)
            by_height[h] = cand;
    }
    free(map_indices);

    /* One write_lock hold across the whole no-I/O sweep (vs per-slot):
     * the lock-free at()/canonical reads stay valid under it. */
    zcl_mutex_lock(&c->write_lock);
    for (int h = 0; h <= tip_h; h++) {
        if (chain_restore_active_slot_is_canonical(c, h))
            continue;
        if (by_height[h]) {
            c->chain[h] = by_height[h];
            populated++;
        } else {
            c->chain[h] = NULL;
        }
    }
    zcl_mutex_unlock(&c->write_lock);

    free(by_height);

    /* wire pprev + pskip across the rebuilt chain. The anchor
     * path leaves tip->pprev=NULL and flat-file loads can leave pskip
     * unpopulated, which forces block_index_get_ancestor to fall back
     * to O(N) pprev walks (or NULL on the anchor). Walking bottom-up
     * lets block_index_build_skip reuse each parent's already-built
     * pskip, keeping this pass O(tip_h · log tip_h) — about 1.7M
     * operations at live tip (3M), well under a second.
     *
     * Only wire pprev when it is currently NULL. Forked entries
     * promoted into chain_active by the bucketing step may legitimately
     * point at a different parent — but if we only fill NULLs we can't
     * stomp on an existing ancestry relationship. Same rule for pskip. */
    for (int h = 1; h <= tip_h; h++) {
        struct block_index *cur = c->chain[h];
        if (!cur) continue;
        if (cur->pprev == NULL) {
            struct block_index *prev = c->chain[h - 1];
            if (prev) cur->pprev = prev;
        }
        if (cur->pskip == NULL && cur->pprev)
            block_index_build_skip(cur);
    }

    populated += chain_restore_repair_active_projection(c, tip_h);

    return populated;
}

int chain_restore_backfill_nbits_from_disk(struct main_state *ms,
                                           const char *datadir)
{
    if (!ms || !datadir || !datadir[0])
        return 0;

    /* collect the active tip height once so we can
     * cheaply identify entries that are "off-chain" — i.e. block-index
     * entries not on the current active chain. If those entries have
     * unrecoverable nBits, we can safely clear BLOCK_HAVE_DATA: the
     * data will be re-fetched from a peer if the chain ever activates
     * through them. Doing this lets the integrity gate pass without
     * leaving 34 corrupt nBits=0 entries blocking healthy boots. */
    int tip_h = active_chain_height(&ms->chain_active);

    int fixed = 0, read_errors = 0, invalidated_off_chain = 0;
    struct block_index **fixed_items = NULL;
    size_t fixed_count = 0, fixed_cap = 0;
    size_t iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p) continue;
        if (p->nBits != 0) continue;
        if (p->nHeight <= 0) continue;   /* genesis nBits is set elsewhere */
        if (p->nDataPos == 0) continue;  /* synthetic anchor; no disk data */
        if (!(p->nStatus & BLOCK_HAVE_DATA)) continue;

        struct block blk;
        if (!read_block_from_disk_index_pread(&blk, p, datadir)) {
            /* Disk read failed despite BLOCK_HAVE_DATA. The data file
             * is missing or truncated. If this entry is not on the
             * active chain, drop BLOCK_HAVE_DATA so the integrity gate
             * stops flagging it and the download path can re-fetch.
             * Never touch entries on the active chain — those are
             * load-bearing for chainwork accounting. */
            bool on_active = false;
            if (tip_h >= 0 && p->nHeight <= tip_h) {
                struct block_index *at = active_chain_at(
                    &ms->chain_active, p->nHeight);
                if (at == p) on_active = true;
            }
            if (!on_active) {
                p->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
                invalidated_off_chain++;
            } else {
                read_errors++;
            }
            continue;
        }

        if (blk.header.nBits != 0) {
            if (!chain_restore_fixed_list_push(&fixed_items, &fixed_count,
                                               &fixed_cap, p)) {
                LOG_WARN("chain",
                         "[nbits-backfill] could not track repaired entry "
                         "h=%d for ordered chainwork recompute; leaving it "
                         "unchanged",
                         p->nHeight);
                read_errors++;
                block_free(&blk);
                continue;
            }
            p->nVersion = blk.header.nVersion;
            p->hashMerkleRoot = blk.header.hashMerkleRoot;
            p->hashFinalSaplingRoot = blk.header.hashFinalSaplingRoot;
            p->nTime = blk.header.nTime;
            p->nBits = blk.header.nBits;
            p->nNonce = blk.header.nNonce;
            fixed++;
        }
        block_free(&blk);
    }

    chain_restore_recompute_chainwork_sorted(fixed_items, fixed_count);
    free(fixed_items);

    if (fixed > 0 || read_errors > 0 || invalidated_off_chain > 0)
        LOG_INFO("chain_restore",
                 "[nbits-backfill] fixed=%d pindex entries (read_errors=%d "
                 "off_chain_cleared=%d)",
                 fixed, read_errors, invalidated_off_chain);

    chain_restore_record_backfill_result(fixed, read_errors,
                                         invalidated_off_chain);

    return fixed;
}

int chain_restore_clear_failed_above_tip(struct main_state *ms)
{
    if (!ms)
        return 0;

    int tip_h = active_chain_height(&ms->chain_active);
    if (tip_h < 0)
        return 0;

    int cleared = 0;
    int refetch = 0;
    size_t iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (!p) continue;
        if (p->nHeight <= tip_h) continue;
        unsigned failed = p->nStatus & (unsigned)BLOCK_FAILED_MASK;
        if (!failed) continue;
        p->nStatus &= ~(unsigned)BLOCK_FAILED_MASK;
        cleared++;

        /* Sticky boot (#4a — restart must not deterministically re-wedge):
         * the slot at EXACTLY tip+1 (H*+1) is the wedge slot. Clearing only
         * BLOCK_FAILED while KEEPING the on-disk body re-admits the SAME body
         * that just failed, so the reducer re-folds it into the identical
         * failure and the restart re-wedges at the same height every boot.
         * Break that loop at the source: drop BLOCK_HAVE_DATA for the H*+1
         * slot so the body-fetch stage re-DOWNLOADS the body from a peer and
         * re-validates the FRESH bytes through the full consensus path (parity
         * preserved). If the peer returns a good body, H* climbs and the wedge
         * clears for good; if it returns the same bad body, body_persist's own
         * bounded re-fetch discipline handles it (a named blocker, never a
         * crash). This is the boot half of the peer-sourced wedge cure; the
         * higher successors keep only the FAILED clear (their bodies are
         * re-validated forward and are not the immediate wedge). */
        if (p->nHeight == tip_h + 1 &&
            (p->nStatus & (unsigned)BLOCK_HAVE_DATA)) {
            p->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
            refetch++;
        }
    }

    if (cleared > 0)
        LOG_INFO("chain_restore",
                 "[chain-restore] cleared %d stale BLOCK_FAILED_VALID "
                 "flags above tip h=%d%s", cleared, tip_h,
                 refetch ? " (and dropped HAVE_DATA at H*+1 to force a peer "
                           "body re-fetch instead of re-folding the same "
                           "failed body)" : "");

    return cleared;
}

static bool chain_restore_served_floor(int *out)
{
    *out = -1;
    sqlite3 *db = progress_store_db();
    if (!db)
        return true;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(height), -1) "
            "FROM tip_finalize_log WHERE ok=1",
            -1, &st, NULL) != SQLITE_OK) {
        const char *msg = sqlite3_errmsg(db);
        if (msg && strstr(msg, "no such table") != NULL) {
            progress_store_tx_unlock();
            return true;
        }
        LOG_WARN("chain",
                 "[chain-restore] served floor prepare failed: %s",
                 msg ? msg : "(no message)");
        progress_store_tx_unlock();
        return false;
    }

    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("chain",
                 "[chain-restore] served floor step failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return true;
}

static void chain_restore_quarantine_synthetic_tip(struct main_state *ms,
                                                   const char *datadir)
{
    if (!ms)
        return;

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (!tip)
        return;
    if (datadir && datadir[0]) {
        if (chain_restore_block_is_consensus_backed_on_disk(tip, datadir))
            return;
    } else if (chain_restore_block_is_consensus_backed(tip)) {
        return;
    }

    struct block_index *replacement = (datadir && datadir[0])
        ? chain_restore_nearest_consensus_backed_ancestor_on_disk(tip, datadir)
        : chain_restore_nearest_consensus_backed_ancestor(tip);
    if (!replacement || replacement == tip)
        return;

    int served_floor = -1;
    if (!chain_restore_served_floor(&served_floor))
        return;
    if (served_floor >= 0 && replacement->nHeight < served_floor) {
        LOG_WARN("chain",
                 "[chain-restore] refusing synthetic-tip quarantine below "
                 "durable finalized floor: replacement_h=%d served_floor=%d "
                 "tip_h=%d; public tip remains floored at served finality",
                 replacement->nHeight, served_floor, tip->nHeight);
        return;
    }

    char old_hash[65] = {0};
    char new_hash[65] = {0};
    if (tip->phashBlock)
        uint256_get_hex(tip->phashBlock, old_hash);
    if (replacement->phashBlock)
        uint256_get_hex(replacement->phashBlock, new_hash);

    LOG_INFO("chain", "[chain-restore] quarantining non-consensus active tip " "h=%d hash=%s status=%u file=%d pos=%u tx=%u chaintx=%lld; " "restoring nearest data-backed ancestor h=%d hash=%s", tip->nHeight, old_hash[0] ? old_hash : "<null>", tip->nStatus, tip->nFile, tip->nDataPos, tip->nTx, (long long)tip->nChainTx, replacement->nHeight, new_hash[0] ? new_hash : "<null>");

    struct zcl_result qr = chain_restore_commit_tip_via_csr(
            ms, replacement, ms->pindex_best_header == tip,
            "quarantine_synthetic_tip");
    if (!qr.ok) {
        LOG_WARN("chain", "[chain-restore] failed to quarantine synthetic tip via csr");
    }
}

static void chain_restore_clear_resolved_anchor(struct main_state *ms,
                                               const char *datadir)
{
    if (!ms)
        return;

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    struct block_index *anchor = snapsync_get_anchor();
    bool backed = (datadir && datadir[0])
        ? chain_restore_block_is_consensus_backed_on_disk(tip, datadir)
        : chain_restore_block_is_consensus_backed(tip);
    if (!anchor || !tip || !backed)
        return;
    if (tip->nHeight < anchor->nHeight)
        return;

    LOG_INFO("chain", "[chain-restore] clearing restore anchor h=%d after resolving " "active consensus tip h=%d", anchor->nHeight, tip->nHeight);
    snapsync_set_anchor(NULL);
}

struct zcl_result chain_restore_finalize(struct main_state *ms, const char *datadir)
{
    if (!ms) return ZCL_ERR(-1, "chain_restore_finalize: null main_state");

    chain_restore_quarantine_synthetic_tip(ms, datadir);
    chain_restore_clear_resolved_anchor(ms, datadir);

    /* (c) the rebuild cascade below mutates shared block_index node
     * fields (nStatus/nFile/nDataPos/phashBlock/pprev/pskip/nBits/...) and the
     * active_chain slot array. bg_hash_verification_service reads EXACTLY those
     * fields under ms->cs_main, so this rebuild MUST hold cs_main too —
     * otherwise it tears block_index/active_chain state out from under a
     * concurrent reader (the malloc_trim-during-free heap-corruption SEGV, same
     * class as the fixed phashBlock UAF). The tip read inside this lock uses
     * active_chain_cached_tip(), not active_chain_tip(): the latter can consult
     * the tip authority and, before that authority is registered, fall back
     * through active_chain_height() into progress_store_tx_lock(). Taking that
     * path under cs_main would invert the reducer reconcile order
     * (progress_store_tx_lock -> cs_main). active_chain_cached_tip() is the raw,
     * lock-free container read and keeps this section on cs_main only, followed
     * by cs_main -> csr->lock (small-tip commit) or cs_main ->
     * active_chain.write_lock. Released before the lock-free post-restore
     * integrity reader below. The rebuild path takes no coins_kv, so the
     * LOCK-ORDER LAW (drive's coins_kv never crosses cs_main) is preserved. */
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *tip = active_chain_cached_tip(&ms->chain_active);
    if (tip)
        (void)chain_restore_rebuild_active_chain(ms, tip, datadir);

    if (datadir && datadir[0])
        (void)chain_restore_backfill_nbits_from_disk(ms, datadir);

    /* Catch-all band-hole scan: a tip not contiguously linked to its
     * trust root means headers below it were installed above the
     * frontier — record the fact loudly (record-only) so the header
     * planner backfills the band. Covers every producer path that
     * reaches finalize, including ones not enumerated above. No-op for
     * trust-rooted chains and at band closure. */
    if (tip)
        utxo_recovery_note_band_unrooted_tip(tip, "chain_restore_finalize");
    zcl_mutex_unlock(&ms->cs_main);

    struct chain_integrity_result r;
    chain_integrity_check_post_restore(&r, ms);

    /* also record csr-side tip ↔ coins_best_block
     * consistency in the boot snapshot. csr_snapshot is idempotent
     * and returns tip_height=-1 if csr isn't initialized (some test
     * paths), in which case we leave csr_consistency_checked=false. */
    {
        struct chain_state_repository *csr = csr_instance();
        if (csr && csr->initialized) {
            struct chain_state_view view;
            csr_snapshot(csr, &view);
            chain_restore_record_csr_consistency(
                view.consistent, view.tip_height, view.header_height);
            if (!view.consistent) {
                LOG_INFO("chain", "[chain-integrity] CSR tip/coins divergence at boot: " "tip_h=%d header_h=%d — first reducer activation " "pass should reconcile", view.tip_height, view.header_height);
            }
        }
    }

    if (!r.ok) {
        /* `r.ok` also folds in tip_slot_ok / tip_real (the tip block being
         * data-backed), which are NOT in the counter message — so a benign
         * header-only / live-tip-only boot can flip r.ok false with every
         * counter at zero. Classify first so the log names the real state:
         * only zero-nbits or active-chain height/pprev mismatches are
         * UNRECOVERABLE corruption; everything else is RECONCILABLE and the
         * reducer fixes it forward. (Logging only — the return below is
         * unchanged.) */
        if (chain_integrity_classify(&r) == CHAIN_INTEGRITY_UNRECOVERABLE) {
            LOG_WARN("chain", "[chain-integrity] post-restore check FAILED "
                "(UNRECOVERABLE): zero_nbits=%d (first_h=%d) tip_window_holes=%d "
                "(first_h=%d) total_holes=%d mismatches=%d (first_h=%d) tip_h=%d",
                r.zero_nbits_count, r.first_nbits_zero_height, r.tip_window_holes,
                r.first_tip_window_hole, r.active_chain_holes,
                r.active_chain_mismatches, r.first_mismatch_height, r.tip_height);
            chain_restore_log_first_mismatch(&ms->chain_active,
                                             r.first_mismatch_height);
        } else {
            LOG_WARN("chain",
                     "[chain-integrity] post-restore check RECONCILABLE: tip_h=%d "
                     "(zero_nbits=%d tip_window_holes=%d mismatches=%d; tip not "
                     "yet data-backed) — reducer will reconcile forward",
                     r.tip_height, r.zero_nbits_count, r.tip_window_holes,
                     r.active_chain_mismatches);
        }
    } else if (tip) {
        /* Holes below tip-WINDOW are expected (live-tip-only boot)
         * and not corruption — report them at INFO so operators
         * can see the chain shape without alarm. */
        if (r.active_chain_holes > 0)
            LOG_INFO("chain",
                     "[chain-integrity] post-restore check OK: "
                     "tip_h=%d tip_window clean, "
                     "%d expected holes below tip-%d (live-tip-only boot)",
                     r.tip_height, r.active_chain_holes,
                     CHAIN_INTEGRITY_TIP_WINDOW);
        else
            LOG_INFO("chain",
                     "[chain-integrity] post-restore check OK: "
                     "tip_h=%d nbits clean, active_chain full",
                     r.tip_height);
        bii_record_recovery_status(
            BII_OK, BII_RECOVERY_ACCEPTED,
            "post-restore integrity clean; active chain reconciled",
            false, false);
        /* Integrity is verifiably clean — any auto-reindex sentinel is
         * stale (already served, or written for a state that no longer
         * exists). Without this, a stale pending sentinel makes every
         * subsequent healthy boot re-run a full -reindex-chainstate
         * forever. The TERMINAL marker must clear here too: it means
         * "budget exhausted at a stall that needs a human", but the node
         * is now provably healthy, so leaving it would permanently poison
         * the reindex path for the NEXT genuine episode — a clear gated only
         * on pending() never fires for a terminal marker. */
        if (datadir && datadir[0]) {
            bool was_terminal = boot_auto_reindex_is_terminal(datadir);
            if (was_terminal || boot_auto_reindex_pending(datadir)) {
                boot_auto_reindex_clear(datadir);
                LOG_INFO("chain",
                         "[chain-integrity] cleared stale auto-reindex "
                         "sentinel (%s): post-restore integrity is clean",
                         was_terminal ? "terminal" : "pending");
            }
        }
    }

    if (!r.ok)
        return ZCL_ERR(-2,
                       "post-restore integrity FAILED: zero_nbits=%d "
                       "tip_window_holes=%d total_holes=%d mismatches=%d "
                       "tip_h=%d tip_slot_ok=%d tip_real=%d",
                       r.zero_nbits_count, r.tip_window_holes,
                       r.active_chain_holes, r.active_chain_mismatches,
                       r.tip_height, (int)r.tip_slot_ok, (int)r.tip_real);
    return ZCL_OK;
}
