/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Integrity — see block_index_integrity.h for rationale.
 *
 * Implementation notes
 * --------------------
 * Sidecar hashing and SQLite cross-checks live in
 * block_index_sidecar_integrity.c. This file owns runtime status plus
 * structural height/pprev/anchor repair.
 */

// one-result-type-ok:repair-counts-and-out-struct — E2 (one way out): this is
// a block-index repair toolkit, not a pass/fail service. The repair entry
// points return int *counts* of entries fixed (block_index_repair_heights /
// _pprev — callers accumulate them: `index_repaired += ...`), not error
// codes; bii_repair_post_activation_anchor returns 0/-1 sentinels (each
// `raw-return-ok:sentinel`) while its real verdict travels in struct
// bii_post_activation_result (tip_restored / tip_restore_refused / heights
// fixed). The remaining surface is enum->name getters (const char*), void
// status recorders/getters, and one bool status query
// (block_index_heights_repaired). No fallible bool/int loses a reason:
// repair outcomes are logged + emitted via EV_BLOCK_INDEX_REPAIR, and the tip
// restore path goes through csr_commit_tip (enum csr_result, logged on
// refusal).

#include "platform/time_compat.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"
#include "services/block_index_integrity.h"

#include "services/chain_state_service.h"
#include "util/safe_alloc.h"
#include "event/event.h"
#include "json/json.h"
#include "core/uint256.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "storage/disk_block_io.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

/* ── Verdict names ──────────────────────────────────────────── */

const char *bii_verdict_name(enum bii_verdict v)
{
    switch (v) {
    case BII_OK:                   return "ok";
    case BII_SIDECAR_MISSING:      return "sidecar_missing";
    case BII_SIDECAR_STALE:        return "sidecar_stale";
    case BII_HASH_MISMATCH:        return "hash_mismatch";
    case BII_TIP_HEIGHT_MISMATCH:  return "tip_height_mismatch";
    case BII_TIP_MISSING_IN_SQL:   return "tip_missing_in_sql";
    case BII_BODY_MISSING:         return "body_missing";
    case BII_BODY_UNREADABLE:      return "body_unreadable";
    case BII_SIDECAR_BAD_MAGIC:    return "sidecar_bad_magic";
    case BII_SIDECAR_UNSUPPORTED:  return "sidecar_unsupported";
    default:                       return "unknown";
    }
}

const char *bii_recovery_action_name(enum bii_recovery_action a)
{
    switch (a) {
    case BII_RECOVERY_NONE:               return "none";
    case BII_RECOVERY_ACCEPTED:           return "accepted";
    case BII_RECOVERY_RECONCILE_REQUIRED: return "reconcile_required";
    case BII_RECOVERY_QUARANTINED:        return "quarantined";
    case BII_RECOVERY_OVERRIDE:           return "override";
    default:                              return "unknown";
    }
}

static pthread_mutex_t g_bii_status_lock = PTHREAD_MUTEX_INITIALIZER;
static struct bii_recovery_status g_bii_status;

void bii_record_recovery_status(enum bii_verdict verdict,
                                enum bii_recovery_action action,
                                const char *reason,
                                bool degraded,
                                bool unsafe_override)
{
    pthread_mutex_lock(&g_bii_status_lock);
    memset(&g_bii_status, 0, sizeof(g_bii_status));
    g_bii_status.verdict = verdict;
    g_bii_status.action = action;
    g_bii_status.unix_time = (int64_t)platform_time_wall_time_t();
    g_bii_status.degraded = degraded;
    g_bii_status.unsafe_override = unsafe_override;
    if (reason)
        snprintf(g_bii_status.reason, sizeof(g_bii_status.reason),
                 "%s", reason);
    pthread_mutex_unlock(&g_bii_status_lock);

    event_emitf(EV_BLOCK_INDEX_REPAIR, 0,
                "verdict=%s action=%s degraded=%s unsafe_override=%s reason=%s",
                bii_verdict_name(verdict),
                bii_recovery_action_name(action),
                degraded ? "true" : "false",
                unsafe_override ? "true" : "false",
                reason ? reason : "");
}

void bii_get_recovery_status(struct bii_recovery_status *out)
{
    if (!out) return;
    pthread_mutex_lock(&g_bii_status_lock);
    *out = g_bii_status;
    pthread_mutex_unlock(&g_bii_status_lock);
}

/* ── Bulk block index height repair ────────────────────────── */

/* True iff `b` is the real genesis block BY HASH. Positional genesis
 * tests (`!pprev`) are forbidden in every repair below: an entry whose
 * parent header is merely missing/unlinked is a DETACHED ROOT, not
 * genesis. Stamping such a root to height 0 and propagating can relabel
 * the entire block index by a constant offset (parent in the map but
 * pprev link lost) — internally consistent, so every later pass calls
 * it "correct", every new network block then fails bad-cb-height, and
 * the tip freezes. */
static bool bii_is_genesis(const struct block_index *b)
{
    const struct chain_params *cp = chain_params_get();
    if (!b || !b->phashBlock || !cp)
        return false;
    return uint256_eq(b->phashBlock, &cp->consensus.hashGenesisBlock);
}

static _Atomic bool g_heights_repaired = false;

bool block_index_heights_repaired(void)
{
    return atomic_load(&g_heights_repaired);
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe: reuses the
 * lock-guarded bii_get_recovery_status() snapshot. */
bool block_index_integrity_dump_state_json(struct json_value *out,
                                           const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct bii_recovery_status st;
    bii_get_recovery_status(&st);
    json_push_kv_str(out, "verdict", bii_verdict_name(st.verdict));
    json_push_kv_str(out, "action", bii_recovery_action_name(st.action));
    json_push_kv_int(out, "unix_time", st.unix_time);
    json_push_kv_bool(out, "degraded", st.degraded);
    json_push_kv_bool(out, "unsafe_override", st.unsafe_override);
    json_push_kv_str(out, "reason", st.reason);
    json_push_kv_bool(out, "heights_repaired",
                      block_index_heights_repaired());
    return true;
}

/* Comparator for sorting block_index pointers by height (ascending). */
static int bii_cmp_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index *const *)a;
    const struct block_index *pb = *(const struct block_index *const *)b;
    return (pa->nHeight > pb->nHeight) - (pa->nHeight < pb->nHeight);
}

/* Pointer-identity sort + lookup for the genesis-reachability marks in
 * block_index_repair_heights (no spare field on block_index to borrow). */
static int bii_cmp_ptr(const void *a, const void *b)
{
    uintptr_t pa = (uintptr_t)*(const struct block_index *const *)a;
    uintptr_t pb = (uintptr_t)*(const struct block_index *const *)b;
    return (pa > pb) - (pa < pb);
}

/* Index of `b` in the pointer-sorted array, or `n` when absent (an
 * entry whose pprev points outside the map snapshot). */
static size_t bii_ptr_index(struct block_index *const *byptr, size_t n,
                            const struct block_index *b)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if ((uintptr_t)byptr[mid] < (uintptr_t)b)
            lo = mid + 1;
        else
            hi = mid;
    }
    return (lo < n && byptr[lo] == b) ? lo : n;
}

static int bii_cmp_disk_pos(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index *const *)a;
    const struct block_index *pb = *(const struct block_index *const *)b;

    if (pa->nFile != pb->nFile)
        return (pa->nFile > pb->nFile) - (pa->nFile < pb->nFile);
    return (pa->nDataPos > pb->nDataPos) -
           (pa->nDataPos < pb->nDataPos);
}

static size_t bii_pprev_repair_max_reads(void)
{
    const char *env = getenv("ZCL_PPREV_REPAIR_MAX_READS");
    char *end = NULL;
    long parsed;

    if (!env || env[0] == '\0')
        return 0;

    parsed = strtol(env, &end, 10);
    if (end == env || *end != '\0' || parsed < 0)
        return 0;

    return (size_t)parsed;
}

int block_index_repair_heights(struct main_state *ms)
{
    return block_index_repair_heights_range(ms, -1, NULL);
}

int block_index_repair_heights_range(struct main_state *ms, int min_height,
                                     int *out_max_height)
{
    if (out_max_height) *out_max_height = -1;
    if (!ms) return 0;

    struct timespec t0;
    platform_time_monotonic_timespec(&t0);

    size_t n = ms->map_block_index.size;
    if (n == 0) {
        atomic_store(&g_heights_repaired, true);
        return 0;
    }

    /* Pass 1: count entries with wrong heights. Parentless entries are
     * judged BY HASH: only the true genesis must sit at 0. A parentless
     * non-genesis entry is a detached root — its stored height is the
     * only truth we have until block_index_repair_pprev relinks it from
     * the durable prev-hash record, so it is reported, never counted as
     * "wrong" (see bii_is_genesis for the relabel failure mode). */
    int wrong = 0;
    int detached = 0;
    int max_h = -1;
    {
        size_t iter = 0;
        struct block_index *pi;
        const struct block_index *first_detached = NULL;
        while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
            if (!pi) continue;
            if (pi->nHeight > max_h) max_h = pi->nHeight;
            /* Cursor gate (OS-S2 #1): a prior verified run already covered
             * entries at/below min_height, so only re-count wrongs above it.
             * The true genesis is always checked (it must sit at 0). */
            if (pi->pprev && pi->nHeight > min_height &&
                pi->nHeight != pi->pprev->nHeight + 1)
                wrong++;
            else if (!pi->pprev) {
                if (bii_is_genesis(pi)) {
                    if (pi->nHeight != 0)
                        wrong++;
                } else if (pi->nHeight > min_height &&
                           (pi->nHeight != 0 || (pi->nStatus & BLOCK_HAVE_DATA))) {
                    detached++;
                    if (!first_detached)
                        first_detached = pi;
                }
            }
        }
        if (out_max_height) *out_max_height = max_h;
        if (detached > 0 && first_detached && first_detached->phashBlock) {
            char hex[65];
            uint256_get_hex(first_detached->phashBlock, hex);
            LOG_WARN("height", "[height-repair] %d detached non-genesis root(s) "
                     "(first %s h=%d) — heights preserved; pprev repair must "
                     "relink them", detached, hex, first_detached->nHeight);
        }
    }

    if (wrong == 0) {
        printf("[height-repair] all %zu block index heights correct\n", n);
        fflush(stdout);
        atomic_store(&g_heights_repaired, true);
        return 0;
    }

    printf("[height-repair] found %d/%zu entries with wrong heights, repairing...\n",
           wrong, n);
    fflush(stdout);

    /* Collect all entries into an array for sorting. */
    struct block_index **arr = zcl_malloc(n * sizeof(*arr), "height_repair_arr");
    if (!arr) {
        LOG_WARN("height", "[height-repair] malloc failed for %zu entries", n);
        return 0;
    }

    size_t iter = 0, idx = 0;
    struct block_index *pi;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
        if (pi && idx < n)
            arr[idx++] = pi;
    }
    n = idx;

    /* Pass 2: Fix heights via multi-pass forward propagation — but ONLY
     * through entries reachable from the TRUE genesis (by hash). A fix
     * may not flow out of a detached non-genesis root: its stored label
     * can be arbitrary, so propagating from it re-anchors an entire —
     * otherwise canonical — subtree and can freeze the tip on
     * bad-cb-height. Detached subtrees keep their stored heights
     * untouched until block_index_repair_pprev relinks the root; the
     * boot sequence then re-runs this repair and the genesis-rooted
     * propagation fixes any residual labels. Reachability marks live in
     * a parallel array; pprev->mark lookups go through a pointer-sorted
     * copy (bsearch). Iteration stays height-sorted so propagation
     * converges in ~1-3 passes. */
    qsort(arr, n, sizeof(*arr), bii_cmp_height);
    struct block_index **byptr =
        zcl_malloc(n * sizeof(*byptr), "height_repair_byptr");
    uint8_t *mark = zcl_calloc(n, 1, "height_repair_mark");
    int repaired = 0;
    if (!byptr || !mark) {
        LOG_WARN("height", "[height-repair] mark alloc failed for %zu "
                 "entries — heights left as stored this boot", n);
        free(byptr);
        free(mark);
        free(arr);
        atomic_store(&g_heights_repaired, true);
        return 0;
    }
    memcpy(byptr, arr, n * sizeof(*byptr));
    qsort(byptr, n, sizeof(*byptr), bii_cmp_ptr);

    for (size_t i = 0; i < n; i++) {
        struct block_index *b = arr[i];
        if (!b->pprev && bii_is_genesis(b)) {
            if (b->nHeight != 0) {
                b->nHeight = 0;
                repaired++;
            }
            size_t gi = bii_ptr_index(byptr, n, b);
            if (gi < n)
                mark[gi] = 1;
        }
    }

    for (int pass = 0; pass < 20; pass++) {
        int progressed = 0;
        for (size_t i = 0; i < n; i++) {
            struct block_index *b = arr[i];
            if (!b->pprev)
                continue;
            size_t bi_idx = bii_ptr_index(byptr, n, b);
            if (bi_idx >= n || mark[bi_idx])
                continue;
            size_t pp_idx = bii_ptr_index(byptr, n, b->pprev);
            if (pp_idx >= n || !mark[pp_idx])
                continue; /* parent not (yet) genesis-rooted */
            int expected = b->pprev->nHeight + 1;
            if (b->nHeight != expected) {
                b->nHeight = expected;
                repaired++;
            }
            mark[bi_idx] = 1;
            progressed++;
        }
        if (progressed == 0)
            break;
    }

    /* Pass 3: Recompute nChainWork now that heights are correct — same
     * genesis-rooted gate: chain work derived from a detached root's
     * label would be equally wrong. Re-sort by the CORRECTED heights:
     * the earlier sort used the pre-repair labels, and parents must be
     * recomputed before their children. */
    qsort(arr, n, sizeof(*arr), bii_cmp_height);
    for (size_t i = 0; i < n; i++) {
        struct block_index *b = arr[i];
        size_t bi_idx = bii_ptr_index(byptr, n, b);
        if (bi_idx >= n || !mark[bi_idx])
            continue;
        struct arith_uint256 proof = GetBlockProof(b);
        if (b->pprev)
            arith_uint256_add(&b->nChainWork, &b->pprev->nChainWork, &proof);
        else
            b->nChainWork = proof;
    }

    free(byptr);
    free(mark);
    free(arr);

    struct timespec t1;
    platform_time_monotonic_timespec(&t1);
    int64_t elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000
                       + (t1.tv_nsec - t0.tv_nsec) / 1000000;

    printf("[height-repair] repaired %d heights in %lld ms\n",
           repaired, (long long)elapsed_ms);
    fflush(stdout);

    event_emitf(EV_BLOCK_INDEX_REPAIR, 0,
                "repaired=%d elapsed_ms=%lld",
                repaired, (long long)elapsed_ms);

    atomic_store(&g_heights_repaired, true);
    return repaired;
}

/* ── pprev chain repair ────────────────────────────────────────
 * After LDB import, the flat file may store wrong prev_hash values
 * (copied from pprev->phashBlock when pprev was already corrupted).
 * This function reads hashPrevBlock directly from block data on disk
 * for every entry with BLOCK_HAVE_DATA and fixes pprev if it points
 * to the wrong parent.
 *
 * Call AFTER block_index_repair_heights() so heights are correct.
 * After pprev repair, recomputes nChainWork and nChainTx. */
int block_index_repair_pprev(struct main_state *ms, const char *datadir,
                             int min_height, int *out_max_height)
{
    if (out_max_height) *out_max_height = -1;
    if (!ms || !datadir) return 0;

    struct timespec t0;
    platform_time_monotonic_timespec(&t0);

    size_t n = ms->map_block_index.size;
    if (n == 0) return 0;

    /* Collect entries with BLOCK_HAVE_DATA into an array sorted by
     * (nFile, nDataPos) so we read each block file sequentially. */
    struct block_index **arr = zcl_malloc(n * sizeof(*arr), "pprev_repair_arr");
    if (!arr) {
        LOG_WARN("pprev", "[pprev-repair] malloc failed for %zu entries", n);
        return 0;
    }

    size_t iter = 0, count = 0;
    struct block_index *pi;
    int max_h = -1;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
        if (!pi) continue;
        if (pi->nHeight > max_h) max_h = pi->nHeight;
        /* By hash, not by height: a detached root relabeled to 0 (or
         * loaded that way from a corrupted flat save) is EXACTLY the
         * entry this pass must relink — an `nHeight > 0` filter would
         * exclude it forever. Only the true genesis has no parent.
         * min_height only skips blocks a prior verified run already
         * covered; a detached root at height 0 is never skipped because
         * min_height < 0 on any datadir that still has unrepaired roots. */
        if (!bii_is_genesis(pi) && (pi->nStatus & BLOCK_HAVE_DATA) &&
            pi->nFile >= 0 && pi->nDataPos > 0 && pi->nHeight > min_height)
            arr[count++] = pi;
    }
    if (out_max_height) *out_max_height = max_h;

    if (count == 0) {
        printf("[pprev-repair] index consistent through h=%d — nothing to "
               "scan above min_height=%d\n", max_h, min_height);
        fflush(stdout);
        free(arr);
        return 0;
    }
    qsort(arr, count, sizeof(*arr), bii_cmp_disk_pos);

    size_t max_reads = bii_pprev_repair_max_reads();
    size_t read_limit = (max_reads > 0 && max_reads < count)
                            ? max_reads
                            : count;
    printf("[pprev-repair] scanning %zu/%zu blocks with data "
           "(ZCL_PPREV_REPAIR_MAX_READS=%zu)\n",
           read_limit, count, max_reads);
    fflush(stdout);

    int repaired = 0, heights_fixed = 0, read_errors = 0;

    for (size_t i = 0; i < read_limit; i++) {
        struct block_index *bi = arr[i];

        /* Read just nVersion (4 bytes) + hashPrevBlock (32 bytes) = 36 bytes
         * from the start of block data on disk. This is much faster than
         * deserializing the entire block. */
        uint8_t hdr_buf[36];
        struct disk_block_pos pos = {
            .nFile = bi->nFile,
            .nPos = bi->nDataPos
        };
        ssize_t nr = disk_block_pread(datadir, &pos, "blk", hdr_buf, 36);
        if (nr < 36) {
            read_errors++;
            continue;
        }

        /* hashPrevBlock is at offset 4 (after nVersion) in little-endian */
        struct uint256 prev_hash;
        memcpy(prev_hash.data, hdr_buf + 4, 32);

        /* Look up the correct parent in the block map */
        struct block_index *correct_pprev =
            block_map_find(&ms->map_block_index, &prev_hash);

        if (!correct_pprev)
            continue; /* parent not in index — can't fix */

        if (bi->pprev != correct_pprev) {
            bi->pprev = correct_pprev;
            repaired++;
        }
        if (bi->nHeight != correct_pprev->nHeight + 1) {
            bi->nHeight = correct_pprev->nHeight + 1;
            heights_fixed++;
            block_index_build_skip(bi);
        }

        boot_progress_note("block_index.pprev_repair", i + 1, read_limit);
        if ((i + 1) % 50000 == 0) {
            printf("[pprev-repair] progress %zu/%zu repaired=%d "
                   "heights=%d read_errors=%d\n",
                   i + 1, read_limit, repaired, heights_fixed, read_errors);
            fflush(stdout);
        }
    }

    /* After fixing pprev, recompute nChainWork and nChainTx.
     * Sort all entries by height for forward propagation. */
    if (repaired > 0 || heights_fixed > 0) {
        /* Re-collect ALL entries (not just HAVE_DATA) for chain recomputation */
        size_t all_count = 0;
        struct block_index **all = zcl_malloc(n * sizeof(*all), "pprev_repair_all");
        if (all) {
            iter = 0;
            while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
                if (pi && all_count < n)
                    all[all_count++] = pi;
            }
            qsort(all, all_count, sizeof(*all), bii_cmp_height);

            int fixed_work = 0, fixed_tx = 0;
            for (size_t i = 0; i < all_count; i++) {
                struct block_index *b = all[i];
                struct arith_uint256 proof = GetBlockProof(b);
                struct arith_uint256 expected;

                if (b->pprev) {
                    arith_uint256_add(&expected, &b->pprev->nChainWork, &proof);
                    if (arith_uint256_compare(&expected, &b->nChainWork) != 0) {
                        b->nChainWork = expected;
                        fixed_work++;
                    }
                    if (b->nTx > 0 && b->pprev->nChainTx > 0) {
                        uint32_t expected_ctx = b->pprev->nChainTx + b->nTx;
                        if (b->nChainTx != expected_ctx) {
                            b->nChainTx = expected_ctx;
                            fixed_tx++;
                        }
                    }
                } else {
                    b->nChainWork = proof;
                }
            }
            free(all);

            if (fixed_work > 0 || fixed_tx > 0)
                printf("[pprev-repair] recomputed: %d chain_work, %d chain_tx\n",
                       fixed_work, fixed_tx);
        }
    }

    free(arr);

    struct timespec t1;
    platform_time_monotonic_timespec(&t1);
    int64_t elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000
                       + (t1.tv_nsec - t0.tv_nsec) / 1000000;

    printf("[pprev-repair] fixed %d pprev links, %d heights (%d read errors) "
           "from %zu/%zu blocks with data in %lld ms\n",
           repaired, heights_fixed, read_errors, read_limit, count,
           (long long)elapsed_ms);
    fflush(stdout);

    if (repaired > 0 || heights_fixed > 0)
        event_emitf(EV_BLOCK_INDEX_REPAIR, 0,
                    "pprev_repaired=%d heights_fixed=%d read_errors=%d elapsed_ms=%lld",
                    repaired, heights_fixed, read_errors,
                    (long long)elapsed_ms);

    return repaired + heights_fixed;
}

/* ──────────────────────────────────────────────────────────────
 * Post-activation anchor repair.
 *
 * Lives here (not in lib/net/src/msg_headers.c) so the inbound P2P
 * handler does not do structural block-index surgery. */

#include "services/chain_restore_repair.h"
#include "services/chain_tip.h"
#include "coins/coins_view.h"
#include "validation/chainstate.h"

int bii_repair_post_activation_anchor(
    struct main_state            *ms,
    struct coins_view_cache      *coins_tip,
    const char                   *datadir,
    struct bii_post_activation_result *result)
{
    struct bii_post_activation_result local = {0};
    if (!result) result = &local;
    memset(result, 0, sizeof(*result));
    result->tip_restore_old_h = -1;
    result->tip_restore_new_h = -1;

    if (!ms || !coins_tip || !datadir) return -1; // raw-return-ok:sentinel
    struct uint256 coins_hash;
    uint256_set_null(&coins_hash);
    coins_view_cache_get_best_block(coins_tip, &coins_hash);
    if (uint256_is_null(&coins_hash)) return -1; // raw-return-ok:sentinel

    struct block_index *coins_bi =
        block_map_find(&ms->map_block_index, &coins_hash);
    if (!coins_bi) return -1; // raw-return-ok:sentinel

    int pre_scan_coins_h = coins_bi->nHeight;
    if (pre_scan_coins_h <= 100000) return -1; // raw-return-ok:sentinel

    int post_act_h = active_chain_height(&ms->chain_active);
    result->tip_restore_old_h = post_act_h;
    result->tip_restore_new_h = pre_scan_coins_h;

    /* Step 1: anchor coins_bi height (no-op if already correct) */
    /* (Skipped here — coins_bi->nHeight was set from block_map, so
     * if the caller wants the UTXO height anchored, it has already
     * been done. There is no external "true" height to inject — the
     * source of truth is the block_map.) */

    /* Step 2: walk DOWN pprev fixing heights.
     *
     * Defensive step cap: pprev cycles in corrupt block_map state
     * could otherwise drive the loop forever. The height assignment
     * below forces monotonicity, which inherently breaks cycles on
     * the first pass, but if a future caller drops that semantic the
     * cap keeps the repair bounded. */
    {
        int fixed = 0;
        int steps = 0;
        struct block_index *cur = coins_bi;
        const int max_steps = pre_scan_coins_h + 1024;
        while (cur && cur->pprev && steps++ < max_steps) {
            int expected = cur->nHeight - 1;
            if (cur->pprev->nHeight != expected) {
                /* A walk that wants the true genesis at a nonzero
                 * height proves the ANCHOR is mislabeled — abort the
                 * relabel rather than shift the whole ancestry (the
                 * global relabel class, see bii_is_genesis). */
                if (bii_is_genesis(cur->pprev) && expected != 0) {
                    LOG_WARN("bii", "[bii-anchor] refused: walk from "
                             "anchor h=%d reaches genesis at h=%d — "
                             "anchor height is wrong, not the chain",
                             pre_scan_coins_h, expected);
                    break;
                }
                cur->pprev->nHeight = expected;
                fixed++;
            }
            cur = cur->pprev;
            if (expected <= 0) break;
        }
        result->heights_fixed_down = fixed;
        if (fixed > 0)
            printf("[bii-anchor] fixed %d pprev heights "
                   "downward from anchor h=%d\n",
                   fixed, pre_scan_coins_h);
    }

    /* Step 3: re-propagate heights forward across the whole map.
     * Routed through block_index_repair_heights so the propagation is
     * gated on genesis-reachability — a positional propagation would
     * re-anchor a detached root's subtree at runtime, the exact relabel
     * class this repair refuses (see bii_is_genesis). */
    {
        int total = block_index_repair_heights(ms);
        result->heights_repropagated = total;
        if (total > 0)
            printf("[bii-anchor] re-propagated %d heights forward\n",
                   total);
    }

    /* Step 4: restore active tip if it's below the anchor */
    if (post_act_h < pre_scan_coins_h) {
        if (chain_restore_block_is_consensus_backed_on_disk(
                coins_bi, datadir)) {
            printf("[bii-anchor] restoring disk-backed coins tip "
                   "h=%d (activation picked h=%d)\n",
                   pre_scan_coins_h, post_act_h);
            struct chain_state_rollback_authorization rollback_auth = {
                .source = CSR_ROLLBACK_SOURCE_RESTORE,
                .decision = POLICY_ALLOW,
                .from_height = active_chain_height(&ms->chain_active),
                .to_height = coins_bi->nHeight,
                .max_depth = INT64_MAX,
                .evidence_class = "block_index_integrity_disk_backed",
                .reason = "bii_anchor_restore_disk_backed",
            };
            struct chain_state_commit commit = {
                .new_tip = coins_bi,
                .new_coins_best = *coins_bi->phashBlock,
                .expected_utxo_count = 0,
                .update_header_tip = true,
                .rollback_auth = &rollback_auth,
                .wallet_scan_height = -1,
                .reason = "bii_anchor_restore_disk_backed",
            };
            enum csr_result rc = csr_commit_tip(csr_instance(), &commit);
            if (rc == CSR_OK) {
                result->tip_restored = true;
#ifdef ZCL_TESTING
            } else if (rc == CSR_REJECTED_NOT_INITIALIZED) {
                (void)chain_set_active_tip(ms, coins_bi, TIP_FROM_P2P_REPAIR,
                                      "bii_anchor_restore_csr_uninit");
                ms->pindex_best_header = coins_bi;
                result->tip_restored = true;
#endif
            } else {
                LOG_WARN("bii", "[bii-anchor] csr rejected disk-backed tip restore " "(%s) h=%d", csr_result_name(rc), pre_scan_coins_h);
                result->tip_restore_refused = true;
            }
        } else {
            LOG_INFO("bii", "[bii-anchor] coins tip h=%d not disk-backed; " "refusing active tip restore over h=%d", pre_scan_coins_h, post_act_h);
            result->tip_restore_refused = true;
        }
    }
    return 0;
}
