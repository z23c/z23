/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_fallback — hash-bound apply candidate recovery.
 *
 * The normal apply path reads active_chain[height]. During bootstrap/refold
 * the visible active-chain window can lag durable reducer rows even though the
 * block map already holds the body. This helper allows exactly that narrow
 * case without trusting height alone. */

#include "utxo_apply_stage_internal.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "script_validate_log_store.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/block_parse_cache.h"
#include "storage/disk_block_io.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

static struct { int64_t h; int64_t reason; uint64_t reps; }
    g_select_idle_warn = { .h = -1, .reason = UA_SELECT_IDLE_NONE };

/* Registry-visible typed blocker for a REAL apply-candidate anomaly (as
 * opposed to a legitimate window-lag wait). See the stall-taxonomy audit
 * (Task A): utxo_apply_select_apply_block returning NULL must not fold
 * BOTH the legitimate backpressure classes (active-chain window lag,
 * no-script-hash yet) AND the genuine anomalies (the block map / durable
 * parent / on-disk body disagreeing with the height-keyed verdict) into one
 * silent JOB_IDLE — no typed blocker, so the self-healing Conditions that key
 * off the blocker registry never armed and only the generic 60 s
 * reducer_drive_watchdog fired, naming nothing specific. The anomaly class now
 * names THIS blocker so blocker_stall_meta_detector's safety net and
 * `z23 core sync blockers` both see the exact reason. TRANSIENT (mirror
 * stage_body_read_hold): the candidate can become resolvable as the window /
 * repair table catches up. */
#define UA_APPLY_ANOMALY_BLOCKER_ID "utxo_apply.apply_candidate_anomaly"

/* True iff `reason` is a GENUINE anomaly — the block map, the durable/visible
 * parent, or the on-disk body actively DISAGREE with the ok-bound height-keyed
 * verdict — rather than a legitimate wait for the active-chain window / repair
 * table to catch up. Only anomalies name UA_APPLY_ANOMALY_BLOCKER_ID; the wait
 * classes stay a silent hold (the pipeline is simply ahead of this stage). */
static bool ua_select_idle_reason_is_anomaly(
        enum utxo_apply_select_idle_reason reason)
{
    switch (reason) {
    case UA_SELECT_IDLE_INDEXED_BODY_READ_FAILED:
    case UA_SELECT_IDLE_INDEXED_BODY_HASH_MISMATCH:
    case UA_SELECT_IDLE_BLOCK_MAP_MISS:
    case UA_SELECT_IDLE_HEIGHT_MISMATCH:
    case UA_SELECT_IDLE_PARENT_MISMATCH:
        return true;
    case UA_SELECT_IDLE_NONE:
    case UA_SELECT_IDLE_NO_MAIN_STATE:
    case UA_SELECT_IDLE_ACTIVE_CHAIN_MISSING:
    case UA_SELECT_IDLE_ACTIVE_CHAIN_BODILESS:
    case UA_SELECT_IDLE_NO_SCRIPT_HASH:
    case UA_SELECT_IDLE_INDEXED_BODY_MISSING:
    case UA_SELECT_IDLE_BLOCK_FAILED:
    case UA_SELECT_IDLE_STAGE_READ_FAILED:
        return false;
    }
    return false;
}

void utxo_apply_select_idle_blocker_clear(void)
{
    blocker_clear(UA_APPLY_ANOMALY_BLOCKER_ID);
}

/* See jobs/utxo_apply_stage.h. The blocker is the liveness fact — it is set on
 * every anomaly tick and cleared the moment a candidate resolves — so its
 * presence alone answers "is a hold live". The height it is held at is the one
 * thing the blocker record does not carry, so that comes from the note's own
 * atomic. Lives here because this file owns UA_APPLY_ANOMALY_BLOCKER_ID. */
int64_t utxo_apply_stage_candidate_anomaly_hold_height(void)
{
    if (!blocker_exists(UA_APPLY_ANOMALY_BLOCKER_ID))
        return -1; // raw-return-ok:sentinel-no-live-hold
    return atomic_load(&g_ua_select_idle_height);
}

const char *utxo_apply_select_idle_reason_name(
        enum utxo_apply_select_idle_reason reason)
{
    switch (reason) {
    case UA_SELECT_IDLE_NONE:
        return "none";
    case UA_SELECT_IDLE_NO_MAIN_STATE:
        return "no_main_state";
    case UA_SELECT_IDLE_ACTIVE_CHAIN_MISSING:
        return "active_chain_missing";
    case UA_SELECT_IDLE_ACTIVE_CHAIN_BODILESS:
        return "active_chain_bodiless";
    case UA_SELECT_IDLE_NO_SCRIPT_HASH:
        return "no_script_hash";
    case UA_SELECT_IDLE_BLOCK_MAP_MISS:
        return "block_map_miss";
    case UA_SELECT_IDLE_HEIGHT_MISMATCH:
        return "height_mismatch";
    case UA_SELECT_IDLE_INDEXED_BODY_MISSING:
        return "indexed_body_missing";
    case UA_SELECT_IDLE_INDEXED_BODY_READ_FAILED:
        return "indexed_body_read_failed";
    case UA_SELECT_IDLE_INDEXED_BODY_HASH_MISMATCH:
        return "indexed_body_hash_mismatch";
    case UA_SELECT_IDLE_PARENT_MISMATCH:
        return "parent_mismatch";
    case UA_SELECT_IDLE_BLOCK_FAILED:
        return "block_failed";
    case UA_SELECT_IDLE_STAGE_READ_FAILED:
        return "stage_read_failed";
    }
    return "unknown";
}

void utxo_apply_select_idle_note(int height,
        enum utxo_apply_select_idle_reason reason,
        const struct block_index *bi)
{
    atomic_fetch_add(&g_ua_select_idle_total, 1);
    atomic_store(&g_ua_select_idle_height, (int64_t)height);
    atomic_store(&g_ua_select_idle_reason, (int64_t)reason);

    /* Split wait-reasons from anomaly-reasons (Task A). A genuine anomaly names
     * a registry-visible TRANSIENT blocker every tick (blocker_set's token
     * bucket dedups the re-fires); a legitimate wait clears it so a
     * just-resolved anomaly does not leave a stale claim. Done BEFORE the WARN
     * throttle below so the blocker is refreshed on the steady-state hold, not
     * only on the first (changed) tick. */
    if (ua_select_idle_reason_is_anomaly(reason)) {
        char reason_buf[BLOCKER_REASON_MAX];
        snprintf(reason_buf, sizeof(reason_buf),
                 "height=%d reason=%.64s: block map, parent visibility, body, "
                 "or height verdict disagree; utxo_apply holds below this "
                 "height until the anomaly resolves",
                 height, utxo_apply_select_idle_reason_name(reason));
        struct blocker_record rec;
        if (blocker_init(&rec, UA_APPLY_ANOMALY_BLOCKER_ID, "utxo_apply",
                         BLOCKER_TRANSIENT, reason_buf))
            (void)blocker_set(&rec);
    } else {
        utxo_apply_select_idle_blocker_clear();
    }

    bool changed = g_select_idle_warn.h != (int64_t)height ||
                   g_select_idle_warn.reason != (int64_t)reason;
    uint64_t suppressed = 0;
    if (changed) {
        suppressed = g_select_idle_warn.reps;
        g_select_idle_warn.h = (int64_t)height;
        g_select_idle_warn.reason = (int64_t)reason;
        g_select_idle_warn.reps = 0;
    } else {
        g_select_idle_warn.reps++;
        return;
    }

    unsigned int status = block_index_status_load(bi);
    int file = block_index_file_load(bi);
    unsigned int data_pos = block_index_data_pos_load(bi);
    LOG_WARN("utxo_apply",
             "[utxo_apply] select idle height=%d reason=%s "
             "bi=%p bi_height=%d status=0x%x file=%d data_pos=%u "
             "(suppressed=%llu)",
             height, utxo_apply_select_idle_reason_name(reason),
             (const void *)bi, bi ? bi->nHeight : -1, status, file, data_pos,
             (unsigned long long)suppressed);
}

static bool indexed_body_hash_verifies(const struct block_index *bi,
                                       const char *datadir,
                                       struct uint256 *parent_hash_out,
                                       enum utxo_apply_select_idle_reason *why)
{
    if (!bi || !bi->phashBlock || !datadir || !datadir[0]) {
        if (why) *why = UA_SELECT_IDLE_INDEXED_BODY_MISSING;
        return false;
    }
    int file = block_index_file_load(bi);
    unsigned int data_pos = block_index_data_pos_load(bi);
    if (file < 0 || data_pos == 0) {
        if (why) *why = UA_SELECT_IDLE_INDEXED_BODY_MISSING;
        return false;
    }

    struct disk_block_pos pos = { .nFile = file, .nPos = data_pos };
    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_pread(&blk, &pos, datadir)) {
        block_free(&blk);
        if (why) *why = UA_SELECT_IDLE_INDEXED_BODY_READ_FAILED;
        return false;
    }
    struct uint256 got;
    block_get_hash(&blk, &got);
    bool ok = uint256_eq(&got, bi->phashBlock);
    if (ok && parent_hash_out)
        *parent_hash_out = blk.header.hashPrevBlock;
    block_free(&blk);
    if (!ok) {
        if (why) *why = UA_SELECT_IDLE_INDEXED_BODY_HASH_MISMATCH;
        /* This same (height,hash) key is what stage_read_block() /
         * block_parse_cache_get() uses; purge it so a poisoned or stale
         * cache slot can never be served to the next apply attempt. */
        block_parse_cache_evict(bi->nHeight, bi->phashBlock->data);
    }
    return ok;
}

static bool candidate_extends_visible_parent(struct main_state *ms,
                                             const struct uint256 *parent_hash,
                                             int height)
{
    if (!ms || !parent_hash)
        return false;
    if (height == 0)
        return uint256_is_null(parent_hash);

    struct block_index *parent =
        active_chain_at(&ms->chain_active, height - 1);
    if (!parent || !parent->phashBlock)
        return false;
    return uint256_eq(parent_hash, parent->phashBlock);
}

static bool indexed_candidate_extends_visible_parent(
        struct main_state *ms, const struct block_index *bi, int height)
{
    if (!ms || !bi)
        return false;
    if (height == 0)
        return bi->pprev == NULL;
    struct block_index *parent =
        active_chain_at(&ms->chain_active, height - 1);
    return parent && parent->phashBlock && bi->pprev &&
           bi->pprev->phashBlock &&
           uint256_eq(bi->pprev->phashBlock, parent->phashBlock);
}

static bool candidate_extends_durable_parent(sqlite3 *db,
                                             const struct uint256 *parent_hash,
                                             int height)
{
    if (!db || !parent_hash)
        return false;
    if (height == 0)
        return uint256_is_null(parent_hash);

    uint8_t durable_hash[32];
    if (tip_finalize_stage_block_hash_at(db, height - 1, durable_hash) &&
        memcmp(durable_hash, parent_hash->data, sizeof(durable_hash)) == 0)
        return true;

    /* The first checkpoint transition replaces the seed's anchor row with a
     * finalized lookahead row, so the canonical trusted-base declaration is
     * the exact fallback witness for that one missing-parent seam. */
    return reducer_frontier_trusted_base_matches(db, height - 1,
                                                  parent_hash->data);
}

static bool indexed_candidate_extends_durable_parent(
        sqlite3 *db, const struct block_index *bi, int height)
{
    if (!db || !bi)
        return false;
    if (height == 0)
        return bi->pprev == NULL;
    if (!bi->pprev || !bi->pprev->phashBlock)
        return false;

    uint8_t durable_hash[32];
    if (tip_finalize_stage_block_hash_at(db, height - 1, durable_hash) &&
        memcmp(durable_hash, bi->pprev->phashBlock->data,
               sizeof(durable_hash)) == 0)
        return true;

    return reducer_frontier_trusted_base_matches(
        db, height - 1, bi->pprev->phashBlock->data);
}

static struct block_index *hash_bound_fallback(
        sqlite3 *db, struct main_state *ms, int height,
        const struct script_validate_verdict_row *sv_row,
        enum utxo_apply_select_idle_reason *why)
{
    if (!ms) {
        if (why) *why = UA_SELECT_IDLE_NO_MAIN_STATE;
        return NULL;
    }
    if (!sv_row || sv_row->ok != 1 || !sv_row->has_block_hash) {
        if (why) *why = UA_SELECT_IDLE_NO_SCRIPT_HASH;
        return NULL;
    }

    struct block_index *bi = block_map_find(&ms->map_block_index,
                                            &sv_row->block_hash);
    if (!bi) {
        if (why) *why = UA_SELECT_IDLE_BLOCK_MAP_MISS;
        return NULL;
    }
    if (bi->nHeight != height) {
        if (why) *why = UA_SELECT_IDLE_HEIGHT_MISMATCH;
        return NULL;
    }
    /* A height/hash-bound upstream verdict proves what was validated; it does
     * not override a later FAILED verdict on that block.  In particular,
     * invalidateblock first rewinds the UTXO cursor and then this same drain
     * batch can revisit the stale script/proof rows.  Returning the failed map
     * owner here immediately reapplied the disconnected block, consumed its
     * restored inputs again, and made mempool resurrection fail with
     * MISSING_INPUTS.  FAILED is hash identity, so also consult a same-hash map
     * owner when the candidate came from another in-RAM identity. */
    if (block_has_any_failure(bi)) {
        if (why) *why = UA_SELECT_IDLE_BLOCK_FAILED;
        return NULL;
    }
    bool indexed_parent_ok =
        indexed_candidate_extends_visible_parent(ms, bi, height) ||
        indexed_candidate_extends_durable_parent(db, bi, height);
    if ((bi->nStatus & BLOCK_HAVE_DATA) != 0 && indexed_parent_ok)
        return bi;

    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));
    enum utxo_apply_select_idle_reason body_why =
        UA_SELECT_IDLE_INDEXED_BODY_MISSING;
    struct uint256 actual_parent;
    uint256_set_null(&actual_parent);
    if (!indexed_body_hash_verifies(bi, datadir, &actual_parent, &body_why)) {
        if (why) *why = body_why;
        return NULL;
    }
    if ((bi->nStatus & BLOCK_HAVE_DATA) == 0)
        block_index_status_fetch_or(bi, BLOCK_HAVE_DATA);
    if (!candidate_extends_visible_parent(ms, &actual_parent, height) &&
        !candidate_extends_durable_parent(db, &actual_parent, height)) {
        if (why) *why = UA_SELECT_IDLE_PARENT_MISMATCH;
        return NULL;
    }
    return bi;
}

struct block_index *utxo_apply_select_apply_block(
        sqlite3 *db, struct main_state *ms, int height,
        const struct script_validate_verdict_row *sv_row)
{
    if (!ms) {
        utxo_apply_select_idle_note(height, UA_SELECT_IDLE_NO_MAIN_STATE,
                                    NULL);
        return NULL;
    }

    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    struct block_index *map_bi = bi && bi->phashBlock
        ? block_map_find(&ms->map_block_index, bi->phashBlock) : NULL;
    bool failed = bi && (block_has_any_failure(bi) ||
        (map_bi && map_bi->nHeight == bi->nHeight &&
         block_has_any_failure(map_bi)));
    if (bi && !failed && (bi->nStatus & BLOCK_HAVE_DATA)) {
        utxo_apply_select_idle_blocker_clear();
        return bi;
    }

    atomic_fetch_add(&g_ua_window_miss_total, 1);
    atomic_store(&g_ua_window_miss_height, (int64_t)height);

    enum utxo_apply_select_idle_reason why = failed
        ? UA_SELECT_IDLE_BLOCK_FAILED
        : (bi ? UA_SELECT_IDLE_ACTIVE_CHAIN_BODILESS
              : UA_SELECT_IDLE_ACTIVE_CHAIN_MISSING);
    struct block_index *fallback = hash_bound_fallback(db, ms, height, sv_row,
                                                       &why);
    if (!fallback) {
        utxo_apply_select_idle_note(height, why, bi);
        return NULL;
    }

    atomic_fetch_add(&g_ua_hash_bound_fallback_total, 1);
    atomic_store(&g_ua_hash_bound_fallback_height, (int64_t)height);
    utxo_apply_select_idle_blocker_clear();
    return fallback;
}
