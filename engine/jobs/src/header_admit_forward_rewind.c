/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "header_admit_forward_rewind.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_helpers.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/coins_kv.h"
#include "util/log_throttle.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/stage.h"
#include "validation/main_state.h"

#include <string.h>

#define STAGE_NAME "header_admit"

/* A blocks-less checkpoint activation can publish the finalized parent while
 * its active-chain window slot remains absent. Header admission must not guess
 * across that hole, but it can use either convention-aware finalized history
 * or the exact durable trusted-base (height,hash) pair installed by the
 * checkpoint CAS. Both witnesses are hash-bound; absence/mismatch refuses. */
static bool durable_parent_matches(sqlite3 *db, int parent_height,
                                   const struct uint256 *parent_hash)
{
    uint8_t durable_hash[32];
    if (reducer_frontier_trusted_base_matches(db, parent_height,
                                               parent_hash->data))
        return true;
    if (tip_finalize_stage_block_hash_at(db, parent_height, durable_hash) &&
        memcmp(durable_hash, parent_hash->data, sizeof(durable_hash)) == 0)
        return true;
    return false;
}

static bool log_row_parent_match(sqlite3 *db, int height,
                                 const struct uint256 *expected_parent,
                                 bool *out_known, bool *out_matches)
{
    *out_known = false;
    *out_matches = false;
    if (!db || height < 0 || !expected_parent)
        return true;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT parent_hash FROM header_admit_log WHERE height=?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-parent prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_known = true;
        const void *blob = sqlite3_column_blob(st, 0);
        int nb = sqlite3_column_bytes(st, 0);
        *out_matches = blob && nb == 32 &&
            memcmp(blob, expected_parent->data, 32) == 0;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-parent step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static bool log_row_hash_match(sqlite3 *db, int height,
                               const struct uint256 *expected_hash,
                               bool *out_known, bool *out_matches)
{
    *out_known = false;
    *out_matches = false;
    if (!db || height < 0 || !expected_hash)
        return true;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hash FROM header_admit_log WHERE height=?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("header_admit",
                 "[header_admit] replay-parent prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_known = true;
        const void *blob = sqlite3_column_blob(st, 0);
        int nb = sqlite3_column_bytes(st, 0);
        *out_matches = blob && nb == 32 &&
            memcmp(blob, expected_hash->data, 32) == 0;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("header_admit",
                 "[header_admit] replay-parent step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

bool header_admit_forward_replay_parent_ok(sqlite3 *db,
                                           struct main_state *ms,
                                           const struct block_index *bi,
                                           int height)
{
    if (height <= 0)
        return true;
    if (!ms || !bi || !bi->pprev || !bi->pprev->phashBlock)
        return false;

    int active_h = active_chain_height(&ms->chain_active);
    if (height <= active_h)
        return false;

    if (height > active_h + 1) {
        bool known = false, matches = false;
        if (!log_row_hash_match(db, height - 1, bi->pprev->phashBlock,
                                &known, &matches))
            return false;
        return known && matches;
    }

    struct block_index *parent =
        active_chain_at(&ms->chain_active, height - 1);
    if (parent && parent->phashBlock)
        return uint256_eq(bi->pprev->phashBlock, parent->phashBlock);
    return durable_parent_matches(db, height - 1,
                                  bi->pprev->phashBlock);
}

static bool rewind_target_args_invalid(sqlite3 *db,
                                       struct active_chain *chain,
                                       uint64_t cursor,
                                       int *out_target,
                                       const char **out_reason)
{
    return !db || !chain || cursor == 0 || !out_target || !out_reason;
}

static bool tip_unusable_for_rewind(const struct block_index *tip)
{
    return !tip || !tip->phashBlock || tip->nHeight < 0;
}

/* A tip's stored height must agree with its parent link: the parent sits
 * exactly one height below, so a tip with a parent is above genesis. Without
 * a parent link the tip must be genesis or the exact hash-bound trusted base
 * a blocks-less checkpoint activation installs; finalized history does not
 * vouch for a missing parent link. A healthy index always passes. The
 * rhett2 soak node held the real tip hash at height 318 instead of 3225857,
 * which this exposes. The header_admit_log is deliberately not consulted:
 * after a legitimate reorg the old branch's row can remain at the tip's
 * height. */
static bool tip_well_formed(sqlite3 *db, const struct block_index *tip)
{
    if (tip_unusable_for_rewind(tip))
        return false;
    if (tip->pprev)
        return tip->nHeight > 0 && tip->pprev->nHeight == tip->nHeight - 1;
    return tip->nHeight == 0 ||
           reducer_frontier_trusted_base_matches(db, tip->nHeight,
                                                 tip->phashBlock->data);
}

bool header_admit_tip_refused(sqlite3 *db, struct active_chain *chain)
{
    struct block_index *tip = chain ? active_chain_tip(chain) : NULL;
    /* No tip yet (boot) is nothing to judge. */
    if (!tip || tip_well_formed(db, tip))
        return false;  // raw-return-ok:not-refused
    static struct log_throttle refuse_throttle = LOG_THROTTLE_INIT;
    uint64_t reps = 0;
    if (log_throttle_should_emit(&refuse_throttle, (uint64_t)tip->nHeight,
                                 platform_time_wall_unix(), 60, &reps))
        LOG_WARN("header_admit",
                 "[header_admit] tip height %d (hash %s) is malformed or "
                 "disagrees with its parent link; pass refused floor=%d "
                 "repeats=%llu",
                 tip->nHeight, tip->phashBlock ? "set" : "missing",
                 (int)reducer_frontier_floor(), (unsigned long long)reps);
    return true;
}

/* Once admission has passed the trusted anchor (cursor > floor), a rewind to
 * or below it is refused: reorgs below the compiled checkpoint are not
 * legitimate, and a rewind raised to floor+1 would leave the divergent row in
 * place and rewind again on every pass, so the caller ends the pass instead.
 * Below the anchor (a fresh node's from-genesis IBD with no state source, or
 * a from-genesis refold, whose floor is 0) rewinds proceed as before. */
int header_admit_rewind_target_above_anchor(int target, uint64_t cursor)
{
    int floor = (int)reducer_frontier_floor();
    if (target <= floor && cursor > (uint64_t)floor) {
        static struct log_throttle below_throttle = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&below_throttle, (uint64_t)target,
                                     platform_time_wall_unix(), 60, &reps))
            LOG_WARN("header_admit",
                     "[header_admit] rewind to %d refused: at or below the "
                     "trusted anchor %d cursor=%llu repeats=%llu",
                     target, floor, (unsigned long long)cursor,
                     (unsigned long long)reps);
        return HEADER_ADMIT_REWIND_REFUSED;  // raw-return-ok:logged-above
    }
    return (uint64_t)target >= cursor ? HEADER_ADMIT_REWIND_NONE : target;
}

bool header_admit_forward_rewind_target(sqlite3 *db,
                                        struct active_chain *chain,
                                        uint64_t cursor,
                                        int *out_target,
                                        const char **out_reason)
{
    if (out_target)
        *out_target = -1;
    if (out_reason)
        *out_reason = "none";
    if (rewind_target_args_invalid(db, chain, cursor, out_target,
                                   out_reason)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork target invalid args "
                 "db=%p chain=%p cursor=%llu out_target=%p out_reason=%p",
                 (void *)db, (void *)chain, (unsigned long long)cursor,
                 (void *)out_target, (void *)out_reason);
        return false;
    }

    struct block_index *tip = active_chain_tip(chain);
    if (tip_unusable_for_rewind(tip))
        return true;

    int next_h = tip->nHeight + 1;
    if ((uint64_t)next_h >= cursor)
        return true;

    bool row_known = false;
    bool parent_matches = false;
    if (!log_row_parent_match(db, next_h, tip->phashBlock,
                              &row_known, &parent_matches)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork parent audit failed h=%d",
                 next_h);
        return false;  // raw-return-ok:logged-above
    }
    if (row_known && parent_matches)
        return true;

    /* The rewind height, HEADER_ADMIT_REWIND_NONE, or REFUSED (logged). */
    *out_target = header_admit_rewind_target_above_anchor(next_h, cursor);
    *out_reason = row_known ? "parent_mismatch" : "missing_row";
    return true;
}

static const char *const k_downstream[] = {
    "validate_headers",
    "body_fetch",
    "body_persist",
    "script_validate",
    "proof_validate",
    "utxo_apply",
};
#define DOWNSTREAM_N (sizeof(k_downstream) / sizeof(k_downstream[0]))

/* Reads every downstream cursor and the coins frontier before any write, so
 * a failed read leaves all cursors untouched. utxo_apply's cursor co-commits
 * with coins_applied_height; never tear them apart: its lowering stops at the
 * coins frontier. */
static bool clamp_plan(sqlite3 *db, int target, uint64_t current[],
                       int to[])
{
    int32_t coins_h = 0;
    bool coins_found = false;
    if (!coins_kv_get_applied_height(db, &coins_h, &coins_found)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork clamp coins frontier read "
                 "failed target=%d", target);
        return false;
    }
    for (size_t i = 0; i < DOWNSTREAM_N; i++) {
        if (!stage_cursor_read_or_zero(db, k_downstream[i], STAGE_NAME,
                                       &current[i])) {
            LOG_WARN("header_admit",
                     "[header_admit] forward-fork clamp cursor read failed "
                     "stage=%s target=%d", k_downstream[i], target);
            return false;
        }
        bool utxo = strcmp(k_downstream[i], "utxo_apply") == 0;
        to[i] = utxo && coins_found && coins_h > target ? coins_h : target;
        if (to[i] != target && current[i] > (uint64_t)target)
            LOG_WARN("header_admit",
                     "[header_admit] forward-fork clamp stage=%s target=%d "
                     "floored to coins_applied=%d cursor=%llu",
                     k_downstream[i], target, to[i],
                     (unsigned long long)current[i]);
    }
    return true;
}

bool header_admit_forward_rewind_clamp_downstream(sqlite3 *db, int target)
{
    if (!db || target < 0) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork clamp invalid args db=%p "
                 "target=%d", (void *)db, target);
        return false;
    }
    uint64_t current[DOWNSTREAM_N];
    int to[DOWNSTREAM_N];
    if (!clamp_plan(db, target, current, to))
        return false;  // raw-return-ok:logged-above
    for (size_t i = 0; i < DOWNSTREAM_N; i++) {
        if (current[i] <= (uint64_t)to[i])
            continue;
        if (!stage_set_named_cursor(db, k_downstream[i], (uint64_t)to[i])) {
            LOG_WARN("header_admit",
                     "[header_admit] forward-fork clamp failed stage=%s "
                     "from=%llu to=%d",
                     k_downstream[i], (unsigned long long)current[i], to[i]);
            return false;
        }
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork clamp stage=%s from=%llu to=%d",
                 k_downstream[i], (unsigned long long)current[i], to[i]);
    }
    return true;
}
