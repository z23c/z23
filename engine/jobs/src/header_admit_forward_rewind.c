/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "header_admit_forward_rewind.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_helpers.h"
#include "jobs/tip_finalize_stage.h"
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
    if (!db || !chain || cursor == 0 || !out_target || !out_reason) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork target invalid args "
                 "db=%p chain=%p cursor=%llu out_target=%p out_reason=%p",
                 (void *)db, (void *)chain, (unsigned long long)cursor,
                 (void *)out_target, (void *)out_reason);
        return false;
    }

    struct block_index *tip = active_chain_tip(chain);
    if (!tip || !tip->phashBlock || tip->nHeight < 0)
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

    *out_target = next_h;
    *out_reason = row_known ? "parent_mismatch" : "missing_row";
    return true;
}

static bool clamp_cursor_if_ahead(sqlite3 *db, const char *stage_name,
                                  int target)
{
    if (!db || !stage_name || target < 0) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork clamp invalid args "
                 "db=%p stage=%s target=%d",
                 (void *)db, stage_name ? stage_name : "(null)", target);
        return false;
    }

    uint64_t current = 0;
    if (!stage_cursor_read_or_zero(db, stage_name, STAGE_NAME, &current)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork clamp cursor read failed "
                 "stage=%s target=%d",
                 stage_name, target);
        return false;
    }
    if (current <= (uint64_t)target)
        return true;

    if (!stage_set_named_cursor(db, stage_name, (uint64_t)target)) {
        LOG_WARN("header_admit",
                 "[header_admit] forward-fork clamp failed stage=%s "
                 "from=%llu to=%d",
                 stage_name, (unsigned long long)current, target);
        return false;
    }

    LOG_WARN("header_admit",
             "[header_admit] forward-fork clamp stage=%s from=%llu to=%d",
             stage_name, (unsigned long long)current, target);
    return true;
}

bool header_admit_forward_rewind_clamp_downstream(sqlite3 *db, int target)
{
    static const char *const downstream[] = {
        "validate_headers",
        "body_fetch",
        "body_persist",
        "script_validate",
        "proof_validate",
        "utxo_apply",
    };
    for (size_t i = 0; i < sizeof(downstream) / sizeof(downstream[0]); i++)
        if (!clamp_cursor_if_ahead(db, downstream[i], target)) {
            LOG_WARN("header_admit",
                     "[header_admit] forward-fork downstream clamp failed "
                     "stage=%s target=%d",
                     downstream[i], target);
            return false;
        }
    return true;
}
