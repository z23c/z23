/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate NULL-block_hash re-arm — see
 * jobs/script_validate_null_hash_rearm.h. Twin of
 * proof_validate_null_hash_rearm.c.
 *
 * repair-rung-ok:test_reducer_frontier_reconcile_light
 *   The WRITER is already fixed: script_validate_log_insert stamps the block's
 *   hash into every row it authors, so no NEW ok=1/NULL-block_hash row can be
 *   produced. This rung only re-derives the historical pre-fix rows in place (it
 *   imports no state). The re-derive path — a rewound cursor re-folds and
 *   re-stamps block_hash — is exercised by the label-splice re-bind subtest in
 *   test_reducer_frontier_reconcile_light().
 */

#include "jobs/script_validate_null_hash_rearm.h"

#include "jobs/stage_helpers.h"
#include "script_validate_log_store.h"
#include "services/recovery_policy.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdint.h>

#define STAGE_NAME "script_validate"
#define UTXO_APPLY_STAGE_NAME "utxo_apply"
#define TIP_FINALIZE_STAGE_NAME "tip_finalize"
#define REARM_REASON "script_validate.null_hash_rearm"

static enum script_validate_rearm_outcome
finish(struct script_validate_rearm_report *report,
       enum script_validate_rearm_outcome outcome)
{
    if (report)
        report->outcome = outcome;
    return outcome;
}

enum script_validate_rearm_outcome script_validate_null_hash_rearm(
    sqlite3 *db, const struct recovery_policy *policy,
    struct script_validate_rearm_report *report)
{
    struct script_validate_rearm_report local;
    if (!report)
        report = &local;
    report->outcome = SV_REARM_ERROR;
    report->sv_cursor_before = 0;
    report->consumer_floor = 0;
    report->lowest_null_height = -1;
    report->null_row_count = 0;
    report->rewound_to = 0;
    report->deleted_rows = 0;

    if (!db) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm: NULL db");
        return finish(report, SV_REARM_ERROR);
    }

    /* Read the durable cursors. script_validate is upstream of BOTH consumers of
     * its receipts that enforce the hash binding: utxo_apply (label_splice
     * guard) AND tip_finalize (validation_evidence). The floor is the LOWEST of
     * those two so we re-derive every height a downstream consumer still needs,
     * yet never rewind below the deepest consumer's cursor (the LCC invariant —
     * rewinding below a downstream consumer's cursor recreates the reducer
     * wedge). This floor is HARD; it does not depend on the recovery cap. */
    uint64_t sv_cursor = 0, ua_cursor = 0, tf_cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME, &sv_cursor)) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm: sv cursor read failed");
        return finish(report, SV_REARM_ERROR);
    }
    if (!stage_cursor_read_or_zero(db, UTXO_APPLY_STAGE_NAME, STAGE_NAME,
                                   &ua_cursor)) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm: utxo_apply cursor read "
                 "failed");
        return finish(report, SV_REARM_ERROR);
    }
    if (!stage_cursor_read_or_zero(db, TIP_FINALIZE_STAGE_NAME, STAGE_NAME,
                                   &tf_cursor)) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm: tip_finalize cursor read "
                 "failed");
        return finish(report, SV_REARM_ERROR);
    }
    /* The deepest consumer cursor = the lowest of the two; use it as the floor. */
    if (tf_cursor < ua_cursor)
        ua_cursor = tf_cursor;
    report->sv_cursor_before = sv_cursor;
    report->consumer_floor = ua_cursor;

    /* Ensure the block_hash column exists (idempotent) before scanning for
     * NULL-block_hash rows, else the scan fails with "no such column". */
    if (!script_validate_log_ensure_schema(db))
        return finish(report, SV_REARM_ERROR);

    /* Nothing to re-derive if script_validate has not led its consumers. */
    if (sv_cursor <= ua_cursor)
        return finish(report, SV_REARM_NOT_NEEDED);

    int lowest_null = -1;
    int64_t null_count = 0;
    int scan = script_validate_log_lowest_null_block_hash(
        db, (int)ua_cursor, (int)sv_cursor, &lowest_null, &null_count);
    if (scan < 0)
        return finish(report, SV_REARM_ERROR);
    if (scan == 0)
        return finish(report, SV_REARM_NOT_NEEDED);
    report->lowest_null_height = lowest_null;
    report->null_row_count = null_count;

    /* Containment gate. A VALIDATION-ONLY rewind (see the cap rationale in
     * recovery_policy.h): floored at ua_cursor = MIN(utxo_apply, tip_finalize)
     * above, so lowest_null >= ua_cursor and no downstream-applied height is
     * crossed regardless of the cap. Uses the larger ZCL_MAX_VALIDATION_REBIND
     * cap; a NULL policy is loaded from the environment (default-refuse). */
    struct recovery_policy loaded;
    if (!policy) {
        policy_load_from_env(&loaded);
        policy = &loaded;
    }
    enum policy_decision decision = policy_check_validation_rebind(
        policy, (int64_t)sv_cursor, (int64_t)lowest_null, REARM_REASON);
    if (decision != POLICY_ALLOW) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm REFUSED (%s): would rewind "
                 "sv cursor %llu -> %d (%lld heights, %lld NULL rows); raise "
                 "ZCL_MAX_VALIDATION_REBIND or ack to authorise after copy proof",
                 policy_decision_name(decision),
                 (unsigned long long)sv_cursor, lowest_null,
                 (long long)((int64_t)sv_cursor - lowest_null),
                 (long long)null_count);
        return finish(report, SV_REARM_REFUSED);
    }

    /* Rewind FIRST (crash-safe): if we crash after the cursor rewind but before
     * the delete, the reducer re-folds from lowest_null and INSERT-OR-REPLACEs
     * the NULL rows with re-stamped block_hash. Deleting first then crashing
     * would erase the wedge evidence a re-detect relies on. */
    if (!stage_set_named_cursor(db, STAGE_NAME, (uint64_t)lowest_null)) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm: sv cursor rewind %llu -> "
                 "%d failed", (unsigned long long)sv_cursor, lowest_null);
        return finish(report, SV_REARM_ERROR);
    }
    report->rewound_to = (uint64_t)lowest_null;

    /* Delete the NULL-block_hash suffix. A failure here is non-fatal: the
     * cursor is already rewound, so the re-fold re-stamps every height anyway. */
    int64_t deleted = 0;
    if (!script_validate_log_delete_null_block_hash_suffix(db, lowest_null,
                                                           &deleted)) {
        LOG_WARN("script_validate",
                 "[script_validate] null-hash re-arm: suffix delete from %d "
                 "failed (cursor already rewound; re-fold will re-stamp)",
                 lowest_null);
    }
    report->deleted_rows = deleted;

    LOG_INFO("script_validate",
             "[script_validate] null-hash re-arm DONE: sv cursor %llu -> %d, "
             "%lld NULL row(s) deleted; reducer will re-derive + re-stamp "
             "block_hash so utxo_apply can advance",
             (unsigned long long)sv_cursor, lowest_null, (long long)deleted);
    return finish(report, SV_REARM_REARMED);
}
