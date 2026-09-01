/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Label-splice re-bind arm for reducer_frontier_reconcile_light.
 *
 * The wedge
 * ---------
 * After a header-graph cure the canonical node can pin at H* on
 * utxo_apply.label_splice: proof_validate_log / script_validate_log rows at/above
 * the utxo_apply frontier are wedge-era residue with block_hash IS NULL (authored
 * before the writer stamped block_hash), so utxo_apply's label_splice guard
 * CORRECTLY refuses ("verdict is hash-bound to a different block"). proof/script
 * have already passed those heights, so they never re-stamp them on their own.
 *
 * The cure
 * --------
 * Rewind ONLY the proof/script VALIDATION cursors down to the lowest NULL height
 * (floored at MIN(utxo_apply, tip_finalize) — the LCC invariant, never a
 * downstream-applied height) and delete the NULL suffix, so the forward fold
 * re-derives + re-stamps block_hash. Coins, nullifiers, and tip_finalize are
 * NEVER touched. Independent of every coin arm: a fired re-bind is forward
 * progress on its own and must not be masked by an unrelated coin_backfill
 * refusal at a later height (the historical conflation regression).
 */

// repair-rung-ok:test_proof_validate_stage
//   The WRITER is already fixed: proof_validate_log_insert / script_validate_
//   log_insert stamp the block's hash into every row they author, so no NEW
//   ok=1/NULL-block_hash row can be produced (proven by test_proof_validate_
//   stage's hashed-row assertions). This rung re-derives ONLY the historical
//   pre-stamping rows in place — it imports no state; the rewound cursor re-
//   folds and the current writer re-stamps block_hash. The wiring + RED->GREEN
//   proof is the label_splice re-bind subtest in
//   test_reducer_frontier_reconcile_light.

#include "jobs/stage_repair.h"
#include "stage_repair_reducer_frontier_internal.h"

#include "jobs/proof_validate_null_hash_rearm.h"
#include "jobs/script_validate_null_hash_rearm.h"
#include "proof_validate_log_store.h"
#include "script_validate_log_store.h"
#include "services/recovery_policy.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>

#define LABEL_SPLICE_BLOCKER_ID "utxo_apply.label_splice"

/* True iff the ok=1 row at `height` in `table` (proof_validate_log or
 * script_validate_log) carries a NULL block_hash — the cheap per-tick gate that
 * keeps this arm a no-op on a healthy node without paying ensure_schema/rearm.
 * A missing block_hash column (scan prepare error) reads as "not this
 * condition" (false); the blocker gate still covers a column-less node. */
static bool rebind_row_null_at(sqlite3 *db, const char *table, int height)
{
    if (height < 0)
        return false;
    int lowest = -1;
    int64_t count = 0;
    int rc = -1;
    if (table[0] == 'p') /* proof_validate_log */
        rc = proof_validate_log_lowest_null_block_hash(db, height, height + 1,
                                                       &lowest, &count);
    else                 /* script_validate_log */
        rc = script_validate_log_lowest_null_block_hash(db, height, height + 1,
                                                        &lowest, &count);
    return rc == 1 && count > 0;
}

static int min_lowest(int a, int b)
{
    if (a < 0)
        return b;
    if (b < 0)
        return a;
    return a < b ? a : b;
}

bool stage_reducer_frontier_try_label_splice_rebind(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out,
    bool *mutated)
{
    if (!db || !out || !mutated)
        LOG_FAIL("stage_repair", "label_splice rebind: NULL args");
    *mutated = false;
    /* -1 sentinels set here (not by the caller) so a gate-fail no-op still
     * reads as "no re-bind" (label_splice_rebind_lowest >= 0 is the detect
     * signal — a stale 0 would false-activate the Condition). */
    out->label_splice_rebind_lowest = -1;
    out->label_splice_proof_rewound_to = -1;
    out->label_splice_script_rewound_to = -1;

    /* Cheap gate: only engage when there is real evidence of the label_splice
     * wedge — the utxo_apply.label_splice blocker is active, OR the proof/script
     * verdict at hstar+1 (the height utxo_apply is trying to apply) carries a
     * NULL block_hash. On a healthy node both are false and this arm no-ops
     * without touching the schema. */
    int gate_h = out->hstar + 1;
    bool gate = blocker_exists(LABEL_SPLICE_BLOCKER_ID) ||
                rebind_row_null_at(db, "proof_validate_log", gate_h) ||
                rebind_row_null_at(db, "script_validate_log", gate_h);
    if (!gate)
        return true;

    /* Validation-only policy: dry-run (detect) refuses so it only REPORTS the
     * pending re-bind (report.lowest_null_height) without mutating; apply uses
     * the env-loaded validation-rebind cap. The rearm floors the rewind at
     * MIN(utxo_apply, tip_finalize) internally — that floor is HARD and does not
     * depend on the cap. */
    struct recovery_policy policy;
    policy_load_from_env(&policy);
    if (!apply)
        policy.dry_run = true;

    struct proof_validate_rearm_report pr;
    enum proof_validate_rearm_outcome po =
        proof_validate_null_hash_rearm(db, &policy, &pr);
    struct script_validate_rearm_report sr;
    enum script_validate_rearm_outcome so =
        script_validate_null_hash_rearm(db, &policy, &sr);

    /* An ERROR from a scan/rewind step is logged by the rearm; degrade the arm
     * to a no-op (do NOT fail the whole reconcile — other repairs may be valid).
     * The pending-lowest report field is still meaningful when only one side
     * errored. */
    if (po == PV_REARM_ERROR)
        LOG_WARN("stage_repair",
                 "[stage_repair] label_splice rebind: proof re-arm errored "
                 "(arm no-op for proof this pass)");
    if (so == SV_REARM_ERROR)
        LOG_WARN("stage_repair",
                 "[stage_repair] label_splice rebind: script re-arm errored "
                 "(arm no-op for script this pass)");

    out->label_splice_rebind_lowest =
        min_lowest(po == PV_REARM_ERROR ? -1 : pr.lowest_null_height,
                   so == SV_REARM_ERROR ? -1 : sr.lowest_null_height);

    if (po == PV_REARM_REARMED) {
        out->label_splice_rebound++;
        out->label_splice_proof_rewound_to = (int)pr.rewound_to;
        out->label_splice_deleted_rows += pr.deleted_rows;
        *mutated = true;
    }
    if (so == SV_REARM_REARMED) {
        out->label_splice_rebound++;
        out->label_splice_script_rewound_to = (int)sr.rewound_to;
        out->label_splice_deleted_rows += sr.deleted_rows;
        *mutated = true;
    }

    if (*mutated)
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier label_splice RE-BOUND "
                 "hstar=%d cursors_rewound=%d proof->%d script->%d "
                 "deleted_null_rows=%lld; forward fold re-stamps block_hash so "
                 "utxo_apply can advance (coins/tip_finalize untouched)",
                 out->hstar, out->label_splice_rebound,
                 out->label_splice_proof_rewound_to,
                 out->label_splice_script_rewound_to,
                 (long long)out->label_splice_deleted_rows);
    else if (out->label_splice_rebind_lowest >= 0 && !apply)
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier label_splice re-bind PENDING "
                 "hstar=%d lowest_null=%d (proof_null=%d script_null=%d); the "
                 "remedy pass will rewind the proof/script validation cursors",
                 out->hstar, out->label_splice_rebind_lowest,
                 po == PV_REARM_ERROR ? -1 : pr.lowest_null_height,
                 so == SV_REARM_ERROR ? -1 : sr.lowest_null_height);

    return true;
}
