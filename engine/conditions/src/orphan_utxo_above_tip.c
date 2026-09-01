/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Condition: orphan_utxo_above_tip
 *
 * Detects UTXO rows sitting ABOVE the active chain tip — orphans left
 * behind by a rewind/reorg where the coins set ended up one block (or
 * more) ahead of the connected tip. Heals by calling the existing
 * bounded rewind helper (utxo_recovery_clean_above_tip), which only
 * auto-deletes a single-block overshoot of <= UTXO_BOOT_REWIND_MAX_ROWS
 * (32) rows. A larger/unsafe overshoot is refused by the guard inside
 * that helper; we surface that refusal as COND_REMEDY_FAILED so the
 * engine backs off and ultimately pages a human.
 *
 * This re-homes the boot-time one-shot (engine/composition/src/boot.c) into a
 * continuous, witnessed self-healer. Having both is idempotent.
 */

#include "conditions/orphan_utxo_above_tip.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include "framework/condition.h"

#include "config/runtime.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "services/utxo_recovery_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>

static _Atomic int64_t g_tip_at_detect = -1;

#ifdef ZCL_TESTING
static struct node_db *g_test_ndb;
static _Atomic int g_test_remedy_calls;
#endif

static struct node_db *runtime_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_test_ndb)
        return g_test_ndb;
#endif
    return app_runtime_node_db();
}

/* Current connected tip height, or -1 if not yet established (boot not
 * finalized / no chain). A tip_h <= 0 means we have no authoritative
 * tip to compare against — treat as "nothing orphaned" so the
 * Condition stays quiet until boot establishes the tip. */
static int64_t current_tip_height(void)
{
    struct main_state *ms = condition_engine_main_state();
    if (!ms)
        return -1; // raw-return-ok:engine-not-ready
    return (int64_t)active_chain_height(&ms->chain_active);
}

/* Side-effect-free read: does any UTXO row exist above tip_h?
 * Returns true iff at least one orphan row is present. */
static bool any_utxo_above(int64_t tip_h)
{
    struct node_db *ndb = runtime_ndb();
    if (!ndb || !ndb->open || !ndb->db)
        return false;
    if (tip_h <= 0)
        return false;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT 1 FROM utxos WHERE height > ? LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK) {
        LOG_WARN("condition",
            "[condition:orphan_utxo_above_tip] prepare failed: %s",
            sqlite3_errmsg(ndb->db));
        return false;
    }
    sqlite3_bind_int64(stmt, 1, tip_h);
    bool found = (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

static bool detect_orphan_utxo_above_tip(void)
{
    int64_t tip_h = current_tip_height();
    if (tip_h <= 0)
        return false; /* tip not yet established — stay quiet */

    /* On canonical datadirs (coins_applied_height present) "mirror rows above
     * tip" is Invariant-B pipeline depth or harmless projection lag of the
     * rebuildable node.db utxos cache — NEVER a defect to heal by deleting
     * rows. Detect only on legacy datadirs where the mirror is still the only
     * coins store. */
    {
        int32_t d_h = -1;
        if (reducer_frontier_derive_coins_best_now(&d_h, NULL, NULL))
            return false;
    }

    if (!any_utxo_above(tip_h))
        return false; // raw-return-ok:no-orphans-is-the-healthy-steady-state
    atomic_store(&g_tip_at_detect, tip_h);
    return true;
}

static enum condition_remedy_result remedy_orphan_utxo_above_tip(void)
{
    struct node_db *ndb = runtime_ndb();
    struct main_state *ms = condition_engine_main_state();
    if (!ndb || !ndb->open || !ms)
        return COND_REMEDY_SKIP;

    int64_t tip_h = current_tip_height();

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    /* Reuse the existing guarded helper; do NOT duplicate the 32-row
     * guard. It returns rows-deleted (>0), or 0 both when there was
     * nothing to do AND when the guard refused an unsafe overshoot
     * (it emits EV_BOOT_VALIDATION_FAILED / EV_DB_ERROR in the refusal
     * path). Since the return value alone cannot distinguish "refused"
     * from "nothing to do", we re-run the side-effect-free read after
     * the helper: if orphans remain above tip, the heal did NOT take
     * effect (guard refused) -> FAILED so the engine backs off. */
    int cleaned = utxo_recovery_clean_above_tip(ndb, ms);

    bool still_orphaned = any_utxo_above(tip_h);
    LOG_WARN("condition",
        "[condition:orphan_utxo_above_tip] tip=%" PRId64 " cleaned=%d "
        "remaining=%s action=clean_above_tip",
        tip_h, cleaned, still_orphaned ? "yes" : "no");

    if (still_orphaned) {
        /* Guard refused (overshoot too large / not a single-block
         * overshoot). Helper already emitted the failure event. */
        return COND_REMEDY_FAILED;
    }
    /* cleaned > 0 (rows pruned) or cleaned == 0 with no orphans left. */
    return COND_REMEDY_OK;
}

static bool witness_orphan_utxo_above_tip(int64_t target_at_detect)
{
    (void)target_at_detect;
    int64_t tip_h = current_tip_height();
    if (tip_h <= 0)
        return true; /* tip gone/unestablished — nothing to clean */
    return !any_utxo_above(tip_h);
}

static struct condition c_orphan_utxo_above_tip = {
    .name = "orphan_utxo_above_tip",
    .severity = COND_WARN,
    .poll_secs = 60,
    .backoff_secs = 300,
    .max_attempts = 3,
    .detect = detect_orphan_utxo_above_tip,
    .remedy = remedy_orphan_utxo_above_tip,
    .witness = witness_orphan_utxo_above_tip,
    .witness_window_secs = 60,
};

void register_orphan_utxo_above_tip(void)
{
    (void)condition_register(&c_orphan_utxo_above_tip);
}

#ifdef ZCL_TESTING
void orphan_utxo_above_tip_test_reset(void)
{
    g_test_ndb = NULL;
    atomic_store(&g_tip_at_detect, -1);
    atomic_store(&g_test_remedy_calls, 0);
}

void orphan_utxo_above_tip_test_set_node_db(struct node_db *ndb)
{
    g_test_ndb = ndb;
}

int orphan_utxo_above_tip_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
