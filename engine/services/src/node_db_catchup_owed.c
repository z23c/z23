/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Owed turbo-mode restore for the catchup service: keeps the scope of a
 * pass that yielded inside another writer's transaction, restores it once
 * the shared connection is idle, and carries the test hook for the window
 * between turbo entry and the first BEGIN IMMEDIATE. */

// one-result-type-ok:recovery-primitive-bool — a restore either ran or is
// still owed; a failed restore is logged here and retried by the next pass.

#include "services/node_db_catchup_owed.h"
#include "jobs/node_pace.h"

#include "services/node_db_catchup_lock_guard.h"
#include "services/node_db_catchup_service.h"
#include "util/log_macros.h"

/* The restore (synchronous, cache, index rebuild) cannot run inside the
 * other writer's transaction: PRAGMA synchronous is refused there, so
 * synchronous would stay OFF, and the CREATE INDEX statements would join
 * that transaction. Catchup passes are serialized by the catchup trigger,
 * and shutdown runs after they stop. */
static struct sync_db_turbo_scope g_owed_scope;

void node_db_catchup_owed_defer(struct sync_db_turbo_scope *scope)
{
    if (!scope || !scope->entered)
        return;
    if (g_owed_scope.entered)
        LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                    "catchup: a second turbo scope is owed a restore; "
                    "the earlier one is superseded");
    g_owed_scope = *scope;
    scope->entered = false;
    scope->ndb = NULL;
}

/* Distinguish a busy connection from a failed restore; both remain owed. */
enum catchup_restore_result node_db_catchup_restore_owed_result(struct node_db *ndb)
{
    if (!g_owed_scope.entered)
        return CATCHUP_RESTORE_OK;
    if (node_db_catchup_lock_guard_foreign_txn(ndb))
        return CATCHUP_RESTORE_BUSY;
    if (!sync_db_turbo_scope_end(&g_owed_scope)) {
        LOG_WARN_IN("node_db_catchup_service_run", "catchup",
                    "catchup: owed restore of normal mode failed; "
                    "retrying next pass");
        return CATCHUP_RESTORE_FAILED;
    }
    return CATCHUP_RESTORE_OK;
}

bool node_db_catchup_service_restore_owed(struct node_db *ndb)
{
    return node_db_catchup_restore_owed_result(ndb) == CATCHUP_RESTORE_OK;
}

bool node_db_catchup_thermal_stop(bool background, bool shutdown)
{
    return background && !shutdown && node_pace_get() == NODE_PACE_GENTLE;
}

int node_db_catchup_entry_gate(struct node_db *ndb, bool background, bool *deferred)
{
    enum catchup_restore_result restored = node_db_catchup_restore_owed_result(ndb);
    if (restored == CATCHUP_RESTORE_FAILED) return -1;
    if (restored == CATCHUP_RESTORE_BUSY) return 0;
    node_pace_poll();
    if (background && node_pace_get() == NODE_PACE_GENTLE) {
        if (deferred) *deferred = true;
        return 0;
    }
    return node_pace_get() == NODE_PACE_PAUSE ? 0 : 1;
}

#ifdef ZCL_TESTING
static void (*g_test_after_turbo_hook)(struct node_db *ndb);

void node_db_catchup_test_set_after_turbo_hook(void (*hook)(struct node_db *))
{
    g_test_after_turbo_hook = hook;
}

/* Runs the armed hook once, right after a pass enters turbo mode and
 * before its first BEGIN IMMEDIATE: the window in which another writer can
 * open a transaction on the shared connection. */
void node_db_catchup_test_after_turbo(struct node_db *ndb)
{
    void (*hook)(struct node_db *) = g_test_after_turbo_hook;
    g_test_after_turbo_hook = NULL;
    if (hook)
        hook(ndb);
}
#endif
