/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one-shot self-verified range rewind for sticky recovery. */
// one-result-type-ok:recovery-rung returns typed rung outcomes and names every refusal in the blocker/event ledger

#include "services/sticky_escalator_resnapshot.h"

#include "base/compiler.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>

/* 0=not dispatched, 1=synchronous dispatch running, 2=forward fold pending.
 * Self-heal and supervisor ticks may overlap, so a plain bool is insufficient:
 * the second caller must not read the pre-rewind tip as completion while the
 * first caller is still inside stage_rederive_range. */
static _Atomic int g_dispatch_state = 0;

void sticky_resnapshot_gate_reset(void)
{
    atomic_store(&g_dispatch_state, 0);
}

enum sticky_resnapshot_gate_decision sticky_resnapshot_gate_decide(
    int64_t entry_tip, int64_t observed_tip)
{
    int state = atomic_load(&g_dispatch_state);
    if (state == 2)
        return entry_tip >= 0 && observed_tip >= entry_tip
            ? STICKY_RESNAPSHOT_COMPLETE : STICKY_RESNAPSHOT_HOLD;
    if (state == 1)
        return STICKY_RESNAPSHOT_HOLD;
    int expected = 0;
    return atomic_compare_exchange_strong(&g_dispatch_state, &expected, 1)
        ? STICKY_RESNAPSHOT_INVOKE : STICKY_RESNAPSHOT_HOLD;
}

void sticky_resnapshot_gate_finish(bool progressing)
{
    atomic_store(&g_dispatch_state, progressing ? 2 : 0);
}

int sticky_resnapshot_gate_state(void)
{
    return atomic_load(&g_dispatch_state);
}

struct stage_rederive_range_result;
extern bool stage_rederive_range(struct sqlite3 *db, struct main_state *ms,
                                 int from_height, int to_height,
                                 struct stage_rederive_range_result *out)
    ZCL_WEAK_IMPORT;
extern bool reducer_frontier_nearest_loadable_self_verified_base(
    int32_t at_or_below, bool compiled_checkpoint_loadable,
    int32_t *base_height_out, const char **base_kind_out);

enum sticky_rung_result sticky_escalator_resnapshot_run(
    struct main_state *ms, int observed_tip)
{
    sqlite3 *db = progress_store_db();
    if (!db || !ms) {
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] resnapshot: %s unavailable — cannot "
                 "locate a rewind base", db ? "main_state" : "progress db");
        return STICKY_RUNG_FAILED;
    }

    int32_t artifact_h = -1;
    bool artifact = boot_refold_from_anchor_artifact_available(
        app_runtime_node_db(), &artifact_h);
    int32_t base_h = -1;
    const char *base_kind = "none";
    bool have_base = reducer_frontier_nearest_loadable_self_verified_base(
        INT32_MAX, artifact, &base_h, &base_kind);
    if (!have_base) {
        blocker_name_dependency("sticky_escalator.resnapshot_no_base",
            "sticky_escalator", "resnapshot: no self-verified rewind base "
            "reachable (no self-valid seal, no verified utxo-anchor.snapshot "
            "artifact on disk) — deferring to reindex/refold. A PERSON "
            "decides: see `dumpstate blocker`.");
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-resnapshot-skip reason=no_verified_base");
        return STICKY_RUNG_FAILED;
    }

    if (stage_rederive_range) {
        bool ran = stage_rederive_range(db, ms, base_h, observed_tip, NULL);
        LOG_WARN("sticky_escalator",
                 "[sticky_escalator] resnapshot: in-process re-derive from %s "
                 "base_h=%d ran=%d", base_kind, base_h, (int)ran);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=sticky-resnapshot-rederive base=%s base_h=%d ran=%d",
                    base_kind, base_h, (int)ran);
        return ran ? STICKY_RUNG_PROGRESSING : STICKY_RUNG_FAILED;
    }

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "resnapshot: self-verified rewind base %s@%d reachable but no "
             "in-process rewind consumer (stage_rederive_range / seal "
             "window_rebuild) is linked — deferring to reindex/refold",
             base_kind, base_h);
    blocker_name_dependency("sticky_escalator.resnapshot_no_consumer",
                            "sticky_escalator", reason);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=sticky-resnapshot-defer base=%s base_h=%d "
                "reason=no_inprocess_consumer", base_kind, base_h);
    return STICKY_RUNG_FAILED;
}
