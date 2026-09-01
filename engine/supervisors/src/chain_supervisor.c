/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain domain supervisor children. Owns chain-advance escalation liveness
 * contracts and supervised recovery policy for the chain domain. */

#include "supervisors/chain_supervisor.h"
#include "util/log_macros.h"
#include "supervisors/domains.h"

#include "util/supervisor.h"
#include "platform/time_compat.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "services/chain_state_service.h"
#include "services/legacy_mirror_sync_service.h"
#include "validation/process_block_revalidate.h"
#include "core/uint256.h"
#include "event/event.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Coordinator escalation supervisor child. */
static struct main_state       *g_coord_esc_ms       = NULL;
static struct liveness_contract g_coord_esc_contract;
static supervisor_child_id      g_coord_esc_id        = SUPERVISOR_INVALID_ID;

/* Progress-quiet window: 900s (15 min) of fatal breach + frozen height
 * before forcing mirror promotion. Tuned long because mirror promotion
 * is a bigger hammer than peer-floor seed kicks — we want plenty of
 * time for natural P2P recovery first. */
#define COORD_ESC_QUIET_US ((int64_t)900 * 1000 * 1000)

static void coord_esc_tick(struct liveness_contract *c)
{
    (void)c;
    if (!g_coord_esc_ms) return;
    struct legacy_mirror_sync_stats msnap;
    memset(&msnap, 0, sizeof(msnap));
    legacy_mirror_sync_stats_snapshot(&msnap);
    int local_h = active_chain_height(&g_coord_esc_ms->chain_active);

    /* progress_marker tracks the CONCATENATION of local_height and
     * severity-good. While severity is "fatal", we only advance the
     * marker if local_h actually moves. While severity is anything
     * better, we encode "all good" as a monotonically increasing
     * counter so the quiet timer never fires. */
    bool is_fatal = (strcmp(msnap.lag_breach_severity, "fatal") == 0);
    int64_t marker;
    if (is_fatal) {
        marker = (int64_t)local_h;
    } else {
        /* Non-fatal: bump a forever-increasing counter (using time so
         * it always advances). Frozen-progress detection inactive. */
        marker = (int64_t)platform_time_wall_time_t() + (int64_t)1000000;
    }
    supervisor_progress(g_coord_esc_id, marker);
    /* Also tick so any deadline timer (if configured) doesn't fire. */
    supervisor_tick(g_coord_esc_id);
}

static void coord_esc_stall(struct liveness_contract *c)
{
    (void)c;
    if (!g_coord_esc_ms) {
        event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                    "chain.coord_escalation stalled without main_state");
        LOG_WARN("supervisor", "[supervisor] chain.coord_escalation stalled without main_state");
        return;
    }
    /* Before surfacing the stall, try evidence-based revalidation of the
     * next-child block. If the stuck height has a BLOCK_FAILED_VALID pindex
     * and sufficient oracle evidence agrees on its hash, clear the bit and
     * re-run activation. The canonical wedge class (BLOCK_FAILED_VALID set
     * on the only candidate above the active tip) becomes self-healing within
     * the supervisor's natural 60s tick. */
    int tip_h = active_chain_height(&g_coord_esc_ms->chain_active);
    int stuck_h = tip_h + 1;
    struct uint256 reval_hash;
    memset(&reval_hash, 0, sizeof(reval_hash));
    enum reval_result rr = process_block_revalidate(stuck_h, g_coord_esc_ms,
                                                     &reval_hash);
    LOG_WARN("supervisor", "[supervisor] chain.coord_escalation: revalidate h=%d -> %s", stuck_h, reval_result_name(rr));
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "revalidate height=%d result=%s",
                stuck_h, reval_result_name(rr));
    if (rr == REVAL_RECOVERED) {
        /* Don't also force-mirror — natural activation will pick up the
         * cleared block on the next supervisor tick. */
        return;
    }
    /* Revalidation couldn't help (no failed pindex at this height, no
     * quorum, evidence disagreed, or connect_block re-failed). There is
     * no mirror writer to force-promote; surface the named
     * stall and let the reducer/condition path keep ownership. */
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "chain.coord_escalation revalidation_exhausted height=%d result=%s",
                stuck_h, reval_result_name(rr));
}

void chain_supervisor_register(struct main_state *ms)
{
    if (!ms) return;
    if (g_coord_esc_id != SUPERVISOR_INVALID_ID) return;  /* idempotent */

    supervisor_domains_init();
    g_coord_esc_ms = ms;
    liveness_contract_init(&g_coord_esc_contract, "chain.coord_escalation");
    atomic_store(&g_coord_esc_contract.period_secs, (int64_t)60);
    atomic_store(&g_coord_esc_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_coord_esc_contract.progress_max_quiet_us,
                 COORD_ESC_QUIET_US);
    g_coord_esc_contract.on_tick  = coord_esc_tick;
    g_coord_esc_contract.on_stall = coord_esc_stall;
    g_coord_esc_id = supervisor_register_in_domain(g_chain_sup,
                                                   &g_coord_esc_contract);
    if (g_coord_esc_id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("supervisor", "[supervisor] WARN chain.coord_escalation register failed");
    }
}
