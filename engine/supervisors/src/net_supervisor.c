/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Net domain supervisor children. Owns the outbound peer-floor liveness
 * contract for the net supervisor domain. */

#include "supervisors/net_supervisor.h"
#include "util/log_macros.h"
#include "supervisors/domains.h"

#include "util/supervisor.h"
#include "net/connman.h"
#include "event/event.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

/* Outbound peer floor supervisor child. */
static struct connman          *g_peer_floor_cm        = NULL;
static struct liveness_contract g_peer_floor_contract;
static supervisor_child_id      g_peer_floor_id        = SUPERVISOR_INVALID_ID;

/* Healthy-outbound floor: the single source of truth in net/net.h
 * (ZCL_PEER_FLOOR_HEALTHY = 3). This child must share that value with the
 * connman dialer, the peer_floor_violated condition, and the dns-seed loop —
 * a lower value here would make the supervisor's on_stall fire one healthy
 * peer LATER than every other floor surface. Pinned by lint gate
 * check-peer-floor-single-source. */
#define PEER_FLOOR_TARGET ZCL_PEER_FLOOR_HEALTHY
/* progress-quiet window: if outbound_healthy stays below floor this
 * long, on_stall fires (supervisor edge-once). 60 s matches the
 * existing watchdog's PEER_FLOOR window. */
#define PEER_FLOOR_QUIET_US ((int64_t)60 * 1000 * 1000)

static void peer_floor_tick(struct liveness_contract *c)
{
    if (!g_peer_floor_cm || !c) return;
    size_t healthy = connman_outbound_healthy_count(g_peer_floor_cm);
    /* The progress_marker carries the outbound_healthy count — visible
     * via `z23 dumpstate supervisor` for operator inspection. */
    supervisor_progress(g_peer_floor_id, (int64_t)healthy);
    /* When ≥ floor, also tick so the deadline timer doesn't drift; when
     * below floor, intentionally do NOT tick so the progress_quiet
     * window can advance and eventually fire on_stall. */
    if (healthy >= PEER_FLOOR_TARGET) {
        /* Stable-good connectivity is healthy, not "no progress." Disable
         * the frozen-marker gate while the floor is satisfied and force a
         * same-count NO_PROGRESS latch to clear on recovery. */
        supervisor_set_progress_max_quiet(g_peer_floor_id, 0);
        supervisor_progress(g_peer_floor_id, -1);
        supervisor_progress(g_peer_floor_id, (int64_t)healthy);
        supervisor_tick(g_peer_floor_id);
    } else {
        supervisor_set_progress_max_quiet(g_peer_floor_id,
                                          PEER_FLOOR_QUIET_US);
    }
}

static void peer_floor_stall(struct liveness_contract *c)
{
    (void)c;
    if (!g_peer_floor_cm) return;
    size_t healthy = connman_outbound_healthy_count(g_peer_floor_cm);
    event_emitf(EV_PEER_FLOOR_BREACH, 0,
                "outbound_healthy=%zu floor=%d reason=supervisor:60s_quiet",
                healthy, PEER_FLOOR_TARGET);
    /* Widen addrman: re-add fixed seeds + re-resolve DNS. The connman
     * outbound thread will pick up the fresh targets on its next 1 s
     * tick. */
    connman_kick_seed_discovery(g_peer_floor_cm);
}

void net_supervisor_register(struct connman *cm)
{
    if (!cm) return;
    if (g_peer_floor_id != SUPERVISOR_INVALID_ID) return;  /* idempotent */

    supervisor_domains_init();
    g_peer_floor_cm = cm;
    liveness_contract_init(&g_peer_floor_contract, "net.outbound_floor");
    atomic_store(&g_peer_floor_contract.period_secs, (int64_t)15);
    /* progress-frozen for >60s = stall; no fixed deadline (period_secs
     * drives on_tick, progress_max_quiet drives on_stall) */
    atomic_store(&g_peer_floor_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_peer_floor_contract.progress_max_quiet_us,
                 PEER_FLOOR_QUIET_US);
    g_peer_floor_contract.on_tick  = peer_floor_tick;
    g_peer_floor_contract.on_stall = peer_floor_stall;
    g_peer_floor_id = supervisor_register_in_domain(g_net_sup,
                                                    &g_peer_floor_contract);
    if (g_peer_floor_id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("supervisor", "[supervisor] WARN net.outbound_floor register failed");
    }
}

#ifdef ZCL_TESTING
void net_supervisor_test_tick_peer_floor(void)
{
    peer_floor_tick(&g_peer_floor_contract);
}

long long net_supervisor_test_peer_floor_quiet_us(void)
{
    return (long long)
        atomic_load(&g_peer_floor_contract.progress_max_quiet_us);
}

void net_supervisor_test_reset_runtime(void)
{
    g_peer_floor_cm = NULL;
    g_peer_floor_id = SUPERVISOR_INVALID_ID;
    liveness_contract_init(&g_peer_floor_contract, "net.outbound_floor");
}
#endif
