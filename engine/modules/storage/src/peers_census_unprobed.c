/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * peers_census_unprobed — the UNMEASURED half of the network census.
 *
 * Sibling TU of peers_projection.c, deliberately separate because this is not
 * projection state: it is the running account of addresses we KNOW but did NOT
 * measure (no Tor circuit available for a .onion, the crawler's onion budget
 * spent, an unrenderable address).
 *
 * The whole point is what it does NOT do. A not-probed address must never be
 * routed into peers_projection_emit_census_observed(success=false), because
 * that bumps node_census.dial_fail_count — laundering "we never looked" into
 * "this peer failed" and feeding a false negative into peer reputation, which
 * is strictly worse than having no data. So this file writes no row, appends
 * no ledger, opens no table, and creates no parallel store: it keeps a process
 * counter and the last reason, and the crawler's dumper reports them.
 */

// one-result-type-ok:peers-census-unprobed-bookkeeping — no fallible surface
// here. The note is pure bookkeeping that cannot fail (it always returns true)
// and the accessors are pure reads; peers_projection.c owns the fallible
// projection lifecycle.

#include "storage/peers_projection.h"

#include "util/sync.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic uint64_t g_unprobed_total = 0;
static zcl_mutex_t g_unprobed_lock;
static zcl_once_t g_unprobed_once = ZCL_ONCE_INIT;
static char g_unprobed_reason[PEERS_CENSUS_UNPROBED_REASON_MAX] = "";

static void unprobed_lock_init(void)
{
    zcl_mutex_init(&g_unprobed_lock);
}

bool peers_projection_note_census_unprobed(const uint8_t ip[16], uint16_t port,
                                           const char *reason)
{
    /* The address is deliberately unused: recording WHICH address we failed to
     * look at would be a durable negative about that peer, which is the exact
     * thing this path exists to avoid. Only the population size and the reason
     * are kept. */
    (void)ip;
    (void)port;
    atomic_fetch_add_explicit(&g_unprobed_total, 1, memory_order_relaxed);
    if (reason && reason[0]) {
        if (!zcl_once_call(&g_unprobed_once, unprobed_lock_init))
            return true;
        zcl_mutex_lock(&g_unprobed_lock);
        snprintf(g_unprobed_reason, sizeof(g_unprobed_reason), "%s", reason);
        zcl_mutex_unlock(&g_unprobed_lock);
    }
    return true;
}

uint64_t peers_projection_census_unprobed_total(void)
{
    return atomic_load_explicit(&g_unprobed_total, memory_order_relaxed);
}

void peers_projection_census_unprobed_reason(char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    if (!zcl_once_call(&g_unprobed_once, unprobed_lock_init)) {
        out[0] = '\0';
        return;
    }
    zcl_mutex_lock(&g_unprobed_lock);
    snprintf(out, cap, "%s", g_unprobed_reason);
    zcl_mutex_unlock(&g_unprobed_lock);
}
