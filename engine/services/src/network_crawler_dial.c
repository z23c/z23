/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_crawler_dial — the crawler's two-phase probe wave. Split out of
 * network_crawler.c so the service TU keeps only config, the PURE census fold,
 * the bounded census table, the supervised worker, and the dumper.
 *
 * The contract this file exists to hold: CLEARNET AND ONION ARE BUDGETED
 * SEPARATELY. Clearnet dials cost milliseconds; an onion dial costs a circuit
 * build. Phase 1 (clearnet) therefore always runs first and to completion;
 * phase 2 (onion) runs under its own per-round cap, its own much smaller
 * concurrency cap, its own per-dial timeout, and a wall-clock budget for the
 * phase as a whole. A slow or dead onion costs a bounded amount of time and is
 * banked NOT PROBED — never an unbounded wait, never a stalled crawler tick,
 * and never a false "unreachable".
 */

// one-result-type-ok:network-crawler-dial-waves — this TU has no fallible
// service surface: ncrawl_run_round returns a count of banked results and the
// helpers are void. The crawler's zcl_result lifecycle lives in
// network_crawler.c.

#include "network_crawler_internal.h"

#include "storage/event_log_payloads.h"
#include "storage/peers_projection.h"
#include "storage/topology_store.h"

#include "net/netaddr.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


struct ncrawl_work {
    ncrawl_probe_fn fn;
    const struct net_address *addr;
    int connect_timeout_ms;
    int handshake_timeout_ms;
    struct ncrawl_probe_result out;
    bool ok;
};

static void *ncrawl_worker_fn(void *arg)
{
    struct ncrawl_work *w = arg;
    memset(&w->out, 0, sizeof(w->out));
    w->ok = w->fn && w->fn(w->addr, w->connect_timeout_ms,
                           w->handshake_timeout_ms, &w->out);
    return NULL;
}

/* This round's running totals, threaded through both dial phases. */
struct ncrawl_round_acc {
    int      recorded;      /* recordable results banked (measured + unprobed) */
    int      not_probed;
    int      reachable;
    int      edges_seen;
    int      new_nodes;
    int64_t  topo_now;
};

/* Bank one recordable result: bounded census + the durable ledger + (reachable
 * only) one topology "self" edge. Called with NO crawler lock held.
 *
 * A NOT_PROBED result is banked as a census row and as an unprobed note ONLY.
 * It must never reach peers_projection_emit_census_observed(success=false),
 * because that bumps dial_fail_count — i.e. it would launder "we never looked"
 * into "this peer failed", and that false negative flows into peer reputation.
 * Not looking is strictly better represented as no reachability data at all. */
static void ncrawl_bank_result(struct ncrawl_round_acc *acc,
                               const struct net_address *addr,
                               const struct ncrawl_probe_result *res)
{
    ncrawl_census_ingest(res);

    const struct net_addr *na = &addr->svc.addr;
    uint8_t census_key[16];
    if (na->has_torv3)
        memcpy(census_key, na->torv3, 16);
    else
        memcpy(census_key, na->ip, 16);

    acc->recorded++;

    if (res->outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED) {
        acc->not_probed++;
        (void)peers_projection_note_census_unprobed(census_key, addr->svc.port,
                                                    res->reason);
        return;
    }

    /* Bank the durable node-identity census from this crawler contact (source =
     * crawler), OUTSIDE the crawler lock (the emit does event-log I/O). A
     * reachable contact carries an identity (success upsert); an unreachable
     * one only bumps an existing node's dial_fail_count. The emit fails closed
     * on a malformed user-agent and no-ops if no event log is wired. */
    int64_t obs = res->last_probe_us > 0 ? res->last_probe_us
                                         : platform_time_wall_unix();
    (void)peers_projection_emit_census_observed(
        census_key, addr->svc.port, EV_CENSUS_SOURCE_CRAWLER, res->reachable,
        res->subver, res->version, res->services, res->best_height, obs);

    if (res->reachable) {
        acc->reachable++;
        bool is_new = false;
        if (topology_store_record_self_edge(&addr->svc.addr, addr->svc.port,
                                            acc->topo_now, &is_new)) {
            acc->edges_seen++;
            if (is_new)
                acc->new_nodes++;
        }
    }
}

/* Record `addr` as NOT PROBED without dialing (budget spent / no dialer). */
static void ncrawl_bank_unprobed(struct ncrawl_round_acc *acc,
                                 const struct net_address *addr,
                                 const char *reason)
{
    struct ncrawl_probe_result res;
    memset(&res, 0, sizeof(res));
    res.is_onion = net_addr_is_tor(&addr->svc.addr);
    res.outcome = (uint8_t)NCRAWL_OUTCOME_NOT_PROBED;
    res.best_height = -1;
    res.last_probe_us = platform_time_wall_unix();
    snprintf(res.reason, sizeof(res.reason), "%s", reason ? reason : "skipped");
    if (!network_crawler_render_addr(addr, res.addr, sizeof(res.addr)) ||
        !res.addr[0])
        return; /* unrenderable → nothing to key a census row on */
    ncrawl_bank_result(acc, addr, &res);
}

/* Dial the `count` addresses named by idx[] through fn, at most `concurrent`
 * in flight, banking every recordable result. `deadline_us` (<0 = none) is a
 * monotonic wall-clock ceiling checked BEFORE each wave: once it passes, every
 * remaining address is banked NOT PROBED with `skip_reason` instead of dialed,
 * so a slow transport costs a bounded amount of time and still reports what it
 * did not measure. */
static void ncrawl_dial_group(struct ncrawl_round_acc *acc,
                              const struct net_address *addrs, const int *idx,
                              int count, ncrawl_probe_fn fn, int concurrent,
                              int ct_ms, int ht_ms, int64_t deadline_us,
                              const char *skip_reason)
{
    if (!addrs || !idx || count <= 0 || !fn)
        return;
    if (concurrent < 1)
        concurrent = 1;
    if (concurrent > NCRAWL_MAX_CONCURRENT)
        concurrent = NCRAWL_MAX_CONCURRENT;

    for (int base = 0; base < count; base += concurrent) {
        int wave = count - base;
        if (wave > concurrent)
            wave = concurrent;

        if (deadline_us >= 0 && platform_time_monotonic_us() >= deadline_us) {
            for (int t = base; t < count; t++)
                ncrawl_bank_unprobed(acc, &addrs[idx[t]], skip_reason);
            return;
        }

        struct ncrawl_work items[NCRAWL_MAX_CONCURRENT];
        pthread_t th[NCRAWL_MAX_CONCURRENT];
        bool spawned[NCRAWL_MAX_CONCURRENT];

        for (int t = 0; t < wave; t++) {
            items[t].fn = fn;
            items[t].addr = &addrs[idx[base + t]];
            items[t].connect_timeout_ms = ct_ms;
            items[t].handshake_timeout_ms = ht_ms;
            memset(&items[t].out, 0, sizeof(items[t].out));
            items[t].ok = false;
            spawned[t] = false;
            /* Bounded (<=NCRAWL_MAX_CONCURRENT) short-lived probe workers, all
             * joined before this wave returns — not a long-running thread. */
            // raw-pthread-ok: bounded, joined-per-wave short-lived crawler probe worker
            if (pthread_create(&th[t], NULL, ncrawl_worker_fn, &items[t]) == 0)
                spawned[t] = true;
            else
                ncrawl_worker_fn(&items[t]); /* inline fallback on spawn fail */
        }
        for (int t = 0; t < wave; t++)
            if (spawned[t])
                pthread_join(th[t], NULL);

        for (int t = 0; t < wave; t++)
            if (items[t].ok && items[t].out.addr[0])
                ncrawl_bank_result(acc, items[t].addr, &items[t].out);
    }
}

/* Dial addrs[0..n) and ingest each recordable result into the bounded census.
 * Every REACHABLE result also feeds one topology-graph "self" edge (our own
 * node directly reached this address this round — the crawler-results half
 * of storage/topology_store.h's two edge sources; the other half is
 * addr-message ingestion in core/modules/net/src/msgprocessor_inv.c).
 *
 * TWO PHASES, SEPARATELY BOUNDED. Clearnet runs FIRST, with `concurrent` in
 * flight and the connect/handshake timeouts. Only then does the onion phase
 * run, capped at `onion_per_round` addresses, `onion_concurrent` in flight, the
 * onion per-dial timeout, and a wall-clock budget for the phase as a whole.
 * Onion dials therefore cannot starve the clearnet budget nor stall the tick:
 * onion cost per round is bounded by budget + one in-flight dial timeout, and
 * every onion address the budget did not reach is banked NOT PROBED.
 *
 * `stats` (nullable) accumulates this round's sweep-summary counters.
 * Returns the count of recorded results (measured + not-probed). */
int ncrawl_run_round(const struct net_address *addrs, int n,
                     ncrawl_probe_fn fn,
                     const struct ncrawl_round_limits *lim,
                     struct ncrawl_round_stats *stats)
{
    if (stats)
        memset(stats, 0, sizeof(*stats));
    if (!addrs || n <= 0 || !fn || !lim)
        return 0;
    if (n > NCRAWL_MAX_PER_ROUND)
        n = NCRAWL_MAX_PER_ROUND;

    int concurrent = lim->concurrent;
    int ct_ms = lim->connect_timeout_ms;
    int ht_ms = lim->handshake_timeout_ms;
    int onion_per_round = lim->onion_per_round;
    int onion_concurrent = lim->onion_concurrent;
    int onion_timeout_ms = lim->onion_timeout_ms;
    int onion_budget_ms = lim->onion_round_budget_ms;
    if (concurrent < 1) concurrent = 1;
    if (concurrent > NCRAWL_MAX_CONCURRENT) concurrent = NCRAWL_MAX_CONCURRENT;
    if (ct_ms < 100) ct_ms = 100;
    if (ht_ms < 100) ht_ms = 100;
    if (onion_per_round < 0) onion_per_round = 0;
    if (onion_per_round > NCRAWL_MAX_ONION_PER_ROUND)
        onion_per_round = NCRAWL_MAX_ONION_PER_ROUND;
    if (onion_concurrent < 1) onion_concurrent = 1;
    if (onion_concurrent > NCRAWL_MAX_ONION_CONCURRENT)
        onion_concurrent = NCRAWL_MAX_ONION_CONCURRENT;
    if (onion_timeout_ms < 100) onion_timeout_ms = 100;
    if (onion_budget_ms < 0) onion_budget_ms = 0;

    int clear_idx[NCRAWL_MAX_PER_ROUND];
    int onion_idx[NCRAWL_MAX_PER_ROUND];
    int nclear = 0, nonion = 0;
    for (int i = 0; i < n; i++) {
        if (net_addr_is_tor(&addrs[i].svc.addr))
            onion_idx[nonion++] = i;
        else
            clear_idx[nclear++] = i;
    }

    struct ncrawl_round_acc acc;
    memset(&acc, 0, sizeof(acc));
    acc.topo_now = platform_time_wall_unix();

    /* Phase 1 — clearnet, always first, always to completion. */
    ncrawl_dial_group(&acc, addrs, clear_idx, nclear, fn, concurrent, ct_ms,
                      ht_ms, -1, NULL);

    /* Phase 2 — onion, on its own cap + budget. Anything past the per-round
     * cap is banked NOT PROBED (it comes around on a later round). */
    if (nonion > 0) {
        int dial = nonion < onion_per_round ? nonion : onion_per_round;
        for (int i = dial; i < nonion; i++)
            ncrawl_bank_unprobed(&acc, &addrs[onion_idx[i]],
                                 "onion per-round cap");
        int64_t deadline = onion_budget_ms > 0
                               ? platform_time_monotonic_us() +
                                     (int64_t)onion_budget_ms * 1000
                               : -1;
        /* The onion timeout rides BOTH seam slots on purpose — see the
         * network_crawler_default_probe contract. */
        ncrawl_dial_group(&acc, addrs, onion_idx, dial, fn, onion_concurrent,
                          onion_timeout_ms, onion_timeout_ms, deadline,
                          "onion round budget spent");
    }

    if (stats) {
        stats->recorded = acc.recorded;
        stats->reachable = acc.reachable;
        stats->not_probed = acc.not_probed;
        stats->edges_seen = acc.edges_seen;
        stats->new_nodes = acc.new_nodes;
    }
    return acc.recorded;
}

