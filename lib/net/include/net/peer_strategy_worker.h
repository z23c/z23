/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Background NAT/reachability probe worker.
 *
 * peer_strategy_discover_self() is a BLOCKING probe (NAT-PMP, then UPnP
 * SSDP + SOAP, then naked IP discovery — tens of seconds on a host whose
 * gateway ignores it). It used to run synchronously in the boot sequence,
 * ahead of the reducer stage-pipeline init, so a silent gateway wedged
 * boot: the node answered RPC (the frontend had already started) while
 * the consensus engine never came up. This worker owns the probe instead:
 * boot spawns it and moves on immediately, and the worker publishes the
 * result (profile snapshot + onion-directory self row, the latter still
 * from inside discover_self) when the probe finishes.
 *
 * The same worker re-arms the port mapping at HALF the 7200-second lease
 * (3600 s): nat_add_port_mapping is idempotent refresh, so re-running the
 * probe renews the mapping, re-confirms the public IP, and republishes the
 * directory row through the one existing path. A failed renewal never
 * crashes the node and never abandons the mapping silently: it logs
 * loudly, keeps the last published row, and retries on a bounded
 * exponential backoff (60 s doubling to a 900 s cap).
 *
 * Shutdown is stop() + join(): the renewal wait is a condition variable,
 * so a waiting worker wakes instantly. An in-flight probe cannot be
 * cancelled — nat.c has no cancel seam — but every socket operation in it
 * carries a 2-3 s timeout, bounding a full probe at roughly 25 s worst
 * case; the join waits that out rather than detaching (this tree never
 * abandons an owned thread).
 *
 * Test seams: probe_fn / regtest_fn are injectable; run_once() performs a
 * single probe + publish + schedule step synchronously, and
 * psw_next_delay_secs() is the pure scheduling decision. Tests drive
 * those directly; only the lifecycle test spawns the real thread. */

#ifndef ZCL_NET_PEER_STRATEGY_WORKER_H
#define ZCL_NET_PEER_STRATEGY_WORKER_H

#include "net/peer_strategy.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

/* Mapping lease and renewal cadence. */
#define PSW_LEASE_SECS         7200
#define PSW_RENEW_SECS         3600   /* half-life re-arm */
#define PSW_BACKOFF_INIT_SECS  60
#define PSW_BACKOFF_MAX_SECS   900
/* Documented join bound: exceeds the ~25 s worst-case in-flight probe
 * (every nat.c socket op carries a 2-3 s timeout). On expiry the join
 * logs the straggler and waits it out — ownership is never abandoned. */
#define PSW_JOIN_TIMEOUT_SECS  30

enum psw_state {
    PSW_IDLE = 0,        /* not started, or stopped */
    PSW_PROBING,         /* started, first probe not finished */
    PSW_MAPPED,          /* last probe reached a public endpoint */
    PSW_UNMAPPED,        /* last probe found nothing (or renewal failed) */
    PSW_SKIPPED_REGTEST, /* regtest: no mapping, no renewal, worker exits */
};

struct peer_strategy_worker {
    uint16_t listen_port;

    /* Injectable seams (tests). Defaults installed by
     * peer_strategy_worker_init: the real probe and the chainparams
     * regtest gate. */
    bool (*probe_fn)(struct node_profile *profile, uint16_t port,
                     void *seam_ctx);
    bool (*regtest_fn)(void *seam_ctx);
    void *seam_ctx;

    /* Published result — read under peer_strategy_worker_snapshot(). */
    pthread_mutex_t mu;
    pthread_cond_t  cv;       /* signals stop AND each published result */
    struct node_profile profile;
    enum psw_state state;
    bool stop;
    int  backoff_secs;        /* current retry interval after a failure */
    int  next_delay_secs;     /* delay the loop is (about to be) sleeping */

    pthread_t tid;
    bool      started;
};

void peer_strategy_worker_init(struct peer_strategy_worker *w,
                               uint16_t listen_port);

const char *psw_state_name(enum psw_state s);

/* Pure scheduling decision: lease half-life after a success (and the
 * backoff reset), bounded exponential backoff after a failure
 * (*backoff_secs advances 60 -> 120 -> ... -> 900). */
int psw_next_delay_secs(bool probe_ok, int *backoff_secs);

/* One probe/renewal step, synchronously: regtest gate, probe, publish
 * (profile snapshot +, in the real probe, the directory self row),
 * schedule. Returns false when the worker must exit (stop requested or
 * regtest skip), true when it should sleep next_delay_secs and repeat. */
bool peer_strategy_worker_run_once(struct peer_strategy_worker *w);

/* Spawn the probe loop through thread_registry_spawn (tracked, named
 * "zcl_nat_probe"). Boot calls this and moves on WITHOUT waiting for a
 * result. */
bool peer_strategy_worker_start(struct peer_strategy_worker *w);

/* Signal stop and wake the renewal wait. Non-blocking; an in-flight
 * probe still runs to its socket-timeout bound. Idempotent. */
void peer_strategy_worker_stop(struct peer_strategy_worker *w);

/* Bounded-then-logged join (PSW_JOIN_TIMEOUT_SECS), then an unconditional
 * join: the worker is never detached. Safe without a prior start. */
void peer_strategy_worker_join(struct peer_strategy_worker *w);

/* Locked copy of the last published profile. Returns the state. */
enum psw_state
peer_strategy_worker_snapshot(struct peer_strategy_worker *w,
                              struct node_profile *out);

#endif
