/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_crawler service — see services/network_crawler.h. A supervised worker
 * walks the full local address table (addrman_get_addr), dials a bounded,
 * rate-limited batch of addresses per round OUTSIDE the node's connman (the
 * injectable probe_fn seam), records a bounded/pruned census, and folds it into
 * a whole-network view: reachable count, version histogram, height
 * distribution, onion/clearnet split, the measured/not-probed split, and an
 * eclipse signal (our connected-peer modal height vs the crawled network's
 * modal height). ON by default; the worker still registers and idles when
 * disabled (named degradation). Observational only; never relays, syncs, or
 * touches chain selection.
 *
 * Four TUs, one per concern:
 *   network_crawler.c        this file — config, census table, worker, dumper
 *   network_census_fold.c    the PURE fold (no globals, no clock, no I/O)
 *   network_crawler_dial.c   the two-phase, separately-bounded probe waves
 *   network_crawler_probe.c  the default REAL dialer (clearnet TCP + onion Tor)
 */

// one-result-type-ok:network-crawler-query-accessors — the fallible service
// surface (network_crawler_start) returns struct zcl_result; the remaining
// bool exports (get_view/dump + test helpers are pure predicates) are not
// fallible operations.

#include "network_crawler_internal.h"

#include "services/network_monitor.h"

#include "net/addrman.h"
#include "storage/peers_projection.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/topology_store.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/thread_registry.h"
#include "util/util.h"
#include "supervisors/domains.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NCRAWL_SUPERVISOR_DEADLINE_SEC 300

static struct {
    zcl_mutex_t lock;
    bool started;
    bool enabled;

    struct addr_man *addrman;
    ncrawl_probe_fn probe_fn;
    int round_interval_secs;
    int max_per_round;
    int max_concurrent;
    int connect_timeout_ms;
    int handshake_timeout_ms;
    int onion_max_per_round;
    int onion_max_concurrent;
    int onion_timeout_ms;
    int onion_round_budget_ms;

    /* bounded/pruned census (source of truth for the fold + dumper) */
    struct ncrawl_probe_result census[NCRAWL_MAX_CENSUS];
    int census_count;
    struct network_census_view view;

    /* round stats */
    int64_t rounds_run;
    int probed_last_round;
    int64_t addresses_known;
    int64_t last_round_unix;
    int not_probed_last_round;

    /* supervised worker */
    pthread_t thread;
    _Atomic bool stop_requested;
    bool thread_running;
    _Atomic int64_t loop_ticks;
    _Atomic supervisor_child_id supervisor_id;
#ifdef ZCL_TESTING
    _Atomic int64_t test_own_modal;   /* INT64_MIN = unset */
#endif
} g_ncrawl = {
    .probe_fn = network_crawler_default_probe,
};

static pthread_once_t g_ncrawl_lock_once = PTHREAD_ONCE_INIT;

static void ncrawl_lock_init_once(void)
{
    zcl_mutex_init(&g_ncrawl.lock);
}

static void ncrawl_lock(void)
{
    /* The lock has process lifetime, matching the former static POSIX mutex.
     * pthread_once is supplied by both supported pthread runtimes; the object
     * it initializes is the platform zcl_mutex_t (CRITICAL_SECTION on Win32,
     * recursive pthread mutex on POSIX). */
    if (pthread_once(&g_ncrawl_lock_once, ncrawl_lock_init_once) != 0) {
        LOG_ERROR("network_crawler",
                  "crawler lock one-time initialization failed");
        abort();
    }
    zcl_mutex_lock(&g_ncrawl.lock);
}

static struct liveness_contract g_ncrawl_contract;

/* ── config ──────────────────────────────────────────────────────────── */

void network_crawler_config_defaults(struct network_crawler_config *cfg)
{
    if (!cfg)
        return;
    /* NET-2: ON by default — the eclipse blocker (net_eclipse_suspected) needs
     * the wider-network census to detect that our connected peers are a small
     * minority. The existing rate limits (bounded probe batches on short-lived
     * measurement sockets outside connman) are unchanged. Opt OUT with
     * ZCL_NETWORK_CRAWLER=0. */
    cfg->enabled = true;
    cfg->round_interval_secs = NCRAWL_ROUND_INTERVAL_SECS_DEFAULT;
    cfg->max_per_round = NCRAWL_MAX_PER_ROUND;
    cfg->max_concurrent = NCRAWL_MAX_CONCURRENT;
    cfg->connect_timeout_ms = NCRAWL_CONNECT_TIMEOUT_MS_DEFAULT;
    cfg->handshake_timeout_ms = NCRAWL_HANDSHAKE_TIMEOUT_MS_DEFAULT;
    cfg->onion_max_per_round = NCRAWL_MAX_ONION_PER_ROUND;
    cfg->onion_max_concurrent = NCRAWL_MAX_ONION_CONCURRENT;
    cfg->onion_timeout_ms = NCRAWL_ONION_TIMEOUT_MS_DEFAULT;
    cfg->onion_round_budget_ms = NCRAWL_ONION_ROUND_BUDGET_MS_DEFAULT;
}

static bool ncrawl_env_truthy(const char *e)
{
    return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T' ||
                 e[0] == 'y' || e[0] == 'Y');
}

/* Explicit opt-out truthiness: 0/f/F/n/N disables. */
static bool ncrawl_env_falsy(const char *e)
{
    return e && (e[0] == '0' || e[0] == 'f' || e[0] == 'F' ||
                 e[0] == 'n' || e[0] == 'N');
}

static void ncrawl_config_from_env(struct network_crawler_config *cfg)
{
    /* ON by default (omniscience directive); both the -netcrawl CLI flag and
     * the ZCL_NETWORK_CRAWLER env var are opt-OUT knobs. Precedence: start from
     * the compiled default (true), apply the env override, then let an
     * explicit -netcrawl CLI flag win last (a boot flag beats the shell env).
     * `-netcrawl=0` (or `-nonetcrawl`) fully disables; `-netcrawl`/`-netcrawl=1`
     * re-enables. */
    const char *en = getenv("ZCL_NETWORK_CRAWLER");
    if (ncrawl_env_falsy(en))
        cfg->enabled = false;
    else if (ncrawl_env_truthy(en))
        cfg->enabled = true;
    if (GetArg("-netcrawl", NULL))            /* flag present → it decides */
        cfg->enabled = GetBoolArg("-netcrawl", true);
    const char *iv = getenv("ZCL_NETCRAWL_INTERVAL_SECS");
    if (iv && iv[0]) {
        int v = atoi(iv);
        if (v >= 5 && v <= 86400)
            cfg->round_interval_secs = v;
    }
    const char *pr = getenv("ZCL_NETCRAWL_MAX_PER_ROUND");
    if (pr && pr[0]) {
        int v = atoi(pr);
        if (v >= 1 && v <= NCRAWL_MAX_PER_ROUND)
            cfg->max_per_round = v;
    }
    const char *mc = getenv("ZCL_NETCRAWL_MAX_CONCURRENT");
    if (mc && mc[0]) {
        int v = atoi(mc);
        if (v >= 1 && v <= NCRAWL_MAX_CONCURRENT)
            cfg->max_concurrent = v;
    }
    const char *op = getenv("ZCL_NETCRAWL_ONION_PER_ROUND");
    if (op && op[0]) {
        int v = atoi(op);
        if (v >= 0 && v <= NCRAWL_MAX_ONION_PER_ROUND)
            cfg->onion_max_per_round = v;
    }
    const char *oc = getenv("ZCL_NETCRAWL_ONION_CONCURRENT");
    if (oc && oc[0]) {
        int v = atoi(oc);
        if (v >= 1 && v <= NCRAWL_MAX_ONION_CONCURRENT)
            cfg->onion_max_concurrent = v;
    }
    const char *ot = getenv("ZCL_NETCRAWL_ONION_TIMEOUT_MS");
    if (ot && ot[0]) {
        int v = atoi(ot);
        if (v >= 100 && v <= 120000)
            cfg->onion_timeout_ms = v;
    }
    const char *ob = getenv("ZCL_NETCRAWL_ONION_BUDGET_MS");
    if (ob && ob[0]) {
        int v = atoi(ob);
        if (v >= 0 && v <= 240000)
            cfg->onion_round_budget_ms = v;
    }
}

/* Clamp every knob into its hard bound (defensive: env + cfg both untrusted). */
static void ncrawl_clamp(struct network_crawler_config *c)
{
    if (c->round_interval_secs < 5) c->round_interval_secs = 5;
    if (c->round_interval_secs > 86400) c->round_interval_secs = 86400;
    if (c->max_per_round < 1) c->max_per_round = 1;
    if (c->max_per_round > NCRAWL_MAX_PER_ROUND) c->max_per_round = NCRAWL_MAX_PER_ROUND;
    if (c->max_concurrent < 1) c->max_concurrent = 1;
    if (c->max_concurrent > NCRAWL_MAX_CONCURRENT) c->max_concurrent = NCRAWL_MAX_CONCURRENT;
    if (c->connect_timeout_ms < 100) c->connect_timeout_ms = 100;
    if (c->connect_timeout_ms > 60000) c->connect_timeout_ms = 60000;
    if (c->handshake_timeout_ms < 100) c->handshake_timeout_ms = 100;
    if (c->handshake_timeout_ms > 60000) c->handshake_timeout_ms = 60000;
    if (c->onion_max_per_round < 0) c->onion_max_per_round = 0;
    if (c->onion_max_per_round > NCRAWL_MAX_ONION_PER_ROUND)
        c->onion_max_per_round = NCRAWL_MAX_ONION_PER_ROUND;
    if (c->onion_max_concurrent < 1) c->onion_max_concurrent = 1;
    if (c->onion_max_concurrent > NCRAWL_MAX_ONION_CONCURRENT)
        c->onion_max_concurrent = NCRAWL_MAX_ONION_CONCURRENT;
    if (c->onion_timeout_ms < 100) c->onion_timeout_ms = 100;
    if (c->onion_timeout_ms > 120000) c->onion_timeout_ms = 120000;
    if (c->onion_round_budget_ms < 0) c->onion_round_budget_ms = 0;
    if (c->onion_round_budget_ms > 240000) c->onion_round_budget_ms = 240000;
}

/* ── bounded census table ────────────────────────────────────────────── */

/* Insert-or-update by addr; evict when full. Caller holds g_ncrawl.lock.
 *
 * A NOT_PROBED row NEVER overwrites a row we actually measured — "we did not
 * look this round" must not erase "we measured it last round". It only ever
 * inserts an address we have no measurement for at all.
 *
 * That per-address rule is not enough on its own, and the AGGREGATE one is
 * what this eviction order exists for. ncrawl_bank_unprobed() stamps
 * last_probe_us = now on every row it banks, so a fresh NOT_PROBED row is
 * never the smallest-last_probe_us victim — a pure oldest-first eviction
 * therefore let up to onion_max_per_round unprobed rows per round push real
 * measurements out of the bounded census, one round after another. So:
 * evict a NOT_PROBED row before any MEASURED one, oldest-first inside each
 * class, and refuse to insert a NOT_PROBED row at all when every seat is
 * held by a measurement. A row we never looked at cannot displace a row we
 * did. */
static void ncrawl_census_ingest_locked(const struct ncrawl_probe_result *pr)
{
    if (!pr || !pr->addr[0])
        return;
    for (int i = 0; i < g_ncrawl.census_count; i++) {
        if (strcmp(g_ncrawl.census[i].addr, pr->addr) == 0) {
            if (pr->outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED &&
                g_ncrawl.census[i].outcome ==
                    (uint8_t)NCRAWL_OUTCOME_MEASURED)
                return;
            g_ncrawl.census[i] = *pr;
            return;
        }
    }
    if (g_ncrawl.census_count < NCRAWL_MAX_CENSUS) {
        g_ncrawl.census[g_ncrawl.census_count++] = *pr;
        return;
    }
    int victim = 0;
    bool victim_measured =
        g_ncrawl.census[0].outcome == (uint8_t)NCRAWL_OUTCOME_MEASURED;
    for (int i = 1; i < g_ncrawl.census_count; i++) {
        bool measured =
            g_ncrawl.census[i].outcome == (uint8_t)NCRAWL_OUTCOME_MEASURED;
        if (victim_measured && !measured) {
            victim = i;
            victim_measured = false;
            continue;
        }
        if (victim_measured != measured)
            continue;                       /* keep the unprobed candidate */
        if (g_ncrawl.census[i].last_probe_us <
            g_ncrawl.census[victim].last_probe_us)
            victim = i;
    }
    if (victim_measured &&
        pr->outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED)
        return;   /* full of measurements: the unprobed row waits a round */
    g_ncrawl.census[victim] = *pr;
}

void ncrawl_census_ingest(const struct ncrawl_probe_result *pr)
{
    ncrawl_lock();
    ncrawl_census_ingest_locked(pr);
    zcl_mutex_unlock(&g_ncrawl.lock);
}

/* Snapshot every bound this round runs under. */
static void ncrawl_limits_snapshot(struct ncrawl_round_limits *lim)
{
    ncrawl_lock();
    lim->concurrent = g_ncrawl.max_concurrent;
    lim->connect_timeout_ms = g_ncrawl.connect_timeout_ms;
    lim->handshake_timeout_ms = g_ncrawl.handshake_timeout_ms;
    lim->onion_per_round = g_ncrawl.onion_max_per_round;
    lim->onion_concurrent = g_ncrawl.onion_max_concurrent;
    lim->onion_timeout_ms = g_ncrawl.onion_timeout_ms;
    lim->onion_round_budget_ms = g_ncrawl.onion_round_budget_ms;
    zcl_mutex_unlock(&g_ncrawl.lock);
}

static void ncrawl_refold_locked(int64_t own_modal, int64_t now)
{
    network_census_compute(g_ncrawl.census, g_ncrawl.census_count,
                           own_modal, now, &g_ncrawl.view);
}

static int64_t ncrawl_own_modal(void)
{
#ifdef ZCL_TESTING
    int64_t o = atomic_load(&g_ncrawl.test_own_modal);
    if (o != INT64_MIN)
        return o;
#endif
    struct network_consensus_view v;
    if (network_monitor_get_view(&v))
        return v.modal_height;
    return -1; // raw-return-ok:sentinel-own-modal-unknown
}

/* One full crawl round: pull a bounded address batch from addrman, probe it,
 * refold. Worker-thread-only (the batch buffer is thread-owned). Each round
 * is also this crawler's "sweep boundary" for storage/topology_store.h's
 * topology_sweeps ledger: one bounded batch, a definite start/end, appended
 * unconditionally (best-effort — a not-open topology store just no-ops). */
static void ncrawl_do_round(void)
{
    struct addr_man *am = g_ncrawl.addrman;
    if (!am)
        return;
    static struct net_address batch[NCRAWL_MAX_PER_ROUND]; /* worker-thread-owned */
    size_t want = (size_t)g_ncrawl.max_per_round;
    if (want > NCRAWL_MAX_PER_ROUND)
        want = NCRAWL_MAX_PER_ROUND;
    size_t got = addrman_get_addr(am, batch, want);
    int n = (int)(got > NCRAWL_MAX_PER_ROUND ? NCRAWL_MAX_PER_ROUND : got);

    struct ncrawl_round_limits lim;
    ncrawl_limits_snapshot(&lim);
    int64_t sweep_started = platform_time_wall_unix();
    struct ncrawl_round_stats st;
    int probed = ncrawl_run_round(batch, n, g_ncrawl.probe_fn, &lim, &st);
    int64_t sweep_finished = platform_time_wall_unix();
    (void)topology_store_record_sweep(sweep_started, sweep_finished, n,
                                      st.reachable, st.edges_seen, st.new_nodes);

    int64_t now = sweep_finished;
    int64_t own = ncrawl_own_modal();
    ncrawl_lock();
    g_ncrawl.rounds_run++;
    g_ncrawl.probed_last_round = probed;
    g_ncrawl.not_probed_last_round = st.not_probed;
    g_ncrawl.addresses_known = (int64_t)addrman_size(am);
    g_ncrawl.last_round_unix = now;
    ncrawl_refold_locked(own, now);
    zcl_mutex_unlock(&g_ncrawl.lock);
}

/* ── supervised worker thread ────────────────────────────────────────── */

static void ncrawl_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_ncrawl.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_ncrawl.loop_ticks));
}

static void ncrawl_on_stall(struct liveness_contract *c)
{
    (void)c;
    LOG_WARN("network_crawler",
             "crawler heartbeat lapsed (ticks=%lld) — worker may be wedged",
             (long long)atomic_load(&g_ncrawl.loop_ticks));
}

static void *ncrawl_thread_fn(void *arg)
{
    (void)arg;
    int64_t next_round_at = 0; /* first round immediately when enabled */
    while (!atomic_load(&g_ncrawl.stop_requested)) {
        atomic_fetch_add(&g_ncrawl.loop_ticks, 1);
        ncrawl_heartbeat();

        int64_t now = platform_time_wall_unix();
        if (g_ncrawl.enabled && now >= next_round_at) {
            ncrawl_do_round();
            next_round_at = now + g_ncrawl.round_interval_secs;
        }
        platform_sleep_ms(200); /* responsive stop between rounds */
    }
    return NULL;
}

static struct zcl_result ncrawl_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-5, "network_crawler: supervisor_start failed");

    liveness_contract_init(&g_ncrawl_contract, "net.network_crawler");
    atomic_store(&g_ncrawl_contract.period_secs, 0); /* self-heartbeats */
    atomic_store(&g_ncrawl_contract.deadline_secs, NCRAWL_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_ncrawl_contract.progress_max_quiet_us, 0);
    g_ncrawl_contract.on_stall = ncrawl_on_stall;

    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_net_sup, &g_ncrawl_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-6, "network_crawler: supervisor_register failed");
    atomic_store(&g_ncrawl.supervisor_id, id);
    return ZCL_OK;
}

struct zcl_result network_crawler_start(const struct network_crawler_config *cfg,
                                        struct addr_man *addrman)
{
    if (g_ncrawl.started)
        return ZCL_OK;

    struct network_crawler_config local;
    network_crawler_config_defaults(&local);
    if (cfg)
        local = *cfg;
    ncrawl_config_from_env(&local);
    ncrawl_clamp(&local);

    g_ncrawl.enabled = local.enabled;
    g_ncrawl.addrman = addrman;
    g_ncrawl.round_interval_secs = local.round_interval_secs;
    g_ncrawl.max_per_round = local.max_per_round;
    g_ncrawl.max_concurrent = local.max_concurrent;
    g_ncrawl.connect_timeout_ms = local.connect_timeout_ms;
    g_ncrawl.handshake_timeout_ms = local.handshake_timeout_ms;
    g_ncrawl.onion_max_per_round = local.onion_max_per_round;
    g_ncrawl.onion_max_concurrent = local.onion_max_concurrent;
    g_ncrawl.onion_timeout_ms = local.onion_timeout_ms;
    g_ncrawl.onion_round_budget_ms = local.onion_round_budget_ms;
    if (!g_ncrawl.probe_fn)
        g_ncrawl.probe_fn = network_crawler_default_probe;
    atomic_store(&g_ncrawl.stop_requested, false);
    atomic_store(&g_ncrawl.loop_ticks, 0);
    atomic_store(&g_ncrawl.supervisor_id, SUPERVISOR_INVALID_ID);

    g_ncrawl.thread_running = true;
    int rc = thread_registry_spawn("zcl_network_crawler", ncrawl_thread_fn,
                                   NULL, &g_ncrawl.thread);
    if (rc != 0) {
        g_ncrawl.thread_running = false;
        return ZCL_ERR(-4,
                       "network_crawler: thread_registry_spawn failed (%d)", rc);
    }

    struct zcl_result sup = ncrawl_register_supervisor();
    if (!sup.ok) {
        /* worker still runs; supervision is a liveness contract, not a hard
         * dependency. Name the gap loudly and continue. */
        LOG_WARN("network_crawler", "supervisor registration failed: %s",
                 sup.message);
    }

    g_ncrawl.started = true;
    if (!g_ncrawl.enabled)
        LOG_WARN("network_crawler",
                 "crawler registered but IDLE (disabled via ZCL_NETWORK_CRAWLER=0; "
                 "it is ON by default — the eclipse census is off while disabled)");
    return ZCL_OK;
}

void network_crawler_stop(void)
{
    if (!g_ncrawl.started)
        return;
    atomic_store(&g_ncrawl.stop_requested, true);
    atomic_store(&g_ncrawl_contract.deadline_secs, 0); /* silence stall on stop */
    if (g_ncrawl.thread_running) {
        pthread_join(g_ncrawl.thread, NULL);
        g_ncrawl.thread_running = false;
    }
    g_ncrawl.started = false;
}

bool network_crawler_get_view(struct network_census_view *out)
{
    if (!out)
        return false;
    /* Defined on every path. A false return means "no fold yet", and a
     * caller that reads `out` anyway must see zeros, not whatever was on
     * its stack — the census can now legitimately refuse a row (see the
     * eviction order in ncrawl_census_ingest_locked), so "the answer is
     * always there" is no longer a safe assumption anywhere. */
    memset(out, 0, sizeof(*out));
    ncrawl_lock();
    bool ready = g_ncrawl.view.ready;
    if (ready)
        *out = g_ncrawl.view;
    zcl_mutex_unlock(&g_ncrawl.lock);
    return ready;
}

/* ── introspection (network_census dumper) ───────────────────────────── */

bool network_crawler_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    ncrawl_lock();
    bool started = g_ncrawl.started;
    bool enabled = g_ncrawl.enabled;
    struct network_census_view v = g_ncrawl.view;
    int census_count = g_ncrawl.census_count;
    int64_t rounds = g_ncrawl.rounds_run;
    int probed_last = g_ncrawl.probed_last_round;
    int64_t known = g_ncrawl.addresses_known;
    int64_t last_round = g_ncrawl.last_round_unix;
    int interval = g_ncrawl.round_interval_secs;
    int per_round = g_ncrawl.max_per_round;
    int concurrent = g_ncrawl.max_concurrent;
    int ct_ms = g_ncrawl.connect_timeout_ms;
    int ht_ms = g_ncrawl.handshake_timeout_ms;
    int onion_per = g_ncrawl.onion_max_per_round;
    int onion_conc = g_ncrawl.onion_max_concurrent;
    int onion_to = g_ncrawl.onion_timeout_ms;
    int onion_budget = g_ncrawl.onion_round_budget_ms;
    int not_probed_last = g_ncrawl.not_probed_last_round;
    zcl_mutex_unlock(&g_ncrawl.lock);

    json_push_kv_bool(out, "started", started);
    json_push_kv_bool(out, "enabled", enabled);
    json_push_kv_bool(out, "running", started && enabled);
    json_push_kv_int(out, "round_interval_secs", interval);
    json_push_kv_int(out, "max_per_round", per_round);
    json_push_kv_int(out, "max_concurrent", concurrent);
    json_push_kv_int(out, "connect_timeout_ms", ct_ms);
    json_push_kv_int(out, "handshake_timeout_ms", ht_ms);
    json_push_kv_int(out, "loop_ticks", atomic_load(&g_ncrawl.loop_ticks));
    json_push_kv_int(out, "rounds_run", rounds);
    json_push_kv_int(out, "addresses_known", known);
    json_push_kv_int(out, "census_rows", census_count);
    json_push_kv_int(out, "probed_last_round", probed_last);
    json_push_kv_int(out, "not_probed_last_round", not_probed_last);
    json_push_kv_int(out, "last_round_unix", last_round);

    /* The onion half of the network: its own budget, and whether we can dial
     * it at all right now. onion_probe_available=false means every onion row
     * reads NOT PROBED — the honest state, never "unreachable". */
    json_push_kv_int(out, "onion_max_per_round", onion_per);
    json_push_kv_int(out, "onion_max_concurrent", onion_conc);
    json_push_kv_int(out, "onion_timeout_ms", onion_to);
    json_push_kv_int(out, "onion_round_budget_ms", onion_budget);
    json_push_kv_bool(out, "onion_probe_available",
                      network_crawler_onion_probe_available());
    /* Process-lifetime total of addresses we banked as unmeasured, straight
     * from the durable-ledger side. Distinct from not_probed_count below,
     * which is the CURRENT census snapshot. */
    json_push_kv_int(out, "ledger_unprobed_notes_total",
                     (int64_t)peers_projection_census_unprobed_total());
    {
        char why[PEERS_CENSUS_UNPROBED_REASON_MAX];
        peers_projection_census_unprobed_reason(why, sizeof(why));
        json_push_kv_str(out, "ledger_unprobed_last_reason", why);
    }

    if (!v.ready) {
        diag_push_health(out, true,
                         enabled ? "no census yet"
                                 : "crawler disabled (opt-out: ZCL_NETWORK_CRAWLER=0)");
        return true;
    }

    json_push_kv_int(out, "computed_at", v.computed_at);
    json_push_kv_int(out, "reachable_count", v.reachable_count);
    json_push_kv_int(out, "onion_count", v.onion_count);
    json_push_kv_int(out, "clearnet_count", v.clearnet_count);
    json_push_kv_int(out, "measured_count", v.measured_count);
    json_push_kv_int(out, "not_probed_count", v.not_probed_count);
    json_push_kv_int(out, "onion_measured_count", v.onion_measured_count);
    json_push_kv_int(out, "onion_not_probed_count", v.onion_not_probed_count);
    json_push_kv_str(out, "not_probed_reason", v.not_probed_reason);
    json_push_kv_int(out, "heights_known", v.heights_known);
    json_push_kv_int(out, "modal_height", v.modal_height);
    json_push_kv_int(out, "modal_height_count", v.modal_height_count);
    json_push_kv_int(out, "max_height", v.max_height);
    json_push_kv_int(out, "min_height", v.min_height);
    json_push_kv_int(out, "height_spread", v.height_spread);

    struct json_value versions;
    json_init(&versions);
    json_set_array(&versions);
    int top = v.num_versions;
    if (top > NCRAWL_TOPN_VERSIONS)
        top = NCRAWL_TOPN_VERSIONS;
    for (int i = 0; i < top; i++) {
        struct json_value b;
        json_init(&b);
        json_set_object(&b);
        json_push_kv_str(&b, "subver", v.versions[i].subver);
        json_push_kv_int(&b, "count", v.versions[i].count);
        (void)json_push_back(&versions, &b);
        json_free(&b);
    }
    (void)json_push_kv(out, "version_histogram", &versions);
    json_free(&versions);

    json_push_kv_bool(out, "eclipse_suspected", v.eclipse_suspected);
    struct json_value ev;
    json_init(&ev);
    json_set_object(&ev);
    json_push_kv_int(&ev, "own_modal_height", v.own_modal_height);
    json_push_kv_int(&ev, "network_modal_height", v.network_modal_height);
    json_push_kv_int(&ev, "network_count_at_own_modal",
                     v.network_count_at_own_modal);
    json_push_kv_int(&ev, "reachable_count", v.reachable_count);
    (void)json_push_kv(out, "eclipse_evidence", &ev);
    json_free(&ev);

    char reason[192];
    if (v.eclipse_suspected)
        snprintf(reason, sizeof(reason),
                 "eclipse: our peers modal=%lld is a %d/%d minority vs network "
                 "modal=%lld",
                 (long long)v.own_modal_height, v.network_count_at_own_modal,
                 v.reachable_count, (long long)v.network_modal_height);
    else
        snprintf(reason, sizeof(reason),
                 "reachable=%d modal_height=%lld spread=%lld",
                 v.reachable_count, (long long)v.modal_height,
                 (long long)v.height_spread);
    diag_push_health(out, !v.eclipse_suspected, reason);
    return true;
}

#ifdef ZCL_TESTING
void network_crawler_test_reset(void)
{
    ncrawl_lock();
    g_ncrawl.census_count = 0;
    memset(g_ncrawl.census, 0, sizeof(g_ncrawl.census));
    memset(&g_ncrawl.view, 0, sizeof(g_ncrawl.view));
    g_ncrawl.rounds_run = 0;
    g_ncrawl.probed_last_round = 0;
    g_ncrawl.not_probed_last_round = 0;
    g_ncrawl.addresses_known = 0;
    g_ncrawl.last_round_unix = 0;
    g_ncrawl.probe_fn = network_crawler_default_probe;
    g_ncrawl.max_per_round = NCRAWL_MAX_PER_ROUND;
    g_ncrawl.max_concurrent = NCRAWL_MAX_CONCURRENT;
    g_ncrawl.connect_timeout_ms = NCRAWL_CONNECT_TIMEOUT_MS_DEFAULT;
    g_ncrawl.handshake_timeout_ms = NCRAWL_HANDSHAKE_TIMEOUT_MS_DEFAULT;
    g_ncrawl.onion_max_per_round = NCRAWL_MAX_ONION_PER_ROUND;
    g_ncrawl.onion_max_concurrent = NCRAWL_MAX_ONION_CONCURRENT;
    g_ncrawl.onion_timeout_ms = NCRAWL_ONION_TIMEOUT_MS_DEFAULT;
    g_ncrawl.onion_round_budget_ms = NCRAWL_ONION_ROUND_BUDGET_MS_DEFAULT;
    atomic_store(&g_ncrawl.test_own_modal, INT64_MIN);
    zcl_mutex_unlock(&g_ncrawl.lock);
}

void network_crawler_test_set_probe_fn(ncrawl_probe_fn fn)
{
    ncrawl_lock();
    g_ncrawl.probe_fn = fn ? fn : network_crawler_default_probe;
    zcl_mutex_unlock(&g_ncrawl.lock);
}

void network_crawler_test_set_own_modal(int64_t h)
{
    atomic_store(&g_ncrawl.test_own_modal, h);
}

void network_crawler_test_set_view(const struct network_census_view *v)
{
    if (!v)
        return;
    ncrawl_lock();
    g_ncrawl.view = *v;
    g_ncrawl.view.ready = true;
    zcl_mutex_unlock(&g_ncrawl.lock);
}

int network_crawler_test_probe_round(const struct net_address *addrs, int n)
{
    struct ncrawl_round_limits lim;
    ncrawl_limits_snapshot(&lim);
    int64_t sweep_started = platform_time_wall_unix();
    struct ncrawl_round_stats st;
    int probed = ncrawl_run_round(addrs, n, g_ncrawl.probe_fn, &lim, &st);
    int64_t now = platform_time_wall_unix();
    (void)topology_store_record_sweep(sweep_started, now, n, st.reachable,
                                      st.edges_seen, st.new_nodes);
    int64_t own = ncrawl_own_modal();
    ncrawl_lock();
    g_ncrawl.rounds_run++;
    g_ncrawl.probed_last_round = probed;
    g_ncrawl.not_probed_last_round = st.not_probed;
    ncrawl_refold_locked(own, now);
    zcl_mutex_unlock(&g_ncrawl.lock);
    return probed;
}

int network_crawler_test_census_count(void)
{
    ncrawl_lock();
    int c = g_ncrawl.census_count;
    zcl_mutex_unlock(&g_ncrawl.lock);
    return c;
}

bool network_crawler_test_census_row(const char *addr,
                                     struct ncrawl_probe_result *out)
{
    if (!addr || !out)
        return false;
    memset(out, 0, sizeof(*out));   /* defined even when the row is absent */
    bool found = false;
    ncrawl_lock();
    for (int i = 0; i < g_ncrawl.census_count; i++) {
        if (strcmp(g_ncrawl.census[i].addr, addr) == 0) {
            *out = g_ncrawl.census[i];
            found = true;
            break;
        }
    }
    zcl_mutex_unlock(&g_ncrawl.lock);
    return found;
}

void network_crawler_test_set_onion_limits(int per_round, int concurrent,
                                           int timeout_ms, int budget_ms)
{
    struct network_crawler_config c;
    network_crawler_config_defaults(&c);
    c.onion_max_per_round = per_round;
    c.onion_max_concurrent = concurrent;
    c.onion_timeout_ms = timeout_ms;
    c.onion_round_budget_ms = budget_ms;
    ncrawl_clamp(&c);
    ncrawl_lock();
    g_ncrawl.onion_max_per_round = c.onion_max_per_round;
    g_ncrawl.onion_max_concurrent = c.onion_max_concurrent;
    g_ncrawl.onion_timeout_ms = c.onion_timeout_ms;
    g_ncrawl.onion_round_budget_ms = c.onion_round_budget_ms;
    zcl_mutex_unlock(&g_ncrawl.lock);
}
#endif
