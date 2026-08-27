// one-result-type-ok:absence-of-a-sample-is-a-result-not-an-error — the one
// bool export here is mesh_observation_snapshot(), whose false means "no
// observation has been taken yet". R4 makes that a REPORTABLE state
// (UNVERIFIED), not a failure, and a zcl_result would dress an answer up
// as an error.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mesh_observation_sample.c — the in-node SAMPLER.
 *
 * Once every MESH_OBS_SAMPLE_INTERVAL_SECS it snapshots what THIS node
 * observed and publishes it into one fixed static record. It emits no
 * verdict, grades nothing, and gates nothing.
 *
 * OBSERVER DISCIPLINE (lock-order law)
 * -----------------------------------
 * This is an OBSERVER path, so it obeys the observer rules exactly:
 *   * it takes connman's cs_nodes with zcl_mutex_trylock ONLY, never a
 *     blocking lock, and never csr->lock;
 *   * losing that trylock is EXPECTED on a contended box. It is not an
 *     error and it is not a failure: the record sets lock_contended, keeps
 *     the PREVIOUS tick's edge rows with their own stamps, and increments
 *     rows_unreadable. It never publishes a zero in place of an unread
 *     value, because a zero would read as a measurement;
 *   * nothing that could block is done while cs_nodes is held. Peer rows
 *     are copied out raw under the trylock and every chain lookup happens
 *     after the unlock.
 *
 * COST
 * ----
 * Atomics, one trylock, five in-memory active_chain_at() pointer walks and
 * one chainwork hex render. Zero DB reads, zero fsyncs, zero allocation,
 * O(peers <= 32). At ~120 random IOPS a weak box has ~18 000 random IOs per
 * block slot and chain validation is the mandatory consumer; this sampler's
 * share of that budget is zero. What it did cost is published in
 * sample_elapsed_us, so the claim is checkable rather than asserted.
 */

#include "services/mesh_observation.h"

#include "base/compiler.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "event/event.h"
#include "net/connman.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/onion_stream.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "services/network_monitor.h"
#include "services/quorum_oracle_service.h"
#include "services/sync_monitor.h"
#include "jobs/reducer_frontier.h"
#include "supervisors/domains.h"
#include "util/clientversion.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>

/* Cadence, not a threshold: nothing anywhere grades a node for missing a
 * tick. Ten seconds keeps the record fresher than any reader's default
 * 900 s window by two orders of magnitude, on the slowest box we have. */
#define MESH_OBS_SAMPLE_INTERVAL_SECS 10
#define MESH_OBS_SUPERVISOR_DEADLINE_SEC 120
/* 30 sample intervals, in microseconds. Supervision timing only — it never
 * reaches a published observation, and no reader's conclusion moves if it
 * changes. */
#define MESH_OBS_PROGRESS_QUIET_US \
    ((int64_t)MESH_OBS_SAMPLE_INTERVAL_SECS * 30 * 1000 * 1000)

/* The handshake BUDGET, published beside every elapsed time it bounds so a
 * reader that thinks 120 s is wrong for a spinning-disk box re-derives from
 * elapsed_us without re-measuring anything. Exceeding it produces
 * DEADLINE_EXPIRED and nothing else — never REFUSED, and never a tally of
 * failures, because a budget is mine and the slowness is the network's. */
#define MESH_OBS_HANDSHAKE_DEADLINE_US ((int64_t)120 * 1000 * 1000)

/* ── Tor build fact ─────────────────────────────────────────────────
 * The weak reference resolves NULL against libtor_stub.a and non-NULL
 * against the real libtor.a. shop_native_probes.c and
 * network_telemetry_fill.c already read this same link-time fact the same
 * way; re-declaring the weak reference reads an existing fact rather than
 * inventing one. Without it a stub build would report "no onion" in exactly
 * the shape a real build reports "the onion is down". */
extern int dynhost_client_fetch(const char *, uint16_t, const char *,
    void (*)(int, const uint8_t *, size_t, void *), void *, int)
    ZCL_WEAK_IMPORT;

/* ── published state ────────────────────────────────────────────────── */

static struct {
    zcl_mutex_t lock;          /* LEAF: nothing is taken while it is held */
    bool        lock_ready;
    bool        have_sample;
    struct mesh_observation rec;

    _Atomic bool stop_requested;
    _Atomic long long loop_ticks;
    /* The PROGRESS marker, and it is deliberately not loop_ticks. A loop
     * that wakes every 200ms and reads nothing would advance loop_ticks
     * forever while achieving nothing — the exact "counted activity, not
     * results" shape supervisor.h was written to catch. This counter moves
     * only when a sample actually READ the live peer table. */
    _Atomic long long samples_with_peer_table;
    _Atomic int supervisor_id;
    bool        thread_running;
    pthread_t   thread;
    bool        started;
} g_mo;

static pthread_once_t g_mo_once = PTHREAD_ONCE_INIT;
static struct liveness_contract g_mo_contract;

static void mo_lock_init(void)
{
    zcl_mutex_init(&g_mo.lock);
    g_mo.lock_ready = true;
}

static void mo_ensure_lock(void)
{
    pthread_once(&g_mo_once, mo_lock_init);
}

/* ── raw peer row, copied out under the trylock ─────────────────────── */

struct mo_raw_peer {
    struct net_service svc;
    bool     svc_valid;
    bool     inbound;
    int      state;
    uint32_t peer_id;
    int64_t  connected_monotonic_us;
    int64_t  last_activity_monotonic_us;
    int64_t  last_send_wall;
    int64_t  last_recv_wall;
    int64_t  min_ping_usec_time;
    uint64_t total_headers_delivered;
};

static enum mesh_obs_stage mo_stage_of_peer(int state)
{
    switch (state) {
    case PEER_DISCONNECTED:       return MESH_STAGE_NONE;
    case PEER_CONNECTING:
    case PEER_CONNECTED:          return MESH_STAGE_DIALED;
    case PEER_VERSION_SENT:       return MESH_STAGE_VERSION_SENT;
    case PEER_VERSION_RECEIVED:   return MESH_STAGE_VERSION_RECVD;
    case PEER_HANDSHAKE_COMPLETE: return MESH_STAGE_HANDSHAKE_COMPLETE;
    case PEER_ACTIVE:
    case PEER_SYNCING_HEADERS:
    case PEER_SYNCING_BLOCKS:
    case PEER_SNAPSHOT_SERVING:
    case PEER_SNAPSHOT_RECEIVING: return MESH_STAGE_SERVING;
    /* A stale / closing / banned peer still CONFIRMED a handshake at some
     * point; the field means "the furthest stage actually confirmed", so
     * that is what it keeps saying. */
    case PEER_STALE:
    case PEER_DISCONNECTING:
    case PEER_BANNED:             return MESH_STAGE_HANDSHAKE_COMPLETE;
    default:                      return MESH_STAGE_NONE;
    }
}

/* Copy the live peer table out under ONE trylock.
 *
 * Returns the row count (0 is a real answer: "the table was readable and
 * held no peers"), or one of two NEGATIVE coverage facts that are never
 * peer verdicts and never a row count:
 *
 *   MO_PEERS_CONTENDED  the trylock was not taken this tick.
 *   MO_PEERS_NO_CONNMAN there is no peer table to read at all.
 *
 * They are distinct on purpose. Collapsing "no connman" into 0 would let a
 * node that never wired its network publish an edge-free document that is
 * byte-identical to a healthy node with no peers yet. */
#define MO_PEERS_CONTENDED   (-1)
#define MO_PEERS_NO_CONNMAN  (-2)

static int mo_copy_peers(struct mo_raw_peer *rows, int max, int *truncated)
{
    *truncated = 0;
    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return MO_PEERS_NO_CONNMAN;   // raw-return-ok:no-peer-table-is-coverage-not-an-error
    if (!zcl_mutex_trylock(&cm->manager.cs_nodes))
        return -1;   // raw-return-ok:trylock-contention-is-coverage-not-an-error

    int count = 0;
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!n)
            continue;
        if (count >= max) {
            (*truncated)++;
            continue;
        }
        struct mo_raw_peer *r = &rows[count];
        memset(r, 0, sizeof(*r));
        if (n->advertised_service_valid) {
            r->svc = n->advertised_service;
            r->svc_valid = true;
        } else {
            r->svc = n->addr.svc;
            r->svc_valid = true;
        }
        r->inbound  = n->inbound;
        r->state    = (int)atomic_load(&n->state);
        r->peer_id  = (uint32_t)n->id;
        r->connected_monotonic_us =
            atomic_load(&n->connected_monotonic_us);
        r->last_activity_monotonic_us =
            atomic_load(&n->last_activity_monotonic_us);
        r->last_send_wall = n->last_send;
        r->last_recv_wall = n->last_recv;
        r->min_ping_usec_time = n->min_ping_usec_time;
        r->total_headers_delivered = n->total_headers_delivered;
        count++;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return count;
}

/* ── self: chain position ───────────────────────────────────────────── */

static void mo_fill_chain(struct mesh_obs_self *s)
{
    /* Exactly the access network_monitor.c already performs from its own
     * sampler thread: read the active chain's cached tip and walk back to
     * five fixed rungs. No lock is taken and no DB is touched. */
    struct main_state *ms = sync_monitor_main_state();
    if (!ms) {
        snprintf(s->unavailable_reason, sizeof(s->unavailable_reason), "%s",
                 "chain_state_absent");
        return;
    }
    struct block_index *tip = active_chain_cached_tip(&ms->chain_active);
    if (!tip || !tip->phashBlock) {
        snprintf(s->unavailable_reason, sizeof(s->unavailable_reason), "%s",
                 "chain_tip_absent");
        return;
    }
    s->tip_height    = (int64_t)tip->nHeight;
    s->tip_time_unix = (int64_t)tip->nTime;
    uint256_get_hex(tip->phashBlock, s->tip_hash_hex);
    arith_uint256_get_hex(&tip->nChainWork, s->tip_chainwork_hex);

    for (int i = 0; i < MESH_OBS_ANCHORS; i++) {
        int64_t h = s->tip_height - (int64_t)MESH_OBS_ANCHOR_BACK[i];
        s->anchors[i].present = false;
        s->anchors[i].height = 0;
        s->anchors[i].hash_hex[0] = '\0';
        if (h < 0)
            continue;
        struct block_index *bi = active_chain_at(&ms->chain_active, (int)h);
        if (!bi || !bi->phashBlock)
            continue;   /* a reorg moved under us: publish nothing for the
                         * rung rather than a stale or invented hash */
        s->anchors[i].height = (int64_t)bi->nHeight;
        uint256_get_hex(bi->phashBlock, s->anchors[i].hash_hex);
        s->anchors[i].present = true;
    }
}

/* Our own hash at a height, for verifying a peer's CLAIM. Returns false
 * when we do not hold that height — which verifies nothing either way. */
static bool mo_our_hash_at(int64_t height, char out[MESH_OBS_HEXHASH])
{
    out[0] = '\0';
    if (height < 0)
        return false;
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return false;
    struct block_index *bi = active_chain_at(&ms->chain_active, (int)height);
    if (!bi || !bi->phashBlock)
        return false;
    uint256_get_hex(bi->phashBlock, out);
    return true;
}

/* ── self: the onion promise ladder (R3) ────────────────────────────── */

static void mo_fill_listen_stage(struct mesh_obs_self *s)
{
    s->tor_requested  = tor_integration_is_requested();
    s->tor_stub_build = (dynhost_client_fetch == NULL);
    s->listen_stage   = MESH_STAGE_NONE;
    if (!s->tor_requested || !tor_integration_is_enabled())
        return;

    /* An announcement is a PROMISE: READY is claimed only once all four
     * confirmations are in, and every partial state has its own name. */
    struct tor_onion_port_map pm;
    memset(&pm, 0, sizeof(pm));
    tor_integration_port_map_snapshot(&pm);
    struct onion_stream_stages st;
    memset(&st, 0, sizeof(st));
    onion_stream_get_stages(&st);

    const char *addr = tor_integration_get_onion_address();
    bool descriptor = addr && addr[0] && tor_integration_is_dial_ready();
    bool rendezvous = tor_integration_is_ready();  /* HSDir upload recorded */
    bool circuit    = st.circuit_ready > 0;
    bool listen     = pm.state == TOR_ONION_PORT_MAP_INSTALLED &&
                      pm.complete && pm.p2p_route_installed;

    if (!descriptor)
        return;
    s->listen_stage = MESH_STAGE_DESCRIPTOR;
    if (!rendezvous)
        return;
    s->listen_stage = MESH_STAGE_RENDEZVOUS;
    if (!circuit)
        return;
    s->listen_stage = MESH_STAGE_CIRCUIT;
    if (!listen)
        return;
    s->listen_stage = MESH_STAGE_LISTEN;
    s->listen_stage = MESH_STAGE_READY;
}

/* ── self: capability, published to be WEIGHTED, never to gate ──────── */

static void mo_fill_capability(struct mesh_obs_self *s)
{
    bool known = false;
    bool rot = hw_profile_datadir_rotational(&known);
    s->cores = hw_profile_online_cores();
    s->ram_bytes = hw_profile_ram_bytes();
    s->rotational_known = known;
    s->rotational = rot;
    /* -1 is published AS -1. On a spinning-disk box the pread probe really
     * does get truncated out of its budget by a 70 ms fsync, and reporting
     * that truncation honestly beats pretending 0. */
    s->fsync_us = hw_bench_fsync_us();
    s->pread_us = hw_bench_pread_us();
    const char *fp = hw_bench_fingerprint_hex();
    snprintf(s->hw_fingerprint, sizeof(s->hw_fingerprint), "%s", fp ? fp : "");
}

/* ── the sample ─────────────────────────────────────────────────────── */

void mesh_observation_sample_once(void)
{
    mo_ensure_lock();

    int64_t mono_start = platform_time_monotonic_us();
    int64_t now_unix = platform_time_wall_unix();

    struct mesh_observation local;
    memset(&local, 0, sizeof(local));
    struct mesh_obs_self *s = &local.self;
    snprintf(s->schema, sizeof(s->schema), "%s", MESH_OBS_SCHEMA);
    const char *addr = tor_integration_get_onion_address();
    snprintf(s->onion, sizeof(s->onion), "%s", addr ? addr : "");
    const char *sid = zcl_build_source_id_sha256();
    snprintf(s->source_id, sizeof(s->source_id), "%s", sid ? sid : "");
    s->fsync_us = -1;
    s->pread_us = -1;

    mo_fill_chain(s);
    mo_fill_listen_stage(s);
    mo_fill_capability(s);

    s->provable_tip = reducer_frontier_provable_tip_cached();
    s->provable_tip_published = reducer_frontier_provable_tip_is_published();
    s->reducer_floor = reducer_frontier_floor();
    if (s->provable_tip < 0)
        s->provable_tip = 0;
    if (s->reducer_floor < 0)
        s->reducer_floor = 0;

    /* Minority-work instrument, reused from the netsplit fold rather than
     * recomputed. window_blocks == 0 means the fold REFUSED TO JUDGE. */
    struct network_partition_view pv;
    memset(&pv, 0, sizeof(pv));
    (void)network_monitor_netsplit_suspected(&pv);
    if (pv.arrival.ready) {
        s->implied_hashrate_ratio_milli =
            pv.arrival.implied_hashrate_ratio_milli;
        s->arrival_window_blocks = pv.arrival.window_blocks;
    }
    if (s->implied_hashrate_ratio_milli < 0)
        s->implied_hashrate_ratio_milli = 0;
    if (s->arrival_window_blocks < 0)
        s->arrival_window_blocks = 0;

    /* Phase A — copy the peer table out under ONE trylock. */
    struct mo_raw_peer rows[MESH_OBS_EDGES_MAX];
    int truncated = 0;
    int nrows = mo_copy_peers(rows, MESH_OBS_EDGES_MAX, &truncated);

    if (nrows < 0) {
        /* Either coverage fact is expected and neither is a peer
         * observation. Carry the previous tick's rows forward unchanged,
         * with their own stamps, and name which one happened. */
        s->lock_contended = (nrows == MO_PEERS_CONTENDED);
        snprintf(s->unavailable_reason, sizeof(s->unavailable_reason), "%s",
                 nrows == MO_PEERS_CONTENDED ? "peer_table_contended"
                                             : "no_peer_table");
        zcl_mutex_lock(&g_mo.lock);
        if (g_mo.have_sample) {
            memcpy(local.edges, g_mo.rec.edges, sizeof(local.edges));
            local.edge_count = g_mo.rec.edge_count;
            local.edges_truncated = g_mo.rec.edges_truncated;
            local.rows_unreadable = g_mo.rec.rows_unreadable + 1;
        } else {
            local.rows_unreadable = 1;
        }
        zcl_mutex_unlock(&g_mo.lock);
        goto publish;
    }

    /* The peer table WAS read this tick — nrows == 0 counts, because "the
     * table was readable and empty" is a result. This is the only place the
     * progress marker moves. */
    atomic_fetch_add(&g_mo.samples_with_peer_table, 1);

    /* Phase B — everything that needs the chain, with no peer lock held. */
    struct qo_peer_vote_view votes[QO_PEER_VOTE_VIEW_MAX];
    int nvotes = quorum_oracle_peer_votes_snapshot(votes,
                                                   QO_PEER_VOTE_VIEW_MAX);
    int64_t mono_now = platform_time_monotonic_us();

    local.edges_truncated = truncated;
    for (int i = 0; i < nrows; i++) {
        const struct mo_raw_peer *r = &rows[i];
        struct mesh_obs_edge *e = &local.edges[i];

        uint8_t key[NET_SERVICE_KEY_SIZE];
        memset(key, 0, sizeof(key));
        net_service_get_key(&r->svc, key);
        /* base/hex.h is the ONE hex codec; a private one here would be a
         * second place for the wire format to drift. */
        zcl_hex_encode(key, sizeof(key), e->peer_key_hex);

        /* Only an onion is ever published. A clearnet peer's IP literal
         * never enters this record. */
        if (r->svc.addr.has_torv3)
            (void)net_addr_to_string(&r->svc.addr, e->peer_onion,
                                     sizeof(e->peer_onion));

        e->inbound = r->inbound;
        e->stage = mo_stage_of_peer(r->state);
        e->deadline_us = MESH_OBS_HANDSHAKE_DEADLINE_US;
        e->connected_age_us = r->connected_monotonic_us > 0
            ? mono_now - r->connected_monotonic_us : 0;
        e->stage_elapsed_us = e->connected_age_us;
        e->last_recv_age_us = r->last_activity_monotonic_us > 0
            ? mono_now - r->last_activity_monotonic_us : -1;
        e->last_send_age_us = (r->last_send_wall > 0 && now_unix > 0)
            ? (now_unix - r->last_send_wall) * 1000000 : -1;
        e->min_ping_us = r->min_ping_usec_time > 0 ? r->min_ping_usec_time : -1;

        /* CONFIRMED requires positive evidence: bytes actually arrived from
         * this peer. A spent budget is DEADLINE_EXPIRED and nothing worse —
         * silence is NEVER refusal. Neither yet, and there is simply no
         * observation to report. */
        if (r->last_activity_monotonic_us > 0)
            e->transport = MESH_OBS_CONFIRMED;
        else if (e->connected_age_us > e->deadline_us)
            e->transport = MESH_OBS_DEADLINE;
        else
            e->transport = MESH_OBS_NOT_PROBED;

        e->claimed_height = -1;
        e->claim_age_us = -1;
        for (int v = 0; v < nvotes; v++) {
            if (votes[v].peer_id != r->peer_id)
                continue;
            e->claimed_height = votes[v].height;
            snprintf(e->claimed_tip_hash_hex, sizeof(e->claimed_tip_hash_hex),
                     "%s", votes[v].hash_hex);
            e->claim_age_us = votes[v].unix_time > 0
                ? (now_unix - votes[v].unix_time) * 1000000 : -1;
            break;
        }

        /* My OWN recomputation of the peer's claim against my OWN chain.
         * A contradicting hash is positive counter-evidence, which is the
         * one thing in this sampler that may report REFUSED. */
        e->header_service = r->total_headers_delivered > 0
            ? MESH_OBS_CONFIRMED : MESH_OBS_NOT_PROBED;
        if (e->claimed_height >= 0 && e->claimed_tip_hash_hex[0]) {
            char ours[MESH_OBS_HEXHASH];
            if (mo_our_hash_at(e->claimed_height, ours)) {
                if (strcasecmp(ours, e->claimed_tip_hash_hex) == 0) {
                    e->claim_verified_locally = true;
                } else {
                    e->header_service = MESH_OBS_REFUSED;
                }
            }
        }
    }
    local.edge_count = nrows;

publish:
    s->sampled_unix = now_unix;
    s->sampled_monotonic_us = mono_start;
    s->sample_elapsed_us = platform_time_monotonic_us() - mono_start;

    zcl_mutex_lock(&g_mo.lock);
    g_mo.rec = local;
    g_mo.have_sample = true;
    zcl_mutex_unlock(&g_mo.lock);
}

bool mesh_observation_snapshot(struct mesh_observation *out)
{
    if (!out)
        return false;
    mo_ensure_lock();
    bool got = false;
    zcl_mutex_lock(&g_mo.lock);
    if (g_mo.have_sample) {
        *out = g_mo.rec;
        got = true;
    }
    zcl_mutex_unlock(&g_mo.lock);
    /* false is the honest answer before the first tick: an unsampled node
     * says "I have nothing", never an empty-but-healthy document. */
    return got;
}

/* ── supervised sampler thread ──────────────────────────────────────── */

static void mo_heartbeat(void)
{
    supervisor_child_id id =
        (supervisor_child_id)atomic_load(&g_mo.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    /* The marker is samples that READ the peer table, never loop ticks.
     * There is deliberately no supervisor_progress_idle() call anywhere in
     * this sampler: a readable-but-empty peer table already advances the
     * marker, so the only states that leave it frozen are contention and a
     * missing peer table — a not-wired path, exactly what the detector is
     * for. Reporting either as idle would re-create the silent stall. */
    supervisor_progress(id,
                        (int64_t)atomic_load(&g_mo.samples_with_peer_table));
}

static void mo_on_stall(struct liveness_contract *c)
{
    (void)c;
    LOG_WARN("mesh_observation",
             "sampler heartbeat lapsed (ticks=%lld) — sampler may be wedged",
             (long long)atomic_load(&g_mo.loop_ticks));
}

static void *mo_thread_fn(void *arg)
{
    (void)arg;
    int64_t next_at = 0;   /* sample immediately on the first wake */
    while (!atomic_load(&g_mo.stop_requested)) {
        atomic_fetch_add(&g_mo.loop_ticks, 1);
        mo_heartbeat();
        int64_t now = platform_time_wall_unix();
        if (now >= next_at) {
            mesh_observation_sample_once();
            next_at = now + MESH_OBS_SAMPLE_INTERVAL_SECS;
        }
        platform_sleep_ms(200);
    }
    return NULL;
}

struct zcl_result mesh_observation_register_sampler(void)
{
    if (g_mo.started)
        return ZCL_OK;
    mo_ensure_lock();
    atomic_store(&g_mo.stop_requested, false);
    atomic_store(&g_mo.loop_ticks, 0);
    atomic_store(&g_mo.samples_with_peer_table, 0);
    atomic_store(&g_mo.supervisor_id, SUPERVISOR_INVALID_ID);

    g_mo.thread_running = true;
    int rc = thread_registry_spawn("zcl_mesh_observation", mo_thread_fn, NULL,
                                   &g_mo.thread);
    if (rc != 0) {
        g_mo.thread_running = false;
        return ZCL_ERR(-4,
                       "mesh_observation: thread_registry_spawn failed (%d)",
                       rc);
    }

    if (supervisor_start()) {
        liveness_contract_init(&g_mo_contract, "net.mesh_observation");
        atomic_store(&g_mo_contract.period_secs, 0); /* self-heartbeats */
        atomic_store(&g_mo_contract.deadline_secs,
                     MESH_OBS_SUPERVISOR_DEADLINE_SEC);
        g_mo_contract.on_stall = mo_on_stall;
        supervisor_domains_init();
        supervisor_child_id id =
            supervisor_register_in_domain(g_net_sup, &g_mo_contract);
        if (id == SUPERVISOR_INVALID_ID) {
            LOG_WARN("mesh_observation", "supervisor registration declined");
        } else {
            atomic_store(&g_mo.supervisor_id, (int)id);
            /* ARMED, not exempt. This sampler has a real unit of work — a
             * sample that read the peer table — so "it ran 13000 times and
             * read nothing" must be visible. The window is 30 sample
             * intervals, wide enough that an 8-core 7200rpm box at 91% IO
             * pressure never trips it for being slow; nothing about the
             * window feeds any observation the surface publishes. */
            supervisor_set_progress_max_quiet(id, MESH_OBS_PROGRESS_QUIET_US);
        }
    } else {
        LOG_WARN("mesh_observation", "supervisor_start declined");
    }

    g_mo.started = true;
    return ZCL_OK;
}

void mesh_observation_unregister_sampler(void)
{
    if (!g_mo.started)
        return;
    atomic_store(&g_mo.stop_requested, true);
    atomic_store(&g_mo_contract.deadline_secs, 0); /* silence on shutdown */
    if (g_mo.thread_running) {
        pthread_join(g_mo.thread, NULL);
        g_mo.thread_running = false;
    }
    g_mo.started = false;
}
