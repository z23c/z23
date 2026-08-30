/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_monitor service — see services/network_monitor.h. A supervised
 * sampler thread enumerates connected peers on a cadence, records per-peer
 * chain intelligence (retained in peer_chain_observations), and folds the
 * latest sample into a consensus view (modal tip, max height, fork clusters,
 * our delta). Observational only — never touches chain selection. Adds no
 * P2P messages: peer heights arrive on the existing handshake path, and
 * per-peer tip hashes arrive via the existing accepted-headers callback
 * (network_monitor_note_peer_header, fed from config/src/boot_msg_callbacks.c).
 */

// one-result-type-ok:network-monitor-query-accessors — the fallible service
// surface (network_monitor_start) returns struct zcl_result; the remaining
// bool exports (network_monitor_get_view + test helpers) are pure readiness
// predicates, not fallible operations.

#include "base/hex.h"
#include "platform/socket_compat.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"

#include "models/peer_chain_observation.h"
#include "models/database.h"

#include "net/connman.h"
#include "net/net.h"
#include "net/netaddr.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include "storage/peers_projection.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/thread_registry.h"
#include "supervisors/domains.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NM_SUPERVISOR_DEADLINE_SEC 180

/* A bounded per-peer latest (height, tip hash) learned from accepted headers. */
struct nm_header_vote {
    bool set;
    uint32_t peer_id;
    int height;
    char hash_hex[PEER_OBS_TIP_HEX + 1];
};

static struct {
    zcl_mutex_t lock;
    bool started;

    struct node_db *db;
    int sample_interval_secs;
    int retain_rows;

    /* header-vote map (bounded) */
    struct nm_header_vote votes[NM_MAX_HEADER_VOTES];

    /* latest folded view */
    struct network_consensus_view view;

    /* Edge-trigger for the durable fork ledger: the last fork observation we
     * banked, so a sustained fork emits ONE EV_NET_FORK_OBSERVED, not one per
     * 30s sample. Reset (height=-1) when the fork clears. */
    int64_t last_fork_height;
    char last_fork_hash_a[PEER_OBS_TIP_HEX + 1];
    char last_fork_hash_b[PEER_OBS_TIP_HEX + 1];

    /* sampler thread + supervision */
    pthread_t thread;
    _Atomic bool stop_requested;
    bool thread_running;
    _Atomic int64_t loop_ticks;
    _Atomic supervisor_child_id supervisor_id;
} g_nm = {
    .last_fork_height = -1,
};

static pthread_once_t g_nm_lock_once = PTHREAD_ONCE_INIT;

static void nm_lock_init_once(void)
{
    zcl_mutex_init(&g_nm.lock);
}

static void nm_lock(void)
{
    /* Process-lifetime lock, initialized exactly once as the native
     * zcl_mutex_t for this host (CRITICAL_SECTION on Win32, recursive pthread
     * mutex on POSIX). Every public and worker acquisition uses this gate. */
    if (pthread_once(&g_nm_lock_once, nm_lock_init_once) != 0) {
        LOG_ERROR("network_monitor",
                  "network monitor lock one-time initialization failed");
        abort();
    }
    zcl_mutex_lock(&g_nm.lock);
}

static struct liveness_contract g_nm_contract;

void network_monitor_config_defaults(struct network_monitor_config *cfg)
{
    if (!cfg)
        return;
    cfg->sample_interval_secs = 30;
    cfg->retain_rows = 10000;
}

static void nm_config_from_env(struct network_monitor_config *cfg)
{
    const char *iv = getenv("ZCL_NETMON_INTERVAL_SECS");
    if (iv && iv[0]) {
        int v = atoi(iv);
        if (v >= 1 && v <= 3600)
            cfg->sample_interval_secs = v;
    }
    const char *rr = getenv("ZCL_NETMON_RETAIN_ROWS");
    if (rr && rr[0]) {
        int v = atoi(rr);
        if (v >= 100 && v <= 10000000)
            cfg->retain_rows = v;
    }
}

/* ── header-vote map ─────────────────────────────────────────────────── */

void network_monitor_note_peer_header(uint32_t peer_id, int height,
                                      const char hash_hex[65])
{
    if (!hash_hex || height < 0)
        return;
    nm_lock();
    int free_slot = -1;
    int match = -1;
    for (int i = 0; i < NM_MAX_HEADER_VOTES; i++) {
        if (g_nm.votes[i].set && g_nm.votes[i].peer_id == peer_id) {
            match = i;
            break;
        }
        if (!g_nm.votes[i].set && free_slot < 0)
            free_slot = i;
    }
    int slot = match >= 0 ? match
             : free_slot >= 0 ? free_slot
             : (int)(peer_id % NM_MAX_HEADER_VOTES); /* bounded eviction */
    g_nm.votes[slot].set = true;
    g_nm.votes[slot].peer_id = peer_id;
    g_nm.votes[slot].height = height;
    snprintf(g_nm.votes[slot].hash_hex, sizeof(g_nm.votes[slot].hash_hex),
             "%s", hash_hex);
    zcl_mutex_unlock(&g_nm.lock);
}

/* Look up a peer's latest header vote. Caller holds g_nm.lock. */
static const struct nm_header_vote *nm_find_vote_locked(uint32_t peer_id)
{
    for (int i = 0; i < NM_MAX_HEADER_VOTES; i++) {
        if (g_nm.votes[i].set && g_nm.votes[i].peer_id == peer_id)
            return &g_nm.votes[i];
    }
    return NULL;
}

/* ── pure consensus fold ─────────────────────────────────────────────── */

void network_monitor_compute_view(const struct db_peer_chain_observation *obs,
                                  int n, int64_t our_height, int64_t now_unix,
                                  struct network_consensus_view *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->ready = true;
    out->computed_at = now_unix;
    out->our_height = our_height;
    out->modal_height = -1;
    out->max_height = -1;
    out->fork_height = -1;
    if (!obs || n <= 0)
        return;
    if (n > NM_MAX_PEERS)
        n = NM_MAX_PEERS;
    out->num_peers = n;

    /* modal + max advertised height */
    int64_t best_modal = -1;
    int best_modal_count = 0;
    for (int i = 0; i < n; i++) {
        if (obs[i].best_height < 0)
            continue;
        out->peers_with_height++;
        if (obs[i].best_height > out->max_height)
            out->max_height = obs[i].best_height;
        int c = 0;
        for (int j = 0; j < n; j++)
            if (obs[j].best_height == obs[i].best_height)
                c++;
        if (c > best_modal_count ||
            (c == best_modal_count && obs[i].best_height > best_modal)) {
            best_modal_count = c;
            best_modal = obs[i].best_height;
        }
    }
    out->modal_height = best_modal;
    out->modal_height_count = best_modal_count;
    if (our_height >= 0 && out->max_height >= 0)
        out->delta = out->max_height - our_height;

    /* (height, tip_hash) clusters over peers with a known tip hash */
    for (int i = 0; i < n; i++) {
        if (obs[i].best_height < 0 || obs[i].tip_hash[0] == '\0')
            continue;
        int found = -1;
        for (int k = 0; k < out->num_clusters; k++) {
            if (out->clusters[k].height == obs[i].best_height &&
                strcmp(out->clusters[k].tip_hash, obs[i].tip_hash) == 0) {
                found = k;
                break;
            }
        }
        if (found >= 0) {
            out->clusters[found].peer_count++;
        } else if (out->num_clusters < NM_MAX_FORK_CLUSTERS) {
            struct network_fork_cluster *fc = &out->clusters[out->num_clusters++];
            fc->height = obs[i].best_height;
            snprintf(fc->tip_hash, sizeof(fc->tip_hash), "%s", obs[i].tip_hash);
            fc->peer_count = 1;
        }
    }

    /* fork = two clusters at the SAME height with DIFFERENT hashes, each with
     * at least NM_FORK_MIN_CLUSTER peers. Report the pair with the largest
     * combined support. */
    int best_combined = -1;
    for (int a = 0; a < out->num_clusters; a++) {
        if (out->clusters[a].peer_count < NM_FORK_MIN_CLUSTER)
            continue;
        for (int b = a + 1; b < out->num_clusters; b++) {
            if (out->clusters[b].peer_count < NM_FORK_MIN_CLUSTER)
                continue;
            if (out->clusters[a].height != out->clusters[b].height)
                continue;
            if (strcmp(out->clusters[a].tip_hash, out->clusters[b].tip_hash) == 0)
                continue;
            int combined = out->clusters[a].peer_count +
                           out->clusters[b].peer_count;
            if (combined > best_combined) {
                best_combined = combined;
                out->fork_detected = true;
                out->fork_height = out->clusters[a].height;
                out->fork_count_a = out->clusters[a].peer_count;
                out->fork_count_b = out->clusters[b].peer_count;
                snprintf(out->fork_hash_a, sizeof(out->fork_hash_a), "%s",
                         out->clusters[a].tip_hash);
                snprintf(out->fork_hash_b, sizeof(out->fork_hash_b), "%s",
                         out->clusters[b].tip_hash);
            }
        }
    }
}

/* ── sampling ────────────────────────────────────────────────────────── */

/* Hex-encode a peer's address group (net_addr_get_group) into `out`. Onion
 * and clearnet peers produce distinct group keys by construction — that is
 * the property the netsplit fold leans on. Falls back to the empty string
 * (the fold then keys on the addr string) when the group is unavailable. */
static void nm_group_key_of(const struct p2p_node *node, nm_group_key_t out)
{
    out[0] = '\0';
    if (!node)
        return;
    unsigned char g[NET_ADDR_GROUP_MAX];
    size_t len = net_addr_get_group(&node->addr.svc.addr, g, sizeof(g));
    if (len == 0 || len > sizeof(g))
        return;
    zcl_hex_encode(g, len, out);
}

/* Snapshot current peers into obs[] (bounded), with each peer's address-group
 * key in the parallel groups[] (may be NULL). Returns the count. */
static int nm_snapshot_peers(struct db_peer_chain_observation *obs,
                             nm_group_key_t *groups, int max,
                             int64_t now_unix)
{
    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return 0;

    int count = 0;
    nm_lock();
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes && count < max; i++) {
        struct p2p_node *node = cm->manager.nodes[i];
        if (!node || node->disconnect)
            continue;
        if (node->state < PEER_HANDSHAKE_COMPLETE)
            continue;

        struct db_peer_chain_observation *o = &obs[count];
        memset(o, 0, sizeof(*o));
        o->peer_id = (int64_t)node->id;
        snprintf(o->addr, sizeof(o->addr), "%.127s", node->addr_name);
        snprintf(o->user_agent, sizeof(o->user_agent), "%.95s",
                 node->clean_sub_ver);
        o->version = node->version;
        o->best_height = node->starting_height;
        o->latency_us = node->avg_latency_us;
        o->inbound = node->inbound ? 1 : 0;
        o->first_seen = node->time_connected;
        o->last_seen = node->last_recv;
        o->observed_at = now_unix;
        o->tip_hash[0] = '\0';

        /* Fold in the latest accepted-header vote for a more current height +
         * a learnable tip hash (existing message path, no new wire message). */
        const struct nm_header_vote *v = nm_find_vote_locked((uint32_t)node->id);
        if (v) {
            if ((int64_t)v->height > o->best_height)
                o->best_height = v->height;
            snprintf(o->tip_hash, sizeof(o->tip_hash), "%s", v->hash_hex);
        }
        if (groups)
            nm_group_key_of(node, groups[count]);
        count++;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    zcl_mutex_unlock(&g_nm.lock);
    return count;
}

static int64_t nm_our_height(void)
{
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return -1; // raw-return-ok:sentinel-height-unknown
    return (int64_t)active_chain_height(&ms->chain_active);
}

/* Our active-chain tip hash + header timestamp. Returns false when the chain
 * is not available (the partition fold then reports nothing). */
static bool nm_our_tip(char out_hash[PEER_OBS_TIP_HEX + 1], int64_t *out_time)
{
    out_hash[0] = '\0';
    if (out_time)
        *out_time = -1;
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return false;
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (!tip || !tip->phashBlock)
        return false;
    char hex[65];
    uint256_get_hex(tip->phashBlock, hex);
    snprintf(out_hash, PEER_OBS_TIP_HEX + 1, "%s", hex);
    if (out_time)
        *out_time = (int64_t)tip->nTime;
    return true;
}

/* Fill the arrival window (OLDEST FIRST) from the active chain, and report
 * the consensus target spacing at the tip. Returns the number of samples. */
static int nm_arrival_window(struct nm_arrival_sample *win, int max,
                             int64_t *out_target_spacing_secs)
{
    if (out_target_spacing_secs)
        *out_target_spacing_secs = 0;
    struct main_state *ms = sync_monitor_main_state();
    const struct chain_params *cp = chain_params_get();
    if (!ms || !cp || !win || max <= 0)
        return 0;
    int tip_h = active_chain_height(&ms->chain_active);
    if (tip_h < max)
        return 0;
    *out_target_spacing_secs =
        consensus_pow_target_spacing(&cp->consensus, tip_h);

    int count = 0;
    for (int h = tip_h - max + 1; h <= tip_h; h++) {
        struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (!bi)
            return 0; /* a reorg moved under us — judge nothing this round */
        win[count].height = (int64_t)bi->nHeight;
        win[count].time_unix = (int64_t)bi->nTime;
        win[count].nbits = bi->nBits;
        count++;
    }
    return count;
}

/* One full sample: snapshot peers, persist (best-effort), fold the view. */
static void nm_sample_once(void)
{
    static struct db_peer_chain_observation obs[NM_MAX_PEERS]; /* thread-owned */
    static nm_group_key_t groups[NM_MAX_PEERS];                /* thread-owned */
    int64_t now = platform_time_wall_unix();
    memset(groups, 0, sizeof(groups));
    int n = nm_snapshot_peers(obs, groups, NM_MAX_PEERS, now);
    int64_t our_h = nm_our_height();

    /* Persist history (best-effort — a busy DB never blocks detection, which
     * runs off the folded RAM view below). */
    struct node_db *db = g_nm.db;
    if (db && db->open) {
        for (int i = 0; i < n; i++) {
            if (!db_peer_chain_observation_save(db, &obs[i]))
                LOG_WARN("network_monitor",
                         "observation save failed peer=%lld",
                         (long long)obs[i].peer_id);
        }
        if (n > 0 && !db_peer_chain_observation_prune(db, g_nm.retain_rows))
            LOG_WARN("network_monitor", "retention prune failed");
    }

    struct network_consensus_view v;
    network_monitor_compute_view(obs, n, our_h, now, &v);

    /* Partition (netsplit) fold — three signals, then the composite verdict.
     * Observational: nothing below changes chain selection. */
    struct network_partition_view pv;
    memset(&pv, 0, sizeof(pv));
    char our_tip[PEER_OBS_TIP_HEX + 1];
    int64_t tip_time = -1;
    bool have_tip = nm_our_tip(our_tip, &tip_time);
    network_monitor_fold_tip_disagreement(obs, n, groups, our_h,
                                          have_tip ? our_tip : NULL, &pv);

    static struct nm_arrival_sample win[NM_ARRIVAL_MAX_WINDOW_BLOCKS];
    int64_t spacing = 0;
    int win_n = nm_arrival_window(win, NM_ARRIVAL_MAX_WINDOW_BLOCKS, &spacing);
    network_monitor_fold_arrival_rate(win, win_n, spacing, &pv.arrival);

    network_monitor_partition_verdict(tip_time >= 0 ? now - tip_time : -1,
                                      now, &pv);

    /* Edge-triggered durable fork ledger: bank a NEW fork observation once
     * (height or either cluster hash changed since the last banked one), and
     * re-arm when the fork clears. Fail-open — no event log wired ⇒ no-op. */
    network_monitor_netsplit_publish(&pv);

    bool emit_fork = false;
    nm_lock();
    g_nm.view = v;
    if (v.fork_detected) {
        if (v.fork_height != g_nm.last_fork_height ||
            strcmp(v.fork_hash_a, g_nm.last_fork_hash_a) != 0 ||
            strcmp(v.fork_hash_b, g_nm.last_fork_hash_b) != 0) {
            emit_fork = true;
            g_nm.last_fork_height = v.fork_height;
            snprintf(g_nm.last_fork_hash_a, sizeof(g_nm.last_fork_hash_a),
                     "%s", v.fork_hash_a);
            snprintf(g_nm.last_fork_hash_b, sizeof(g_nm.last_fork_hash_b),
                     "%s", v.fork_hash_b);
        }
    } else {
        g_nm.last_fork_height = -1;
        g_nm.last_fork_hash_a[0] = '\0';
        g_nm.last_fork_hash_b[0] = '\0';
    }
    zcl_mutex_unlock(&g_nm.lock);

    if (emit_fork)
        (void)peers_projection_emit_fork_observed(
            v.fork_height, now, (uint32_t)v.num_clusters,
            (uint32_t)v.fork_count_a, (uint32_t)v.fork_count_b,
            v.fork_hash_a, v.fork_hash_b);
}

bool network_monitor_get_view(struct network_consensus_view *out)
{
    if (!out)
        return false;
    nm_lock();
    bool ready = g_nm.view.ready;
    if (ready)
        *out = g_nm.view;
    zcl_mutex_unlock(&g_nm.lock);
    return ready;
}


static void nm_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_nm.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_nm.loop_ticks));
}

static void nm_on_stall(struct liveness_contract *c)
{
    (void)c;
    LOG_WARN("network_monitor",
             "sampler heartbeat lapsed (ticks=%lld) — sampler may be wedged",
             (long long)atomic_load(&g_nm.loop_ticks));
}

static void *nm_thread_fn(void *arg)
{
    (void)arg;
    int64_t next_sample_at = 0; /* sample immediately on first wake */
    while (!atomic_load(&g_nm.stop_requested)) {
        atomic_fetch_add(&g_nm.loop_ticks, 1);
        nm_supervisor_heartbeat();

        int64_t now = platform_time_wall_unix();
        if (now >= next_sample_at) {
            nm_sample_once();
            next_sample_at = now + g_nm.sample_interval_secs;
        }
        /* 200ms increments so stop() stays responsive between samples. */
        platform_sleep_ms(200);
    }
    return NULL;
}

static struct zcl_result nm_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-5, "network_monitor: supervisor_start failed");

    liveness_contract_init(&g_nm_contract, "net.network_monitor");
    atomic_store(&g_nm_contract.period_secs, 0); /* self-heartbeats */
    atomic_store(&g_nm_contract.deadline_secs, NM_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_nm_contract.progress_max_quiet_us, 0);
    g_nm_contract.on_stall = nm_on_stall;

    supervisor_domains_init();
    supervisor_child_id id = supervisor_register_in_domain(g_net_sup,
                                                           &g_nm_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-6, "network_monitor: supervisor_register failed");
    atomic_store(&g_nm.supervisor_id, id);
    return ZCL_OK;
}

struct zcl_result network_monitor_start(const struct network_monitor_config *cfg,
                                        struct node_db *db)
{
    if (g_nm.started)
        return ZCL_OK;

    struct network_monitor_config local;
    network_monitor_config_defaults(&local);
    if (cfg)
        local = *cfg;
    nm_config_from_env(&local);

    g_nm.db = db;
    g_nm.sample_interval_secs = local.sample_interval_secs;
    g_nm.retain_rows = local.retain_rows;
    atomic_store(&g_nm.stop_requested, false);
    atomic_store(&g_nm.loop_ticks, 0);
    atomic_store(&g_nm.supervisor_id, SUPERVISOR_INVALID_ID);
    memset(&g_nm.view, 0, sizeof(g_nm.view));

    g_nm.thread_running = true;
    int rc = thread_registry_spawn("zcl_network_monitor", nm_thread_fn, NULL,
                                   &g_nm.thread);
    if (rc != 0) {
        g_nm.thread_running = false;
        return ZCL_ERR(-4, "network_monitor: thread_registry_spawn failed (%d)",
                       rc);
    }

    struct zcl_result sup = nm_register_supervisor();
    if (!sup.ok) {
        /* The sampler still runs; supervision is a liveness contract, not a
         * hard dependency. Name the gap loudly and continue. */
        LOG_WARN("network_monitor", "supervisor registration failed: %s",
                 sup.message);
    }

    g_nm.started = true;
    return ZCL_OK;
}

void network_monitor_stop(void)
{
    if (!g_nm.started)
        return;
    atomic_store(&g_nm.stop_requested, true);
    atomic_store(&g_nm_contract.deadline_secs, 0); /* silence stall on shutdown */
    if (g_nm.thread_running) {
        pthread_join(g_nm.thread, NULL);
        g_nm.thread_running = false;
    }
    g_nm.started = false;
}

/* ── introspection ───────────────────────────────────────────────────── */

bool network_monitor_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct network_consensus_view v;
    bool ready = network_monitor_get_view(&v);
    json_push_kv_bool(out, "ready", ready);
    json_push_kv_bool(out, "started", g_nm.started);
    json_push_kv_int(out, "sample_interval_secs", g_nm.sample_interval_secs);
    json_push_kv_int(out, "retain_rows", g_nm.retain_rows);
    json_push_kv_int(out, "loop_ticks", atomic_load(&g_nm.loop_ticks));

    int retained = g_nm.db ? db_peer_chain_observation_count(g_nm.db) : 0;
    json_push_kv_int(out, "retained_rows", retained);

    if (!ready) {
        diag_push_health(out, true, "no sample yet");
        return true;
    }

    json_push_kv_int(out, "computed_at", v.computed_at);
    json_push_kv_int(out, "num_peers", v.num_peers);
    json_push_kv_int(out, "peers_with_height", v.peers_with_height);
    json_push_kv_int(out, "modal_height", v.modal_height);
    json_push_kv_int(out, "modal_height_count", v.modal_height_count);
    json_push_kv_int(out, "max_height", v.max_height);
    json_push_kv_int(out, "our_height", v.our_height);
    json_push_kv_int(out, "delta_behind_best", v.delta);
    json_push_kv_bool(out, "fork_detected", v.fork_detected);
    json_push_kv_int(out, "fork_height", v.fork_height);
    if (v.fork_detected) {
        json_push_kv_str(out, "fork_hash_a", v.fork_hash_a);
        json_push_kv_str(out, "fork_hash_b", v.fork_hash_b);
        json_push_kv_int(out, "fork_count_a", v.fork_count_a);
        json_push_kv_int(out, "fork_count_b", v.fork_count_b);
    }

    struct json_value clusters;
    json_init(&clusters);
    json_set_array(&clusters);
    for (int i = 0; i < v.num_clusters; i++) {
        struct json_value c;
        json_init(&c);
        json_set_object(&c);
        json_push_kv_int(&c, "height", v.clusters[i].height);
        json_push_kv_str(&c, "tip_hash", v.clusters[i].tip_hash);
        json_push_kv_int(&c, "peer_count", v.clusters[i].peer_count);
        (void)json_push_back(&clusters, &c);
        json_free(&c);
    }
    (void)json_push_kv(out, "tip_clusters", &clusters);
    json_free(&clusters);

    char reason[128];
    bool healthy = !v.fork_detected;
    if (v.fork_detected)
        snprintf(reason, sizeof(reason),
                 "fork: %d vs %d peers disagree at height %lld",
                 v.fork_count_a, v.fork_count_b, (long long)v.fork_height);
    else
        snprintf(reason, sizeof(reason), "delta_behind_best=%lld",
                 (long long)v.delta);
    diag_push_health(out, healthy, reason);
    return true;
}

#ifdef ZCL_TESTING

void network_monitor_test_set_view(const struct network_consensus_view *v)
{
    if (!v)
        return;
    nm_lock();
    g_nm.view = *v;
    g_nm.view.ready = true;
    zcl_mutex_unlock(&g_nm.lock);
}
#endif
