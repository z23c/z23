/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_monitor_netsplit — the SUSPECTED_NETSPLIT signal. See the
 * "Partition (netsplit) detection" block in services/network_monitor.h for
 * the contract and the reasoning; this file is the three pure folds, the
 * standing verdict they publish, and its diagnostics dumper.
 *
 * Its sibling engine/services/src/network_monitor.c owns the sampler thread and
 * feeds this file once per sample via network_monitor_netsplit_publish().
 * Observational only: nothing here changes chain selection.
 */

// one-result-type-ok:netsplit-pure-folds — the pure folds return void (they
// fill a caller-owned view), the standing verdict is a bool predicate, and
// the dumper follows the CLAUDE.md dump convention's mandated bool return.
// There is no fallible operation in this file to carry a struct zcl_result.

#include "services/network_monitor.h"

#include "chain/pow.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
    zcl_mutex_t lock;
    struct network_partition_view view;
} g_ns;

static pthread_once_t g_ns_lock_once = PTHREAD_ONCE_INIT;

static void ns_lock_init_once(void)
{
    zcl_mutex_init(&g_ns.lock);
}

static void ns_lock(void)
{
    /* This process-lifetime lock must be initialized as the host's native
     * zcl_mutex_t (CRITICAL_SECTION on Win32, pthread mutex on POSIX).
     * Route every acquisition through pthread_once so no caller can observe
     * the zero-initialized object before its platform initialization. */
    if (pthread_once(&g_ns_lock_once, ns_lock_init_once) != 0) {
        LOG_ERROR("network_monitor",
                  "netsplit lock one-time initialization failed");
        abort();
    }
    zcl_mutex_lock(&g_ns.lock);
}


/* Bounded per-cluster distinct-address-group ledger. A cluster that draws
 * from more than this many groups is already far past the >= 2 bar, so
 * saturating here can only UNDER-count, never over-count. */
enum { NM_MAX_CLUSTER_GROUPS = 16 };

struct nm_tip_cluster {
    char          hash[PEER_OBS_TIP_HEX + 1];
    int           peers;
    int           groups;
    nm_group_key_t group[NM_MAX_CLUSTER_GROUPS];
};

static bool nm_hash_hex_valid(const char *h)
{
    if (!h || strlen(h) != PEER_OBS_TIP_HEX)
        return false;
    for (int i = 0; i < PEER_OBS_TIP_HEX; i++) {
        char c = h[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

/* Canonicalise a validated 64-hex hash to lowercase. Tip hashes reach this
 * fold from two sources (our own uint256_get_hex and per-peer header votes);
 * normalising once means every comparison below is an exact strcmp and a
 * case difference can never be mistaken for a chain disagreement. */
static void nm_hash_norm(char dst[PEER_OBS_TIP_HEX + 1], const char *src)
{
    for (int i = 0; i < PEER_OBS_TIP_HEX; i++) {
        char c = src[i];
        dst[i] = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
    }
    dst[PEER_OBS_TIP_HEX] = '\0';
}

/* Add `key` to a cluster's distinct-group ledger. Idempotent per key. */
static void nm_cluster_add_group(struct nm_tip_cluster *c, const char *key)
{
    if (!c || !key || key[0] == '\0')
        return;
    for (int i = 0; i < c->groups; i++)
        if (strcmp(c->group[i], key) == 0)
            return;
    if (c->groups >= NM_MAX_CLUSTER_GROUPS)
        return; /* saturate: under-counts, never over-counts */
    snprintf(c->group[c->groups], sizeof(c->group[c->groups]), "%s", key);
    c->groups++;
}

void network_monitor_fold_tip_disagreement(
    const struct db_peer_chain_observation *obs, int n,
    const nm_group_key_t *group_keys,
    int64_t our_height, const char *our_tip_hash,
    struct network_partition_view *out)
{
    if (!out)
        return;
    out->peer_tip_disagreement = false;
    out->at_height = -1;
    out->our_tip_hash[0] = '\0';
    out->rival_tip_hash[0] = '\0';
    out->rival_peers = 0;
    out->rival_groups = 0;
    out->agreeing_peers = 0;
    out->agreeing_groups = 0;
    out->peers_considered = 0;
    out->peers_ahead = 0;

    /* No usable tip of our own ⇒ nothing to disagree WITH. Report nothing
     * rather than guessing. */
    if (our_height < 0 || !nm_hash_hex_valid(our_tip_hash))
        return;
    out->at_height = our_height;
    nm_hash_norm(out->our_tip_hash, our_tip_hash);
    if (!obs || n <= 0)
        return;
    if (n > NM_MAX_PEERS)
        n = NM_MAX_PEERS;

    /* Cluster[0] is OUR OWN tip, injected as a synthetic observation so the
     * fold can see the "everyone else holds X, we hold Y" case that the
     * peer-vs-peer fork fold cannot. It starts with zero PEERS behind it —
     * our own testimony never counts as peer support. */
    struct nm_tip_cluster cl[NM_MAX_FORK_CLUSTERS];
    memset(cl, 0, sizeof(cl));
    int num_cl = 1;
    nm_hash_norm(cl[0].hash, our_tip_hash);

    for (int i = 0; i < n; i++) {
        if (obs[i].tip_hash[0] == '\0' || obs[i].best_height < 0)
            continue;
        if (obs[i].best_height > our_height) {
            out->peers_ahead++;
            continue;
        }
        if (obs[i].best_height != our_height)
            continue; /* lagging peer: a different tip proves nothing */
        if (!nm_hash_hex_valid(obs[i].tip_hash))
            continue;
        out->peers_considered++;

        const char *key = NULL;
        if (group_keys && group_keys[i][0] != '\0')
            key = group_keys[i];
        else if (obs[i].addr[0] != '\0')
            key = obs[i].addr; /* fallback: one peer, one group */
        else
            continue; /* unattributable peer cannot vote */

        char peer_hash[PEER_OBS_TIP_HEX + 1];
        nm_hash_norm(peer_hash, obs[i].tip_hash);

        int found = -1;
        for (int k = 0; k < num_cl; k++) {
            if (strcmp(cl[k].hash, peer_hash) == 0) {
                found = k;
                break;
            }
        }
        if (found < 0) {
            if (num_cl >= NM_MAX_FORK_CLUSTERS)
                continue; /* bounded: extra rival tips are ignored */
            found = num_cl++;
            snprintf(cl[found].hash, sizeof(cl[found].hash), "%s", peer_hash);
        }
        cl[found].peers++;
        nm_cluster_add_group(&cl[found], key);
    }

    out->agreeing_peers = cl[0].peers;
    out->agreeing_groups = cl[0].groups;

    /* Strongest rival = most DISTINCT ADDRESS GROUPS (peers break the tie).
     * Ranking by groups rather than peers is the whole point: one address
     * group running twenty peers must not outrank two honest groups. */
    int best = -1;
    for (int k = 1; k < num_cl; k++) {
        if (best < 0 || cl[k].groups > cl[best].groups ||
            (cl[k].groups == cl[best].groups && cl[k].peers > cl[best].peers))
            best = k;
    }
    if (best < 0)
        return;

    out->rival_peers = cl[best].peers;
    out->rival_groups = cl[best].groups;
    snprintf(out->rival_tip_hash, sizeof(out->rival_tip_hash), "%s",
             cl[best].hash);

    /* Fire only when the rival is corroborated by >= 2 distinct address
     * groups (header_corroboration's rule) AND >= 2 peers, AND our own side
     * is the weaker one. Equal group support is a fork, not evidence that WE
     * are the minority — `fork_detected` already covers that. */
    out->peer_tip_disagreement =
        cl[best].groups >= NM_NETSPLIT_MIN_RIVAL_GROUPS &&
        cl[best].peers >= NM_NETSPLIT_MIN_RIVAL_PEERS &&
        cl[best].groups > cl[0].groups;
}

void network_monitor_fold_arrival_rate(const struct nm_arrival_sample *win,
                                       int win_n, int64_t target_spacing_secs,
                                       struct network_arrival_rate *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!win || win_n < NM_ARRIVAL_MIN_WINDOW_BLOCKS || target_spacing_secs <= 0)
        return;
    if (win_n > NM_ARRIVAL_MAX_WINDOW_BLOCKS)
        win_n = NM_ARRIVAL_MAX_WINDOW_BLOCKS;

    int64_t span = win[win_n - 1].time_unix - win[0].time_unix;
    if (span <= 0)
        return; /* non-monotonic header timestamps — refuse to judge */

    double base_diff = difficulty_from_bits(win[0].nbits);
    if (!(base_diff > 0.0))
        return;
    double sum_diff = 0.0;
    for (int i = 0; i < win_n; i++)
        sum_diff += difficulty_from_bits(win[i].nbits);
    double mean_diff = sum_diff / (double)win_n;

    out->window_blocks = win_n;
    out->span_secs = span;
    out->observed_interval_milli = (span * 1000) / (int64_t)(win_n - 1);
    out->expected_interval_milli = target_spacing_secs * 1000;
    if (out->observed_interval_milli <= 0)
        return;

    double diff_ratio = mean_diff / base_diff;
    out->difficulty_ratio_milli = (int64_t)(diff_ratio * 1000.0);

    /* implied hashrate ∝ difficulty / interval, normalised so that "arriving
     * exactly as this chain's own difficulty predicts" == 1000. */
    double implied = diff_ratio *
                     ((double)out->expected_interval_milli /
                      (double)out->observed_interval_milli);
    out->implied_hashrate_ratio_milli = (int64_t)(implied * 1000.0);
    out->ready = true;
    out->rate_below_floor =
        out->implied_hashrate_ratio_milli < NM_ARRIVAL_LOW_RATIO_MILLI;
}

void network_monitor_partition_verdict(int64_t tip_age_secs, int64_t now_unix,
                                       struct network_partition_view *out)
{
    if (!out)
        return;
    out->ready = true;
    out->computed_at = now_unix;
    out->tip_age_secs = tip_age_secs;
    out->tip_stale = tip_age_secs >= 0 && tip_age_secs > NM_TIP_STALE_SECS;

    out->signals_firing = (out->peer_tip_disagreement ? 1 : 0) +
                          (out->arrival.rate_below_floor ? 1 : 0) +
                          (out->tip_stale ? 1 : 0);

    /* No single source decides. The peer signal names the rival chain (and is
     * already un-trippable by one peer or one address group); a LOCAL,
     * peer-independent signal must corroborate that we are the ones on the
     * wrong side. Peer testimony alone never raises the verdict. */
    out->netsplit_suspected =
        out->peer_tip_disagreement &&
        (out->arrival.rate_below_floor || out->tip_stale);

    if (out->netsplit_suspected) {
        snprintf(out->reason, sizeof(out->reason),
                 "SUSPECTED_NETSPLIT: %d peers in %d address groups hold "
                 "%.16s at height %lld, we hold %.16s (%s)",
                 out->rival_peers, out->rival_groups, out->rival_tip_hash,
                 (long long)out->at_height, out->our_tip_hash,
                 out->arrival.rate_below_floor
                     ? "block arrival implies a minority of the hashrate this "
                       "chain's difficulty was set by"
                     : "tip stale beyond expected variance");
    } else if (out->peer_tip_disagreement) {
        snprintf(out->reason, sizeof(out->reason),
                 "peer tip disagreement at height %lld (%d groups) — held: no "
                 "local signal corroborates that we are the minority",
                 (long long)out->at_height, out->rival_groups);
    } else if (out->signals_firing > 0) {
        snprintf(out->reason, sizeof(out->reason),
                 "%d local signal(s) firing, no corroborated peer tip "
                 "disagreement", out->signals_firing);
    } else {
        snprintf(out->reason, sizeof(out->reason), "no partition signal");
    }
}

void network_monitor_netsplit_publish(const struct network_partition_view *v)
{
    if (!v)
        return;
    ns_lock();
    bool onset = v->netsplit_suspected && !g_ns.view.netsplit_suspected;
    g_ns.view = *v;
    g_ns.view.ready = true;
    zcl_mutex_unlock(&g_ns.lock);

    /* Edge-triggered: say it ONCE per onset, never once per 30 s sample. The
     * standing verdict lives in the `netsplit` dumper and in
     * network_monitor_netsplit_suspected(); this line only makes the onset
     * visible in node.log. */
    if (onset)
        LOG_WARN("network_monitor", "%s", v->reason);
}

bool network_monitor_netsplit_suspected(struct network_partition_view *out)
{
    ns_lock();
    struct network_partition_view pv = g_ns.view;
    zcl_mutex_unlock(&g_ns.lock);
    if (out)
        *out = pv;
    return pv.ready && pv.netsplit_suspected;
}

bool network_monitor_netsplit_dump_state_json(struct json_value *out,
                                              const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct network_partition_view pv;
    bool suspected = network_monitor_netsplit_suspected(&pv);

    json_push_kv_bool(out, "ready", pv.ready);
    json_push_kv_bool(out, "netsplit_suspected", suspected);
    json_push_kv_int(out, "signals_firing", pv.signals_firing);
    json_push_kv_int(out, "computed_at", pv.computed_at);
    json_push_kv_str(out, "reason", pv.reason);

    if (!pv.ready) {
        diag_push_health(out, true, "no partition fold yet");
        return true;
    }

    /* signal 1 — peer tip disagreement (>= 2 distinct address groups) */
    struct json_value s1;
    json_init(&s1);
    json_set_object(&s1);
    json_push_kv_bool(&s1, "firing", pv.peer_tip_disagreement);
    json_push_kv_int(&s1, "at_height", pv.at_height);
    json_push_kv_str(&s1, "our_tip_hash", pv.our_tip_hash);
    json_push_kv_str(&s1, "rival_tip_hash", pv.rival_tip_hash);
    json_push_kv_int(&s1, "rival_peers", pv.rival_peers);
    json_push_kv_int(&s1, "rival_groups", pv.rival_groups);
    json_push_kv_int(&s1, "agreeing_peers", pv.agreeing_peers);
    json_push_kv_int(&s1, "agreeing_groups", pv.agreeing_groups);
    json_push_kv_int(&s1, "peers_considered", pv.peers_considered);
    json_push_kv_int(&s1, "peers_ahead", pv.peers_ahead);
    json_push_kv_int(&s1, "min_rival_groups", NM_NETSPLIT_MIN_RIVAL_GROUPS);
    json_push_kv_int(&s1, "min_rival_peers", NM_NETSPLIT_MIN_RIVAL_PEERS);
    (void)json_push_kv(out, "peer_tip_disagreement", &s1);
    json_free(&s1);

    /* signal 2 — block arrival rate vs nBits-implied difficulty */
    struct json_value s2;
    json_init(&s2);
    json_set_object(&s2);
    json_push_kv_bool(&s2, "firing", pv.arrival.rate_below_floor);
    json_push_kv_bool(&s2, "ready", pv.arrival.ready);
    json_push_kv_int(&s2, "window_blocks", pv.arrival.window_blocks);
    json_push_kv_int(&s2, "span_secs", pv.arrival.span_secs);
    json_push_kv_int(&s2, "observed_interval_milli",
                     pv.arrival.observed_interval_milli);
    json_push_kv_int(&s2, "expected_interval_milli",
                     pv.arrival.expected_interval_milli);
    json_push_kv_int(&s2, "difficulty_ratio_milli",
                     pv.arrival.difficulty_ratio_milli);
    json_push_kv_int(&s2, "implied_hashrate_ratio_milli",
                     pv.arrival.implied_hashrate_ratio_milli);
    json_push_kv_int(&s2, "low_ratio_floor_milli", NM_ARRIVAL_LOW_RATIO_MILLI);
    (void)json_push_kv(out, "arrival_rate", &s2);
    json_free(&s2);

    /* signal 3 — tip staleness (reused node_health threshold) */
    struct json_value s3;
    json_init(&s3);
    json_set_object(&s3);
    json_push_kv_bool(&s3, "firing", pv.tip_stale);
    json_push_kv_int(&s3, "tip_age_secs", pv.tip_age_secs);
    json_push_kv_int(&s3, "stale_secs", NM_TIP_STALE_SECS);
    (void)json_push_kv(out, "tip_staleness", &s3);
    json_free(&s3);

    diag_push_health(out, !suspected, pv.reason);
    return true;
}
