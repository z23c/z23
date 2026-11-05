/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_monitor fold, config and sampler tests aimed at the survivors of the
 * network_monitor.c mutation sweep. Entry point network_monitor_fold_tests(),
 * called from test_network_monitor(). Local fixtures only: synthetic
 * observations for the pure fold, a fake connman + one installed chain slot
 * and a temp sqlite file for the real sampler thread. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "json/json.h"
#include "models/database.h"
#include "models/peer_chain_observation.h"
#include "net/connman.h"
#include "net/download.h"
#include "net/netaddr.h"
#include "platform/time_compat.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int network_monitor_fold_tests(void);

#define NMF_CHECK(cond) do { \
    if (cond) { /* pass */ } \
    else { printf("  FAIL: %s (line %d)\n", #cond, __LINE__); failures++; } \
} while (0)

static void nmf_hash(char *dst, char c)
{
    memset(dst, c, PEER_OBS_TIP_HEX);
    dst[PEER_OBS_TIP_HEX] = '\0';
}

static void nmf_set(struct db_peer_chain_observation *o, int64_t id,
                    int64_t height, char hashc)
{
    memset(o, 0, sizeof(*o));
    o->peer_id = id;
    o->best_height = height;
    if (hashc)
        nmf_hash(o->tip_hash, hashc);
}

static bool nmf_hash_is(const char *got, char c)
{
    char want[PEER_OBS_TIP_HEX + 1];
    nmf_hash(want, c);
    return strcmp(got, want) == 0;
}

/* ── modal height, tie-break, skip rules, trap element past n ─────────── */
static int nmf_modal_case(const struct db_peer_chain_observation *obs,
                          int n, int64_t want_modal)
{
    int failures = 0;
    struct network_consensus_view v;
    network_monitor_compute_view(obs, n, 0, 77, &v);
    NMF_CHECK(v.num_peers == n);
    NMF_CHECK(v.peers_with_height == 6); /* -1 skipped, 0 and 150 counted */
    NMF_CHECK(v.max_height == 200);
    NMF_CHECK(v.modal_height == want_modal);
    NMF_CHECK(v.modal_height_count == 2);
    /* clusters: 100/a x2, 200/b x2, 0/z x1; the -1 peer and the hashless 150
     * peer never form a cluster; the trap element past n never counts. */
    NMF_CHECK(v.num_clusters == 3);
    int by_height_a = v.clusters[0].height == 100 ? 0 : 1;
    NMF_CHECK(v.clusters[by_height_a].peer_count == 2);
    NMF_CHECK(v.clusters[2].height == 0);
    NMF_CHECK(v.clusters[2].peer_count == 1);
    NMF_CHECK(nmf_hash_is(v.clusters[2].tip_hash, 'z'));
    return failures;
}

static int nmf_test_modal(void)
{
    int failures = 0;
    printf("network_monitor fold: modal height, ties, skips, bounds...\n");
    /* Lower height first: a tie goes to the greater height. */
    struct db_peer_chain_observation up[8];
    nmf_set(&up[0], 1, 100, 'a');
    nmf_set(&up[1], 2, 100, 'a');
    nmf_set(&up[2], 3, 200, 'b');
    nmf_set(&up[3], 4, 200, 'b');
    nmf_set(&up[4], 5, -1, 'x');  /* no height: skipped, hash ignored */
    nmf_set(&up[5], 6, 0, 'z');   /* height 0 is a real height */
    nmf_set(&up[6], 7, 150, 0);   /* height but no tip hash */
    nmf_set(&up[7], 8, 100, 'a'); /* trap: lies past n */
    failures += nmf_modal_case(up, 7, 200);

    /* Greater height first: still the greater one on the tie. */
    struct db_peer_chain_observation down[8];
    nmf_set(&down[0], 3, 200, 'b');
    nmf_set(&down[1], 4, 200, 'b');
    nmf_set(&down[2], 1, 100, 'a');
    nmf_set(&down[3], 2, 100, 'a');
    nmf_set(&down[4], 5, -1, 'x');
    nmf_set(&down[5], 6, 0, 'z');
    nmf_set(&down[6], 7, 150, 0);
    nmf_set(&down[7], 8, 100, 'a');
    struct network_consensus_view v;
    network_monitor_compute_view(down, 7, 0, 77, &v);
    NMF_CHECK(v.modal_height == 200 && v.modal_height_count == 2);
    NMF_CHECK(v.num_clusters == 3);
    return failures;
}

/* ── delta, empty and degenerate inputs ───────────────────────────────── */
static int nmf_test_delta_and_empty(void)
{
    int failures = 0;
    printf("network_monitor fold: delta and degenerate inputs...\n");
    struct db_peer_chain_observation o[3];
    struct network_consensus_view v;

    nmf_set(&o[0], 1, 50, 'a');
    nmf_set(&o[1], 2, 50, 'a');
    network_monitor_compute_view(o, 2, 0, 5, &v); /* our height 0 is known */
    NMF_CHECK(v.delta == 50 && v.our_height == 0 && v.computed_at == 5);
    network_monitor_compute_view(o, 2, -1, 5, &v); /* unknown: delta stays 0 */
    NMF_CHECK(v.delta == 0 && v.max_height == 50);
    network_monitor_compute_view(o, 2, 60, 5, &v); /* we are ahead */
    NMF_CHECK(v.delta == -10);

    nmf_set(&o[0], 1, 0, 'a'); /* the best peer sits at height 0 */
    nmf_set(&o[1], 2, 0, 'a');
    network_monitor_compute_view(o, 2, 5, 5, &v);
    NMF_CHECK(v.max_height == 0 && v.delta == -5);

    nmf_set(&o[0], 1, -1, 'a'); /* nobody advertises a height */
    nmf_set(&o[1], 2, -1, 'a');
    nmf_set(&o[2], 3, -1, 0);
    network_monitor_compute_view(o, 3, 5, 5, &v);
    NMF_CHECK(v.num_peers == 3 && v.peers_with_height == 0);
    NMF_CHECK(v.modal_height == -1 && v.modal_height_count == 0);
    NMF_CHECK(v.max_height == -1 && v.delta == 0);
    NMF_CHECK(v.fork_height == -1 && !v.fork_detected);

    network_monitor_compute_view(NULL, 3, 9, 8, &v); /* NULL obs, n > 0 */
    NMF_CHECK(v.ready && v.num_peers == 0 && v.our_height == 9);
    NMF_CHECK(v.modal_height == -1 && v.max_height == -1);
    NMF_CHECK(v.fork_height == -1 && v.computed_at == 8);
    network_monitor_compute_view(o, 0, 9, 8, &v);
    NMF_CHECK(v.ready && v.num_peers == 0 && v.modal_height == -1);
    network_monitor_compute_view(o, 2, 9, 8, NULL); /* NULL out is safe */
    return failures;
}

/* ── cluster cap, peer clamp ──────────────────────────────────────────── */
static int nmf_test_caps(void)
{
    int failures = 0;
    printf("network_monitor fold: cluster cap and peer clamp...\n");
    struct db_peer_chain_observation o[300];
    struct network_consensus_view v;

    for (int i = 0; i < 17; i++)
        nmf_set(&o[i], i + 1, i + 1, 'a'); /* 17 distinct clusters */
    network_monitor_compute_view(o, 17, 0, 1, &v);
    NMF_CHECK(v.peers_with_height == 17);
    NMF_CHECK(v.num_clusters == NM_MAX_FORK_CLUSTERS);
    NMF_CHECK(v.clusters[NM_MAX_FORK_CLUSTERS - 1].height == 16);
    NMF_CHECK(v.clusters[0].height == 1 && v.clusters[0].peer_count == 1);

    for (int i = 0; i < 300; i++)
        nmf_set(&o[i], i + 1, 100, 'a');
    network_monitor_compute_view(o, 300, 0, 1, &v);
    NMF_CHECK(v.num_peers == NM_MAX_PEERS);
    NMF_CHECK(v.peers_with_height == NM_MAX_PEERS);
    NMF_CHECK(v.modal_height_count == NM_MAX_PEERS);
    NMF_CHECK(v.clusters[0].peer_count == NM_MAX_PEERS);

    /* same hash at two heights is two clusters, same height two hashes too */
    nmf_set(&o[0], 1, 10, 'a');
    nmf_set(&o[1], 2, 11, 'a');
    nmf_set(&o[2], 3, 10, 'b');
    network_monitor_compute_view(o, 3, 0, 1, &v);
    NMF_CHECK(v.num_clusters == 3 && !v.fork_detected);
    return failures;
}

/* ── fork verdict: strongest pair wins, first wins a tie ─────────────── */
static void nmf_fill(struct db_peer_chain_observation *o, int *k, int count,
                     int64_t height, char hashc)
{
    for (int i = 0; i < count; i++) {
        nmf_set(&o[*k], *k + 1, height, hashc);
        (*k)++;
    }
}

static int nmf_test_fork(void)
{
    int failures = 0;
    printf("network_monitor fold: fork verdict ranking...\n");
    struct db_peer_chain_observation o[24];
    struct network_consensus_view v;
    int k = 0;

    /* 'b' before 'a' at height 100 (so the pair compares b against a), then a
     * stronger 3+2 pair at 200 that must outrank it. */
    nmf_fill(o, &k, 2, 100, 'b');
    nmf_fill(o, &k, 2, 100, 'a');
    nmf_fill(o, &k, 3, 200, 'c');
    nmf_fill(o, &k, 2, 200, 'd');
    network_monitor_compute_view(o, k, 200, 1, &v);
    NMF_CHECK(v.fork_detected && v.fork_height == 200);
    NMF_CHECK(v.fork_count_a == 3 && v.fork_count_b == 2);
    NMF_CHECK(nmf_hash_is(v.fork_hash_a, 'c'));
    NMF_CHECK(nmf_hash_is(v.fork_hash_b, 'd'));

    /* only the 'b'/'a' pair: reported in cluster order */
    k = 0;
    nmf_fill(o, &k, 2, 100, 'b');
    nmf_fill(o, &k, 2, 100, 'a');
    network_monitor_compute_view(o, k, 100, 1, &v);
    NMF_CHECK(v.fork_detected && v.fork_height == 100);
    NMF_CHECK(nmf_hash_is(v.fork_hash_a, 'b'));
    NMF_CHECK(nmf_hash_is(v.fork_hash_b, 'a'));

    /* equal combined support at two heights: the first pair keeps the slot */
    k = 0;
    nmf_fill(o, &k, 2, 100, 'a');
    nmf_fill(o, &k, 2, 100, 'b');
    nmf_fill(o, &k, 2, 300, 'c');
    nmf_fill(o, &k, 2, 300, 'd');
    network_monitor_compute_view(o, k, 100, 1, &v);
    NMF_CHECK(v.fork_detected && v.fork_height == 100);
    NMF_CHECK(nmf_hash_is(v.fork_hash_a, 'a'));

    /* a sub-minimum cluster never pairs, however many others disagree */
    k = 0;
    nmf_fill(o, &k, 3, 100, 'a');
    nmf_fill(o, &k, 1, 100, 'b');
    nmf_fill(o, &k, 3, 100, 'c');
    network_monitor_compute_view(o, k, 100, 1, &v);
    NMF_CHECK(v.fork_detected);
    NMF_CHECK(nmf_hash_is(v.fork_hash_a, 'a'));
    NMF_CHECK(nmf_hash_is(v.fork_hash_b, 'c'));
    return failures;
}

/* ── config defaults ──────────────────────────────────────────────────── */
static int nmf_test_config_defaults(void)
{
    int failures = 0;
    printf("network_monitor config defaults...\n");
    struct network_monitor_config cfg = { .sample_interval_secs = 1,
                                          .retain_rows = 1 };
    network_monitor_config_defaults(&cfg);
    NMF_CHECK(cfg.sample_interval_secs == 30);
    NMF_CHECK(cfg.retain_rows == 10000);
    network_monitor_config_defaults(NULL); /* must not crash */
    return failures;
}

/* ── start/stop: env bounds and the dump ─────────────────────────────── */
static int nmf_dump_int(const struct json_value *d, const char *key,
                        int64_t want)
{
    const struct json_value *f = json_get(d, key);
    if (f && json_get_int(f) == want)
        return 0;
    printf("  FAIL: dump key %s != %lld\n", key, (long long)want);
    return 1;
}

static int nmf_start_dump(const char *iv, const char *rr,
                          const struct network_monitor_config *cfg,
                          int64_t want_iv, int64_t want_rr)
{
    int failures = 0;
    if (iv)
        setenv("ZCL_NETMON_INTERVAL_SECS", iv, 1);
    else
        unsetenv("ZCL_NETMON_INTERVAL_SECS");
    if (rr)
        setenv("ZCL_NETMON_RETAIN_ROWS", rr, 1);
    else
        unsetenv("ZCL_NETMON_RETAIN_ROWS");
    NMF_CHECK(network_monitor_start(cfg, NULL).ok);
    struct network_consensus_view v;
    while (!network_monitor_get_view(&v))
        platform_sleep_ms(5);
    struct json_value d;
    json_init(&d);
    NMF_CHECK(network_monitor_dump_state_json(&d, NULL));
    failures += nmf_dump_int(&d, "sample_interval_secs", want_iv);
    failures += nmf_dump_int(&d, "retain_rows", want_rr);
    NMF_CHECK(json_get_bool(json_get(&d, "started")));
    NMF_CHECK(json_get_bool(json_get(&d, "ready")));
    NMF_CHECK(json_get_int(json_get(&d, "loop_ticks")) >= 1);
    NMF_CHECK(json_get_int(json_get(&d, "retained_rows")) == 0);
    json_free(&d);
    network_monitor_stop();
    json_init(&d);
    NMF_CHECK(network_monitor_dump_state_json(&d, NULL));
    NMF_CHECK(!json_get_bool(json_get(&d, "started")));
    json_free(&d);
    return failures;
}

static int nmf_test_config_cycles(void)
{
    int failures = 0;
    printf("network_monitor start/stop: env bounds, cfg, idempotence...\n");
    network_monitor_stop(); /* not started: no-op */
    struct network_monitor_config c1 = { 7, 200 };
    struct network_monitor_config c2 = { 9, 300 };
    failures += nmf_start_dump(NULL, NULL, NULL, 30, 10000);
    failures += nmf_start_dump(NULL, NULL, &c1, 7, 200);
    failures += nmf_start_dump("1", "100", &c1, 1, 100);
    failures += nmf_start_dump("3600", "10000000", &c1, 3600, 10000000);
    failures += nmf_start_dump("0", "99", &c1, 7, 200);
    failures += nmf_start_dump("3601", "10000001", &c1, 7, 200);
    failures += nmf_start_dump("", "", &c1, 7, 200);

    /* a second start while running keeps the first configuration */
    unsetenv("ZCL_NETMON_INTERVAL_SECS");
    unsetenv("ZCL_NETMON_RETAIN_ROWS");
    NMF_CHECK(network_monitor_start(&c1, NULL).ok);
    NMF_CHECK(network_monitor_start(&c2, NULL).ok);
    struct json_value d;
    json_init(&d);
    NMF_CHECK(network_monitor_dump_state_json(&d, NULL));
    failures += nmf_dump_int(&d, "sample_interval_secs", 7);
    failures += nmf_dump_int(&d, "retain_rows", 200);
    json_free(&d);
    network_monitor_stop();
    return failures;
}

/* ── dump of an injected view ─────────────────────────────────────────── */
static int nmf_test_dump_view(void)
{
    int failures = 0;
    printf("network_monitor dump of an injected view...\n");
    struct network_consensus_view v;
    memset(&v, 0, sizeof(v));
    v.computed_at = 1234;
    v.num_peers = 5;
    v.peers_with_height = 4;
    v.modal_height = 90;
    v.modal_height_count = 3;
    v.max_height = 95;
    v.our_height = 80;
    v.delta = 15;
    v.fork_height = -1;
    v.num_clusters = 2;
    v.clusters[0].height = 90;
    v.clusters[0].peer_count = 3;
    nmf_hash(v.clusters[0].tip_hash, 'a');
    v.clusters[1].height = 95;
    v.clusters[1].peer_count = 1;
    nmf_hash(v.clusters[1].tip_hash, 'b');
    network_monitor_test_set_view(&v);

    struct json_value d;
    json_init(&d);
    NMF_CHECK(network_monitor_dump_state_json(&d, "ignored"));
    failures += nmf_dump_int(&d, "computed_at", 1234);
    failures += nmf_dump_int(&d, "num_peers", 5);
    failures += nmf_dump_int(&d, "peers_with_height", 4);
    failures += nmf_dump_int(&d, "modal_height", 90);
    failures += nmf_dump_int(&d, "modal_height_count", 3);
    failures += nmf_dump_int(&d, "max_height", 95);
    failures += nmf_dump_int(&d, "our_height", 80);
    failures += nmf_dump_int(&d, "delta_behind_best", 15);
    failures += nmf_dump_int(&d, "fork_height", -1);
    NMF_CHECK(!json_get_bool(json_get(&d, "fork_detected")));
    NMF_CHECK(json_get(&d, "fork_hash_a") == NULL);
    NMF_CHECK(json_get(&d, "fork_count_a") == NULL);
    const struct json_value *cl = json_get(&d, "tip_clusters");
    NMF_CHECK(cl && json_size(cl) == 2);
    const struct json_value *c1 = cl ? json_at(cl, 1) : NULL;
    NMF_CHECK(c1 && json_get_int(json_get(c1, "height")) == 95);
    NMF_CHECK(c1 && json_get_int(json_get(c1, "peer_count")) == 1);
    NMF_CHECK(c1 && nmf_hash_is(json_get_str(json_get(c1, "tip_hash")), 'b'));
    const struct json_value *h = json_get(&d, "_health");
    NMF_CHECK(h && json_get_bool(json_get(h, "ok")));
    NMF_CHECK(h && strcmp(json_get_str(json_get(h, "reason")),
                          "delta_behind_best=15") == 0);
    json_free(&d);

    v.fork_detected = true;
    v.fork_height = 90;
    v.fork_count_a = 3;
    v.fork_count_b = 2;
    nmf_hash(v.fork_hash_a, 'a');
    nmf_hash(v.fork_hash_b, 'b');
    network_monitor_test_set_view(&v);
    json_init(&d);
    NMF_CHECK(network_monitor_dump_state_json(&d, NULL));
    NMF_CHECK(json_get_bool(json_get(&d, "fork_detected")));
    failures += nmf_dump_int(&d, "fork_height", 90);
    failures += nmf_dump_int(&d, "fork_count_a", 3);
    failures += nmf_dump_int(&d, "fork_count_b", 2);
    NMF_CHECK(nmf_hash_is(json_get_str(json_get(&d, "fork_hash_a")), 'a'));
    NMF_CHECK(nmf_hash_is(json_get_str(json_get(&d, "fork_hash_b")), 'b'));
    h = json_get(&d, "_health");
    NMF_CHECK(h && !json_get_bool(json_get(h, "ok")));
    NMF_CHECK(h && strcmp(json_get_str(json_get(h, "reason")),
                          "fork: 3 vs 2 peers disagree at height 90") == 0);
    json_free(&d);
    return failures;
}

int network_monitor_fold_sampler_tests(void);

int network_monitor_fold_tests(void)
{
    int failures = 0;
    failures += nmf_test_modal();
    failures += nmf_test_delta_and_empty();
    failures += nmf_test_caps();
    failures += nmf_test_fork();
    failures += nmf_test_config_defaults();
    failures += nmf_test_config_cycles();
    failures += nmf_test_dump_view();
    failures += network_monitor_fold_sampler_tests();
    return failures;
}
