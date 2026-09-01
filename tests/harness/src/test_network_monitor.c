/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_network_monitor — the network-monitoring station:
 *   1. observation ingest + bounded retention pruning (peer_chain_observation),
 *   2. consensus-view fold (modal tip, max height, our delta, fork clusters)
 *      from synthetic observations,
 *   3. each of the three redundant detectors fires on its synthetic trigger and
 *      does NOT false-fire on healthy data. */

#include "test/test_core.h"

#include "services/network_monitor.h"
#include "models/peer_chain_observation.h"
#include "models/database.h"

#include "conditions/net_tip_regression.h"
#include "conditions/net_fork_detected.h"
#include "conditions/net_partition_suspected.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define NM_CHECK(cond) do { \
    if (cond) { /* pass */ } \
    else { printf("  FAIL: %s (line %d)\n", #cond, __LINE__); failures++; } \
} while (0)

static void fill_hash(char *dst, char c)
{
    memset(dst, c, PEER_OBS_TIP_HEX);
    dst[PEER_OBS_TIP_HEX] = '\0';
}

static struct db_peer_chain_observation mk_obs(int64_t peer_id, int64_t height,
                                               char hashc)
{
    struct db_peer_chain_observation o;
    memset(&o, 0, sizeof(o));
    o.peer_id = peer_id;
    snprintf(o.addr, sizeof(o.addr), "10.0.0.%d:8033", (int)peer_id);
    snprintf(o.user_agent, sizeof(o.user_agent), "/zclassic23:1.0/");
    o.version = 170100;
    o.best_height = height;
    if (hashc)
        fill_hash(o.tip_hash, hashc);
    o.latency_us = 12000 + peer_id;
    o.inbound = 0;
    o.first_seen = 1000;
    o.last_seen = 2000;
    o.observed_at = 3000;
    return o;
}

/* ── 1. model ingest + retention ─────────────────────────────────────── */
static int test_observation_model(void)
{
    int failures = 0;
    printf("peer_chain_observation ingest + retention pruning...\n");

    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    snprintf(dbdir, sizeof(dbdir), ".zcl_test_netmon_%d", (int)getpid());
    mkdir(dbdir, 0755);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));

    if (node_db_open(&ndb, dbpath)) {
        /* ingest 25 rows */
        for (int i = 0; i < 25; i++) {
            struct db_peer_chain_observation o = mk_obs(i, 3000000 + i, 'a');
            o.observed_at = 0; /* let save stamp it */
            NM_CHECK(db_peer_chain_observation_save(&ndb, &o));
        }
        NM_CHECK(db_peer_chain_observation_count(&ndb) == 25);

        /* retention: keep newest 10 */
        NM_CHECK(db_peer_chain_observation_prune(&ndb, 10));
        NM_CHECK(db_peer_chain_observation_count(&ndb) == 10);

        /* newest-first read: the most recent row (peer_id 24) is first */
        struct db_peer_chain_observation out[10];
        int n = db_peer_chain_observation_recent(&ndb, out, 10);
        NM_CHECK(n == 10);
        NM_CHECK(out[0].peer_id == 24);
        NM_CHECK(out[0].best_height == 3000024);
        NM_CHECK(out[0].tip_hash[0] == 'a');

        /* pruning to a larger N than present is a no-op success */
        NM_CHECK(db_peer_chain_observation_prune(&ndb, 1000));
        NM_CHECK(db_peer_chain_observation_count(&ndb) == 10);

        node_db_close(&ndb);
    } else {
        printf("  FAIL: node_db_open\n");
        failures++;
    }

    char cmd[384];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
    (void)system(cmd);
    return failures;
}

/* ── 2. consensus-view fold ──────────────────────────────────────────── */
static int test_consensus_view(void)
{
    int failures = 0;
    printf("consensus-view fold: modal tip, max, delta, fork clusters...\n");

    /* modal + max + delta, no fork (all one hash) */
    {
        struct db_peer_chain_observation obs[4];
        obs[0] = mk_obs(1, 100, 'a');
        obs[1] = mk_obs(2, 100, 'a');
        obs[2] = mk_obs(3, 100, 'a');
        obs[3] = mk_obs(4, 99, 'a');
        struct network_consensus_view v;
        network_monitor_compute_view(obs, 4, 95, 12345, &v);
        NM_CHECK(v.ready);
        NM_CHECK(v.num_peers == 4);
        NM_CHECK(v.modal_height == 100);
        NM_CHECK(v.modal_height_count == 3);
        NM_CHECK(v.max_height == 100);
        NM_CHECK(v.our_height == 95);
        NM_CHECK(v.delta == 5);
        NM_CHECK(!v.fork_detected);
    }

    /* fork: two clusters at height 200 (hash a x2, hash b x2) */
    {
        struct db_peer_chain_observation obs[5];
        obs[0] = mk_obs(1, 200, 'a');
        obs[1] = mk_obs(2, 200, 'a');
        obs[2] = mk_obs(3, 200, 'b');
        obs[3] = mk_obs(4, 200, 'b');
        obs[4] = mk_obs(5, 200, 'c'); /* lone dissenter, below min cluster */
        struct network_consensus_view v;
        network_monitor_compute_view(obs, 5, 200, 12345, &v);
        NM_CHECK(v.fork_detected);
        NM_CHECK(v.fork_height == 200);
        NM_CHECK(v.fork_count_a == 2);
        NM_CHECK(v.fork_count_b == 2);
        NM_CHECK(v.fork_hash_a[0] != v.fork_hash_b[0]);
    }

    /* NOT a fork: a single peer disagreeing (below min cluster) */
    {
        struct db_peer_chain_observation obs[4];
        obs[0] = mk_obs(1, 300, 'a');
        obs[1] = mk_obs(2, 300, 'a');
        obs[2] = mk_obs(3, 300, 'a');
        obs[3] = mk_obs(4, 300, 'z'); /* one lying/lagging peer */
        struct network_consensus_view v;
        network_monitor_compute_view(obs, 4, 300, 12345, &v);
        NM_CHECK(!v.fork_detected);
    }

    /* empty sample is safe */
    {
        struct network_consensus_view v;
        network_monitor_compute_view(NULL, 0, 100, 12345, &v);
        NM_CHECK(v.ready);
        NM_CHECK(v.num_peers == 0);
        NM_CHECK(v.max_height == -1);
        NM_CHECK(!v.fork_detected);
    }
    return failures;
}

/* helper: build + inject a view */
static void inject_view(int num_peers, int64_t our_h, int64_t modal,
                        int64_t maxh, bool fork, int64_t fork_h)
{
    struct network_consensus_view v;
    memset(&v, 0, sizeof(v));
    v.ready = true;
    v.num_peers = num_peers;
    v.peers_with_height = num_peers;
    v.our_height = our_h;
    v.modal_height = modal;
    v.max_height = maxh;
    v.delta = maxh >= 0 && our_h >= 0 ? maxh - our_h : 0;
    v.fork_detected = fork;
    v.fork_height = fork ? fork_h : -1;
    if (fork) {
        fill_hash(v.fork_hash_a, 'a');
        fill_hash(v.fork_hash_b, 'b');
        v.fork_count_a = 2;
        v.fork_count_b = 2;
    }
    network_monitor_test_set_view(&v);
}

/* ── 3a. net_tip_regression ──────────────────────────────────────────── */
static int test_tip_regression_condition(void)
{
    int failures = 0;
    printf("net_tip_regression: fires on frozen-behind, not on progress...\n");

    /* trigger: our height frozen while network modal advances, we are behind */
    net_tip_regression_test_reset();
    net_tip_regression_test_set_now(1000);
    inject_view(3, 100, 100, 100, false, -1);
    NM_CHECK(!net_tip_regression_test_detect()); /* baseline */
    net_tip_regression_test_set_now(1000 + 901);
    inject_view(3, 100, 103, 110, false, -1); /* modal +3, we froze, behind */
    NM_CHECK(net_tip_regression_test_detect());

    /* healthy: our height advances -> no fire */
    net_tip_regression_test_reset();
    net_tip_regression_test_set_now(2000);
    inject_view(3, 100, 100, 100, false, -1);
    NM_CHECK(!net_tip_regression_test_detect());
    net_tip_regression_test_set_now(2000 + 901);
    inject_view(3, 105, 110, 110, false, -1); /* we advanced to 105 */
    NM_CHECK(!net_tip_regression_test_detect());

    /* healthy: at tip, nobody ahead -> no fire even if time passes */
    net_tip_regression_test_reset();
    net_tip_regression_test_set_now(3000);
    inject_view(3, 500, 500, 500, false, -1);
    NM_CHECK(!net_tip_regression_test_detect());
    net_tip_regression_test_set_now(3000 + 901);
    inject_view(3, 500, 500, 500, false, -1);
    NM_CHECK(!net_tip_regression_test_detect());

    net_tip_regression_test_reset();
    return failures;
}

/* ── 3b. net_fork_detected ───────────────────────────────────────────── */
static int test_fork_condition(void)
{
    int failures = 0;
    printf("net_fork_detected: fires on a fork, not on agreement...\n");

    net_fork_detected_test_reset();
    inject_view(4, 200, 200, 200, true, 200);
    NM_CHECK(net_fork_detected_test_detect());

    inject_view(4, 200, 200, 200, false, -1);
    NM_CHECK(!net_fork_detected_test_detect());

    net_fork_detected_test_reset();
    return failures;
}

/* ── 3c. net_partition_suspected ─────────────────────────────────────── */
static int test_partition_condition(void)
{
    int failures = 0;
    printf("net_partition_suspected: fires on eclipse + frozen-behind...\n");

    /* Signal A: sustained peer collapse */
    net_partition_suspected_test_reset();
    net_partition_suspected_test_set_now(1000);
    inject_view(1, 100, 100, 100, false, -1); /* 1 peer < floor 2 */
    NM_CHECK(!net_partition_suspected_test_detect()); /* not yet sustained */
    net_partition_suspected_test_set_now(1000 + 601);
    inject_view(1, 100, 100, 100, false, -1);
    NM_CHECK(net_partition_suspected_test_detect()); /* eclipse */

    /* Signal B: peers present, behind, nothing moving */
    net_partition_suspected_test_reset();
    net_partition_suspected_test_set_now(5000);
    inject_view(3, 100, 110, 110, false, -1);
    NM_CHECK(!net_partition_suspected_test_detect());
    net_partition_suspected_test_set_now(5000 + 601);
    inject_view(3, 100, 110, 110, false, -1); /* still behind, frozen */
    NM_CHECK(net_partition_suspected_test_detect());

    /* healthy: plenty of peers, at tip -> no fire */
    net_partition_suspected_test_reset();
    net_partition_suspected_test_set_now(8000);
    inject_view(5, 100, 100, 100, false, -1);
    NM_CHECK(!net_partition_suspected_test_detect());
    net_partition_suspected_test_set_now(8000 + 601);
    inject_view(5, 100, 100, 100, false, -1);
    NM_CHECK(!net_partition_suspected_test_detect());

    /* healthy: peers present and catching up (our height moves) -> no fire */
    net_partition_suspected_test_reset();
    net_partition_suspected_test_set_now(9000);
    inject_view(3, 100, 110, 110, false, -1);
    NM_CHECK(!net_partition_suspected_test_detect());
    net_partition_suspected_test_set_now(9000 + 601);
    inject_view(3, 108, 110, 110, false, -1); /* our height advanced to 108 */
    NM_CHECK(!net_partition_suspected_test_detect());

    net_partition_suspected_test_reset();
    return failures;
}

int test_network_monitor(void)
{
    printf("\n=== network_monitor tests ===\n");
    int failures = 0;
    failures += test_observation_model();
    failures += test_consensus_view();
    failures += test_tip_regression_condition();
    failures += test_fork_condition();
    failures += test_partition_condition();
    if (failures == 0)
        printf("=== network_monitor: all passed ===\n");
    else
        printf("=== network_monitor: %d FAILED ===\n", failures);
    return failures;
}
