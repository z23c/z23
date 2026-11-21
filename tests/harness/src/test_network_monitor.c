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
#include "util/supervisor.h"
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

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}

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
    test_make_tmpdir(dbdir, sizeof(dbdir), "netmon", "observation");
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

    failures += !fixture_rm_ok(dbdir);
    return failures;
}

static int test_failed_retention_bounds_history(void)
{
    int failures = 0;
    struct node_db db = {0};
    NM_CHECK(node_db_open(&db, ":memory:"));
    if (!db.open) return failures + 1;
    struct db_peer_chain_observation obs = mk_obs(1, 100, 'a');
    bool pending = true;
    network_monitor_persist_sample(&db, &obs, 1, 1, &pending);
    NM_CHECK(!pending && db_peer_chain_observation_count(&db) == 1);
    NM_CHECK(sqlite3_exec(db.db, "CREATE TEMP TRIGGER deny_prune BEFORE DELETE ON "
        "peer_chain_observations BEGIN SELECT RAISE(ABORT,'fixture'); END",
        NULL, NULL, NULL) == SQLITE_OK);
    obs.peer_id = 2;
    network_monitor_persist_sample(&db, &obs, 1, 1, &pending);
    NM_CHECK(pending && db_peer_chain_observation_count(&db) == 2);
    for (int i = 0; i < 3; i++)
        network_monitor_persist_sample(&db, &obs, 1, 1, &pending);
    NM_CHECK(pending && db_peer_chain_observation_count(&db) == 2);
    NM_CHECK(sqlite3_exec(db.db, "DROP TRIGGER deny_prune", NULL, NULL, NULL) == SQLITE_OK);
    obs.peer_id = 3;
    network_monitor_persist_sample(&db, &obs, 1, 1, &pending);
    struct db_peer_chain_observation latest[2];
    NM_CHECK(!pending && db_peer_chain_observation_recent(&db, latest, 2) == 1 &&
             latest[0].peer_id == 3);
    node_db_close(&db);
    return failures;
}

static int test_prune_sparse_boundaries(void)
{
    int failures = 0;
    struct node_db db = {0};
    NM_CHECK(node_db_open(&db, ":memory:"));
    if (!db.open) return failures + 1;
    const char *insert = "INSERT INTO peer_chain_observations "
        "(id,peer_id,addr,user_agent,observed_at) VALUES "
        "(-20,1,'a','x',1),(0,2,'a','x',1),"
        "(13,3,'a','x',1),(9223372036854775807,4,'a','x',1)";
    NM_CHECK(sqlite3_exec(db.db, insert, NULL, NULL, NULL) == SQLITE_OK);
    NM_CHECK(db_peer_chain_observation_prune(&db, 10));
    NM_CHECK(db_peer_chain_observation_count(&db) == 4);
    NM_CHECK(db_peer_chain_observation_prune(&db, 2));
    struct db_peer_chain_observation out[4];
    int count = db_peer_chain_observation_recent(&db, out, 4);
    NM_CHECK(count == 2 && out[0].peer_id == 4 && out[1].peer_id == 3);
    NM_CHECK(db_peer_chain_observation_prune(&db, 0));
    NM_CHECK(db_peer_chain_observation_count(&db) == 0);
    NM_CHECK(sqlite3_exec(db.db, insert, NULL, NULL, NULL) == SQLITE_OK);
    NM_CHECK(db_peer_chain_observation_prune(&db, -1));
    NM_CHECK(db_peer_chain_observation_count(&db) == 0);
    node_db_close(&db);
    return failures;
}

static bool fixture_is_wal(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &s, NULL) != SQLITE_OK)
        return false;
    bool wal = sqlite3_step(s) == SQLITE_ROW &&
               strcmp((const char *)sqlite3_column_text(s, 0), "wal") == 0;
    sqlite3_finalize(s);
    return wal;
}

static int fixture_progress(void *ctx)
{
    (*(int *)ctx)++;
    return 0;
}

static int test_prune_diagnostic(void)
{
    int failures = 0;
    char dir[256], path[320], text[1024] = {0};
    struct node_db db = {0};
    test_make_tmpdir(dir, sizeof(dir), "netmon", "prune-diagnostic");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    if (!node_db_open(&db, path)) {
        (void)fixture_rm_ok(dir);
        return 1;
    }
    NM_CHECK(fixture_is_wal(db.db));
    int rc = sqlite3_exec(db.db, "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL "
        "SELECT x+1 FROM n WHERE x<10005) INSERT INTO peer_chain_observations"
        "(peer_id,addr,user_agent,observed_at) SELECT x,'peer','/test/',1 FROM n", NULL, NULL, NULL);
    NM_CHECK(rc == SQLITE_OK);
    NM_CHECK(db_peer_chain_observation_count(&db) == 10005);
    int progress = 0;
    sqlite3_progress_handler(db.db, 1000, fixture_progress, &progress);
    bool pruned = db_peer_chain_observation_prune(&db, 10000);
    sqlite3_progress_handler(db.db, 0, NULL, NULL);
    printf("prune VM progress callbacks=%d (1000 steps each)\n", progress);
    NM_CHECK(pruned);
    NM_CHECK(progress < 60);
    NM_CHECK(db_peer_chain_observation_count(&db) == 10000);
    NM_CHECK(sqlite3_exec(db.db, "PRAGMA query_only=ON", NULL, NULL, NULL) == SQLITE_OK);
    FILE *log = tmpfile();
    int saved = dup(STDERR_FILENO);
    if (!log || saved < 0 || dup2(fileno(log), STDERR_FILENO) < 0) {
        failures++;
    } else {
        bool ok = db_peer_chain_observation_prune(&db, 10000);
        fflush(stderr);
        if (dup2(saved, STDERR_FILENO) < 0) failures++;
        rewind(log);
        size_t bytes = fread(text, 1, sizeof(text) - 1, log);
        NM_CHECK(bytes > 0);
        NM_CHECK(!ok);
        NM_CHECK(strstr(text, "prune step failed rc=8:") != NULL);
        NM_CHECK(strstr(text, sqlite3_errstr(SQLITE_READONLY)) != NULL);
        NM_CHECK(db_peer_chain_observation_count(&db) == 10000);
    }
    if (saved >= 0) close(saved);
    if (log) fclose(log);
    node_db_close(&db);
    failures += !fixture_rm_ok(dir);
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

/* A malformed interval must not silently turn the nine-hundred-second
 * tip-regression window into a ten-second one merely because it has a
 * numeric prefix. Preserve any caller override exactly. */
static int test_tip_regression_rejects_malformed_window(void)
{
    int failures = 0;
    const char *var = "ZCL_NET_TIP_REGRESSION_SECS";
    const char *old = getenv(var);
    char *saved = old ? strdup(old) : NULL;
    if (old && !saved)
        return 1;

    bool set = setenv(var, "10junk", 1) == 0;
    net_tip_regression_test_reset();
    net_tip_regression_test_set_now(10000);
    inject_view(3, 100, 100, 100, false, -1);
    NM_CHECK(set && !net_tip_regression_test_detect()); /* baseline */
    net_tip_regression_test_set_now(10011);
    inject_view(3, 100, 103, 110, false, -1);
    bool held_default = !net_tip_regression_test_detect();
    NM_CHECK(held_default);
    net_tip_regression_test_reset();

    bool valid_set = setenv(var, "10", 1) == 0;
    net_tip_regression_test_set_now(11000);
    inject_view(3, 100, 100, 100, false, -1);
    bool valid_first = !net_tip_regression_test_detect();
    net_tip_regression_test_set_now(11010);
    inject_view(3, 100, 103, 110, false, -1);
    bool valid_detected = net_tip_regression_test_detect();
    NM_CHECK(valid_set && valid_first && valid_detected);
    net_tip_regression_test_reset();

    if (saved)
        (void)setenv(var, saved, 1);
    else
        (void)unsetenv(var);
    free(saved);
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

/* A malformed interval must not silently turn the six-hundred-second
 * partition signal into a ten-second one merely because it has a numeric
 * prefix. Preserve any caller override exactly. */
static int test_partition_rejects_malformed_window(void)
{
    int failures = 0;
    const char *var = "ZCL_NET_PARTITION_SECS";
    const char *old = getenv(var);
    char *saved = old ? strdup(old) : NULL;
    if (old && !saved)
        return 1;

    bool set = setenv(var, "10junk", 1) == 0;
    net_partition_suspected_test_reset();
    net_partition_suspected_test_set_now(10000);
    inject_view(1, 100, 100, 100, false, -1);
    bool first = !net_partition_suspected_test_detect();
    net_partition_suspected_test_set_now(10011);
    inject_view(1, 100, 100, 100, false, -1);
    bool held_default = !net_partition_suspected_test_detect();
    net_partition_suspected_test_set_now(10600);
    inject_view(1, 100, 100, 100, false, -1);
    bool default_detected = net_partition_suspected_test_detect();
    NM_CHECK(set && first && held_default && default_detected);
    net_partition_suspected_test_reset();

    bool valid_set = setenv(var, "10", 1) == 0;
    net_partition_suspected_test_set_now(11000);
    inject_view(1, 100, 100, 100, false, -1);
    bool valid_first = !net_partition_suspected_test_detect();
    net_partition_suspected_test_set_now(11010);
    inject_view(1, 100, 100, 100, false, -1);
    bool valid_detected = net_partition_suspected_test_detect();
    NM_CHECK(valid_set && valid_first && valid_detected);
    net_partition_suspected_test_reset();

    if (saved)
        (void)setenv(var, saved, 1);
    else
        (void)unsetenv(var);
    free(saved);
    return failures;
}

int network_monitor_fold_tests(void);

/* ── 4. supervisor registration pairs with start/stop ────────────────── */
static int run_restart_registration_case(void)
{
    int failures = 0;
    printf("network_monitor: stop unregisters, restart registers once...\n");
    int base = supervisor_child_count_total();

    struct network_monitor_config cfg;
    network_monitor_config_defaults(&cfg);
    for (int round = 0; round < 2; round++) {
        struct zcl_result r = network_monitor_start(&cfg, NULL);
        NM_CHECK(r.ok);
        if (!r.ok)
            return failures;
        NM_CHECK(supervisor_child_count_total() == base + 1);
        network_monitor_stop();
        NM_CHECK(supervisor_child_count_total() == base);
    }
    network_monitor_stop(); /* a second stop stays a no-op */
    NM_CHECK(supervisor_child_count_total() == base);
    return failures;
}

int test_network_monitor(void)
{
    printf("\n=== network_monitor tests ===\n");
    int failures = 0;
    failures += test_observation_model();
    failures += test_failed_retention_bounds_history();
    failures += test_prune_sparse_boundaries();
    failures += test_prune_diagnostic();
    failures += test_consensus_view();
    failures += test_tip_regression_condition();
    failures += test_tip_regression_rejects_malformed_window();
    failures += test_fork_condition();
    failures += test_partition_condition();
    failures += test_partition_rejects_malformed_window();
    failures += network_monitor_fold_tests();
    failures += run_restart_registration_case();
    if (failures == 0)
        printf("=== network_monitor: all passed ===\n");
    else
        printf("=== network_monitor: %d FAILED ===\n", failures);
    return failures;
}
