/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the network-omniscience operator READ surface (engine/modules/storage/src/
 * census_read.c) that backs the `net census|node|versions|graph` commands and
 * the explorer /network page. The reader folds TWO real writer stores:
 *   <datadir>/peers_projection.db : node_census, census_observations (ip BLOB)
 *   <datadir>/topology.db         : topology_edges, topology_sweeps (ip TEXT)
 *
 * Coverage:
 *   0. schema parity: the VERBATIM fixture DDL matches the columns the REAL
 *      writers create (peers_projection_open / topology_store_open) — future
 *      column drift fails this test loudly.
 *   1. empty-store degradation: no peers_projection.db → CENSUS_READ_DB_ABSENT
 *      (never an error); a file whose node_census table is missing →
 *      CENSUS_READ_TABLES_ABSENT.
 *   2. list + filters + pagination on a fixture-populated census, and the hard
 *      row cap / past-end offset bounds.
 *   3. one-node lookup with bounded observation history + topology edges.
 *   4. version distribution + graph/topology stats + sweep freshness.
 *   5. the explorer /network page renders bounded HTML with fixture data, and
 *      renders the "census empty" card when the store is absent.
 *
 * Every SELECT in census_read.c is exercised against the fixtures.
 *
 * One TEST()/ASSERT() block per function (the TEST macro uses a single fixed
 * `_test_next:` label per function).
 */

#include "test/test_core.h"
#include "services/network_crawler.h"
#include "storage/census_read.h"
#include "storage/peers_projection.h"
#include "storage/topology_store.h"
#include "storage/event_log.h"
#include "views/explorer_pages_view.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── fixture ─────────────────────────────────────────────────────────── */

static struct census_node mknode(const char *ip, int port, const char *ua,
                                 int64_t pv, int64_t height, int64_t last_seen)
{
    struct census_node n;
    memset(&n, 0, sizeof(n));
    snprintf(n.ip, sizeof(n.ip), "%s", ip);
    n.port = port;
    snprintf(n.user_agent, sizeof(n.user_agent), "%s", ua);
    n.protocol_version = pv;
    n.services = 1;
    n.reported_height = height;
    n.first_seen = last_seen - 1000;
    n.last_seen = last_seen;
    n.last_success = last_seen;      /* reachable */
    n.dial_success_count = 3;
    n.dial_fail_count = 2;
    return n;
}

/* Seed a canonical census with 4 nodes + edges + observations + one sweep.
 * now is the reference clock for the recency filter. */
static bool seed_census(const char *dir, int64_t now)
{
    if (!census_read_test_create_schema(dir))
        return false;
    struct census_node a = mknode("203.0.113.1", 8033, "/MagicBean:2.1.2/",
                                  170002, 3200000, now - 60);
    struct census_node b = mknode("203.0.113.2", 8033, "/MagicBean:2.1.1/",
                                  170002, 3199000, now - 120);
    struct census_node c = mknode("198.51.100.9", 8033, "/Zclassic23:0.1.0/",
                                  180000, 3200500, now - 30);
    struct census_node d = mknode("192.0.2.7", 8033, "/MagicBean:2.1.2/",
                                  170002, 1000000, now - 200000); /* stale */
    if (!census_read_test_insert_node(dir, &a) ||
        !census_read_test_insert_node(dir, &b) ||
        !census_read_test_insert_node(dir, &c) ||
        !census_read_test_insert_node(dir, &d))
        return false;
    /* Topology: two observers both advertise c's endpoint; a advertises b. */
    if (!census_read_test_insert_edge(dir, "203.0.113.1", 8033,
                                      "198.51.100.9", 8033, 7, now - 40) ||
        !census_read_test_insert_edge(dir, "203.0.113.2", 8033,
                                      "198.51.100.9", 8033, 3, now - 50) ||
        !census_read_test_insert_edge(dir, "203.0.113.1", 8033,
                                      "203.0.113.2", 8033, 2, now - 70))
        return false;
    /* Observations for c. */
    if (!census_read_test_insert_observation(dir, "198.51.100.9", 8033,
                                             now - 30, 3200500,
                                             "/Zclassic23:0.1.0/", 180000, 1) ||
        !census_read_test_insert_observation(dir, "198.51.100.9", 8033,
                                             now - 90, 3200400,
                                             "/Zclassic23:0.1.0/", 180000, 1))
        return false;
    /* One completed crawler sweep (census freshness). */
    if (!census_read_test_insert_sweep(dir, now - 300, now - 10, 4, 3, 3, 4))
        return false;
    return true;
}

/* Collect a table's column names (in cid order, '|'-joined) from a db file. */
static bool columns_of(const char *dbpath, const char *table, char *out,
                       size_t cap)
{
    out[0] = '\0';
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK;
    size_t off = 0;
    while (ok && sqlite3_step(s) == SQLITE_ROW) { // raw-sql-ok:test-read
        const char *name = (const char *)sqlite3_column_text(s, 1);
        int n = snprintf(out + off, cap - off, "%s|", name ? name : "?");
        if (n > 0 && (size_t)n < cap - off) off += (size_t)n;
    }
    sqlite3_finalize(s);
    sqlite3_close(db);
    return ok && out[0] != '\0';
}

/* ── 0. schema parity: fixture DDL vs real writer DDL ─────────────────── */

static int test_census_schema_parity(void)
{
    int failures = 0;
    TEST("census_read: VERBATIM fixture schema matches the real writer schema") {
        /* Fixture (verbatim CREATE TABLE copies) in one datadir. */
        char fixdir[256];
        test_make_tmpdir(fixdir, sizeof(fixdir), "net_census_fix", "main");
        ASSERT(census_read_test_create_schema(fixdir));

        /* Real writer schema in a second datadir, created by the production
         * openers themselves (drift-proof: they own the authoritative DDL). */
        char proddir[256];
        test_make_tmpdir(proddir, sizeof(proddir), "net_census_prod", "main");

        char elog[300], peers[300];
        snprintf(elog, sizeof(elog), "%s/events.log", proddir);
        snprintf(peers, sizeof(peers), "%s/peers_projection.db", proddir);
        event_log_t *log = event_log_open(elog);
        ASSERT(log != NULL);
        peers_projection_t *p = peers_projection_open(peers, log);
        ASSERT(p != NULL);
        peers_projection_close(p);
        event_log_close(log);

        ASSERT(topology_store_open(proddir));
        topology_store_close();

        /* Compare the column sets of every table the reader SELECTs. */
        char fixp[300], prodp[300], fixt[300], prodt[300];
        snprintf(fixp, sizeof(fixp), "%s/peers_projection.db", fixdir);
        snprintf(prodp, sizeof(prodp), "%s/peers_projection.db", proddir);
        snprintf(fixt, sizeof(fixt), "%s/topology.db", fixdir);
        snprintf(prodt, sizeof(prodt), "%s/topology.db", proddir);

        char fc[512], pc[512];
        const char *tbl;

        tbl = "node_census";
        ASSERT(columns_of(fixp, tbl, fc, sizeof(fc)));
        ASSERT(columns_of(prodp, tbl, pc, sizeof(pc)));
        ASSERT_STR_EQ(fc, pc);

        tbl = "census_observations";
        ASSERT(columns_of(fixp, tbl, fc, sizeof(fc)));
        ASSERT(columns_of(prodp, tbl, pc, sizeof(pc)));
        ASSERT_STR_EQ(fc, pc);

        tbl = "topology_edges";
        ASSERT(columns_of(fixt, tbl, fc, sizeof(fc)));
        ASSERT(columns_of(prodt, tbl, pc, sizeof(pc)));
        ASSERT_STR_EQ(fc, pc);

        tbl = "topology_sweeps";
        ASSERT(columns_of(fixt, tbl, fc, sizeof(fc)));
        ASSERT(columns_of(prodt, tbl, pc, sizeof(pc)));
        ASSERT_STR_EQ(fc, pc);

        PASS();
    } _test_next:;
    return failures;
}

/* ── 1. empty-store degradation ──────────────────────────────────────── */

static int test_census_empty_degradation(void)
{
    int failures = 0;
    TEST("census_read: absent census file degrades to DB_ABSENT, never error") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_census_empty", "main");

        census_reader *r = NULL;
        enum census_read_status st = census_read_open(dir, &r);
        ASSERT(st == CENSUS_READ_DB_ABSENT);
        ASSERT(r == NULL);
        /* Every accessor is NULL-safe / empty on the degraded reader. */
        ASSERT(census_read_node_total(NULL) == 0);
        struct census_node rows[CENSUS_LIST_HARD_CAP];
        int64_t matched = 7;
        ASSERT(census_read_list(NULL, NULL, 0, 25, rows, CENSUS_LIST_HARD_CAP,
                                &matched) == 0);
        ASSERT(matched == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_census_tables_absent(void)
{
    int failures = 0;
    TEST("census_read: file present but node_census missing → TABLES_ABSENT") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_census_notable", "main");

        /* Create the primary census DB file with an UNRELATED table only, so
         * the file opens but node_census is absent. */
        char path[600];
        ASSERT(census_read_db_path(dir, path, sizeof(path)));
        sqlite3 *db = NULL;
        ASSERT(sqlite3_open_v2(path, &db,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                               NULL) == SQLITE_OK);
        ASSERT(sqlite3_exec(db, "CREATE TABLE unrelated(x INTEGER)",
                            NULL, NULL, NULL) == SQLITE_OK);
        sqlite3_close(db);

        census_reader *r = NULL;
        enum census_read_status st = census_read_open(dir, &r);
        ASSERT(st == CENSUS_READ_TABLES_ABSENT);
        ASSERT(r == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. list + filters + pagination bounds ───────────────────────────── */

static int test_census_list_and_filters(void)
{
    int failures = 0;
    TEST("census_read: list orders by last_seen, filters, and bounds pages") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_census_list", "main");
        int64_t now = 1750000000;
        ASSERT(seed_census(dir, now));

        census_reader *r = NULL;
        ASSERT(census_read_open(dir, &r) == CENSUS_READ_OK);
        ASSERT(r != NULL);
        ASSERT(census_read_node_total(r) == 4);

        struct census_node rows[CENSUS_LIST_HARD_CAP];
        int64_t matched = 0;

        /* No filter: all 4, newest last_seen first (c is newest at now-30). */
        int n = census_read_list(r, NULL, 0, 25, rows, CENSUS_LIST_HARD_CAP,
                                 &matched);
        ASSERT(n == 4);
        ASSERT(matched == 4);
        ASSERT_STR_EQ(rows[0].ip, "198.51.100.9");
        ASSERT(rows[0].reported_height == 3200500);
        ASSERT(rows[0].reachable);        /* dial_success_count 3 > 0 */
        ASSERT(rows[0].dial_success_count == 3);
        ASSERT(rows[0].dial_fail_count == 2);

        /* ua-contains filter: only the two MagicBean:2.1.2 + 2.1.1 → 3 nodes. */
        struct census_filter f = { .ua_contains = "MagicBean",
                                   .min_height = -1, .seen_within_secs = -1 };
        n = census_read_list(r, &f, 0, 25, rows, CENSUS_LIST_HARD_CAP, &matched);
        ASSERT(matched == 3);
        ASSERT(n == 3);

        /* min_height filter: last_reported_height >= 3200000 → a and c. */
        struct census_filter fh = { .min_height = 3200000,
                                    .seen_within_secs = -1 };
        n = census_read_list(r, &fh, 0, 25, rows, CENSUS_LIST_HARD_CAP,
                             &matched);
        ASSERT(matched == 2);

        /* seen_within filter: last 1000s → excludes the stale node d. */
        struct census_filter fs = { .min_height = -1,
                                    .seen_within_secs = 1000, .now_unix = now };
        n = census_read_list(r, &fs, 0, 25, rows, CENSUS_LIST_HARD_CAP,
                             &matched);
        ASSERT(matched == 3);

        /* Pagination: page size 2, offset 0 then 2, covers all 4 without dup. */
        int p0 = census_read_list(r, NULL, 0, 2, rows, CENSUS_LIST_HARD_CAP,
                                  &matched);
        ASSERT(p0 == 2);
        char first_ip[64];
        snprintf(first_ip, sizeof(first_ip), "%s", rows[0].ip);
        int p1 = census_read_list(r, NULL, 2, 2, rows, CENSUS_LIST_HARD_CAP,
                                  &matched);
        ASSERT(p1 == 2);
        ASSERT(strcmp(rows[0].ip, first_ip) != 0);

        /* Bounds: a limit above the hard cap is clamped; a past-end offset is
         * empty; matched still reports the true total. */
        int capd = census_read_list(r, NULL, 0, 100000, rows,
                                    CENSUS_LIST_HARD_CAP, &matched);
        ASSERT(capd <= CENSUS_LIST_HARD_CAP);
        ASSERT(capd == 4);
        int past = census_read_list(r, NULL, 999, 25, rows,
                                    CENSUS_LIST_HARD_CAP, &matched);
        ASSERT(past == 0);
        ASSERT(matched == 4);

        census_read_close(r);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. one-node lookup ──────────────────────────────────────────────── */

static int test_census_node_lookup(void)
{
    int failures = 0;
    TEST("census_read: node lookup returns row + bounded obs + edges") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_census_node", "main");
        int64_t now = 1750000000;
        ASSERT(seed_census(dir, now));

        census_reader *r = NULL;
        ASSERT(census_read_open(dir, &r) == CENSUS_READ_OK);

        struct census_node node;
        struct census_observation obs[CENSUS_MAX_OBSERVATIONS];
        struct census_edge edges[CENSUS_MAX_EDGES];
        int obs_n = 0, edge_n = 0;

        bool found = census_read_node(r, "198.51.100.9", 8033, &node,
                                      obs, CENSUS_MAX_OBSERVATIONS, &obs_n,
                                      edges, CENSUS_MAX_EDGES, &edge_n);
        ASSERT(found);
        ASSERT(node.reported_height == 3200500);
        ASSERT_STR_EQ(node.user_agent, "/Zclassic23:0.1.0/");
        ASSERT(obs_n == 2);
        ASSERT(obs[0].reported_height == 3200500); /* newest first */
        ASSERT(obs[0].services == 1);
        /* c is advertised by two observers → 2 edges reference its endpoint. */
        ASSERT(edge_n == 2);
        ASSERT_STR_EQ(edges[0].advertised, "198.51.100.9:8033");

        /* Absent endpoint → found=false, counts zeroed. */
        bool miss = census_read_node(r, "10.0.0.1", 8033, &node,
                                     obs, CENSUS_MAX_OBSERVATIONS, &obs_n,
                                     edges, CENSUS_MAX_EDGES, &edge_n);
        ASSERT(!miss);
        ASSERT(obs_n == 0 && edge_n == 0);

        census_read_close(r);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. versions + graph ─────────────────────────────────────────────── */

static int test_census_versions_and_graph(void)
{
    int failures = 0;
    TEST("census_read: version distribution + graph stats are correct") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_census_vg", "main");
        int64_t now = 1750000000;
        ASSERT(seed_census(dir, now));

        census_reader *r = NULL;
        ASSERT(census_read_open(dir, &r) == CENSUS_READ_OK);

        struct census_version_bucket vb[CENSUS_MAX_VERSION_BUCKETS];
        int nv = census_read_versions(r, vb, CENSUS_MAX_VERSION_BUCKETS);
        /* Three distinct UAs: 2.1.2 (x2), 2.1.1 (x1), Zclassic23 (x1). */
        ASSERT(nv == 3);
        /* Descending by count → the 2.1.2 bucket (count 2) is first. */
        ASSERT(vb[0].count == 2);
        ASSERT_STR_EQ(vb[0].user_agent, "/MagicBean:2.1.2/");
        ASSERT(vb[0].max_reported_height == 3200000);

        struct census_graph_stats g;
        ASSERT(census_read_graph(r, &g));
        ASSERT(g.node_count == 4);
        ASSERT(g.edge_count == 3);
        ASSERT(g.observation_count == 2);
        /* Two DISTINCT advertised endpoints are themselves in the census
         * (c=198.51.100.9:8033 and b=203.0.113.2:8033). */
        ASSERT(g.advertised_in_census == 2);
        ASSERT(g.top_count >= 1);
        /* Most-advertised endpoint is c (summed times_seen 7+3=10). */
        ASSERT_STR_EQ(g.top[0].advertised, "198.51.100.9:8033");
        ASSERT(g.top[0].times_seen == 10);
        ASSERT(g.top[0].distinct_observers == 2);
        /* Census freshness: the last completed sweep finished at now-10. */
        ASSERT(g.sweeps_total == 1);
        ASSERT(g.last_sweep_finished_unix == now - 10);

        census_read_close(r);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. explorer /network page ───────────────────────────────────────── */

static int test_census_explorer_page(void)
{
    int failures = 0;
    TEST("explorer /network renders bounded HTML for fixture and empty store") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_census_explorer", "main");
        int64_t now = 1750000000;
        ASSERT(seed_census(dir, now));

        size_t cap = 262144;
        uint8_t *buf = malloc(cap);
        ASSERT(buf != NULL);

        size_t n = explorer_view_network(dir, buf, cap);
        ASSERT(n > 0);
        ASSERT(n < cap); /* bounded: never fills the whole buffer */
        buf[n < cap ? n : cap - 1] = '\0';
        ASSERT(strstr((char *)buf, "Network") != NULL);
        ASSERT(strstr((char *)buf, "Version distribution") != NULL);
        ASSERT(strstr((char *)buf, "MagicBean") != NULL);
        ASSERT(strstr((char *)buf, "198.51.100.9:8033") != NULL);

        /* Empty store → the "census empty" degradation card, still HTTP 200. */
        char empty[256];
        test_make_tmpdir(empty, sizeof(empty), "net_census_explorer_empty",
                         "main");
        size_t m = explorer_view_network(empty, buf, cap);
        ASSERT(m > 0);
        ASSERT(m < cap);
        buf[m < cap ? m : cap - 1] = '\0';
        ASSERT(strstr((char *)buf, "census empty") != NULL);

        free(buf);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. crawler default gate: ON by default (omniscience) ─────────────── */

static int test_crawler_default_gate(void)
{
    int failures = 0;
    TEST("network_crawler: ON by default (omniscience directive)") {
        struct network_crawler_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        network_crawler_config_defaults(&cfg);
        /* The dialer defaults ON so a plain boot obsesses about the whole
         * network; -netcrawl=0 / ZCL_NETWORK_CRAWLER=0 opt out (resolved in
         * network_crawler_start via ncrawl_config_from_env). The rate limits
         * stay bounded for always-on. */
        ASSERT(cfg.enabled);
        ASSERT(cfg.max_per_round >= 1 &&
               cfg.max_per_round <= NCRAWL_MAX_PER_ROUND);
        ASSERT(cfg.max_concurrent >= 1 &&
               cfg.max_concurrent <= NCRAWL_MAX_CONCURRENT);
        ASSERT(cfg.round_interval_secs >= 5);
        PASS();
    } _test_next:;
    return failures;
}

int test_net_census(void);
int test_net_census(void)
{
    int failures = 0;
    failures += test_census_schema_parity();
    failures += test_crawler_default_gate();
    failures += test_census_empty_degradation();
    failures += test_census_tables_absent();
    failures += test_census_list_and_filters();
    failures += test_census_node_lookup();
    failures += test_census_versions_and_graph();
    failures += test_census_explorer_page();
    return failures;
}
