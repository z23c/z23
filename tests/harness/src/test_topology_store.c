/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for topology_store (engine/modules/storage/src/topology_store.c) — the
 * P2P topology graph: "node X advertised address Y".
 *
 * Coverage:
 *   - open creates <datadir>/topology.db with the edges + sweeps tables
 *   - record_edge creates a new edge, and re-recording the SAME edge
 *     upserts (times_seen increments, last_advertised bumps,
 *     first_advertised stays fixed)
 *   - non-routable garbage (0.0.0.0, loopback, RFC1918 private) is
 *     rejected — never stored
 *   - distinct onion (torv3) addresses render distinct identities and
 *     never collapse into one topology node
 *   - out_new_advertised_node fires exactly once per newly-seen advertised
 *     node, regardless of which observer reports it first
 *   - bounded-upsert cap eviction removes the globally oldest
 *     last_advertised rows and never exceeds the cap
 *   - record_self_edge (crawler results) and record_sweep (sweep summary
 *     ledger) both work end to end
 *   - dump_state_json reports open/edge_count/top_advertised/last_sweep */

#include "test/test_core.h"

#include "json/json.h"
#include "net/netaddr.h"
#include "storage/topology_store.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TS_CHECK(name, expr) do { \
    printf("topology_store: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)


static struct net_addr ts_ipv4(unsigned char a, unsigned char b,
                               unsigned char c, unsigned char d)
{
    struct net_addr addr;
    net_addr_init(&addr);
    unsigned char ip4[4] = { a, b, c, d };
    net_addr_set_ipv4(&addr, ip4);
    return addr;
}

static struct net_addr ts_onion(unsigned char fill)
{
    struct net_addr addr;
    net_addr_init(&addr);
    addr.has_torv3 = true;
    memset(addr.torv3, fill, sizeof(addr.torv3));
    return addr;
}

int test_topology_store(void)
{
    printf("\n=== topology_store tests ===\n");
    int failures = 0;

    /* ── open creates the file + both tables ─────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "open");

        TS_CHECK("first open succeeds", topology_store_open(dir));
        TS_CHECK("second open is idempotent (same handle, no error)",
                 topology_store_open(dir));

        struct stat st;
        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/topology.db", dir);
        TS_CHECK("topology.db file exists", stat(fpath, &st) == 0);

        topology_store_close();
        TS_CHECK("record_edge no-ops (false) once closed",
                 !topology_store_record_edge(NULL, 0, NULL, 0, 0, NULL));
        test_cleanup_tmpdir(dir);
    }

    /* ── record_edge: new edge, then upsert on re-observation ───────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "upsert");
        TS_CHECK("open for upsert", topology_store_open(dir));
        topology_store_test_reset();

        struct net_addr observer = ts_ipv4(81, 214, 132, 5);
        struct net_addr advertised = ts_ipv4(66, 70, 182, 7);

        bool is_new = false;
        TS_CHECK("first observation recorded",
                 topology_store_record_edge(&observer, 8033, &advertised,
                                            8033, 1000, &is_new));
        TS_CHECK("first observation is a new node", is_new);
        TS_CHECK("edge_count == 1 after first observation",
                 topology_store_test_edge_count() == 1);

        is_new = true; /* poison to prove it gets cleared to false */
        TS_CHECK("re-observation (same edge) upserts, not duplicates",
                 topology_store_record_edge(&observer, 8033, &advertised,
                                            8033, 2000, &is_new));
        TS_CHECK("re-observation is NOT a new node", !is_new);
        TS_CHECK("edge_count stays 1 (upsert, not insert)",
                 topology_store_test_edge_count() == 1);

        /* A different observer reporting the SAME advertised node is a new
         * EDGE (distinct observer,advertised pair) but not a new NODE. */
        struct net_addr observer2 = ts_ipv4(81, 214, 132, 9);
        is_new = true;
        TS_CHECK("second observer, same node: recorded",
                 topology_store_record_edge(&observer2, 8033, &advertised,
                                            8033, 3000, &is_new));
        TS_CHECK("second observer, same node: NOT a new node", !is_new);
        TS_CHECK("edge_count == 2 (two distinct observer edges)",
                 topology_store_test_edge_count() == 2);

        topology_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── PEDANTIC: non-routable garbage rejected, never stored ───────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "reject");
        TS_CHECK("open for reject", topology_store_open(dir));
        topology_store_test_reset();

        struct net_addr good_observer = ts_ipv4(81, 214, 132, 1);
        struct net_addr unspecified = ts_ipv4(0, 0, 0, 0);
        struct net_addr loopback = ts_ipv4(127, 0, 0, 1);
        struct net_addr rfc1918 = ts_ipv4(192, 168, 1, 1);
        struct net_addr rfc5737_doc = ts_ipv4(192, 0, 2, 55); /* TEST-NET-1 */

        TS_CHECK("unspecified 0.0.0.0 advertised rejected",
                 !topology_store_record_edge(&good_observer, 8033,
                                             &unspecified, 8033, 100, NULL));
        TS_CHECK("loopback 127.0.0.1 advertised rejected",
                 !topology_store_record_edge(&good_observer, 8033, &loopback,
                                             8033, 100, NULL));
        TS_CHECK("RFC1918 private 192.168.1.1 advertised rejected",
                 !topology_store_record_edge(&good_observer, 8033, &rfc1918,
                                             8033, 100, NULL));
        TS_CHECK("RFC5737 documentation range rejected",
                 !topology_store_record_edge(&good_observer, 8033,
                                             &rfc5737_doc, 8033, 100, NULL));
        TS_CHECK("a non-routable observer is rejected too",
                 !topology_store_record_edge(&loopback, 8033, &good_observer,
                                             8033, 100, NULL));
        TS_CHECK("nothing got stored — edge_count stays 0",
                 topology_store_test_edge_count() == 0);

        topology_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── distinct onion identities never collapse ─────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "onion");
        TS_CHECK("open for onion", topology_store_open(dir));
        topology_store_test_reset();

        struct net_addr observer = ts_ipv4(81, 214, 132, 20);
        struct net_addr onion_a = ts_onion(0xaa);
        struct net_addr onion_b = ts_onion(0xbb);

        TS_CHECK("onion node A recorded",
                 topology_store_record_edge(&observer, 8033, &onion_a, 8033,
                                            100, NULL));
        TS_CHECK("onion node B recorded",
                 topology_store_record_edge(&observer, 8033, &onion_b, 8033,
                                            100, NULL));
        TS_CHECK("two DISTINCT onion identities -> two edges (no collapse)",
                 topology_store_test_edge_count() == 2);

        topology_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── bounded-upsert cap eviction ──────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "evict");
        TS_CHECK("open for evict", topology_store_open(dir));
        topology_store_test_reset();
        topology_store_test_set_cap(5);

        struct net_addr observer = ts_ipv4(81, 214, 132, 30);
        for (int i = 0; i < 10; i++) {
            struct net_addr advertised = ts_ipv4(66, 70, 182, (unsigned char)i);
            /* Strictly increasing last_advertised so eviction order (oldest
             * last_advertised first) is deterministic and provable. */
            (void)topology_store_record_edge(&observer, 8033, &advertised,
                                             8033, 1000 + i, NULL);
        }
        TS_CHECK("row count never exceeds the lowered cap",
                 topology_store_test_edge_count() == 5);

        /* The 5 SURVIVORS must be the 5 most-recently-advertised (i=5..9);
         * the earliest (i=0) must be gone. */
        struct net_addr oldest = ts_ipv4(66, 70, 182, 0);
        struct net_addr newest = ts_ipv4(66, 70, 182, 9);
        bool oldest_is_new = false, newest_is_new = false;
        (void)topology_store_record_edge(&observer, 8033, &oldest, 8033,
                                         1000, &oldest_is_new);
        (void)topology_store_record_edge(&observer, 8033, &newest, 8033,
                                         1009, &newest_is_new);
        TS_CHECK("oldest edge (i=0) was evicted (re-insert reports \"new\")",
                 oldest_is_new);
        TS_CHECK("newest edge (i=9) survived (re-insert is NOT \"new\")",
                 !newest_is_new);

        topology_store_test_set_cap(0); /* restore default */
        topology_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── record_self_edge (crawler results) + record_sweep ────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "sweep");
        TS_CHECK("open for sweep", topology_store_open(dir));
        topology_store_test_reset();

        struct net_addr reached = ts_ipv4(66, 70, 182, 40);
        bool is_new = false;
        TS_CHECK("record_self_edge accepted",
                 topology_store_record_self_edge(&reached, 8033, 5000,
                                                 &is_new));
        TS_CHECK("record_self_edge: first sighting is new", is_new);
        TS_CHECK("edge_count == 1 after one self edge",
                 topology_store_test_edge_count() == 1);

        TS_CHECK("sweep_count starts at 0",
                 topology_store_test_sweep_count() == 0);
        TS_CHECK("record_sweep appended",
                 topology_store_record_sweep(5000, 5010, 64, 40, 40, 12));
        TS_CHECK("sweep_count == 1 after one sweep",
                 topology_store_test_sweep_count() == 1);
        TS_CHECK("record_sweep appended a second row",
                 topology_store_record_sweep(5100, 5111, 64, 30, 30, 5));
        TS_CHECK("sweep_count == 2 after a second sweep",
                 topology_store_test_sweep_count() == 2);

        topology_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── dump_state_json surfaces the graph summary ───────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "topology_store", "dump");
        TS_CHECK("open for dump", topology_store_open(dir));
        topology_store_test_reset();

        struct net_addr observer = ts_ipv4(81, 214, 132, 50);
        struct net_addr popular = ts_ipv4(66, 70, 182, 50);
        struct net_addr rare = ts_ipv4(66, 70, 182, 51);
        struct net_addr observer2 = ts_ipv4(81, 214, 132, 51);
        (void)topology_store_record_edge(&observer, 8033, &popular, 8033,
                                         100, NULL);
        (void)topology_store_record_edge(&observer2, 8033, &popular, 8033,
                                         100, NULL);
        (void)topology_store_record_edge(&observer, 8033, &rare, 8033, 100,
                                         NULL);
        (void)topology_store_record_sweep(100, 110, 3, 3, 3, 2);

        struct json_value j;
        json_init(&j);
        TS_CHECK("dump_state_json returns true",
                 topology_store_dump_state_json(&j, NULL));

        const struct json_value *open_v = json_get(&j, "open");
        TS_CHECK("dump reports open=true",
                 open_v != NULL && json_get_bool(open_v) == true);
        const struct json_value *ec = json_get(&j, "edge_count");
        TS_CHECK("dump reports edge_count == 3",
                 ec != NULL && json_get_int(ec) == 3);
        const struct json_value *dobs = json_get(&j, "distinct_observers");
        TS_CHECK("dump reports distinct_observers == 2",
                 dobs != NULL && json_get_int(dobs) == 2);
        const struct json_value *dadv =
            json_get(&j, "distinct_advertised_nodes");
        TS_CHECK("dump reports distinct_advertised_nodes == 2",
                 dadv != NULL && json_get_int(dadv) == 2);

        const struct json_value *top = json_get(&j, "top_advertised");
        TS_CHECK("dump includes top_advertised array",
                 top != NULL && top->type == JSON_ARR &&
                 json_size(top) >= 1);
        if (top && json_size(top) >= 1) {
            const struct json_value *first = json_at(top, 0);
            const struct json_value *indeg =
                first ? json_get(first, "in_degree") : NULL;
            TS_CHECK("top_advertised[0] is the higher-in-degree node",
                     indeg != NULL && json_get_int(indeg) == 2);
        }

        const struct json_value *last_sweep = json_get(&j, "last_sweep");
        TS_CHECK("dump includes last_sweep", last_sweep != NULL);
        if (last_sweep) {
            const struct json_value *es = json_get(last_sweep, "edges_seen");
            TS_CHECK("last_sweep edges_seen == 3",
                     es != NULL && json_get_int(es) == 3);
        }

        json_free(&j);
        topology_store_close();
        test_cleanup_tmpdir(dir);
    }

    printf("topology_store: %d failures\n", failures);
    return failures;
}
