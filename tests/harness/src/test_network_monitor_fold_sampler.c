/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_monitor sampler tests: the real sampler thread over a fake connman,
 * one installed active-chain slot and a temp sqlite file. Aimed at the
 * snapshot, header-vote, persistence and fork-ledger survivors of the
 * network_monitor.c mutation sweep. Entry point
 * network_monitor_fold_sampler_tests(), called from
 * network_monitor_fold_tests(). */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/uint256.h"
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

int network_monitor_fold_sampler_tests(void);

#define NMS_CHECK(cond) do { \
    if (cond) { /* pass */ } \
    else { printf("  FAIL: %s (line %d)\n", #cond, __LINE__); failures++; } \
} while (0)

enum { NMS_NODES = 12 };

static struct connman g_cm;
static struct download_manager g_dm;
static struct main_state g_ms;
static struct block_index g_tip;
static struct p2p_node g_nodes[NMS_NODES];
static struct p2p_node *g_ptrs[NMS_NODES + 1];

static void nms_hash(char *dst, char c)
{
    memset(dst, c, PEER_OBS_TIP_HEX);
    dst[PEER_OBS_TIP_HEX] = '\0';
}

static void nms_node(struct p2p_node *n, node_id_t id, enum peer_state st,
                     unsigned char a, unsigned char b, int height)
{
    unsigned char ip[4] = { a, b, 0, (unsigned char)id };
    memset(n, 0, sizeof(*n));
    n->id = id;
    n->state = st;
    net_addr_set_ipv4(&n->addr.svc.addr, ip);
    snprintf(n->addr_name, sizeof(n->addr_name), "%u.%u.0.%u:8033", a, b,
             (unsigned)(unsigned char)id);
    snprintf(n->clean_sub_ver, sizeof(n->clean_sub_ver), "/ua%d/", (int)id);
    n->version = 170100 + (int)id;
    n->starting_height = height;
    n->avg_latency_us = 1000 + (int64_t)id;
    n->inbound = (id & 1) != 0;
    n->time_connected = 111;
    n->last_recv = 222;
}

/* Build the peer set. Returns the number of slots used. */
static int nms_build_peers(const char *our_hex)
{
    char rival[65], other[65], third[65];
    nms_hash(rival, 'b');
    nms_hash(other, 'c');
    nms_hash(third, 'e');
    int k = 0;
    /* three peers on our tip (public space: RFC1918 collapses to one group): two share a /16 group, one is elsewhere */
    nms_node(&g_nodes[k++], 1, PEER_HANDSHAKE_COMPLETE, 20, 1, 10);
    nms_node(&g_nodes[k++], 2, PEER_HANDSHAKE_COMPLETE, 20, 1, 4);
    nms_node(&g_nodes[k++], 3, PEER_HANDSHAKE_COMPLETE, 20, 2, 10);
    /* two rival peers in two groups */
    nms_node(&g_nodes[k++], 4, PEER_HANDSHAKE_COMPLETE, 11, 1, 10);
    nms_node(&g_nodes[k++], 5, PEER_HANDSHAKE_COMPLETE, 11, 2, 10);
    /* skipped: disconnecting, and short of the handshake */
    nms_node(&g_nodes[k], 6, PEER_HANDSHAKE_COMPLETE, 12, 1, 99);
    g_nodes[k++].disconnect = true;
    nms_node(&g_nodes[k++], 7, PEER_CONNECTED, 12, 2, 98);
    /* vote height lower than the handshake height must not win */
    nms_node(&g_nodes[k++], 9, PEER_HANDSHAKE_COMPLETE, 10, 3, 12);
    nms_node(&g_nodes[k++], 10, PEER_HANDSHAKE_COMPLETE, 10, 5, 10);
    nms_node(&g_nodes[k++], 11, PEER_HANDSHAKE_COMPLETE, 10, 4, 7);
    network_monitor_note_peer_header(1, 5, rival);      /* superseded below */
    network_monitor_note_peer_header(1, 10, our_hex);
    network_monitor_note_peer_header(2, 10, our_hex);
    network_monitor_note_peer_header(3, 10, our_hex);
    network_monitor_note_peer_header(4, 10, rival);
    network_monitor_note_peer_header(5, 10, rival);
    network_monitor_note_peer_header(9, 3, other);
    network_monitor_note_peer_header(10, 10, third);
    network_monitor_note_peer_header(8, -1, rival);     /* negative: refused */
    network_monitor_note_peer_header(8, 10, NULL);      /* NULL hash: refused */
    return k;
}

static void nms_fill_votes_and_evict(void)
{
    char h[65];
    nms_hash(h, 'v');
    /* 7 relevant ids hold slots 0..6; 249 fillers take the other slots, so
     * the map is exactly full. */
    for (uint32_t id = 1000; id < 1249; id++)
        network_monitor_note_peer_header(id, 1, h);
    nms_hash(h, 'w');
    /* A full map evicts slot (id % 256): id 262 lands on slot 6 = node 10, 
     * which loses its vote (tip hash empty, handshake height kept). */
    network_monitor_note_peer_header(262, 10, h);
}

static void nms_setup(char *our_hex)
{
    memset(&g_cm, 0, sizeof(g_cm));
    memset(&g_dm, 0, sizeof(g_dm));
    main_state_init(&g_ms);
    zcl_mutex_init(&g_cm.manager.cs_nodes);
    zcl_mutex_init(&g_dm.cs);
    static struct chain_params params;
    memset(&params, 0, sizeof(params));
    g_cm.params = &params;

    memset(&g_tip, 0, sizeof(g_tip));
    g_tip.nHeight = 10;
    g_tip.nTime = 1700000000;
    for (int i = 0; i < 32; i++)
        g_tip.hashBlock.data[i] = (unsigned char)(0x40 + i);
    g_tip.phashBlock = &g_tip.hashBlock;
    active_chain_install_tip_slot(&g_ms.chain_active, &g_tip);
    uint256_get_hex(&g_tip.hashBlock, our_hex);
}

static const struct db_peer_chain_observation *
nms_row(const struct db_peer_chain_observation *rows, int n, int64_t id)
{
    for (int i = 0; i < n; i++)
        if (rows[i].peer_id == id)
            return &rows[i];
    return NULL;
}

static int nms_check_rows(struct node_db *db, const char *our_hex)
{
    int failures = 0;
    static struct db_peer_chain_observation rows[64];
    int n = db_peer_chain_observation_recent(db, rows, 64);
    NMS_CHECK(n == 8);
    const struct db_peer_chain_observation *r2 = nms_row(rows, n, 2);
    NMS_CHECK(r2 != NULL);
    if (!r2)
        return failures;
    NMS_CHECK(strcmp(r2->addr, "20.1.0.2:8033") == 0);
    NMS_CHECK(strcmp(r2->user_agent, "/ua2/") == 0);
    NMS_CHECK(r2->version == 170102);
    NMS_CHECK(r2->best_height == 10); /* vote 10 beats handshake 4 */
    NMS_CHECK(r2->latency_us == 1002);
    NMS_CHECK(r2->inbound == 0);
    NMS_CHECK(r2->first_seen == 111 && r2->last_seen == 222);
    NMS_CHECK(r2->observed_at > 1000000000);
    NMS_CHECK(strcmp(r2->tip_hash, our_hex) == 0);
    const struct db_peer_chain_observation *r1 = nms_row(rows, n, 1);
    NMS_CHECK(r1 && r1->inbound == 1 && strcmp(r1->tip_hash, our_hex) == 0);
    const struct db_peer_chain_observation *r9 = nms_row(rows, n, 9);
    NMS_CHECK(r9 && r9->best_height == 12 && r9->tip_hash[0] == 'c');
    const struct db_peer_chain_observation *r10 = nms_row(rows, n, 10);
    NMS_CHECK(r10 && r10->best_height == 10 && r10->tip_hash[0] == '\0');
    const struct db_peer_chain_observation *r11 = nms_row(rows, n, 11);
    NMS_CHECK(r11 && r11->best_height == 7 && r11->tip_hash[0] == '\0');
    NMS_CHECK(nms_row(rows, n, 6) == NULL && nms_row(rows, n, 7) == NULL);
    return failures;
}

static int nms_check_view(const char *our_hex)
{
    int failures = 0;
    struct network_consensus_view v;
    NMS_CHECK(network_monitor_get_view(&v));
    NMS_CHECK(v.num_peers == 8 && v.peers_with_height == 8);
    NMS_CHECK(v.our_height == 10);
    NMS_CHECK(v.max_height == 12 && v.delta == 2);
    NMS_CHECK(v.modal_height == 10 && v.modal_height_count == 6);
    NMS_CHECK(v.num_clusters == 3);
    NMS_CHECK(v.fork_detected && v.fork_height == 10);
    NMS_CHECK(v.fork_count_a == 3 && v.fork_count_b == 2);
    NMS_CHECK(strcmp(v.fork_hash_a, our_hex) == 0);
    NMS_CHECK(v.fork_hash_b[0] == 'b');

    /* the partition fold sees the address groups: two peers of one /16 are
     * ONE group, so our side holds 3 peers in 2 groups. */
    struct network_partition_view pv;
    (void)network_monitor_netsplit_suspected(&pv);
    NMS_CHECK(pv.ready && pv.at_height == 10);
    NMS_CHECK(strcmp(pv.our_tip_hash, our_hex) == 0);
    NMS_CHECK(pv.agreeing_peers == 3 && pv.agreeing_groups == 2);
    NMS_CHECK(pv.rival_peers == 2 && pv.rival_groups == 2);
    return failures;
}

int network_monitor_fold_sampler_tests(void)
{
    int failures = 0;
    printf("network_monitor sampler over a fake connman...\n");
    char dbdir[256];
    char dbpath[320];
    static struct node_db ndb;
    char our_hex[65];

    test_make_tmpdir(dbdir, sizeof(dbdir), "netmon", "sampler");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, dbpath)) {
        printf("  FAIL: node_db_open\n");
        (void)test_rm_rf_recursive(dbdir);
        return 1;
    }

    nms_setup(our_hex);
    sync_monitor_init();
    int used = nms_build_peers(our_hex);
    nms_fill_votes_and_evict();
    for (int i = 0; i < used; i++)
        g_ptrs[i] = &g_nodes[i];
    g_ptrs[used] = NULL; /* a NULL slot inside the array is skipped */
    g_cm.manager.nodes = g_ptrs;
    g_cm.manager.num_nodes = (size_t)used + 1;
    sync_monitor_set_context(&g_cm, &g_dm, &g_ms);

    unsetenv("ZCL_NETMON_INTERVAL_SECS");
    unsetenv("ZCL_NETMON_RETAIN_ROWS");
    struct network_monitor_config cfg = { 30, 100 };
    NMS_CHECK(network_monitor_start(&cfg, &ndb).ok);
    struct network_consensus_view v;
    while (!network_monitor_get_view(&v))
        platform_sleep_ms(5);
    network_monitor_stop();

    failures += nms_check_rows(&ndb, our_hex);
    failures += nms_check_view(our_hex);
    struct json_value d;
    json_init(&d);
    NMS_CHECK(network_monitor_dump_state_json(&d, NULL));
    NMS_CHECK(json_get_int(json_get(&d, "retained_rows")) == 8);
    json_free(&d);

    sync_monitor_set_context(NULL, NULL, NULL);
    main_state_free(&g_ms);
    node_db_close(&ndb);
    if (test_rm_rf_recursive(dbdir) != 0 && errno != ENOENT) {
        printf("  FAIL: fixture cleanup\n");
        failures++;
    }
    return failures;
}
