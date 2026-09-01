/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for node health snapshot service. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "coins/coins_view.h"
#include "controllers/network_controller.h"
#include "net/connman.h"
#include "net/net.h"
#include "services/block_source_policy.h"
#include "services/node_health_service.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_evidence_persistence_service.h"
#include "services/chain_state_service.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/sync_monitor.h"
#include "storage/body_history.h"
#include "storage/progress_store.h"
#include "event/event.h"
#include "platform/os_proc.h"
#include "util/alerts.h"
#include "util/mem_pressure.h"
#include "validation/main_state.h"
#include "validation/mirror_consensus.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <sys/stat.h>

static bool health_test_init_main_tip(struct main_state *ms,
                                      struct block_index *tip,
                                      struct uint256 *tip_hash,
                                      int height,
                                      uint8_t marker,
                                      int64_t age_seconds)
{
    if (!ms || !tip || !tip_hash)
        return false;
    memset(ms, 0, sizeof(*ms));
    memset(tip, 0, sizeof(*tip));
    memset(tip_hash, 0, sizeof(*tip_hash));
    main_state_init(ms);
    block_index_init(tip);
    tip_hash->data[0] = marker;
    tip->phashBlock = tip_hash;
    tip->nHeight = height;
    tip->nTime = (uint32_t)(platform_time_wall_time_t() - age_seconds);
    tip->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
    arith_uint256_set_u64(&tip->nChainWork, (uint64_t)height + 1);
    if (!active_chain_move_window_tip(&ms->chain_active, tip))
        return false;
    ms->pindex_best_header = tip;
    return true;
}

static bool health_test_init_connman_peer(struct connman *cm,
                                          struct net_address *addr,
                                          struct p2p_node **node_out,
                                          const char *name,
                                          int height)
{
    if (!cm || !addr || !node_out)
        return false;
    memset(cm, 0, sizeof(*cm));
    memset(addr, 0, sizeof(*addr));
    net_manager_init(&cm->manager);
    cm->manager.nodes = zcl_calloc(1, sizeof(*cm->manager.nodes),
                                   "test_nodes");
    if (!cm->manager.nodes)
        return false;
    *node_out = p2p_node_create(&cm->manager, ZCL_INVALID_SOCKET, addr,
                                name, false);
    if (!*node_out)
        return false;
    (*node_out)->starting_height = height;
    (*node_out)->state = PEER_HANDSHAKE_COMPLETE;
    (*node_out)->services = NODE_NETWORK;
    cm->manager.nodes[0] = *node_out;
    cm->manager.num_nodes = 1;
    rpc_net_set_connman(cm);
    return true;
}

int test_node_health_service(void)
{
    int failures = 0;

    printf("node_health_service: network-tip resolution (modal + clamp)... ");
    {
        bool ok = true;
        /* plausible max, no modal -> raw max */
        ok = ok && node_health_resolve_network_tip(
                       100050, 0, 100000, false, -1, 0) == 100050;
        /* lone above-band liar -> clamped to header_tip+10000 */
        ok = ok && node_health_resolve_network_tip(
                       5000000, 1, 100000, false, -1, 0) == 110000;
        /* two independent peers corroborate -> trust raw max */
        ok = ok && node_health_resolve_network_tip(
                       5000000, 2, 100000, false, -1, 0) == 5000000;
        /* modal agreed by >=3 beats a clamped liar max */
        ok = ok && node_health_resolve_network_tip(
                       5000000, 1, 100000, true, 100200, 3) == 100200;
        /* modal < 3 observations -> fall back to the (clamped) MAX */
        ok = ok && node_health_resolve_network_tip(
                       100050, 0, 100000, true, 100200, 2) == 100050;
        /* unknown header tip -> no clamp */
        ok = ok && node_health_resolve_network_tip(
                       100050, 0, -1, false, -1, 0) == 100050;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: idle snapshot reports unhealthy without peers... ");
    {
        struct node_health_snapshot health;
        rpc_net_set_connman(NULL);
        sync_set_state(SYNC_IDLE, "reset");
        node_health_collect(&health, NULL, NULL);

        bool ok = (health.sync_state == SYNC_IDLE);
        ok = ok && !health.synced;
        ok = ok && !health.has_peers;
        ok = ok && !health.healthy;
        ok = ok && !health.tor_ready;
        ok = ok && !health.onion_service_ready;
        ok = ok && health.tip_height == -1;
        ok = ok && health.header_height == -1;
        ok = ok && health.tip_lag == 0;
        ok = ok && !health.catchup_active;
        ok = ok && health.catchup_progress_age_seconds == 0;
        ok = ok && !health.import_active;
        ok = ok && health.import_progress_age_seconds == 0;
        ok = ok && strcmp(health.degraded_reason, "no_peers") == 0;
        ok = ok && !health.serving;
        ok = ok && strcmp(health.blocking_reason, "no_peers") == 0;
        ok = ok && !health.warning;
        ok = ok && health.warning_count == 0;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: at_tip without peers stays unhealthy... ");
    {
        struct node_health_snapshot health;
        rpc_net_set_connman(NULL);
        sync_set_state(SYNC_FINDING_PEERS, "test");
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
        sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
        sync_set_state(SYNC_AT_TIP, "test");
        node_health_collect(&health, NULL, NULL);

        bool ok = health.synced;
        ok = ok && !health.has_peers;
        ok = ok && !health.healthy;
        ok = ok && health.peer_count == 0;
        ok = ok && !health.onion_service_ready;
        ok = ok && strcmp(health.degraded_reason, "no_peers") == 0;
        ok = ok && !health.serving;
        ok = ok && strcmp(health.blocking_reason, "no_peers") == 0;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: at-tip peers without active tip stay unhealthy... ");
    {
        struct node_health_snapshot health;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        bool ok = true;

        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "missing-tip-peer", 10);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(10);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, NULL);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && !health.healthy;
            ok = ok && health.tip_height == -1;
            ok = ok && health.header_height == -1;
            ok = ok && health.peer_best_height == 10;
            ok = ok && strcmp(health.degraded_reason,
                              "active_tip_unknown") == 0;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.blocking_reason,
                              "active_tip_unknown") == 0;
        }

        node_health_test_set_log_head_override(-2);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: headers ahead of active tip report degraded state... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip, header;
        struct uint256 h_tip = {0}, h_hdr = {0};

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&tip, 0, sizeof(tip));
        memset(&header, 0, sizeof(header));
        main_state_init(&ms);
        net_manager_init(&cm.manager);
        block_index_init(&tip);
        block_index_init(&header);

        h_tip.data[0] = 1;
        h_hdr.data[0] = 2;
        tip.phashBlock = &h_tip;
        tip.nHeight = 100;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        header.phashBlock = &h_hdr;
        header.nHeight = 125;
        header.pprev = &tip;
        header.nTime = tip.nTime;
        bool ok = active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &header;

        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes), "test_nodes");
        ok = ok && (cm.manager.nodes != NULL);
        node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr,
                               "test-peer", false);
        ok = ok && (node != NULL);
        if (ok) {
            node->starting_height = 125;
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->services = NODE_NETWORK;
            cm.manager.nodes[0] = node;
            cm.manager.num_nodes = 1;
            rpc_net_set_connman(&cm);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && !health.healthy;
            ok = ok && health.tip_height == 100;
            ok = ok && health.header_height == 125;
            ok = ok && strcmp(health.degraded_reason, "headers_ahead_25") == 0;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.blocking_reason,
                              "headers_ahead_25") == 0;
        }

        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: small header gap stays serving healthy... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip, header;
        struct uint256 h_tip = {0}, h_hdr = {0};
        const int tip_height = 200;
        const int header_height =
            tip_height + ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&tip, 0, sizeof(tip));
        memset(&header, 0, sizeof(header));
        main_state_init(&ms);
        net_manager_init(&cm.manager);
        block_index_init(&tip);
        block_index_init(&header);

        h_tip.data[0] = 3;
        h_hdr.data[0] = 4;
        tip.phashBlock = &h_tip;
        tip.nHeight = tip_height;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        header.phashBlock = &h_hdr;
        header.nHeight = header_height;
        header.pprev = &tip;
        header.nTime = tip.nTime;
        bool ok = active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &header;

        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes),
                                      "test_nodes");
        ok = ok && (cm.manager.nodes != NULL);
        node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr,
                               "small-gap-peer", false);
        ok = ok && (node != NULL);
        if (ok) {
            node->starting_height = header_height;
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->services = NODE_NETWORK;
            cm.manager.nodes[0] = node;
            cm.manager.num_nodes = 1;
            rpc_net_set_connman(&cm);
            node_health_test_set_log_head_override(header_height);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.serving;
            ok = ok && health.tip_height == tip_height;
            ok = ok && health.header_height == header_height;
            ok = ok && health.tip_lag == ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.blocking_reason[0] == '\0';
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: reducer log-head gap degrades health... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip = {0};
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&tip, 0, sizeof(tip));
        main_state_init(&ms);
        net_manager_init(&cm.manager);
        block_index_init(&tip);

        h_tip.data[0] = 102;
        tip.phashBlock = &h_tip;
        tip.nHeight = 102;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        arith_uint256_set_u64(&tip.nChainWork, 103);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &tip;

        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes),
                                      "test_nodes");
        ok = ok && (cm.manager.nodes != NULL);
        if (ok) {
            node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr,
                                   "log-head-peer", false);
            ok = ok && (node != NULL);
        }
        if (ok) {
            node->starting_height = tip.nHeight;
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->services = NODE_NETWORK;
            cm.manager.nodes[0] = node;
            cm.manager.num_nodes = 1;
            rpc_net_set_connman(&cm);
            node_health_test_set_log_head_override(100);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && !health.healthy;
            ok = ok && health.tip_height == tip.nHeight;
            ok = ok && health.peer_best_height == tip.nHeight;
            ok = ok && health.log_head == 100;
            ok = ok && health.log_head_gap == 2;
            ok = ok && strcmp(health.degraded_reason,
                              "log_head_gap_2") == 0;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.blocking_reason,
                              "log_head_gap_2") == 0;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: unknown reducer log-head blocks green health... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        bool ok = true;
        memset(&cm, 0, sizeof(cm));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 111,
                                             111, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "unknown-log-peer",
                                                 tip.nHeight);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(-1);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && !health.healthy;
            ok = ok && health.log_head == -1;
            ok = ok && health.log_head_gap == -1;
            ok = ok && strcmp(health.degraded_reason,
                              "log_head_unknown") == 0;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.blocking_reason,
                              "log_head_unknown") == 0;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: durable tip_finalize cursor backs startup health... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        char dir[256];
        bool ok = true;
        memset(&ms, 0, sizeof(ms));
        memset(&cm, 0, sizeof(cm));
        memset(&tip, 0, sizeof(tip));
        memset(&h_tip, 0, sizeof(h_tip));
        test_fmt_tmpdir(dir, sizeof(dir), "node_health", "durable_log_head");
        (void)mkdir("./test-tmp", 0755);
        (void)mkdir(dir, 0755);
        progress_store_close();
        ok = ok && progress_store_open(dir);
        ok = ok && sqlite3_exec(progress_store_db(),
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('tip_finalize',111,0)",
            NULL, NULL, NULL) == SQLITE_OK;
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 111,
                                             112, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "durable-log-peer",
                                                 tip.nHeight);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(-2);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.serving;
            ok = ok && health.log_head == 111;
            ok = ok && health.log_head_gap == 0;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.blocking_reason[0] == '\0';
        }

        node_health_test_set_log_head_override(-2);
        progress_store_close();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: source-policy gap demotes stale at-tip FSM... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;
        memset(&cm, 0, sizeof(cm));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 120,
                                             120, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "source-gap-peer",
                                                 tip.nHeight);
        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight + 5;
        decision.sources[BSP_SOURCE_P2P].source = BSP_SOURCE_P2P;
        decision.sources[BSP_SOURCE_P2P].available = true;
        decision.sources[BSP_SOURCE_P2P].healthy = true;
        decision.sources[BSP_SOURCE_P2P].selectable = true;
        decision.sources[BSP_SOURCE_P2P].height = tip.nHeight + 5;
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = !health.synced;
            ok = ok && health.has_peers;
            ok = ok && !health.healthy;
            ok = ok && strcmp(health.degraded_reason,
                              "chain_advance_gap_5") == 0;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.blocking_reason,
                              "chain_advance_gap_5") == 0;
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: at-tip stale block timestamp stays healthy... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip = {0};
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&tip, 0, sizeof(tip));
        main_state_init(&ms);
        net_manager_init(&cm.manager);
        block_index_init(&tip);

        h_tip.data[0] = 203;
        tip.phashBlock = &h_tip;
        tip.nHeight = 203;
        tip.nTime = (uint32_t)(platform_time_wall_time_t() - 700);
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        arith_uint256_set_u64(&tip.nChainWork, 204);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &tip;

        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes),
                                      "test_nodes");
        ok = ok && (cm.manager.nodes != NULL);
        if (ok) {
            node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr,
                                   "stale-at-tip-peer", false);
            ok = ok && (node != NULL);
        }
        if (ok) {
            node->starting_height = tip.nHeight;
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->services = NODE_NETWORK;
            cm.manager.nodes[0] = node;
            cm.manager.num_nodes = 1;
            rpc_net_set_connman(&cm);
            node_health_test_set_log_head_override(tip.nHeight);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.tip_stale;
            ok = ok && health.tip_stale_seconds >= 600;
            ok = ok && health.tip_height == tip.nHeight;
            ok = ok && health.peer_best_height == tip.nHeight;
            ok = ok && health.log_head_gap == 0;
            ok = ok && health.healthy;
            ok = ok && health.serving;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.blocking_reason[0] == '\0';
            ok = ok && health.warning;
            ok = ok && health.warning_count >= 1;
            ok = ok && strstr(health.warning_reasons, "tip_stale") != NULL;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: high RSS is warning not serving blocker... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&decision, 0, sizeof(decision));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 155,
                                             155, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "high-rss-peer",
                                                 tip.nHeight);
        ok = ok && body_history_test_publish_proven(tip.nHeight);

        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight;
        decision.projection_height = tip.nHeight;
        decision.projection_lag = 0;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = tip.nHeight;

        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            node_health_test_set_memory_rss_mb_override(5000);
            sync_set_state(SYNC_IDLE, "high rss reset");
            sync_set_state(SYNC_FINDING_PEERS, "high rss");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "high rss");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.serving;
            ok = ok && health.memory_rss_mb == 5000;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.blocking_reason[0] == '\0';
            ok = ok && health.warning;
            ok = ok && health.warning_count >= 1;
            ok = ok && strstr(health.warning_reasons,
                              "high_memory_usage") != NULL;
        }

        node_health_test_set_memory_rss_mb_override(-1);
        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: high RSS keeps real blocker primary... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&decision, 0, sizeof(decision));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 156,
                                             156, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "high-rss-blocked-peer",
                                                 tip.nHeight);

        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight;
        decision.projection_height = tip.nHeight;
        decision.projection_lag = 0;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = tip.nHeight;

        if (ok) {
            (void)node;
            alerts_shutdown();
            event_log_init();
            unsetenv("ZCL_ALERTS_DISABLE");
            unsetenv("ZCL_ALERT_WEBHOOK_URL");
            alerts_init();
            alerts_reset();
            event_emitf(EV_OPERATOR_NEEDED, 0, "chain_integrity_failed");

            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            node_health_test_set_memory_rss_mb_override(5000);
            sync_set_state(SYNC_IDLE, "high rss blocked reset");
            sync_set_state(SYNC_FINDING_PEERS, "high rss blocked");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "high rss blocked");
            node_health_collect(&health, NULL, &ms);

            ok = !health.healthy;
            ok = ok && !health.serving;
            ok = ok && health.operator_needed;
            ok = ok && health.memory_rss_mb == 5000;
            ok = ok && strcmp(health.degraded_reason,
                              "operator_needed:chain_integrity_failed") == 0;
            ok = ok && strcmp(health.blocking_reason,
                              "operator_needed:chain_integrity_failed") == 0;
            ok = ok && strstr(health.operator_needed_detail,
                              "chain_integrity_failed") != NULL;
            ok = ok && health.warning;
            ok = ok && strstr(health.warning_reasons,
                              "high_memory_usage") != NULL;

            alerts_operator_needed_clear();
            const char *long_blocker =
                "check=window.consistency I4.3 utxo_apply log hole: "
                "contiguous ok=1 prefix h=3056758 but cursor=3171120 "
                "first_hole_h=3056759 "
                "repair_owner=reducer_frontier_reconcile_light";
            event_emitf(EV_OPERATOR_NEEDED, 0, "%s", long_blocker);
            node_health_collect(&health, NULL, &ms);
            ok = ok && strstr(health.operator_needed_detail,
                              "first_hole_h=3056759") != NULL;
            ok = ok && strstr(health.blocking_reason,
                              "reducer_frontier_reconcile_light") != NULL;
        }

        alerts_shutdown();
        node_health_test_set_memory_rss_mb_override(-1);
        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: mem_pressure CRITICAL flips healthy false... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&decision, 0, sizeof(decision));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 157,
                                             157, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "mem-pressure-peer",
                                                 tip.nHeight);
        ok = ok && body_history_test_publish_proven(tip.nHeight);

        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight;
        decision.projection_height = tip.nHeight;
        decision.projection_lag = 0;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = tip.nHeight;

        if (ok) {
            (void)node;
            mem_pressure_reset_for_testing();
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_IDLE, "mem pressure reset");
            sync_set_state(SYNC_FINDING_PEERS, "mem pressure");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "mem pressure");

            struct os_proc_mem critical = {
                .rss_bytes = 950, .vsize_bytes = 950,
                .cgroup_current = -1, .cgroup_high = -1, .cgroup_max = -1,
                .sys_total_bytes = 1000, .sys_avail_bytes = 50,
            };
            os_proc_mem_set_override(&critical);
            mem_pressure_poll_tick();
            node_health_collect(&health, NULL, &ms);

            ok = !health.healthy;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.degraded_reason,
                              "memory_pressure_critical") == 0;
            ok = ok && strstr(health.warning_reasons,
                              "mem_pressure_high") != NULL;

            struct os_proc_mem nominal = {
                .rss_bytes = 100, .vsize_bytes = 100,
                .cgroup_current = -1, .cgroup_high = -1, .cgroup_max = -1,
                .sys_total_bytes = 1000, .sys_avail_bytes = 900,
            };
            os_proc_mem_set_override(&nominal);
            mem_pressure_poll_tick();
            node_health_collect(&health, NULL, &ms);
            ok = ok && health.healthy;
            ok = ok && health.serving;
        }

        os_proc_mem_set_override(NULL);
        mem_pressure_reset_for_testing();
        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: coordinator at-tip overrides stale sync FSM... ");
    {
        struct bsp_decision decision;
        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = 3117591;
        decision.target_height = 3117591;
        decision.projection_height = 3117591;
        decision.projection_lag = 0;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = 3117591;

        bool ok = node_health_chain_advance_synced(&decision);
        decision.projection_lag = 2;
        ok = ok && node_health_chain_advance_synced(&decision);
        decision.projection_lag = 0;
        snprintf(decision.blocker, sizeof(decision.blocker),
                 "body-hash-mismatch");
        ok = ok && !node_health_chain_advance_synced(&decision);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: source-policy at-tip normalizes health sync label... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&decision, 0, sizeof(decision));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 145,
                                             145, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "source-at-tip-peer",
                                                 tip.nHeight);
        ok = ok && body_history_test_publish_proven(tip.nHeight);

        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight;
        decision.projection_height = tip.nHeight;
        decision.projection_lag = 0;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = tip.nHeight;

        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_IDLE, "test reset");
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.sync_state == SYNC_AT_TIP;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.serving;
            ok = ok && health.tip_height == tip.nHeight;
            ok = ok && health.header_height == tip.nHeight;
            ok = ok && health.peer_best_height == tip.nHeight;
            ok = ok && health.log_head == tip.nHeight;
            ok = ok && health.log_head_gap == 0;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.blocking_reason[0] == '\0';
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: old errors stay visible without degrading... ");
    {
        struct node_health_snapshot health;
        struct error_ring *er = error_ring_global();
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        bool ok = true;

        memset(&ms, 0, sizeof(ms));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        error_ring_init(er);
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 130,
                                             130, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "old-error-peer",
                                                 tip.nHeight);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            error_ring_observer(EV_DB_ERROR, 0, "old recoverable error",
                                21, er);
            er->entries[0].timestamp_us =
                ((int64_t)platform_time_wall_time_t() - 600) * 1000000;
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.error_total == 1;
            ok = ok && !health.last_error_recent;
            ok = ok && health.last_error_age_seconds >= 300;
            ok = ok && strcmp(health.last_error_type,
                              event_type_name(EV_DB_ERROR)) == 0;
            ok = ok && strcmp(health.last_error,
                              "old recoverable error") == 0;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.serving;
            ok = ok && !health.warning;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        error_ring_init(er);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: recent errors stay actionable without false degradation... ");
    {
        struct node_health_snapshot health;
        struct error_ring *er = error_ring_global();
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        bool ok = true;

        memset(&ms, 0, sizeof(ms));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        error_ring_init(er);
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 140,
                                             140, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "recent-error-peer",
                                                 tip.nHeight);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            error_ring_observer(EV_BLOCK_REJECTED, 0, "fresh reject",
                                12, er);
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.error_total == 1;
            ok = ok && health.last_error_recent;
            ok = ok && health.last_error_age_seconds >= 0;
            ok = ok && health.last_error_age_seconds <= 300;
            ok = ok && strcmp(health.last_error_type,
                              event_type_name(EV_BLOCK_REJECTED)) == 0;
            ok = ok && strcmp(health.last_error, "fresh reject") == 0;
            ok = ok && health.degraded_reason[0] == '\0';
            ok = ok && health.serving;
            ok = ok && health.warning;
            ok = ok && health.warning_count >= 1;
            ok = ok && strstr(health.warning_reasons, "recent_error") != NULL;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        error_ring_init(er);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: unsafe mirror override fails health loud... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&ms, 0, sizeof(ms));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        mirror_consensus_reset_for_test();
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 150,
                                             150, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "unsafe-mirror-peer",
                                                 tip.nHeight);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            mirror_consensus_record_override(42, "test_unsafe_override");
            node_health_collect(&health, NULL, &ms);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && !health.healthy;
            ok = ok && !health.serving;
            ok = ok && strcmp(health.degraded_reason,
                              "mirror_unsafe_overrides_1") == 0;
            ok = ok && strcmp(health.blocking_reason,
                              "mirror_unsafe_overrides_1") == 0;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        mirror_consensus_reset_for_test();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: same-height mirror hash gap fails health... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct legacy_mirror_sync_stats mirror = {0};
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&ms, 0, sizeof(ms));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        legacy_mirror_sync_reset_for_test();
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 151,
                                             151, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "mirror-hash-gap-peer",
                                                 tip.nHeight);
        if (ok) {
            (void)node;
            node_health_test_set_log_head_override(tip.nHeight);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            mirror.enabled = true;
            mirror.running = true;
            mirror.reachable = true;
            mirror.local_height = tip.nHeight;
            mirror.legacy_height = tip.nHeight;
            legacy_mirror_sync_test_set_stats(&mirror, &ms);
            node_health_collect(&health, NULL, &ms);

            ok = health.synced && health.has_peers && !health.healthy;
            ok = ok && strcmp(
                health.degraded_reason,
                "mirror_same_height_hash_unavailable_or_mismatch") == 0;

            snprintf(mirror.zclassic23_hash,
                     sizeof(mirror.zclassic23_hash), "%064x", 1);
            snprintf(mirror.zclassicd_hash,
                     sizeof(mirror.zclassicd_hash), "%064x", 2);
            legacy_mirror_sync_test_set_stats(&mirror, &ms);
            memset(&health, 0, sizeof(health));
            node_health_collect(&health, NULL, &ms);
            ok = ok && !health.healthy && strcmp(
                health.degraded_reason,
                "mirror_same_height_hash_unavailable_or_mismatch") == 0;
        }

        node_health_test_set_log_head_override(-2);
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        legacy_mirror_sync_reset_for_test();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: runtime fallback reads chain evidence... ");
    {
        struct node_health_snapshot health;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct coins_view null_view;
        struct coins_view_cache coins_tip;
        struct block_index tip;
        struct uint256 tip_hash;
        struct block_index *header_tip = NULL;
        bool ok = true;

        memset(&health, 0, sizeof(health));
        memset(&ndb, 0, sizeof(ndb));
        memset(&dbsvc, 0, sizeof(dbsvc));
        memset(&runtime, 0, sizeof(runtime));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        memset(&null_view, 0, sizeof(null_view));
        memset(&tip, 0, sizeof(tip));
        memset(&tip_hash, 0, sizeof(tip_hash));
        main_state_init(&ms);
        coins_view_cache_init(&coins_tip, &null_view);
        net_manager_init(&cm.manager);

        ok = ok && node_db_open(&ndb, ":memory:");
        if (ok) {
            db_service_init(&dbsvc);
            ok = ok && db_service_attach(&dbsvc, &ndb);
            ok = ok && db_service_start(&dbsvc);
            runtime.db_service = &dbsvc;
            app_runtime_set_current(&runtime);
        }

        tip_hash.data[0] = 0x7a;
        block_index_init(&tip);
        tip.phashBlock = &tip_hash;
        tip.nHeight = 7;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        arith_uint256_set_u64(&tip.nChainWork, 8);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &tip;
        header_tip = &tip;
        coins_view_cache_set_best_block(&coins_tip, &tip_hash);
        block_map_insert(&ms.map_block_index, &tip_hash, &tip);
        const struct block_index *canon =
            block_map_find(&ms.map_block_index, &tip_hash);
        if (canon)
            tip.phashBlock = canon->phashBlock;

        if (ok) {
            csr_init(csr_instance(), &ms.map_block_index, &ms.chain_active,
                     &header_tip, &coins_tip, &ndb, NULL);
            sync_monitor_set_context(NULL, NULL, &ms);
            struct chain_evidence_controller seed = {
                .ndb = &ndb,
                .csr = csr_instance(),
                .state = CEC_TIP_FOLLOWING,
            };
            struct chain_evidence_record evidence = {
                .source_class = CEC_SOURCE_CLASS_NATIVE_P2P,
                .publish_state = CEC_PUBLISH_LOCAL_EVIDENCE,
                .header_ancestry_linked = true,
                .chainwork_recomputed = true,
                .nakamoto_selected_best_work = true,
                .block_bytes_hash_checked = true,
            };
            const char state_name[] = "tip_following";
            ok = ok && node_db_state_set(&ndb, "cec.sync_state",
                                         state_name, sizeof(state_name));
            ok = ok && node_db_state_set(&ndb, "cec.active_tip_hash",
                                         tip.phashBlock->data, 32);
            ok = ok && node_db_state_set_int(&ndb, "cec.active_tip_height",
                                             tip.nHeight);
            ok = ok && node_db_state_set_int(&ndb, "cec.coins_best_block_height",
                                             tip.nHeight);
            ok = ok && node_db_state_set_int(&ndb, "cec.utxo_max_height",
                                             tip.nHeight);
            ok = ok && node_db_state_set_int(&ndb, "cec.publish_state",
                                             CEC_PUBLISH_LOCAL_EVIDENCE);
            ok = ok && node_db_state_set_int(&ndb,
                                             "cec.active_tip_source_class",
                                             CEC_SOURCE_CLASS_NATIVE_P2P);
            ok = ok && chain_evidence_store_persist(
                           &seed, "cec.block_index_evidence_state",
                           &evidence).ok;
            ok = ok && chain_evidence_store_persist(
                           &seed, "cec.active_tip_evidence", &evidence).ok;
        }

        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes),
                                      "test_nodes");
        ok = ok && (cm.manager.nodes != NULL);
        if (ok) {
            node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr,
                                   "runtime-health-peer", false);
            ok = ok && (node != NULL);
        }
        if (ok) {
            node->starting_height = tip.nHeight;
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->services = NODE_NETWORK;
            cm.manager.nodes[0] = node;
            cm.manager.num_nodes = 1;
            rpc_net_set_connman(&cm);
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            sync_set_state(SYNC_CONNECTING_BLOCKS, "test");
            sync_set_state(SYNC_AT_TIP, "test");
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_collect(&health, NULL, NULL);

            ok = health.synced;
            ok = ok && health.has_peers;
            ok = ok && health.healthy;
            ok = ok && health.tip_height == tip.nHeight;
            ok = ok && health.header_height == tip.nHeight;
            ok = ok && health.degraded_reason[0] == '\0';
            if (!ok)
                fprintf(stderr, "node_health_service runtime fallback: "
                        "healthy=%d synced=%d peers=%d tip=%d header=%d "
                        "reason=%s\n",
                        health.healthy, health.synced, health.has_peers,
                        health.tip_height, health.header_height,
                        health.degraded_reason);
        }

        sync_monitor_set_context(NULL, NULL, NULL);
        node_health_test_set_log_head_override(-2);
        csr_free(csr_instance());
        app_runtime_set_current(NULL);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        coins_view_cache_free(&coins_tip);
        main_state_free(&ms);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: stale DB transaction reports degraded state... ");
    {
        struct node_health_snapshot health;
        struct node_db ndb;
        struct node_db_status st;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        bool ok = node_db_open(&ndb, ":memory:");
        memset(&dbsvc, 0, sizeof(dbsvc));
        memset(&runtime, 0, sizeof(runtime));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        net_manager_init(&cm.manager);
        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes), "test_nodes");
        ok = ok && (cm.manager.nodes != NULL);
        if (ok) {
            node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr,
                                   "db-test-peer", false);
            ok = ok && (node != NULL);
        }
        if (ok) {
            node->starting_height = 10;
            node->state = PEER_HANDSHAKE_COMPLETE;
            node->services = NODE_NETWORK;
            cm.manager.nodes[0] = node;
            cm.manager.num_nodes = 1;
            rpc_net_set_connman(&cm);
        }
        if (ok) {
            db_service_init(&dbsvc);
            ok = ok && db_service_attach(&dbsvc, &ndb);
            ok = ok && db_service_start(&dbsvc);
            runtime.db_service = &dbsvc;
            app_runtime_set_current(&runtime);
        }

        ok = ok && node_db_begin(&ndb);
        node_db_get_status(&ndb, &st);
        ok = ok && st.tx_open;

        /* Simulate an inactive open transaction and existing peers-free state. */
        if (ndb.state_mutex_init) {
            zcl_mutex_lock(&ndb.state_mutex);
            ndb.last_activity_time = (int64_t)platform_time_wall_time_t() - 61;
            zcl_mutex_unlock(&ndb.state_mutex);
        }

        sync_set_state(SYNC_FINDING_PEERS, "test");
        node_health_collect(&health, &ndb, NULL);
        ok = ok && health.db_open;
        ok = ok && health.db_tx_open;
        ok = ok && health.db_service_started;
        ok = ok && health.db_service_worker_started;
        ok = ok && health.db_service_queue_depth == 0;
        ok = ok && health.db_last_activity_age_seconds >= 60;
        ok = ok && !health.catchup_active;
        ok = ok && health.catchup_progress_age_seconds == 0;
        ok = ok && !health.import_active;
        ok = ok && health.import_progress_age_seconds == 0;
        ok = ok && strncmp(health.degraded_reason, "db_tx_open_", 11) == 0;

        app_runtime_set_current(NULL);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* The health snapshot used to answer "am I synced" a SECOND time, from a
     * block_source_policy decision that only knows heights and source health.
     * That answer overwrote the sync FSM's, and the FSM is the one that
     * refuses at-tip while the node cannot prove it holds the block bodies
     * for its own history. So a node with a 126k-block body hole had its
     * refusal overturned in the health snapshot and then published
     * `sync_state:"at_tip", healthy:true` on /api/status, /api/v1/health,
     * `healthcheck full`, and the starter-bundle mint gate.
     *
     * These two cases pin both directions: an unproven archive cannot be
     * upgraded, and a proven one still can (so the gate is a gate, not a
     * removal of the feature). */
    printf("node_health_service: unproven body archive refuses the "
           "source-policy at-tip upgrade... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;
        memset(&cm, 0, sizeof(cm));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 130,
                                             130, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "unproven-archive-peer",
                                                 tip.nHeight);
        /* A decision node_health_chain_advance_synced() accepts: chosen
         * source healthy, and its target is our own height. */
        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight;
        decision.sources[BSP_SOURCE_P2P].source = BSP_SOURCE_P2P;
        decision.sources[BSP_SOURCE_P2P].available = true;
        decision.sources[BSP_SOURCE_P2P].healthy = true;
        decision.sources[BSP_SOURCE_P2P].selectable = true;
        decision.sources[BSP_SOURCE_P2P].height = tip.nHeight;
        if (ok) {
            (void)node;
            /* UNKNOWN: nothing has established coverage. This is exactly what
             * the owner's node reports, and it must be refused as hard as a
             * known hole. */
            body_history_reset();
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            /* The FSM has correctly NOT reached at-tip. */
            sync_set_state(SYNC_IDLE, "unproven archive reset");
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            node_health_collect(&health, NULL, &ms);

            /* Before the fix both of these were manufactured here. */
            ok = !health.synced;
            ok = ok && health.sync_state != SYNC_AT_TIP;
            /* The FSM's real answer survives into the snapshot. */
            ok = ok && health.sync_state == SYNC_BLOCKS_DOWNLOAD;
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        body_history_reset();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("node_health_service: proven body archive still permits the "
           "source-policy at-tip upgrade... ");
    {
        struct node_health_snapshot health;
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index tip;
        struct uint256 h_tip;
        struct bsp_decision decision;
        bool ok = true;
        memset(&cm, 0, sizeof(cm));
        ok = ok && health_test_init_main_tip(&ms, &tip, &h_tip, 131,
                                             131, 0);
        ok = ok && health_test_init_connman_peer(&cm, &addr, &node,
                                                 "proven-archive-peer",
                                                 tip.nHeight);
        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = tip.nHeight;
        decision.target_height = tip.nHeight;
        decision.sources[BSP_SOURCE_P2P].source = BSP_SOURCE_P2P;
        decision.sources[BSP_SOURCE_P2P].available = true;
        decision.sources[BSP_SOURCE_P2P].healthy = true;
        decision.sources[BSP_SOURCE_P2P].selectable = true;
        decision.sources[BSP_SOURCE_P2P].height = tip.nHeight;

        if (ok) {
            (void)node;
            ok = body_history_test_publish_proven(tip.nHeight);
            node_health_test_set_log_head_override(tip.nHeight);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_IDLE, "proven archive reset");
            sync_set_state(SYNC_FINDING_PEERS, "test");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "test");
            sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test");
            node_health_collect(&health, NULL, &ms);

            ok = ok && health.synced;
            ok = ok && health.sync_state == SYNC_AT_TIP;
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        body_history_reset();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* One canonical comparison: every at-tip gate reaches "may I claim
     * completeness?" through body_history_status_is_proven(), so UNKNOWN can
     * never leak through a site that wrote `!= INCOMPLETE`. */
    printf("node_health_service: at-tip completeness predicate is "
           "fail-closed on every status... ");
    {
        bool ok = body_history_status_is_proven(BODY_HISTORY_COMPLETE);
        ok = ok && !body_history_status_is_proven(BODY_HISTORY_UNKNOWN);
        ok = ok && !body_history_status_is_proven(BODY_HISTORY_INCOMPLETE);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    sync_set_state(SYNC_IDLE, "done");
    return failures;
}
