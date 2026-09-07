/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network sibling: bootstrapstatus's versioned P2P and beta6 snapshot
 * contract (readiness, review-required, and missing-index postures),
 * its snapshot authority posture, and getnetworkinfo's separation of
 * inbound reachability from outbound handshakes (addnode add/remove/
 * errors and peerinfo). Each scenario builds its own fixture context,
 * calls the RPC, asserts on the result, and frees what it owns; the
 * assertion helpers above each scenario are private to that scenario
 * and add no file-scope mutable state of their own.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_network_priv.h"

/* A fixed 12-hex stand-in for some other node's source-identity prefix. It is
 * deliberately NOT this binary's own: the point of the field is that a
 * stranger's node can name a build it is not itself running. */
#define SYNCDIAG_PEER_SRC_PREFIX "a1b2c3d4e5f6"

/* Fixture for the bootstrapstatus P2P+snapshot scenario: a connman with
 * one listen socket and one addrman entry, five peers in varying
 * lifecycle states, and an on-disk snapshot bundle + block index. */
struct sd_bootstrap_ctx {
    struct connman cm;
    struct node_signals sigs;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    char tmp_template[64];
    char *tmp_dir;
    char snap_path[512];
    char index_path[512];
};

static bool sd_bootstrap_setup_connman(struct sd_bootstrap_ctx *ctx)
{
    progress_store_close();
    memcpy(ctx->tmp_template, "/tmp/zcl-bootstrapstatus-XXXXXX",
          sizeof "/tmp/zcl-bootstrapstatus-XXXXXX");
    ctx->tmp_dir = mkdtemp(ctx->tmp_template);
    memset(ctx->snap_path, 0, sizeof ctx->snap_path);
    memset(ctx->index_path, 0, sizeof ctx->index_path);
    int snap_n = ctx->tmp_dir ? snprintf(ctx->snap_path,
                                         sizeof(ctx->snap_path),
                                         "%s/utxo-seed-3170000.snapshot",
                                         ctx->tmp_dir) : -1;
    int index_n = ctx->tmp_dir ? snprintf(ctx->index_path,
                                          sizeof(ctx->index_path),
                                          "%s/block_index.bin",
                                          ctx->tmp_dir) : -1;

    chain_params_select(CHAIN_MAIN);
    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    bool ok = ctx->tmp_dir != NULL &&
              snap_n > 0 && (size_t)snap_n < sizeof(ctx->snap_path) &&
              index_n > 0 && (size_t)index_n < sizeof(ctx->index_path);
    ok = ok && syncdiag_touch_file(ctx->snap_path);
    ok = ok && syncdiag_touch_file(ctx->index_path);
    ok = ok && connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    if (ok) {
        ctx->cm.manager.listen_sockets =
            zcl_calloc(1, sizeof(*ctx->cm.manager.listen_sockets),
                       "syncdiag_listen_socket");
        ok = ctx->cm.manager.listen_sockets != NULL;
    }
    if (ok) {
        ctx->cm.manager.listen_sockets[0].socket = ZCL_INVALID_SOCKET;
        ctx->cm.manager.num_listen_sockets = 1;
        ctx->cm.manager.listen_sockets_cap = 1;
    }
    reducer_frontier_provable_tip_set(3170000);
    msg_version_clear_external_ip_for_test();
    msg_version_set_external_ip("203.0.113.7:8033", 8033);
    return ok;
}

static bool sd_bootstrap_setup_addrman(struct sd_bootstrap_ctx *ctx,
                                       bool ok)
{
    if (ok) {
        struct net_address addr;
        struct net_addr src;
        syncdiag_set_ipv4(&addr, 8, 8, 8, 8, 8033);
        addr.nServices = NODE_NETWORK;
        net_addr_init(&src);
        unsigned char src_ip[4] = {1, 2, 3, 4};
        net_addr_set_ipv4(&src, src_ip);
        ok = addrman_add(&ctx->cm.manager.addrman, &addr, &src, 0);
    }
    return ok;
}

/* Builds the five peers this scenario asserts on: two live zclassic23
 * peers (one inbound, one addnode-sourced with a duplicate inbound
 * connection to it), one legacy MagicBean peer, and one self-hairpin
 * connection back to our own advertised external address. */
static bool sd_bootstrap_setup_peers(struct sd_bootstrap_ctx *ctx, bool ok)
{
    struct p2p_node *zcl_a = ok
        ? syncdiag_add_peer(&ctx->cm, 21, false, PEER_HANDSHAKE_COMPLETE)
        : NULL;
    struct p2p_node *zcl_b = ok
        ? syncdiag_add_peer(&ctx->cm, 22, true, PEER_HANDSHAKE_COMPLETE)
        : NULL;
    struct p2p_node *zcl_b_dup = ok
        ? syncdiag_add_peer(&ctx->cm, 22, false, PEER_HANDSHAKE_COMPLETE)
        : NULL;
    struct p2p_node *legacy_peer = ok
        ? syncdiag_add_peer(&ctx->cm, 23, false, PEER_HANDSHAKE_COMPLETE)
        : NULL;
    struct p2p_node *self_hairpin = ok
        ? syncdiag_add_peer(&ctx->cm, 24, true, PEER_HANDSHAKE_COMPLETE)
        : NULL;
    ok = ok && zcl_a && zcl_b && zcl_b_dup && legacy_peer &&
         self_hairpin;
    if (ok) {
        snprintf(zcl_a->addr_name, sizeof(zcl_a->addr_name),
                 "198.51.100.21:8033");
        zcl_a->starting_height = 3170000;
        syncdiag_note_peer_lifecycle_active(
            zcl_a, PEER_LIFECYCLE_SOURCE_ADDNODE);

        snprintf(zcl_b->addr_name, sizeof(zcl_b->addr_name),
                 "198.51.100.22:8033");
        zcl_b->starting_height = 3169999;
        syncdiag_note_peer_lifecycle_active(
            zcl_b, PEER_LIFECYCLE_SOURCE_INBOUND);

        syncdiag_set_ipv4(&zcl_b_dup->addr, 198, 51, 100, 22, 8033);
        snprintf(zcl_b_dup->addr_name, sizeof(zcl_b_dup->addr_name),
                 "198.51.100.22:8033");
        zcl_b_dup->starting_height = 3170000;
        syncdiag_note_peer_lifecycle_active(
            zcl_b_dup, PEER_LIFECYCLE_SOURCE_ADDRMAN);

        legacy_peer->services = NODE_NETWORK;
        snprintf(legacy_peer->addr_name,
                 sizeof(legacy_peer->addr_name),
                 "198.51.100.23:8033");
        snprintf(legacy_peer->sub_ver, sizeof(legacy_peer->sub_ver),
                 "%s", "/MagicBean:2.1.2-beta6/");
        snprintf(legacy_peer->clean_sub_ver,
                 sizeof(legacy_peer->clean_sub_ver),
                 "%s", legacy_peer->sub_ver);
        legacy_peer->starting_height = 3170000;
        syncdiag_note_peer_lifecycle_active(
            legacy_peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);

        snprintf(self_hairpin->addr_name,
                 sizeof(self_hairpin->addr_name),
                 "203.0.113.7:49152");
        self_hairpin->starting_height = 3170000;
        syncdiag_note_peer_lifecycle_active(
            self_hairpin, PEER_LIFECYCLE_SOURCE_INBOUND);
    }
    return ok;
}

static bool sd_bootstrapstatus_ready_contract(const struct json_value *result)
{
    bool ok = true;
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.bootstrap_status.v1") == 0;
    ok = ok && json_get_int(json_get(result,
                                      "schema_version")) == 1;
    ok = ok && json_get_bool(json_get(result,
                                      "serving_p2p_bootstrap"));
    ok = ok && json_get_bool(json_get(result,
                                      "serving_addr_bootstrap"));
    ok = ok && !json_get_bool(json_get(result,
                                       "serving_snapshot_bootstrap"));
    ok = ok && strcmp(json_get_str(json_get(result, "readiness")),
                      "ready_p2p_and_addr") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
        "fresh_node_next_action")),
                      "connect_direct_p2p_and_request_headers_blocks") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "zclassic23_fast_sync_compatible"));
    ok = ok && json_get_bool(json_get(result,
        "zclassicd_beta6_p2p_compatible"));
    ok = ok && !json_get_bool(json_get(result,
        "zclassicd_beta6_fast_bootstrap_compatible"));

    return ok;
}

static bool sd_bootstrapstatus_ready_p2p_and_peers(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *p2p = json_get(result, "p2p");
    const struct json_value *peers = json_get(result, "peers");
    ok = ok && p2p && p2p->type == JSON_OBJ;
    ok = ok && json_get_int(json_get(p2p, "protocolversion")) ==
              PROTOCOL_VERSION;
    ok = ok && json_get_int(json_get(p2p,
                                      "minimum_peer_protocol")) ==
              MIN_PEER_PROTO_VERSION;
    ok = ok && json_get_bool(json_get(p2p, "node_network"));
    ok = ok && json_get_bool(json_get(p2p, "node_zclassic23"));
    ok = ok && !json_get_bool(json_get(p2p, "node_bootstrap"));
    ok = ok && json_get_int(json_get(p2p,
                                      "advertised_start_height")) ==
              3170000;

    ok = ok && peers && peers->type == JSON_OBJ;
    ok = ok && json_get_int(json_get(peers, "connections")) == 5;
    ok = ok && json_get_int(json_get(peers,
        "zclassic23_peers")) == 2;
    return ok;
}

static bool sd_bootstrapstatus_ready_zclassic23_peer_quorum(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *peers = json_get(result, "peers");
    ok = ok && json_get_int(json_get(peers,
        "zclassic23_peer_connections")) == 3;
    ok = ok && json_get_int(json_get(peers,
        "zclassic23_duplicate_connections_excluded")) == 1;
    ok = ok && json_get_int(json_get(peers,
        "zclassic23_self_connections_excluded")) == 1;
    ok = ok && json_get_bool(json_get(peers,
        "local_zclassic23_node_included"));
    ok = ok && json_get_int(json_get(peers,
        "zclassic23_nodes_seen")) == 3;
    ok = ok && json_get_bool(json_get(peers,
        "zclassic23_two_node_floor_met"));
    ok = ok && json_get_bool(json_get(peers,
        "local_zclassic23_bootstrap_node_verified"));
    ok = ok && json_get_int(json_get(peers,
        "verified_zclassic23_bootstrap_nodes_seen")) == 3;
    ok = ok && json_get_bool(json_get(peers,
        "verified_zclassic23_two_node_floor_met"));
    ok = ok && json_get_int(json_get(peers,
        "legacy_compatible_peers")) == 1;
    ok = ok && json_get_int(json_get(peers,
        "verified_zclassic23_bootstrap_peer_count")) == 2;
    ok = ok && json_get_int(json_get(peers,
        "verified_zclassic23_bootstrap_connection_count")) == 3;
    return ok;
}

static bool sd_bootstrapstatus_ready_verified_peer_quorum(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *peers = json_get(result, "peers");
    const struct json_value *verified =
        peers ? json_get(peers,
            "verified_zclassic23_bootstrap_peers") : NULL;
    ok = ok && json_get_int(json_get(peers,
        "verified_zclassic23_duplicate_connections_excluded")) == 1;
    ok = ok && json_get_int(json_get(peers,
        "verified_zclassic23_self_connections_excluded")) == 1;
    ok = ok && json_get_int(json_get(peers,
        "fast_sync_useful_zclassic23_peer_count")) == 2;
    ok = ok && json_get_int(json_get(peers,
        "fast_sync_useful_zclassic23_connection_count")) == 3;
    ok = ok && json_get_int(json_get(peers,
        "zclassic23_bootstrap_quorum_target")) == 2;
    ok = ok && json_get_bool(json_get(peers,
        "zclassic23_bootstrap_quorum_met"));
    ok = ok && json_get_bool(json_get(peers,
        "zclassic23_fast_sync_quorum_met"));
    ok = ok && strcmp(json_get_str(json_get(peers,
        "zclassic23_bootstrap_quorum_status")),
                      "redundant") == 0;
    ok = ok && verified && verified->type == JSON_ARR;
    ok = ok && json_size(verified) == 2;
    return ok;
}

static bool sd_bootstrapstatus_ready_first_verified_peer(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *peers = json_get(result, "peers");
    const struct json_value *verified =
        peers ? json_get(peers,
            "verified_zclassic23_bootstrap_peers") : NULL;
    const struct json_value *first_verified =
        verified && json_size(verified) > 0 ? json_at(verified, 0) : NULL;
    ok = ok && first_verified && first_verified->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(first_verified,
        "verified_by")), "live_handshake") == 0;
    ok = ok && json_get_bool(json_get(first_verified,
        "bootstrap_useful"));
    ok = ok && json_get_bool(json_get(first_verified,
        "fast_sync_useful"));
    ok = ok && strcmp(json_get_str(json_get(first_verified,
        "bootstrap_readiness")), "useful") == 0;
    return ok;
}

static bool sd_bootstrapstatus_ready_addrman(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *addrman = json_get(result, "addrman");
    const struct json_value *zcl23 =
        json_get(result, "zclassic23_bootstrap");
    ok = ok && addrman && addrman->type == JSON_OBJ;
    ok = ok && json_get_int(json_get(addrman, "entries")) == 1;
    ok = ok && json_get_bool(json_get(addrman,
                                      "addr_relay_ready"));

    ok = ok && zcl23 && zcl23->type == JSON_OBJ;
    return ok;
}

static bool sd_bootstrapstatus_ready_zclassic23_bootstrap(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *zcl23 =
        json_get(result, "zclassic23_bootstrap");
    const struct json_value *loader =
        json_get(result, "snapshot_loader");
    ok = ok && strcmp(json_get_str(json_get(zcl23, "schema")),
                      "zcl.bootstrap.zclassic23.v1") == 0;
    ok = ok && json_get_bool(json_get(zcl23, "serving"));
    ok = ok && json_get_bool(json_get(zcl23,
        "preferred_for_fresh_zclassic23"));
    ok = ok && json_get_bool(json_get(zcl23, "full_node_bootstrap"));
    ok = ok && json_get_bool(json_get(zcl23, "addr_relay_ready"));
    ok = ok && strcmp(json_get_str(json_get(zcl23,
        "route_preference")),
                      "direct_p2p_then_znam_onion_fallback") == 0;
    ok = ok && strcmp(json_get_str(json_get(zcl23,
        "endpoint_record_schema")),
                      "zcl.names.service_record.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(zcl23,
        "clearnet_address")), "203.0.113.7") == 0;
    ok = ok && json_get_int(json_get(zcl23, "p2p_port")) == 8033;
    ok = ok && json_array_has_str(json_get(zcl23,
        "fresh_node_flow"), "fallback_to_onion_endpoint");

    ok = ok && loader && loader->type == JSON_OBJ;
    return ok;
}

static bool sd_bootstrapstatus_ready_snapshot_loader(const struct json_value *result,
                                           const char *snap_path)
{
    bool ok = true;
    const struct json_value *loader =
        json_get(result, "snapshot_loader");
    ok = ok && strcmp(json_get_str(json_get(loader, "schema")),
                      "zcl.snapshot_loader.v1") == 0;
    ok = ok && json_get_int(json_get(loader, "schema_version")) == 1;
    ok = ok && json_get_bool(json_get(loader, "bundle_present"));
    ok = ok && json_get_int(json_get(loader,
                                     "bundle_seed_height")) == 3170000;
    ok = ok && strcmp(json_get_str(json_get(loader, "bundle_path")),
                      snap_path) == 0;
    ok = ok && json_get_bool(json_get(loader,
                                      "block_index_present"));
    ok = ok && json_get_bool(json_get(loader, "bootable_bundle"));
    ok = ok && json_get_bool(json_get(loader,
        "active_loader_configured"));
    ok = ok && strcmp(json_get_str(json_get(loader,
        "active_loader_path")), snap_path) == 0;
    ok = ok && json_get_bool(json_get(loader,
        "active_loader_matches_bundle"));
    ok = ok && strcmp(json_get_str(json_get(loader,
        "recovery_hint")), "loader_active") == 0;
    return ok;
}

static bool sd_bootstrapstatus_ready_snapshot_authority_and_legacy(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *loader =
        json_get(result, "snapshot_loader");
    const struct json_value *authority = json_get(loader, "authority");
    const struct json_value *legacy =
        json_get(result, "legacy_p2p_bootstrap");
    ok = ok && authority && authority->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(authority, "schema")),
                      "zcl.snapshot_loader_authority.v1") == 0;
    ok = ok && !json_get_bool(json_get(authority,
                                       "progress_store_open"));
    ok = ok && !json_get_bool(json_get(authority,
                                       "coins_kv_proven_authority"));
    ok = ok && !json_get_bool(json_get(authority,
                                       "fast_rebuild_authority_ready"));
    ok = ok && strcmp(json_get_str(json_get(authority,
        "authority_posture")), "unknown_no_progress_store") == 0;

    ok = ok && legacy && legacy->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(legacy, "serving"));
    ok = ok && json_array_has_str(json_get(legacy, "messages"),
                                  "getheaders");
    ok = ok && json_array_has_str(json_get(legacy, "messages"),
                                  "getaddr");

    return ok;
}

static bool sd_bootstrapstatus_ready_beta6_snapshot(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *beta6 =
        json_get(result, "beta6_snapshot_bootstrap");
    ok = ok && beta6 && beta6->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(beta6,
                                            "required_service_bit")),
                      "NODE_BOOTSTRAP") == 0;
    ok = ok && json_get_int(json_get(beta6,
                                      "required_service_bit_value")) ==
              NODE_BOOTSTRAP;
    ok = ok && !json_get_bool(json_get(beta6, "advertised"));
    ok = ok && !json_get_bool(json_get(beta6, "serving"));
    ok = ok && json_array_has_str(json_get(beta6, "messages"),
                                  "getbsman");
    ok = ok && json_array_has_str(json_get(beta6, "messages"),
                                  "getbschk");

    ok = ok && json_array_has_str(json_get(result, "blockers"),
                                  "beta6_NODE_BOOTSTRAP_not_advertised");
    return ok;
}


static bool sd_bootstrapstatus_review_required_contract(const struct json_value *result)
{
    bool ok = true;
    ok = ok && !json_get_bool(json_get(result, "ok"));
    ok = ok && json_get_bool(json_get(result, "transport_ready"));
    ok = ok && json_get_bool(json_get(
        result, "security_review_required"));
    ok = ok && !json_get_bool(json_get(
        result, "security_posture_ok"));
    ok = ok && strcmp(json_get_str(json_get(
        result, "security_posture_status")),
        "review_required_test") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "readiness")),
                      "blocked") == 0;
    ok = ok && !json_get_bool(json_get(
        result, "serving_p2p_bootstrap"));
    ok = ok && !json_get_bool(json_get(
        result, "serving_addr_bootstrap"));
    ok = ok && !json_get_bool(json_get(
        result, "zclassic23_fast_sync_compatible"));
    return ok;
}

static bool sd_bootstrapstatus_review_required_bootstrap_sources(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *zcl23 =
        json_get(result, "zclassic23_bootstrap");
    const struct json_value *legacy =
        json_get(result, "legacy_p2p_bootstrap");
    ok = ok && zcl23 && !json_get_bool(json_get(zcl23, "serving"));
    ok = ok && legacy && !json_get_bool(json_get(legacy, "serving"));
    ok = ok && json_array_has_str(json_get(result, "blockers"),
                                  "review_required_test");
    return ok;
}

static bool sd_bootstrapstatus_snapshot_missing_index_loader(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *loader = json_get(result, "snapshot_loader");
    ok = ok && loader && loader->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(loader, "bundle_present"));
    ok = ok && !json_get_bool(json_get(loader,
                                       "block_index_present"));
    ok = ok && !json_get_bool(json_get(loader, "bootable_bundle"));
    ok = ok && !json_get_bool(json_get(loader,
        "active_loader_configured"));
    ok = ok && strcmp(json_get_str(json_get(loader,
        "recovery_hint")), "install_tip_seed_snapshot") == 0;

    return ok;
}

/* case: bootstrapstatus exposes the versioned P2P and beta6 snapshot
 * bootstrap contract for a transport-ready node with a quorum of
 * verified zclassic23 peers, then re-reads it once a security-review
 * override blocks every readiness claim, then again once the block
 * index file is missing from the snapshot bundle. */
static bool sd_bootstrapstatus_ready_phase1(struct sd_bootstrap_ctx *ctx)
{
    bool ok = sd_bootstrap_setup_connman(ctx);
    ok = sd_bootstrap_setup_addrman(ctx, ok);
    ok = sd_bootstrap_setup_peers(ctx, ok);

    rpc_table_init(&ctx->tbl);
    register_net_rpc_commands(&ctx->tbl);
    rpc_net_set_connman(&ctx->cm);
    rpc_net_set_boot_context(ctx->tmp_dir, ctx->snap_path);

    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "bootstrapstatus",
                                 &ctx->params, &ctx->result);
    ok = sd_bootstrapstatus_ready_contract(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_p2p_and_peers(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_zclassic23_peer_quorum(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_verified_peer_quorum(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_first_verified_peer(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_addrman(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_zclassic23_bootstrap(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_snapshot_loader(&ctx->result, ctx->snap_path) && ok;
    ok = sd_bootstrapstatus_ready_snapshot_authority_and_legacy(&ctx->result) && ok;
    ok = sd_bootstrapstatus_ready_beta6_snapshot(&ctx->result) && ok;
    return ok;
}

static bool sd_bootstrapstatus_ready_phase2(struct sd_bootstrap_ctx *ctx,
                                            bool ok)
{
    /* A transport-ready, tip-published node must still refuse every
     * serving/readiness claim while security posture requires review. */
    agent_security_posture_test_override_review_required(1);
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "bootstrapstatus",
                                 &ctx->params, &ctx->result);
    ok = sd_bootstrapstatus_review_required_contract(&ctx->result) && ok;
    ok = sd_bootstrapstatus_review_required_bootstrap_sources(&ctx->result) && ok;
    agent_security_posture_test_override_review_required(0);
    return ok;
}

static bool sd_bootstrapstatus_ready_phase3(struct sd_bootstrap_ctx *ctx,
                                            bool ok)
{
    ok = ok && unlink(ctx->index_path) == 0;
    rpc_net_set_boot_context(ctx->tmp_dir, NULL);
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "bootstrapstatus",
                                 &ctx->params, &ctx->result);
    ok = sd_bootstrapstatus_snapshot_missing_index_loader(&ctx->result) && ok;
    return ok;
}

static bool sd_bootstrapstatus_ready_teardown(struct sd_bootstrap_ctx *ctx,
                                              bool ok)
{
    json_free(&ctx->params);
    json_free(&ctx->result);
    rpc_net_set_connman(NULL);
    rpc_net_set_boot_context(NULL, NULL);
    msg_version_clear_external_ip_for_test();
    reducer_frontier_provable_tip_reset();
    connman_free(&ctx->cm);
    if (ctx->tmp_dir) {
        unlink(ctx->snap_path);
        unlink(ctx->index_path);
        rmdir(ctx->tmp_dir);
    }
    return ok;
}

bool sd_bootstrapstatus_ready_scenario(void)
{
    struct sd_bootstrap_ctx ctx;
    bool ok = sd_bootstrapstatus_ready_phase1(&ctx);
    ok = sd_bootstrapstatus_ready_phase2(&ctx, ok);
    ok = sd_bootstrapstatus_ready_phase3(&ctx, ok);
    return sd_bootstrapstatus_ready_teardown(&ctx, ok);
}

static bool sd_bootstrapstatus_authority_proven_not_folded(
    const struct json_value *result)
{
    bool ok = true;
    const struct json_value *loader =
        json_get(result, "snapshot_loader");
    const struct json_value *authority =
        loader ? json_get(loader, "authority") : NULL;
    ok = ok && authority && authority->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(authority,
                                      "progress_store_open"));
    ok = ok && json_get_bool(json_get(authority,
                                      "hstar_available"));
    ok = ok && json_get_int(json_get(authority, "hstar")) ==
              REDUCER_FRONTIER_TRUSTED_ANCHOR;
    ok = ok && json_get_bool(json_get(authority,
                                      "coins_applied_height_readable"));
    ok = ok && json_get_bool(json_get(authority,
                                      "coins_applied_height_present"));
    ok = ok && json_get_int(json_get(authority,
                                     "coins_applied_height")) ==
              REDUCER_FRONTIER_TRUSTED_ANCHOR + 1;
    ok = ok && json_get_bool(json_get(authority,
                                      "coins_kv_proven_authority"));
    return ok;
}

static bool sd_bootstrapstatus_authority_proven_not_folded_posture(
    const struct json_value *result)
{
    bool ok = true;
    const struct json_value *loader =
        json_get(result, "snapshot_loader");
    const struct json_value *authority =
        loader ? json_get(loader, "authority") : NULL;
    ok = ok && authority && authority->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(authority,
                                      "coins_cover_hstar"));
    ok = ok && json_get_bool(json_get(authority,
                                      "fast_rebuild_authority_ready"));
    ok = ok && !json_get_bool(json_get(authority,
                                       "self_folded_marker"));
    ok = ok && !json_get_bool(json_get(authority,
        "self_derived_tip_static_checks"));
    ok = ok && strcmp(json_get_str(json_get(authority,
        "self_derived_reason")), "borrowed_seed_no_refold_marker") == 0;
    ok = ok && strcmp(json_get_str(json_get(authority,
        "authority_posture")), "proven_but_not_self_folded") == 0;
    return ok;
}

static bool sd_bootstrapstatus_authority_self_folded(
    const struct json_value *result)
{
    bool ok = true;
    const struct json_value *loader =
        json_get(result, "snapshot_loader");
    const struct json_value *authority =
        loader ? json_get(loader, "authority") : NULL;
    ok = ok && authority && authority->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(authority,
                                      "self_folded_marker"));
    ok = ok && json_get_bool(json_get(authority,
        "self_derived_tip_static_checks"));
    ok = ok && strcmp(json_get_str(json_get(authority,
        "self_derived_reason")), "ok") == 0;
    ok = ok && strcmp(json_get_str(json_get(authority,
        "authority_posture")), "self_folded_marker_present") == 0;
    return ok;
}

/* case: bootstrapstatus's snapshot_loader.authority posture moves from
 * "proven but not self-folded" (a coins_kv authority proven from a
 * borrowed seed, no refold marker yet) to "self-folded marker present"
 * once the anchor is marked self-folded. */
struct sd_snapshot_authority_ctx {
    char dir[256];
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    sqlite3 *pdb;
};

static bool sd_snapshot_authority_setup(struct sd_snapshot_authority_ctx *ctx)
{
    test_reset_shared_globals();
    progress_store_close();
    chain_params_select(CHAIN_MAIN);

    test_make_tmpdir(ctx->dir, sizeof(ctx->dir), "syncdiag",
                     "bootstrap_authority");

    uint8_t txid[32] = {0};
    const uint8_t one = 0x01;
    ctx->pdb = NULL;
    bool ok = progress_store_open(ctx->dir);
    if (ok)
        ctx->pdb = progress_store_db();
    if (ok) {
        memset(txid, 0xB7, sizeof(txid));
        ok = ctx->pdb &&
             coins_kv_ensure_schema(ctx->pdb) &&
             syncdiag_seed_reducer_frontier_at_anchor(
                 ctx->pdb, REDUCER_FRONTIER_TRUSTED_ANCHOR) &&
             coins_kv_add(ctx->pdb, txid, 0, 5000000000LL,
                          REDUCER_FRONTIER_TRUSTED_ANCHOR, true,
                          NULL, 0) &&
             syncdiag_set_coins_applied(
                 ctx->pdb, REDUCER_FRONTIER_TRUSTED_ANCHOR + 1) &&
             progress_meta_set(ctx->pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                               &one, sizeof(one));
    }
    return ok;
}

static bool sd_snapshot_authority_rpc1(struct sd_snapshot_authority_ctx *ctx,
                                       bool ok)
{
    rpc_table_init(&ctx->tbl);
    register_net_rpc_commands(&ctx->tbl);
    rpc_net_set_connman(NULL);
    rpc_net_set_boot_context(ctx->dir, NULL);

    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "bootstrapstatus",
                                 &ctx->params, &ctx->result);
    ok = sd_bootstrapstatus_authority_proven_not_folded(&ctx->result) && ok;
    ok = sd_bootstrapstatus_authority_proven_not_folded_posture(
        &ctx->result) && ok;
    return ok;
}

static bool sd_snapshot_authority_rpc2(struct sd_snapshot_authority_ctx *ctx,
                                       bool ok)
{
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && coins_kv_mark_self_folded(ctx->pdb);
    ok = ok && rpc_table_execute(&ctx->tbl, "bootstrapstatus",
                                 &ctx->params, &ctx->result);
    ok = sd_bootstrapstatus_authority_self_folded(&ctx->result) && ok;
    return ok;
}

static bool sd_snapshot_authority_teardown(
    struct sd_snapshot_authority_ctx *ctx, bool ok)
{
    json_free(&ctx->params);
    json_free(&ctx->result);
    rpc_net_set_connman(NULL);
    rpc_net_set_boot_context(NULL, NULL);
    progress_store_close();
    test_cleanup_tmpdir(ctx->dir);
    test_reset_shared_globals();
    return ok;
}

bool sd_bootstrapstatus_snapshot_authority_scenario(void)
{
    struct sd_snapshot_authority_ctx ctx;
    bool ok = sd_snapshot_authority_setup(&ctx);
    ok = sd_snapshot_authority_rpc1(&ctx, ok);
    ok = sd_snapshot_authority_rpc2(&ctx, ok);
    return sd_snapshot_authority_teardown(&ctx, ok);
}

/* Fixture + phase helpers for the reachability-vs-handshake scenario:
 * an outbound and an inbound peer, one publishing a build identity in
 * its subversion; one addnode target that has already failed once over
 * TCP. */
struct sd_reach_ctx {
    struct connman cm;
    struct node_signals sigs;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
};

static bool sd_reachability_setup(struct sd_reach_ctx *ctx)
{
    chain_params_select(CHAIN_MAIN);
    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    bool ok = connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    struct p2p_node *outbound = syncdiag_add_peer(
        &ctx->cm, 11, false, PEER_HANDSHAKE_COMPLETE);
    struct p2p_node *inbound = syncdiag_add_peer(
        &ctx->cm, 12, true, PEER_HANDSHAKE_COMPLETE);
    ok = ok && outbound != NULL && inbound != NULL;
    if (inbound)
        inbound->accepted_local_port = 8055;
    /* One peer publishes a build identity in its subversion, one does
     * not (the fixture's default is the pre-change string an older node
     * still sends). getpeerinfo must report both — the identity for the
     * first, "unknown" for the second — so a stranger can ask their own
     * node what its peers are running without logging into any of them. */
    if (outbound) {
        snprintf(outbound->sub_ver, sizeof(outbound->sub_ver), "%s",
                 "/ZClassic23:0.1.0(src:" SYNCDIAG_PEER_SRC_PREFIX ")/");
        snprintf(outbound->clean_sub_ver, sizeof(outbound->clean_sub_ver),
                 "%s", outbound->sub_ver);
    }
    if (ok) {
        struct net_address addr;
        struct net_service svc;
        net_address_init(&addr);
        ok = lookup_numeric("51.178.179.75:8033", &svc,
                            ctx->cm.manager.default_port);
        if (ok) {
            addr.svc = svc;
            ctx->cm.addnodes[ctx->cm.num_addnodes++] = addr;
            connman_record_addnode_failure(&ctx->cm, 0,
                                           CONNMAN_ADDNODE_FAILURE_TCP);
        }
    }
    return ok;
}

/* case: getnetworkinfo separates inbound reachability from outbound
 * handshakes — initial state has one handshaked peer each way. */
static bool sd_reachability_initial_state_handshake_counts(struct sd_reach_ctx *ctx,
                                                bool ok)
{
    ok = ok && rpc_table_execute(&ctx->tbl, "getnetworkinfo",
                                 &ctx->params, &ctx->result);

    ok = ok && ctx->result.type == JSON_OBJ;
    ok = ok && json_get_int(json_get(&ctx->result,
                                     "handshaked_connections")) == 2;
    ok = ok && json_get_int(json_get(&ctx->result,
                                      "inbound_handshaked_connections"))
              == 1;
    ok = ok && json_get_int(json_get(&ctx->result,
                                      "outbound_handshaked_connections"))
              == 1;
    ok = ok && json_get_bool(json_get(&ctx->result,
                                      "inbound_handshake_seen"));
    ok = ok && json_get_bool(json_get(&ctx->result,
                                      "remote_handshake_seen"));
    ok = ok && json_get_int(json_get(&ctx->result,
                                      "legacy_compatible_peers")) ==
              json_get_int(json_get(&ctx->result, "magicbean_peers"));
    ok = ok && json_get_int(json_get(&ctx->result,
                                      "legacy_magicbean_peers")) ==
              json_get_int(json_get(&ctx->result, "magicbean_peers"));
    ok = ok && json_get_int(json_get(&ctx->result, "zclassic23_peers")) ==
              json_get_int(json_get(&ctx->result, "zclassic_c23_peers"));
    return ok;
}

/* case: the one addnode target already carries a TCP failure. */
static bool sd_reachability_initial_state_addnode_target(struct sd_reach_ctx *ctx,
                                                bool ok)
{
    const struct json_value *addnodes =
        json_get(&ctx->result, "addnode_status");
    const struct json_value *first =
        addnodes && addnodes->type == JSON_ARR ? json_at(addnodes, 0)
                                               : NULL;
    ok = ok && addnodes && addnodes->type == JSON_ARR;
    ok = ok && json_size(addnodes) == 1;
    ok = ok && first && json_get(first, "address") != NULL;
    ok = ok && first && json_get_int(json_get(first, "index")) == 0;
    ok = ok && first && !json_get_bool(json_get(first, "connected"));
    return ok;
}

static bool sd_reachability_initial_state_addnode_backoff(struct sd_reach_ctx *ctx,
                                                bool ok)
{
    const struct json_value *addnodes =
        json_get(&ctx->result, "addnode_status");
    const struct json_value *first =
        addnodes && addnodes->type == JSON_ARR ? json_at(addnodes, 0)
                                               : NULL;
    ok = ok && first &&
         json_get_int(json_get(first, "backoff_seconds")) > 0;
    ok = ok && first &&
         json_get_int(json_get(first, "backoff_remaining_seconds")) >= 0;
    ok = ok && first &&
         json_get_int(json_get(first, "tcp_failures")) == 1;
    ok = ok && first &&
         json_get_int(json_get(first, "protocol_failures")) == 0;
    return ok;
}

/* case: addnode remove drops the failing target, and getnetworkinfo's
 * addnode_status confirms it is gone. */
static bool sd_reachability_addnode_remove(struct sd_reach_ctx *ctx, bool ok)
{
    json_free(&ctx->params);
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, "51.178.179.75:8033");
    ok = ok && json_push_back(&ctx->params, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, "remove");
    ok = ok && json_push_back(&ctx->params, &v);
    json_free(&v);

    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "addnode", &ctx->params,
                                 &ctx->result);
    if (!ok)
        return ok;

    json_free(&ctx->params);
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "getnetworkinfo",
                                 &ctx->params, &ctx->result);
    const struct json_value *addnodes =
        json_get(&ctx->result, "addnode_status");
    ok = ok && addnodes && addnodes->type == JSON_ARR;
    ok = ok && json_size(addnodes) == 0;
    return ok;
}

/* case: removing an already-removed addnode target reports "not found";
 * an unrecognised action reports it "must be" one of the known ones. */
static bool sd_reachability_addnode_remove_not_found(
    struct sd_reach_ctx *ctx, bool ok)
{
    json_free(&ctx->params);
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, "51.178.179.75:8033");
    ok = ok && json_push_back(&ctx->params, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, "remove");
    ok = ok && json_push_back(&ctx->params, &v);
    json_free(&v);
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && !rpc_table_execute(&ctx->tbl, "addnode", &ctx->params,
                                  &ctx->result);
    ok = ok && strstr(json_get_str(&ctx->result), "not found") != NULL;
    return ok;
}

static bool sd_reachability_addnode_bogus_command(
    struct sd_reach_ctx *ctx, bool ok)
{
    json_free(&ctx->params);
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, "51.178.179.75:8033");
    ok = ok && json_push_back(&ctx->params, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, "bogus");
    ok = ok && json_push_back(&ctx->params, &v);
    json_free(&v);
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && !rpc_table_execute(&ctx->tbl, "addnode", &ctx->params,
                                  &ctx->result);
    ok = ok && strstr(json_get_str(&ctx->result), "must be") != NULL;
    return ok;
}

static bool sd_reachability_addnode_errors(struct sd_reach_ctx *ctx, bool ok)
{
    ok = sd_reachability_addnode_remove_not_found(ctx, ok);
    if (!ok)
        return ok;
    return sd_reachability_addnode_bogus_command(ctx, ok);
}

/* case: getpeerinfo reports one peer's build identity honestly (a known
 * SHA-256 prefix, not a promoted full identity) and the other's absence
 * of one the same way an unstamped local build spells it. */
static bool sd_reachability_peerinfo_call(struct sd_reach_ctx *ctx, bool ok)
{
    json_free(&ctx->params);
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_free(&ctx->result);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "getpeerinfo",
                                 &ctx->params, &ctx->result);
    return ok;
}

static bool sd_reachability_peerinfo_peer0(const struct json_value *result,
                                           bool ok)
{
    const struct json_value *peer0 =
        result->type == JSON_ARR ? json_at(result, 0) : NULL;
    ok = ok && peer0 && json_get_bool(json_get(peer0, "zclassic23"));
    ok = ok && peer0 && json_get_bool(json_get(peer0, "zclassic_c23"));
    ok = ok && peer0 && json_get(peer0, "lifecycle") == NULL;
    ok = ok && peer0 &&
         json_get_int(json_get(peer0, "accepted_local_port")) == 0;
    return ok;
}

static bool sd_reachability_peerinfo_peer1(const struct json_value *result,
                                           bool ok)
{
    const struct json_value *peer1 =
        result->type == JSON_ARR ? json_at(result, 1) : NULL;
    ok = ok && peer1 &&
         json_get_int(json_get(peer1, "accepted_local_port")) == 8055;
    ok = ok && peer1 &&
         !json_get_bool(json_get(peer1, "source_is_loopback"));
    ok = ok && peer1 &&
         !json_get_bool(json_get(peer1, "onion_ingress_candidate"));
    return ok;
}

/* case: the compact wire prefix is named honestly; it is not promoted
 * into a full source identity that the peer did not publish. */
static bool sd_reachability_peerinfo_identity0(
    const struct json_value *result, bool ok)
{
    const struct json_value *peer0 =
        result->type == JSON_ARR ? json_at(result, 0) : NULL;
    ok = ok && peer0 && !json_get_bool(json_get(peer0, "source_id_known"));
    ok = ok && peer0 &&
         json_get_bool(json_get(peer0, "source_id_prefix_known"));
    ok = ok && peer0 &&
         strcmp(json_get_str(json_get(peer0, "source_id_sha256")),
                "unknown") == 0;
    ok = ok && peer0 &&
         strcmp(json_get_str(json_get(peer0, "source_id_prefix")),
                SYNCDIAG_PEER_SRC_PREFIX) == 0;
    return ok;
}

/* case: identity absence is a normal answer, spelled the same way an
 * unstamped local build spells it in getnetworkinfo — never an error. */
static bool sd_reachability_peerinfo_identity1(
    const struct json_value *result, bool ok)
{
    const struct json_value *peer1 =
        result->type == JSON_ARR ? json_at(result, 1) : NULL;
    ok = ok && peer1 && !json_get_bool(json_get(peer1, "source_id_known"));
    ok = ok && peer1 &&
         !json_get_bool(json_get(peer1, "source_id_prefix_known"));
    ok = ok && peer1 &&
         strcmp(json_get_str(json_get(peer1, "source_id_sha256")),
                "unknown") == 0;
    return ok;
}

/* case: getnetworkinfo separates inbound reachability from outbound
 * handshakes, addnode remove/re-remove/bogus-action error handling, and
 * getpeerinfo's honest build-identity reporting, all against one
 * connman fixture. */
bool sd_getnetworkinfo_reachability_scenario(void)
{
    struct sd_reach_ctx ctx;
    bool ok = sd_reachability_setup(&ctx);

    rpc_table_init(&ctx.tbl);
    register_net_rpc_commands(&ctx.tbl);
    rpc_net_set_connman(&ctx.cm);

    json_init(&ctx.params);
    json_set_array(&ctx.params);
    json_init(&ctx.result);

    ok = ok && sd_reachability_initial_state_handshake_counts(&ctx, ok);
    ok = ok && sd_reachability_initial_state_addnode_target(&ctx, ok);
    ok = ok && sd_reachability_initial_state_addnode_backoff(&ctx, ok);
    ok = ok && sd_reachability_addnode_remove(&ctx, ok);
    ok = ok && sd_reachability_addnode_errors(&ctx, ok);
    ok = ok && sd_reachability_peerinfo_call(&ctx, ok);
    ok = ok && sd_reachability_peerinfo_peer0(&ctx.result, ok);
    ok = ok && sd_reachability_peerinfo_peer1(&ctx.result, ok);
    ok = ok && sd_reachability_peerinfo_identity0(&ctx.result, ok);
    ok = ok && sd_reachability_peerinfo_identity1(&ctx.result, ok);

    json_free(&ctx.params);
    json_free(&ctx.result);
    rpc_net_set_connman(NULL);
    connman_free(&ctx.cm);
    return ok;
}
