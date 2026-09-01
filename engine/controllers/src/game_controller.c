/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Game Controller — RPC interface for the P2P game platform.
 *
 * Exposes game type registry, latency measurement, and game sessions
 * to CLI users and external tools. */

#include "controllers/game_controller.h"
#include "controllers/strong_params.h"
#include "net/p2p_game.h"
#include "json/json.h"
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "util/log_macros.h"

/* ── Controller context ──────────────────────────────────────── */

struct game_context {
    struct connman *connman;
};

static struct game_context g_game_ctx = {0};

void rpc_game_set_connman(struct connman *cm)
{
    g_game_ctx.connman = cm;
}

/* ── Find peer by ID ─────────────────────────────────────────── */

static struct p2p_node *find_peer_by_id(int64_t peer_id)
{
    struct connman *cm = g_game_ctx.connman;
    if (!cm) return NULL;

    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *node = cm->manager.nodes[i];
        if (node && (int64_t)node->id == peer_id)
            return node;
    }
    return NULL;
}

/* ── RPC: gametypes ──────────────────────────────────────────── */

static bool rpc_gametypes(const struct json_value *params, bool help,
                          struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "gametypes\n"
        "\nList all registered P2P game types.\n"
        "\nResult: array of game type objects with id, name, and state_size.");

    json_set_array(result);

    const struct game_type_def *types = game_type_list();
    for (const struct game_type_def *g = types; g->name; g++) {
        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_int(&entry, "id", (int64_t)g->type_id);
        json_push_kv_str(&entry, "name", g->name);
        json_push_kv_int(&entry, "state_size", (int64_t)g->state_size);
        json_push_back(result, &entry);
        json_free(&entry);
    }

    return true;
}

/* ── RPC: pingpeer ───────────────────────────────────────────── */

static bool rpc_pingpeer(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "pingpeer peer_id\n"
        "\nSend a P2P ping game to measure round-trip latency.\n"
        "\nArguments:\n"
        "1. peer_id (numeric) — connected peer ID from getpeerinfo\n"
        "\nResult: object with latency measurements (from existing P2P ping).");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    int64_t peer_id = rpc_require_int(&p, 0, "peer_id");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    struct connman *cm = g_game_ctx.connman;
    if (!cm) {
        json_set_str(result, "P2P not initialized");
        return false;
    }

    zcl_mutex_lock(&cm->manager.cs_nodes);
    struct p2p_node *node = find_peer_by_id(peer_id);

    if (!node) {
        zcl_mutex_unlock(&cm->manager.cs_nodes);
        json_set_str(result, "Peer not found");
        return false;
    }

    json_set_object(result);
    json_push_kv_int(result, "peer_id", (int64_t)node->id);
    json_push_kv_str(result, "addr", node->addr_name);
    json_push_kv_int(result, "ping_usec", node->ping_usec_time);
    json_push_kv_int(result, "min_ping_usec", node->min_ping_usec_time);
    json_push_kv_int(result, "avg_latency_usec", node->avg_latency_us);

    double ping_ms = (double)node->ping_usec_time / 1000.0;
    double min_ms = (double)node->min_ping_usec_time / 1000.0;
    double avg_ms = (double)node->avg_latency_us / 1000.0;
    json_push_kv_real(result, "ping_ms", ping_ms);
    json_push_kv_real(result, "min_ping_ms", min_ms);
    json_push_kv_real(result, "avg_latency_ms", avg_ms);

    /* Queue a fresh ping if one isn't already pending */
    if (!node->ping_queued && node->ping_nonce_sent == 0) {
        node->ping_queued = true;
        json_push_kv_bool(result, "ping_queued", true);
    } else {
        json_push_kv_bool(result, "ping_queued", false);
    }

    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return true;
}

/* ── RPC: getpeerlatency ─────────────────────────────────────── */

static bool rpc_getpeerlatency(const struct json_value *params, bool help,
                               struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getpeerlatency\n"
        "\nReturn latency measurements for all connected peers.\n"
        "\nResult: array of objects with peer_id, addr, ping_ms, min_ping_ms.");

    struct connman *cm = g_game_ctx.connman;
    if (!cm) {
        json_set_array(result);
        return true;
    }

    json_set_array(result);

    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *node = cm->manager.nodes[i];
        if (!node || node->version == 0) continue;

        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_int(&entry, "peer_id", (int64_t)node->id);
        json_push_kv_str(&entry, "addr", node->addr_name);
        json_push_kv_bool(&entry, "inbound", node->inbound);
        json_push_kv_real(&entry, "ping_ms",
            (double)node->ping_usec_time / 1000.0);
        json_push_kv_real(&entry, "min_ping_ms",
            (double)node->min_ping_usec_time / 1000.0);
        json_push_kv_real(&entry, "avg_latency_ms",
            (double)node->avg_latency_us / 1000.0);
        json_push_kv_int(&entry, "version", (int64_t)node->version);
        json_push_kv_str(&entry, "subver", node->clean_sub_ver);
        json_push_back(result, &entry);
        json_free(&entry);
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);

    return true;
}

/* ── REST API helpers ─────────────────────────────────────────── */

bool api_gametypes(struct json_value *result)
{
    return rpc_gametypes(NULL, false, result);
}

bool api_getpeerlatency(struct json_value *result)
{
    return rpc_getpeerlatency(NULL, false, result);
}

/* ── Registration ────────────────────────────────────────────── */

void register_game_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "game", "gametypes",      rpc_gametypes,      true },
        { "game", "pingpeer",       rpc_pingpeer,       true },
        { "game", "getpeerlatency", rpc_getpeerlatency, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
