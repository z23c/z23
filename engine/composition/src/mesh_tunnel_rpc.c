/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The node-side verbs behind `z23 dev fleet tunnel`. Each one is a
 * thin, bounded adapter over config/mesh_tunnel.h: the decisions, the allow
 * table and the sockets all live there, and nothing here widens any of
 * them. Every refusal is the tunnel's own named token. */

#include "config/mesh_tunnel.h"

#include "json/json.h"
#include "rpc/server.h"
#include "util/log_macros.h"

#include <string.h>

static const struct json_value *tun_input(const struct json_value *params)
{
    const struct json_value *first =
        params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static const char *tun_str(const struct json_value *in, const char *key)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static int64_t tun_int(const struct json_value *in, const char *key)
{
    const struct json_value *value = in ? json_get(in, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : -1;
}

/* A port the caller named: 1..65535, or -1 for "absent". Anything else is
 * not a port and is refused rather than clamped. */
static bool tun_port(const struct json_value *in, const char *key,
                     bool required, uint16_t *out)
{
    int64_t raw = tun_int(in, key);
    if (raw < 0)
        return !required && (*out = 0, true);
    if (raw == 0 || raw > 65535)
        return false;
    *out = (uint16_t)raw;
    return true;
}

/* One named refusal, in the tunnel's own vocabulary. */
static void tun_refuse(struct json_value *result,
                       enum mesh_tunnel_refusal reason)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "refusal", mesh_tunnel_refusal_string(reason));
    LOG_WARN("net.mesh_tunnel", "tunnel verb refused: %s",
             mesh_tunnel_refusal_string(reason));
}

static bool rpc_tunnel_open(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_tunnel_open {\"peer\":\"<64 lowercase "
                             "hex>\",\"remote_port\":22,\"local_port\":0}");
        return true;
    }
    const struct json_value *in = tun_input(params);
    uint16_t remote = 0, local = 0;
    if (!tun_port(in, "remote_port", true, &remote) ||
        !tun_port(in, "local_port", false, &local)) {
        tun_refuse(result, MESH_TUNNEL_REFUSED_MALFORMED);
        return true;
    }
    uint64_t tunnel_id = 0;
    uint16_t bound = 0;
    enum mesh_tunnel_refusal r = mesh_tunnel_listen(
        tun_str(in, "peer"), remote, local, &tunnel_id, &bound);
    if (r != MESH_TUNNEL_OK) {
        tun_refuse(result, r);
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_int(result, "tunnel_id", (int64_t)tunnel_id);
    json_push_kv_int(result, "local_port", (int64_t)bound);
    json_push_kv_int(result, "remote_port", (int64_t)remote);
    json_push_kv_str(result, "local_host", "127.0.0.1");
    return true;
}

static bool rpc_tunnel_close(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_tunnel_close {\"tunnel_id\":<id>}");
        return true;
    }
    int64_t id = tun_int(tun_input(params), "tunnel_id");
    if (id <= 0 || !mesh_tunnel_close((uint64_t)id)) {
        tun_refuse(result, MESH_TUNNEL_REFUSED_MALFORMED);
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_int(result, "tunnel_id", id);
    return true;
}

static bool rpc_tunnel_list(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    if (help) {
        json_set_str(result, "mesh_tunnel_list {}");
        return true;
    }
    struct mesh_tunnel_row rows[MESH_TUNNEL_LISTENERS_MAX];
    size_t total = 0;
    size_t count = mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total);
    struct mesh_tunnel_allow_row allow[MESH_TUNNEL_ALLOW_MAX];
    size_t allow_total = 0;
    size_t allow_count =
        mesh_tunnel_allow_list(allow, MESH_TUNNEL_ALLOW_MAX, &allow_total);

    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_int(&row, "tunnel_id", (int64_t)rows[i].tunnel_id);
        json_push_kv_str(&row, "peer", rows[i].peer);
        json_push_kv_int(&row, "local_port", (int64_t)rows[i].local_port);
        json_push_kv_int(&row, "remote_port", (int64_t)rows[i].remote_port);
        json_push_kv_int(&row, "streams_open", (int64_t)rows[i].streams_open);
        json_push_kv_int(&row, "streams_total",
                         (int64_t)rows[i].streams_total);
        json_push_kv_int(&row, "bytes_out", (int64_t)rows[i].bytes_to_peer);
        json_push_kv_int(&row, "bytes_in", (int64_t)rows[i].bytes_from_peer);
        json_push_kv_int(&row, "opened_unix", rows[i].opened_unix);
        json_push_back(&list, &row);
        json_free(&row);
    }
    json_push_kv(result, "tunnels", &list);
    json_free(&list);
    json_push_kv_int(result, "tunnels_total", (int64_t)total);

    struct json_value rules;
    json_init(&rules);
    json_set_array(&rules);
    for (size_t i = 0; i < allow_count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "peer", allow[i].peer);
        json_push_kv_int(&row, "port", (int64_t)allow[i].port);
        json_push_kv_str(&row, "why", allow[i].why);
        json_push_back(&rules, &row);
        json_free(&row);
    }
    json_push_kv(result, "allow", &rules);
    json_free(&rules);
    json_push_kv_int(result, "allow_total", (int64_t)allow_total);
    return true;
}

static bool rpc_tunnel_allow(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_tunnel_allow {\"peer\":\"<64 lowercase "
                             "hex>\",\"port\":22,\"why\":\"ssh\"}");
        return true;
    }
    const struct json_value *in = tun_input(params);
    uint16_t port = 0;
    if (!tun_port(in, "port", true, &port)) {
        tun_refuse(result, MESH_TUNNEL_REFUSED_MALFORMED);
        return true;
    }
    enum mesh_tunnel_refusal r =
        mesh_tunnel_allow(tun_str(in, "peer"), port, tun_str(in, "why"));
    if (r != MESH_TUNNEL_OK) {
        tun_refuse(result, r);
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "peer", tun_str(in, "peer"));
    json_push_kv_int(result, "port", (int64_t)port);
    return true;
}

static bool rpc_tunnel_deny(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result, "mesh_tunnel_deny {\"peer\":\"<64 lowercase "
                             "hex>\",\"port\":22}");
        return true;
    }
    const struct json_value *in = tun_input(params);
    uint16_t port = 0;
    if (!tun_port(in, "port", true, &port) ||
        !mesh_tunnel_deny(tun_str(in, "peer"), port)) {
        tun_refuse(result, MESH_TUNNEL_REFUSED_TARGET_NOT_ALLOWED);
        return true;
    }
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "peer", tun_str(in, "peer"));
    json_push_kv_int(result, "port", (int64_t)port);
    return true;
}

void mesh_tunnel_register_rpc(struct rpc_table *table)
{
    if (!table) {
        LOG_ERROR("net.mesh_tunnel", "RPC registration requires rpc_table");
        return;
    }
    const struct rpc_command commands[] = {
        {"mesh", "mesh_tunnel_open", rpc_tunnel_open, true},
        {"mesh", "mesh_tunnel_close", rpc_tunnel_close, true},
        {"mesh", "mesh_tunnel_list", rpc_tunnel_list, true},
        {"mesh", "mesh_tunnel_allow", rpc_tunnel_allow, true},
        {"mesh", "mesh_tunnel_deny", rpc_tunnel_deny, true},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
