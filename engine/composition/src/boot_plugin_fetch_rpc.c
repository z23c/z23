/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resident plugin_fetch_begin / plugin_fetch_poll. begin starts a
 *          bounded swarm fetch of one package root from this node's own peers
 *          and returns a job id at once; the job then runs the same
 *          verify-and-install path `plugin fetch` uses (plugin_dist_receive)
 *          on the resident package store, as a NEW generation. Nothing is
 *          switched or run. Owner-only and local: the RPC listener is local
 *          and cookie-authenticated, the CLI leaves are REMOTE_CLASS_NEVER, and
 *          the datadir and plugin store are never taken from input. */

#include "config/boot_plugin_fetch.h"

#include "config/boot_zcode_swarm.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "plugin/plugin_fetch_job.h"
#include "rpc/server.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static struct plugin_fetch_table *g_table;

static const struct json_value *fetch_input(const struct json_value *params)
{
    const struct json_value *first = params && json_size(params) ? json_at(params, 0) : NULL;
    return first && first->type == JSON_OBJ ? first : NULL;
}

static void fetch_error(struct json_value *result, const char *code, const char *message,
                        const char *next_action)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", false);
    json_push_kv_str(result, "code", code);
    json_push_kv_str(result, "message", message);
    if (next_action && next_action[0])
        json_push_kv_str(result, "next_action", next_action);
}

/* The resident handles for one call; false (named) when hosting is off. */
static bool fetch_ctx(struct plugin_fetch_ctx *ctx, char plugins[PATH_MAX], char scratch[PATH_MAX])
{
    struct vcs_package_store *store = vcs_package_store_global();
    const char *root = vcs_package_store_root_dir(store);
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!store || !engine || !root || !zcl_native_plugin_root(plugins, PATH_MAX))
        return false;
    if (snprintf(scratch, PATH_MAX, "%s/plugin-dist", root) >= PATH_MAX ||
        (mkdir(scratch, 0700) != 0 && errno != EEXIST))
        return false;
    *ctx = (struct plugin_fetch_ctx){
        .engine = engine, .store = store, .plugins_dir = plugins, .scratch_dir = scratch
    };
    return true;
}

static bool fetch_int(const struct json_value *in, const char *key, uint64_t *out, bool *bad)
{
    const struct json_value *v = json_get(in, key);
    if (!v)
        return false;
    int64_t n = v->type == JSON_INT ? json_get_int(v) : -1;
    if (n < 0)
        *bad = true;
    else
        *out = (uint64_t)n;
    return true;
}

/* Reads the request fields; false (result filled) on any malformed one. */
static bool fetch_parse(const struct json_value *in, struct plugin_fetch_request *rq,
                        uint64_t peers[PLUGIN_FETCH_PEERS_MAX], struct json_value *result)
{
    const char *hex = json_get_str(json_get(in, "root"));
    bool bad = false;
    uint64_t timeout = 0;
    memset(rq, 0, sizeof(*rq));
    rq->name = json_get_str(json_get(in, "name"));
    (void)fetch_int(in, "max_bytes", &rq->max_bytes, &bad);
    (void)fetch_int(in, "timeout_s", &timeout, &bad);
    rq->timeout_s = timeout > UINT32_MAX ? UINT32_MAX : (uint32_t)timeout;
    const struct json_value *allow = json_get(in, "allow_downgrade");
    rq->allow_downgrade = allow && allow->type == JSON_BOOL && json_get_bool(allow);
    const struct json_value *list = json_get(in, "peers");
    if (list && (list->type != JSON_ARR || json_size(list) > PLUGIN_FETCH_PEERS_MAX))
        bad = true;
    for (size_t i = 0; list && !bad && i < json_size(list); i++) {
        const struct json_value *p = json_at(list, i);
        int64_t id = p && p->type == JSON_INT ? json_get_int(p) : -1;
        if (id <= 0)
            bad = true;
        else
            peers[rq->peer_count++] = (uint64_t)id;
    }
    rq->peers = rq->peer_count ? peers : NULL;
    if (bad || !hex || strlen(hex) != 64u || !zcl_hex_decode_lower(hex, rq->root, 32) || !rq->name) {
        fetch_error(result, "PLUGIN_FETCH_ARGUMENT",
                    "root (64 lowercase hex), name, and optional peers (positive ints), max_bytes, "
                    "timeout_s, allow_downgrade are required in one input object",
                    "pass the missing or malformed argument; see the command's usage");
        return false;
    }
    return true;
}

static bool fetch_begin(const struct json_value *params, bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result, "plugin_fetch_begin {root,name,peers?,max_bytes?,timeout_s?,allow_downgrade?}");
        return true;
    }
    const struct json_value *in = fetch_input(params);
    struct plugin_fetch_request rq;
    uint64_t peers[PLUGIN_FETCH_PEERS_MAX];
    char plugins[PATH_MAX], scratch[PATH_MAX];
    struct plugin_fetch_ctx ctx;
    if (!in || json_get(in, "datadir") || json_get(in, "plugins_dir")) {
        fetch_error(result, "PLUGIN_FETCH_ARGUMENT",
                    "one input object without datadir or plugins_dir is required (both are implicit)",
                    "pass root and name only");
        return true;
    }
    if (!fetch_parse(in, &rq, peers, result))
        return true;
    if (!g_table || !fetch_ctx(&ctx, plugins, scratch)) {
        fetch_error(result, "PLUGIN_FETCH_NO_SWARM", "package hosting is not running on this node",
                    "start the node with -packagehost=1");
        return true;
    }
    struct plugin_fetch_begin_result r;
    plugin_fetch_begin(g_table, &ctx, &rq, (uint64_t)platform_time_wall_time_t(), &r);
    if (r.status != PLUGIN_FETCH_BEGIN_OK) {
        fetch_error(result, plugin_fetch_begin_code(r.status), r.detail, "");
        return true;
    }
    /* The WANTs go out now, not on the next periodic turn. */
    boot_zcode_swarm_request_tick();
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.plugin_fetch_job.v1");
    json_push_kv_int(result, "job", (int64_t)r.job);
    json_push_kv_bool(result, "existing", r.existing);
    json_push_kv_str(result, "state", "fetching");
    return true;
}

static void fetch_render(struct json_value *result, const struct plugin_fetch_view *v)
{
    json_set_object(result);
    json_push_kv_bool(result, "ok", true);
    json_push_kv_str(result, "schema", "zcl.plugin_fetch_job.v1");
    json_push_kv_int(result, "job", (int64_t)v->job);
    json_push_kv_str(result, "state", plugin_fetch_state_string(v->state));
    json_push_kv_str(result, "root", v->root_hex);
    json_push_kv_str(result, "name", v->name);
    json_push_kv_int(result, "started", (int64_t)v->started);
    json_push_kv_int(result, "deadline", (int64_t)v->deadline);
    json_push_kv_int(result, "max_bytes", (int64_t)v->max_bytes);
    json_push_kv_int(result, "present_chunks", v->present_chunks);
    json_push_kv_int(result, "total_chunks", v->total_chunks);
    json_push_kv_int(result, "present_bytes", (int64_t)v->present_bytes);
    json_push_kv_int(result, "total_bytes", (int64_t)v->total_bytes);
    if (v->state == PLUGIN_FETCH_FAILED) {
        json_push_kv_str(result, "code", v->code);
        json_push_kv_str(result, "detail", v->detail);
        json_push_kv_str(result, "next_action", v->next_action);
    } else if (v->state == PLUGIN_FETCH_INSTALLED) {
        json_push_kv_str(result, "version", v->version);
        json_push_kv_str(result, "generation", v->generation);
        json_push_kv_bool(result, "already_present", v->already_present);
        json_push_kv_bool(result, "downgrade_allowed", v->downgrade_allowed);
        json_push_kv_bool(result, "switched", false);
    }
}

static bool fetch_poll(const struct json_value *params, bool help, struct json_value *result)
{
    if (help) {
        json_set_str(result, "plugin_fetch_poll {job}");
        return true;
    }
    const struct json_value *in = fetch_input(params);
    const struct json_value *id = in ? json_get(in, "job") : NULL;
    int64_t job = id && id->type == JSON_INT ? json_get_int(id) : 0;
    char plugins[PATH_MAX], scratch[PATH_MAX];
    struct plugin_fetch_ctx ctx;
    struct plugin_fetch_view v;
    if (job <= 0) {
        fetch_error(result, "PLUGIN_FETCH_ARGUMENT", "job must be a positive integer", "");
        return true;
    }
    if (g_table && fetch_ctx(&ctx, plugins, scratch))
        plugin_fetch_advance(g_table, &ctx, (uint64_t)platform_time_wall_time_t());
    if (!g_table || !plugin_fetch_status(g_table, (uint64_t)job, &v)) {
        fetch_error(result, "PLUGIN_FETCH_UNKNOWN_JOB", "no such job; finished jobs are dropped oldest first",
                    "start a new fetch");
        return true;
    }
    fetch_render(result, &v);
    return true;
}

void boot_plugin_fetch_tick(void)
{
    char plugins[PATH_MAX], scratch[PATH_MAX];
    struct plugin_fetch_ctx ctx;
    if (g_table && fetch_ctx(&ctx, plugins, scratch))
        plugin_fetch_advance(g_table, &ctx, (uint64_t)platform_time_wall_time_t());
}

void boot_plugin_fetch_register_rpc(struct rpc_table *table)
{
    if (!g_table)
        g_table = plugin_fetch_table_new();
    const struct rpc_command commands[] = {
        { "plugin", "plugin_fetch_begin", fetch_begin, true },
        { "plugin", "plugin_fetch_poll", fetch_poll, true },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(table, &commands[i]);
}
