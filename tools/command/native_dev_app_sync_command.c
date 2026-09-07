/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: `dev app sync` — one App topic's replication seen from the
 * operator's side: what this node holds, the frontier it would ask a peer
 * with, and the named refusal when a peer is asked for over a link this
 * process does not have.
 *
 * The pull itself lives in engine/services/src/app_event_sync.c and the
 * wire in engine/modules/appsync. This leaf composes the two things that
 * are the OPERATOR's, and nothing else:
 *
 *   the SCOPE — app id, topic, chain and the topic's byte budget — compiled
 *   from the checkout's own apps/<id>/app.def and the selected chain's
 *   genesis. Host policy, never anything a row said about itself.
 *
 *   the PEER — a name, and a session to ask over. A one-shot command
 *   launched from a checkout holds neither a mesh identity nor a paired
 *   Noise session, so naming a peer here is refused by name today. The
 *   refusal is the honest answer, not a placeholder: a pull that cannot
 *   prove who answered would be worse than no pull.
 */

#include "command/native_command.h"

#include "appsync/app_event_sync.h"
#include "base/bytes.h"
#include "chain/chainparams.h"
#include "base/hex.h"
#include "framework/app_definition.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/app_event_sync_service.h"

#include <stdio.h>
#include <string.h>

#define APP_SYNC_LEAF_EVIDENCE "dev.app.sync"

static void app_sync_refuse(struct zcl_command_reply *reply, const char *code,
                            const char *phase, const char *message,
                            const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                           message, evidence);
}

/* The checkout this command was launched from. Same rule the other dev
 * leaves use: the dispatcher's own context first, the environment second,
 * and the working directory last. */
static const char *app_sync_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

/* Host policy for one (app_id, topic), compiled from the App's own
 * declaration. The byte budget is the topic's, not a number this command
 * chose, and the chain is the selected network's genesis — so an event can
 * neither widen its topic's budget nor claim to belong to another chain. */
static bool app_sync_scope(const char *root, const char *app_id,
                           const char *topic,
                           struct zcl_app_event_scope_v1 *out,
                           const char **why)
{
    struct zcl_app_definition_v1 def;
    struct zcl_result parsed = zcl_app_definition_load_v1(root, app_id, &def);
    if (!parsed.ok) {
        *why = "no such App in this checkout, or its app.def would not parse";
        return false;
    }
    const struct chain_params *params = chain_params_get();
    if (!params) {
        *why = "no chain parameters are selected, so no chain id exists";
        return false;
    }
    for (size_t i = 0; i < def.topic_count; i++) {
        if (strcmp(def.topics[i].name, topic) != 0)
            continue;
        memset(out, 0, sizeof(*out));
        out->struct_size = sizeof(*out);
        (void)snprintf(out->app_id, sizeof(out->app_id), "%s", app_id);
        (void)snprintf(out->topic, sizeof(out->topic), "%s", topic);
        memcpy(out->chain_id, params->consensus.hashGenesisBlock.data,
               sizeof(out->chain_id));
        out->max_event_bytes = def.topics[i].max_event_bytes;
        return true;
    }
    *why = "that App declares no such P2P topic";
    return false;
}

/* `<datadir>/node.db`, absolute or nothing. A relative datadir resolves
 * against whatever directory the caller happened to be in, which is how two
 * processes quietly end up looking at two different databases. */
static bool app_sync_db_path(char *out, size_t cap)
{
    const char *datadir = zcl_native_command_datadir();
    if (!datadir || datadir[0] != '/')
        return false;
    return (size_t)snprintf(out, cap, "%s/node.db", datadir) < cap;
}

static void app_sync_push_frontier(struct json_value *data,
                                   const struct zcl_app_sync_frontier *f)
{
    (void)json_push_kv_int(data, "held", (int64_t)f->rows);
    if (f->have) {
        char hex[65] = { 0 };
        zcl_hex_encode(f->event_id, 32, hex);
        (void)json_push_kv_str(data, "frontier", hex);
    } else {
        /* An empty topic has no frontier, and saying "0000..." would be a
         * value where there is none. */
        (void)json_push_kv_str(data, "frontier", "");
    }
}

/* ── dev.app.sync ──────────────────────────────────────────────────────── */

void zcl_native_handle_dev_app_sync(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.dev_app_sync.v1");
    const char *app_id = json_get_str(json_get(request->input, "app_id"));
    const char *topic = json_get_str(json_get(request->input, "topic"));
    const char *peer = json_get_str(json_get(request->input, "peer"));
    if (!app_id || !app_id[0] || !topic || !topic[0]) {
        app_sync_refuse(reply, "MISSING_ARGS", "normalize",
                        "app_id and topic are both required",
                        APP_SYNC_LEAF_EVIDENCE);
        return;
    }

    struct zcl_app_event_scope_v1 scope;
    const char *why = "";
    if (!app_sync_scope(app_sync_source_root(request), app_id, topic, &scope,
                        &why)) {
        app_sync_refuse(reply, "UNKNOWN_TOPIC", "resolve", why, topic);
        return;
    }

    char path[512];
    if (!app_sync_db_path(path, sizeof(path))) {
        app_sync_refuse(reply, "DATADIR_UNAVAILABLE", "datadir",
                        "the datadir must be an absolute path",
                        APP_SYNC_LEAF_EVIDENCE);
        return;
    }
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, path)) {
        app_sync_refuse(reply, "NODE_DB_UNAVAILABLE", "open",
                        "the node database under this datadir would not open",
                        path);
        return;
    }

    struct zcl_app_sync_frontier frontier;
    bool read = zcl_app_event_sync_frontier(&ndb, scope.app_id, scope.topic,
                                            &frontier);
    /* A peer named is a pull asked for, and this process holds no paired
     * session to ask over. The refusal names the peer and the rule, and
     * nothing was written: `zcl_app_event_replicate` refuses before it
     * touches the table. */
    struct zcl_app_sync_report report;
    memset(&report, 0, sizeof(report));
    bool asked = peer && peer[0];
    int64_t arrival = (int64_t)platform_time_wall_time_t();
    if (read && asked && arrival > 0) {
        struct zcl_app_sync_peer target = {
            .name = peer, .ask = NULL, .ctx = NULL,
        };
        (void)zcl_app_event_replicate(&ndb, &scope, &target,
                                      arrival, &report);
    }
    node_db_close(&ndb);

    if (!read) {
        app_sync_refuse(reply, "TOPIC_UNREADABLE", "read",
                        "this node's rows for that topic would not be read",
                        topic);
        return;
    }
    if (asked) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
            "NO_SESSION", "dispatch", true, false,
            "this command holds no paired session, so no peer was asked and "
            "nothing was stored. Pair the machines and run the pull from the "
            "node; a checkout process has no mesh identity to prove who "
            "answered.", peer);
        return;
    }

    (void)json_push_kv_str(&reply->data, "schema", "zcl.dev_app_sync.v1");
    (void)json_push_kv_str(&reply->data, "app_id", scope.app_id);
    (void)json_push_kv_str(&reply->data, "topic", scope.topic);
    (void)json_push_kv_int(&reply->data, "max_event_bytes",
                           (int64_t)scope.max_event_bytes);
    (void)json_push_kv_int(&reply->data, "pulled", 0);
    (void)json_push_kv_int(&reply->data, "verified", 0);
    (void)json_push_kv_int(&reply->data, "refused", 0);
    app_sync_push_frontier(&reply->data, &frontier);
    (void)json_push_kv_int(&reply->data, "batch_max",
                           (int64_t)ZCL_APP_SYNC_BATCH_MAX);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
