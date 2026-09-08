/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native command adapter (contract §3, §8). Normalizes argv into a
 * registry lookup: longest-registered-path resolution, one JSON input object
 * from --input='<obj>' / --input=- / typed flags, and exactly one bounded JSON
 * document out. Unknown keys and out-of-range values are rejected before any
 * side effect; an unknown branch fails with nearby valid paths plus one
 * executable next action and NEVER becomes an arbitrary RPC method.
 *
 * READ-ONLY Core/Ops leaves execute through zcl_native_bridge_command: a leaf
 * either calls its transport-neutral body function (engine/controllers/
 * *_native_handlers.c) or, for a pure 1:1 proxy, calls the backing JSON-RPC
 * method directly. Discovery
 * leaves (help/search/describe/schema) render the native discovery document
 * directly. The `dev` subtree uses this same resolver; its process and watcher
 * handlers are injected only in a ZCL_DEV_BUILD catalog.
 */

#define _GNU_SOURCE
#include "command/native_command.h"
#include "command/native_command_priv.h"
#include "base/hex.h"

#include "config/command_catalog.h"
#include "framework/app_definition.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#ifdef ZCL_DEV_BUILD
#include "hotswap/hotswap_module.h"
#include "command/native_dev_hotswap.h"
#include "command/native_dev_retrieval_stream.h"
#include "devloop.h"
#endif

#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/boot_status.h"
#include "controllers/native_handler_body.h"
#include "controllers/status_native_helpers.h"
#include "controllers/status_native_handlers.h"
#include "controllers/chain_native_handlers.h"
#include "controllers/wallet_native_handlers.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_native_handlers.h"
#include "controllers/net_native_handlers.h"
#include "controllers/app_native_handlers.h"
#include "controllers/meta_native_handlers.h"
#include "controllers/ops_native_handlers.h"
#include "controllers/explain_native_handlers.h"
#include "controllers/policy_native_handlers.h"
#include "controllers/policy_native_resident.h"
#include "config/consensus_state_producer_receipt.h"
#include "command/rom_compile_render.h"
#include "command/rom_compile_offline.h"
#include "command/rom_watch_loop.h"
#include "command/cli_render.h"
#include "controllers/rpc_client.h"
#include "util/telemetry_ontology.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── root recognition ──────────────────────────────────────────────── */
/* Canonical roots this adapter owns. `status` is the compact native entry
 * point; the large diagnostic document remains explicit under core.status. */
bool zcl_native_command_is_root(const char *word)
{
    if (!word || !word[0])
        return false;
    static const char *const roots[] = {
        "status", "core", "app", "dev", "ops", "discover", "code", "vault",
        "zcode", "metaverse", "yardsale", "zses", "story", "help",
        /* The fleet AI message board and wiki. A root rather than an
         * `ops.*` child for the same reason `general` is: it is what an
         * agent reads BEFORE it starts work and writes when it finishes,
         * and a prefix between an agent and the fleet's shared memory is
         * how that memory stops being read. It grants no authority — the
         * board carries requests and pointers, and the gates decide. */
        "fleet",
        "search",
        /* Operator-UX convenience roots: bare aliases of ops.explain /
         * ops.profile so `z23 explain sync` / `zclassic23 profile`
         * work without the `ops` prefix (each leaf carries the matching
         * alias in engine/composition/commands/ops.def). `meaning` joins them because the
         * field ontology is most needed by an operator who does not yet know
         * which report — let alone which prefix — to reach for. */
        "explain", "profile", "meaning",
        /* Onboarding roots: `z23 join` is the first command a stranger runs
         * after installing, and `z23 update` the one they reach for later.
         * Both are bare aliases of zcode.node.* (engine/composition/commands/zcode.def)
         * for exactly the reason above: a four-word canonical path is not
         * what someone types on their first day. */
        "join", "update",
        /* `general` is the dispatch brief for one territory (engine/composition/commands/
         * code.def). It is a root rather than a `code.*` child because it is
         * what an agent runs BEFORE it starts work, and putting a prefix
         * between an agent and the inventory it keeps mis-remembering is how
         * the inventory keeps getting mis-remembered. It grants no authority:
         * it reports and never decides. */
        "general",
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        if (strcmp(word, roots[i]) == 0)
            return true;
        /* CLI UX contract: the canonical dotted form
         * (`z23 zcode.science.study.list`) names the same leaf as the
         * spaced form — a first token of `<root>.<rest>` belongs to this
         * adapter too, and zcl_native_command_main splits it into path
         * segments before resolution. */
        size_t n = strlen(roots[i]);
        if (strncmp(word, roots[i], n) == 0 && word[n] == '.')
            return true;
    }
    return false;
}

/* ── dispatch bindings for the bridge ─────────────────────────────────
 * Every bridged leaf resolves to exactly ONE of:
 *   - a transport-neutral body function, or
 *   - a direct JSON-RPC method for a pure pass-through leaf.
 * The golden catalog test proves the union covers every bridged leaf exactly. */
static const struct {
    const char *path;
    zcl_native_body_fn body;
} g_bridge_native_body[] = {
    { "status", zcl_native_status_journey_body },
    { "core.status", zcl_native_status_body },
    { "core.status.brief", zcl_native_status_brief_body },
    { "core.chain.block.get", zcl_native_getblock_body },
    { "core.chain.transaction.get", zcl_native_getrawtransaction_body },
    { "core.sync.blockers", zcl_native_blockers_body },
    { "core.sync.diagnose", zcl_native_syncdiag_body },
    { "core.consensus.report", zcl_native_consensus_report_body },
    { "core.consensus.utxo.audit", zcl_native_utxo_audit_body },
    { "core.network.peers.incidents", zcl_native_peer_incidents_body },
    { "core.network.onion.health", zcl_native_onion_health_body },
    { "core.wallet.address.list", zcl_native_listaddresses_body },
    { "core.wallet.utxo.list", zcl_native_listunspent_body },
    { "core.wallet.transaction.list", zcl_native_listtransactions_body },
    { "core.wallet.transaction.get", zcl_native_gettransaction_body },
    { "core.wallet.address.public-key",
      zcl_native_address_public_key_body },
    { "core.wallet.shielded.balance", zcl_native_z_getbalance_body },
    { "core.wallet.shielded.notes", zcl_native_z_listunspent_body },
    { "core.storage.query", zcl_native_sql_body },
    { "ops.diagnose", zcl_native_agent_diagnose_body },
    { "ops.logs", zcl_native_node_log_body },
    { "ops.timeline", zcl_native_timeline_body },
    { "ops.metrics", zcl_native_metrics_body },
    { "ops.health", zcl_native_ops_health_body },
    { "ops.postmortem.list", zcl_native_postmortem_list_body },
    { "ops.debug.dash.kpi", zcl_native_kpi_body },
    { "ops.debug.dash.snapshot", zcl_native_operator_snapshot_body },
    { "ops.debug.dash.summary", zcl_native_operator_summary_body },
    { "ops.debug.dash.milestone", zcl_native_milestone_body },
    { "ops.debug.dash.mirror", zcl_native_mirror_status_body },
    { "ops.debug.dash.selfheal", zcl_native_self_heal_stats_body },
    /* app features (ZCL app controller port — read surface) */
    { "app.names.resolve", zcl_native_name_resolve_body },
    { "app.names.list", zcl_native_name_list_body },
    { "app.tokens.list", zcl_native_zslp_listtokens_body },
    { "app.messaging.inbox", zcl_native_msg_inbox_body },
    { "app.market.list", zcl_native_zmarket_list_body },
    { "app.market.status", zcl_native_zmarket_status_body },
    { "app.market.content.list", zcl_native_zmarket_content_list_body },
    /* The pure decision leaf. Its body reaches no RPC and no datadir, which
     * is what makes it dispatchable in-process as a hot-swap probe case. */
    { "zcode.package.policy.limits", zcl_native_policy_limits_body },
    { "app.swap.chains", zcl_native_swap_chains_body },
    { "app.swap.list", zcl_native_swap_list_body },
};

/* enum bridge_rpc_array_kind / struct bridge_rpc_required_field / struct
 * bridge_rpc_binding live in native_command_priv.h: native_command_bridge.c's
 * dispatch pipeline validates an RPC success body against the binding this
 * file resolves. */
static const struct bridge_rpc_binding g_bridge_rpc_direct[] = {
    { "core.chain.tip", "getchaintip", JSON_OBJ,
      {{"hash", JSON_STR}, {"height", JSON_INT}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.chain.mempool.status", "getmempoolinfo", JSON_OBJ,
      {{"size", JSON_INT}, {"bytes", JSON_INT}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.chain.mempool.list", "getrawmempool", JSON_ARR,
      {{0}}, BRIDGE_RPC_ARRAY_TXIDS },
    { "core.sync.status", "syncstate", JSON_OBJ,
      {{"state", JSON_STR}, {"state_id", JSON_INT}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.sync.validation", "validationstatus", JSON_OBJ,
      {{"state", JSON_STR}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.consensus.integrity", "getdataintegrity", JSON_OBJ,
      {{"source", JSON_STR}, {"master", JSON_STR}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.consensus.utxo.commitment", "getutxocommitment", JSON_OBJ,
      {{"sha3_hash", JSON_STR}, {"height", JSON_INT},
       {"utxo_count", JSON_INT}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.consensus.mmb", "getmmrroot", JSON_OBJ,
      {{"mmr_root", JSON_STR}, {"num_leaves", JSON_INT}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.network.status", "getnetworkinfo", JSON_OBJ,
      {{"connections", JSON_INT}, {"networks", JSON_ARR}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.network.peers.list", "getpeerinfo", JSON_ARR,
      {{0}}, BRIDGE_RPC_ARRAY_PEERS },
    { "core.network.peers.latency", "getpeerlatency", JSON_ARR,
      {{0}}, BRIDGE_RPC_ARRAY_LATENCY },
    { "core.network.onion.status", "onionstatus", JSON_OBJ,
      {{"schema", JSON_STR}, {"bootstrap_state", JSON_STR},
       {"tor_ready", JSON_BOOL}, {"onion_service_ready", JSON_BOOL},
       {"onion_address", JSON_STR}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.wallet.status", "getwalletinfo", JSON_OBJ,
      {{"balance", JSON_STR}, {"txcount", JSON_INT}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.wallet.balance", "z_gettotalbalance", JSON_OBJ,
      {{"transparent", JSON_STR}, {"total", JSON_STR}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.wallet.backup.status", "walletbackupstatus", JSON_OBJ,
      {{"running", JSON_BOOL}, {"total_runs", JSON_INT}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.wallet.audit", "walletaudit", JSON_OBJ,
      {{"chain_height", JSON_INT}, {"summary", JSON_OBJ}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.storage.stats", "db_info", JSON_OBJ,
      {{"tip_height", JSON_INT}, {"utxo_count", JSON_INT}},
      BRIDGE_RPC_ARRAY_NONE },
    { "core.mining.status", "getmininginfo", JSON_OBJ,
      {{"blocks", JSON_INT}, {"chain", JSON_STR}}, BRIDGE_RPC_ARRAY_NONE },
    { "core.mining.benchmark", "benchmark", JSON_OBJ,
      {{"primary_benchmark_source", JSON_STR},
       {"primary_benchmarks", JSON_ARR}}, BRIDGE_RPC_ARRAY_NONE },
    { "ops.lanes", "agentlanes", JSON_OBJ,
      {{"status", JSON_STR}, {"lanes", JSON_ARR}}, BRIDGE_RPC_ARRAY_NONE },
    { "ops.recovery.status", "refold", JSON_OBJ,
      {{"ready_for_refold", JSON_BOOL}, {"primary_blocker", JSON_STR}},
      BRIDGE_RPC_ARRAY_NONE },
};

const struct bridge_rpc_binding *bridge_rpc_binding_for_path(
    const char *path)
{
    if (!path)
        return NULL;
    for (size_t i = 0;
         i < sizeof(g_bridge_rpc_direct) / sizeof(g_bridge_rpc_direct[0]);
         i++) {
        if (strcmp(g_bridge_rpc_direct[i].path, path) == 0)
            return &g_bridge_rpc_direct[i];
    }
    return NULL;
}

zcl_native_body_fn zcl_native_bridge_body_for_path(const char *path)
{
    if (!path)
        return NULL;
    for (size_t i = 0;
         i < sizeof(g_bridge_native_body) / sizeof(g_bridge_native_body[0]);
         i++) {
        if (strcmp(g_bridge_native_body[i].path, path) == 0)
            return g_bridge_native_body[i].body;
    }
    return NULL;
}

const char *zcl_native_bridge_rpc_for_path(const char *path)
{
    const struct bridge_rpc_binding *binding =
        bridge_rpc_binding_for_path(path);
    return binding ? binding->rpc_method : NULL;
}

static bool bridge_has_exact_binding(const char *path)
{
    return (zcl_native_bridge_body_for_path(path) != NULL) !=
           (zcl_native_bridge_rpc_for_path(path) != NULL);
}

/* ── one-shot RPC client bootstrap ──────────────────────────────────── */
static char g_bridge_datadir[512];
static int g_bridge_rpc_port;
static bool g_bridge_rpc_ready;
static bool g_native_input_from_stdin;
static bool g_native_datadir_explicit;
static enum chain_network g_native_network = CHAIN_MAIN;

bool zcl_native_input_was_stdin(void)
{
    return g_native_input_from_stdin;
}

const char *zcl_native_command_datadir(void)
{
    return g_bridge_datadir;
}

int zcl_native_command_rpc_port(void)
{
    return g_bridge_rpc_port;
}

bool zcl_native_command_datadir_is_explicit(void)
{
    return g_native_datadir_explicit;
}

enum chain_network zcl_native_command_network(void)
{
    return g_native_network;
}

void zcl_native_bridge_bind_rpc(const char *datadir, int rpc_port)
{
    (void)snprintf(g_bridge_datadir, sizeof(g_bridge_datadir), "%s",
                   datadir ? datadir : "");
    g_bridge_rpc_port = rpc_port;
    node_rpc_client_init(g_bridge_datadir, g_bridge_rpc_port);
    g_bridge_rpc_ready = true;
}

static void bridge_ensure_rpc_client(void)
{
    if (g_bridge_rpc_ready)
        return;
    /* A one-shot native process has no app_init(): initialize the JSON-RPC
     * client (datadir cookie + port) and select mainnet chain params for any
     * body function that consults them. */
    node_rpc_client_init(g_bridge_datadir, g_bridge_rpc_port);
    chain_params_select(g_native_network);
    g_bridge_rpc_ready = true;
}

/* See native_command.h — exported for non-bridge handlers that still need the
 * initialized RPC client (dev hot-swap apply/probe). */
void zcl_native_bridge_ensure_rpc(void)
{
    bridge_ensure_rpc_client();
}

void zcl_native_bridge_command(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    if (!request || !request->spec || !reply)
        return;
    zcl_native_bridge_run(request,
                          zcl_native_bridge_body_for_path(request->spec->path),
                          reply);
}

/* ── discovery + app handlers (bound by the catalog) ───────────────── */
/* These make the discovery and app leaves independently executable through the
 * registry (e.g. via a direct execute); the CLI adapter below renders the
 * native discovery documents directly for tighter budgets. */
static const struct zcl_command_registry *catalog(void)
{
    return zcl_command_catalog();
}

static void discover_reply_document(struct zcl_command_reply *reply,
                                    size_t (*render)(
                                        const struct zcl_command_registry *,
                                        const char *, char *, size_t),
                                    const char *arg)
{
    char buf[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t n = render(catalog(), arg, buf, sizeof(buf));
    if (n == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PATH",
                               "resolve", false, false,
                               "no such command path", arg ? arg : "");
        return;
    }
    struct json_value doc;
    if (!json_read(&doc, buf, n) || doc.type != JSON_OBJ) {
        json_free(&doc);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                               "serialize", false, false,
                               "discovery document did not parse", "");
        return;
    }
    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &doc);
    json_free(&doc);
}

void zcl_native_handle_discover_help(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    const char *path = json_get_str(json_get(request->input, "path"));
    discover_reply_document(reply, zcl_command_registry_menu_json,
                            path ? path : "");
}

void zcl_native_handle_discover_describe(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *path = json_get_str(json_get(request->input, "path"));
    discover_reply_document(reply, zcl_command_registry_describe_json,
                            path ? path : "");
}

void zcl_native_handle_discover_search(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *query = json_get_str(json_get(request->input, "query"));
    discover_reply_document(reply, zcl_command_registry_search_json,
                            query ? query : "");
}

void zcl_native_handle_discover_schema(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *path = json_get_str(json_get(request->input, "path"));
    const char *side = json_get_str(json_get(request->input, "side"));
    bool alias = false;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(catalog(), path ? path : "", &alias);
    if (!spec) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PATH",
                               "resolve", false, false, "no such command path",
                               path ? path : "");
        return;
    }
    bool want_output = side && strcmp(side, "output") == 0;
    (void)json_push_kv_str(&reply->data, "path", spec->path);
    (void)json_push_kv_str(&reply->data, "side",
                           want_output ? "output" : "input");
    (void)json_push_kv_str(&reply->data, "id",
                           want_output ? spec->output_schema
                                       : spec->input_schema);
    (void)json_push_kv_str(&reply->data, "allowed_keys",
                           spec->input_keys ? spec->input_keys : "");
}

void zcl_native_handle_app_list(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    (void)request;
    /* Compile-time catalog only. Definitions are data and grant no runtime
     * authority; checkout inspection is a separate dev command. */
    struct json_value apps;
    json_init(&apps);
    json_set_array(&apps);
    size_t count = zcl_app_definition_builtin_count_v1();
    for (size_t i = 0; i < count; i++) {
        const char *app_id = zcl_app_definition_builtin_id_v1(i);
        if (!app_id)
            continue;
        struct json_value item;
        json_init(&item);
        json_set_str(&item, app_id);
        (void)json_push_back(&apps, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "apps", &apps);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv_str(&reply->data, "catalog", "built-in-strict-v1");
    json_free(&apps);
}

void zcl_native_handle_app_inspect(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const char *app_id = json_get_str(json_get(request->input, "app_id"));
    if (!app_id || !app_id[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_APP_ID",
                               "normalize", false, false,
                               "app_id is required", "");
        return;
    }
    if (!zcl_app_definition_builtin_v1(app_id)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_APP",
                               "resolve", false, false,
                               "no such installed App", app_id);
        (void)zcl_command_reply_add_next(reply, "app.list", "{}",
                                         "list installed Apps");
        return;
    }
    char manifest[ZCL_APP_ID_MAX + sizeof("apps//app.def")];
    int n = snprintf(manifest, sizeof(manifest), "apps/%s/app.def", app_id);
    if (n <= 0 || (size_t)n >= sizeof(manifest)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "APP_PATH_OVERFLOW",
                               "render", false, false,
                               "built-in App path exceeds its bound", app_id);
        return;
    }
    (void)json_push_kv_str(&reply->data, "app_id", app_id);
    (void)json_push_kv_str(&reply->data, "manifest", manifest);
    (void)json_push_kv_str(&reply->data, "status", "checkout-only");
    (void)json_push_kv_str(&reply->data, "authority", "definition-only");
}

/* Shared by every leaf that calls one RPC method and expects one JSON object
 * body back: bind the RPC client, dispatch, and require a parseable object.
 * Fails the reply (NODE_UNAVAILABLE / bad_body_code) and returns false
 * otherwise; `*body_out` is only valid to json_free() when this returns
 * true. */
static bool nc_rpc_fetch_object(const char *method, const char *params,
                                const char *evidence,
                                const char *unavailable_msg,
                                const char *bad_body_code,
                                const char *bad_body_msg,
                                struct zcl_command_reply *reply,
                                struct json_value *body_out)
{
    bridge_ensure_rpc_client();
    char *result = node_rpc_call(method, params);
    if (!result) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false, unavailable_msg,
                               evidence);
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return false;
    }
    if (!json_read(body_out, result, strlen(result)) ||
        body_out->type != JSON_OBJ) {
        json_free(body_out);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, bad_body_code,
                               "serialize", false, false, bad_body_msg,
                               evidence);
        return false;
    }
    free(result);
    return true;
}

/* node_rpc_call surfaces a JSON-RPC failure as either {"error":{...}}
 * (transport) or a bare {"code":..,"message":..} (RPC-level). Shared by
 * every leaf in this section that treats both as a failed dump; callers
 * that need a differently-shaped message (e.g. an "error" that can itself be
 * a bare string) read `*err_out`/`*emsg_out` themselves. */
static bool nc_rpc_body_has_error(const struct json_value *body,
                                  const struct json_value **err_out,
                                  const struct json_value **ecode_out,
                                  const struct json_value **emsg_out)
{
    const struct json_value *err = json_get(body, "error");
    const struct json_value *ecode = json_get(body, "code");
    const struct json_value *emsg = json_get(body, "message");
    *err_out = err;
    *ecode_out = ecode;
    *emsg_out = emsg;
    return (err && !json_is_null(err)) ||
           (ecode && ecode->type == JSON_INT && emsg && emsg->type == JSON_STR);
}

/* ── ops.state / ops.selftest native leaves ──────────────────────────────
 * ops.state calls the `dumpstate` RPC method directly, while ops.selftest is
 * a node-free, deterministic well-formedness sweep of the registry. */
/* dumpstate params: [subsystem] or [subsystem, key]. Build via JSON so the
 * subsystem/key strings are correctly escaped, never printf-spliced. */
static bool nc_ops_state_build_params(const char *sub, const char *key,
                                      char *out, size_t out_cap)
{
    struct json_value params, item;
    json_init(&params);
    json_set_array(&params);
    json_init(&item);
    json_set_str(&item, sub);
    (void)json_push_back(&params, &item);
    json_free(&item);
    if (key && key[0]) {
        json_init(&item);
        json_set_str(&item, key);
        (void)json_push_back(&params, &item);
        json_free(&item);
    }
    size_t pn = json_write(&params, out, out_cap);
    json_free(&params);
    return pn > 0 && pn < out_cap;
}

/* Values alone do not say whether they are good. When this subsystem has a
 * field ontology, either attach the verdicts (--explain) or, at minimum,
 * SAY that meaning exists — the failure this closes is an operator reading
 * a number with no idea it could be explained at all. Off by default, so a
 * routine dump does not grow. */
static void nc_ops_state_attach_meaning(const struct zcl_command_request *request,
                                        const char *sub,
                                        const struct json_value *body,
                                        struct zcl_command_reply *reply)
{
    if (!telemetry_subsystem_covered(sub))
        return;
    const struct json_value *st = json_get(body, "state");
    if (json_get_bool(json_get(request->input, "explain")) && st) {
        struct json_value meaning;
        json_init(&meaning);
        if (telemetry_ontology_annotate(sub, st, &meaning))
            (void)json_push_kv(&reply->data, "meaning", &meaning);
        json_free(&meaning);
    } else {
        (void)json_push_kv_bool(&reply->data, "meaning_available", true);
        (void)zcl_command_reply_add_next(
            reply, "ops.state",
            "{\"subsystem\":\"<same>\",\"explain\":true}",
            "re-run with explain to get each field judged against its "
            "healthy range");
    }
}

void zcl_native_handle_ops_state(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *sub = json_get_str(json_get(request->input, "subsystem"));
    if (!sub || !sub[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SUBSYSTEM",
                               "normalize", false, false,
                               "subsystem is required", "ops.state");
        nc_add_describe_next(reply, request->spec->path,
                             "inspect the subsystem input contract");
        return;
    }
    const char *key = json_get_str(json_get(request->input, "key"));

    char params_json[512];
    if (!nc_ops_state_build_params(sub, key, params_json,
                                   sizeof(params_json))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                               "normalize", false, false,
                               "could not encode dumpstate params", sub);
        return;
    }

    struct json_value body;
    if (!nc_rpc_fetch_object("dumpstate", params_json, sub,
                             "the node did not return a state body",
                             "BAD_STATE_BODY",
                             "dumpstate returned a non-object body", reply,
                             &body))
        return;
    /* node_rpc_call surfaces a JSON-RPC failure as either {"error":{...}}
     * (transport) or a bare {"code":..,"message":..} (RPC-level). Treat both
     * as a failed dump — e.g. an unknown subsystem. */
    const struct json_value *err, *ecode, *emsg;
    if (nc_rpc_body_has_error(&body, &err, &ecode, &emsg)) {
        (void)ecode;
        const char *msg = NULL;
        if (err && err->type == JSON_OBJ)
            msg = json_get_str(json_get(err, "message"));
        else if (emsg && emsg->type == JSON_STR)
            msg = json_get_str(emsg);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "STATE_ERROR",
                               "execute", false, false,
                               msg && msg[0] ? msg
                                             : "dumpstate reported an error",
                               sub);
        json_free(&body);
        return;
    }
    /* Success: project the state body into the envelope (view/budget bounded). */
    zcl_native_bridge_project(request, &body, reply);
    nc_ops_state_attach_meaning(request, sub, &body, reply);
    json_free(&body);
}

void zcl_native_handle_network_chain_view(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    /* The reachable-network chain view lives in the running node's
     * network_monitor subsystem; surface it through the same SELECT-only
     * dumpstate RPC that ops.state uses, pinned to that subsystem. */
    struct json_value body;
    if (!nc_rpc_fetch_object("dumpstate", "[\"network_monitor\"]",
                             "network_monitor",
                             "the node did not return the network view",
                             "BAD_STATE_BODY",
                             "network view returned a non-object body",
                             reply, &body))
        return;
    const struct json_value *err, *ecode, *emsg;
    if (nc_rpc_body_has_error(&body, &err, &ecode, &emsg)) {
        (void)ecode;
        const char *msg = NULL;
        if (err && err->type == JSON_OBJ)
            msg = json_get_str(json_get(err, "message"));
        else if (emsg && emsg->type == JSON_STR)
            msg = json_get_str(emsg);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "STATE_ERROR",
                               "execute", false, false,
                               msg && msg[0] ? msg
                                             : "network view reported an error",
                               "network_monitor");
        json_free(&body);
        return;
    }
    zcl_native_bridge_project(request, &body, reply);
    json_free(&body);
}

/* ── ops.statecatalog ────────────────────────────────────────────────
 *
 * The discovery half of `ops state`. `ops state` demands a subsystem name
 * and errors MISSING_SUBSYSTEM without one, so until this leaf existed an
 * agent could only learn the names by reading
 * engine/controllers/include/controllers/diagnostics_dumpers.def out of the
 * source tree — which is not shipped in a release binary. The catalog was
 * already reachable as the flat legacy `z23 statecatalog` shim,
 * but flat shims carry no typed envelope, no declared risk/authority, and
 * no `discover` entry, so from the typed registry the 148-plus subsystems
 * were undiscoverable.
 *
 * There is no second catalog here. diag_rpc_statecatalog() renders the
 * one built from diagnostics_dumpers.def; this leaf calls it and pages
 * the result. Node-free: the registry is compiled in, so this answers
 * with the node stopped — unlike `ops state`, which needs a live one.
 *
 * WHY THE DEFAULT IS NAMES ONLY. The full catalog is ~150 entries of
 * rich metadata — far past the 8192-byte envelope the argv path can
 * serialize (the CLI's own out buffer is ZCL_COMMAND_LIST_BUDGET + 1, so
 * a leaf that declares more simply fails RESPONSE_BUDGET_EXCEEDED rather
 * than truncating). A silently truncated catalog would be worse than an
 * error — an agent would conclude a subsystem does not exist. So the
 * default answer is the COMPLETE name list, which is the thing you need
 * to call `ops state` at all and is the one part that must never be
 * clipped. Metadata is opt-in and bounded two ways: `subsystem=<name>`
 * for one descriptor in full, or `limit`/`page` for a small window of
 * descriptors — and asking for a window drops `names` from the response,
 * because a caller paging descriptors already has them. `count` is the
 * true total in every mode. */

#define NC_CATALOG_PAGE_DEFAULT 5
#define NC_CATALOG_PAGE_MAX     5

static bool nc_statecatalog_fetch(struct zcl_command_reply *reply,
                                  struct json_value *catalog,
                                  const struct json_value **subs_out,
                                  size_t *total_out)
{
    json_init(catalog);
    if (!diag_rpc_statecatalog(NULL, false, catalog)) {
        json_free(catalog);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_UNAVAILABLE",
                               "execute", false, false,
                               "the diagnostics registry did not render a "
                               "catalog", "ops.statecatalog");
        return false;
    }
    const struct json_value *subs = json_get(catalog, "subsystems");
    if (!subs || subs->type != JSON_ARR) {
        json_free(catalog);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_MALFORMED",
                               "serialize", false, false,
                               "the diagnostics catalog carried no subsystems "
                               "array", "ops.statecatalog");
        return false;
    }
    *subs_out = subs;
    *total_out = json_size(subs);
    return true;
}

/* One named subsystem: its whole descriptor, unpaged and untrimmed. */
static void nc_statecatalog_one(const char *want, struct json_value *catalog,
                                const struct json_value *subs, size_t total,
                                struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < total; i++) {
        const struct json_value *e = json_at(subs, i);
        const char *name = e ? json_get_str(json_get(e, "name")) : NULL;
        if (name && strcmp(name, want) == 0) {
            (void)json_push_kv(&reply->data, "subsystem", e);
            json_free(catalog);
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
            return;
        }
    }
    json_free(catalog);
    /* No `next` action pointing back at this leaf: push_next_array
     * rejects a self-referential next and drops the WHOLE envelope to
     * RESPONSE_BUDGET_EXCEEDED when it does. The message carries the
     * instruction instead, and serialize_reply still attaches the
     * describe-next automatically. */
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_SUBSYSTEM",
                           "resolve", false, false,
                           "no dumpstate subsystem by that name — re-run "
                           "this command with no `subsystem` to get the "
                           "complete `names` list", want);
}

/* Default mode: every name, complete, in one call. This is the discovery
 * answer and it is never paged away. */
static void nc_statecatalog_names_only(struct json_value *catalog,
                                       const struct json_value *subs,
                                       size_t total,
                                       struct zcl_command_reply *reply)
{
    struct json_value names;
    json_init(&names);
    json_set_array(&names);
    for (size_t i = 0; i < total; i++) {
        const struct json_value *e = json_at(subs, i);
        const char *name = e ? json_get_str(json_get(e, "name")) : NULL;
        if (!name)
            continue;
        struct json_value nv;
        json_init(&nv);
        json_set_str(&nv, name);
        (void)json_push_back(&names, &nv);
        json_free(&nv);
    }
    (void)json_push_kv(&reply->data, "names", &names);
    json_free(&names);
    (void)json_push_kv_str(&reply->data, "detail",
                           "add subsystem=<name> for one descriptor in "
                           "full, or limit/page for a window of them");
    json_free(catalog);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void nc_statecatalog_paged(const struct zcl_command_request *request,
                                  struct json_value *catalog,
                                  const struct json_value *subs, size_t total,
                                  struct zcl_command_reply *reply)
{
    const struct json_value *lv = json_get(request->input, "limit");
    const struct json_value *pv = json_get(request->input, "page");
    int64_t page_size = NC_CATALOG_PAGE_DEFAULT;
    if (lv && lv->type == JSON_INT)
        page_size = json_get_int(lv);
    if (page_size > NC_CATALOG_PAGE_MAX)
        page_size = NC_CATALOG_PAGE_MAX;
    if (page_size < 1)
        page_size = 1;
    int64_t page = 0;
    if (pv && pv->type == JSON_INT)
        page = json_get_int(pv);
    if (page < 0)
        page = 0;

    int64_t pages = total == 0 ? 0
                               : ((int64_t)total + page_size - 1) / page_size;
    size_t start = (size_t)(page * page_size);
    (void)json_push_kv_int(&reply->data, "page", page);
    (void)json_push_kv_int(&reply->data, "page_size", page_size);
    (void)json_push_kv_int(&reply->data, "pages", pages);
    (void)json_push_kv_bool(&reply->data, "has_more",
                            (int64_t)start + page_size < (int64_t)total);

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = start; i < total && (int64_t)(i - start) < page_size; i++) {
        const struct json_value *e = json_at(subs, i);
        if (e)
            (void)json_push_back(&rows, e);
    }
    (void)json_push_kv(&reply->data, "subsystems", &rows);
    json_free(&rows);
    json_free(catalog);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_ops_statecatalog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct json_value catalog;
    const struct json_value *subs;
    size_t total;
    if (!nc_statecatalog_fetch(reply, &catalog, &subs, &total))
        return;

    (void)json_push_kv_str(&reply->data, "source",
                           json_get_str(json_get(&catalog, "source")));
    (void)json_push_kv_str(&reply->data, "catalog_schema",
                           json_get_str(json_get(&catalog, "schema")));
    (void)json_push_kv_int(&reply->data, "count", (int64_t)total);
    (void)json_push_kv_bool(&reply->data, "node_free", true);

    const char *want = json_get_str(json_get(request->input, "subsystem"));
    if (want && want[0]) {
        nc_statecatalog_one(want, &catalog, subs, total, reply);
        return;
    }

    const struct json_value *lv = json_get(request->input, "limit");
    const struct json_value *pv = json_get(request->input, "page");
    bool want_rows = lv != NULL || pv != NULL;
    if (!want_rows) {
        nc_statecatalog_names_only(&catalog, subs, total, reply);
        return;
    }
    nc_statecatalog_paged(request, &catalog, subs, total, reply);
}

/* Handler / schema / effect-risk / semantics half of the READY-leaf
 * dispatchability contract. */
static const char *nc_selftest_schema_reason(const struct zcl_command_spec *s)
{
    if (!s->handler)
        return "ready-leaf-missing-handler";
    if (!s->input_schema || !s->input_schema[0] ||
        !s->output_schema || !s->output_schema[0] ||
        !s->example || !s->example[0])
        return "missing-schema-or-example";
    if (s->effect == ZCL_COMMAND_EFFECT_READ &&
        s->risk != ZCL_COMMAND_RISK_READ)
        return "read-effect-risk-conflict";
    if (!s->semantics || !s->semantics[0])
        return "missing-semantics";
    if (strcmp(s->semantics, s->summary) == 0)
        return "semantics-equals-summary";
    return NULL;
}

/* Budget / bridge-binding half of the READY-leaf dispatchability contract. */
static const char *nc_selftest_budget_reason(const struct zcl_command_spec *s)
{
    if (s->budget_bytes != 0 &&
        (s->budget_bytes < 256 || s->budget_bytes > 65536))
        return "budget-out-of-range";
    if (s->handler == zcl_native_bridge_command &&
        !bridge_has_exact_binding(s->path))
        return "bridge-leaf-without-exact-binding";
    return NULL;
}

/* A READY leaf must be dispatchable: a non-NULL handler plus the
 * schema/example/effect-risk guarantees zcl_command_registry_validate
 * enforces. This is a static, node-free contract check. Returns the
 * violated-contract reason, or NULL when the leaf is well-formed. */
static const char *nc_selftest_leaf_reason(const struct zcl_command_spec *s)
{
    const char *reason = nc_selftest_schema_reason(s);
    return reason ? reason : nc_selftest_budget_reason(s);
}

void zcl_native_handle_ops_selftest(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct zcl_command_registry *reg = catalog();
    size_t total = 0, passed = 0, failed = 0, skipped = 0;

    struct json_value failures;
    json_init(&failures);
    json_set_array(&failures);

    for (size_t i = 0; i < reg->count; i++) {
        const struct zcl_command_spec *s = &reg->commands[i];
        if (s->mode == ZCL_COMMAND_MODE_BRANCH)
            continue;
        total++;
        /* PLANNED / COMPAT leaves are intentionally non-executable — they are
         * skips, never failures (discovery already fails them closed). */
        if (s->availability != ZCL_COMMAND_READY) {
            skipped++;
            continue;
        }
        const char *reason = nc_selftest_leaf_reason(s);
        if (reason) {
            failed++;
            if (failures.num_children < 32) {
                struct json_value f;
                json_init(&f);
                json_set_object(&f);
                (void)json_push_kv_str(&f, "path", s->path);
                (void)json_push_kv_str(&f, "reason", reason);
                (void)json_push_back(&failures, &f);
                json_free(&f);
            }
        } else {
            passed++;
        }
    }

    (void)json_push_kv_str(&reply->data, "mode", "registry");
    (void)json_push_kv_int(&reply->data, "total", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "pass", (int64_t)passed);
    (void)json_push_kv_int(&reply->data, "fail", (int64_t)failed);
    (void)json_push_kv_int(&reply->data, "skip", (int64_t)skipped);
    (void)json_push_kv(&reply->data, "failures", &failures);
    json_free(&failures);

    reply->status = failed == 0 ? ZCL_COMMAND_STATUS_PASSED
                                : ZCL_COMMAND_STATUS_FAILED;
    reply->exit_code = failed == 0 ? ZCL_COMMAND_EXIT_OK
                                   : ZCL_COMMAND_EXIT_FAILED;
}

/* ── ops.debug.meaning native leaf ─────────────────────────────────────────
 * Node-free by construction: it reads the static telemetry ontology compiled
 * into this binary and never touches the RPC client. That is deliberate — the
 * operator who most needs to know what `pre_handshake_disconnects` counts and
 * what 8-of-8 implies is the one whose node will not start. */
static bool meaning_matches_question(const struct telemetry_question *q,
                                     const char *needle)
{
    if (!needle || !needle[0])
        return true;
    char low[256];
    size_t n = strlen(needle);
    if (n >= sizeof(low))
        n = sizeof(low) - 1;
    for (size_t i = 0; i < n; i++)
        low[i] = (char)tolower((unsigned char)needle[i]);
    low[n] = '\0';
    if (strstr(q->id, low) || strstr(q->keywords, low))
        return true;
    /* Word-wise: any word of the query that is a keyword counts as a hit, so
     * a whole sentence routes as well as a single term. */
    const char *p = low;
    while (*p) {
        while (*p && !isalnum((unsigned char)*p)) p++;
        const char *w = p;
        while (*p && isalnum((unsigned char)*p)) p++;
        size_t wl = (size_t)(p - w);
        if (wl >= 4) {
            char word[64];
            if (wl < sizeof(word)) {
                memcpy(word, w, wl);
                word[wl] = '\0';
                if (strstr(q->keywords, word))
                    return true;
            }
        }
    }
    return false;
}

/* A question routes to a command; that is the whole point of the index. */
static void nc_meaning_routes(const char *question,
                              struct zcl_command_reply *reply)
{
    struct json_value routes;
    json_init(&routes);
    json_set_array(&routes);
    for (size_t i = 0; i < telemetry_question_count(); i++) {
        const struct telemetry_question *q = telemetry_question_at(i);
        if (!q || !meaning_matches_question(q, question))
            continue;
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        (void)json_push_kv_str(&obj, "question", q->question);
        (void)json_push_kv_str(&obj, "run", q->command);
        (void)json_push_kv_str(&obj, "subsystem", q->subsystem);
        (void)json_push_kv_str(&obj, "decisive_fields", q->fields);
        (void)json_push_kv_str(&obj, "how_to_read", q->how_to_read);
        (void)json_push_back(&routes, &obj);
        json_free(&obj);
    }
    (void)json_push_kv_int(&reply->data, "routes_matched",
                           (int64_t)json_size(&routes));
    (void)json_push_kv(&reply->data, "routes", &routes);
    json_free(&routes);
}

static void nc_meaning_ontology(const char *key,
                                struct zcl_command_reply *reply)
{
    struct json_value onto;
    json_init(&onto);
    if (!telemetry_ontology_json(&onto, key)) {
        json_free(&onto);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "ONTOLOGY_RENDER_FAILED", "render", false,
                               false, "could not render the field ontology",
                               "ops.debug.meaning");
        return;
    }
    const struct json_value *fields = json_get(&onto, "fields");
    size_t matched = fields ? json_size(fields) : 0;
    if (key && matched == 0) {
        json_free(&onto);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "NO_SUCH_FIELD",
                               "resolve", false, false,
                               "no covered subsystem or field by that name",
                               key);
        (void)zcl_command_reply_add_next(reply, "ops.debug.meaning", "{}",
                                         "list every covered field");
        return;
    }
    (void)json_push_kv_int(&reply->data, "fields_matched", (int64_t)matched);
    const char *carry[] = { "fields", "alias_prefixes",
                            "covered_subsystems", "questions" };
    for (size_t i = 0; i < sizeof(carry) / sizeof(carry[0]); i++) {
        const struct json_value *v = json_get(&onto, carry[i]);
        if (v)
            (void)json_push_kv(&reply->data, carry[i], v);
    }
    (void)json_push_kv_int(&reply->data, "field_rows_total",
                           (int64_t)telemetry_field_count());
    json_free(&onto);
}

void zcl_native_handle_ops_meaning(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *subsystem = json_get_str(json_get(request->input, "subsystem"));
    /* `name`, not `field`: --field is a RESERVED CLI flag (output projection),
     * so a leaf input key called `field` is unreachable from the command line. */
    const char *field = json_get_str(json_get(request->input, "name"));
    const char *question = json_get_str(json_get(request->input, "question"));

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.telemetry_ontology.v1");
    (void)json_push_kv_bool(&reply->data, "node_free", true);
    (void)json_push_kv_str(&reply->data, "source",
                           "platform/modules/util/include/util/telemetry_ontology.def");

    if (question && question[0])
        nc_meaning_routes(question, reply);

    const char *key = (field && field[0]) ? field
                    : (subsystem && subsystem[0]) ? subsystem : NULL;
    if (key || !(question && question[0]))
        nc_meaning_ontology(key, reply);
}

/* ── ops.debug.backtrace native leaf ───────────────────────────────────────
 * Dispatches the `selfbacktrace` RPC method directly so the running node dumps a
 * backtrace for every thread and returns the log path + thread_count. This is
 * the typed answer to "what is every thread doing right now" on hosts where
 * perf_event_paranoid / yama ptrace_scope block perf and gdb attach. */
void zcl_native_handle_ops_debug_backtrace(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    bridge_ensure_rpc_client();
    char *result = node_rpc_call("selfbacktrace", "[]");
    if (!result) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a backtrace body",
                               "ops.debug.backtrace");
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }
    struct json_value body;
    if (!json_read(&body, result, strlen(result)) || body.type != JSON_OBJ) {
        json_free(&body);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_BACKTRACE_BODY",
                               "serialize", false, false,
                               "selfbacktrace returned a non-object body",
                               "ops.debug.backtrace");
        return;
    }
    free(result);

    const struct json_value *err = json_get(&body, "error");
    if (err && err->type == JSON_STR) {
        const char *msg = json_get_str(err);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BACKTRACE_ERROR",
                               "execute", false, false,
                               msg && msg[0] ? msg
                                             : "self-backtrace dump failed",
                               "ops.debug.backtrace");
        json_free(&body);
        return;
    }

    const char *path = json_get_str(json_get(&body, "path"));
    const struct json_value *tc = json_get(&body, "thread_count");
    (void)json_push_kv_str(&reply->data, "path", path ? path : "");
    (void)json_push_kv_int(&reply->data, "thread_count",
                           tc ? json_get_int(tc) : 0);
    json_free(&body);
}

/* ── ops.debug.bundle native leaf ──────────────────────────────────────────
 * Dispatches the `debugbundle` RPC method directly so the running node writes
 * ONE JSON debug bundle (every registered state dumper + build identity +
 * supervisor stall summary) to <datadir>/debug-bundle-<utc>.json and returns
 * the path + capture counts. This is the typed answer to "collect complete
 * node state for a postmortem" in a single command. */
void zcl_native_handle_ops_debug_bundle(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct json_value body;
    if (!nc_rpc_fetch_object("debugbundle", "[]", "ops.debug.bundle",
                             "the node did not return a debug-bundle body",
                             "BAD_BUNDLE_BODY",
                             "debugbundle returned a non-object body", reply,
                             &body))
        return;

    /* node_rpc_call surfaces a JSON-RPC failure as {"error":{...}}
     * (transport), a bare {"code":..,"message":..} (RPC-level, e.g. warmup),
     * or {"error":".."} (handler-level). All three are a failed bundle. */
    const struct json_value *err, *ecode, *emsg;
    if (nc_rpc_body_has_error(&body, &err, &ecode, &emsg)) {
        (void)ecode;
        const char *msg = NULL;
        if (err && err->type == JSON_OBJ)
            msg = json_get_str(json_get(err, "message"));
        else if (err && err->type == JSON_STR)
            msg = json_get_str(err);
        else if (emsg && emsg->type == JSON_STR)
            msg = json_get_str(emsg);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BUNDLE_ERROR",
                               "execute", false, false,
                               msg && msg[0] ? msg
                                             : "debug bundle write failed",
                               "ops.debug.bundle");
        json_free(&body);
        return;
    }

    const char *path = json_get_str(json_get(&body, "path"));
    (void)json_push_kv_str(&reply->data, "path", path ? path : "");
    (void)json_push_kv_int(&reply->data, "bytes",
                           json_get_int(json_get(&body, "bytes")));
    (void)json_push_kv_int(&reply->data, "subsystems_captured",
                           json_get_int(json_get(&body,
                                                 "subsystems_captured")));
    (void)json_push_kv_int(&reply->data, "subsystems_failed",
                           json_get_int(json_get(&body, "subsystems_failed")));
    json_free(&body);
}

/* ── ops.explain <topic> native leaf ───────────────────────────────────────
 * Composes, IN C, what an operator otherwise stitches together from four
 * surfaces (reducer frontier, blocker registry, condition engine, health/sync
 * RPCs). explain_build fetches the shared RPC bundle and dispatches through the
 * topic table; the reply carries a prose `text` block + the structured fields.
 * The CLI renders `text` verbatim unless --format=json (see nc_render_prose). */
void zcl_native_handle_ops_explain(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *topic = json_get_str(json_get(request->input, "topic"));
    if (!topic || !topic[0])
        topic = "sync";

    bridge_ensure_rpc_client();
    struct json_value data;
    json_init(&data);
    bool ok = explain_build(topic, &data);
    if (!ok) {
        const char *emsg = json_get_str(json_get(&data, "error"));
        char known[128];
        explain_topics_csv(known, sizeof(known));
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_TOPIC",
                               "resolve", false, false,
                               emsg && emsg[0] ? emsg : "unknown explain topic",
                               known);
        nc_add_describe_next(reply, request->spec->path,
                             "inspect the supported explain topics");
        json_free(&data);
        return;
    }
    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &data);
    json_free(&data);
}

/* ── ops.profile native leaf ────────────────────────────────────────────────
 * Dispatches the `profile` RPC (samples this node's /proc/self/task twice
 * `seconds` apart, in-process) and renders a prose top-N thread table + verdict
 * + reducer stage step-EWMA. This replaces the /proc sampling an operator does
 * by hand to find a bottleneck. */
static void nc_profile_clamp_params(const struct zcl_command_request *request,
                                    int64_t *seconds_out, int64_t *top_n_out)
{
    int64_t seconds = json_get_int(json_get(request->input, "seconds"));
    if (seconds < 1) seconds = 3;
    if (seconds > 60) seconds = 60;
    int64_t top_n = json_get_int(json_get(request->input, "top_n"));
    if (top_n < 1) top_n = 8;
    if (top_n > 32) top_n = 32;
    *seconds_out = seconds;
    *top_n_out = top_n;
}

/* Render the busiest-threads block (cpu_ms / wchan) of the profile prose. */
static void nc_profile_render_threads(const struct json_value *body, char *t,
                                      size_t cap, size_t *len_io)
{
    size_t len = *len_io;
    const struct json_value *threads = json_get(body, "threads");
    if (!threads || threads->type != JSON_ARR) {
        *len_io = len;
        return;
    }
    int n = snprintf(t + len, cap - len,
                     "  busiest threads (cpu_ms / wchan):\n");
    if (n > 0) len += (size_t)n;
    for (size_t i = 0; i < threads->num_children && len < cap - 128; i++) {
        const struct json_value *th = &threads->children[i];
        n = snprintf(t + len, cap - len,
                     "    %-16s tid=%lld cpu=%lldms (%lld%%) wchan=%s\n",
                     json_get_str(json_get(th, "name"))
                         ? json_get_str(json_get(th, "name")) : "?",
                     (long long)json_get_int(json_get(th, "tid")),
                     (long long)json_get_int(json_get(th, "cpu_ms")),
                     (long long)json_get_int(json_get(th, "cpu_pct")),
                     json_get_str(json_get(th, "wchan"))
                         ? json_get_str(json_get(th, "wchan")) : "-");
        if (n > 0) len += (size_t)n;
    }
    *len_io = len;
}

/* Render the reducer stage rates (steps/sec, cursor) block of the profile
 * prose. */
static void nc_profile_render_stages(const struct json_value *body, char *t,
                                     size_t cap, size_t *len_io)
{
    size_t len = *len_io;
    const struct json_value *stages = json_get(body, "stage_ewma");
    if (!stages || stages->type != JSON_ARR || len >= cap - 256) {
        *len_io = len;
        return;
    }
    int n = snprintf(t + len, cap - len,
                     "  reducer stage rates (steps/sec, cursor):\n");
    if (n > 0) len += (size_t)n;
    for (size_t i = 0; i < stages->num_children && len < cap - 96; i++) {
        const struct json_value *sg = &stages->children[i];
        n = snprintf(t + len, cap - len, "    %-16s %lld  (%lld)\n",
                     json_get_str(json_get(sg, "stage"))
                         ? json_get_str(json_get(sg, "stage")) : "?",
                     (long long)json_get_int(json_get(sg, "steps_per_sec")),
                     (long long)json_get_int(json_get(sg, "cursor")));
        if (n > 0) len += (size_t)n;
    }
    *len_io = len;
}

/* Render a prose block from the structured profile body. */
static void nc_profile_render_text(const struct json_value *body, char *t,
                                   size_t cap)
{
    size_t len = 0;
    int n = snprintf(t + len, cap - len, "profile — %s\n",
                     json_get_str(json_get(body, "verdict"))
                         ? json_get_str(json_get(body, "verdict")) : "unknown");
    if (n > 0) len += (size_t)n;
    n = snprintf(t + len, cap - len,
                 "  sampled %lld threads over %lld ms\n",
                 (long long)json_get_int(json_get(body, "sampled_threads")),
                 (long long)json_get_int(json_get(body, "sample_ms")));
    if (n > 0) len += (size_t)n;

    nc_profile_render_threads(body, t, cap, &len);
    nc_profile_render_stages(body, t, cap, &len);
}

void zcl_native_handle_ops_profile(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    int64_t seconds, top_n;
    nc_profile_clamp_params(request, &seconds, &top_n);

    char params[64];
    (void)snprintf(params, sizeof(params), "[%lld,%lld]",
                   (long long)seconds, (long long)top_n);

    bridge_ensure_rpc_client();
    char *result = node_rpc_call("profile", params);
    struct json_value body;
    if (!result || !json_read(&body, result, strlen(result)) ||
        body.type != JSON_OBJ) {
        if (result) json_free(&body);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a profile body",
                               "ops.debug.profile");
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }
    free(result);

    const struct json_value *err = json_get(&body, "error");
    if (err && err->type == JSON_STR) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "PROFILE_ERROR",
                               "execute", false, false,
                               json_get_str(err), "ops.debug.profile");
        json_free(&body);
        return;
    }

    char t[1600];
    nc_profile_render_text(&body, t, sizeof(t));

    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &body);
    (void)json_push_kv_str(&reply->data, "text", t);
    json_free(&body);
}

/* ── ops.producer.status native leaf (node-free) ────────────────────────────
 * Reads another datadir's producer kernel store (`consensus.db`, or the
 * legacy `progress.kv` on a pre-flip datadir — resolved via
 * consensus_db_kernel_store_path(); stage cursors + session/receipt
 * lifecycle) and the mint-progress.log tail, with NO node contact, for an
 * operator watching a mint/anchor producer. Read-only. Takes datadir=. */
static void nc_read_log_tail(const char *datadir, char *out, size_t cap)
{
    if (cap) out[0] = '\0';
    char path[CONSENSUS_STATE_PRODUCER_DATADIR_MAX +
              sizeof("/mint-progress.log")];
    int path_len = snprintf(path, sizeof(path), "%s/mint-progress.log",
                            datadir);
    if (path_len < 0 || (size_t)path_len >= sizeof(path))
        return;
    FILE *f = fopen(path, "re");
    if (!f)
        return;
    /* Read the last <=4KB, keep the last non-empty line. */
    if (fseek(f, 0, SEEK_END) == 0) {
        long sz = ftell(f);
        long off = sz > 4096 ? sz - 4096 : 0;
        if (off > 0) (void)fseek(f, off, SEEK_SET);
    }
    char buf[4200];
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';
    while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r'))
        buf[--got] = '\0';
    char *nl = strrchr(buf, '\n');
    const char *line = nl ? nl + 1 : buf;
    (void)snprintf(out, cap, "%s", line);
}

/* A digest-verified finalized receipt is the immutable completion authority;
 * live stage cursors may belong to a later/restarted writer and must not
 * override its H*+1 fold cursor. */
static int64_t nc_producer_applied_height(
    const struct producer_status_read *st)
{
    if (!st)
        return -1;
    if (st->receipt_finalized)
        return st->fold_cursor > 0 ? st->fold_cursor - 1 : -1;
    if (st->utxo_apply_cursor > 0)
        return st->utxo_apply_cursor - 1;
    if (st->utxo_apply_cursor == 0)
        return -1;
    return st->tip_finalize_cursor;
}

#ifdef ZCL_TESTING
int64_t zcl_native_producer_applied_height_for_test(
    const struct producer_status_read *st);

int64_t zcl_native_producer_applied_height_for_test(
    const struct producer_status_read *st)
{
    return nc_producer_applied_height(st);
}
#endif

/* applied_at has one-second resolution.  Five seconds admits ordinary clock
 * scheduling/NTP jitter, while a larger future timestamp is rejected as ETA
 * evidence until wall time catches up. */
enum { NC_PRODUCER_RATE_FUTURE_SKEW_TOLERANCE_SECONDS = 5 };

/* Resolve + validate the target producer datadir: explicit input.datadir
 * wins, else the CLI's --datadir default. Fails the reply and returns NULL
 * on a missing or oversize datadir. */
static const char *nc_producer_resolve_datadir(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    if ((!datadir || !datadir[0]) && g_bridge_datadir[0])
        datadir = g_bridge_datadir;
    if (!datadir || !datadir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "ops.debug.producer");
        nc_add_describe_next(reply, request->spec->path,
                             "inspect the required producer datadir input");
        return NULL;
    }
    if (strlen(datadir) >= CONSENSUS_STATE_PRODUCER_DATADIR_MAX) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "producer datadir must be at most 1023 bytes",
                               "ops.debug.producer");
        return NULL;
    }
    return datadir;
}

/* The durable applied-rate window (consensus.db:utxo_apply_log.applied_at)
 * and whether it is recent/clock-sane enough to drive an ETA. */
static void nc_producer_compute_rate(
    const struct producer_status_read *st, int64_t *rate_sample_age_seconds,
    int64_t *rate_stale_after_seconds, int64_t *rate_future_skew_seconds,
    bool *rate_sample_clock_valid, bool *durable_rate_recent)
{
    *rate_sample_age_seconds = -1;
    *rate_stale_after_seconds = -1;
    *rate_future_skew_seconds = 0;
    *rate_sample_clock_valid = false;
    *durable_rate_recent = false;
    if (!st->durable_rate_available)
        return;
    int64_t now = platform_time_wall_unix();
    int64_t interval = st->rate_newer_time_unix - st->rate_older_time_unix;
    *rate_stale_after_seconds = interval > 43200 ? 86400 : interval * 2;
    if (*rate_stale_after_seconds < 300)
        *rate_stale_after_seconds = 300;
    if (now > 0 && st->rate_newer_time_unix > now) {
        *rate_future_skew_seconds = st->rate_newer_time_unix - now;
        *rate_sample_clock_valid = *rate_future_skew_seconds <=
            NC_PRODUCER_RATE_FUTURE_SKEW_TOLERANCE_SECONDS;
        if (*rate_sample_clock_valid)
            *rate_sample_age_seconds = 0;
    } else if (now > 0) {
        *rate_sample_clock_valid = true;
        *rate_sample_age_seconds = now - st->rate_newer_time_unix;
    }
    *durable_rate_recent = *rate_sample_clock_valid &&
        *rate_sample_age_seconds <= *rate_stale_after_seconds;
}

/* Whether an ETA can be claimed at all, and (when it can and blocks remain)
 * the ETA itself. */
static void nc_producer_compute_eta(
    const struct producer_status_read *st, int64_t height,
    int64_t target_height, int64_t remaining, bool durable_rate_recent,
    bool *eta_available_out, int64_t *eta_seconds_out)
{
    bool target_reached = height >= 0 && target_height >= 0 &&
                          height >= target_height;
    bool eta_available = target_reached ||
        (st->durable_rate_available && durable_rate_recent &&
         height >= 0 && target_height >= 0);
    int64_t eta_seconds = eta_available && remaining > 0
        ? (remaining * INT64_C(1000) +
           st->rate_blocks_per_second_milli - 1) /
              st->rate_blocks_per_second_milli
        : eta_available ? 0 : -1;
    *eta_available_out = eta_available;
    *eta_seconds_out = eta_seconds;
}

/* Fill every reply->data field ops.debug.producer reports, once the target
 * datadir's producer status, rate window and ETA are all resolved. */
static void nc_producer_fill_reply(
    struct zcl_command_reply *reply, const char *datadir,
    const struct producer_status_read *st, const char *log_tail,
    const char *receipt_state, int64_t height, int64_t target_height,
    int64_t remaining, int64_t rate_sample_age_seconds,
    int64_t rate_stale_after_seconds, int64_t rate_future_skew_seconds,
    bool rate_sample_clock_valid, bool durable_rate_recent,
    bool eta_available, int64_t eta_seconds, const char *t)
{
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_bool(&reply->data, "progress_kv_present",
                            st->progress_kv_present);
    (void)json_push_kv_str(&reply->data, "receipt_state", receipt_state);
    (void)json_push_kv_bool(&reply->data, "session_open", st->session_open);
    (void)json_push_kv_bool(&reply->data, "receipt_finalized",
                            st->receipt_finalized);
    (void)json_push_kv_int(&reply->data, "height", height);
    (void)json_push_kv_int(&reply->data, "utxo_apply_cursor",
                           st->utxo_apply_cursor);
    (void)json_push_kv_int(&reply->data, "tip_finalize_cursor",
                           st->tip_finalize_cursor);
    (void)json_push_kv_int(&reply->data, "fold_cursor", st->fold_cursor);
    (void)json_push_kv_str(&reply->data, "receipt_schema", st->receipt_schema);
    (void)json_push_kv_str(&reply->data, "source_tree_root",
                           st->source_tree_root);
    (void)json_push_kv_str(&reply->data, "source_epoch_digest",
                           st->source_epoch_digest);
    (void)json_push_kv_str(&reply->data, "producer_commit",
                           st->producer_commit);
    (void)json_push_kv_int(&reply->data, "validation_profile",
                           st->validation_profile);
    (void)json_push_kv_int(&reply->data, "target_height", target_height);
    (void)json_push_kv_str(&reply->data, "target_kind",
                           "compiled_sovereign_anchor");
    (void)json_push_kv_int(&reply->data, "remaining_blocks", remaining);
    if (height >= 0 && target_height > 0) {
        int64_t progress_ppm = height >= target_height
            ? INT64_C(1000000)
            : height * INT64_C(1000000) / target_height;
        (void)json_push_kv_int(&reply->data, "progress_ppm", progress_ppm);
    }
    (void)json_push_kv_bool(&reply->data, "durable_rate_available",
                            st->durable_rate_available);
    (void)json_push_kv_bool(&reply->data, "durable_rate_recent",
                            durable_rate_recent);
    (void)json_push_kv_bool(&reply->data, "rate_sample_clock_valid",
                            rate_sample_clock_valid);
    (void)json_push_kv_int(
        &reply->data, "rate_future_skew_tolerance_seconds",
        NC_PRODUCER_RATE_FUTURE_SKEW_TOLERANCE_SECONDS);
    (void)json_push_kv_str(&reply->data, "rate_source",
                           "consensus.db:utxo_apply_log.applied_at");
    if (st->durable_rate_available) {
        (void)json_push_kv_int(&reply->data, "rate_older_height",
                               st->rate_older_height);
        (void)json_push_kv_int(&reply->data, "rate_older_time_unix",
                               st->rate_older_time_unix);
        (void)json_push_kv_int(&reply->data, "rate_newer_height",
                               st->rate_newer_height);
        (void)json_push_kv_int(&reply->data, "rate_newer_time_unix",
                               st->rate_newer_time_unix);
        (void)json_push_kv_int(&reply->data, "rate_blocks_per_second_milli",
                               st->rate_blocks_per_second_milli);
        (void)json_push_kv_int(&reply->data, "rate_sample_age_seconds",
                               rate_sample_age_seconds);
        (void)json_push_kv_int(&reply->data, "rate_stale_after_seconds",
                               rate_stale_after_seconds);
        (void)json_push_kv_int(&reply->data, "rate_future_skew_seconds",
                               rate_future_skew_seconds);
    }
    (void)json_push_kv_bool(&reply->data, "eta_available", eta_available);
    if (eta_available) {
        (void)json_push_kv_int(&reply->data, "eta_seconds", eta_seconds);
        (void)json_push_kv_str(&reply->data, "eta_target",
                               "compiled_sovereign_anchor");
    }
    (void)json_push_kv_str(&reply->data, "last_log", log_tail);
    (void)json_push_kv_str(&reply->data, "text", t);
}

/* Render the one-line human summary (data.text). */
static void nc_producer_render_text(
    const char *datadir, const char *receipt_state,
    const struct producer_status_read *st, int64_t height,
    int64_t target_height, int64_t remaining, bool eta_available,
    int64_t eta_seconds, char *t, size_t cap)
{
    if (!st->progress_kv_present) {
        (void)snprintf(t, cap, "producer=%s state=not_started height=unknown",
                       datadir);
    } else if (eta_available && st->durable_rate_available) {
        int64_t rate_whole = st->rate_blocks_per_second_milli / 1000;
        int64_t rate_tenth = (st->rate_blocks_per_second_milli % 1000) / 100;
        (void)snprintf(
            t, cap,
            "producer=%s receipt=%s height=%lld target=%lld remaining=%lld "
            "rate=%lld.%lldblk/s eta=%llds",
            datadir, receipt_state, (long long)height,
            (long long)target_height, (long long)remaining,
            (long long)rate_whole, (long long)rate_tenth,
            (long long)eta_seconds);
    } else if (eta_available) {
        (void)snprintf(t, cap,
                       "producer=%s receipt=%s height=%lld target=%lld "
                       "remaining=0 rate=unknown eta=0s",
                       datadir, receipt_state, (long long)height,
                       (long long)target_height);
    } else {
        (void)snprintf(t, cap,
                       "producer=%s receipt=%s height=%lld target=%lld "
                       "rate=unknown eta=unknown",
                       datadir, receipt_state, (long long)height,
                       (long long)target_height);
    }
}

void zcl_native_handle_ops_producer_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = nc_producer_resolve_datadir(request, reply);
    if (!datadir)
        return;

    struct producer_status_read st;
    char why[256];
    if (!consensus_state_producer_status_read(datadir, &st, why,
                                              sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "PRODUCER_UNREADABLE",
                               "execute", true, false,
                               why[0] ? why : "producer datadir unreadable",
                               datadir);
        return;
    }

    char log_tail[512];
    nc_read_log_tail(datadir, log_tail, sizeof(log_tail));

    const char *receipt_state = st.receipt_finalized ? "finalized"
                              : st.session_open ? "open" : "absent";
    /* utxo_apply names the NEXT height to process; tip_finalize owns its
     * already-served height. A finalized receipt supersedes both. */
    int64_t height = nc_producer_applied_height(&st);
    const struct sha3_utxo_checkpoint *checkpoint =
        get_sha3_utxo_checkpoint();
    int64_t target_height = checkpoint ? checkpoint->height : -1;
    int64_t remaining = -1;
    if (height >= 0 && target_height >= 0)
        remaining = target_height > height ? target_height - height : 0;

    int64_t rate_sample_age_seconds, rate_stale_after_seconds;
    int64_t rate_future_skew_seconds;
    bool rate_sample_clock_valid, durable_rate_recent;
    nc_producer_compute_rate(&st, &rate_sample_age_seconds,
                             &rate_stale_after_seconds,
                             &rate_future_skew_seconds,
                             &rate_sample_clock_valid, &durable_rate_recent);

    bool eta_available;
    int64_t eta_seconds;
    nc_producer_compute_eta(&st, height, target_height, remaining,
                            durable_rate_recent, &eta_available,
                            &eta_seconds);

    char t[2048];
    nc_producer_render_text(datadir, receipt_state, &st, height,
                            target_height, remaining, eta_available,
                            eta_seconds, t, sizeof(t));

    nc_producer_fill_reply(reply, datadir, &st, log_tail, receipt_state,
                           height, target_height, remaining,
                           rate_sample_age_seconds, rate_stale_after_seconds,
                           rate_future_skew_seconds, rate_sample_clock_valid,
                           durable_rate_recent, eta_available, eta_seconds, t);
}

/* ── ops.rom native leaf ─────────────────────────────────────────────────
 * Dispatches `dumpstate rom_compile` (engine/jobs/src/rom_compile_status.c —
 * pure composition over EXISTING telemetry: the per-stage step-EWMA
 * counters, the refold-in-progress signal, the L0 reducer frontier, the
 * sealed segment store, and the state-seal ring — no second producer)
 * against THIS running node and renders the rich-ASCII human view via
 * rom_compile_render_ascii. The structured zcl.rom_compile.v1 body is
 * copied into reply->data verbatim for machine consumers; the CLI prints
 * data.text unless --format=json. */
void zcl_native_handle_ops_rom(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    bridge_ensure_rpc_client();
    char *result = node_rpc_call("dumpstate", "[\"rom_compile\"]");
    if (!result) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a rom_compile body",
                               "ops.rom");
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }
    struct json_value envelope;
    if (!json_read(&envelope, result, strlen(result)) ||
        envelope.type != JSON_OBJ) {
        json_free(&envelope);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_BODY",
                               "execute", false, false,
                               "dumpstate rom_compile returned unparsable JSON",
                               "ops.rom");
        return;
    }
    free(result);

    const struct json_value *err = json_get(&envelope, "error");
    if (err && err->type == JSON_STR) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "ROM_STATUS_ERROR",
                               "execute", false, false,
                               json_get_str(err), "ops.rom");
        json_free(&envelope);
        return;
    }

    const struct json_value *state = json_get(&envelope, "state");
    char text[4096];
    rom_compile_render_ascii(state, text, sizeof(text));

    json_free(&reply->data);
    json_init(&reply->data);
    if (state && state->type == JSON_OBJ)
        json_copy(&reply->data, state);
    else
        json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "text", text);
    json_free(&envelope);
}

/* ── ops.rom --watch: live redraw loop (Phase B) ─────────────────────────
 * The single-shot ops.rom leaf above is unchanged. When the operator adds
 * --watch/--once (optionally --interval=<secs>, --datadir=<dir>), the argv path
 * intercepts BEFORE registry dispatch (native_command_main) and drives
 * rom_watch_run with one of two fetch closures: the live-node dumpstate RPC, or
 * the read-only offline composer against a foreign producer datadir. All the
 * loop/redraw/parse logic lives in rom_watch_loop.c + rom_compile_offline.c;
 * this file only builds the closure and parses the four flags. */

/* Live fetch: dumpstate rom_compile against THIS node, unwrap the `state`. */
static bool nc_rom_fetch_live(void *ctx, struct json_value *out, char *err,
                              size_t errlen)
{
    (void)ctx;
    bridge_ensure_rpc_client();
    char *result = node_rpc_call("dumpstate", "[\"rom_compile\"]");
    if (!result) {
        (void)snprintf(err, errlen, "node did not return a rom_compile body");
        return false;
    }
    struct json_value env;
    if (!json_read(&env, result, strlen(result)) || env.type != JSON_OBJ) {
        json_free(&env);
        free(result);
        (void)snprintf(err, errlen, "dumpstate rom_compile returned unparsable JSON");
        return false;
    }
    free(result);
    const struct json_value *e = json_get(&env, "error");
    if (e && e->type == JSON_STR) {
        (void)snprintf(err, errlen, "%s", json_get_str(e));
        json_free(&env);
        return false;
    }
    const struct json_value *state = json_get(&env, "state");
    if (!state || state->type != JSON_OBJ) {
        (void)snprintf(err, errlen, "dumpstate rom_compile returned no state body");
        json_free(&env);
        return false;
    }
    json_copy(out, state);
    json_free(&env);
    return true;
}

/* Offline fetch: compose a rom_compile body from a foreign producer datadir. */
static bool nc_rom_fetch_offline(void *ctx, struct json_value *out, char *err,
                                 size_t errlen)
{
    const char *datadir = (const char *)ctx;
    return rom_compile_offline_compose(datadir, out, err, errlen);
}

/* Scan the unconsumed argv words for the ops.rom watch flags. If neither
 * --watch, --once, nor --datadir=<dir> is present, returns false (the caller
 * falls through to the normal single-shot dispatch). Otherwise builds the fetch
 * closure + opts, runs rom_watch_run, stores its exit code in *rc, and returns
 * true. Recognizes: --watch, --once, --interval=<secs>, --datadir=<dir>. */
static void nc_ops_rom_parse_watch_flags(
    const char *const *words, size_t count, size_t consumed,
    bool *want_watch, bool *want_once, int *interval_ms,
    const char **offline_datadir)
{
    for (size_t i = consumed; i < count; i++) {
        const char *w = words[i];
        if (!w)
            continue;
        if (strcmp(w, "--watch") == 0) {
            *want_watch = true;
        } else if (strcmp(w, "--once") == 0) {
            *want_once = true;
        } else if (strncmp(w, "--interval=", 11) == 0) {
            int secs = atoi(w + 11);
            if (secs > 0)
                *interval_ms = secs * 1000;
        } else if (strncmp(w, "--datadir=", 10) == 0) {
            *offline_datadir = w + 10;
        }
    }
}

static int nc_ops_rom_dispatch_fetch(const char *offline_datadir,
                                     const char *cli_datadir,
                                     struct rom_watch_opts *opts)
{
    if (offline_datadir && offline_datadir[0])
        return rom_watch_run(nc_rom_fetch_offline, (void *)offline_datadir,
                             opts);
    if (offline_datadir) {
        /* --datadir= with an empty value: fall back to the CLI default if any,
         * else run live. */
        if (cli_datadir && cli_datadir[0])
            return rom_watch_run(nc_rom_fetch_offline, (void *)cli_datadir,
                                 opts);
        return rom_watch_run(nc_rom_fetch_live, NULL, opts);
    }
    return rom_watch_run(nc_rom_fetch_live, NULL, opts);
}

static bool nc_ops_rom_try_watch(const char *const *words, size_t count,
                                 size_t consumed, const char *cli_datadir,
                                 int *rc)
{
    bool want_watch = false, want_once = false;
    int interval_ms = 2000;
    const char *offline_datadir = NULL;
    nc_ops_rom_parse_watch_flags(words, count, consumed, &want_watch,
                                 &want_once, &interval_ms, &offline_datadir);

    if (!want_watch && !want_once && !offline_datadir)
        return false;

    struct rom_watch_opts opts = {
        .interval_ms = interval_ms,
        /* --once (or the default single offline shot) renders exactly once;
         * --watch loops until interrupted. */
        .max_iters = want_watch && !want_once ? 0 : 1,
        .ansi = isatty(fileno(stdout)) ? true : false,
        .stream = stdout,
    };
    *rc = nc_ops_rom_dispatch_fetch(offline_datadir, cli_datadir, &opts);
    return true;
}

#ifdef ZCL_DEV_BUILD
static void nc_print_error(const char *command, const char *code,
                           const char *phase, const char *message,
                           const char *evidence, const char *next_command,
                           const char *next_key, const char *next_value);

static bool nc_parse_i64_exact(const char *value, int64_t min, int64_t max,
                               int64_t *out)
{
    if (!value || !value[0] || !out) return false;
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    if (errno || !end || *end || parsed < min || parsed > max) return false;
    *out = (int64_t)parsed;
    return true;
}

enum nc_dev_events_flags_result {
    NC_DEV_EVENTS_NOT_JSONL,
    NC_DEV_EVENTS_JSONL,
    NC_DEV_EVENTS_INVALID,
};

/* Scan the unconsumed argv words for --format=jsonl / --after= /
 * --heartbeat-ms=. Prints the typed error and returns NC_DEV_EVENTS_INVALID
 * (with *rc set) on a malformed value. */
static enum nc_dev_events_flags_result nc_dev_events_parse_flags(
    const char *const *words, size_t count, size_t consumed, int64_t *after,
    int64_t *heartbeat_ms, int *rc)
{
    bool jsonl = false;
    for (size_t i = consumed; i < count; i++) {
        const char *word = words[i];
        if (!word) continue;
        if (strcmp(word, "--format=jsonl") == 0) {
            jsonl = true;
        } else if (strncmp(word, "--after=", 8) == 0) {
            if (!nc_parse_i64_exact(word + 8, 0, INT64_MAX, after)) {
                nc_print_error("dev.loop.events", "INVALID_SUBSCRIPTION_CURSOR",
                               "normalize", "--after must be nonnegative",
                               "after", "", "", "");
                *rc = ZCL_COMMAND_EXIT_INVALID;
                return NC_DEV_EVENTS_INVALID;
            }
        } else if (strncmp(word, "--heartbeat-ms=", 15) == 0) {
            if (!nc_parse_i64_exact(word + 15, 100, 300000, heartbeat_ms)) {
                nc_print_error("dev.loop.events", "INVALID_SUBSCRIPTION_CURSOR",
                               "normalize",
                               "--heartbeat-ms must be 100..300000",
                               "heartbeat_ms", "", "", "");
                *rc = ZCL_COMMAND_EXIT_INVALID;
                return NC_DEV_EVENTS_INVALID;
            }
        }
    }
    return jsonl ? NC_DEV_EVENTS_JSONL : NC_DEV_EVENTS_NOT_JSONL;
}

static bool nc_dev_events_is_interrupting(const char *phase,
                                          const char *status)
{
    return (phase && (strcmp(phase, "STORY_RED") == 0 ||
                       strcmp(phase, "COMPILE_RED") == 0 ||
                       strcmp(phase, "FOCUSED_RED") == 0)) ||
           (status && (strcmp(status, "story_red") == 0 ||
                       strcmp(status, "compile_red") == 0 ||
                       strcmp(status, "focused_red") == 0 ||
                       strcmp(status, "rejected") == 0));
}

/* Attach the zcl.dev_diagnostic_capsule.v1 `diagnostic` object carried by an
 * interrupting cycle event. */
static void nc_dev_events_build_diagnostic(const struct json_value *cycle,
                                           struct json_value *line, bool *ok)
{
    struct json_value capsule;
    json_init(&capsule);
    json_set_object(&capsule);
    *ok = json_push_kv_str(&capsule, "schema",
                           "zcl.dev_diagnostic_capsule.v1");
    static const struct { const char *from; const char *to; } f[] = {
        {"phase", "phase"}, {"edit_epoch", "edit_epoch"},
        {"source_tu", "source_tu"},
        {"failure_capsule", "message"},
        {"compiler_output", "detail"},
    };
    for (size_t j = 0; *ok && j < sizeof(f) / sizeof(f[0]); j++) {
        const struct json_value *v = json_get(cycle, f[j].from);
        *ok = !v || json_push_kv(&capsule, f[j].to, v);
    }
    if (*ok) *ok = json_push_kv(line, "diagnostic", &capsule);
    json_free(&capsule);
}

/* Fill a FOUND event's `kind` / `interrupting` / `diagnostic` / `event`
 * fields from the raw cycle-state body. Assumes the caller's `ok` was
 * already true (schema/cursor pushed). */
static bool nc_dev_events_build_found(struct json_value *line,
                                      const char *body, size_t body_len)
{
    struct json_value cycle;
    json_init(&cycle);
    bool ok = json_read(&cycle, body, body_len) && cycle.type == JSON_OBJ;
    const char *phase = ok ? json_get_str(json_get(&cycle, "phase")) : NULL;
    const char *status = ok ? json_get_str(json_get(&cycle, "status")) : NULL;
    bool interrupting = nc_dev_events_is_interrupting(phase, status);
    ok = ok && json_push_kv_str(line, "kind",
        phase && phase[0] ? phase : "CYCLE_EVENT") &&
        json_push_kv_bool(line, "interrupting", interrupting);
    if (ok && interrupting)
        nc_dev_events_build_diagnostic(&cycle, line, &ok);
    if (ok) ok = json_push_kv(line, "event", &cycle);
    json_free(&cycle);
    return ok;
}

/* Encode and write one jsonl event line to stdout. Returns false when the
 * write failed (or the line failed to encode) — the caller then sets *rc
 * and stops the stream. */
static bool nc_dev_events_emit_line(const struct json_value *line, int *rc,
                                    bool ok)
{
    char encoded[20000];
    size_t encoded_len = ok ? json_write(line, encoded, sizeof(encoded) - 2)
                            : 0;
    if (!encoded_len || fwrite(encoded, 1, encoded_len, stdout) !=
                            encoded_len ||
        fputc('\n', stdout) == EOF || fflush(stdout) != 0) {
        *rc = encoded_len ? ZCL_COMMAND_EXIT_OK : ZCL_COMMAND_EXIT_INTERNAL;
        return false;
    }
    return true;
}

/* One iteration of the jsonl stream: wait for the next cycle event (or a
 * heartbeat), build its line, and write it. Returns false to stop the
 * stream (with *rc set); on true, `*after` has advanced past a FOUND
 * event. */
static bool nc_dev_events_stream_step(const char *root, int64_t *after,
                                      int64_t heartbeat_ms, int *rc)
{
    char body[16384], why[160] = {0};
    size_t body_len = 0;
    int64_t cursor = *after;
    enum zcl_devloop_state_lookup lookup = zcl_devloop_cycle_state_wait_after(
        root, *after, (int)heartbeat_ms, body, sizeof(body), &body_len,
        &cursor, why, sizeof(why));
    if (lookup != ZCL_DEVLOOP_STATE_FOUND)
        cursor = *after;
    if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
        nc_print_error("dev.loop.events", "DEV_EVENT_STREAM_INVALID", "read",
                       "event cursor or SHA3 validation failed",
                       why[0] ? why : "event_stream_invalid", "", "", "");
        *rc = ZCL_COMMAND_EXIT_INTERNAL;
        return false;
    }
    struct json_value line;
    json_init(&line);
    json_set_object(&line);
    bool ok = json_push_kv_str(&line, "schema", "zcl.dev_loop_event.v1") &&
        json_push_kv_int(&line, "cursor", cursor);
    if (lookup == ZCL_DEVLOOP_STATE_FOUND) {
        if (ok)
            ok = nc_dev_events_build_found(&line, body, body_len);
        *after = cursor;
    } else {
        ok = ok && json_push_kv_str(&line, "kind", "HEARTBEAT") &&
            json_push_kv_bool(&line, "interrupting", false);
    }
    bool wrote = nc_dev_events_emit_line(&line, rc, ok);
    json_free(&line);
    return wrote;
}

/* Persistent machine interface. The normal registry handler returns one
 * resumable event; --format=jsonl keeps this one local process attached and
 * advances the same cursor forever. It performs no build/proof/storage/network
 * work and exits naturally when the subscriber closes stdout. */
static bool nc_dev_events_try_stream(const char *const *words, size_t count,
                                     size_t consumed, int *rc)
{
    int64_t after = 0, heartbeat_ms = 15000;
    enum nc_dev_events_flags_result flags =
        nc_dev_events_parse_flags(words, count, consumed, &after,
                                  &heartbeat_ms, rc);
    if (flags == NC_DEV_EVENTS_INVALID)
        return true;
    if (flags == NC_DEV_EVENTS_NOT_JSONL)
        return false;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    if (!root || !root[0]) root = ".";
    while (nc_dev_events_stream_step(root, &after, heartbeat_ms, rc))
        ;
    return true;
}
#endif

/* ── core.node.bootstatus / core.node.bootwait native leaves ───────────────
 * Pre-RPC boot observability. Both read <datadir>/boot_status.json directly
 * off disk (util/boot_status.h) — NO node contact, NO RPC — so they answer
 * "what boot stage are we at, is it serving yet?" during the exact window
 * (snapshot load / refold / index rebuild) when RPC has not bound and the only
 * alternative was ss/ps/tail node.log. bootstatus is a single read; bootwait
 * polls until serving or a timeout. */

/* Resolve the target datadir: explicit input.datadir wins, else the CLI's
 * --datadir (g_bridge_datadir). Returns NULL when neither is set. */
static const char *nc_bootstatus_datadir(const struct zcl_command_request *req)
{
    const char *dd = json_get_str(json_get(req->input, "datadir"));
    if (dd && dd[0])
        return dd;
    if (g_bridge_datadir[0])
        return g_bridge_datadir;
    return NULL;
}

/* Project a parsed boot_status snapshot into reply->data. */
static void nc_bootstatus_fill(struct zcl_command_reply *reply,
                               const struct boot_status_snapshot *s)
{
    (void)json_push_kv_str(&reply->data, "phase", s->phase);
    (void)json_push_kv_str(&reply->data, "stage", s->stage);
    (void)json_push_kv_int(&reply->data, "stage_ordinal", s->stage_ordinal);
    (void)json_push_kv_int(&reply->data, "height", s->height);
    (void)json_push_kv_bool(&reply->data, "rpc_bound", s->rpc_bound);
    (void)json_push_kv_bool(&reply->data, "serving", s->serving);
    (void)json_push_kv_int(&reply->data, "started_unix", s->started_unix);
    (void)json_push_kv_int(&reply->data, "updated_unix", s->updated_unix);
    (void)json_push_kv_int(&reply->data, "elapsed_s", s->elapsed_s);
    if (s->activity[0]) {
        (void)json_push_kv_str(&reply->data, "activity", s->activity);
        (void)json_push_kv_int(&reply->data, "progress_current",
                               s->progress_current);
        (void)json_push_kv_int(&reply->data, "progress_target",
                               s->progress_target);
    }
    if (s->blocker[0]) {
        (void)json_push_kv_str(&reply->data, "blocker", s->blocker);
        (void)json_push_kv_str(&reply->data, "blocker_reason",
                               s->blocker_reason);
    }
}

void zcl_native_handle_core_node_bootstatus(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = nc_bootstatus_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.node.bootstatus");
        nc_add_describe_next(reply, request->spec->path,
                             "inspect the boot-status datadir input");
        return;
    }

    struct boot_status_snapshot snap;
    char why[192];
    if (!boot_status_read(datadir, &snap, why, sizeof(why))) {
        /* No beacon yet: the node has not started booting (or is a build
         * without the writer). Fail closed (exit 3) — never invent a status. */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "NO_BOOT_STATUS",
                               "execute", true, false,
                               why[0] ? why : "no boot_status.json yet",
                               datadir);
        nc_add_string_next(reply, "core.node.bootwait", "datadir", datadir,
                           "wait for the beacon to appear");
        return;
    }
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    nc_bootstatus_fill(reply, &snap);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_core_node_bootwait(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = nc_bootstatus_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.node.bootwait");
        return;
    }

    /* Bounded poll: default 60s budget, 500ms cadence. The validator already
     * range-checks these (timeout_ms 1..300000, heartbeat_ms 100..60000). */
    int64_t timeout_ms = 60000;
    int64_t poll_ms = 500;
    const struct json_value *tmo = json_get(request->input, "timeout_ms");
    if (tmo && tmo->type == JSON_INT)
        timeout_ms = json_get_int(tmo);
    const struct json_value *hb = json_get(request->input, "heartbeat_ms");
    if (hb && hb->type == JSON_INT)
        poll_ms = json_get_int(hb);

    int64_t t0_ms = platform_time_monotonic_ms();
    struct boot_status_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    snap.stage_ordinal = -1;
    snap.height = -1;
    bool ever_seen = false;
    int polls = 0;

    for (;;) {
        char why[192];
        if (boot_status_read(datadir, &snap, why, sizeof(why))) {
            ever_seen = true;
            if (snap.serving) {
                (void)json_push_kv_str(&reply->data, "datadir", datadir);
                (void)json_push_kv_int(&reply->data, "polls", polls);
                nc_bootstatus_fill(reply, &snap);
                reply->status = ZCL_COMMAND_STATUS_PASSED;
                reply->exit_code = ZCL_COMMAND_EXIT_OK;
                return;
            }
        }
        polls++;

        int64_t elapsed_ms = platform_time_monotonic_ms() - t0_ms;
        if (elapsed_ms >= timeout_ms)
            break;

        int64_t remain = timeout_ms - elapsed_ms;
        int64_t sleep_ms = poll_ms < remain ? poll_ms : remain;
        struct timespec ts = { .tv_sec = sleep_ms / 1000,
                               .tv_nsec = (sleep_ms % 1000) * 1000000L };
        (void)nanosleep(&ts, NULL);
    }

    /* Timed out: report the last observed state (transiently unavailable). */
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_int(&reply->data, "polls", polls);
    if (ever_seen)
        nc_bootstatus_fill(reply, &snap);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
        "BOOT_WAIT_TIMEOUT", "execute", true, false,
        ever_seen ? "boot not serving before the timeout"
                  : "no boot_status.json before the timeout",
        datadir);
}

/* ── argv normalization + dispatch ─────────────────────────────────── */
enum { NC_MAX_WORDS = 64 };

static bool nc_is_flag(const char *word)
{
    return word && word[0] == '-';
}

static bool nc_is_integer(const char *s)
{
    if (!s || !s[0])
        return false;
    size_t i = 0;
    if (s[0] == '-' || s[0] == '+')
        i = 1;
    if (!s[i])
        return false;
    for (; s[i]; i++) {
        if (!isdigit((unsigned char)s[i]))
            return false;
    }
    return true;
}

/* Split "--key=value" (or "-key=value"). Returns false if not a value flag. */
static bool nc_split_flag(const char *word, char *key, size_t key_size,
                          const char **value)
{
    const char *p = word;
    while (*p == '-')
        p++;
    const char *eq = strchr(p, '=');
    size_t klen = eq ? (size_t)(eq - p) : strlen(p);
    if (klen == 0 || klen >= key_size)
        return false;
    memcpy(key, p, klen);
    key[klen] = 0;
    *value = eq ? eq + 1 : NULL;
    return true;
}

static bool nc_set_typed_value(struct json_value *obj, const char *key,
                               const char *value)
{
    if (!value)
        return json_push_kv_bool(obj, key, true);
    if (strcmp(value, "true") == 0)
        return json_push_kv_bool(obj, key, true);
    if (strcmp(value, "false") == 0)
        return json_push_kv_bool(obj, key, false);
    if (nc_is_integer(value)) {
        errno = 0;
        long long parsed = strtoll(value, NULL, 10);
        if (errno != 0)
            return false;
        return json_push_kv_int(obj, key, (int64_t)parsed);
    }
    return json_push_kv_str(obj, key, value);
}

static bool nc_parse_size_control(const char *value, size_t minimum,
                                  size_t maximum, size_t *out)
{
    if (!value || !nc_is_integer(value) || value[0] == '-' || value[0] == '+')
        return false;
    errno = 0;
    unsigned long long parsed = strtoull(value, NULL, 10);
    if (errno != 0 || parsed < minimum || parsed > maximum)
        return false;
    *out = (size_t)parsed;
    return true;
}

/* Read the whole `--input=-` document, refusing anything past `max_bytes`.
 * `max_bytes` is the caller's per-leaf budget from
 * zcl_command_registry_input_budget_bytes(), NOT a constant: a leaf that
 * declares a 1 MiB manifest key must be able to receive 2 MiB of hex, and a
 * leaf that declares only short keys must not. `*oversize` distinguishes
 * "the document is bigger than this leaf can take" from "the read failed",
 * so the CLI can name the rule instead of reporting a generic parse error. */
static char *nc_read_stdin(size_t max_bytes, bool *oversize)
{
    if (oversize)
        *oversize = false;
    if (max_bytes < 2)
        max_bytes = 2;
    /* One byte past the budget so an OVER-limit document is detected by
     * actually reading the extra byte, never inferred from a full buffer —
     * a document of exactly max_bytes must be accepted, not refused. */
    const size_t hard_cap = max_bytes + 2; /* +1 sentinel, +1 NUL */
    size_t cap = 4096, len = 0;
    if (cap > hard_cap)
        cap = hard_cap;
    char *buf = (char *)zcl_malloc(cap, "native_command.stdin");
    if (!buf)
        return NULL;
    for (;;) {
        if (len + 1 >= cap) {
            if (cap >= hard_cap)
                break; /* read the sentinel byte; length check below rules */
            size_t ncap = cap * 2;
            if (ncap > hard_cap)
                ncap = hard_cap;
            char *nb = (char *)zcl_realloc(buf, ncap, "native_command.stdin");
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
        ssize_t r = read(STDIN_FILENO, buf + len, cap - len - 1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            return NULL;
        }
        if (r == 0)
            break;
        len += (size_t)r;
    }
    if (len > max_bytes) {
        if (oversize)
            *oversize = true;
        free(buf);
        return NULL;
    }
    buf[len] = 0;
    return buf;
}

#ifdef ZCL_DEV_BUILD
enum nc_dev_retrieval_flags_result {
    NC_DEV_RETRIEVAL_NOT_REQUESTED,
    NC_DEV_RETRIEVAL_OK,
    NC_DEV_RETRIEVAL_INVALID,
};

enum nc_dev_retrieval_flag_kind {
    NC_DEV_RETRIEVAL_FLAG_BAD,
    NC_DEV_RETRIEVAL_FLAG_FORMAT,
    NC_DEV_RETRIEVAL_FLAG_INPUT,
    NC_DEV_RETRIEVAL_FLAG_OTHER,
};

/* Classify one flag word against the JSONL transport's two accepted
 * options. NC_DEV_RETRIEVAL_FLAG_BAD means the caller-visible error has
 * already been printed and *rc set. */
static enum nc_dev_retrieval_flag_kind nc_dev_retrieval_classify_flag(
    const char *word, int *rc)
{
    if (!word || !nc_is_flag(word)) {
        fprintf(stderr,
                "dev.retrieval.benchmark: BAD_FLAG: JSONL accepts only "
                "--format=jsonl --input=-\n");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return NC_DEV_RETRIEVAL_FLAG_BAD;
    }
    char key[64];
    const char *value = NULL;
    if (!nc_split_flag(word, key, sizeof(key), &value)) {
        fprintf(stderr,
                "dev.retrieval.benchmark: BAD_FLAG: malformed option\n");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return NC_DEV_RETRIEVAL_FLAG_BAD;
    }
    if (strcmp(key, "format") == 0 && value && strcmp(value, "jsonl") == 0)
        return NC_DEV_RETRIEVAL_FLAG_FORMAT;
    if (strcmp(key, "input") == 0 && value && strcmp(value, "-") == 0)
        return NC_DEV_RETRIEVAL_FLAG_INPUT;
    return NC_DEV_RETRIEVAL_FLAG_OTHER;
}

/* Scan the unconsumed argv words for the JSONL transport's exact flag
 * contract: --format=jsonl and --input=-, each exactly once, nothing else.
 * NC_DEV_RETRIEVAL_NOT_REQUESTED means the caller should fall through to
 * the ordinary one-document formatter untouched. */
static enum nc_dev_retrieval_flags_result nc_dev_retrieval_parse_flags(
    const char *const *words, size_t count, size_t consumed, int *rc)
{
    bool requested = false;
    for (size_t i = consumed; i < count; i++)
        if (words[i] && strcmp(words[i], "--format=jsonl") == 0)
            requested = true;
    if (!requested) return NC_DEV_RETRIEVAL_NOT_REQUESTED;

    bool seen_format = false, seen_input = false;
    for (size_t i = consumed; i < count; i++) {
        enum nc_dev_retrieval_flag_kind kind =
            nc_dev_retrieval_classify_flag(words[i], rc);
        if (kind == NC_DEV_RETRIEVAL_FLAG_BAD)
            return NC_DEV_RETRIEVAL_INVALID;
        if (kind == NC_DEV_RETRIEVAL_FLAG_FORMAT && !seen_format) {
            seen_format = true;
        } else if (kind == NC_DEV_RETRIEVAL_FLAG_INPUT && !seen_input) {
            seen_input = true;
        } else {
            fprintf(stderr,
                    "dev.retrieval.benchmark: BAD_FLAG: JSONL accepts each "
                    "of --format=jsonl and --input=- exactly once\n");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return NC_DEV_RETRIEVAL_INVALID;
        }
    }
    if (!seen_format || !seen_input) {
        fprintf(stderr,
                "dev.retrieval.benchmark: BAD_FLAG: JSONL requires "
                "--format=jsonl --input=-\n");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return NC_DEV_RETRIEVAL_INVALID;
    }
    return NC_DEV_RETRIEVAL_OK;
}

/* Read and validate stdin's one bounded JSON object against the leaf's
 * input contract. On failure, *input has already been freed. */
static bool nc_dev_retrieval_read_input(const struct zcl_command_spec *spec,
                                        struct json_value *input, int *rc)
{
    bool oversize = false;
    size_t input_budget = zcl_command_registry_input_budget_bytes(spec);
    char *raw = nc_read_stdin(input_budget, &oversize);
    json_init(input);
    bool parsed = raw && json_read(input, raw, strlen(raw)) &&
                  input->type == JSON_OBJ;
    free(raw);
    if (!parsed) {
        json_free(input);
        fprintf(stderr,
                "dev.retrieval.benchmark: BAD_INPUT: stdin must be one "
                "bounded JSON object%s\n", oversize ? " (over budget)" : "");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return false;
    }
    char why[160];
    if (!zcl_command_registry_input_validate(spec, input, why, sizeof(why))) {
        json_free(input);
        fprintf(stderr, "dev.retrieval.benchmark: INVALID_INPUT: %s\n", why);
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return false;
    }
    return true;
}

/* Run the streaming leaf itself and report a failure to stderr the same
 * way the rest of this CLI-only transport does. */
static void nc_dev_retrieval_run_stream(const struct zcl_command_spec *spec,
                                        struct json_value *input, int *rc)
{
    char error_code[64], error_message[192];
    g_native_input_from_stdin = true;
    *rc = zcl_native_dev_retrieval_stream_jsonl(
        input, spec->budget_bytes ? (size_t)spec->budget_bytes
                                  : (size_t)ZCL_COMMAND_LIST_BUDGET,
        stdout, error_code, sizeof(error_code), error_message,
        sizeof(error_message));
    g_native_input_from_stdin = false;
    if (*rc != ZCL_COMMAND_EXIT_OK)
        fprintf(stderr, "dev.retrieval.benchmark: %s: %s\n",
                error_code[0] ? error_code : "STREAM_FAILED",
                error_message[0] ? error_message : "stream failed");
}

/* CLI-only complete-page transport for the observational retrieval leaf.
 * It deliberately sits outside the ordinary one-document formatter while
 * reusing the leaf's exact bounded input contract and implementation. */
static bool nc_dev_retrieval_try_stream(
    const struct zcl_command_spec *spec, const char *const *words,
    size_t count, size_t consumed, int *rc)
{
    enum nc_dev_retrieval_flags_result flags =
        nc_dev_retrieval_parse_flags(words, count, consumed, rc);
    if (flags == NC_DEV_RETRIEVAL_NOT_REQUESTED)
        return false;
    if (flags == NC_DEV_RETRIEVAL_INVALID)
        return true;

    struct json_value input;
    if (!nc_dev_retrieval_read_input(spec, &input, rc))
        return true;

    nc_dev_retrieval_run_stream(spec, &input, rc);
    json_free(&input);
    return true;
}
#endif

static bool nc_next_input_valid(const char *current_command,
                                const char *next_command,
                                const struct json_value *input)
{
    const struct zcl_command_spec *next_spec =
        zcl_command_registry_find(catalog(), next_command, NULL);
    char why[160] = {0};
    if (!next_spec || next_spec->mode == ZCL_COMMAND_MODE_BRANCH ||
        (current_command && current_command[0] &&
         strcmp(current_command, next_spec->path) == 0) ||
        !zcl_command_registry_input_validate(next_spec, input, why,
                                             sizeof(why)))
        return false;

    return true;
}

/* ── terminal-lane human presentation (docs/work/UX_PLAN.md (terminal lane)) ────
 * The canonical typed-JSON document is ALWAYS computed first, unchanged;
 * these helpers only decide whether the final print swaps in the human
 * rendering from tools/command/cli_render.c. Resolution is once per CLI
 * process: isatty(stdout) (or the ZCL_HUMAN force), with NO_COLOR /
 * TERM=dumb honored inside the renderer. A successfully parsed
 * --format=json pins the canonical JSON even on a TTY. Pipes therefore
 * stay byte-identical by construction — and a renderer that does not
 * recognize a document shape returns 0 and falls through to the JSON. */
static struct zcl_cli_render_env g_nc_render_env;
static bool g_nc_render_resolved;
static bool g_nc_format_json;

static const struct zcl_cli_render_env *nc_render_env(void)
{
    if (!g_nc_render_resolved) {
        g_nc_render_env = zcl_cli_render_resolve(fileno(stdout));
        g_nc_render_resolved = true;
    }
    return &g_nc_render_env;
}

static bool nc_human(void)
{
    return nc_render_env()->human && !g_nc_format_json;
}

static void nc_print_doc(const char *doc, const char *command_path)
{
    if (nc_human()) {
        char human[ZCL_COMMAND_LIST_BUDGET + 1];
        size_t hn = zcl_cli_render_doc(doc, strlen(doc), command_path,
                                       nc_render_env(), human,
                                       sizeof(human));
        if (hn > 0) {
            fputs(human, stdout);
            return;
        }
    }
    printf("%s\n", doc);
}

/* Build the `error` object (code/message/phase/blockers/next_action). */
static void nc_print_error_build_error(const char *code, const char *phase,
                                       const char *message,
                                       const char *evidence,
                                       const char *next_reason,
                                       struct json_value *error)
{
    struct json_value blockers;
    json_init(&blockers);
    json_set_array(&blockers);
    (void)json_push_kv_str(error, "code", code);
    (void)json_push_kv_str(error, "error_code", code);
    (void)json_push_kv_str(error, "message", message);
    (void)json_push_kv_str(error, "phase", phase);
    (void)json_push_kv_str(error, "current_state", "REQUEST_FAILED");
    (void)json_push_kv_bool(error, "retryable", false);
    (void)json_push_kv_bool(error, "human_action_required", true);
    (void)json_push_kv_str(error, "next_action",
                           next_reason && next_reason[0]
                               ? next_reason
                               : "follow the first next command");
    (void)json_push_kv_bool(error, "mutated", false);
    if (evidence && evidence[0])
        (void)json_push_kv_str(error, "evidence", evidence);
    (void)json_push_kv(error, "blockers", &blockers);
    json_free(&blockers);
}

/* Append the single valid next-action entry (if any) to `next`. */
static void nc_print_error_build_next(const char *command,
                                      const char *next_command,
                                      const char *next_input,
                                      const char *next_reason,
                                      struct json_value *next,
                                      struct json_value *item)
{
    if (next_command && next_command[0]) {
        struct json_value parsed;
        if (next_input && next_input[0] &&
            json_read(&parsed, next_input, strlen(next_input)) &&
            parsed.type == JSON_OBJ &&
            nc_next_input_valid(command, next_command, &parsed)) {
            (void)json_push_kv_str(item, "command", next_command);
            (void)json_push_kv(item, "input", &parsed);
            (void)json_push_kv_str(item, "reason",
                                   next_reason ? next_reason : "");
            (void)json_push_back(next, item);
        }
        json_free(&parsed);
    }
}

static void nc_print_error(const char *command, const char *code,
                           const char *phase, const char *message,
                           const char *evidence,
                           const char *next_command,
                           const char *next_input, const char *next_reason)
{
    struct json_value root, error, next, item;
    json_init(&root);
    json_init(&error);
    json_init(&next);
    json_init(&item);
    json_set_object(&root);
    json_set_object(&error);
    json_set_array(&next);
    json_set_object(&item);

    (void)json_push_kv_str(&root, "schema", "zcl.result.v1");
    (void)json_push_kv_str(&root, "command", command ? command : "");
    (void)json_push_kv_bool(&root, "ok", false);
    (void)json_push_kv_str(&root, "status", "failed");
    (void)json_push_kv_str(&root, "request_id", "local-cli");
    (void)json_push_kv_int(&root, "elapsed_us", 0);
    nc_print_error_build_error(code, phase, message, evidence, next_reason,
                               &error);
    (void)json_push_kv(&root, "error", &error);
    nc_print_error_build_next(command, next_command, next_input, next_reason,
                              &next, &item);
    (void)json_push_kv(&root, "next", &next);

    char out[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = json_write(&root, out, sizeof(out));
    if (n == 0 || n >= sizeof(out))
        (void)snprintf(out, sizeof(out),
                       "{\"schema\":\"zcl.result.v1\",\"ok\":false,"
                       "\"status\":\"failed\",\"error\":{\"code\":\"%s\","
                       "\"error_code\":\"%s\",\"current_state\":\"REQUEST_FAILED\","
                       "\"retryable\":false,\"human_action_required\":true,"
                       "\"next_action\":\"inspect the command contract\"}}",
                       code, code);
    nc_print_doc(out, command);
    json_free(&item);
    json_free(&next);
    json_free(&error);
    json_free(&root);
}

static void nc_print_error_next_string(
    const char *command, const char *code, const char *phase,
    const char *message, const char *evidence, const char *next_command,
    const char *next_key, const char *next_value, const char *next_reason)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    char encoded[512];
    bool ok = next_key && next_value &&
              json_push_kv_str(&input, next_key, next_value);
    size_t n = ok ? json_write(&input, encoded, sizeof(encoded)) : 0;
    json_free(&input);
    nc_print_error(command, code, phase, message, evidence,
                   n > 0 && n < sizeof(encoded) ? next_command : NULL,
                   n > 0 && n < sizeof(encoded) ? encoded : NULL,
                   next_reason);
}

/* Print a branch menu. Returns a contract exit code. */
static int nc_emit_menu(const char *path)
{
    char out[ZCL_COMMAND_BRANCH_BUDGET + 1];
    size_t n = zcl_command_registry_menu_json(catalog(), path, out,
                                              sizeof(out));
    if (n == 0) {
        nc_print_error_next_string(
            path, "MENU_BUDGET", "serialize",
            "menu exceeded its byte budget", path, "discover.describe",
            "path", path, "inspect this branch contract");
        return ZCL_COMMAND_EXIT_INTERNAL;
    }
    nc_print_doc(out, path);
    return ZCL_COMMAND_EXIT_OK;
}

/* Handle the four discovery leaves by rendering the native document directly. */
/* The discover.schema branch: bind a synthetic request, dispatch through the
 * ordinary handler, and copy its rendered body out. Returns false (having
 * already printed the error) when the path does not resolve. */
static bool nc_run_discover_schema(const struct zcl_command_spec *spec,
                                   const char *arg, const char *side,
                                   char *out, size_t out_cap, size_t *n_out)
{
    struct zcl_command_request req = { 0 };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "path", arg ? arg : "");
    if (side)
        (void)json_push_kv_str(&input, "side", side);
    req.spec = spec;
    req.input = &input;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, spec->output_schema);
    zcl_native_handle_discover_schema(&req, &reply);
    (void)json_push_kv_str(&reply.data, "schema", "zcl.command_schema.v1");
    *n_out = json_write(&reply.data, out, out_cap);
    if (reply.exit_code != ZCL_COMMAND_EXIT_OK) {
        nc_print_error(spec->path, "UNKNOWN_PATH", "resolve",
                       "no such command path", arg ? arg : "",
                       "discover.help", "{}", "browse the tree first");
        zcl_command_reply_free(&reply);
        json_free(&input);
        return false;
    }
    zcl_command_reply_free(&reply);
    json_free(&input);
    return true;
}

/* "The answer did not fit" is NOT "there is no such command". describe_json
 * returns 0 for both, and reporting the second for the first cost
 * core.wallet.recovery.restore its entire written contract: the leaf
 * dispatched fine, help and search both listed it, and `discover describe`
 * on it answered UNKNOWN_PATH. Resolve the path ourselves so the two can be
 * told apart — same shape as nc_emit_menu's MENU_BUDGET. check-describe-budget
 * keeps every leaf under the budget; this is what the operator sees if one
 * ever gets through. */
static int nc_run_discover_empty(const struct zcl_command_spec *spec,
                                 const char *arg)
{
    if (strcmp(spec->path, "discover.describe") == 0) {
        if (zcl_command_registry_find(catalog(), arg, NULL)) {
            nc_print_error_next_string(
                spec->path, "DESCRIBE_BUDGET", "serialize",
                "this command's describe document exceeded its byte "
                "budget, so it could not be rendered; the command itself "
                "is registered and callable",
                arg, "discover.schema", "path", arg,
                "read this command's input keys instead");
            return ZCL_COMMAND_EXIT_INTERNAL;
        }
        nc_print_error(spec->path, "UNKNOWN_PATH", "resolve",
                       "no such command path", arg ? arg : "",
                       "discover.help", "{}",
                       "browse the tree first");
    } else {
        nc_print_error_next_string(
            spec->path, "UNKNOWN_PATH", "resolve",
            "no such command path or budget exceeded", arg ? arg : "",
            "discover.describe", "path", spec->path,
            "inspect this discovery command");
    }
    return ZCL_COMMAND_EXIT_INVALID;
}

static int nc_run_discover(const struct zcl_command_spec *spec,
                           const char *arg, const char *side)
{
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t n = 0;
    if (strcmp(spec->path, "discover.help") == 0) {
        n = zcl_command_registry_menu_json(catalog(), arg ? arg : "", out,
                                           sizeof(out));
    } else if (strcmp(spec->path, "discover.describe") == 0) {
        if (!arg || !arg[0]) {
            nc_print_error(spec->path, "MISSING_PATH", "normalize",
                           "describe requires a command path", "",
                           "discover.help", "{}", "browse the tree first");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        n = zcl_command_registry_describe_json(catalog(), arg, out,
                                               sizeof(out));
    } else if (strcmp(spec->path, "discover.search") == 0) {
        if (!arg || !arg[0]) {
            nc_print_error(spec->path, "MISSING_QUERY", "normalize",
                           "search requires a query", "", "discover.help",
                           "{}", "browse the tree first");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        n = zcl_command_registry_search_json(catalog(), arg, out,
                                             sizeof(out));
    } else { /* discover.schema */
        if (!nc_run_discover_schema(spec, arg, side, out, sizeof(out), &n))
            return ZCL_COMMAND_EXIT_INVALID;
    }
    if (n == 0)
        return nc_run_discover_empty(spec, arg);
    nc_print_doc(out, spec->path);
    return ZCL_COMMAND_EXIT_OK;
}

/* ── CLI UX contract: ONE-LINE status brief ──────────────────────────
 * See docs/NATIVE_COMMAND_INTERFACE.md "CLI UX contract". Exactly one line
 * (<=200 bytes), stable `key=value` pairs separated by single spaces, no
 * JSON braces. Reads only the flat fields core.status.brief already computed
 * (zcl_native_status_brief_body) — the render and the field selector below
 * both read this one JSON object; neither builds a second data path. */
static void nc_kv_int_or_unknown(char *buf, size_t cap, size_t *len,
                                 const char *key, const struct json_value *v)
{
    int n;
    if (v && v->type == JSON_INT)
        n = snprintf(buf + *len, cap - *len, "%s=%lld ", key,
                     (long long)json_get_int(v));
    else
        n = snprintf(buf + *len, cap - *len, "%s=unknown ", key);
    if (n > 0 && (size_t)n < cap - *len)
        *len += (size_t)n;
}

/* Exposed (non-static) so test_operator_ux can drive it with a fabricated
 * brief body and assert each key=value pair renders. */
/* Typed-blocker-registry count + head, from the same authority as `dumpstate
 * blocker`, shown beside the headline `blocker=` so the two operator
 * surfaces can never name disjoint truths. Rendered only when the node
 * exports them (older nodes omit the fields; a missing field must not
 * fabricate a zero — see the sparse-body contract test). */
static void nc_brief_render_blocker(const struct json_value *d, char *buf,
                                    size_t cap, size_t *len_io)
{
    size_t len = *len_io;
    int n;
    const struct json_value *nblk = json_get(d, "active_blockers");
    if (nblk && nblk->type == JSON_INT) {
        n = snprintf(buf + len, cap - len, "blockers=%lld ",
                     (long long)json_get_int(nblk));
        if (n > 0 && (size_t)n < cap - len) len += (size_t)n;
    }
    const char *bhead = json_get_str(json_get(d, "blocker_head"));
    if (bhead && bhead[0]) {
        n = snprintf(buf + len, cap - len, "blocker_head=%s ", bhead);
        if (n > 0 && (size_t)n < cap - len) len += (size_t)n;
    }
    const struct json_value *bage = json_get(d, "blocker_age_s");
    if (bage && bage->type == JSON_INT)
        n = snprintf(buf + len, cap - len, "blocker_age=%llds ",
                    (long long)json_get_int(bage));
    else
        n = snprintf(buf + len, cap - len, "blocker_age=unknown ");
    if (n > 0 && (size_t)n < cap - len) len += (size_t)n;
    *len_io = len;
}

/* Every field above but the last appends its own trailing separator space;
 * trim it defensively (also covers a mid-line snprintf that hit the buffer
 * edge). Then hard-clamp to the 200-byte contract — real fields never get
 * near this, but the CLI must never emit a line the spec forbids. */
static void nc_brief_clamp(char *buf, size_t len)
{
    if (len > 0 && buf[len - 1] == ' ')
        buf[--len] = '\0';
    if (len > 200) {
        /* Clamp at the last space inside the 200-byte contract so the
         * line never ends mid-token; the hard clamp is the fallback when
         * no space exists. */
        size_t cut = 200;
        while (cut > 0 && buf[cut - 1] != ' ')
            cut--;
        if (cut > 0)
            buf[cut - 1] = '\0';
        else
            buf[200] = '\0';
    }
}

void zcl_native_status_brief_render(const struct json_value *d, char *buf,
                                    size_t cap)
{
    if (!buf || cap == 0)
        return;
    buf[0] = '\0';
    size_t len = 0;

    nc_kv_int_or_unknown(buf, cap, &len, "hstar", json_get(d, "hstar"));
    nc_kv_int_or_unknown(buf, cap, &len, "gap", json_get(d, "gap"));
    nc_kv_int_or_unknown(buf, cap, &len, "peer_best", json_get(d, "peer_best"));

    const char *sync_state = json_get_str(json_get(d, "sync_state"));
    int n = snprintf(buf + len, cap - len, "sync=%s ",
                     (sync_state && sync_state[0]) ? sync_state : "unknown");
    if (n > 0 && (size_t)n < cap - len) len += (size_t)n;

    const char *blocker = json_get_str(json_get(d, "primary_blocker"));
    n = snprintf(buf + len, cap - len, "blocker=%s ",
                (blocker && blocker[0]) ? blocker : "unknown");
    if (n > 0 && (size_t)n < cap - len) len += (size_t)n;

    nc_brief_render_blocker(d, buf, cap, &len);

    nc_kv_int_or_unknown(buf, cap, &len, "conditions",
                        json_get(d, "active_conditions"));
    nc_kv_int_or_unknown(buf, cap, &len, "peers", json_get(d, "peer_count"));

    const struct json_value *rss = json_get(d, "rss_mb");
    if (rss && rss->type == JSON_INT)
        n = snprintf(buf + len, cap - len, "rss_mb=%lld",
                    (long long)json_get_int(rss));
    else
        n = snprintf(buf + len, cap - len, "rss_mb=unknown");
    if (n > 0 && (size_t)n < cap - len) len += (size_t)n;

    nc_brief_clamp(buf, len);
}

/* Root money-journey status has a different contract from the chain brief.
 * Keep its default rendering equally bounded and scannable, but name the
 * questions a user is actually asking before a payment. */
static const char *nc_bool_answer(const struct json_value *d, const char *key,
                                  const char *yes, const char *no)
{
    const struct json_value *v = d ? json_get(d, key) : NULL;
    return v && v->type == JSON_BOOL
        ? (json_get_bool(v) ? yes : no) : "unknown";
}

static void nc_status_journey_text(const char *src, char *dst, size_t cap,
                                   const char *oversized)
{
    if (!dst || cap == 0)
        return;
    if (!src || !src[0]) {
        (void)snprintf(dst, cap, "unknown");
        return;
    }
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) {
        unsigned char ch = (unsigned char)src[i];
        dst[i] = ch == '\n' || ch == '\r' || ch == '\t'
            ? ' ' : (ch < 0x20 || ch == 0x7f ? '?' : (char)ch);
    }
    if (src[i]) {
        (void)snprintf(dst, cap, "%s", oversized);
        return;
    }
    dst[i] = '\0';
}

/* A named primary blocker outranks a bare RPC error code as the reported
 * blocker text. */
static const char *nc_journey_blocker_field(const struct json_value *d)
{
    const char *primary = d
        ? json_get_str(json_get(d, "primary_blocker")) : NULL;
    const char *error_code = d
        ? json_get_str(json_get(d, "error_code")) : NULL;
    return primary && primary[0] &&
                  strcmp(primary, "none") != 0 &&
                  strcmp(primary, "unknown") != 0
        ? primary : error_code;
}

/* Renders an integer zat amount field, leaving `out` at its "unknown"
 * default when the field is absent or not an int. */
static void nc_journey_amount_text(const struct json_value *v, char *out,
                                   size_t cap)
{
    if (v && v->type == JSON_INT)
        (void)snprintf(out, cap, "%lld", (long long)json_get_int(v));
}

void zcl_native_status_journey_render(const struct json_value *d, char *buf,
                                      size_t cap)
{
    if (!buf || cap == 0)
        return;
    const char *blocker = nc_journey_blocker_field(d);
    const struct json_value *spendable = d
        ? json_get(d, "spendable_zat") : NULL;
    const struct json_value *pending = d ? json_get(d, "pending_zat") : NULL;
    const struct json_value *reserved = d
        ? json_get(d, "reserved_zat") : NULL;
    const char *next_action = d
        ? json_get_str(json_get(d, "next_action")) : NULL;
    char spendable_text[32] = "unknown";
    char pending_text[32] = "unknown";
    char reserved_text[32] = "unknown";
    char blocker_text[48] = "unknown";
    char next_action_text[80] = "unknown";
    nc_journey_amount_text(spendable, spendable_text, sizeof(spendable_text));
    nc_journey_amount_text(pending, pending_text, sizeof(pending_text));
    nc_journey_amount_text(reserved, reserved_text, sizeof(reserved_text));
    nc_status_journey_text(blocker, blocker_text, sizeof(blocker_text),
                           "status_detail_too_long");
    nc_status_journey_text(next_action, next_action_text,
                           sizeof(next_action_text),
                           "z23 status --format=json");
    char line[321];
    int n = snprintf(
        line, sizeof(line),
        "node=%s synced=%s wallet=%s receive=%s send=%s "
        "spendable_zat=%s pending_zat=%s reserved_zat=%s blocker=%s "
        "next_action=%s",
        nc_bool_answer(d, "node_healthy", "healthy", "blocked"),
        nc_bool_answer(d, "synced", "yes", "no"),
        nc_bool_answer(d, "wallet_ready", "ready", "not_ready"),
        nc_bool_answer(d, "can_receive", "yes", "no"),
        nc_bool_answer(d, "can_send", "yes", "no"),
        spendable_text, pending_text, reserved_text,
        blocker_text, next_action_text);
    if (n < 0 || (size_t)n >= sizeof(line))
        (void)snprintf(line, sizeof(line),
                       "node=blocked blocker=status_render_overflow "
                       "next_action=%s", next_action_text);
    (void)snprintf(buf, cap, "%s", line);
}

/* Pick one short, deterministic next step from the same brief body: a named
 * blocker outranks "still behind" outranks the native health leaf. Never
 * allocates. */
const char *zcl_native_status_brief_next_command(const struct json_value *d)
{
    const char *blocker = json_get_str(json_get(d, "primary_blocker"));
    if (blocker && blocker[0] && strcmp(blocker, "none") != 0 &&
        strcmp(blocker, "unknown") != 0)
        return "z23 explain blockers";
    const struct json_value *gapv = json_get(d, "gap");
    if (gapv && gapv->type == JSON_INT && json_get_int(gapv) > 0)
        return "z23 explain sync";
    return "z23 ops health";
}

/* ── CLI UX contract: field selector ─────────────────────────────────
 * See docs/NATIVE_COMMAND_INTERFACE.md "CLI UX contract". `status field=` and
 * `dumpstate <subsystem> field=` both call this one function — neither
 * hand-rolls its own key lookup. */
enum { NC_FIELD_MAX = 24, NC_FIELD_NAME_MAX = 65 };

/* Parse "a, b, c" into up to NC_FIELD_MAX distinct, trimmed field names. */
/* Scan the next comma-separated, space-trimmed token starting at `*p_io`.
 * Returns false when no token remains (end of string). */
static bool nc_field_next_token(const char **p_io, const char **start_out,
                                size_t *flen_out)
{
    const char *p = *p_io;
    while (*p == ' ' || *p == ',') p++;
    if (!*p) {
        *p_io = p;
        return false;
    }
    const char *start = p;
    while (*p && *p != ',') p++;
    const char *end = p;
    while (end > start && end[-1] == ' ') end--;
    *start_out = start;
    *flen_out = (size_t)(end - start);
    *p_io = p;
    return true;
}

static bool nc_field_is_duplicate(
    char names[NC_FIELD_MAX][NC_FIELD_NAME_MAX], size_t nnames,
    const char *candidate)
{
    for (size_t j = 0; j < nnames; j++) {
        if (strcmp(names[j], candidate) == 0)
            return true;
    }
    return false;
}

static bool nc_field_parse_names(const char *fields_csv,
                                 char names[NC_FIELD_MAX][NC_FIELD_NAME_MAX],
                                 size_t *nnames_out, char *err, size_t err_cap)
{
    size_t nnames = 0;
    const char *p = fields_csv;
    const char *start;
    size_t flen;
    while (nc_field_next_token(&p, &start, &flen)) {
        if (flen == 0 || flen >= NC_FIELD_NAME_MAX) {
            if (err) snprintf(err, err_cap,
                             "malformed field name in 'field=%s'", fields_csv);
            return false;
        }
        if (nnames >= NC_FIELD_MAX) {
            if (err) snprintf(err, err_cap,
                             "too many fields requested (max %d)",
                             NC_FIELD_MAX);
            return false;
        }
        memcpy(names[nnames], start, flen);
        names[nnames][flen] = '\0';
        if (nc_field_is_duplicate(names, nnames, names[nnames])) {
            if (err) snprintf(err, err_cap, "duplicate field '%s'",
                             names[nnames]);
            return false;
        }
        nnames++;
    }
    if (nnames == 0) {
        if (err) snprintf(err, err_cap, "field= requires at least one name");
        return false;
    }
    *nnames_out = nnames;
    return true;
}

/* Validate every requested name exists before rendering anything — never a
 * partial selection. */
static bool nc_field_validate_names(
    const struct json_value *obj,
    char names[NC_FIELD_MAX][NC_FIELD_NAME_MAX], size_t nnames, char *err,
    size_t err_cap)
{
    for (size_t i = 0; i < nnames; i++) {
        if (json_get(obj, names[i]))
            continue;
        char known[320];
        size_t klen = 0;
        known[0] = '\0';
        for (size_t k = 0; k < obj->num_children && k < 16; k++) {
            int n = snprintf(known + klen, sizeof(known) - klen, "%s%s",
                             klen ? "," : "", obj->keys[k]);
            if (n > 0 && (size_t)n < sizeof(known) - klen)
                klen += (size_t)n;
        }
        if (err)
            snprintf(err, err_cap, "no such field '%s'; known: %s", names[i],
                     known);
        return false;
    }
    return true;
}

/* Render one field's value as key=value text. json_write returns the bytes
 * NEEDED — >= cap means the value was cut mid-string. Never emit a
 * truncated container: fail typed so the caller reaches for --format=json
 * instead. */
static bool nc_field_format_value(const struct json_value *v, char *valbuf,
                                  size_t valbuf_cap, const char *name,
                                  char *err, size_t err_cap)
{
    switch (v->type) {
    case JSON_BOOL:
        snprintf(valbuf, valbuf_cap, "%s",
                json_get_bool(v) ? "true" : "false");
        break;
    case JSON_INT:
        snprintf(valbuf, valbuf_cap, "%lld", (long long)json_get_int(v));
        break;
    case JSON_REAL:
        snprintf(valbuf, valbuf_cap, "%g", json_get_real(v));
        break;
    case JSON_STR: {
        const char *s = json_get_str(v);
        snprintf(valbuf, valbuf_cap, "%s", s ? s : "");
        break;
    }
    case JSON_NULL:
        snprintf(valbuf, valbuf_cap, "null");
        break;
    case JSON_ARR:
    case JSON_OBJ:
    default: {
        size_t need = json_write(v, valbuf, valbuf_cap);
        if (need >= valbuf_cap) {
            if (err)
                snprintf(err, err_cap,
                         "field '%s' is a %zu-byte container — too large "
                         "for key=value rendering; use --format=json",
                         name, need);
            return false;
        }
        break;
    }
    }
    return true;
}

/* Render every validated field as "name=value\n" into `out`, in order. */
static bool nc_field_render_all(
    const struct json_value *obj,
    char names[NC_FIELD_MAX][NC_FIELD_NAME_MAX], size_t nnames, char *out,
    size_t out_cap, char *err, size_t err_cap)
{
    size_t len = 0;
    for (size_t i = 0; i < nnames; i++) {
        const struct json_value *v = json_get(obj, names[i]);
        char valbuf[4096];
        if (!nc_field_format_value(v, valbuf, sizeof(valbuf), names[i], err,
                                   err_cap))
            return false;
        int n = snprintf(out + len, out_cap - len, "%s=%s\n", names[i],
                         valbuf);
        if (n <= 0 || (size_t)n >= out_cap - len) {
            if (err) snprintf(err, err_cap,
                             "field selection exceeded the output buffer");
            return false;
        }
        len += (size_t)n;
    }
    return true;
}

bool zcl_native_render_field_selection(const struct json_value *obj,
                                       const char *fields_csv,
                                       char *out, size_t out_cap,
                                       char *err, size_t err_cap)
{
    if (err && err_cap)
        err[0] = '\0';
    if (!obj || obj->type != JSON_OBJ) {
        if (err) snprintf(err, err_cap, "nothing to select fields from");
        return false;
    }
    if (!fields_csv || !fields_csv[0]) {
        if (err) snprintf(err, err_cap, "field= requires at least one name");
        return false;
    }

    char names[NC_FIELD_MAX][NC_FIELD_NAME_MAX];
    size_t nnames;
    if (!nc_field_parse_names(fields_csv, names, &nnames, err, err_cap))
        return false;
    if (!nc_field_validate_names(obj, names, nnames, err, err_cap))
        return false;
    return nc_field_render_all(obj, names, nnames, out, out_cap, err,
                               err_cap);
}

/* ── shared field validators ──────────────────────────────────────────
 * One place for the "exactly 64 lowercase hex characters" contract that
 * every DHT root, receipt id, and other 32-byte content-addressed key in
 * this tree shares, so every command names the field and states the same
 * shape instead of a dozen near-identical hand-rolled sentences. */
bool zcl_native_require_hex64(const char *field, const char *value,
                              uint8_t out[32], char *err, size_t err_size)
{
    uint8_t scratch[32];
    if (value && zcl_hex_decode_lower(value, out ? out : scratch, 32))
        return true;
    if (err && err_size)
        snprintf(err, err_size,
                "%s must be 64 lowercase hex characters, e.g. 3f9a... "
                "(32 bytes hex-encoded)",
                field && field[0] ? field : "value");
    return false;
}

/* ── CLI UX contract: unrecognized-command diagnostic ────────────────
 * See docs/NATIVE_COMMAND_INTERFACE.md "CLI UX contract". Pure text
 * builder — engine/entry/main.c's raw-RPC fallback calls this once it has confirmed
 * (via the RPC layer's method-not-found response) that `method` is not a
 * real command, then fprintf's the result to stderr. */
/* Append "did you mean: <path> <path> ...\n" from a search-json `matches`
 * array. */
static void nc_render_did_you_mean(const struct json_value *matches,
                                   char *out, size_t out_cap, size_t *len_io)
{
    size_t len = *len_io;
    int n = snprintf(out + len, out_cap - len, "did you mean:");
    if (n <= 0 || (size_t)n >= out_cap - len) {
        *len_io = len;
        return;
    }
    len += (size_t)n;
    for (size_t i = 0; i < matches->num_children && i < 3; i++) {
        const char *path = json_get_str(
            json_get(&matches->children[i], "path"));
        if (!path || !path[0])
            continue;
        n = snprintf(out + len, out_cap - len, " %s", path);
        if (n > 0 && (size_t)n < out_cap - len)
            len += (size_t)n;
    }
    n = snprintf(out + len, out_cap - len, "\n");
    if (n > 0 && (size_t)n < out_cap - len)
        len += (size_t)n;
    *len_io = len;
}

size_t zcl_native_render_unknown_command(
    const struct zcl_command_registry *reg, const char *method, char *out,
    size_t out_cap)
{
    if (!out || out_cap == 0 || !method || !method[0])
        return 0;
    out[0] = '\0';
    size_t len = 0;
    int n = snprintf(out + len, out_cap - len,
                     "error=UNKNOWN_COMMAND detail=no such command '%s' "
                     "try=z23 discover search %s\n",
                     method, method);
    if (n <= 0 || (size_t)n >= out_cap - len)
        return 0;
    len += (size_t)n;

    if (!reg)
        return len;
    char buf[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t bn = zcl_command_registry_search_json(reg, method, buf,
                                                 sizeof(buf));
    if (bn == 0)
        return len;
    struct json_value doc;
    if (!json_read(&doc, buf, bn) || doc.type != JSON_OBJ) {
        json_free(&doc);
        return len;
    }
    const struct json_value *matches = json_get(&doc, "matches");
    if (matches && matches->type == JSON_ARR && matches->num_children > 0)
        nc_render_did_you_mean(matches, out, out_cap, &len);
    json_free(&doc);
    return len;
}

/* Render the prose text for a prose leaf into `buf`. Returns true if a text
 * block was produced; false means the caller should print the JSON envelope
 * (e.g. an error result with no data.text). `data` is the envelope's `data`. */
static bool nc_prose_text(const char *path, const struct json_value *data,
                          char *buf, size_t cap)
{
    if (!data || data->type != JSON_OBJ)
        return false;
    const char *text = json_get_str(json_get(data, "text"));
    if (text && text[0]) {
        (void)snprintf(buf, cap, "%s", text);
        return true;
    }
    if (strcmp(path, "status") == 0) {
        zcl_native_status_journey_render(data, buf, cap);
        return true;
    }
    if (strcmp(path, "core.status.brief") == 0) {
        zcl_native_status_brief_render(data, buf, cap);
        return true;
    }
    return false;
}

const char *zcl_native_agent_session_env(void)
{
    const char *s = getenv("ZCL_AGENT_SESSION");
    return (s && s[0]) ? s : NULL;
}

/* ── zcl_native_command_main decomposition ──────────────────────────────
 * The one-shot CLI entry point below is a strict sequence of phases: boot
 * the process-local state, resolve the word list to a leaf, parse its
 * flags, build/validate its input, execute it, then render the result.
 * Each phase is pulled out as a named helper below so the top-level
 * function reads as that sequence; every helper keeps the exact control
 * flow (order, early returns, frees) of the code it replaces. */
struct nc_main_state {
    /* resolve */
    char root_split[ZCL_COMMAND_MAX_PATH];
    const char *words[NC_MAX_WORDS];
    size_t count;
    size_t consumed;
    bool was_alias;
    char invoked[ZCL_COMMAND_MAX_PATH];
    const struct zcl_command_spec *spec;

    /* flags */
    struct json_value flags;
    const char *positional[NC_MAX_WORDS];
    size_t npos;
    const char *input_flag;
    const char *view;
    const char *side;
    const char *cursor;
    char input_cursor[64];
    size_t budget;
    size_t max_items;
    bool seen_input, seen_view, seen_side, seen_budget, seen_max_items,
        seen_cursor, seen_format, seen_field;
    const char *field_csv;
    bool suggest_next;

    /* input */
    struct json_value input;
};

/* NC_MAIN_CONTINUE is not a valid zcl_command_exit value (those are all
 * >= 0); it signals "no early return, proceed" from a boot-phase helper. */
enum { NC_MAIN_CONTINUE = -1 };

/* Process-local boot: select the chain, bind the RPC bridge, validate the
 * registry, and (dev builds only) apply a ZCL_HOTSWAP_PRELOAD override. */
static int nc_main_bootstrap(const char *root_word, const char *datadir,
                             int rpc_port, enum chain_network network,
                             bool datadir_explicit,
                             const struct zcl_command_registry **reg_out)
{
    g_native_network = network;
    g_native_datadir_explicit = datadir_explicit;
    chain_params_select(network);
    zcl_native_bridge_bind_rpc(datadir, rpc_port);
    /* Stamp the resident half of the hot-swappable package-policy surface
     * BEFORE any module .so can be dlopen'd below. The swappable leaf reports
     * this flag: a generation that had cloned the state would answer false. */
    zcl_native_policy_resident_mark_boot();

    const struct zcl_command_registry *reg = catalog();
    char why[128];
    if (!zcl_command_registry_validate(reg, why, sizeof(why))) {
        nc_print_error(root_word, "REGISTRY_INVALID", "startup", why, "",
                       "", "", "");
        return ZCL_COMMAND_EXIT_INTERNAL;
    }

#ifdef ZCL_DEV_BUILD
    /* ZCL_HOTSWAP_PRELOAD=<module.so> — process-local hot-swap: install the
     * module's ENTIRE leaf set in THIS throwaway CLI's registry as one
     * all-or-nothing batch, then dispatch normally, so the operator sees the
     * freshly compiled bodies with no resident restart. Probe-class authority
     * (hotswap_activate_local): path confinement, the dev-datadir check, the
     * admit gauntlet, and probe-before-publish all apply, and the registry
     * commit re-checks READY + EFFECT_READ. The overrides die with the
     * process. The hooks are the ONE shared implementation in
     * tools/command/native_dev_hotswap.c. */
    const char *hotswap_preload = getenv("ZCL_HOTSWAP_PRELOAD");
    if (hotswap_preload && hotswap_preload[0]) {
        zcl_command_registry_set_active(reg);
        struct hotswap_publish_hooks preload_hooks;
        zcl_native_hotswap_publish_hooks(&preload_hooks, /*with_quiesce=*/false);
        struct hotswap_activate_report report;
        if (!hotswap_activate_local(hotswap_preload, g_bridge_datadir,
                                    &preload_hooks, &report)) {
            nc_print_error("dev.hotswap.preload", "HOTSWAP_REFUSED",
                           report.stage[0] ? report.stage : "activate",
                           report.error[0] ? report.error
                                           : "hot-swap preload refused",
                           hotswap_preload, "", "", "");
            return ZCL_COMMAND_EXIT_BLOCKED;
        }
    }
#endif /* ZCL_DEV_BUILD */

    *reg_out = reg;
    return NC_MAIN_CONTINUE;
}

/* Word list = root + args (flags included). Resolution stops at the first
 * flag or dotted/pathy word — so a dotted FIRST token (the canonical
 * `zcode.science.study.list` form the docs and examples use) is split
 * into path segments here, making it identical to the spaced form.
 * `st->root_split` backs every pointer this stores into st->words, so it
 * must stay alive exactly as long as st does. */
static const struct zcl_command_spec *nc_main_resolve(
    const struct zcl_command_registry *reg, const char *root_word,
    const char *const *args, int nargs, struct nc_main_state *st, int *rc)
{
    st->count = 0;
    if (strchr(root_word, '.')) {
        size_t rl = strlen(root_word);
        if (rl >= sizeof(st->root_split)) {
            nc_print_error(root_word, "UNKNOWN_COMMAND", "resolve",
                           "command path too long", root_word,
                           "", "", "");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return NULL;
        }
        memcpy(st->root_split, root_word, rl + 1);
        char *seg = st->root_split;
        while (seg && *seg && st->count < NC_MAX_WORDS) {
            char *dot = strchr(seg, '.');
            if (dot)
                *dot = 0;
            st->words[st->count++] = seg;
            seg = dot ? dot + 1 : NULL;
        }
    } else {
        st->words[st->count++] = root_word;
    }
    for (int i = 0; i < nargs && st->count < NC_MAX_WORDS; i++)
        st->words[st->count++] = args[i];

    st->was_alias = false;
    const struct zcl_command_spec *spec = zcl_command_registry_resolve_words(
        reg, st->words, st->count, &st->consumed, &st->was_alias, st->invoked,
        sizeof(st->invoked));
    if (!spec) {
        nc_print_error_next_string(
            root_word, "UNKNOWN_COMMAND", "resolve", "unknown command root",
            root_word, "discover.search", "query", root_word,
            "search for the intended command");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return NULL;
    }
    return spec;
}

/* ops.rom watch mode and the dev-build-only CLI transports each intercept
 * dispatch for one exact leaf path before the ordinary flag parser runs
 * (ops.debug.rom takes empty input, so its --watch/--once/--interval flags
 * would otherwise be rejected as unknown keys). Order matches the leaf
 * checks this replaces exactly: ops.rom first, then (dev builds only)
 * events, retrieval, and train. */
static bool nc_main_try_intercepts(const struct zcl_command_spec *spec,
                                   const char *const *words, size_t count,
                                   size_t consumed, const char *datadir,
                                   int *rc)
{
    if (strcmp(spec->path, "ops.debug.rom") == 0 &&
        nc_ops_rom_try_watch(words, count, consumed, datadir, rc))
        return true;
#ifdef ZCL_DEV_BUILD
    if (strcmp(spec->path, "dev.loop.events") == 0 &&
        nc_dev_events_try_stream(words, count, consumed, rc))
        return true;
    if (strcmp(spec->path, "dev.retrieval.benchmark") == 0 &&
        nc_dev_retrieval_try_stream(spec, words, count, consumed, rc))
        return true;
    if (strncmp(spec->path, "dev.train.", 10) == 0 &&
        zcl_native_dev_train_cli(spec, words, count, consumed, rc))
        return true;
#endif
    return false;
}

enum nc_main_flag_result {
    NC_FLAG_OK,
    NC_FLAG_BAD,
    NC_FLAG_UNMATCHED,
};

static bool nc_main_flag_input_bad(bool seen, const char *value)
{
    return seen || !value || !value[0];
}

static bool nc_main_flag_view_bad(bool seen, const char *value)
{
    return seen || !value ||
           (strcmp(value, "summary") != 0 && strcmp(value, "normal") != 0 &&
            strcmp(value, "full") != 0);
}

static bool nc_main_flag_side_bad(bool seen, const char *value)
{
    return seen || !value ||
           (strcmp(value, "input") != 0 && strcmp(value, "output") != 0);
}

static bool nc_main_flag_cursor_bad(bool seen, const char *value)
{
    return seen || !value || !value[0] || strlen(value) > 256;
}

static bool nc_main_flag_json_bad(bool seen, const char *value)
{
    return seen || value;
}

static bool nc_main_flag_format_bad(bool seen, const char *value)
{
    return seen || !value || strcmp(value, "json") != 0;
}

static bool nc_main_flag_field_bad(bool seen, const char *value)
{
    return seen || !value || !value[0];
}

/* Handle one non-flag word: `field=value` (either spelling of the field
 * selector) or a bare positional. Returning false means field= was
 * malformed; *why already carries the message and the caller stops the
 * loop, matching the original inline check exactly. */
static bool nc_main_parse_bare_word(const char *w, struct nc_main_state *st,
                                    char *why, size_t why_cap)
{
    if (strncmp(w, "field=", 6) == 0) {
        if (st->seen_field || !w[6]) {
            (void)snprintf(why, why_cap,
                          "field= requires one non-empty value and "
                          "may appear once");
            return false;
        }
        st->seen_field = true;
        st->field_csv = w + 6;
        return true;
    }
    if (st->npos < NC_MAX_WORDS)
        st->positional[st->npos++] = w;
    return true;
}

/* --input / --view / --side / --budget-bytes / --max-items: the flags that
 * only accept one value out of a known-good set and remember it in *st. */
static enum nc_main_flag_result nc_main_apply_flag_group1(
    const char *flag_key, const char *value, struct nc_main_state *st,
    char *why, size_t why_cap)
{
    if (strcmp(flag_key, "input") == 0) {
        if (nc_main_flag_input_bad(st->seen_input, value)) {
            (void)snprintf(why, why_cap,
                           "--input requires one non-empty value and may appear once");
            return NC_FLAG_BAD;
        }
        st->seen_input = true;
        st->input_flag = value;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "view") == 0) {
        if (nc_main_flag_view_bad(st->seen_view, value)) {
            (void)snprintf(why, why_cap,
                           "--view must be summary, normal, or full and may appear once");
            return NC_FLAG_BAD;
        }
        st->seen_view = true;
        st->view = value;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "side") == 0) {
        if (nc_main_flag_side_bad(st->seen_side, value)) {
            (void)snprintf(why, why_cap,
                           "--side must be input or output and may appear once");
            return NC_FLAG_BAD;
        }
        st->seen_side = true;
        st->side = value;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "budget-bytes") == 0) {
        if (st->seen_budget ||
            !nc_parse_size_control(value, 512, ZCL_COMMAND_LIST_BUDGET,
                                   &st->budget)) {
            (void)snprintf(why, why_cap,
                           "--budget-bytes must be in 512..%u and may appear once",
                           ZCL_COMMAND_LIST_BUDGET);
            return NC_FLAG_BAD;
        }
        st->seen_budget = true;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "max-items") == 0) {
        if (st->seen_max_items ||
            !nc_parse_size_control(value, 1, 100, &st->max_items)) {
            (void)snprintf(why, why_cap,
                           "--max-items must be in 1..100 and may appear once");
            return NC_FLAG_BAD;
        }
        st->seen_max_items = true;
        return NC_FLAG_OK;
    }
    return NC_FLAG_UNMATCHED;
}

/* --cursor / --json / --format / --field / --next / the removed --fields
 * and --quiet spellings: the remaining response-control flags. */
static enum nc_main_flag_result nc_main_apply_flag_group2(
    const char *flag_key, const char *value, struct nc_main_state *st,
    char *why, size_t why_cap)
{
    if (strcmp(flag_key, "cursor") == 0) {
        if (nc_main_flag_cursor_bad(st->seen_cursor, value)) {
            (void)snprintf(why, why_cap,
                           "--cursor requires one value of at most 256 bytes");
            return NC_FLAG_BAD;
        }
        st->seen_cursor = true;
        st->cursor = value;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "json") == 0) {
        /* `--json` is the spelling people reach for when they want the
         * machine document, and it means exactly `--format=json`. It is
         * declared HERE, as a response control, rather than left to the
         * typed-input path below: as an input key it would belong to
         * whichever leaf happened to declare it, so the same word would
         * mean "give me JSON" on one command and something else on the
         * next. It takes no value for the same reason --next does. */
        if (nc_main_flag_json_bad(st->seen_format, value)) {
            (void)snprintf(why, why_cap, "--json takes no value and may appear once");
            return NC_FLAG_BAD;
        }
        st->seen_format = true;
        g_nc_format_json = true;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "format") == 0) {
        if (nc_main_flag_format_bad(st->seen_format, value)) {
            (void)snprintf(why, why_cap,
                           "only one --format=json is implemented for bounded native results");
            return NC_FLAG_BAD;
        }
        st->seen_format = true;
        g_nc_format_json = true;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "field") == 0) {
        if (nc_main_flag_field_bad(st->seen_field, value)) {
            (void)snprintf(why, why_cap,
                           "--field requires one non-empty value and "
                           "may appear once");
            return NC_FLAG_BAD;
        }
        st->seen_field = true;
        st->field_csv = value;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "next") == 0) {
        st->suggest_next = true;
        return NC_FLAG_OK;
    }
    if (strcmp(flag_key, "fields") == 0 || strcmp(flag_key, "quiet") == 0) {
        (void)snprintf(why, why_cap,
                       "--%s is not implemented; refusing a silent no-op",
                       flag_key);
        return NC_FLAG_BAD;
    }
    return NC_FLAG_UNMATCHED;
}

/* Collect the tokens the path did not consume: positionals in order and
 * value flags into a scratch object (st->flags). CLI UX contract: field
 * selector + the bare no-arg entry point's next-command hint. `field=` is
 * accepted BOTH as a bare dash-less word (the documented
 * `z23 status field=a,b` convention) and as a normal `--field=a,b` flag;
 * both set the same field_csv. --next is internal-ish (used by the bare
 * no-arg entry point) but harmless for a caller to pass directly. */
static bool nc_main_parse_flags(struct nc_main_state *st, int *rc)
{
    json_init(&st->flags);
    json_set_object(&st->flags);
    st->npos = 0;
    st->input_flag = NULL;
    st->view = NULL;
    st->side = NULL;
    st->cursor = NULL;
    st->budget = 0;
    st->max_items = 0;
    st->seen_input = false;
    st->seen_view = false;
    st->seen_side = false;
    st->seen_budget = false;
    st->seen_max_items = false;
    st->seen_cursor = false;
    st->seen_format = false;
    st->field_csv = NULL;
    st->seen_field = false;
    st->suggest_next = false;

    bool flag_error = false;
    char flag_key[128];
    char flag_why[160] = "malformed or duplicate option";
    for (size_t i = st->consumed; i < st->count; i++) {
        const char *w = st->words[i];
        if (!nc_is_flag(w)) {
            if (!nc_main_parse_bare_word(w, st, flag_why, sizeof(flag_why))) {
                flag_error = true;
                break;
            }
            continue;
        }
        const char *value = NULL;
        if (!nc_split_flag(w, flag_key, sizeof(flag_key), &value)) {
            flag_error = true;
            break;
        }
        enum nc_main_flag_result r1 = nc_main_apply_flag_group1(
            flag_key, value, st, flag_why, sizeof(flag_why));
        if (r1 == NC_FLAG_BAD) {
            flag_error = true;
            break;
        }
        if (r1 == NC_FLAG_UNMATCHED) {
            enum nc_main_flag_result r2 = nc_main_apply_flag_group2(
                flag_key, value, st, flag_why, sizeof(flag_why));
            if (r2 == NC_FLAG_BAD) {
                flag_error = true;
                break;
            }
            if (r2 == NC_FLAG_UNMATCHED &&
                !nc_set_typed_value(&st->flags, flag_key, value)) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "malformed, duplicate, or out-of-range --%s value",
                               flag_key);
                break;
            }
        }
    }
    if (flag_error) {
        json_free(&st->flags);
        nc_print_error_next_string(
            st->spec->path, "BAD_FLAG", "normalize", flag_why, st->spec->path,
            "discover.describe", "path", st->spec->path,
            "inspect the input schema");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return false;
    }
    return true;
}

/* Discovery leaves render their native document directly.
 *
 * They read the POSITIONAL argument, but their declared contract also
 * lists that argument as an input key (`discover.schema` declares
 * "path,side"), and every other leaf in the tree accepts its keys through
 * --input. Ignoring --input here broke the one loop these leaves exist to
 * close: an INVALID_INPUT reply suggests `discover.schema` with
 * `{"path":"<leaf>"}`, and following that suggestion literally answered
 * UNKNOWN_PATH because the object was never read. Honour the declared
 * keys: the positional still wins when both are given, so no existing
 * invocation changes meaning. */
static bool nc_main_read_disc_input(const char *arg, const char *input_flag,
                                    struct json_value *disc_input)
{
    return !arg && input_flag && strcmp(input_flag, "-") != 0 &&
           json_read(disc_input, input_flag, strlen(input_flag)) &&
           disc_input->type == JSON_OBJ;
}

static bool nc_main_valid_side_value(const char *s)
{
    return s && s[0] && (strcmp(s, "input") == 0 || strcmp(s, "output") == 0);
}

static int nc_main_run_discover_leaf(struct nc_main_state *st)
{
    const char *arg = st->npos > 0 ? st->positional[0] : NULL;
    struct json_value disc_input;
    json_init(&disc_input);
    bool have_disc_input =
        nc_main_read_disc_input(arg, st->input_flag, &disc_input);
    if (have_disc_input) {
        /* The leaf's own first positional key names the argument. */
        const char *pk = st->spec->positional_keys ? st->spec->positional_keys
                                                    : "";
        const char *end = strchr(pk, ',');
        char key[64];
        size_t klen = end ? (size_t)(end - pk) : strlen(pk);
        if (klen > 0 && klen < sizeof(key)) {
            memcpy(key, pk, klen);
            key[klen] = '\0';
            const char *v = json_get_str(json_get(&disc_input, key));
            if (v && v[0]) arg = v;
        }
        if (!st->side) {
            const char *s = json_get_str(json_get(&disc_input, "side"));
            if (nc_main_valid_side_value(s))
                st->side = s;
        }
    }
    int rc = nc_run_discover(st->spec, arg, st->side);
    json_free(&disc_input);
    json_free(&st->flags);
    return rc;
}

/* A branch: no deeper leaf resolved. */
static int nc_main_run_branch(struct nc_main_state *st)
{
    if (st->npos > 0) {
        char attempted[ZCL_COMMAND_MAX_PATH];
        (void)snprintf(attempted, sizeof(attempted), "%s.%s", st->spec->path,
                       st->positional[0]);
        json_free(&st->flags);
        nc_print_error_next_string(
            attempted, "UNKNOWN_COMMAND", "resolve",
            "no such command under this branch", attempted,
            "discover.search", "query", st->positional[0],
            "search for the intended command");
        return ZCL_COMMAND_EXIT_INVALID;
    }
    int rc = nc_emit_menu(st->spec->path);
    json_free(&st->flags);
    return rc;
}

/* A leaf: build the one JSON input object.
 *
 * Both spellings of --input are read against the SAME per-leaf budget the
 * validator's per-key limits imply, so neither can accept a document the
 * other would refuse, and neither truncates one the validator would take.
 * NOTE for large inputs: Linux caps a single argv string at
 * MAX_ARG_STRLEN (128 KiB), so a multi-megabyte document must arrive on
 * `--input=-` (stdin) — the argv form fails in execve long before here. */
static bool nc_main_build_input(struct nc_main_state *st, int *rc)
{
    json_init(&st->input);
    const size_t input_budget =
        zcl_command_registry_input_budget_bytes(st->spec);
    g_native_input_from_stdin = false;
    if (st->input_flag) {
        if (strcmp(st->input_flag, "-") == 0) {
            g_native_input_from_stdin = true;
            bool oversize = false;
            char *raw = nc_read_stdin(input_budget, &oversize);
            bool ok = raw && json_read(&st->input, raw, strlen(raw)) &&
                      st->input.type == JSON_OBJ;
            free(raw);
            if (!ok) {
                json_free(&st->input);
                json_free(&st->flags);
                char detail[192];
                if (oversize)
                    (void)snprintf(detail, sizeof(detail),
                                   "stdin --input=- is over this command's %zu "
                                   "byte input budget",
                                   input_budget);
                else
                    (void)snprintf(detail, sizeof(detail),
                                   "stdin --input=- must be one JSON object");
                nc_print_error_next_string(
                    st->spec->path, "BAD_INPUT", "normalize",
                    detail, st->spec->path,
                    "discover.schema", "path", st->spec->path,
                    "inspect the input schema");
                *rc = ZCL_COMMAND_EXIT_INVALID;
                return false;
            }
        } else if (strlen(st->input_flag) > input_budget) {
            json_free(&st->input);
            json_free(&st->flags);
            char detail[192];
            (void)snprintf(detail, sizeof(detail),
                           "--input is %zu bytes, over this command's %zu byte "
                           "input budget",
                           strlen(st->input_flag), input_budget);
            nc_print_error_next_string(
                st->spec->path, "BAD_INPUT", "normalize", detail, st->spec->path,
                "discover.schema", "path", st->spec->path,
                "inspect the input schema");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return false;
        } else if (!json_read(&st->input, st->input_flag,
                              strlen(st->input_flag)) ||
                   st->input.type != JSON_OBJ) {
            json_free(&st->input);
            json_free(&st->flags);
            nc_print_error_next_string(
                st->spec->path, "BAD_INPUT", "normalize",
                "--input must be one JSON object", st->spec->path,
                "discover.schema", "path", st->spec->path,
                "inspect the input schema");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return false;
        }
    } else {
        json_set_object(&st->input);
    }

    /* Merge typed flags into the input object. */
    for (size_t i = 0; i < st->flags.num_children; i++) {
        struct json_value copy;
        json_init(&copy);
        json_copy(&copy, &st->flags.children[i]);
        (void)json_push_kv(&st->input, st->flags.keys[i], &copy);
        json_free(&copy);
    }
    json_free(&st->flags);
    return true;
}

/* Map positionals onto positional_keys in order. */
static bool nc_main_map_positionals(struct nc_main_state *st, int *rc)
{
    if (st->npos == 0)
        return true;
    const char *pk = st->spec->positional_keys ? st->spec->positional_keys
                                                : "";
    size_t used = 0;
    const char *at = pk;
    for (size_t i = 0; i < st->npos; i++) {
        if (!at || !*at) {
            json_free(&st->input);
            nc_print_error_next_string(
                st->spec->path, "TOO_MANY_ARGS", "normalize",
                "more positional arguments than the leaf accepts",
                st->spec->path, "discover.schema", "path", st->spec->path,
                "inspect the input schema");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return false;
        }
        const char *end = strchr(at, ',');
        size_t klen = end ? (size_t)(end - at) : strlen(at);
        char key[64];
        if (klen >= sizeof(key)) {
            json_free(&st->input);
            nc_print_error(st->spec->path, "BAD_SCHEMA", "normalize",
                           "positional key too long", st->spec->path, "", "",
                           "");
            *rc = ZCL_COMMAND_EXIT_INTERNAL;
            return false;
        }
        memcpy(key, at, klen);
        key[klen] = 0;
        if (!nc_set_typed_value(&st->input, key, st->positional[i])) {
            json_free(&st->input);
            nc_print_error(st->spec->path, "BAD_INPUT", "normalize",
                           "could not set positional argument", key, "",
                           "", "");
            *rc = ZCL_COMMAND_EXIT_INTERNAL;
            return false;
        }
        used++;
        at = end ? end + 1 : NULL;
    }
    (void)used;
    return true;
}

/* Reject unknown keys and duplicates before any side effect.
 *
 * The message NAMES the keys this leaf accepts. A rejection that only says
 * which key was wrong, and points at a second command to learn the right
 * one, costs a caller one round trip it usually will not spend: the
 * observed failure was an agent guessing `name` for `code find`, reading
 * "inspect the input schema", and falling back to grep. The accepted set
 * is already in the spec at this point, so carrying it in the error is
 * free and removes the trip entirely. */
static bool nc_main_validate_input(struct nc_main_state *st, int *rc)
{
    char why[128];
    if (!zcl_command_registry_input_validate(st->spec, &st->input, why,
                                             sizeof(why))) {
        json_free(&st->input);
        char detail[ZCL_COMMAND_MAX_PATH + 512];
        (void)zcl_command_registry_input_reject_detail(st->spec, why, detail,
                                                       sizeof(detail));
        nc_print_error_next_string(
            st->spec->path, "INVALID_INPUT", "normalize", detail, st->spec->path,
            "discover.schema", "path", st->spec->path,
            "inspect the input schema");
        *rc = ZCL_COMMAND_EXIT_INVALID;
        return false;
    }
    return true;
}

/* The frozen grammar permits paging/view controls inside --input as well
 * as top-level flags. Normalize both spellings to the one request object,
 * and reject ambiguous double specification. */
static bool nc_main_normalize_controls(struct nc_main_state *st, int *rc)
{
    const struct json_value *input_view = json_get(&st->input, "view");
    if (input_view) {
        if (st->seen_view) {
            json_free(&st->input);
            nc_print_error_next_string(
                st->spec->path, "DUPLICATE_CONTROL", "normalize",
                "view was supplied both inside --input and as a flag", "view",
                "discover.schema", "path", st->spec->path,
                "supply each response control once");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return false;
        }
        st->view = json_get_str(input_view);
    }
    const struct json_value *input_max_items =
        json_get(&st->input, "max_items");
    if (input_max_items) {
        if (st->seen_max_items) {
            json_free(&st->input);
            nc_print_error_next_string(
                st->spec->path, "DUPLICATE_CONTROL", "normalize",
                "max_items was supplied both inside --input and as a flag",
                "max_items", "discover.schema", "path", st->spec->path,
                "supply each response control once");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return false;
        }
        st->max_items = (size_t)json_get_int(input_max_items);
    }
    const struct json_value *input_cursor_value =
        json_get(&st->input, "cursor");
    if (input_cursor_value) {
        if (st->seen_cursor) {
            json_free(&st->input);
            nc_print_error_next_string(
                st->spec->path, "DUPLICATE_CONTROL", "normalize",
                "cursor was supplied both inside --input and as a flag",
                "cursor", "discover.schema", "path", st->spec->path,
                "supply each response control once");
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return false;
        }
        if (input_cursor_value->type == JSON_STR) {
            st->cursor = json_get_str(input_cursor_value);
        } else {
            (void)snprintf(st->input_cursor, sizeof(st->input_cursor), "%lld",
                           (long long)json_get_int(input_cursor_value));
            st->cursor = st->input_cursor;
        }
    }
    return true;
}

/* Chain the four sequential --input preparation steps: read/merge, map
 * positionals, reject unknown keys, then normalize the paging/view
 * controls. Each step's own early-return contract (frees st->input on
 * failure, sets *rc) is unchanged; this only removes the four separate
 * call-sites the caller would otherwise need. */
static bool nc_main_prepare_input(struct nc_main_state *st, int *rc)
{
    if (!nc_main_build_input(st, rc))
        return false;
    if (!nc_main_map_positionals(st, rc))
        return false;
    if (!nc_main_validate_input(st, rc))
        return false;
    if (!nc_main_normalize_controls(st, rc))
        return false;
    return true;
}

/* The caller provides this leaf's declared bounded envelope; the registry
 * still enforces the contract and any smaller caller-requested budget. */
static bool nc_main_execute(struct nc_main_state *st,
                            const struct zcl_command_registry *reg, char *out,
                            size_t out_cap, size_t *n_out,
                            enum zcl_command_exit *exit_code_out, int *rc)
{
    const char *operator_lane = getenv("ZCL_OPERATOR_LANE");
#ifdef ZCL_DEV_BUILD
    /* The development executable is itself the confined dev-lane authority:
     * its mutating handlers target only ~/.zclassic-c23-dev and are omitted
     * from release builds.  Requiring callers to repeat
     * ZCL_OPERATOR_LANE=dev made the documented one-command edit loop deny
     * itself as lane "unknown".  An explicit environment value still wins,
     * so setting canonical/soak continues to fail closed. */
    if (!operator_lane || !operator_lane[0])
        operator_lane = "dev";
#endif
    struct zcl_command_context ctx = {
        .registry = reg,
        .source_root = getenv("ZCL_DEV_SOURCE_ROOT"),
        .operator_lane = operator_lane,
        .granted_capabilities = ~(uint64_t)0,
        /* The local argv operator is omnipotent: full capabilities and the
         * OWNER authority ceiling. Remote/multi-user sessions raise the ceiling
         * from their role instead (never reaching this argv path). */
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        /* Agent spend-policy presentation (docs/work/agent-spend-policy-design.md,
         * "Minting + presentation"): ZCL_AGENT_SESSION carries a session id
         * minted by vault.session.create. When set and non-empty the kernel's
         * execute_json gate and the vault's dispatch gate bound every
         * spend-shaped dispatch to that session's caps. Explicit exemption:
         * unset/empty leaves context.agent_session NULL and this argv context
         * is the omnipotent local operator, byte-identical to before the
         * policy layer existed — the ceiling and capabilities above stay as
         * built either way, because a session grant only ever narrows. */
        .agent_session = zcl_native_agent_session_env(),
#ifdef ZCL_DEV_BUILD
        .dev_build = true,
#else
        .dev_build = false,
#endif
    };

    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(
        reg, st->spec, &ctx, &st->input, st->was_alias, st->invoked, st->view,
        st->budget, st->max_items, st->cursor, out, out_cap, &exit_code);
    g_native_input_from_stdin = false;
    json_free(&st->input);
    if (n == 0) {
        nc_print_error(st->spec->path, "EXECUTE_FAILED", "serialize",
                       "handler produced no bounded result", st->spec->path, "",
                       "", "");
        *rc = ZCL_COMMAND_EXIT_INTERNAL;
        return false;
    }
    *n_out = n;
    *exit_code_out = exit_code;
    return true;
}

/* CLI UX contract: field selector. `field=`/--field= wins over prose and
 * --format=json alike — a caller who named fields wants exactly those
 * lines, nothing else. Selects out of reply.data, the SAME object the
 * JSON envelope and the prose renderer below both read; no second data
 * path. Unknown field name -> the frozen `error=... detail=... try=...`
 * one-line error contract (docs/NATIVE_COMMAND_INTERFACE.md).
 * Returns true when this call is fully handled (*rc holds the process
 * exit code); false means fall through to the ordinary rendering below. */
static bool nc_main_apply_field_selection(const struct zcl_command_spec *spec,
                                          const char *field_csv, char *out,
                                          size_t n, size_t out_cap,
                                          enum zcl_command_exit exit_code,
                                          int *rc)
{
    if (!field_csv)
        return false;
    struct json_value env;
    bool handled = false;
    if (json_read(&env, out, n) && env.type == JSON_OBJ) {
        const struct json_value *data = json_get(&env, "data");
        char *sel = zcl_malloc(out_cap, "native_field_selection");
        if (!sel) {
            nc_print_error(spec->path, "ALLOCATION_FAILED", "render",
                           "could not allocate bounded field selection", spec->path,
                           "", "", "");
            json_free(&env);
            *rc = ZCL_COMMAND_EXIT_INTERNAL;
            return true;
        }
        char selerr[320];
        if (data && zcl_native_render_field_selection(
                        data, field_csv, sel, out_cap, selerr,
                        sizeof(selerr))) {
            fputs(sel, stdout);
            handled = true;
        } else {
            fprintf(stderr,
                   "error=UNKNOWN_FIELD detail=%s try=%s\n",
                   data ? selerr : "this result has no selectable data",
                   spec->path);
            json_free(&env);
            free(sel);
            *rc = ZCL_COMMAND_EXIT_INVALID;
            return true;
        }
        free(sel);
    }
    json_free(&env);
    if (handled) {
        *rc = (int)exit_code;
        return true;
    }
    return false;
}

/* Prose leaves render a human/AI-readable text block by default; an
 * explicit --format=json (seen_format) keeps the structured envelope. On a
 * failed result (no data.text) fall back to the JSON envelope so the
 * structured error/next-action is never hidden.
 * Returns true when this call is fully handled (*rc holds the process
 * exit code); false means fall through to the plain JSON document. */
static bool nc_main_render_prose(const struct zcl_command_spec *spec,
                                 bool seen_format, bool suggest_next,
                                 const char *out, size_t n,
                                 enum zcl_command_exit exit_code, int *rc)
{
    bool eligible =
        !seen_format && (spec->traits & ZCL_COMMAND_TRAIT_PROSE) != 0;
    if (!eligible)
        return false;
    struct json_value env;
    if (json_read(&env, out, n) && env.type == JSON_OBJ) {
        char text[ZCL_COMMAND_LIST_BUDGET + 1];
        const struct json_value *data = json_get(&env, "data");
        if (nc_prose_text(spec->path, data, text, sizeof(text))) {
            /* The ONE-LINE brief is the frozen contract; on a human
             * terminal it additionally takes ANSI accents (dim keys,
             * sync/blocker tint). Pipes and NO_COLOR get the exact
             * plain line. */
            const char *emit = text;
            char colored[ZCL_COMMAND_LIST_BUDGET + 1];
            if (nc_human() &&
                (strcmp(spec->path, "status") == 0 ||
                 strcmp(spec->path, "core.status.brief") == 0) &&
                zcl_cli_render_brief(text, nc_render_env(), colored,
                                     sizeof(colored)) > 0)
                emit = colored;
            printf("%s\n", emit);
            /* The next: line prints by default on a human terminal
             * (nc_human); pipes keep the frozen one-line contract
             * unless --next was passed explicitly. */
            if ((suggest_next || nc_human()) &&
                (strcmp(spec->path, "status") == 0 ||
                 strcmp(spec->path, "core.status.brief") == 0))
                printf("next: %s\n",
                       strcmp(spec->path, "status") == 0
                           ? json_get_str_or(data, "next_action",
                                             "z23 core status brief")
                           : zcl_native_status_brief_next_command(data));
            json_free(&env);
            *rc = (int)exit_code;
            return true;
        }
    }
    json_free(&env);
    return false;
}

static size_t nc_main_response_capacity(const struct zcl_command_spec *spec)
{
    size_t budget = spec->budget_bytes > 0
                        ? (size_t)spec->budget_bytes
                        : (size_t)ZCL_COMMAND_RESULT_BUDGET;
    if (budget < ZCL_COMMAND_ERROR_BUDGET)
        budget = ZCL_COMMAND_ERROR_BUDGET;
    return budget + 1;
}

int zcl_native_command_main(const char *root_word, const char *const *args,
                            int nargs, const char *datadir, int rpc_port,
                            enum chain_network network,
                            bool datadir_explicit)
{
    if (!root_word || !root_word[0])
        return ZCL_COMMAND_EXIT_INVALID;

    const struct zcl_command_registry *reg = NULL;
    int boot_rc = nc_main_bootstrap(root_word, datadir, rpc_port, network,
                                    datadir_explicit, &reg);
    if (boot_rc != NC_MAIN_CONTINUE)
        return boot_rc;

    struct nc_main_state st;
    int rc = ZCL_COMMAND_EXIT_INVALID;
    st.spec = nc_main_resolve(reg, root_word, args, nargs, &st, &rc);
    if (!st.spec)
        return rc;

    if (nc_main_try_intercepts(st.spec, st.words, st.count, st.consumed,
                               datadir, &rc))
        return rc;

    if (!nc_main_parse_flags(&st, &rc))
        return rc;

    /* Discovery leaves render their native document directly. */
    if (st.spec->layer == ZCL_COMMAND_LAYER_DISCOVER &&
        st.spec->mode != ZCL_COMMAND_MODE_BRANCH)
        return nc_main_run_discover_leaf(&st);

    /* A branch: no deeper leaf resolved. */
    if (st.spec->mode == ZCL_COMMAND_MODE_BRANCH)
        return nc_main_run_branch(&st);

    if (!nc_main_prepare_input(&st, &rc))
        return rc;

    size_t out_cap = nc_main_response_capacity(st.spec);
    char *out = zcl_malloc(out_cap, "native_command_response");
    if (!out) {
        json_free(&st.input);
        nc_print_error(st.spec->path, "ALLOCATION_FAILED", "serialize",
                       "could not allocate bounded command response", st.spec->path,
                       "", "", "");
        return ZCL_COMMAND_EXIT_INTERNAL;
    }
    size_t n = 0;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    if (!nc_main_execute(&st, reg, out, out_cap, &n, &exit_code, &rc)) {
        free(out);
        return rc;
    }

    if (nc_main_apply_field_selection(st.spec, st.field_csv, out, n, out_cap,
                                      exit_code, &rc)) {
        free(out);
        return rc;
    }

    if (nc_main_render_prose(st.spec, st.seen_format, st.suggest_next, out, n,
                             exit_code, &rc)) {
        free(out);
        return rc;
    }

    nc_print_doc(out, st.spec->path);
    free(out);
    return (int)exit_code;
}
