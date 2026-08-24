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
 * either calls its transport-neutral body function (app/controllers/
 * *_native_handlers.c) or, for a pure 1:1 proxy, calls the backing JSON-RPC
 * method directly. Discovery
 * leaves (help/search/describe/schema) render the native discovery document
 * directly. The `dev` subtree uses this same resolver; its process and watcher
 * handlers are injected only in a ZCL_DEV_BUILD catalog.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "config/command_catalog.h"
#include "framework/app_definition.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#ifdef ZCL_DEV_BUILD
#include "hotswap/hotswap_module.h"
#include "command/native_dev_hotswap.h"
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
        "zcode", "metaverse", "yardsale", "zses", "help", "search",
        /* Operator-UX convenience roots: bare aliases of ops.explain /
         * ops.profile so `z23 explain sync` / `zclassic23 profile`
         * work without the `ops` prefix (each leaf carries the matching
         * alias in config/commands/ops.def). `meaning` joins them because the
         * field ontology is most needed by an operator who does not yet know
         * which report — let alone which prefix — to reach for. */
        "explain", "profile", "meaning",
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
    { "app.swap.chains", zcl_native_swap_chains_body },
    { "app.swap.list", zcl_native_swap_list_body },
};

enum bridge_rpc_array_kind {
    BRIDGE_RPC_ARRAY_NONE = 0,
    BRIDGE_RPC_ARRAY_TXIDS,
    BRIDGE_RPC_ARRAY_PEERS,
    BRIDGE_RPC_ARRAY_LATENCY,
};

struct bridge_rpc_required_field {
    const char *name;
    enum json_type type;
};

struct bridge_rpc_binding {
    const char *path;
    const char *rpc_method;
    enum json_type top_type;
    struct bridge_rpc_required_field required[5];
    enum bridge_rpc_array_kind array_kind;
};

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
    { "ops.health", "healthcheck", JSON_OBJ,
      {{"status", JSON_STR}, {"healthy", JSON_BOOL}, {"serving", JSON_BOOL}},
      BRIDGE_RPC_ARRAY_NONE },
    { "ops.lanes", "agentlanes", JSON_OBJ,
      {{"status", JSON_STR}, {"lanes", JSON_ARR}}, BRIDGE_RPC_ARRAY_NONE },
    { "ops.recovery.status", "refold", JSON_OBJ,
      {{"ready_for_refold", JSON_BOOL}, {"primary_blocker", JSON_STR}},
      BRIDGE_RPC_ARRAY_NONE },
};

static const struct bridge_rpc_binding *bridge_rpc_binding_for_path(
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

static const char *bridge_json_type_name(enum json_type type)
{
    static const char *const names[] = {
        "null", "bool", "int", "real", "string", "array", "object",
    };
    return (unsigned)type < sizeof(names) / sizeof(names[0])
               ? names[type]
               : "unknown";
}

static bool bridge_is_hex64(const char *s)
{
    if (!s || strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isxdigit(c))
            return false;
    }
    return true;
}

static bool bridge_validate_array_item(
    const struct bridge_rpc_binding *binding,
    const struct json_value *item, size_t index,
    char *why, size_t why_cap)
{
    const char *field_a = NULL;
    const char *field_b = NULL;
    switch (binding->array_kind) {
    case BRIDGE_RPC_ARRAY_TXIDS:
        if (item->type == JSON_STR && bridge_is_hex64(json_get_str(item)))
            return true;
        (void)snprintf(why, why_cap,
                       "item %zu must be a 64-hex transaction id", index);
        return false;
    case BRIDGE_RPC_ARRAY_PEERS:
        field_a = "id";
        field_b = "addr";
        break;
    case BRIDGE_RPC_ARRAY_LATENCY:
        field_a = "peer_id";
        field_b = "addr";
        break;
    case BRIDGE_RPC_ARRAY_NONE:
        return true;
    }
    if (item->type != JSON_OBJ) {
        (void)snprintf(why, why_cap, "item %zu must be an object", index);
        return false;
    }
    const struct json_value *a = json_get(item, field_a);
    const struct json_value *b = json_get(item, field_b);
    if (!a || a->type != JSON_INT) {
        (void)snprintf(why, why_cap, "item %zu field %s must be int",
                       index, field_a);
        return false;
    }
    if (!b || b->type != JSON_STR) {
        (void)snprintf(why, why_cap, "item %zu field %s must be string",
                       index, field_b);
        return false;
    }
    return true;
}

/* A bare, parseable JSON value is not proof that the requested RPC exists or
 * that the running node speaks this source epoch's contract. Direct-RPC
 * leaves therefore validate the stable minimum of the legacy result shape.
 * These checks intentionally do not require a synthetic `schema` member:
 * zclassicd-compatible RPCs predate schema labels, but their field/type shape
 * is stable. Empty list results remain valid; every populated element is
 * checked so a mixed or arbitrary array fails closed. */
static bool bridge_validate_rpc_success(
    const struct bridge_rpc_binding *binding,
    const struct json_value *doc, char *why, size_t why_cap)
{
    if (!binding || !doc) {
        (void)snprintf(why, why_cap, "missing direct-RPC contract");
        return false;
    }
    if (doc->type != binding->top_type) {
        (void)snprintf(why, why_cap, "top level must be %s (got %s)",
                       bridge_json_type_name(binding->top_type),
                       bridge_json_type_name(doc->type));
        return false;
    }
    for (size_t i = 0;
         i < sizeof(binding->required) / sizeof(binding->required[0]); i++) {
        const struct bridge_rpc_required_field *required =
            &binding->required[i];
        if (!required->name)
            break;
        const struct json_value *field = json_get(doc, required->name);
        if (!field || field->type != required->type) {
            (void)snprintf(why, why_cap, "field %s must be %s",
                           required->name,
                           bridge_json_type_name(required->type));
            return false;
        }
    }
    if (binding->top_type == JSON_ARR) {
        for (size_t i = 0; i < doc->num_children; i++) {
            if (!bridge_validate_array_item(binding, &doc->children[i], i,
                                            why, why_cap))
                return false;
        }
    }
    return true;
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

/* Translate the CLI leaf input into the exact argument object its handler
 * expects. Most leaves are pass-through; a few need a rename. */
static bool bridge_build_args(const char *path,
                              const struct json_value *input,
                              struct json_value *out, bool *use_out)
{
    *use_out = false;
    if (strcmp(path, "core.chain.block.get") == 0) {
        json_init(out);
        json_set_object(out);
        const struct json_value *height = json_get(input, "height");
        const struct json_value *hash = json_get(input, "hash");
        const struct json_value *verbosity = json_get(input, "verbosity");
        if (hash && !json_is_null(hash)) {
            if (!json_push_kv_str(out, "block_id", json_get_str(hash))) {
                json_free(out);
                return false;
            }
        } else if (height && !json_is_null(height)) {
            char idbuf[32];
            (void)snprintf(idbuf, sizeof(idbuf), "%lld",
                           (long long)json_get_int(height));
            if (!json_push_kv_str(out, "block_id", idbuf)) {
                json_free(out);
                return false;
            }
        }
        if (verbosity && !json_is_null(verbosity)) {
            if (!json_push_kv_int(out, "verbosity", json_get_int(verbosity))) {
                json_free(out);
                return false;
            }
        }
        *use_out = true;
        return true;
    }
    return true; /* pass-through: caller uses `input` directly */
}

/* ── progressive-disclosure projection (contract §8/§9) ──────────────────
 * A bridged command body can exceed the ordinary-result budget. Rather
 * than fail with RESPONSE_BUDGET_EXCEEDED, project the top-level object to fit:
 *   summary — scalar top-level fields only (containers dropped);
 *   normal  — greedy from --cursor until the leaf budget (default);
 *   full    — greedy from --cursor, honoring --max-items, paging via a cursor.
 * Truncation is always explicit: a `_page` object records the advancing
 * cursor, while `next` points at the leaf contract instead of creating an
 * executable self-loop. `--cursor` is honored in normal and full so a
 * truncated list can actually continue. */
enum { NC_ENVELOPE_RESERVE = 768 };

static void nc_add_describe_next(struct zcl_command_reply *reply,
                                 const char *path, const char *reason)
{
    if (!reply || !path || !path[0])
        return;
    char input[ZCL_COMMAND_MAX_PATH + 16];
    int n = snprintf(input, sizeof(input), "{\"path\":\"%s\"}", path);
    if (n > 0 && (size_t)n < sizeof(input))
        (void)zcl_command_reply_add_next(reply, "discover.describe", input,
                                         reason);
}

static void nc_add_string_next(struct zcl_command_reply *reply,
                               const char *command, const char *key,
                               const char *value, const char *reason)
{
    if (!reply || !command || !key || !value)
        return;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    char encoded[sizeof(reply->next[0].input_json)];
    bool ok = json_push_kv_str(&input, key, value);
    size_t n = ok ? json_write(&input, encoded, sizeof(encoded)) : 0;
    json_free(&input);
    if (n > 0 && n < sizeof(encoded))
        (void)zcl_command_reply_add_next(reply, command, encoded, reason);
}

static bool nc_is_scalar(const struct json_value *v)
{
    return v && v->type <= JSON_STR; /* NULL/BOOL/INT/REAL/STR */
}

static size_t nc_json_size(const struct json_value *value)
{
    char scratch[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t n = json_write(value, scratch, sizeof(scratch));
    return (n == 0 || n >= sizeof(scratch)) ? sizeof(scratch) : n;
}

static int nc_peer_kind(const struct json_value *row)
{
    if (json_get_bool(json_get(row, "zclassic23")))
        return 0;
    if (json_get_bool(json_get(row, "magicbean")))
        return 1;
    return 2;
}

/* Stable kind order: Z23, then MagicBean, then other. No host list. */
static void nc_peer_order(const struct json_value *body, size_t *ord, size_t n)
{
    for (size_t i = 0; i < n; i++)
        ord[i] = i;
    for (size_t i = 1; i < n; i++) {
        size_t v = ord[i];
        size_t j = i;
        int vk = nc_peer_kind(&body->children[v]);
        while (j > 0 &&
               nc_peer_kind(&body->children[ord[j - 1]]) > vk) {
            ord[j] = ord[j - 1];
            j--;
        }
        ord[j] = v;
    }
}

static void nc_project_array(const struct zcl_command_request *request,
                             const struct json_value *body,
                             struct zcl_command_reply *reply)
{
    const char *view = request->view && request->view[0] ? request->view
                                                          : "normal";
    bool summary = strcmp(view, "summary") == 0;
    bool full = strcmp(view, "full") == 0;
    size_t contract = ZCL_COMMAND_RESULT_BUDGET;
    if (request->spec && request->spec->budget_bytes > (int)contract)
        contract = (size_t)request->spec->budget_bytes;
    if (request->budget_bytes > 0 && request->budget_bytes < contract)
        contract = request->budget_bytes;
    size_t data_budget = contract > NC_ENVELOPE_RESERVE
                             ? contract - NC_ENVELOPE_RESERVE
                             : contract / 2;
    /* Reserve room inside data for the stable page descriptor. */
    size_t items_budget = data_budget > 256 ? data_budget - 256
                                             : data_budget / 2;

    size_t start = 0;
    if (!summary && request->cursor && request->cursor[0]) {
        char *end = NULL;
        unsigned long long c = strtoull(request->cursor, &end, 10);
        if (end && !*end)
            start = (size_t)c;
    }

    size_t ord[256];
    const size_t *map = NULL;
    size_t nbody = body->num_children;
    if (request->spec && request->spec->path &&
        strcmp(request->spec->path, "core.network.peers.list") == 0 &&
        nbody > 0 && nbody <= 256) {
        nc_peer_order(body, ord, nbody);
        map = ord;
    }

    struct json_value items;
    json_init(&items);
    json_set_array(&items);
    size_t included = 0;
    size_t next_cursor = nbody;
    bool truncated = summary && body->num_children > 0;
    bool skipped_oversize = false;
    size_t skipped_index = 0;
    if (summary)
        next_cursor = 0;

    for (size_t i = start; !summary && i < nbody; i++) {
        if (full && request->max_items > 0 && included >= request->max_items) {
            truncated = true;
            next_cursor = i;
            break;
        }
        struct json_value probe, copy;
        json_init(&probe);
        json_init(&copy);
        json_copy(&probe, &items);
        json_copy(&copy, &body->children[map ? map[i] : i]);
        (void)json_push_back(&probe, &copy);
        size_t sz = nc_json_size(&probe);
        json_free(&probe);
        if (sz <= items_budget) {
            (void)json_push_back(&items, &copy);
            included++;
            json_free(&copy);
            continue;
        }
        json_free(&copy);
        truncated = true;
        if (included == 0) {
            skipped_oversize = true;
            skipped_index = i;
            next_cursor = i + 1;
        } else {
            next_cursor = i;
        }
        break;
    }

    struct json_value page, data;
    json_init(&page);
    json_init(&data);
    json_set_object(&page);
    json_set_object(&data);
    (void)json_push_kv_str(&page, "view", view);
    (void)json_push_kv_int(&page, "total_items",
                           (int64_t)body->num_children);
    (void)json_push_kv_int(&page, "included", (int64_t)included);
    (void)json_push_kv_bool(&page, "truncated", truncated);
    if (truncated)
        (void)json_push_kv_int(&page, "next_cursor", (int64_t)next_cursor);
    if (truncated && request->spec && request->spec->path) {
        char words[128];
        char cont[192];
        size_t wl = 0;
        for (const char *p = request->spec->path;
             *p && wl + 1 < sizeof(words); p++)
            words[wl++] = *p == '.' ? ' ' : *p;
        words[wl] = '\0';
        if (snprintf(cont, sizeof(cont), "z23 %s --cursor=%zu", words,
                     next_cursor) > 0)
            (void)json_push_kv_str(&page, "continue", cont);
    }
    if (skipped_oversize)
        (void)json_push_kv_int(&page, "skipped_oversize_index",
                               (int64_t)skipped_index);
    (void)json_push_kv(&data, "items", &items);
    (void)json_push_kv(&data, "_page", &page);
    json_free(&items);
    json_free(&page);

    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &data);
    json_free(&data);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;

    if (truncated)
        nc_add_describe_next(
            reply, request->spec->path,
            summary ? "inspect paging controls before retrieving list items"
                    : "inspect paging controls before continuing this list");
}

void zcl_native_bridge_project(const struct zcl_command_request *request,
                               const struct json_value *body,
                               struct zcl_command_reply *reply)
{
    if (body && body->type == JSON_ARR) {
        nc_project_array(request, body, reply);
        return;
    }
    if (!body || body->type != JSON_OBJ) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_TOOL_BODY",
                               "serialize", false, false,
                               "command returned an unsupported body shape",
                               request && request->spec
                                   ? request->spec->path : "");
        return;
    }
    const char *view = request->view && request->view[0] ? request->view
                                                          : "normal";
    bool summary = strcmp(view, "summary") == 0;
    bool full = strcmp(view, "full") == 0;

    size_t contract = ZCL_COMMAND_RESULT_BUDGET;
    if (request->budget_bytes > 0 && request->budget_bytes < contract)
        contract = request->budget_bytes;
    size_t data_budget = contract > NC_ENVELOPE_RESERVE
                             ? contract - NC_ENVELOPE_RESERVE
                             : contract / 2;

    size_t start = 0;
    if (!summary && request->cursor && request->cursor[0]) {
        char *end = NULL;
        unsigned long long c = strtoull(request->cursor, &end, 10);
        if (end && !*end)
            start = (size_t)c;
    }
    size_t total = body->num_children;

    struct json_value acc;
    json_init(&acc);
    json_set_object(&acc);
    size_t included = 0, omitted = 0, next_cursor = total;
    bool truncated = false;
    const char *oversize_key = NULL;
    for (size_t i = (summary ? 0 : start); i < total; i++) {
        const struct json_value *val = &body->children[i];
        if (summary && !nc_is_scalar(val)) {
            omitted++;
            continue;
        }
        if (full && request->max_items > 0 && included >= request->max_items) {
            truncated = true;
            next_cursor = i;
            break;
        }
        /* Measure a copy with the candidate member before committing it. */
        struct json_value probe, copy;
        json_init(&probe);
        json_init(&copy);
        json_copy(&probe, &acc);
        json_copy(&copy, val);
        (void)json_push_kv(&probe, body->keys[i], &copy);
        size_t sz = nc_json_size(&probe);
        json_free(&probe);
        if (sz <= data_budget) {
            (void)json_push_kv(&acc, body->keys[i], &copy);
            included++;
            json_free(&copy);
        } else {
            json_free(&copy);
            truncated = true;
            /* A single field larger than the whole page budget must not stall
             * the cursor: advance past it and name it so the caller can fetch
             * it narrowly (a wider budget, --fields, or the command directly). */
            if (included == 0) {
                next_cursor = i + 1;
                oversize_key = body->keys[i];
            } else {
                next_cursor = i;
            }
            break;
        }
    }
    if (summary && omitted > 0)
        truncated = true;

    /* Attach the explicit page descriptor. */
    struct json_value page;
    json_init(&page);
    json_set_object(&page);
    (void)json_push_kv_str(&page, "view", view);
    (void)json_push_kv_int(&page, "total_fields", (int64_t)total);
    (void)json_push_kv_int(&page, "included", (int64_t)included);
    (void)json_push_kv_bool(&page, "truncated", truncated);
    if (truncated && !summary)
        (void)json_push_kv_int(&page, "next_cursor", (int64_t)next_cursor);
    if (oversize_key)
        (void)json_push_kv_str(&page, "skipped_oversize", oversize_key);
    (void)json_push_kv(&acc, "_page", &page);
    json_free(&page);

    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, &acc);
    json_free(&acc);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;

    if (truncated)
        nc_add_describe_next(
            reply, request->spec->path,
            summary ? "inspect paging controls before retrieving full fields"
                    : "inspect paging controls before continuing these fields");
}

/* Run a bridged leaf with an EXPLICIT body function — everything
 * zcl_native_bridge_command does after resolving the body pointer: build the
 * command arguments from the request, dispatch (the supplied body function, or —
 * when `body` is NULL and the leaf is a pure 1:1 proxy — the backing JSON-RPC
 * method directly), then project the resulting body into the reply envelope.
 * A hot-swap generation supplies its OWN freshly-compiled body here; the
 * ordinary registry path passes zcl_native_bridge_body_for_path(path). When
 * `body` is NULL and the path also has no direct-RPC binding (i.e. an unknown
 * / unbound path), this fails with the same NO_BRIDGE_BINDING reply the
 * pre-extraction code produced. */
void zcl_native_bridge_run(const struct zcl_command_request *request,
                           zcl_native_body_fn body,
                           struct zcl_command_reply *reply)
{
    if (!request || !request->spec || !reply)
        return;
    zcl_native_body_fn resident_body =
        zcl_native_bridge_body_for_path(request->spec->path);
    const struct bridge_rpc_binding *rpc_binding =
        bridge_rpc_binding_for_path(request->spec->path);
    const char *rpc_method = rpc_binding ? rpc_binding->rpc_method : NULL;
    bool valid_binding = body ? (resident_body != NULL && rpc_method == NULL)
                              : (resident_body == NULL && rpc_method != NULL);
    if (!valid_binding) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_BRIDGE_BINDING",
                               "dispatch", false, false,
                               body && rpc_method
                                   ? "ready leaf has ambiguous dispatch bindings"
                                   : "ready leaf has no dispatch binding",
                               request->spec->path);
        return;
    }

    bridge_ensure_rpc_client();

    struct json_value translated;
    bool use_translated = false;
    if (!bridge_build_args(request->spec->path, request->input, &translated,
                           &use_translated)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                               "normalize", false, false,
                               "could not normalize leaf arguments",
                               request->spec->path);
        return;
    }
    const struct json_value *args =
        use_translated ? &translated : request->input;

    /* Dispatch through the supplied body function or the backing RPC. */
    struct zcl_native_body_err body_err = { 0 };
    char *result = body ? body(args, &body_err)
                        : node_rpc_call(rpc_method, NULL);
    if (use_translated)
        json_free(&translated);

    if (!result) {
        char msgbuf[224];
        const char *msg;
        enum zcl_command_status failure_status = ZCL_COMMAND_STATUS_FAILED;
        enum zcl_command_exit failure_exit = ZCL_COMMAND_EXIT_FAILED;
        bool retryable = false;
        if (body) {
            msg = body_err.message[0] ? body_err.message
                                      : "command handler reported an error";
            if (body_err.status == ZCL_NATIVE_BODY_UNAVAILABLE) {
                failure_status = ZCL_COMMAND_STATUS_BLOCKED;
                failure_exit = ZCL_COMMAND_EXIT_TRANSIENT;
                retryable = true;
            } else if (body_err.status == ZCL_NATIVE_BODY_INVALID) {
                failure_exit = ZCL_COMMAND_EXIT_INVALID;
            } else if (body_err.status == ZCL_NATIVE_BODY_INTERNAL) {
                failure_exit = ZCL_COMMAND_EXIT_INTERNAL;
            }
        } else {
            (void)snprintf(msgbuf, sizeof(msgbuf), "RPC %s returned null",
                           rpc_method);
            msg = msgbuf;
        }
        zcl_command_reply_fail(reply, failure_status, failure_exit,
                               "TOOL_ERROR", "execute", retryable, false, msg,
                               request->spec->path);
        nc_add_describe_next(reply, request->spec->path,
                             "inspect this command before retrying");
        return;
    }

    struct json_value body_doc;
    if (!json_read(&body_doc, result, strlen(result))) {
        json_free(&body_doc);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_TOOL_BODY",
                               "serialize", false, false,
                               "command returned an invalid JSON body",
                               request->spec->path);
        return;
    }
    free(result);

    const struct json_value *err = body_doc.type == JSON_OBJ
                                       ? json_get(&body_doc, "error") : NULL;
    if (body_doc.type == JSON_OBJ && status_json_is_rpc_error(&body_doc)) {
        const char *msg = NULL;
        if (err && err->type == JSON_OBJ)
            msg = json_get_str(json_get(err, "message"));
        else if (err && err->type == JSON_STR)
            msg = json_get_str(err);
        else
            msg = json_get_str(json_get(&body_doc, "message"));
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "TOOL_ERROR",
                               "execute", false, false,
                               msg && msg[0] ? msg : "command reported an error",
                               request->spec->path);
        json_free(&body_doc);
        return;
    }

    if (body && body_doc.type != JSON_OBJ) {
        /* Legacy diag RPC handlers report errors as a bare string body
         * ("<cmd>: <reason>", the json_set_str(result, ...) convention). A
         * string body can never be a success here — the body contract
         * requires an object — so surface the handler's own message as a
         * typed TOOL_ERROR instead of an opaque BAD_TOOL_BODY that hides
         * it. Non-string non-objects stay BAD_TOOL_BODY. */
        const char *legacy_msg = body_doc.type == JSON_STR
                                     ? json_get_str(&body_doc) : NULL;
        if (legacy_msg && legacy_msg[0]) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "TOOL_ERROR",
                                   "execute", false, false, legacy_msg,
                                   request->spec->path);
            json_free(&body_doc);
            return;
        }
        json_free(&body_doc);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_TOOL_BODY",
                               "serialize", false, false,
                               "command returned a non-object body",
                               request->spec->path);
        return;
    }
    if (!body) {
        char why[160];
        if (!bridge_validate_rpc_success(rpc_binding, &body_doc,
                                         why, sizeof(why))) {
            char msg[224];
            (void)snprintf(msg, sizeof(msg),
                           "RPC %s returned an incompatible success body: %s",
                           rpc_method ? rpc_method : "(unbound)", why);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED, "TOOL_ERROR",
                                   "execute", false, false, msg,
                                   request->spec->path);
            json_free(&body_doc);
            return;
        }
    }

    /* Success: project the command body into the result envelope's data, bounded
     * by view + budget so a large read pages instead of overflowing (§8/§9). */
    zcl_native_bridge_project(request, &body_doc, reply);
    json_free(&body_doc);
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

/* ── ops.state / ops.selftest native leaves ──────────────────────────────
 * ops.state calls the `dumpstate` RPC method directly, while ops.selftest is
 * a node-free, deterministic well-formedness sweep of the registry. */
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

    /* dumpstate params: [subsystem] or [subsystem, key]. Build via JSON so the
     * subsystem/key strings are correctly escaped, never printf-spliced. */
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
    char params_json[512];
    size_t pn = json_write(&params, params_json, sizeof(params_json));
    json_free(&params);
    if (pn == 0 || pn >= sizeof(params_json)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                               "normalize", false, false,
                               "could not encode dumpstate params", sub);
        return;
    }

    bridge_ensure_rpc_client();
    /* Call the RPC layer directly. */
    char *result = node_rpc_call("dumpstate", params_json);
    if (!result) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a state body", sub);
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }
    struct json_value body;
    if (!json_read(&body, result, strlen(result)) || body.type != JSON_OBJ) {
        json_free(&body);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "dumpstate returned a non-object body", sub);
        return;
    }
    free(result);
    /* node_rpc_call surfaces a JSON-RPC failure as either {"error":{...}}
     * (transport) or a bare {"code":..,"message":..} (RPC-level). Treat both
     * as a failed dump — e.g. an unknown subsystem. */
    const struct json_value *err = json_get(&body, "error");
    const struct json_value *ecode = json_get(&body, "code");
    const struct json_value *emsg = json_get(&body, "message");
    if ((err && !json_is_null(err)) ||
        (ecode && ecode->type == JSON_INT && emsg && emsg->type == JSON_STR)) {
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

    /* Values alone do not say whether they are good. When this subsystem has a
     * field ontology, either attach the verdicts (--explain) or, at minimum,
     * SAY that meaning exists — the failure this closes is an operator reading
     * a number with no idea it could be explained at all. Off by default, so a
     * routine dump does not grow. */
    if (telemetry_subsystem_covered(sub)) {
        const struct json_value *st = json_get(&body, "state");
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
    bridge_ensure_rpc_client();
    char *result = node_rpc_call("dumpstate", "[\"network_monitor\"]");
    if (!result) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return the network view",
                               "network_monitor");
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }
    struct json_value body;
    if (!json_read(&body, result, strlen(result)) || body.type != JSON_OBJ) {
        json_free(&body);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "network view returned a non-object body",
                               "network_monitor");
        return;
    }
    free(result);
    const struct json_value *err = json_get(&body, "error");
    const struct json_value *ecode = json_get(&body, "code");
    const struct json_value *emsg = json_get(&body, "message");
    if ((err && !json_is_null(err)) ||
        (ecode && ecode->type == JSON_INT && emsg && emsg->type == JSON_STR)) {
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
 * app/controllers/include/controllers/diagnostics_dumpers.def out of the
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

void zcl_native_handle_ops_statecatalog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct json_value catalog;
    json_init(&catalog);
    if (!diag_rpc_statecatalog(NULL, false, &catalog)) {
        json_free(&catalog);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_UNAVAILABLE",
                               "execute", false, false,
                               "the diagnostics registry did not render a "
                               "catalog", "ops.statecatalog");
        return;
    }
    const struct json_value *subs = json_get(&catalog, "subsystems");
    if (!subs || subs->type != JSON_ARR) {
        json_free(&catalog);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_MALFORMED",
                               "serialize", false, false,
                               "the diagnostics catalog carried no subsystems "
                               "array", "ops.statecatalog");
        return;
    }
    size_t total = json_size(subs);

    (void)json_push_kv_str(&reply->data, "source",
                           json_get_str(json_get(&catalog, "source")));
    (void)json_push_kv_str(&reply->data, "catalog_schema",
                           json_get_str(json_get(&catalog, "schema")));
    (void)json_push_kv_int(&reply->data, "count", (int64_t)total);
    (void)json_push_kv_bool(&reply->data, "node_free", true);

    /* One named subsystem: its whole descriptor, unpaged and untrimmed. */
    const char *want = json_get_str(json_get(request->input, "subsystem"));
    if (want && want[0]) {
        for (size_t i = 0; i < total; i++) {
            const struct json_value *e = json_at(subs, i);
            const char *name = e ? json_get_str(json_get(e, "name")) : NULL;
            if (name && strcmp(name, want) == 0) {
                (void)json_push_kv(&reply->data, "subsystem", e);
                json_free(&catalog);
                reply->status = ZCL_COMMAND_STATUS_PASSED;
                reply->exit_code = ZCL_COMMAND_EXIT_OK;
                return;
            }
        }
        json_free(&catalog);
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
        return;
    }

    const struct json_value *lv = json_get(request->input, "limit");
    const struct json_value *pv = json_get(request->input, "page");
    bool want_rows = lv != NULL || pv != NULL;

    /* Default mode: every name, complete, in one call. This is the
     * discovery answer and it is never paged away. */
    if (!want_rows) {
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
        json_free(&catalog);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
        return;
    }

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
    json_free(&catalog);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
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
        /* A READY leaf must be dispatchable: a non-NULL handler plus the
         * schema/example/effect-risk guarantees zcl_command_registry_validate
         * enforces. This is a static, node-free contract check. */
        const char *reason = NULL;
        if (!s->handler)
            reason = "ready-leaf-missing-handler";
        else if (!s->input_schema || !s->input_schema[0] ||
                 !s->output_schema || !s->output_schema[0] ||
                 !s->example || !s->example[0])
            reason = "missing-schema-or-example";
        else if (s->effect == ZCL_COMMAND_EFFECT_READ &&
                 s->risk != ZCL_COMMAND_RISK_READ)
            reason = "read-effect-risk-conflict";
        else if (!s->semantics || !s->semantics[0])
            reason = "missing-semantics";
        else if (strcmp(s->semantics, s->summary) == 0)
            reason = "semantics-equals-summary";
        else if (s->budget_bytes != 0 &&
                 (s->budget_bytes < 256 || s->budget_bytes > 65536))
            reason = "budget-out-of-range";
        else if (s->handler == zcl_native_bridge_command &&
                 !bridge_has_exact_binding(s->path))
            reason = "bridge-leaf-without-exact-binding";

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
                           "lib/util/include/util/telemetry_ontology.def");

    /* A question routes to a command; that is the whole point of the index. */
    if (question && question[0]) {
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

    const char *key = (field && field[0]) ? field
                    : (subsystem && subsystem[0]) ? subsystem : NULL;
    if (key || !(question && question[0])) {
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
        (void)json_push_kv_int(&reply->data, "fields_matched",
                               (int64_t)matched);
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

    bridge_ensure_rpc_client();
    char *result = node_rpc_call("debugbundle", "[]");
    if (!result) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a debug-bundle body",
                               "ops.debug.bundle");
        (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                         "confirm the node is running");
        return;
    }
    struct json_value body;
    if (!json_read(&body, result, strlen(result)) || body.type != JSON_OBJ) {
        json_free(&body);
        free(result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_BUNDLE_BODY",
                               "serialize", false, false,
                               "debugbundle returned a non-object body",
                               "ops.debug.bundle");
        return;
    }
    free(result);

    /* node_rpc_call surfaces a JSON-RPC failure as {"error":{...}}
     * (transport), a bare {"code":..,"message":..} (RPC-level, e.g. warmup),
     * or {"error":".."} (handler-level). All three are a failed bundle. */
    const struct json_value *err = json_get(&body, "error");
    const struct json_value *ecode = json_get(&body, "code");
    const struct json_value *emsg = json_get(&body, "message");
    if ((err && !json_is_null(err)) ||
        (ecode && ecode->type == JSON_INT && emsg && emsg->type == JSON_STR)) {
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
void zcl_native_handle_ops_profile(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    int64_t seconds = json_get_int(json_get(request->input, "seconds"));
    if (seconds < 1) seconds = 3;
    if (seconds > 60) seconds = 60;
    int64_t top_n = json_get_int(json_get(request->input, "top_n"));
    if (top_n < 1) top_n = 8;
    if (top_n > 32) top_n = 32;

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

    /* Render a prose block from the structured profile body. */
    char t[1600];
    size_t len = 0;
    int n;
    n = snprintf(t + len, sizeof(t) - len, "profile — %s\n",
                 json_get_str(json_get(&body, "verdict"))
                     ? json_get_str(json_get(&body, "verdict")) : "unknown");
    if (n > 0) len += (size_t)n;
    n = snprintf(t + len, sizeof(t) - len,
                 "  sampled %lld threads over %lld ms\n",
                 (long long)json_get_int(json_get(&body, "sampled_threads")),
                 (long long)json_get_int(json_get(&body, "sample_ms")));
    if (n > 0) len += (size_t)n;

    const struct json_value *threads = json_get(&body, "threads");
    if (threads && threads->type == JSON_ARR) {
        n = snprintf(t + len, sizeof(t) - len,
                     "  busiest threads (cpu_ms / wchan):\n");
        if (n > 0) len += (size_t)n;
        for (size_t i = 0; i < threads->num_children && len < sizeof(t) - 128;
             i++) {
            const struct json_value *th = &threads->children[i];
            n = snprintf(t + len, sizeof(t) - len,
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
    }
    const struct json_value *stages = json_get(&body, "stage_ewma");
    if (stages && stages->type == JSON_ARR && len < sizeof(t) - 256) {
        n = snprintf(t + len, sizeof(t) - len,
                     "  reducer stage rates (steps/sec, cursor):\n");
        if (n > 0) len += (size_t)n;
        for (size_t i = 0; i < stages->num_children && len < sizeof(t) - 96;
             i++) {
            const struct json_value *sg = &stages->children[i];
            n = snprintf(t + len, sizeof(t) - len, "    %-16s %lld  (%lld)\n",
                         json_get_str(json_get(sg, "stage"))
                             ? json_get_str(json_get(sg, "stage")) : "?",
                         (long long)json_get_int(json_get(sg, "steps_per_sec")),
                         (long long)json_get_int(json_get(sg, "cursor")));
            if (n > 0) len += (size_t)n;
        }
    }

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

void zcl_native_handle_ops_producer_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
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
        return;
    }
    if (strlen(datadir) >= CONSENSUS_STATE_PRODUCER_DATADIR_MAX) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "producer datadir must be at most 1023 bytes",
                               "ops.debug.producer");
        return;
    }

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
    int64_t rate_sample_age_seconds = -1;
    int64_t rate_stale_after_seconds = -1;
    int64_t rate_future_skew_seconds = 0;
    bool rate_sample_clock_valid = false;
    bool durable_rate_recent = false;
    if (st.durable_rate_available) {
        int64_t now = platform_time_wall_unix();
        int64_t interval = st.rate_newer_time_unix - st.rate_older_time_unix;
        rate_stale_after_seconds = interval > 43200 ? 86400 : interval * 2;
        if (rate_stale_after_seconds < 300)
            rate_stale_after_seconds = 300;
        if (now > 0 && st.rate_newer_time_unix > now) {
            rate_future_skew_seconds = st.rate_newer_time_unix - now;
            rate_sample_clock_valid = rate_future_skew_seconds <=
                NC_PRODUCER_RATE_FUTURE_SKEW_TOLERANCE_SECONDS;
            if (rate_sample_clock_valid)
                rate_sample_age_seconds = 0;
        } else if (now > 0) {
            rate_sample_clock_valid = true;
            rate_sample_age_seconds = now - st.rate_newer_time_unix;
        }
        durable_rate_recent = rate_sample_clock_valid &&
            rate_sample_age_seconds <= rate_stale_after_seconds;
    }
    bool target_reached = height >= 0 && target_height >= 0 &&
                          height >= target_height;
    bool eta_available = target_reached ||
        (st.durable_rate_available && durable_rate_recent &&
         height >= 0 && target_height >= 0);
    int64_t eta_seconds = eta_available && remaining > 0
        ? (remaining * INT64_C(1000) +
           st.rate_blocks_per_second_milli - 1) /
              st.rate_blocks_per_second_milli
        : eta_available ? 0 : -1;

    char t[2048];
    if (!st.progress_kv_present) {
        (void)snprintf(t, sizeof(t),
                       "producer=%s state=not_started height=unknown",
                       datadir);
    } else if (eta_available && st.durable_rate_available) {
        int64_t rate_whole = st.rate_blocks_per_second_milli / 1000;
        int64_t rate_tenth =
            (st.rate_blocks_per_second_milli % 1000) / 100;
        (void)snprintf(
            t, sizeof(t),
            "producer=%s receipt=%s height=%lld target=%lld remaining=%lld "
            "rate=%lld.%lldblk/s eta=%llds",
            datadir, receipt_state, (long long)height,
            (long long)target_height, (long long)remaining,
            (long long)rate_whole, (long long)rate_tenth,
            (long long)eta_seconds);
    } else if (eta_available) {
        (void)snprintf(t, sizeof(t),
                       "producer=%s receipt=%s height=%lld target=%lld "
                       "remaining=0 rate=unknown eta=0s",
                       datadir, receipt_state, (long long)height,
                       (long long)target_height);
    } else {
        (void)snprintf(t, sizeof(t),
                       "producer=%s receipt=%s height=%lld target=%lld "
                       "rate=unknown eta=unknown",
                       datadir, receipt_state, (long long)height,
                       (long long)target_height);
    }

    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_bool(&reply->data, "progress_kv_present",
                            st.progress_kv_present);
    (void)json_push_kv_str(&reply->data, "receipt_state", receipt_state);
    (void)json_push_kv_bool(&reply->data, "session_open", st.session_open);
    (void)json_push_kv_bool(&reply->data, "receipt_finalized",
                            st.receipt_finalized);
    (void)json_push_kv_int(&reply->data, "height", height);
    (void)json_push_kv_int(&reply->data, "utxo_apply_cursor",
                           st.utxo_apply_cursor);
    (void)json_push_kv_int(&reply->data, "tip_finalize_cursor",
                           st.tip_finalize_cursor);
    (void)json_push_kv_int(&reply->data, "fold_cursor", st.fold_cursor);
    (void)json_push_kv_str(&reply->data, "receipt_schema",
                           st.receipt_schema);
    (void)json_push_kv_str(&reply->data, "source_tree_root",
                           st.source_tree_root);
    (void)json_push_kv_str(&reply->data, "source_epoch_digest",
                           st.source_epoch_digest);
    (void)json_push_kv_str(&reply->data, "producer_commit",
                           st.producer_commit);
    (void)json_push_kv_int(&reply->data, "validation_profile",
                           st.validation_profile);
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
                            st.durable_rate_available);
    (void)json_push_kv_bool(&reply->data, "durable_rate_recent",
                            durable_rate_recent);
    (void)json_push_kv_bool(&reply->data, "rate_sample_clock_valid",
                            rate_sample_clock_valid);
    (void)json_push_kv_int(
        &reply->data, "rate_future_skew_tolerance_seconds",
        NC_PRODUCER_RATE_FUTURE_SKEW_TOLERANCE_SECONDS);
    (void)json_push_kv_str(&reply->data, "rate_source",
                           "consensus.db:utxo_apply_log.applied_at");
    if (st.durable_rate_available) {
        (void)json_push_kv_int(&reply->data, "rate_older_height",
                               st.rate_older_height);
        (void)json_push_kv_int(&reply->data, "rate_older_time_unix",
                               st.rate_older_time_unix);
        (void)json_push_kv_int(&reply->data, "rate_newer_height",
                               st.rate_newer_height);
        (void)json_push_kv_int(&reply->data, "rate_newer_time_unix",
                               st.rate_newer_time_unix);
        (void)json_push_kv_int(&reply->data,
                               "rate_blocks_per_second_milli",
                               st.rate_blocks_per_second_milli);
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

/* ── ops.rom native leaf ─────────────────────────────────────────────────
 * Dispatches `dumpstate rom_compile` (app/jobs/src/rom_compile_status.c —
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
static bool nc_ops_rom_try_watch(const char *const *words, size_t count,
                                 size_t consumed, const char *cli_datadir,
                                 int *rc)
{
    bool want_watch = false, want_once = false;
    int interval_ms = 2000;
    const char *offline_datadir = NULL;

    for (size_t i = consumed; i < count; i++) {
        const char *w = words[i];
        if (!w)
            continue;
        if (strcmp(w, "--watch") == 0) {
            want_watch = true;
        } else if (strcmp(w, "--once") == 0) {
            want_once = true;
        } else if (strncmp(w, "--interval=", 11) == 0) {
            int secs = atoi(w + 11);
            if (secs > 0)
                interval_ms = secs * 1000;
        } else if (strncmp(w, "--datadir=", 10) == 0) {
            offline_datadir = w + 10;
        }
    }

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

    if (offline_datadir && offline_datadir[0]) {
        *rc = rom_watch_run(nc_rom_fetch_offline, (void *)offline_datadir,
                            &opts);
    } else if (offline_datadir) {
        /* --datadir= with an empty value: fall back to the CLI default if any,
         * else run live. */
        if (cli_datadir && cli_datadir[0])
            *rc = rom_watch_run(nc_rom_fetch_offline, (void *)cli_datadir,
                                &opts);
        else
            *rc = rom_watch_run(nc_rom_fetch_live, NULL, &opts);
    } else {
        *rc = rom_watch_run(nc_rom_fetch_live, NULL, &opts);
    }
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

/* Persistent machine interface. The normal registry handler returns one
 * resumable event; --format=jsonl keeps this one local process attached and
 * advances the same cursor forever. It performs no build/proof/storage/network
 * work and exits naturally when the subscriber closes stdout. */
static bool nc_dev_events_try_stream(const char *const *words, size_t count,
                                     size_t consumed, int *rc)
{
    bool jsonl = false;
    int64_t after = 0, heartbeat_ms = 15000;
    for (size_t i = consumed; i < count; i++) {
        const char *word = words[i];
        if (!word) continue;
        if (strcmp(word, "--format=jsonl") == 0) {
            jsonl = true;
        } else if (strncmp(word, "--after=", 8) == 0) {
            if (!nc_parse_i64_exact(word + 8, 0, INT64_MAX, &after)) {
                nc_print_error("dev.loop.events", "INVALID_SUBSCRIPTION_CURSOR",
                               "normalize", "--after must be nonnegative",
                               "after", "", "", "");
                *rc = ZCL_COMMAND_EXIT_INVALID;
                return true;
            }
        } else if (strncmp(word, "--heartbeat-ms=", 15) == 0) {
            if (!nc_parse_i64_exact(word + 15, 100, 300000,
                                    &heartbeat_ms)) {
                nc_print_error("dev.loop.events", "INVALID_SUBSCRIPTION_CURSOR",
                               "normalize",
                               "--heartbeat-ms must be 100..300000",
                               "heartbeat_ms", "", "", "");
                *rc = ZCL_COMMAND_EXIT_INVALID;
                return true;
            }
        }
    }
    if (!jsonl) return false;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    if (!root || !root[0]) root = ".";
    for (;;) {
        char body[16384], why[160] = {0};
        size_t body_len = 0;
        int64_t cursor = after;
        enum zcl_devloop_state_lookup lookup =
            zcl_devloop_cycle_state_wait_after(
                root, after, (int)heartbeat_ms, body, sizeof(body),
                &body_len, &cursor, why, sizeof(why));
        if (lookup != ZCL_DEVLOOP_STATE_FOUND)
            cursor = after;
        if (lookup == ZCL_DEVLOOP_STATE_INVALID) {
            nc_print_error("dev.loop.events", "DEV_EVENT_STREAM_INVALID",
                           "read", "event cursor or SHA3 validation failed",
                           why[0] ? why : "event_stream_invalid", "", "", "");
            *rc = ZCL_COMMAND_EXIT_INTERNAL;
            return true;
        }
        struct json_value line;
        json_init(&line); json_set_object(&line);
        bool ok = json_push_kv_str(&line, "schema", "zcl.dev_loop_event.v1") &&
            json_push_kv_int(&line, "cursor", cursor);
        if (lookup == ZCL_DEVLOOP_STATE_FOUND) {
            struct json_value cycle;
            json_init(&cycle);
            ok = ok && json_read(&cycle, body, body_len) &&
                 cycle.type == JSON_OBJ;
            const char *phase = ok
                ? json_get_str(json_get(&cycle, "phase")) : NULL;
            const char *status = ok
                ? json_get_str(json_get(&cycle, "status")) : NULL;
            bool interrupting =
                (phase && (strcmp(phase, "STORY_RED") == 0 ||
                           strcmp(phase, "COMPILE_RED") == 0 ||
                           strcmp(phase, "FOCUSED_RED") == 0)) ||
                (status && (strcmp(status, "story_red") == 0 ||
                            strcmp(status, "compile_red") == 0 ||
                            strcmp(status, "focused_red") == 0 ||
                            strcmp(status, "rejected") == 0));
            ok = ok && json_push_kv_str(&line, "kind",
                phase && phase[0] ? phase : "CYCLE_EVENT") &&
                json_push_kv_bool(&line, "interrupting", interrupting);
            if (ok && interrupting) {
                struct json_value capsule;
                json_init(&capsule); json_set_object(&capsule);
                ok = json_push_kv_str(&capsule, "schema",
                                      "zcl.dev_diagnostic_capsule.v1");
                static const struct { const char *from; const char *to; } f[] = {
                    {"phase", "phase"}, {"edit_epoch", "edit_epoch"},
                    {"source_tu", "source_tu"},
                    {"failure_capsule", "message"},
                    {"compiler_output", "detail"},
                };
                for (size_t j = 0; ok && j < sizeof(f) / sizeof(f[0]); j++) {
                    const struct json_value *v = json_get(&cycle, f[j].from);
                    ok = !v || json_push_kv(&capsule, f[j].to, v);
                }
                if (ok) ok = json_push_kv(&line, "diagnostic", &capsule);
                json_free(&capsule);
            }
            if (ok) ok = json_push_kv(&line, "event", &cycle);
            json_free(&cycle);
            after = cursor;
        } else {
            ok = ok && json_push_kv_str(&line, "kind", "HEARTBEAT") &&
                json_push_kv_bool(&line, "interrupting", false);
        }
        char encoded[20000];
        size_t encoded_len = ok ? json_write(&line, encoded,
                                              sizeof(encoded) - 2) : 0;
        json_free(&line);
        if (!encoded_len || fwrite(encoded, 1, encoded_len, stdout) !=
                                encoded_len ||
            fputc('\n', stdout) == EOF || fflush(stdout) != 0) {
            *rc = encoded_len ? ZCL_COMMAND_EXIT_OK
                              : ZCL_COMMAND_EXIT_INTERNAL;
            return true;
        }
    }
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

static void nc_print_error(const char *command, const char *code,
                           const char *phase, const char *message,
                           const char *evidence,
                           const char *next_command,
                           const char *next_input, const char *next_reason)
{
    struct json_value root, error, blockers, next, item;
    json_init(&root);
    json_init(&error);
    json_init(&blockers);
    json_init(&next);
    json_init(&item);
    json_set_object(&root);
    json_set_object(&error);
    json_set_array(&blockers);
    json_set_array(&next);
    json_set_object(&item);

    (void)json_push_kv_str(&root, "schema", "zcl.result.v1");
    (void)json_push_kv_str(&root, "command", command ? command : "");
    (void)json_push_kv_bool(&root, "ok", false);
    (void)json_push_kv_str(&root, "status", "failed");
    (void)json_push_kv_str(&root, "request_id", "local-cli");
    (void)json_push_kv_int(&root, "elapsed_us", 0);
    (void)json_push_kv_str(&error, "code", code);
    (void)json_push_kv_str(&error, "error_code", code);
    (void)json_push_kv_str(&error, "message", message);
    (void)json_push_kv_str(&error, "phase", phase);
    (void)json_push_kv_str(&error, "current_state", "REQUEST_FAILED");
    (void)json_push_kv_bool(&error, "retryable", false);
    (void)json_push_kv_bool(&error, "human_action_required", true);
    (void)json_push_kv_str(&error, "next_action",
                           next_reason && next_reason[0]
                               ? next_reason
                               : "follow the first next command");
    (void)json_push_kv_bool(&error, "mutated", false);
    if (evidence && evidence[0])
        (void)json_push_kv_str(&error, "evidence", evidence);
    (void)json_push_kv(&error, "blockers", &blockers);
    (void)json_push_kv(&root, "error", &error);
    if (next_command && next_command[0]) {
        struct json_value parsed;
        if (next_input && next_input[0] &&
            json_read(&parsed, next_input, strlen(next_input)) &&
            parsed.type == JSON_OBJ &&
            nc_next_input_valid(command, next_command, &parsed)) {
            (void)json_push_kv_str(&item, "command", next_command);
            (void)json_push_kv(&item, "input", &parsed);
            (void)json_push_kv_str(&item, "reason",
                                   next_reason ? next_reason : "");
            (void)json_push_back(&next, &item);
        }
        json_free(&parsed);
    }
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
    json_free(&blockers);
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
        n = json_write(&reply.data, out, sizeof(out));
        if (reply.exit_code != ZCL_COMMAND_EXIT_OK) {
            nc_print_error(spec->path, "UNKNOWN_PATH", "resolve",
                           "no such command path", arg ? arg : "",
                           "discover.help", "{}", "browse the tree first");
            zcl_command_reply_free(&reply);
            json_free(&input);
            return ZCL_COMMAND_EXIT_INVALID;
        }
        zcl_command_reply_free(&reply);
        json_free(&input);
    }
    if (n == 0) {
        if (strcmp(spec->path, "discover.describe") == 0) {
            /* "The answer did not fit" is NOT "there is no such command".
             * describe_json returns 0 for both, and reporting the second for
             * the first cost core.wallet.recovery.restore its entire written
             * contract: the leaf dispatched fine, help and search both listed
             * it, and `discover describe` on it answered UNKNOWN_PATH. Resolve
             * the path ourselves so the two can be told apart — same shape as
             * nc_emit_menu's MENU_BUDGET. check-describe-budget keeps every
             * leaf under the budget; this is what the operator sees if one
             * ever gets through. */
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
    nc_print_doc(out, spec->path);
    return ZCL_COMMAND_EXIT_OK;
}

/* Operator-UX prose leaves: default output is a human/AI-readable text block
 * rendered from reply->data; --format=json emits the structured envelope. */
static bool nc_is_prose_leaf(const char *path)
{
    return path &&
           (strcmp(path, "status") == 0 ||
            strcmp(path, "ops.debug.explain") == 0 ||
            strcmp(path, "ops.debug.profile") == 0 ||
            strcmp(path, "ops.debug.producer") == 0 ||
            strcmp(path, "ops.debug.rom") == 0 ||
            strcmp(path, "core.status.brief") == 0);
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

    /* Typed-blocker-registry count + head, from the same authority as
     * `dumpstate blocker`, shown beside the headline `blocker=` so the two
     * operator surfaces can never name disjoint truths. Rendered only when the
     * node exports them (older nodes omit the fields; a missing field must not
     * fabricate a zero — see the sparse-body contract test). */
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

    /* Every field above but the last appends its own trailing separator
     * space; trim it defensively (also covers a mid-line snprintf that hit
     * the buffer edge). Then hard-clamp to the 200-byte contract — real
     * fields never get near this, but the CLI must never emit a line the
     * spec forbids. */
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

void zcl_native_status_journey_render(const struct json_value *d, char *buf,
                                      size_t cap)
{
    if (!buf || cap == 0)
        return;
    const char *primary = d
        ? json_get_str(json_get(d, "primary_blocker")) : NULL;
    const char *error_code = d
        ? json_get_str(json_get(d, "error_code")) : NULL;
    const char *blocker = primary && primary[0] &&
                                  strcmp(primary, "none") != 0 &&
                                  strcmp(primary, "unknown") != 0
        ? primary : error_code;
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
    if (spendable && spendable->type == JSON_INT)
        (void)snprintf(spendable_text, sizeof(spendable_text), "%lld",
                       (long long)json_get_int(spendable));
    if (pending && pending->type == JSON_INT)
        (void)snprintf(pending_text, sizeof(pending_text), "%lld",
                       (long long)json_get_int(pending));
    if (reserved && reserved->type == JSON_INT)
        (void)snprintf(reserved_text, sizeof(reserved_text), "%lld",
                       (long long)json_get_int(reserved));
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

    enum { NC_FIELD_MAX = 24, NC_FIELD_NAME_MAX = 65 };
    char names[NC_FIELD_MAX][NC_FIELD_NAME_MAX];
    size_t nnames = 0;
    const char *p = fields_csv;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',') p++;
        const char *end = p;
        while (end > start && end[-1] == ' ') end--;
        size_t flen = (size_t)(end - start);
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
        for (size_t j = 0; j < nnames; j++) {
            if (strcmp(names[j], names[nnames]) == 0) {
                if (err) snprintf(err, err_cap, "duplicate field '%s'",
                                 names[nnames]);
                return false;
            }
        }
        nnames++;
    }
    if (nnames == 0) {
        if (err) snprintf(err, err_cap, "field= requires at least one name");
        return false;
    }

    /* Validate every name exists before rendering anything — never a
     * partial selection. */
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

    size_t len = 0;
    for (size_t i = 0; i < nnames; i++) {
        const struct json_value *v = json_get(obj, names[i]);
        char valbuf[4096];
        switch (v->type) {
        case JSON_BOOL:
            snprintf(valbuf, sizeof(valbuf), "%s",
                    json_get_bool(v) ? "true" : "false");
            break;
        case JSON_INT:
            snprintf(valbuf, sizeof(valbuf), "%lld",
                    (long long)json_get_int(v));
            break;
        case JSON_REAL:
            snprintf(valbuf, sizeof(valbuf), "%g", json_get_real(v));
            break;
        case JSON_STR: {
            const char *s = json_get_str(v);
            snprintf(valbuf, sizeof(valbuf), "%s", s ? s : "");
            break;
        }
        case JSON_NULL:
            snprintf(valbuf, sizeof(valbuf), "null");
            break;
        case JSON_ARR:
        case JSON_OBJ:
        default: {
            /* json_write returns the bytes NEEDED — >= cap means the value
             * was cut mid-string. Never emit a truncated container: fail
             * typed so the caller reaches for --format=json instead. */
            size_t need = json_write(v, valbuf, sizeof(valbuf));
            if (need >= sizeof(valbuf)) {
                if (err)
                    snprintf(err, err_cap,
                             "field '%s' is a %zu-byte container — too large "
                             "for key=value rendering; use --format=json",
                             names[i], need);
                return false;
            }
            break;
        }
        }
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

/* ── CLI UX contract: unrecognized-command diagnostic ────────────────
 * See docs/NATIVE_COMMAND_INTERFACE.md "CLI UX contract". Pure text
 * builder — src/main.c's raw-RPC fallback calls this once it has confirmed
 * (via the RPC layer's method-not-found response) that `method` is not a
 * real command, then fprintf's the result to stderr. */
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
    if (matches && matches->type == JSON_ARR && matches->num_children > 0) {
        n = snprintf(out + len, out_cap - len, "did you mean:");
        if (n > 0 && (size_t)n < out_cap - len) {
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
        }
    }
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

int zcl_native_command_main(const char *root_word, const char *const *args,
                            int nargs, const char *datadir, int rpc_port,
                            enum chain_network network,
                            bool datadir_explicit)
{
    if (!root_word || !root_word[0])
        return ZCL_COMMAND_EXIT_INVALID;
    /* This one-shot process never runs resident boot, but package and wallet
     * handlers perform node-bound validation locally. Keep their selected
     * chain identical to the explicitly targeted resident. */
    g_native_network = network;
    g_native_datadir_explicit = datadir_explicit;
    chain_params_select(network);
    zcl_native_bridge_bind_rpc(datadir, rpc_port);

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

    /* Word list = root + args (flags included). Resolution stops at the first
     * flag or dotted/pathy word — so a dotted FIRST token (the canonical
     * `zcode.science.study.list` form the docs and examples use) is split
     * into path segments here, making it identical to the spaced form. */
    char root_split[ZCL_COMMAND_MAX_PATH];
    const char *words[NC_MAX_WORDS];
    size_t count = 0;
    if (strchr(root_word, '.')) {
        size_t rl = strlen(root_word);
        if (rl >= sizeof(root_split)) {
            nc_print_error(root_word, "UNKNOWN_COMMAND", "resolve",
                           "command path too long", root_word,
                           "", "", "");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        memcpy(root_split, root_word, rl + 1);
        char *seg = root_split;
        while (seg && *seg && count < NC_MAX_WORDS) {
            char *dot = strchr(seg, '.');
            if (dot)
                *dot = 0;
            words[count++] = seg;
            seg = dot ? dot + 1 : NULL;
        }
    } else {
        words[count++] = root_word;
    }
    for (int i = 0; i < nargs && count < NC_MAX_WORDS; i++)
        words[count++] = args[i];

    size_t consumed = 0;
    bool was_alias = false;
    char invoked[ZCL_COMMAND_MAX_PATH];
    const struct zcl_command_spec *spec = zcl_command_registry_resolve_words(
        reg, words, count, &consumed, &was_alias, invoked, sizeof(invoked));
    if (!spec) {
        nc_print_error_next_string(
            root_word, "UNKNOWN_COMMAND", "resolve", "unknown command root",
            root_word, "discover.search", "query", root_word,
            "search for the intended command");
        return ZCL_COMMAND_EXIT_INVALID;
    }

    /* ops.rom watch mode: intercept --watch / --once / --interval=<secs> /
     * --datadir=<dir> BEFORE the flag parser below (ops.debug.rom takes empty
     * input, so those flags would otherwise be rejected as unknown keys). When
     * one is present this runs the redraw loop and returns its exit code. */
    if (strcmp(spec->path, "ops.debug.rom") == 0) {
        int rc = 0;
        if (nc_ops_rom_try_watch(words, count, consumed, datadir, &rc))
            return rc;
    }

#ifdef ZCL_DEV_BUILD
    if (strcmp(spec->path, "dev.loop.events") == 0) {
        int rc = 0;
        if (nc_dev_events_try_stream(words, count, consumed, &rc))
            return rc;
    }
#endif

    /* Collect the tokens the path did not consume: positionals in order and
     * value flags into a scratch object. */
    const char *positional[NC_MAX_WORDS];
    size_t npos = 0;
    struct json_value flags;
    json_init(&flags);
    json_set_object(&flags);
    const char *input_flag = NULL;
    const char *view = NULL;
    const char *side = NULL;
    const char *cursor = NULL;
    size_t budget = 0;
    size_t max_items = 0;
    bool flag_error = false;
    bool seen_input = false, seen_view = false, seen_side = false;
    bool seen_budget = false, seen_max_items = false, seen_cursor = false;
    bool seen_format = false;
    /* CLI UX contract: field selector + the bare no-arg entry point's next-
     * command hint. `field=` is accepted BOTH as a bare dash-less word (the
     * documented `z23 status field=a,b` convention) and as a normal
     * `--field=a,b` flag; both set the same field_csv. --next is
     * internal-ish (used by the bare no-arg entry point) but harmless for a
     * caller to pass directly. */
    const char *field_csv = NULL;
    bool seen_field = false;
    bool suggest_next = false;
    char flag_key[128];
    char flag_why[160] = "malformed or duplicate option";
    for (size_t i = consumed; i < count; i++) {
        const char *w = words[i];
        if (!nc_is_flag(w)) {
            if (strncmp(w, "field=", 6) == 0) {
                if (seen_field || !w[6]) {
                    flag_error = true;
                    (void)snprintf(flag_why, sizeof(flag_why),
                                  "field= requires one non-empty value and "
                                  "may appear once");
                    break;
                }
                seen_field = true;
                field_csv = w + 6;
                continue;
            }
            if (npos < NC_MAX_WORDS)
                positional[npos++] = w;
            continue;
        }
        const char *value = NULL;
        if (!nc_split_flag(w, flag_key, sizeof(flag_key), &value)) {
            flag_error = true;
            break;
        }
        if (strcmp(flag_key, "input") == 0) {
            if (seen_input || !value || !value[0]) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--input requires one non-empty value and may appear once");
                break;
            }
            seen_input = true;
            input_flag = value;
        } else if (strcmp(flag_key, "view") == 0) {
            if (seen_view || !value ||
                (strcmp(value, "summary") != 0 && strcmp(value, "normal") != 0 &&
                 strcmp(value, "full") != 0)) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--view must be summary, normal, or full and may appear once");
                break;
            }
            seen_view = true;
            view = value;
        } else if (strcmp(flag_key, "side") == 0) {
            if (seen_side || !value ||
                (strcmp(value, "input") != 0 && strcmp(value, "output") != 0)) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--side must be input or output and may appear once");
                break;
            }
            seen_side = true;
            side = value;
        } else if (strcmp(flag_key, "budget-bytes") == 0) {
            if (seen_budget ||
                !nc_parse_size_control(value, 512, ZCL_COMMAND_LIST_BUDGET,
                                       &budget)) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--budget-bytes must be in 512..%u and may appear once",
                               ZCL_COMMAND_LIST_BUDGET);
                break;
            }
            seen_budget = true;
        } else if (strcmp(flag_key, "max-items") == 0) {
            if (seen_max_items ||
                !nc_parse_size_control(value, 1, 100, &max_items)) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--max-items must be in 1..100 and may appear once");
                break;
            }
            seen_max_items = true;
        } else if (strcmp(flag_key, "cursor") == 0) {
            if (seen_cursor || !value || !value[0] || strlen(value) > 256) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--cursor requires one value of at most 256 bytes");
                break;
            }
            seen_cursor = true;
            cursor = value;
        } else if (strcmp(flag_key, "format") == 0) {
            if (seen_format || !value || strcmp(value, "json") != 0) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "only one --format=json is implemented for bounded native results");
                break;
            }
            seen_format = true;
            g_nc_format_json = true;
        } else if (strcmp(flag_key, "field") == 0) {
            if (seen_field || !value || !value[0]) {
                flag_error = true;
                (void)snprintf(flag_why, sizeof(flag_why),
                               "--field requires one non-empty value and "
                               "may appear once");
                break;
            }
            seen_field = true;
            field_csv = value;
        } else if (strcmp(flag_key, "next") == 0) {
            suggest_next = true;
        } else if (strcmp(flag_key, "fields") == 0 ||
                   strcmp(flag_key, "quiet") == 0) {
            flag_error = true;
            (void)snprintf(flag_why, sizeof(flag_why),
                           "--%s is not implemented; refusing a silent no-op",
                           flag_key);
            break;
        } else if (!nc_set_typed_value(&flags, flag_key, value)) {
            flag_error = true;
            (void)snprintf(flag_why, sizeof(flag_why),
                           "malformed, duplicate, or out-of-range --%s value",
                           flag_key);
            break;
        }
    }
    if (flag_error) {
        json_free(&flags);
        nc_print_error_next_string(
            spec->path, "BAD_FLAG", "normalize", flag_why, spec->path,
            "discover.describe", "path", spec->path,
            "inspect the input schema");
        return ZCL_COMMAND_EXIT_INVALID;
    }

    /* Discovery leaves render their native document directly. */
    if (spec->layer == ZCL_COMMAND_LAYER_DISCOVER &&
        spec->mode != ZCL_COMMAND_MODE_BRANCH) {
        const char *arg = npos > 0 ? positional[0] : NULL;
        int rc = nc_run_discover(spec, arg, side);
        json_free(&flags);
        return rc;
    }

    /* A branch: no deeper leaf resolved. */
    if (spec->mode == ZCL_COMMAND_MODE_BRANCH) {
        if (npos > 0) {
            char attempted[ZCL_COMMAND_MAX_PATH];
            (void)snprintf(attempted, sizeof(attempted), "%s.%s", spec->path,
                           positional[0]);
            json_free(&flags);
            nc_print_error_next_string(
                attempted, "UNKNOWN_COMMAND", "resolve",
                "no such command under this branch", attempted,
                "discover.search", "query", positional[0],
                "search for the intended command");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        int rc = nc_emit_menu(spec->path);
        json_free(&flags);
        return rc;
    }

    /* A leaf: build the one JSON input object. */
    struct json_value input;
    json_init(&input);
    /* Both spellings of --input are read against the SAME per-leaf budget the
     * validator's per-key limits imply, so neither can accept a document the
     * other would refuse, and neither truncates one the validator would take.
     * NOTE for large inputs: Linux caps a single argv string at
     * MAX_ARG_STRLEN (128 KiB), so a multi-megabyte document must arrive on
     * `--input=-` (stdin) — the argv form fails in execve long before here. */
    const size_t input_budget = zcl_command_registry_input_budget_bytes(spec);
    g_native_input_from_stdin = false;
    if (input_flag) {
        if (strcmp(input_flag, "-") == 0) {
            g_native_input_from_stdin = true;
            bool oversize = false;
            char *raw = nc_read_stdin(input_budget, &oversize);
            bool ok = raw && json_read(&input, raw, strlen(raw)) &&
                      input.type == JSON_OBJ;
            free(raw);
            if (!ok) {
                json_free(&input);
                json_free(&flags);
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
                    spec->path, "BAD_INPUT", "normalize",
                    detail, spec->path,
                    "discover.schema", "path", spec->path,
                    "inspect the input schema");
                return ZCL_COMMAND_EXIT_INVALID;
            }
        } else if (strlen(input_flag) > input_budget) {
            json_free(&input);
            json_free(&flags);
            char detail[192];
            (void)snprintf(detail, sizeof(detail),
                           "--input is %zu bytes, over this command's %zu byte "
                           "input budget",
                           strlen(input_flag), input_budget);
            nc_print_error_next_string(
                spec->path, "BAD_INPUT", "normalize", detail, spec->path,
                "discover.schema", "path", spec->path,
                "inspect the input schema");
            return ZCL_COMMAND_EXIT_INVALID;
        } else if (!json_read(&input, input_flag, strlen(input_flag)) ||
                   input.type != JSON_OBJ) {
            json_free(&input);
            json_free(&flags);
            nc_print_error_next_string(
                spec->path, "BAD_INPUT", "normalize",
                "--input must be one JSON object", spec->path,
                "discover.schema", "path", spec->path,
                "inspect the input schema");
            return ZCL_COMMAND_EXIT_INVALID;
        }
    } else {
        json_set_object(&input);
    }

    /* Merge typed flags into the input object. */
    for (size_t i = 0; i < flags.num_children; i++) {
        struct json_value copy;
        json_init(&copy);
        json_copy(&copy, &flags.children[i]);
        (void)json_push_kv(&input, flags.keys[i], &copy);
        json_free(&copy);
    }
    json_free(&flags);

    /* Map positionals onto positional_keys in order. */
    if (npos > 0) {
        const char *pk = spec->positional_keys ? spec->positional_keys : "";
        size_t used = 0;
        const char *at = pk;
        for (size_t i = 0; i < npos; i++) {
            if (!at || !*at) {
                json_free(&input);
                nc_print_error_next_string(
                    spec->path, "TOO_MANY_ARGS", "normalize",
                    "more positional arguments than the leaf accepts",
                    spec->path, "discover.schema", "path", spec->path,
                    "inspect the input schema");
                return ZCL_COMMAND_EXIT_INVALID;
            }
            const char *end = strchr(at, ',');
            size_t klen = end ? (size_t)(end - at) : strlen(at);
            char key[64];
            if (klen >= sizeof(key)) {
                json_free(&input);
                nc_print_error(spec->path, "BAD_SCHEMA", "normalize",
                               "positional key too long", spec->path, "", "",
                               "");
                return ZCL_COMMAND_EXIT_INTERNAL;
            }
            memcpy(key, at, klen);
            key[klen] = 0;
            if (!nc_set_typed_value(&input, key, positional[i])) {
                json_free(&input);
                nc_print_error(spec->path, "BAD_INPUT", "normalize",
                               "could not set positional argument", key, "",
                               "", "");
                return ZCL_COMMAND_EXIT_INTERNAL;
            }
            used++;
            at = end ? end + 1 : NULL;
        }
        (void)used;
    }

    /* Reject unknown keys and duplicates before any side effect. */
    if (!zcl_command_registry_input_validate(spec, &input, why, sizeof(why))) {
        json_free(&input);
        nc_print_error_next_string(
            spec->path, "INVALID_INPUT", "normalize", why, spec->path,
            "discover.schema", "path", spec->path,
            "inspect the input schema");
        return ZCL_COMMAND_EXIT_INVALID;
    }

    /* The frozen grammar permits paging/view controls inside --input as well
     * as top-level flags. Normalize both spellings to the one request object,
     * and reject ambiguous double specification. */
    char input_cursor[64];
    const struct json_value *input_view = json_get(&input, "view");
    if (input_view) {
        if (seen_view) {
            json_free(&input);
            nc_print_error_next_string(
                spec->path, "DUPLICATE_CONTROL", "normalize",
                "view was supplied both inside --input and as a flag", "view",
                "discover.schema", "path", spec->path,
                "supply each response control once");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        view = json_get_str(input_view);
    }
    const struct json_value *input_max_items = json_get(&input, "max_items");
    if (input_max_items) {
        if (seen_max_items) {
            json_free(&input);
            nc_print_error_next_string(
                spec->path, "DUPLICATE_CONTROL", "normalize",
                "max_items was supplied both inside --input and as a flag",
                "max_items", "discover.schema", "path", spec->path,
                "supply each response control once");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        max_items = (size_t)json_get_int(input_max_items);
    }
    const struct json_value *input_cursor_value = json_get(&input, "cursor");
    if (input_cursor_value) {
        if (seen_cursor) {
            json_free(&input);
            nc_print_error_next_string(
                spec->path, "DUPLICATE_CONTROL", "normalize",
                "cursor was supplied both inside --input and as a flag",
                "cursor", "discover.schema", "path", spec->path,
                "supply each response control once");
            return ZCL_COMMAND_EXIT_INVALID;
        }
        if (input_cursor_value->type == JSON_STR) {
            cursor = json_get_str(input_cursor_value);
        } else {
            (void)snprintf(input_cursor, sizeof(input_cursor), "%lld",
                           (long long)json_get_int(input_cursor_value));
            cursor = input_cursor;
        }
    }

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

    /* One registry leaf currently declares the 16 KiB extended-list budget.
     * The dispatcher must offer the largest declared bounded envelope; the
     * registry still enforces each leaf's own (usually smaller) budget. */
    char out[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(
        reg, spec, &ctx, &input, was_alias, invoked, view, budget, max_items,
        cursor, out, sizeof(out), &exit_code);
    g_native_input_from_stdin = false;
    json_free(&input);
    if (n == 0) {
        nc_print_error(spec->path, "EXECUTE_FAILED", "serialize",
                       "handler produced no bounded result", spec->path, "",
                       "", "");
        return ZCL_COMMAND_EXIT_INTERNAL;
    }

    /* CLI UX contract: field selector. `field=`/--field= wins over prose and
     * --format=json alike — a caller who named fields wants exactly those
     * lines, nothing else. Selects out of reply.data, the SAME object the
     * JSON envelope and the prose renderer below both read; no second data
     * path. Unknown field name -> the frozen `error=... detail=... try=...`
     * one-line error contract (docs/NATIVE_COMMAND_INTERFACE.md). */
    if (field_csv) {
        struct json_value env;
        bool handled = false;
        if (json_read(&env, out, n) && env.type == JSON_OBJ) {
            const struct json_value *data = json_get(&env, "data");
            char sel[ZCL_COMMAND_EXTENDED_LIST_BUDGET + 1];
            char selerr[320];
            if (data && zcl_native_render_field_selection(
                            data, field_csv, sel, sizeof(sel), selerr,
                            sizeof(selerr))) {
                fputs(sel, stdout);
                handled = true;
            } else {
                fprintf(stderr,
                       "error=UNKNOWN_FIELD detail=%s try=%s\n",
                       data ? selerr : "this result has no selectable data",
                       spec->path);
                json_free(&env);
                return ZCL_COMMAND_EXIT_INVALID;
            }
        }
        json_free(&env);
        if (handled)
            return (int)exit_code;
    }

    /* Prose leaves render a human/AI-readable text block by default; an
     * explicit --format=json (seen_format) keeps the structured envelope. On a
     * failed result (no data.text) fall back to the JSON envelope so the
     * structured error/next-action is never hidden. */
    if (!seen_format && nc_is_prose_leaf(spec->path)) {
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
                return (int)exit_code;
            }
        }
        json_free(&env);
    }

    nc_print_doc(out, spec->path);
    return (int)exit_code;
}
