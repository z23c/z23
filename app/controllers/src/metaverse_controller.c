/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the registry-owned `metaverse` tree. Two independent
 * leaf groups share this file because they share one command root:
 *
 * `metaverse.agent.*` — the confined-agent-broker read half: parse,
 * authorize the shape of the input, call ONE service, render. No broker
 * logic lives here — the confinement, the grant, and the receipt chain are
 * all in lib/session/agent_broker.h, and this file only reads what the
 * broker recorded. Both leaves are read-only and create nothing, including
 * the directory they are pointed at. A `dir` that does not exist is a named
 * refusal, never a side effect.
 *
 * `metaverse.property.*` — the property-catalog read half:
 * `metaverse property list` and `metaverse property show`. THE INVARIANT OF
 * THIS HALF: it holds no ownership logic and writes nothing. Every field it
 * renders comes from ONE call into the property catalog projection
 * (services/property_catalog.h), which in turn asks each property kind's
 * own authoritative model. There is no catalog table to fall out of date
 * with the chain, the wallet, or the package store, because the projection
 * keeps nothing between calls. These are READ leaves in the strict sense:
 * the catalog reaches store bytes by path and never opens a handle whose
 * open() mutates the datadir. `datadir` resolution follows the zcode
 * precedent: explicit input.datadir wins, else the CLI's --datadir, else a
 * named MISSING_DATADIR refusal — this surface never silently falls back to
 * a global.
 *
 * Bound by config/commands/metaverse.def.
 */

#include "command/native_command.h"

#include "base/log_macros.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "metaverse/property_id.h"
#include "metaverse/property_view.h"
#include "models/database.h"
#include "services/metaverse_agent_service.h"
#include "services/property_catalog.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MV_TAG "native.metaverse"

/* The rendered documents are bounded by the leaves' ZCL_COMMAND_LIST_BUDGET;
 * this buffer is the slack above it so a document that would exceed the budget
 * is reported as too large rather than silently truncated. */
#define MV_DOC_MAX 16384

static char *mv_money_rpc(const char *datadir, int rpc_port,
                          const char *method, const char *params,
                          long connect_ms, long total_ms)
{
    return node_rpc_call_at_deadline(datadir, rpc_port, method, params,
                                     connect_ms, total_ms);
}

static void mv_fail(struct zcl_command_reply *reply,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *message, const char *evidence)
{
    enum zcl_command_status status =
        exit_code == ZCL_COMMAND_EXIT_BLOCKED ? ZCL_COMMAND_STATUS_BLOCKED
                                              : ZCL_COMMAND_STATUS_FAILED;
    zcl_command_reply_fail(reply, status, exit_code, code, "handle", false,
                           false, message, evidence ? evidence : "");
}

/* Map the service's refusal onto the command error contract. The service's own
 * message becomes the evidence, so the operator sees which rule was broken and
 * not just the directory they typed. */
static void mv_fail_result(struct zcl_command_reply *reply,
                           const struct zcl_result *r)
{
    switch (r->code) {
    case MVS_ERR_NOT_A_DIR:
        mv_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NOT_A_DIR",
                "no such broker directory — run `zclassic23 "
                "--metaverse-broker --broker-dir=DIR` first, or point --dir at "
                "the directory a broker already used",
                r->message);
        return;
    case MVS_ERR_RENDER_FAILED:
        mv_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RENDER_FAILED",
                "the document did not fit this leaf's output budget; lower "
                "--limit", r->message);
        return;
    default:
        mv_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_ARGS",
                "dir must be a non-empty absolute path", r->message);
        return;
    }
}

/* Read and shape-check the shared `dir` input. Returns NULL after failing the
 * reply when it is absent. */
static const char *mv_dir(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply)
{
    const char *dir = json_get_str(json_get(request->input, "dir"));
    if (!dir || !dir[0]) {
        mv_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_DIR",
                "dir is required: the broker directory to read", "dir");
        return NULL;
    }
    return dir;
}

/* Fold a rendered JSON document into reply->data. The service already produced
 * valid JSON; a parse failure here would mean the service and this file
 * disagree, which is an internal fault worth naming rather than papering. */
static bool mv_emit(struct zcl_command_reply *reply, const char *doc,
                    size_t len)
{
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, doc, len)) {
        json_free(&v);
        mv_fail(reply, ZCL_COMMAND_EXIT_FAILED, "INTERNAL",
                "the broker document did not re-parse as JSON", "");
        LOG_FAIL(MV_TAG, "service produced %zu bytes that do not parse", len);
    }
    json_copy(&reply->data, &v);
    json_free(&v);
    return true;
}

/* ── metaverse.agent.status ─────────────────────────────────────────────── */
void zcl_native_handle_metaverse_agent_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *dir = mv_dir(request, reply);
    if (!dir)
        return;

    char doc[MV_DOC_MAX];
    size_t n = 0;
    struct zcl_result r =
        metaverse_agent_service_status(dir, doc, sizeof(doc), &n);
    if (!r.ok) {
        mv_fail_result(reply, &r);
        return;
    }
    (void)mv_emit(reply, doc, n);
}

/* ── metaverse.agent.money ─────────────────────────────────────────────── */
void zcl_native_handle_metaverse_agent_money(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *dir = mv_dir(request, reply);
    if (!dir)
        return;
    char doc[MV_DOC_MAX];
    size_t n = 0;
    struct zcl_result r =
        metaverse_agent_service_money(dir, mv_money_rpc,
                                      doc, sizeof(doc), &n);
    if (!r.ok) {
        mv_fail_result(reply, &r);
        return;
    }
    (void)mv_emit(reply, doc, n);
}

/* ── metaverse.agent.liquidity ─────────────────────────────────────────── */
void zcl_native_handle_metaverse_agent_liquidity(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *dir = mv_dir(request, reply);
    if (!dir)
        return;
    const char *scope = json_get_str(json_get(request->input, "wallet_scope"));
    int64_t recipient_value_zat = json_get_int(
        json_get(request->input, "recipient_value_zat"));
    int64_t maximum_fee_zat = json_get_int(
        json_get(request->input, "maximum_fee_zat"));
    int64_t concurrency = json_get_int(json_get(request->input,
                                                "concurrency"));
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0) ||
        recipient_value_zat <= 0 || maximum_fee_zat < 0 ||
        concurrency < 1 || concurrency > 50) {
        mv_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_LIQUIDITY_REQUEST",
                "wallet_scope dev|prod, positive recipient_value_zat, "
                "non-negative maximum_fee_zat, and concurrency 1..50 are required",
                "wallet_scope,recipient_value_zat,maximum_fee_zat,concurrency");
        return;
    }
    char doc[MV_DOC_MAX];
    size_t n = 0;
    struct zcl_result r = metaverse_agent_service_liquidity(
        dir, scope, recipient_value_zat, maximum_fee_zat, (int)concurrency,
        mv_money_rpc, doc, sizeof(doc), &n);
    if (!r.ok) {
        mv_fail_result(reply, &r);
        return;
    }
    (void)mv_emit(reply, doc, n);
}

/* ── metaverse.agent.audit ──────────────────────────────────────────────── */
void zcl_native_handle_metaverse_agent_audit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *dir = mv_dir(request, reply);
    if (!dir)
        return;

    int64_t limit = json_get_int(json_get(request->input, "limit"));
    if (limit < 0 || limit > 200) {
        mv_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_LIMIT",
                "limit must be between 0 (default) and 200", "limit");
        return;
    }

    char doc[MV_DOC_MAX];
    size_t n = 0;
    struct zcl_result r =
        metaverse_agent_service_audit(dir, (size_t)limit, doc, sizeof(doc), &n);
    if (!r.ok) {
        mv_fail_result(reply, &r);
        return;
    }
    (void)mv_emit(reply, doc, n);
}

/* ── metaverse.property.list / metaverse.property.show ─────────────────── */

#define MV_CMD_ITEM_CAP_DEFAULT 16u

static void mv_catalog_sources_open(
    const char *datadir, struct property_catalog_sources *sources,
    struct sqlite3 **sql_out, struct node_db *ndb,
    char *reason, size_t reason_cap)
{
    enum zcl_node_db_ro_status st;
    char path[1200];

    memset(sources, 0, sizeof(*sources));
    sources->chain_height = -1;
    reason[0] = '\0';
    st = zcl_native_node_db_open_readonly(datadir, sql_out, ndb, path,
                                           sizeof(path));
    if (st == ZCL_NODE_DB_RO_OK) {
        sources->node_db = ndb;
        return;
    }
    switch (st) {
    case ZCL_NODE_DB_RO_ABSENT:
        snprintf(reason, reason_cap,
                 "no node.db at %.80s; chain-derived property registries have "
                 "not been folded and cannot be reported as empty", path);
        break;
    case ZCL_NODE_DB_RO_UNRECOVERED_LOG:
        snprintf(reason, reason_cap,
                 "node.db has an unrecovered WAL and cannot be read without "
                 "creating a wal-index");
        break;
    case ZCL_NODE_DB_RO_PATH_TOO_LONG:
        snprintf(reason, reason_cap, "node.db path is too long");
        break;
    case ZCL_NODE_DB_RO_UNREADABLE:
        snprintf(reason, reason_cap,
                 "node.db exists but is not readable as a SQLite database");
        break;
    case ZCL_NODE_DB_RO_NO_DATADIR:
    default:
        snprintf(reason, reason_cap, "no datadir resolved for node.db");
        break;
    }
    sources->node_db_unavailable_reason = reason;
}

static const char *mv_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

/* Explicit input.datadir wins, else the CLI's --datadir; NULL when neither
 * is set (the zcode.package.show precedent). */
static const char *mv_datadir(const struct zcl_command_request *request)
{
    const char *dd = mv_input_str(request->input, "datadir");

    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static bool mv_require_datadir(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply,
                               const char *leaf, const char **out)
{
    *out = mv_datadir(request);
    if (*out)
        return true;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                           "normalize", false, false,
                           "no datadir given (input datadir or --datadir)",
                           leaf);
    return false;
}

void zcl_native_handle_metaverse_property_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *datadir = NULL;
    const char *kind_name;
    struct property_catalog_query q;
    struct property_catalog_page *page;
    struct zcl_result r;
    const struct json_value *limit_v;
    struct property_catalog_sources sources;
    struct sqlite3 *sql = NULL;
    struct node_db ndb;
    char source_reason[192];

    if (!request || !reply)
        return;
    if (!mv_require_datadir(request, reply, "metaverse.property.list",
                            &datadir))
        return;

    memset(&q, 0, sizeof(q));
    q.limit = MV_CMD_ITEM_CAP_DEFAULT;
    limit_v = json_get(request->input, "limit");
    if (limit_v) {
        int64_t want = json_get_int(limit_v);

        if (want > 0)
            q.limit = (size_t)want;
    }
    kind_name = mv_input_str(request->input, "kind");
    if (kind_name && kind_name[0]) {
        q.kind = metaverse_kind_from_name(kind_name);
        if (!metaverse_kind_valid(q.kind)) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_KIND",
                                   "normalize", false, false,
                                   "kind must be one of the property kinds "
                                   "the catalog enumerates",
                                   kind_name);
            return;
        }
    }

    page = property_catalog_page_new();
    if (!page) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "execute",
                               false, false,
                               "the catalog page could not be allocated",
                               "metaverse.property.list");
        return;
    }
    memset(&sources, 0, sizeof(sources));
    memset(&ndb, 0, sizeof(ndb));
    sources.chain_height = -1;
    if (q.kind == METAVERSE_KIND_UNKNOWN ||
        q.kind == METAVERSE_KIND_ZNAM_NAME ||
        q.kind == METAVERSE_KIND_ZSLP_ASSET)
        mv_catalog_sources_open(datadir, &sources, &sql, &ndb,
                                source_reason, sizeof(source_reason));
    r = property_catalog_list_with_sources(datadir, &q, &sources, page);
    zcl_native_node_db_close_readonly(&sql, &ndb);
    if (!r.ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_FAILED",
                               "execute", false, false,
                               "the property catalog projection failed",
                               r.message);
        property_catalog_page_free(page);
        return;
    }
    r = property_catalog_page_to_json(page, &reply->data);
    property_catalog_page_free(page);
    if (!r.ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                               "render", false, false,
                               "the catalog page could not be rendered",
                               r.message);
        return;
    }
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
}

void zcl_native_handle_metaverse_property_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *datadir = NULL;
    const char *id_text;
    struct metaverse_property_id id;
    struct metaverse_property_view view;
    struct zcl_result r;
    struct property_catalog_sources sources;
    struct sqlite3 *sql = NULL;
    struct node_db ndb;

    if (!request || !reply)
        return;
    if (!mv_require_datadir(request, reply, "metaverse.property.show",
                            &datadir))
        return;

    id_text = mv_input_str(request->input, "property_id");
    if (!metaverse_property_id_parse(id_text, &id)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PROPERTY_ID",
                               "normalize", false, false,
                               "property_id must be "
                               "'<kind>:<64-hex immutable root>'",
                               id_text ? id_text : "");
        return;
    }
    memset(&sources, 0, sizeof(sources));
    memset(&ndb, 0, sizeof(ndb));
    sources.chain_height = -1;
    if (id.kind == METAVERSE_KIND_ZNAM_NAME ||
        id.kind == METAVERSE_KIND_ZSLP_ASSET) {
        const char *registry = id.kind == METAVERSE_KIND_ZNAM_NAME
                                   ? "the ZNAM property registry"
                                   : "the ZSLP asset registry";

        if (!zcl_native_node_db_require_readonly(
                datadir, reply, registry, &sql, &ndb))
            return;
        sources.node_db = &ndb;
        r = property_catalog_show_with_sources(datadir, &id, &sources,
                                               &view);
        zcl_native_node_db_close_readonly(&sql, &ndb);
    } else {
        r = property_catalog_show_with_sources(datadir, &id, &sources,
                                               &view);
    }
    if (!r.ok) {
        /* A kind with no reader wired is a distinct, named refusal — never
         * an empty result that reads as "this node owns nothing". */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "KIND_UNAVAILABLE",
                               "execute", false, false,
                               "this property kind cannot be projected from "
                               "this datadir",
                               r.message);
        return;
    }
    if (!metaverse_view_to_json(&view, &reply->data)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RENDER_FAILED",
                               "render", false, false,
                               "the property view could not be rendered",
                               view.id_text);
        return;
    }
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
}

/* Both generation formats bind the property catalog's read-only command
 * leaves directly. Their service, view, codec, and adapter implementations
 * are members of the same reloadable island (config/hotswap_islands.def). */
#ifdef ZCL_HOTSWAP_GEN
#include "hotswap/hotswap.h"
static const struct zcl_hotswap_leaf_replacement k_metaverse_leaves[] = {
    { "metaverse.agent.status", zcl_native_handle_metaverse_agent_status },
    { "metaverse.agent.money", zcl_native_handle_metaverse_agent_money },
    { "metaverse.agent.liquidity",
      zcl_native_handle_metaverse_agent_liquidity },
    { "metaverse.agent.audit", zcl_native_handle_metaverse_agent_audit },
    { "metaverse.property.list", zcl_native_handle_metaverse_property_list },
    { "metaverse.property.show", zcl_native_handle_metaverse_property_show },
};
ZCL_HOTSWAP_EXPORT_LEAVES(
    k_metaverse_leaves,
    sizeof(k_metaverse_leaves) / sizeof(k_metaverse_leaves[0]))
#endif

#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
static const struct zcl_hotswap_leaf k_metaverse_module_leaves[] = {
    { "metaverse.agent.status", zcl_native_handle_metaverse_agent_status },
    { "metaverse.agent.money", zcl_native_handle_metaverse_agent_money },
    { "metaverse.agent.liquidity",
      zcl_native_handle_metaverse_agent_liquidity },
    { "metaverse.agent.audit", zcl_native_handle_metaverse_agent_audit },
    { "metaverse.property.list", zcl_native_handle_metaverse_property_list },
    { "metaverse.property.show", zcl_native_handle_metaverse_property_show },
};
static bool metaverse_module_selftest(char *error, size_t error_cap)
{
    (void)error;
    (void)error_cap;
    return true;
}
ZCL_HOTSWAP_MODULE_LEAVES(k_metaverse_module_leaves,
                          metaverse_module_selftest)
#endif
