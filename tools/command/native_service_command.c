/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `app.service` branch — the declared-service
 * surface:
 *
 *   app service list      every service declared by
 *                         engine/composition/services/bindings.def, plus the catalog's
 *                         SHA3 root
 *   app service inspect   one binding in full: the two namespaces it owns
 *                         (commands, state tables), its ZSLP token gate, the
 *                         enforced isolation flag set, and its identity
 *   app service access    evaluate one gate against the debit-correct
 *                         zslp_ledger at the binding's declared snapshot
 *                         height and explain the verdict
 *   app service status    the in-process lifecycle registry
 *
 * `list`, `inspect`, and `status` never open a database. `access` opens
 * <datadir>/node.db through zcl_native_node_db_require_readonly
 * (command/native_command.h): SQLITE_OPEN_READONLY plus PRAGMA
 * query_only=ON, so it creates, migrates and writes nothing. That is load-
 * bearing, not incidental — `datadir` is caller-supplied and falls back to
 * the CLI's resolved datadir, i.e. the operator's LIVE node when the leaf
 * is run with no arguments. This comment previously CLAIMED a read-only
 * open while the code called node_db_open(), the boot ceremony, which
 * opens READWRITE|CREATE and then creates schema, migrates, quarantines
 * the file by rename() on a failed quick_check, and DELETEs the
 * snapshot_staging rows. node.db is WAL, so a running node holding it open
 * blocked none of that.
 *
 * Pointing `access` at a datadir whose node is mid-write is safe for that
 * datadir; the read may simply give up on a locked WAL rather than block.
 *
 * These four are the REGISTRY's own leaves. A service's own leaves live under
 * its command_prefix (app.service.<name>.*) and are declared in a
 * engine/composition/commands .def like any other native command, so they inherit the
 * catalog's auth/effect/risk declaration rather than asserting their own. */

#include "command/native_command.h"

#include "config/service_binding_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/block.h"
#include "models/database.h"
#include "services/service_lifecycle.h"
#include "services/service_token_gate.h"

#include <stdio.h>
#include <string.h>

static const char *svc_input_str(const struct zcl_command_request *request,
                                 const char *key)
{
    if (!request || !request->input)
        return NULL;
    const struct json_value *v = json_get(request->input, key);
    return v ? json_get_str(v) : NULL;
}

static void svc_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", in[i]);
    out[2 * len] = '\0';
}

/* 40 lowercase-or-uppercase hex chars -> 20 bytes. */
static bool svc_parse_hash160(const char *hex, uint8_t out[20])
{
    if (!hex || strlen(hex) != 40)
        return false;
    for (size_t i = 0; i < 20; i++) {
        unsigned value = 0;
        for (size_t nibble = 0; nibble < 2; nibble++) {
            char c = hex[2 * i + nibble];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') digit = (unsigned)(c - 'a') + 10u;
            else if (c >= 'A' && c <= 'F') digit = (unsigned)(c - 'A') + 10u;
            else return false;
            value = (value << 4) | digit;
        }
        out[i] = (uint8_t)value;
    }
    return true;
}

static void svc_binding_summary_json(const struct zcl_service_binding_v1 *b,
                                     struct json_value *item)
{
    char digest_hex[65] = {0};
    uint8_t digest[32];
    if (zcl_service_binding_digest_v1(b, digest))
        svc_hex(digest, 32, digest_hex);
    (void)json_push_kv_str(item, "service", b->name);
    (void)json_push_kv_str(item, "display_name", b->display_name);
    (void)json_push_kv_str(item, "version", b->version);
    (void)json_push_kv_int(item, "binding_id", (int64_t)b->binding_id);
    (void)json_push_kv_str(item, "command_prefix", b->command_prefix);
    (void)json_push_kv_str(item, "state_table_prefix", b->state_table_prefix);
    (void)json_push_kv_str(item, "state_schema", b->state_schema);
    (void)json_push_kv_int(item, "host_service_id",
                           (int64_t)b->host_service_id);
    (void)json_push_kv_str(item, "digest", digest_hex);
}

/* The boundary, spelled out rather than left to the reader. */
static void svc_isolation_json(const struct zcl_service_binding_v1 *b,
                               struct json_value *out)
{
    struct json_value iso;
    json_init(&iso);
    json_set_object(&iso);
    (void)json_push_kv_bool(&iso, "never_affects_block_validity",
                            (b->isolation &
                             ZCL_SERVICE_ISOLATION_NO_BLOCK_VALIDITY) != 0);
    (void)json_push_kv_bool(&iso, "never_writes_consensus_state",
                            (b->isolation &
                             ZCL_SERVICE_ISOLATION_NO_CONSENSUS_WRITE) != 0);
    (void)json_push_kv_bool(
        &iso, "never_blocks_on_progress_lock",
        (b->isolation &
         ZCL_SERVICE_ISOLATION_NO_BLOCKING_PROGRESS_LOCK) != 0);
    (void)json_push_kv_bool(
        &iso, "auth_declared_by_command_catalog",
        (b->isolation & ZCL_SERVICE_ISOLATION_CATALOG_DECLARED_AUTH) != 0);
    (void)json_push_kv_bool(&iso, "writes_only_owned_state_tables",
                            (b->isolation &
                             ZCL_SERVICE_ISOLATION_OWNED_STATE_ONLY) != 0);
    (void)json_push_kv_bool(
        &iso, "complete",
        b->isolation == ZCL_SERVICE_ISOLATION_REQUIRED_V1);
    (void)json_push_kv(out, "isolation", &iso);
    json_free(&iso);
}

void zcl_native_handle_service_list(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    (void)request;
    size_t bad_index = 0;
    enum zcl_service_binding_result check =
        zcl_service_binding_catalog_check_v1(&bad_index);
    if (check != ZCL_SERVICE_BINDING_OK) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_INVALID",
                               "resolve", false, false,
                               "the declared service catalog does not validate",
                               zcl_service_binding_result_name_v1(check));
        return;
    }
    size_t count = 0;
    const struct zcl_service_binding_v1 *catalog =
        zcl_service_binding_catalog_v1(&count);
    struct json_value services;
    json_init(&services);
    json_set_array(&services);
    for (size_t i = 0; i < count; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        svc_binding_summary_json(&catalog[i], &item);
        (void)json_push_back(&services, &item);
        json_free(&item);
    }
    char root_hex[65] = {0};
    uint8_t root[32];
    if (zcl_service_binding_catalog_root_v1(root))
        svc_hex(root, 32, root_hex);
    (void)json_push_kv(&reply->data, "services", &services);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv_str(&reply->data, "catalog_root", root_hex);
    (void)json_push_kv_str(&reply->data, "schema",
                           ZCL_SERVICE_BINDING_CATALOG_SCHEMA_NAME);
    (void)json_push_kv_str(&reply->data, "source",
                           "engine/composition/services/bindings.def");
    json_free(&services);
}

static const struct zcl_service_binding_v1 *svc_require_binding(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *name = svc_input_str(request, "service");
    if (!name || !name[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SERVICE",
                               "normalize", false, false,
                               "service is required", "");
        return NULL;
    }
    const struct zcl_service_binding_v1 *binding =
        zcl_service_binding_find_v1(name);
    if (!binding) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_SERVICE",
                               "resolve", false, false,
                               "no such declared service", name);
        (void)zcl_command_reply_add_next(reply, "app.service.list", "{}",
                                         "list declared services");
        return NULL;
    }
    return binding;
}

void zcl_native_handle_service_inspect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct zcl_service_binding_v1 *binding =
        svc_require_binding(request, reply);
    if (!binding)
        return;
    svc_binding_summary_json(binding, &reply->data);
    (void)json_push_kv_int(&reply->data, "state_schema_version",
                           (int64_t)binding->state_schema_version);
    (void)json_push_kv_int(&reply->data, "health_deadline_ms",
                           (int64_t)binding->health_deadline_ms);

    char token_hex[65];
    svc_hex(binding->gate.token_genesis_txid, 32, token_hex);
    struct json_value gate;
    json_init(&gate);
    json_set_object(&gate);
    (void)json_push_kv_str(&gate, "ledger", "zslp_ledger");
    (void)json_push_kv_str(&gate, "token_genesis_txid", token_hex);
    (void)json_push_kv_bool(&gate, "token_unminted",
                            zcl_service_gate_token_unminted_v1(
                                binding->gate.token_genesis_txid));
    (void)json_push_kv_int(&gate, "min_balance",
                           (int64_t)binding->gate.min_balance);
    (void)json_push_kv_str(
        &gate, "snapshot_kind",
        binding->gate.snapshot_kind == ZCL_SERVICE_GATE_SNAPSHOT_FIXED_HEIGHT
            ? "fixed_height" : "confirmed_depth");
    (void)json_push_kv_int(&gate, "snapshot_param",
                           binding->gate.snapshot_param);
    (void)json_push_kv_str(
        &gate, "holder_kind",
        binding->gate.holder_kind == ZCL_SERVICE_GATE_HOLDER_ADDRESS
            ? "address" : "wallet");
    (void)json_push_kv(&reply->data, "token_gate", &gate);
    json_free(&gate);

    svc_isolation_json(binding, &reply->data);
    (void)json_push_kv_str(&reply->data, "schema",
                           ZCL_SERVICE_BINDING_SCHEMA_NAME);
}

void zcl_native_handle_service_access(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct zcl_service_binding_v1 *binding =
        svc_require_binding(request, reply);
    if (!binding)
        return;

    uint8_t address[20];
    const uint8_t *address_arg = NULL;
    const char *address_hex = svc_input_str(request, "address");
    if (address_hex && address_hex[0]) {
        if (!svc_parse_hash160(address_hex, address)) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_ADDRESS",
                                   "normalize", false, false,
                                   "address must be 40 hex characters "
                                   "(a 20-byte hash160)", address_hex);
            return;
        }
        address_arg = address;
    }

    const char *datadir = svc_input_str(request, "datadir");
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();
    /* READ leaf: strictly read-only. node_db_open() here would create,
     * migrate and clean the staging tables of whatever datadir the caller
     * named — including the live one this leaf defaults to. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the ZSLP ledger", &db, &ndb))
        return;

    /* An explicit tip pins the snapshot for a reproducible re-check; without
     * one, the highest fully validated block is the tip. */
    int32_t tip_height = -1;
    const struct json_value *tip_arg = request->input
        ? json_get(request->input, "tip_height") : NULL;
    if (tip_arg && tip_arg->type == JSON_INT)
        tip_height = (int32_t)json_get_int(tip_arg);
    else
        tip_height = (int32_t)db_block_max_height(&ndb);

    struct service_gate_verdict verdict;
    struct zcl_result evaluated = service_token_gate_evaluate(
        &ndb, binding, tip_height, address_arg, &verdict);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!evaluated.ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "GATE_EVAL",
                               "execute", false, false,
                               evaluated.message, binding->name);
        return;
    }
    (void)json_push_kv_str(&reply->data, "service", binding->name);
    (void)json_push_kv_int(&reply->data, "tip_height", tip_height);
    service_token_gate_verdict_json(&verdict, &reply->data);
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.service_access_verdict.v1");
    if (!verdict.granted)
        (void)zcl_command_reply_add_next(reply, "app.service.inspect",
                                         "{\"service\":\"\"}",
                                         "inspect the binding's declared gate");
}

void zcl_native_handle_service_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *name = svc_input_str(request, "service");
    if (name && name[0] && !zcl_service_binding_find_v1(name)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_SERVICE",
                               "resolve", false, false,
                               "no such declared service", name);
        (void)zcl_command_reply_add_next(reply, "app.service.list", "{}",
                                         "list declared services");
        return;
    }
    struct json_value state;
    json_init(&state);
    if (!service_lifecycle_dump_state_json(&state, name)) {
        json_free(&state);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "LIFECYCLE_DUMP",
                               "execute", false, false,
                               "the lifecycle registry could not be read",
                               name ? name : "");
        return;
    }
    (void)json_push_kv(&reply->data, "lifecycle", &state);
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.service_lifecycle.v1");
    json_free(&state);
}
