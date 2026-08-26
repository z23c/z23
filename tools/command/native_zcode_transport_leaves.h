/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The shared leaf skeleton behind every DHT-transport command family
 * (attestation lane, work lane, task lane). Each lane's translation unit
 * owns its rows, its namespace, and its window policy; these are the
 * input plumbing and forward-driving helpers that would otherwise be
 * copy-pasted per lane. Include from exactly one TU — every helper is
 * static by design, one definition per including unit. */

#ifndef ZCL_TOOLS_COMMAND_NATIVE_ZCODE_TRANSPORT_LEAVES_H
#define ZCL_TOOLS_COMMAND_NATIVE_ZCODE_TRANSPORT_LEAVES_H

#include "base/hex.h"
#include "base/log_macros.h"
#include "command/native_command.h"

#include "json/json.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <string.h>

static const char *ztl_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static const char *ztl_datadir(const struct zcl_command_request *request)
{
    const char *dd = ztl_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Resolve <datadir>/zcode. False with the error body already set. */
static bool ztl_zcode_dir(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply,
                          const char *command, char out[4400])
{
    const char *datadir = ztl_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return false;
    }
    int n = snprintf(out, 4400, "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= 4400) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return false;
    }
    return true;
}

/* One required canonical 64-hex root input. False with the error body set. */
static bool ztl_hex32(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *command,
                      const char *key, const char *code, const char *what,
                      uint8_t out[32])
{
    const char *hex = ztl_input_str(request->input, key);
    if (!hex || strlen(hex) != 64 || !zcl_hex_decode_lower(hex, out, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "normalize",
                               false, false, what,
                               hex && hex[0] ? hex : command);
        return false;
    }
    return true;
}

/* The store these leaves verify and fetch through. The node-global handle
 * when a hosting daemon owns this process; otherwise the datadir's own
 * store, exactly as zcode package fetch does for its one-shot path. The
 * pull leaves are MUTATE, so opening the store is not a read side-effect. */
static struct vcs_package_store *ztl_open_store(
    const struct zcl_command_request *request, bool *own_out,
    const char *log_tag)
{
    *own_out = false;
    struct vcs_package_store *store = vcs_package_store_global();
    if (store)
        return store;
    const char *datadir = ztl_datadir(request);
    if (!datadir || !datadir[0])
        return NULL;
    store = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (!store) {
        LOG_ERROR(log_tag, "package store failed to open under %s", datadir);
        return NULL;
    }
    *own_out = true;
    return store;
}

static void ztl_close_store(struct vcs_package_store *store, bool own)
{
    if (own && store)
        vcs_package_store_close(store);
}

/* Fill one ready-to-run `zcode network publish` input. kind decides
 * whether semantic_root is carried; the namespace names the lane. */
static void ztl_publish_input(struct json_value *out, const char *kind,
                              const char *namespace,
                              const char *semantic_root_hex,
                              const char *transport_root_hex, uint64_t now,
                              uint64_t window_s)
{
    json_set_object(out);
    (void)json_push_kv_str(out, "mode", "plan");
    (void)json_push_kv_str(out, "kind", kind);
    (void)json_push_kv_str(out, "namespace", namespace);
    if (semantic_root_hex)
        (void)json_push_kv_str(out, "semantic_root", semantic_root_hex);
    (void)json_push_kv_str(out, "transport_root", transport_root_hex);
    (void)json_push_kv_int(out, "sequence", (int64_t)now);
    (void)json_push_kv_int(out, "not_before", (int64_t)now);
    (void)json_push_kv_int(out, "expiry", (int64_t)(now + window_s));
}

/* Drive the EXISTING record-discovery handler rather than reimplementing a
 * DHT query: {kind:"pointer", namespace, semantic_root} is exactly the
 * selector the records handler parses. Returns false with the error body
 * already set on the caller's reply. */
static bool ztl_query_pointers(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply,
                               const char *namespace,
                               const char *semantic_root_hex,
                               struct json_value *records_out)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "kind", "pointer");
    (void)json_push_kv_str(&input, "namespace", namespace);
    (void)json_push_kv_str(&input, "semantic_root", semantic_root_hex);
    const char *datadir = ztl_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&input, "datadir", datadir);
    struct zcl_command_request forwarded = *request;
    forwarded.input = &input;
    struct zcl_command_reply records;
    zcl_command_reply_init(&records, "zcl.zcode_network_records.v1");
    zcl_native_handle_zcode_network_records(&forwarded, &records);
    json_free(&input);
    if (records.exit_code != ZCL_COMMAND_EXIT_OK) {
        zcl_command_reply_fail(
            reply, records.status, records.exit_code,
            records.error.code[0] ? records.error.code
                                  : "POINTER_LOOKUP_FAILED",
            records.error.phase[0] ? records.error.phase : "discover",
            records.error.retryable, false,
            records.error.message[0]
                ? records.error.message
                : "the pointer lookup did not complete",
            records.error.evidence);
        zcl_command_reply_free(&records);
        return false;
    }
    const struct json_value *rows = json_get(&records.data, "records");
    json_init(records_out);
    if (rows && rows->type == JSON_ARR)
        json_copy(records_out, rows);
    else
        json_set_array(records_out);
    zcl_command_reply_free(&records);
    return true;
}

/* Drive the EXISTING fetch handler for one transport root. Never fails the
 * caller: *fetched_out is set (false on refusal) and the outcome string
 * names whatever verdict came back, so the row can record it. */
static void ztl_fetch_one(const struct zcl_command_request *request,
                          const char *namespace,
                          const char *transport_root_hex,
                          int64_t maximum_bytes, bool *fetched_out,
                          char *outcome, size_t outcome_cap)
{
    *fetched_out = false;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "root", transport_root_hex);
    (void)json_push_kv_str(&input, "namespace", namespace);
    const char *datadir = ztl_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&input, "datadir", datadir);
    (void)json_push_kv_int(&input, "maximum_bytes", maximum_bytes);
    struct zcl_command_request forwarded = *request;
    forwarded.input = &input;
    struct zcl_command_reply fetch;
    zcl_command_reply_init(&fetch, "zcl.zcode_package_fetch.v1");
    zcl_native_handle_zcode_package_fetch(&forwarded, &fetch);
    json_free(&input);
    if (fetch.exit_code != ZCL_COMMAND_EXIT_OK) {
        (void)snprintf(outcome, outcome_cap, "%s",
                       fetch.error.code[0] ? fetch.error.code
                                           : "FETCH_FAILED");
        zcl_command_reply_free(&fetch);
        return;
    }
    const char *verdict = json_get_str(json_get(&fetch.data, "fetch_result"));
    if (!verdict)
        verdict = json_get_str(json_get(&fetch.data, "result"));
    *fetched_out = json_get_bool(json_get(&fetch.data, "already_complete")) ||
        (verdict && strcmp(verdict, "already-complete") == 0);
    (void)snprintf(outcome, outcome_cap, "%s",
                   verdict ? verdict : (*fetched_out ? "already-complete"
                                                     : "scheduled"));
    zcl_command_reply_free(&fetch);
}

#endif /* ZCL_TOOLS_COMMAND_NATIVE_ZCODE_TRANSPORT_LEAVES_H */
