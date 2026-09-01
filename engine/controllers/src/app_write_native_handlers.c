/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry handlers for the MUTATING app.* feature leaves.
 *
 * Each leaf proxies one existing node RPC. The backing controllers remain the
 * only transaction builders; this file owns the CONFIRM_PLAN_COMMIT handshake,
 * typed reply, and fail-closed handling of RPCs that report degraded success.
 *
 * Bound in engine/composition/commands/app_features.def. */

#include "controllers/native_handler_body.h" /* json_get_bool_or */
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AWN_TAG "native.app.write"

enum { AWN_MAX_ARGS = 6 };

/* How one leaf input key reaches the backing RPC's positional params.
 * The registry validator enforced the JSON type; this picks the encoding. */
enum awn_kind { AWN_STR, AWN_INT, AWN_REAL, AWN_U64_STR };

struct awn_arg {
    const char *key;
    enum awn_kind kind;
    bool required;
};

struct awn_leaf {
    const char *action;        /* plan-stage action label */
    const char *method;        /* backing JSON-RPC method */
    bool plan_commit;          /* leaf declares CONFIRM_PLAN_COMMIT */
    /* When non-NULL, the RPC's `status` must equal this; else BLOCKED. */
    const char *require_status;
    const char *degraded_code;
    const char *degraded_message;
    struct awn_arg args[AWN_MAX_ARGS]; /* .key == NULL terminates */
};

/* ── small helpers ──────────────────────────────────────────────────── */

static void awn_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(AWN_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence ? evidence : "");
}

/* Coerce an amount-shaped value (int / real / decimal string) to a double.
 * Returns false when the text is not a number the RPC could use. */
static bool awn_real(const struct json_value *v, double *out)
{
    if (!v)
        return false;
    if (v->type == JSON_REAL) {
        *out = json_get_real(v);
        return true;
    }
    if (v->type == JSON_INT) {
        *out = (double)json_get_int(v);
        return true;
    }
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (!s || !s[0])
            return false;
        char *end = NULL;
        double parsed = strtod(s, &end);
        if (!end || *end)
            return false;
        *out = parsed;
        return true;
    }
    return false;
}

static bool awn_u64_string(const struct json_value *v, const char **out)
{
    if (!v || v->type != JSON_STR)
        return false;
    const char *s = json_get_str(v);
    if (!s || !s[0]) return false;
    uint64_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (n > (UINT64_MAX - digit) / 10) return false;
        n = n * 10 + digit;
    }
    if (n == 0) return false;
    *out = s;
    return true;
}

/* Deterministic, non-secret plan token: FNV-1a over the leaf path and every
 * supplied value (16 hex), comparable across the plan and committed reply. */
static void awn_plan_token(char out[17], const char *path,
                           const struct json_value *input)
{
    uint64_t h = 1469598103934665603ULL;
    const char *seed = path ? path : "";
    for (const char *p = seed; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    if (input && input->type == JSON_OBJ) {
        for (size_t i = 0; i < input->num_children; i++) {
            const char *k = input->keys ? input->keys[i] : NULL;
            if (!k || !k[0] || strcmp(k, "confirm") == 0)
                continue;
            char scratch[512];
            size_t n = json_write(&input->children[i], scratch,
                                  sizeof(scratch));
            if (n >= sizeof(scratch))
                n = sizeof(scratch) - 1;
            for (const char *p = k; *p; p++) {
                h ^= (unsigned char)*p;
                h *= 1099511628211ULL;
            }
            for (size_t j = 0; j < n; j++) {
                h ^= (unsigned char)scratch[j];
                h *= 1099511628211ULL;
            }
            h ^= 0x1f;
            h *= 1099511628211ULL;
        }
    }
    (void)snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* Re-serialize the caller's own input with confirm:true — the exact document
 * that commits this plan. The kernel refuses a self-pointing next-action, so
 * the commit input travels as data (wallet plan/commit precedent). */
static void awn_commit_input(const struct json_value *input, char *out,
                             size_t cap)
{
    struct json_value ci;
    json_init(&ci);
    json_set_object(&ci);
    if (input && input->type == JSON_OBJ) {
        for (size_t i = 0; i < input->num_children; i++) {
            const char *k = input->keys ? input->keys[i] : NULL;
            if (!k || !k[0] || strcmp(k, "confirm") == 0)
                continue;
            (void)json_push_kv(&ci, k, &input->children[i]);
        }
    }
    (void)json_push_kv_bool(&ci, "confirm", true);
    size_t n = json_write(&ci, out, cap);
    json_free(&ci);
    if (n == 0 || n >= cap) {
        LOG_WARN(AWN_TAG, "commit input truncated (%zu bytes)", n);
        (void)snprintf(out, cap, "{\"confirm\":true}");
    }
}

/* Copy every top-level member of an RPC result object onto the reply data. */
static void awn_merge_object(struct json_value *dst,
                             const struct json_value *src)
{
    if (!src || src->type != JSON_OBJ)
        return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *k = src->keys ? src->keys[i] : NULL;
        if (!k || !k[0])
            continue;
        (void)json_push_kv(dst, k, &src->children[i]);
    }
}

/* Detect an RPC failure body: node_rpc_call returns the JSON-RPC `error`
 * member verbatim, and a handler's plain-text refusal arrives as a bare
 * JSON string (engine/modules/rpc/src/httpserver.c) — both shapes are errors. */
static bool awn_body_is_error(const struct json_value *body,
                              const char **msg_out)
{
    if (!body)
        return true;
    if (body->type == JSON_STR) {
        if (msg_out)
            *msg_out = json_get_str(body);
        return true;
    }
    if (body->type != JSON_OBJ)
        return false;
    const struct json_value *err = json_get(body, "error");
    if (err && !json_is_null(err)) {
        if (msg_out) {
            if (err->type == JSON_OBJ)
                *msg_out = json_get_str(json_get(err, "message"));
            else if (err->type == JSON_STR)
                *msg_out = json_get_str(err);
        }
        return true;
    }
    const struct json_value *code = json_get(body, "code");
    const struct json_value *m = json_get(body, "message");
    if (code && code->type == JSON_INT && m && m->type == JSON_STR) {
        if (msg_out)
            *msg_out = json_get_str(m);
        return true;
    }
    return false;
}

/* ── the one runner every leaf in this file shares ──────────────────── */

static void awn_run(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply,
                    const struct awn_leaf *leaf)
{
    if (!request || !request->spec || !reply || !leaf)
        return;
    const char *path = request->spec->path;

    size_t count = 0;
    while (count < AWN_MAX_ARGS && leaf->args[count].key)
        count++;

    const struct json_value *vals[AWN_MAX_ARGS] = { NULL };
    size_t supplied = 0;
    for (size_t i = 0; i < count; i++) {
        const struct json_value *v = json_get(request->input,
                                              leaf->args[i].key);
        if (v && json_is_null(v))
            v = NULL;
        if (!v && leaf->args[i].required) {
            char msg[160];
            (void)snprintf(msg, sizeof(msg), "%s is required",
                           leaf->args[i].key);
            awn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                     ZCL_COMMAND_EXIT_INVALID, "MISSING_INPUT", "normalize",
                     msg, path);
            return;
        }
        vals[i] = v;
        if (v)
            supplied = i + 1;
    }

    char token[17];
    awn_plan_token(token, path, request->input);

    bool confirm = json_get_bool_or(request->input, "confirm", false);
    if (leaf->plan_commit && !confirm) {
        char commit[768];
        awn_commit_input(request->input, commit, sizeof(commit));
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_str(&reply->data, "action", leaf->action);
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_str(&reply->data, "plan_token", token);
        (void)json_push_kv_str(&reply->data, "backing_method", leaf->method);
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "re-run this same command with the commit_input below to execute");
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        reply->error.mutated = false;
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    for (size_t i = 0; i < supplied; i++) {
        const struct json_value *v = vals[i];
        switch (leaf->args[i].kind) {
        case AWN_INT:
            rpc_arg_builder_push_int(&p, v ? json_get_int(v) : 0);
            break;
        case AWN_REAL: {
            double d = 0.0;
            if (v && !awn_real(v, &d)) {
                rpc_arg_builder_free(&p);
                char msg[160];
                (void)snprintf(msg, sizeof(msg), "%s must be a number",
                               leaf->args[i].key);
                awn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                         "normalize", msg, path);
                return;
            }
            rpc_arg_builder_push_real(&p, d);
            break;
        }
        case AWN_U64_STR: {
            const char *s = NULL;
            char ibuf[21]; /* u64 max is 20 digits */
            if (v && v->type == JSON_INT && json_get_int(v) > 0) {
                /* Bare-int CLI args (vault.def "units":25) render to the
                 * RPC's decimal-string form; push_str deep-copies ibuf. */
                (void)snprintf(ibuf, sizeof(ibuf), "%lld",
                               (long long)json_get_int(v));
                s = ibuf;
            } else if (!awn_u64_string(v, &s)) {
                rpc_arg_builder_free(&p);
                char msg[160];
                (void)snprintf(msg, sizeof(msg),
                    "%s must be an unsigned decimal string",
                    leaf->args[i].key);
                awn_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                         "normalize", msg, path);
                return;
            }
            rpc_arg_builder_push_str(&p, s);
            break;
        }
        case AWN_STR:
        default: {
            const char *s = v ? json_get_str(v) : NULL;
            rpc_arg_builder_push_str(&p, s ? s : "");
            break;
        }
        }
    }
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the backing RPC parameters", path);
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(leaf->method, params);
    free(params);
    if (!raw) {
        awn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 "the node did not answer the backing command", leaf->method);
        return;
    }

    struct json_value body;
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&body);
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "the backing command returned an unparseable body",
                 leaf->method);
        return;
    }

    const char *emsg = NULL;
    if (awn_body_is_error(&body, &emsg)) {
        char msg[256];
        (void)snprintf(msg, sizeof(msg), "%s",
                       emsg && emsg[0] ? emsg
                                       : "the backing command reported an "
                                         "error");
        json_free(&body);
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "APP_RPC_ERROR", "execute", msg, leaf->method);
        return;
    }
    if (body.type != JSON_OBJ) {
        json_free(&body);
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "the backing command returned a non-object body",
                 leaf->method);
        return;
    }

    /* A true RPC success that did not do the job the leaf promises. */
    if (leaf->require_status) {
        const char *status = json_get_str(json_get(&body, "status"));
        if (!status || strcmp(status, leaf->require_status) != 0) {
            char msg[320];
            (void)snprintf(msg, sizeof(msg), "%s (backing status: %s)",
                           leaf->degraded_message
                               ? leaf->degraded_message
                               : "the backing command did not complete",
                           status && status[0] ? status : "absent");
            json_free(&body);
            awn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                     ZCL_COMMAND_EXIT_BLOCKED,
                     leaf->degraded_code ? leaf->degraded_code
                                         : "APP_WRITE_INCOMPLETE",
                     "execute", msg, leaf->method);
            return;
        }
    }

    awn_merge_object(&reply->data, &body);
    json_free(&body);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
}

/* ── ZCL Names (ZNAM) ───────────────────────────────────────────────── */

/* ── Messaging (ZMSG) ───────────────────────────────────────────────── */

/* msg_send's first positional argument is the recipient, typed by channel:
 * numeric peer id for "p2p", zs1... address for "onchain". The leaf keeps
 * two distinct typed keys (peer_id / to) and picks the one the channel
 * names, so a caller cannot silently address the wrong channel. */
void zcl_native_handle_message_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->spec || !reply)
        return;
    const char *path = request->spec->path;
    const char *channel = json_get_str(json_get(request->input, "channel"));
    if (!channel || !channel[0])
        channel = "p2p";
    bool onchain = strcmp(channel, "onchain") == 0;
    if (!onchain && strcmp(channel, "p2p") != 0) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "INVALID_CHANNEL", "normalize",
                 "channel must be \"p2p\" or \"onchain\"", path);
        return;
    }

    const struct json_value *message = json_get(request->input, "message");
    const char *body = json_get_str(message);
    if (!body || !body[0]) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize", "message is required", path);
        return;
    }

    const struct json_value *peer_id = json_get(request->input, "peer_id");
    const char *to = json_get_str(json_get(request->input, "to"));
    const char *from_address =
        json_get_str(json_get(request->input, "from_address"));
    const char *reply_to = json_get_str(json_get(request->input, "reply_to"));

    if (onchain && (!to || !to[0])) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 "the onchain channel requires `to` (a zs1... shielded "
                 "recipient)", path);
        return;
    }
    if (!onchain && (!peer_id || peer_id->type != JSON_INT)) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 "the p2p channel requires `peer_id` (a connected peer's "
                 "numeric id from `core network peers list`)", path);
        return;
    }
    if (onchain && (!from_address || !from_address[0])) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 "the onchain channel requires `from_address` to fund the "
                 "shielded carrier transaction", path);
        return;
    }

    char token[17];
    awn_plan_token(token, path, request->input);
    if (!json_get_bool_or(request->input, "confirm", false)) {
        char commit[768];
        awn_commit_input(request->input, commit, sizeof(commit));
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_str(&reply->data, "action", "message-send");
        (void)json_push_kv_str(&reply->data, "channel", channel);
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_bool(&reply->data, "spends_funds", onchain);
        (void)json_push_kv_str(&reply->data, "plan_token", token);
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "re-run this same command with the commit_input below to execute");
        (void)json_push_kv_str(&reply->data, "commit_input", commit);
        reply->error.mutated = false;
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    if (onchain)
        rpc_arg_builder_push_str(&p, to);
    else
        rpc_arg_builder_push_int(&p, json_get_int(peer_id));
    rpc_arg_builder_push_str(&p, body);
    rpc_arg_builder_push_str(&p, onchain ? "onchain" : "p2p");
    if (onchain) {
        rpc_arg_builder_push_str(&p, from_address);
        if (reply_to && reply_to[0])
            rpc_arg_builder_push_str(&p, reply_to);
    }
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the msg_send parameters", path);
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("msg_send", params);
    free(params);
    if (!raw) {
        awn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 "the node did not answer msg_send", "msg_send");
        return;
    }
    struct json_value doc;
    bool parsed = json_read(&doc, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&doc);
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "msg_send returned an unparseable body", "msg_send");
        return;
    }
    const char *emsg = NULL;
    if (awn_body_is_error(&doc, &emsg)) {
        char msg[256];
        (void)snprintf(msg, sizeof(msg), "%s",
                       emsg && emsg[0] ? emsg : "msg_send reported an error");
        json_free(&doc);
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "APP_RPC_ERROR", "execute", msg, "msg_send");
        return;
    }
    if (doc.type != JSON_OBJ) {
        json_free(&doc);
        awn_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "msg_send returned a non-object body", "msg_send");
        return;
    }
    const char *status = json_get_str(json_get(&doc, "status"));
    if (!status || strcmp(status, "sent") != 0) {
        char msg[256];
        (void)snprintf(msg, sizeof(msg),
                       "msg_send did not report the message as sent "
                       "(status: %s)", status && status[0] ? status : "absent");
        json_free(&doc);
        awn_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                 "MESSAGE_NOT_SENT", "execute", msg, "msg_send");
        return;
    }
    awn_merge_object(&reply->data, &doc);
    json_free(&doc);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
}

void zcl_native_handle_message_read(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const struct awn_leaf leaf = {
        .action = "message-read", .method = "msg_read",
        .plan_commit = false, .require_status = "read",
        .degraded_code = "MESSAGE_NOT_MARKED",
        .degraded_message = "msg_read did not report the message as read",
        .args = {
            { "msg_id", AWN_STR, true },
            { NULL, AWN_STR, false },
        },
    };
    awn_run(request, reply, &leaf);
}

/* ── Atomic swaps (ZSWP) ────────────────────────────────────────────── */

void zcl_native_handle_swap_initiate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const struct awn_leaf leaf = {
        .action = "swap-initiate", .method = "swap_initiate",
        .plan_commit = true, .require_status = NULL,
        .degraded_code = NULL, .degraded_message = NULL,
        .args = {
            { "my_address", AWN_STR, true },
            { "counter_address", AWN_STR, true },
            { "amount", AWN_REAL, true },
            { "locktime_blocks", AWN_INT, true },
            { "chain", AWN_STR, false },
            { NULL, AWN_STR, false },
        },
    };
    awn_run(request, reply, &leaf);
}

void zcl_native_handle_swap_participate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const struct awn_leaf leaf = {
        .action = "swap-participate", .method = "swap_participate",
        .plan_commit = true, .require_status = NULL,
        .degraded_code = NULL, .degraded_message = NULL,
        .args = {
            { "my_address", AWN_STR, true },
            { "counter_address", AWN_STR, true },
            { "amount", AWN_REAL, true },
            { "locktime_blocks", AWN_INT, true },
            { "secret_hash", AWN_STR, true },
            { "chain", AWN_STR, false },
        },
    };
    awn_run(request, reply, &leaf);
}
