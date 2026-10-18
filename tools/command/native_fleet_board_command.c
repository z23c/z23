/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet board *` and `fleet wiki *` — the CLI half of the fleet AI message
 * board and wiki.
 *
 * These leaves run in a one-shot process launched from a checkout, which
 * holds no node state and no host identity. Every one of them therefore asks
 * the LOCAL RUNNING NODE over the `fleet_board` RPC method and FAILS CLOSED
 * when no node answers, guiding explicit instance selection. It never
 * falls back to a private file: a board only one process can see is a
 * notebook, and two agents keeping private notebooks is precisely the problem
 * this branch exists to remove.
 *
 * Bound by engine/composition/commands/fleet_board.def.
 */

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "controllers/rpc_client.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "rpc/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Environment the interim shell tool honoured, kept so existing agent scripts
 * swap to this command without edits. An explicit input key always wins: the
 * environment is a default, never an override. */
#define FLEET_BOARD_AGENT_ENV "BOARD_AGENT"
#define FLEET_BOARD_REF_ENV "BOARD_REF"

static void fb_fail(struct zcl_command_reply *reply,
                    enum zcl_command_status status,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *stage, bool retryable, const char *message,
                    const char *evidence)
{
    zcl_command_reply_fail(reply, status, exit_code, code, stage, retryable,
                           false, message, evidence ? evidence : "fleet.board");
}

/* A failed selected endpoint does not establish that every local node is
 * stopped. Guide discovery before any separately authorized startup. */
static void fb_no_node(struct zcl_command_reply *reply)
{
    fb_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
            "NODE_UNAVAILABLE", "dispatch", true,
            "the selected local node did not answer the board call. Run "
            "`z23-dev status` to inspect local instances, then retry with "
            "explicit -rpcport=<PORT> and -datadir=<DIR> for the intended "
            "instance. Check its RPC authentication if it is running. "
            "The board never writes a private copy.",
            "fleet.board");
    (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                     "inspect the selected node and local instances");
}

/* A node ANSWERED (it is up, reachable, and its auth cookie was accepted)
 * but its JSON-RPC error names -32601 "method not found": the running
 * binary predates the fleet_board RPC. That is generation skew on a live
 * node, never an unreachable one, so it must never render as
 * NODE_UNAVAILABLE nor suggest starting anything. The body can arrive
 * either bare (node_rpc_call already unwrapped the JSON-RPC envelope and
 * handed back just the error object) or enveloped (a raw
 * `{"result":...,"error":{...},"id":...}` reply, as a stubbed test or a
 * transport that did not unwrap it), so check both shapes the same way. */
static bool fb_method_not_found(const struct json_value *body, char *message,
                                size_t message_len)
{
    if (message && message_len)
        message[0] = '\0';
    const struct json_value *err = json_get(body, "error");
    const struct json_value *obj =
        (err && err->type == JSON_OBJ) ? err : body;
    const struct json_value *code_v = json_get(obj, "code");
    if (!code_v || code_v->type != JSON_INT)
        return false;
    if (json_get_int(code_v) != RPC_METHOD_NOT_FOUND)
        return false;
    const char *msg = json_get_str(json_get(obj, "message"));
    if (message && message_len && msg && msg[0])
        snprintf(message, message_len, "%s", msg);
    return true;
}

/* The node answered but its running image has no fleet_board RPC — a
 * generation-skew node, not an unreachable one. Name the cause, carry the
 * node's own -32601 message as evidence, and point at redeploying THAT
 * node, never at starting one. */
static void fb_rpc_unsupported(struct zcl_command_reply *reply,
                               const char *node_message)
{
    char message[416];
    (void)snprintf(message, sizeof(message),
        "the selected node answered but its running image has no "
        "fleet_board RPC method (JSON-RPC -32601: %s) — this is a node "
        "running an older build (generation skew), not an unreachable "
        "node. Redeploy or upgrade that node's running image, then retry. "
        "`z23-dev status` will not fix this.",
        node_message && node_message[0] ? node_message : "Method not found");
    fb_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_INVALID,
            "BOARD_RPC_UNSUPPORTED", "dispatch", false, message,
            "fleet.board");
    (void)zcl_command_reply_add_next(reply, "core.status", "{}",
        "identify the selected node's running build so it can be "
        "redeployed/upgraded to a build with the fleet_board RPC");
}

/* The board handler was never reached: no `ok` field came back, only a
 * transport-shaped error. Split out of fb_call so that call stays under the
 * complexity cap — this one decision (which of the two distinct refusals
 * applies) lives in exactly one place. */
static void fb_budget_exhausted(struct zcl_command_reply *reply)
{
    fb_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
        "BOARD_OBSERVATION_BUDGET_EXHAUSTED", "dispatch", true,
        "the brief's board observation budget is exhausted; board evidence "
        "remains unknown", "fleet.board");
}

/* The transport's own enveloped refusal: the absolute deadline passed before
 * any request byte was sent. A node's answer arrives unwrapped, never in this
 * shape. */
static bool fb_deadline_expired(const struct json_value *body)
{
    const struct json_value *err = json_get(body, "error");
    const struct json_value *code =
        err && err->type == JSON_OBJ ? json_get(err, "code") : NULL;
    return code && code->type == JSON_INT &&
           json_get_int(code) == NODE_RPC_DEADLINE_EXPIRED;
}

static void fb_handle_no_answer(struct zcl_command_reply *reply,
                                const struct json_value *body)
{
    char node_message[320];
    if (fb_deadline_expired(body)) {
        fb_budget_exhausted(reply);
        return;
    }
    if (fb_method_not_found(body, node_message, sizeof(node_message)))
        fb_rpc_unsupported(reply, node_message);
    else
        fb_no_node(reply);
}

/* Serialize one JSON object as the single RPC parameter. The array brackets
 * are written around the object rather than by building a wrapper array, so
 * the whole request is one bounded buffer with no allocation to leak on a
 * refusal path. */
static bool fb_params(const struct json_value *obj, char *out, size_t cap)
{
    if (cap < 3)
        return false;
    out[0] = '[';
    size_t n = json_write(obj, out + 1, cap - 2);
    if (n == 0 || n >= cap - 2)
        return false;
    out[1 + n] = ']';
    out[2 + n] = '\0';
    return true;
}

static void fb_board_refusal(struct zcl_command_reply *reply,
                             const struct json_value *body)
{
    const char *code = json_get_str(json_get(body, "code"));
    const char *msg = json_get_str(json_get(body, "message"));
    bool busy = code && strcmp(code, "BOARD_BUSY") == 0;
    fb_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            busy ? ZCL_COMMAND_EXIT_TRANSIENT : ZCL_COMMAND_EXIT_INVALID,
            code && code[0] ? code : "BOARD_REFUSED", "execute", busy,
            msg && msg[0] ? msg : "the board refused this request",
            "fleet.board");
}

#ifdef ZCL_TESTING
/* Lets a registered test model a slow endpoint bootstrap, which is otherwise
 * too fast to observe consuming an allowance. NULL restores the real one. */
static void (*g_fb_bootstrap_hook)(void);

void zcl_native_fleet_board_test_set_bootstrap(void (*fn)(void))
{
    g_fb_bootstrap_hook = fn;
}
#endif

static void fb_bootstrap(void)
{
#ifdef ZCL_TESTING
    if (g_fb_bootstrap_hook) {
        g_fb_bootstrap_hook();
        return;
    }
#endif
    zcl_native_bridge_ensure_rpc();
}

/* A composed observation may spend only its remaining monotonic budget.
 * Zero retains the direct board leaf's ordinary RPC timeout. No global RPC
 * state or environment is changed, and an exhausted observation does no I/O.
 * The observation is capped to FAST once, here, so the one absolute deadline
 * handed to the transport is not pushed later by endpoint bootstrap. */
static bool fb_observation_deadline(struct zcl_command_reply *reply,
                                    int64_t deadline_ms, int64_t *until_ms)
{
    *until_ms = 0;
    if (deadline_ms == 0)
        return true;
    int64_t now = platform_time_monotonic_ms();
    if (deadline_ms <= now) {
        fb_budget_exhausted(reply);
        return false;
    }
    int64_t cap;
    if (__builtin_add_overflow(now, ZCL_COMMAND_LATENCY_BUDGET_FAST_MS, &cap))
        cap = INT64_MAX;
    *until_ms = deadline_ms < cap ? deadline_ms : cap;
    return true;
}

static char *fb_rpc_call(struct zcl_command_reply *reply, const char *params,
                         int64_t deadline_ms)
{
    int64_t until_ms;
    /* Expired observations must not initialize or contact the endpoint. */
    if (!fb_observation_deadline(reply, deadline_ms, &until_ms))
        return NULL;
    fb_bootstrap();
    char *raw;
    if (deadline_ms == 0) {
        raw = node_rpc_call("fleet_board", params);
    } else if (until_ms <= platform_time_monotonic_ms()) {
        /* Bootstrap consumed the whole allowance: no request at all. */
        fb_budget_exhausted(reply);
        return NULL;
    } else {
        /* The transport re-checks the same deadline around the cookie read
         * and before connect/transmit rather than restarting it. */
        raw = node_rpc_call_until("fleet_board", params,
                                  ZCL_COMMAND_LATENCY_BUDGET_FAST_MS, until_ms);
    }
    if (!raw)
        fb_no_node(reply);
    return raw;
}

/* One round trip. On success `body` holds the node's reply object and the
 * caller owns it; on failure the reply is already filled in. */
static bool fb_body_transport_error(const struct json_value *body)
{
    const struct json_value *err = json_get(body, "error");
    const struct json_value *code = json_get(body, "code");
    const struct json_value *msg = json_get(body, "message");
    return (err && !json_is_null(err)) ||
        (code && code->type == JSON_INT && msg && msg->type == JSON_STR);
}

static bool fb_body_accepted(struct zcl_command_reply *reply, struct json_value *body)
{
    const struct json_value *ok = json_get(body, "ok");
    bool board_answered = ok && ok->type == JSON_BOOL;
    bool transport_error = fb_body_transport_error(body);
    if (!board_answered && transport_error) {
        fb_handle_no_answer(reply, body);
        json_free(body);
        return false;
    }
    if (transport_error) {
        const struct json_value *err = json_get(body, "error");
        const char *msg = err && err->type == JSON_OBJ ? json_get_str(json_get(err, "message")) : NULL;
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "BOARD_RPC_ERROR", "execute", false,
            msg && msg[0] ? msg : "the node reported an error", "fleet.board");
        json_free(body);
        return false;
    }
    if (ok && ok->type == JSON_BOOL && !json_get_bool(ok)) {
        fb_board_refusal(reply, body);
        json_free(body);
        return false;
    }
    return true;
}

static bool fb_call_bounded(struct zcl_command_reply *reply, struct json_value *in,
                    struct json_value *body, int64_t deadline_ms, size_t capacity)
{
    char *params = zcl_malloc(capacity, "fleet_board_rpc_params");
    if (!params) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "RPC_INPUT_ALLOC", "prepare", false, "bounded board RPC input allocation failed", "fleet.board");
        return false;
    }
    if (!fb_params(in, params, capacity)) {
        free(params);
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INPUT_TOO_LARGE", "normalize", false,
                "the request does not fit one board call; a wiki page is "
                "capped at 16 KiB and a post at 2 KiB", "fleet.board");
        return false;
    }
    char *raw = fb_rpc_call(reply, params, deadline_ms);
    free(params);
    if (!raw)
        return false;
    if (!json_read(body, raw, strlen(raw)) || body->type != JSON_OBJ) {
        json_free(body);
        free(raw);
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "BAD_BOARD_BODY", "serialize", false,
                "the node returned a non-object board body", "fleet.board");
        return false;
    }
    free(raw);

    /* A JSON-RPC transport error and a board refusal are different failures
     * and must not be collapsed: the first means the node did not run the
     * call, the second means it ran it and said no. The board handler always
     * answers with an `ok` field, so an error body WITHOUT one never reached
     * the board — no node, wrong datadir, or no auth cookie — and the caller
     * needs endpoint and authentication diagnosis before any startup. */
    return fb_body_accepted(reply, body);
}

static bool fb_call(struct zcl_command_reply *reply, struct json_value *in,
                    struct json_value *body, int64_t deadline_ms)
{
    return fb_call_bounded(reply, in, body, deadline_ms, FLEET_BOARD_RPC_PARAMS_MAX);
}

/* Copy `key` from the request input into the outgoing object, falling back to
 * an environment default and then to nothing. */
static void fb_forward_str(struct json_value *out,
                           const struct json_value *in, const char *key,
                           const char *env_name)
{
    const char *v = json_get_str(json_get(in, key));
    if ((!v || !v[0]) && env_name)
        v = getenv(env_name);
    if (v && v[0])
        (void)json_push_kv_str(out, key, v);
}

static void fb_forward_int(struct json_value *out,
                           const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    if (v && v->type == JSON_INT)
        (void)json_push_kv_int(out, key, json_get_int(v));
    /* A shell caller who typed --ttl=3600 arrives as a string; accept that
     * rather than silently ignoring the flag the caller clearly meant. */
    else if (v && v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (s && s[0])
            (void)json_push_kv_int(out, key, (int64_t)strtoll(s, NULL, 10));
    }
}

/* A wiki index row has no body; its line reads "slug — summary". */
static const char *fb_index_text(const struct json_value *post, char *buf, size_t cap)
{
    (void)snprintf(buf, cap, "%s \xE2\x80\x94 %s", json_get_str(json_get(post, "slug")),
                   json_get_str(json_get(post, "summary")));
    return buf;
}

/* The line an agent's script greps, one per post:
 *   <ts> <host12> [<kind>] <agent>: <text>  (id <id>) re:<ref>
 * The renderer prints a scalar array one entry per line, so pushing this as
 * the FIRST key of a list reply gives a line-oriented reading of the board
 * without a second output mode to keep in step. */
static void fb_post_line(const struct json_value *post, char *out, size_t cap)
{
    const char *host = json_get_str(json_get(post, "host"));
    const char *kind = json_get_str(json_get(post, "kind"));
    const char *agent = json_get_str(json_get(post, "agent"));
    const char *text = json_get_str(json_get(post, "text"));
    char index_text[FLEET_BOARD_LINE_MAX];
    if (json_get(post, "summary")) text = fb_index_text(post, index_text, sizeof(index_text));
    const char *id = json_get_str(json_get(post, "id"));
    const struct json_value *ts = json_get(post, "created_at");
    const char *ref = json_get_str(json_get(post, "ref"));
    static const char k_no_ref[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    bool has_ref = ref && strcmp(ref, k_no_ref) != 0;
    (void)snprintf(out, cap, "%lld %.12s [%s] %s: %s  (id %.16s)%s%.16s",
                   ts && ts->type == JSON_INT ? (long long)json_get_int(ts) : 0,
                   host ? host : "", kind ? kind : "?",
                   agent && agent[0] ? agent : "-", text ? text : "",
                   id ? id : "", has_ref ? " re:" : "",
                   has_ref ? ref : "");
}

/* Project a node list reply into the command reply, lines first. */
void zcl_native_fleet_board_project_list(
    const struct zcl_command_request *request,
    const struct json_value *body, struct zcl_command_reply *reply)
{
    const struct json_value *posts = json_get(body, "posts");
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    if (posts && posts->type == JSON_ARR) {
        for (size_t i = 0; i < json_size(posts); i++) {
            char line[FLEET_BOARD_LINE_MAX];
            fb_post_line(json_at(posts, i), line, sizeof(line));
            struct json_value item;
            json_init(&item);
            json_set_object(&item);
            (void)json_push_kv_str(&item, "line", line);
            (void)json_push_kv(&item, "post", json_at(posts, i));
            (void)json_push_back(&rows, &item);
            json_free(&item);
        }
    }
    /* Budget both representations together; paging them independently would
     * disconnect a human-readable line from its signed post. */
    zcl_native_bridge_project(request, &rows, reply);
    json_free(&rows);
    const struct json_value *items = json_get(&reply->data, "items");
    struct json_value data, lines, selected;
    json_init(&data);
    json_set_object(&data);
    json_init(&lines);
    json_set_array(&lines);
    json_init(&selected);
    json_set_array(&selected);
    for (size_t i = 0; i < json_size(items); i++) {
        const struct json_value *item = json_at(items, i);
        (void)json_push_back(&lines, json_get(item, "line"));
        (void)json_push_back(&selected, json_get(item, "post"));
    }
    (void)json_push_kv(&data, "lines", &lines);
    (void)json_push_kv(&data, "posts", &selected);
    (void)json_push_kv_int(&data, "returned", (int64_t)json_size(&selected));
    (void)json_push_kv(&data, "_page", json_get(&reply->data, "_page"));
    json_free(&lines);
    json_free(&selected);
    json_free(&reply->data);
    reply->data = data;
}

/* Copy every key of the node's reply except its transport envelope. */
static void fb_project_object(struct zcl_command_reply *reply,
                              const struct json_value *body)
{
    if (!body->keys)
        return;
    for (size_t i = 0; i < body->num_children; i++) {
        const char *key = body->keys[i];
        if (!key || strcmp(key, "ok") == 0)
            continue;
        if (!json_push_kv(&reply->data, key, &body->children[i])) {
            json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
            fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "BOARD_PROJECTION_FAILED", "execute", false,
                "cannot faithfully copy the signed board response", "fleet.board");
            return;
        }
    }
}

/* One `kind=note` post over the same `fleet_board` RPC method the CLI leaf
 * below uses — a native in-process call, never a shelled-out
 * `z23-dev fleet board post`. Used by the trigger board_post action
 * (tools/command/native_fleet_triggers_eval.c) so a fired trigger reaches
 * the board through the identical fail-closed path a human's own `fleet
 * board post` command would take. */
bool zcl_native_fleet_board_post_note(const char *text, char *why,
                                      size_t why_cap)
{
    if (why && why_cap)
        why[0] = 0;
    if (!text || !text[0]) {
        if (why)
            (void)snprintf(why, why_cap, "empty board post text");
        return false;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "post");
    (void)json_push_kv_str(&out, "kind", "note");
    (void)json_push_kv_str(&out, "text", text);

    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_triggers_board_post.v1");
    struct json_value body;
    json_init(&body);
    bool ok = fb_call(&reply, &out, &body, 0);
    json_free(&out);
    if (ok)
        json_free(&body);
    if (!ok && why)
        (void)snprintf(why, why_cap, "%s",
                       reply.error.message[0] ? reply.error.message
                                              : "the board post was refused");
    zcl_command_reply_free(&reply);
    return ok;
}

/* ── fleet board post ───────────────────────────────────────────────── */
void zcl_native_handle_fleet_board_post(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *kind = json_get_str(json_get(in, "kind"));
    const char *text = json_get_str(json_get(in, "text"));
    if (!kind || !kind[0] || !text || !text[0]) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_ARGS", "normalize", false,
                "usage: fleet board post <kind> <text> — kind is one of "
                "problem, need, offer, claim, result, note", "kind,text");
        return;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "post");
    (void)json_push_kv_str(&out, "kind", kind);
    (void)json_push_kv_str(&out, "text", text);
    fb_forward_str(&out, in, "agent", FLEET_BOARD_AGENT_ENV);
    fb_forward_str(&out, in, "ref", FLEET_BOARD_REF_ENV);
    fb_forward_str(&out, in, "receipt", NULL);
    fb_forward_str(&out, in, "scope", NULL);
    fb_forward_str(&out, in, "room", NULL);
    fb_forward_int(&out, in, "ttl");

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
}

/* ── fleet board list ───────────────────────────────────────────────── */
static void fb_list(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply, int64_t deadline_ms)
{
    const struct json_value *in = request->input;
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "list");
    fb_forward_str(&out, in, "kind", NULL);
    fb_forward_str(&out, in, "host", NULL);
    fb_forward_str(&out, in, "scope", NULL);
    fb_forward_str(&out, in, "room", NULL);
    fb_forward_int(&out, in, "since");
    fb_forward_int(&out, in, "limit");
    const struct json_value *open = json_get(in, "open");
    if (open && ((open->type == JSON_BOOL && json_get_bool(open)) ||
                 open->type == JSON_STR))
        (void)json_push_kv_bool(&out, "open", true);

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, deadline_ms);
    json_free(&out);
    if (!ok)
        return;
    zcl_native_fleet_board_project_list(request, &body, reply);
    json_free(&body);
    (void)zcl_command_reply_add_next(
        reply, "fleet.board.show", "{}",
        "read one post whole, including its receipt");
}

void zcl_native_handle_fleet_board_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    fb_list(request, reply, 0);
}

void zcl_native_fleet_board_list_until(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, int64_t deadline_ms)
{
    /* Unlike the direct leaf, this entry must never select generic defaults. */
    fb_list(request, reply, deadline_ms > 0 ? deadline_ms : -1);
}

/* ── fleet board show ───────────────────────────────────────────────── */
void zcl_native_handle_fleet_board_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *id = json_get_str(json_get(request->input, "id"));
    if (!id || !id[0]) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_ID", "normalize", false,
                "usage: fleet board show <id>", "id");
        return;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "show");
    (void)json_push_kv_str(&out, "id", id);

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
}

/* ── fleet board status ─────────────────────────────────────────────── */
void zcl_native_handle_fleet_board_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "status");

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
}

/* ── fleet wiki write ───────────────────────────────────────────────── */
void zcl_native_handle_fleet_wiki_write(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *slug = json_get_str(json_get(in, "slug"));
    const char *title = json_get_str(json_get(in, "title"));
    const char *text = json_get_str(json_get(in, "text"));
    if (!slug || !slug[0] || !title || !title[0] || !text || !text[0]) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_ARGS", "normalize", false,
                "usage: fleet wiki write <slug> <title> <body> — slug is "
                "lowercase [a-z0-9-]", "slug,title,text");
        return;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "post");
    (void)json_push_kv_str(&out, "kind", "wiki");
    (void)json_push_kv_str(&out, "slug", slug);
    (void)json_push_kv_str(&out, "title", title);
    (void)json_push_kv_str(&out, "text", text);
    fb_forward_str(&out, in, "agent", FLEET_BOARD_AGENT_ENV);
    fb_forward_str(&out, in, "supersedes", NULL);
    fb_forward_int(&out, in, "ttl");
    fb_forward_str(&out, in, "format", NULL);

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
}

/* ── fleet wiki read ────────────────────────────────────────────────── */
static bool fb_chunk_values(const struct json_value *input,
                            int64_t *offset, int64_t *bytes)
{
    const struct json_value *o = json_get(input, "offset");
    const struct json_value *n = json_get(input, "bytes");
    if ((o && o->type != JSON_INT) || (n && n->type != JSON_INT))
        return false;
    *offset = o ? json_get_int(o) : 0;
    *bytes = n ? json_get_int(n) : 1024;
    return *offset >= 0 && *offset <= 16384 && *bytes >= 1 && *bytes <= 1024;
}

static size_t fb_wiki_response_cap(const struct zcl_command_request *request)
{
    size_t cap = request->spec && request->spec->budget_bytes > 0
        ? (size_t)request->spec->budget_bytes : ZCL_COMMAND_RESULT_BUDGET;
    if (request->budget_bytes && request->budget_bytes < cap)
        cap = request->budget_bytes;
    return cap;
}

/* A truncated slug read names the exact chunk route that resumes it. The
 * registry refuses a self-referential next entry, so the hint is data. */
static bool fb_wiki_read_hint(const char *id, int64_t offset,
                              struct json_value *cont)
{
    struct json_value input;
    json_init(cont);
    json_init(&input);
    json_set_object(cont);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "id", id) &&
        json_push_kv_int(&input, "offset", offset) &&
        json_push_kv_int(&input, "bytes", 1024) &&
        json_push_kv_str(cont, "command", "fleet.wiki.read") &&
        json_push_kv(cont, "input", &input);
    json_free(&input);
    return ok;
}

static void fb_wiki_read_next(struct zcl_command_reply *reply)
{
    const struct json_value *t = json_get(&reply->data, "truncated");
    if (!t || !json_get_bool(t))
        return;
    struct json_value cont;
    bool ok = fb_wiki_read_hint(json_get_str(json_get(&reply->data, "id")),
        json_get_int(json_get(&reply->data, "next_offset")), &cont) &&
        json_push_kv(&reply->data, "continue", &cont);
    json_free(&cont);
    if (!ok)
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "BOARD_PROJECTION_FAILED", "execute", false,
            "cannot faithfully build the continuation hint", "fleet.board");
}

/* Measure the actual continuation representation at the largest allowed
 * byte offset. Full replies need none of this reservation. */
static bool fb_wiki_read_allowance(const struct zcl_command_request *request,
                                   struct json_value *out)
{
    /* Direct-handler callers have no registry envelope observation. Preserve
     * their existing conservative RPC reservation rather than invent one. */
    if (!request->success_data_budget_provided)
        return true;
    if (!request->success_data_budget)
        return false;
    static const char id[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    struct json_value cont, extra;
    json_init(&extra); json_set_object(&extra);
    bool ok = fb_wiki_read_hint(id, 16384, &cont) &&
        json_push_kv(&extra, "continue", &cont);
    /* Replacing the enclosing {} by a field in nonempty data adds a comma:
     * subtract one byte, not two. Escaping is measured by json_write. */
    if (ok) ok = json_push_kv_int(out, "data_budget",
                     (int64_t)request->success_data_budget) &&
        json_push_kv_int(out, "continuation_bytes", (int64_t)json_write(&extra, NULL, 0) - 1);
    json_free(&cont);
    json_free(&extra);
    return ok;
}

static bool fb_wiki_chunk_request(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply,
                                  struct json_value *out)
{
    int64_t offset, bytes;
    size_t cap = fb_wiki_response_cap(request);
    if (!fb_chunk_values(request->input, &offset, &bytes) || cap < 2048 ||
        json_get(request->input, "slug")) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_CHUNK", "normalize", false,
            "offset must be 0..16384, bytes 1..1024; chunks require a response budget of at least 2048", "id,offset,bytes");
        return false;
    }
    fb_forward_str(out, request->input, "id", NULL);
    (void)json_push_kv_int(out, "offset", offset);
    (void)json_push_kv_int(out, "bytes", bytes);
    (void)json_push_kv_int(out, "response_budget", (int64_t)cap);
    return true;
}

void zcl_native_handle_fleet_wiki_read(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *slug = json_get_str(json_get(request->input, "slug"));
    bool chunk = json_get(request->input, "id") != NULL;
    if (!chunk && (!slug || !slug[0])) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_SLUG", "normalize", false,
                "usage: fleet wiki read <slug>", "slug");
        return;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    bool prepared = json_push_kv_str(&out, "op", "wiki_read");
    if (chunk) {
        if (!fb_wiki_chunk_request(request, reply, &out)) {
            json_free(&out);
            return;
        }
    } else {
        if (json_get(request->input, "offset") || json_get(request->input, "bytes")) {
            fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_ID", "normalize", false,
                "byte chunks require an exact revision id", "id");
            json_free(&out);
            return;
        }
        prepared = prepared && json_push_kv_str(&out, "slug", slug) &&
            json_push_kv_int(&out, "response_budget", (int64_t)fb_wiki_response_cap(request)) &&
            fb_wiki_read_allowance(request, &out);
    }
    if (!prepared) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "BOARD_PROJECTION_FAILED", "prepare", false,
            "cannot faithfully build the wiki read request", "fleet.board");
        json_free(&out);
        return;
    }

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    if (!chunk && reply->status == ZCL_COMMAND_STATUS_PASSED)
        fb_wiki_read_next(reply);
    json_free(&body);
}

void zcl_native_fleet_wiki_write_rpc(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct json_value input, body;
    json_init(&input);
    json_init(&body);
    if (!json_copy_checked(&input, request->input) ||
        !json_push_kv_str(&input, "op", "wiki_write")) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "WIKI_PREPARE", "prepare", false, "wiki request projection failed", "json");
    } else if (fb_call_bounded(reply, &input, &body, 0,
        zcl_command_registry_input_budget_bytes(request->spec))) {
        bool replayed = false;
        bool verified = zcl_native_fleet_wiki_receipt_matches(&body, &input, &replayed);
        fb_project_object(reply, &body);
        if (verified) {
            reply->error.mutated = !replayed;
            (void)snprintf(reply->error.current_state, sizeof(reply->error.current_state),
                "%s", replayed ? "retained_replay" : "committed");
        }
    }
    json_free(&body);
    json_free(&input);
}

/* ── fleet wiki list ────────────────────────────────────────────────── */
void zcl_native_handle_fleet_wiki_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "wiki_list");

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    zcl_native_fleet_board_project_list(request, &body, reply);
    json_free(&body);
    (void)zcl_command_reply_add_next(reply, "fleet.wiki.read", "{}",
                                     "read one page in full");
}

/* ── fleet wiki history ─────────────────────────────────────────────── */
void zcl_native_handle_fleet_wiki_history(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (json_get(request->input, "target")) {
        struct json_value out, body;
        json_init(&out); json_set_object(&out); json_init(&body);
        const char *target = json_get_str(json_get(request->input, "target"));
        const struct json_value *cursor = json_get(request->input, "after_id");
        bool prepared = json_push_kv_str(&out, "op", "wiki_history") &&
            target && json_push_kv_str(&out, "target", target);
        if (prepared && cursor)
            prepared = cursor->type == JSON_STR && json_push_kv_str(&out, "after_id", cursor->val.s);
        size_t cap = fb_wiki_response_cap(request);
        prepared = prepared && json_push_kv_int(&out, "response_budget", (int64_t)cap);
        if (prepared && request->success_data_budget_provided)
            prepared = json_push_kv_int(&out, "data_budget", (int64_t)request->success_data_budget);
        if (!prepared)
            fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "REVIEW_REQUEST_FAILED", "prepare", false,
                "cannot faithfully construct target and continuation request", "fleet.wiki.history");
        else if (fb_call(reply, &out, &body, 0)) fb_project_object(reply, &body);
        json_free(&body); json_free(&out);
        return;
    }
    const char *slug = json_get_str(json_get(request->input, "slug"));
    if (!slug || !slug[0]) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_SLUG", "normalize", false,
                "usage: fleet wiki history <slug>", "slug");
        return;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "wiki_history");
    (void)json_push_kv_str(&out, "slug", slug);

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    zcl_native_fleet_board_project_list(request, &body, reply);
    json_free(&body);
}

/* ── fleet wiki find ────────────────────────────────────────────────── */
static bool fb_wiki_find_request(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, struct json_value *out)
{
    size_t budget = request->budget_bytes ? request->budget_bytes : 4096;
    if (budget > 8192) budget = 8192;
    if (budget < 2048) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "QUERY_BUDGET", "normalize", false,
            "wiki queries require at least 2048 response bytes", "budget_bytes");
        return false;
    }
    fb_forward_str(out, request->input, "q", NULL);
    fb_forward_str(out, request->input, "topic", NULL);
    fb_forward_str(out, request->input, "applies_to", NULL);
    fb_forward_str(out, request->input, "after_slug", NULL);
    (void)json_push_kv_int(out, "response_budget", (int64_t)budget);
    return true;
}

void zcl_native_handle_fleet_wiki_find(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "wiki_find");
    if (!fb_wiki_find_request(request, reply, &out)) {
        json_free(&out);
        return;
    }

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body, 0);
    json_free(&out);
    if (!ok)
        return;
    bool advanced = json_get(request->input, "topic") ||
        json_get(request->input, "applies_to") || json_get(request->input, "after_slug");
    if (advanced && strcmp(json_get_str(json_get(&body, "query_schema")),
                            "zcl.fleet_wiki_query.v1")) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "WIKI_QUERY_UNAVAILABLE", "execute", false,
            "the selected node does not report the bounded query contract", "query_schema");
        json_free(&body);
        return;
    }
    fb_project_object(reply, &body);
    json_free(&body);
    const char *id = json_get_str(json_get(json_at(json_get(&reply->data,
        "entries"), 0), "id"));
    bool valid_id = strlen(id) == 64;
    for (size_t i = 0; valid_id && i < 64; i++)
        valid_id = (id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f');
    if (valid_id) {
        char input[96];
        (void)snprintf(input, sizeof(input), "{\"id\":\"%s\"}", id);
        (void)zcl_command_reply_add_next(reply, "fleet.wiki.read", input,
            "read exact revision body chunks and verify the reconstructed post");
    }
}
