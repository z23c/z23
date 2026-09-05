/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet board *` and `fleet wiki *` — the CLI half of the fleet AI message
 * board and wiki.
 *
 * These leaves run in a one-shot process launched from a checkout, which
 * holds no node state and no host identity. Every one of them therefore asks
 * the LOCAL RUNNING NODE over the `fleet_board` RPC method and FAILS CLOSED
 * when no node answers, naming the exact command that starts one. It never
 * falls back to a private file: a board only one process can see is a
 * notebook, and two agents keeping private notebooks is precisely the problem
 * this branch exists to remove.
 *
 * Bound by engine/composition/commands/fleet_board.def.
 */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"

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

/* The one refusal that matters: there is no node to ask. It names the command
 * that fixes it, because an agent that cannot reach the board needs the next
 * action, not a diagnosis. */
static void fb_no_node(struct zcl_command_reply *reply)
{
    fb_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
            "NODE_UNAVAILABLE", "dispatch", true,
            "no local node answered. The board lives in the node, and this "
            "command never writes a private copy. Start a node with "
            "`build/bin/zclassic23 -daemon`, then run this again.",
            "fleet.board");
    (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                     "confirm a local node is running");
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

/* One round trip. On success `body` holds the node's reply object and the
 * caller owns it; on failure the reply is already filled in. */
static bool fb_call(struct zcl_command_reply *reply, struct json_value *in,
                    struct json_value *body)
{
    char params[FLEET_BOARD_RPC_PARAMS_MAX];
    if (!fb_params(in, params, sizeof(params))) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INPUT_TOO_LARGE", "normalize", false,
                "the request does not fit one board call; a wiki page is "
                "capped at 16 KiB and a post at 2 KiB", "fleet.board");
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("fleet_board", params);
    if (!raw) {
        fb_no_node(reply);
        return false;
    }
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
     * needs the command that starts a node, not a protocol message. */
    const struct json_value *ok = json_get(body, "ok");
    const struct json_value *err = json_get(body, "error");
    const struct json_value *bare_code = json_get(body, "code");
    const struct json_value *bare_msg = json_get(body, "message");
    bool board_answered = ok && ok->type == JSON_BOOL;
    bool transport_error =
        (err && !json_is_null(err)) ||
        (bare_code && bare_code->type == JSON_INT && bare_msg &&
         bare_msg->type == JSON_STR);
    if (!board_answered && transport_error) {
        fb_no_node(reply);
        json_free(body);
        return false;
    }
    if (transport_error) {
        const char *msg = err && err->type == JSON_OBJ
                              ? json_get_str(json_get(err, "message"))
                              : NULL;
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "BOARD_RPC_ERROR", "execute", false,
                msg && msg[0] ? msg : "the node reported an error",
                "fleet.board");
        json_free(body);
        return false;
    }
    if (ok && ok->type == JSON_BOOL && !json_get_bool(ok)) {
        const char *code = json_get_str(json_get(body, "code"));
        const char *msg = json_get_str(json_get(body, "message"));
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                code && code[0] ? code : "BOARD_REFUSED", "execute", false,
                msg && msg[0] ? msg : "the board refused this request",
                "fleet.board");
        json_free(body);
        return false;
    }
    return true;
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
static void fb_project_list(struct zcl_command_reply *reply,
                            const struct json_value *body)
{
    const struct json_value *posts = json_get(body, "posts");
    struct json_value lines;
    json_init(&lines);
    json_set_array(&lines);
    if (posts && posts->type == JSON_ARR) {
        for (size_t i = 0; i < json_size(posts); i++) {
            char line[FLEET_BOARD_LINE_MAX];
            fb_post_line(json_at(posts, i), line, sizeof(line));
            struct json_value item;
            json_init(&item);
            json_set_str(&item, line);
            (void)json_push_back(&lines, &item);
            json_free(&item);
        }
    }
    (void)json_push_kv(&reply->data, "lines", &lines);
    json_free(&lines);
    if (posts)
        (void)json_push_kv(&reply->data, "posts", posts);
    const struct json_value *returned = json_get(body, "returned");
    if (returned && returned->type == JSON_INT)
        (void)json_push_kv_int(&reply->data, "returned",
                               json_get_int(returned));
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
        (void)json_push_kv(&reply->data, key, &body->children[i]);
    }
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
    fb_forward_int(&out, in, "ttl");

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
}

/* ── fleet board list ───────────────────────────────────────────────── */
void zcl_native_handle_fleet_board_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "list");
    fb_forward_str(&out, in, "kind", NULL);
    fb_forward_str(&out, in, "host", NULL);
    fb_forward_int(&out, in, "since");
    fb_forward_int(&out, in, "limit");
    const struct json_value *open = json_get(in, "open");
    if (open && ((open->type == JSON_BOOL && json_get_bool(open)) ||
                 open->type == JSON_STR))
        (void)json_push_kv_bool(&out, "open", true);

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body);
    json_free(&out);
    if (!ok)
        return;
    fb_project_list(reply, &body);
    json_free(&body);
    (void)zcl_command_reply_add_next(
        reply, "fleet.board.show", "{}",
        "read one post whole, including its receipt");
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
    bool ok = fb_call(reply, &out, &body);
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
    bool ok = fb_call(reply, &out, &body);
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

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
}

/* ── fleet wiki read ────────────────────────────────────────────────── */
void zcl_native_handle_fleet_wiki_read(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *slug = json_get_str(json_get(request->input, "slug"));
    if (!slug || !slug[0]) {
        fb_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_SLUG", "normalize", false,
                "usage: fleet wiki read <slug>", "slug");
        return;
    }
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    (void)json_push_kv_str(&out, "op", "wiki_read");
    (void)json_push_kv_str(&out, "slug", slug);

    struct json_value body;
    json_init(&body);
    bool ok = fb_call(reply, &out, &body);
    json_free(&out);
    if (!ok)
        return;
    fb_project_object(reply, &body);
    json_free(&body);
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
    bool ok = fb_call(reply, &out, &body);
    json_free(&out);
    if (!ok)
        return;
    fb_project_list(reply, &body);
    json_free(&body);
    (void)zcl_command_reply_add_next(reply, "fleet.wiki.read", "{}",
                                     "read one page in full");
}

/* ── fleet wiki history ─────────────────────────────────────────────── */
void zcl_native_handle_fleet_wiki_history(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
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
    bool ok = fb_call(reply, &out, &body);
    json_free(&out);
    if (!ok)
        return;
    fb_project_list(reply, &body);
    json_free(&body);
}
