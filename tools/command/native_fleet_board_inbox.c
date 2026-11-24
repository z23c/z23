/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `fleet board inbox`, `fleet board wait` and `fleet board delivery` — the
 * CLI half of the board's per-agent views (the node half is
 * engine/composition/src/boot_fleet_board_inbox_rpc.c). Like every board
 * leaf they ask the local running node over the `fleet_board` RPC and fail
 * closed when none answers.
 *
 * `wait` is the long-poll an agent uses instead of sleep-and-reread: it asks
 * the node for one bounded wait slice (FLEET_BOARD_WAIT_SLICE_MS) at a time,
 * carrying the cursor forward between slices, for at most
 * FLEET_BOARD_WAIT_MAX_MS in all. When the node's few wait slots are taken
 * it reads the inbox every FLEET_BOARD_WAIT_RETRY_MS instead, so a busy node
 * makes a wait slower, never wrong. It never posts and never consumes.
 *
 * Bound by engine/composition/commands/fleet_board.def. */

#include "command/native_command.h"
#include "command/native_fleet.h"
#include "config/boot_fleet_board.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FBI_AGENT_ENV "BOARD_AGENT"

/* The reader's filters, rebuilt into a fresh RPC object for every call. */
struct fbi_req {
    char agent[FLEET_BOARD_AGENT_MAX + 1];
    char ref[65];
    int64_t after;
    int64_t limit;     /* 0 = node default */
    int64_t text_max;  /* -1 = node default */
};

static void fbi_invalid(struct zcl_command_reply *reply, const char *code,
                        const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, message, evidence ? evidence : "fleet.board");
}

/* An integer input given as a JSON integer or as the digits a shell typed.
 * Absent leaves *out alone and succeeds. */
static bool fbi_int(const struct json_value *in, const char *key, int64_t *out)
{
    const struct json_value *v = json_get(in, key);
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type == JSON_INT) {
        *out = json_get_int(v);
        return true;
    }
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    char *end = NULL;
    if (!s || !s[0])
        return false;
    long long n = strtoll(s, &end, 10);
    if (!end || *end)
        return false;
    *out = (int64_t)n;
    return true;
}

static bool fbi_parse(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, struct fbi_req *out)
{
    const struct json_value *in = request->input;
    memset(out, 0, sizeof(*out));
    out->text_max = -1;
    const char *agent = json_get_str(json_get(in, "agent"));
    if (!agent || !agent[0])
        agent = getenv(FBI_AGENT_ENV);
    const char *ref = json_get_str(json_get(in, "ref"));
    bool ok = (!agent || strlen(agent) <= FLEET_BOARD_AGENT_MAX) &&
              (!ref || strlen(ref) <= 64) && fbi_int(in, "after", &out->after) &&
              fbi_int(in, "limit", &out->limit) &&
              fbi_int(in, "text_max", &out->text_max);
    if (!ok) {
        fbi_invalid(reply, "BAD_INBOX_INPUT",
                    "after, limit and text_max are whole numbers; agent is "
                    "your label (or set BOARD_AGENT); ref is a post id",
                    "input");
        return false;
    }
    (void)snprintf(out->agent, sizeof(out->agent), "%s", agent ? agent : "");
    (void)snprintf(out->ref, sizeof(out->ref), "%s", ref ? ref : "");
    return true;
}

/* The node-side request object for `op`; slice_ms < 0 adds no timeout. */
static bool fbi_build(const struct fbi_req *r, const char *op, int64_t slice_ms,
                      struct json_value *out)
{
    json_init(out);
    json_set_object(out);
    return json_push_kv_str(out, "op", op) &&
           (!r->agent[0] || json_push_kv_str(out, "agent", r->agent)) &&
           (!r->ref[0] || json_push_kv_str(out, "ref", r->ref)) &&
           json_push_kv_int(out, "after", r->after) &&
           (r->limit == 0 || json_push_kv_int(out, "limit", r->limit)) &&
           (r->text_max < 0 || json_push_kv_int(out, "text_max", r->text_max)) &&
           (slice_ms < 0 || json_push_kv_int(out, "timeout_ms", slice_ms));
}

/* Copy the node's reply into the leaf's data, leaving out "ok". */
static bool fbi_project(struct zcl_command_reply *reply, const struct json_value *body)
{
    for (size_t i = 0; body->keys && i < body->num_children; i++) {
        const char *key = body->keys[i];
        if (!key || strcmp(key, "ok") == 0)
            continue;
        if (!json_push_kv(&reply->data, key, &body->children[i])) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_FAILED,
                                   "BOARD_PROJECTION_FAILED", "execute", false,
                                   false, "cannot copy the board response",
                                   "fleet.board");
            return false;
        }
    }
    return true;
}

/* The next-step hint carrying the reader's cursor forward. */
static void fbi_next(struct zcl_command_reply *reply, const char *command,
                     const struct fbi_req *r, const char *reason)
{
    struct json_value next;
    char buf[512];
    json_init(&next);
    json_set_object(&next);
    bool ok = (!r->agent[0] || json_push_kv_str(&next, "agent", r->agent)) &&
              json_push_kv_int(&next, "after", r->after) &&
              (!r->ref[0] || json_push_kv_str(&next, "ref", r->ref));
    size_t n = ok ? json_write(&next, buf, sizeof(buf)) : 0;
    if (n > 0 && n < sizeof(buf))
        (void)zcl_command_reply_add_next(reply, command, buf, reason);
    json_free(&next);
}

static int64_t fbi_next_after(const struct json_value *body, int64_t fallback)
{
    const struct json_value *v = json_get(body, "next_after");
    return v && v->type == JSON_INT ? json_get_int(v) : fallback;
}

/* One node call into `body`. False with the refusal in `reply`. */
static bool fbi_call(const struct fbi_req *r, const char *op, int64_t slice_ms,
                     struct zcl_command_reply *reply, struct json_value *body)
{
    struct json_value call;
    json_init(body);
    if (!fbi_build(r, op, slice_ms, &call)) {
        json_free(&call);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "RPC_INPUT_ALLOC",
                               "prepare", false, false,
                               "the board request could not be built",
                               "fleet.board");
        return false;
    }
    bool answered = zcl_native_fleet_board_call(&call, body, reply);
    json_free(&call);
    if (!answered)
        json_init(body); /* the call released it; leave it safe to free */
    return answered;
}

/* ── fleet board inbox ──────────────────────────────────────────────── */

void zcl_native_handle_fleet_board_inbox(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    struct fbi_req r;
    struct json_value body;
    if (!fbi_parse(request, reply, &r))
        return;
    if (fbi_call(&r, "inbox", -1, reply, &body) && fbi_project(reply, &body)) {
        r.after = fbi_next_after(&body, r.after);
        fbi_next(reply, "fleet.board.wait", &r,
                 "block until the next row for you arrives, from this cursor");
    }
    json_free(&body);
}

/* ── fleet board wait ───────────────────────────────────────────────── */

static bool fbi_wait_timeout(const struct json_value *in,
                             struct zcl_command_reply *reply, int64_t *out)
{
    *out = FLEET_BOARD_WAIT_DEFAULT_MS;
    if (fbi_int(in, "timeout_ms", out) && *out >= 1 &&
        *out <= FLEET_BOARD_WAIT_MAX_MS)
        return true;
    fbi_invalid(reply, "BAD_TIMEOUT",
                "timeout_ms is 1..60000 (default 30000); to wait longer, wait "
                "again from next_after", "input.timeout_ms");
    return false;
}

enum fbi_slice { FBI_SLICE_ROWS, FBI_SLICE_EMPTY, FBI_SLICE_BUSY, FBI_SLICE_FAILED };

/* One node call: a wait slice, or a plain inbox read when `poll`. */
static enum fbi_slice fbi_slice(const struct fbi_req *r, bool poll, int64_t slice_ms,
                                struct zcl_command_reply *reply,
                                struct json_value *body)
{
    if (!fbi_call(r, poll ? "inbox" : "inbox_wait", poll ? -1 : slice_ms, reply,
                  body))
        return strcmp(reply->error.code, "WAIT_BUSY") == 0 ? FBI_SLICE_BUSY
                                                           : FBI_SLICE_FAILED;
    const struct json_value *rows = json_get(body, "rows");
    return rows && rows->type == JSON_ARR && json_size(rows) > 0 ? FBI_SLICE_ROWS
                                                                 : FBI_SLICE_EMPTY;
}

static void fbi_wait_timed_out(struct zcl_command_reply *reply,
                               const struct fbi_req *r, int64_t waited_ms)
{
    char evidence[128];
    (void)snprintf(evidence, sizeof(evidence), "after=%lld waited_ms=%lld",
                   (long long)r->after, (long long)waited_ms);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "WAIT_TIMEOUT", "wait",
                           true, false,
                           "nothing for you arrived before the timeout; "
                           "nothing was consumed", evidence);
    fbi_next(reply, "fleet.board.wait", r, "wait again from the advanced cursor");
}

/* Reset a refused slice's reply so the next call starts clean. */
static void fbi_reply_reset(struct zcl_command_reply *reply)
{
    const char *schema = reply->data_schema;
    zcl_command_reply_free(reply);
    zcl_command_reply_init(reply, schema);
}

static int64_t fbi_min(int64_t a, int64_t b)
{
    return a < b ? a : b;
}

void zcl_native_handle_fleet_board_wait(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    struct fbi_req r;
    struct json_value body;
    int64_t timeout_ms;
    if (!fbi_wait_timeout(request->input, reply, &timeout_ms) ||
        !fbi_parse(request, reply, &r))
        return;
    int64_t start = platform_time_monotonic_ms();
    bool poll = false;
    for (;;) {
        int64_t left = timeout_ms - (platform_time_monotonic_ms() - start);
        enum fbi_slice got = fbi_slice(&r, poll, fbi_min(left > 0 ? left : 0,
                                       FLEET_BOARD_WAIT_SLICE_MS), reply, &body);
        if (got == FBI_SLICE_ROWS && fbi_project(reply, &body)) {
            r.after = fbi_next_after(&body, r.after);
            fbi_next(reply, "fleet.board.wait", &r, "wait for the row after these");
        }
        if (got == FBI_SLICE_ROWS || got == FBI_SLICE_FAILED) {
            json_free(&body);
            return;
        }
        poll = got == FBI_SLICE_BUSY;
        if (poll)
            fbi_reply_reset(reply);
        r.after = fbi_next_after(&body, r.after);
        json_free(&body);
        left = timeout_ms - (platform_time_monotonic_ms() - start);
        if (left <= 0)
            break;
        if (poll)
            platform_sleep_ms((int)fbi_min(left, FLEET_BOARD_WAIT_RETRY_MS));
    }
    fbi_wait_timed_out(reply, &r, platform_time_monotonic_ms() - start);
}

/* ── fleet board delivery ───────────────────────────────────────────── */

void zcl_native_handle_fleet_board_delivery(const struct zcl_command_request *request,
                                            struct zcl_command_reply *reply)
{
    const char *id = json_get_str(json_get(request->input, "id"));
    if (!id || !id[0]) {
        fbi_invalid(reply, "MISSING_ID",
                    "usage: fleet board delivery <id> (the id fleet board post "
                    "printed)", "id");
        return;
    }
    struct json_value req, body;
    json_init(&req);
    json_set_object(&req);
    json_init(&body);
    bool answered = json_push_kv_str(&req, "op", "delivery") &&
                    json_push_kv_str(&req, "id", id) &&
                    zcl_native_fleet_board_call(&req, &body, reply);
    if (answered && fbi_project(reply, &body))
        (void)zcl_command_reply_add_next(reply, "fleet.board.show", "{}",
                                        "read the post itself");
    if (answered)
        json_free(&body);
    json_free(&req);
}
