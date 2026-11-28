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
 * the node answers the plain inbox page in the same call and the leaf asks
 * again after FLEET_BOARD_WAIT_RETRY_MS, doubling to
 * FLEET_BOARD_WAIT_RETRY_MAX_MS, so a busy node makes a wait slower, never
 * wrong, and never a busy loop. It never posts and never consumes.
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

static size_t fbi_cap(const struct zcl_command_request *request)
{
    size_t cap = request->spec && request->spec->budget_bytes
                     ? (size_t)request->spec->budget_bytes : ZCL_COMMAND_RESULT_BUDGET;
    if (request->budget_bytes && request->budget_bytes < cap)
        cap = request->budget_bytes;
    return cap;
}

/* The registry's empty-next allowance excludes the item. Measure its full
 * object with the widest signed cursor, plus 10 bytes for ,"next":[] in a
 * compact envelope (the normal envelope already contains that empty array). */
static bool fbi_next_reserve(const struct fbi_req *r, size_t *reserve)
{
    struct json_value input, item;
    json_init(&input);
    json_set_object(&input);
    json_init(&item);
    json_set_object(&item);
    bool ok = (!r->agent[0] || json_push_kv_str(&input, "agent", r->agent)) &&
              json_push_kv_int(&input, "after", INT64_MIN) &&
              (!r->ref[0] || json_push_kv_str(&input, "ref", r->ref)) &&
              json_push_kv_str(&item, "command", "fleet.board.wait") &&
              json_push_kv(&item, "input", &input) &&
              json_push_kv_str(&item, "reason",
                  "block until the next row for you arrives, from this cursor");
    if (ok)
        *reserve = json_write(&item, NULL, 0) + 10;
    json_free(&item);
    json_free(&input);
    return ok;
}

static bool fbi_page_copy(struct json_value *data, const struct json_value *body)
{
    for (size_t i = 0; body->keys && i < body->num_children; i++) {
        const char *key = body->keys[i];
        if (!key || !strcmp(key, "ok") || !strcmp(key, "rows") ||
            !strcmp(key, "returned") || !strcmp(key, "next_after") ||
            !strcmp(key, "has_more") || !strcmp(key, "next") ||
            !strcmp(key, "next_read") || !strcmp(key, "unvouched") ||
            !strcmp(key, "trust_note"))
            continue;
        if (!json_push_kv(data, key, &body->children[i]))
            return false;
    }
    return true;
}

static bool fbi_page_commands(struct json_value *data, const struct fbi_req *r,
                              int64_t cursor)
{
    char cmd[256], ref[80] = "";
    if (r->ref[0])
        (void)snprintf(ref, sizeof(ref), " --ref=%s", r->ref);
    (void)snprintf(cmd, sizeof(cmd), "z23 fleet board wait --agent=%s --after=%lld%s",
                   r->agent, (long long)cursor, ref);
    bool ok = json_push_kv_str(data, "next", cmd);
    (void)snprintf(cmd, sizeof(cmd), "z23 fleet board inbox --agent=%s --after=%lld%s",
                   r->agent, (long long)cursor, ref);
    return ok && json_push_kv_str(data, "next_read", cmd);
}

static bool fbi_page_rows(const struct json_value *source, struct json_value *rows,
                          size_t used, size_t max, unsigned *unvouched)
{
    for (size_t i = 0; i < json_size(source); i++) {
        const struct json_value *row = json_at(source, i);
        size_t n = json_write(row, NULL, 0) + 1;
        if (used + n > max)
            break;
        if (!json_push_back(rows, row))
            return false;
        used += n;
        *unvouched += json_get_bool(json_get(row, "author_role")) ? 0u : 1u;
    }
    return true;
}

static bool fbi_page_metadata(struct json_value *data, size_t cap,
                              bool cut, bool more)
{
    return json_push_kv_bool(data, "has_more", more) &&
           json_push_kv_str(data, "stopped_by", cut ? "byte_budget" : more ? "limit" : "end") &&
           json_push_kv_bool(data, "truncated_by_budget", cut) &&
           json_push_kv_int(data, "byte_budget", (int64_t)cap) &&
           (!cut || json_push_kv_str(data, "notice",
               "The reply byte budget cut this page before the row limit; continue with next_after."));
}

static bool fbi_page_fields(struct json_value *data, const struct json_value *body,
                            const struct json_value *rows, const struct fbi_req *r,
                            size_t cap, unsigned unvouched, int64_t *cursor)
{
    const struct json_value *source = json_get(body, "rows");
    size_t count = json_size(rows);
    bool cut = count < json_size(source);
    bool more = cut || json_get_bool(json_get(body, "has_more"));
    *cursor = cut && count
        ? json_get_int(json_get(json_at(rows, count - 1), "arrival"))
        : fbi_next_after(body, r->after);
    const struct json_value *trust = json_get(body, "trust_note");
    return !(cut && !count) &&
         json_push_kv(data, "rows", rows) &&
         json_push_kv_int(data, "returned", (int64_t)count) &&
         (!unvouched || (trust && json_push_kv_int(data, "unvouched", unvouched) &&
                         json_push_kv(data, "trust_note", trust))) &&
         json_push_kv_int(data, "next_after", *cursor) &&
         fbi_page_metadata(data, cap, cut, more) &&
         fbi_page_commands(data, r, *cursor);
}

/* Serialize the non-row data at its widest: 20-digit signed integers, the
 * longer false booleans, byte-budget notice and any node trust note. The
 * row loop adds each serialized row plus a comma (one byte conservative). */
static bool fbi_page_measure(struct json_value *data, const struct json_value *body,
                             const struct fbi_req *r, size_t cap, size_t *used)
{
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    const struct json_value *trust = json_get(body, "trust_note");
    bool ok = fbi_page_copy(data, body) && json_push_kv(data, "rows", &rows) &&
              json_push_kv_int(data, "returned", INT64_MIN) &&
              (!trust || (json_push_kv_int(data, "unvouched", INT64_MIN) &&
                          json_push_kv(data, "trust_note", trust))) &&
              json_push_kv_int(data, "next_after", INT64_MIN) &&
              fbi_page_metadata(data, cap, true, false) &&
              fbi_page_commands(data, r, INT64_MIN);
    if (ok)
        *used = json_write(data, NULL, 0) + 1; /* false is longer than true */
    json_free(&rows);
    return ok;
}

static bool fbi_page_project(const struct zcl_command_request *request,
                             struct zcl_command_reply *reply,
                             const struct json_value *body, struct fbi_req *r)
{
    const struct json_value *source = json_get(body, "rows");
    struct json_value rows, data, measured;
    json_init(&rows);
    json_set_array(&rows);
    json_init(&data);
    json_set_object(&data);
    json_init(&measured);
    json_set_object(&measured);
    size_t cap = fbi_cap(request);
    size_t allowance = request->success_data_budget_provided
        ? request->success_data_budget : (cap > 1024 ? cap - 1024 : 0);
    size_t used = 0, next = 0;
    bool ok = source && source->type == JSON_ARR &&
              fbi_page_copy(&data, body) &&
              fbi_page_measure(&measured, body, r, cap, &used) &&
              fbi_next_reserve(r, &next);
    size_t max = allowance > next ? allowance - next : 0;
    unsigned unvouched = 0;
    int64_t cursor = r->after;
    ok = ok && used <= max &&
         fbi_page_rows(source, &rows, used, max, &unvouched) &&
         fbi_page_fields(&data, body, &rows, r, cap, unvouched, &cursor);
    if (ok) {
        json_free(&reply->data);
        reply->data = data;
        r->after = cursor;
    } else {
        json_free(&data);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BOARD_PAGE_BUDGET",
                               "serialize", false, false,
                               "the inbox page could not fit or be allocated",
                               "fleet.board.inbox");
    }
    json_free(&measured);
    json_free(&rows);
    return ok;
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
    if (fbi_call(&r, "inbox", -1, reply, &body) &&
        fbi_page_project(request, reply, &body, &r)) {
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

/* One wait slice. A node with no free wait slot answers the plain inbox
 * page in the same call, marked wait_busy: BUSY when it carries no row. */
static enum fbi_slice fbi_slice(const struct fbi_req *r, int64_t slice_ms,
                                struct zcl_command_reply *reply,
                                struct json_value *body)
{
    if (!fbi_call(r, "inbox_wait", slice_ms, reply, body))
        return FBI_SLICE_FAILED;
    const struct json_value *rows = json_get(body, "rows");
    if (rows && rows->type == JSON_ARR && json_size(rows) > 0)
        return FBI_SLICE_ROWS;
    return json_get_bool(json_get(body, "wait_busy")) ? FBI_SLICE_BUSY
                                                       : FBI_SLICE_EMPTY;
}

static void fbi_wait_timed_out(struct zcl_command_reply *reply,
                               const struct fbi_req *r, int64_t waited_ms,
                               bool has_more)
{
    char evidence[128];
    (void)snprintf(evidence, sizeof(evidence), "after=%lld waited_ms=%lld%s",
                   (long long)r->after, (long long)waited_ms,
                   has_more ? " has_more=true" : "");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "WAIT_TIMEOUT", "wait",
                           true, false,
                           has_more ? "the timeout came before the node had read "
                                      "up to the newest row (has_more); rows for "
                                      "you may be waiting: wait or read the inbox "
                                      "again from the cursor. Nothing was consumed"
                                    : "nothing for you arrived before the "
                                      "timeout; nothing was consumed",
                           evidence);
    fbi_next(reply, "fleet.board.wait", r, "wait again from the advanced cursor");
}

static int64_t fbi_min(int64_t a, int64_t b)
{
    return a < b ? a : b;
}

static int64_t fbi_left(int64_t timeout_ms, int64_t start)
{
    int64_t left = timeout_ms - (platform_time_monotonic_ms() - start);
    return left > 0 ? left : 0;
}

/* Between slices: read on at once when the last page stopped short
 * (has_more); after a refused slot, back off (doubling to the ceiling). */
static void fbi_wait_pause(enum fbi_slice got, bool has_more, int64_t left,
                           int64_t *retry_ms)
{
    if (got != FBI_SLICE_BUSY || has_more)
        return;
    platform_sleep_ms((int)fbi_min(left, *retry_ms));
    *retry_ms = fbi_min(*retry_ms * 2, FLEET_BOARD_WAIT_RETRY_MAX_MS);
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
    int64_t retry_ms = FLEET_BOARD_WAIT_RETRY_MS;
    bool has_more = false;
    for (;;) {
        enum fbi_slice got = fbi_slice(
            &r, fbi_min(fbi_left(timeout_ms, start), FLEET_BOARD_WAIT_SLICE_MS),
            reply, &body);
        if (got == FBI_SLICE_ROWS && fbi_project(reply, &body)) {
            r.after = fbi_next_after(&body, r.after);
            fbi_next(reply, "fleet.board.wait", &r, "wait for the row after these");
        }
        if (got == FBI_SLICE_ROWS || got == FBI_SLICE_FAILED) {
            json_free(&body);
            return;
        }
        has_more = json_get_bool(json_get(&body, "has_more"));
        r.after = fbi_next_after(&body, r.after);
        json_free(&body);
        int64_t left = fbi_left(timeout_ms, start);
        if (left <= 0)
            break;
        fbi_wait_pause(got, has_more, left, &retry_ms);
    }
    fbi_wait_timed_out(reply, &r, platform_time_monotonic_ms() - start, has_more);
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
