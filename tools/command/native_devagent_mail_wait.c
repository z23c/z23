/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.agent.mail.wait: block (bounded) until a mail row newer than `since`
 * matches the filters dev.agent.mail pull accepts, then return that pull
 * page unchanged. The leaf reads mail through the pull action of
 * zcl_native_handle_dev_agent_mail, so row order, paging, filtering and the
 * next_since token are exactly pull's; following next_since never repeats a
 * row. It never posts and never acks.
 *
 * Wake source: a directory watcher on <state root>/mail, re-armed before
 * every pull so an append between the pull and the wait is not lost. When the
 * watcher cannot open (no mail dir yet, or no native watcher), the wait falls
 * back to re-pulling every WAIT_POLL_MS. */

#include "command/native_command.h"

#include "command/native_dev_bounded_wait.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_watcher.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <string.h>

#define WAIT_LEAF "dev.agent.mail.wait"
#define WAIT_DEFAULT_MS 30000
#define WAIT_MAX_MS 600000
#define WAIT_POLL_MS 2000
#define WAIT_TOKEN_CAP 4096u

/* The pull page comes from the mail leaf's own handler, held as a pointer:
 * this leaf forwards only the filter keys below and never the post keys. */
static const zcl_command_handler_fn wait_pull_handler =
    zcl_native_handle_dev_agent_mail;

static const char *const wait_forward_keys[] = {
    "since", "to", "ref", "from", "kind",
};

static void wait_invalid(struct zcl_command_reply *reply, const char *msg,
                         const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                           "normalize", false, false, msg, evidence);
}

/* timeout_ms: absent -> default; otherwise an integer in 1..WAIT_MAX_MS. */
static bool wait_timeout_ms(const struct json_value *input,
                            struct zcl_command_reply *reply, int64_t *out)
{
    const struct json_value *v = json_get(input, "timeout_ms");
    *out = WAIT_DEFAULT_MS;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type == JSON_INT && json_get_int(v) >= 1 &&
        json_get_int(v) <= WAIT_MAX_MS) {
        *out = json_get_int(v);
        return true;
    }
    wait_invalid(reply, "timeout_ms is an integer in 1..600000",
                 "input.timeout_ms");
    return false;
}

/* The pull request for one attempt: action=pull plus the forwarded filters. */
static bool wait_build_pull(const struct json_value *input,
                            struct json_value *pull)
{
    json_init(pull);
    json_set_object(pull);
    if (!json_push_kv_str(pull, "action", "pull"))
        return false;
    for (size_t i = 0;
         i < sizeof(wait_forward_keys) / sizeof(wait_forward_keys[0]); i++) {
        const struct json_value *v = json_get(input, wait_forward_keys[i]);
        if (v && v->type != JSON_NULL &&
            !json_push_kv(pull, wait_forward_keys[i], v))
            return false;
    }
    return true;
}

static bool wait_mail_dir(char *out, size_t cap)
{
    char state[4096];
    int n;
    if (!platform_state_root_existing(state, sizeof(state)))
        return false;
    n = snprintf(out, cap, "%s/mail", state);
    return n > 0 && (size_t)n < cap;
}

/* Run one pull. True when `out` holds a final reply (rows or a failure). */
static bool wait_pull_once(const struct zcl_command_request *request,
                           struct json_value *pull,
                           struct zcl_command_reply *out)
{
    struct zcl_command_request sub = *request;
    const struct json_value *rows;
    sub.input = pull;
    zcl_command_reply_init(out, "zcl.agent_mail.v1");
    wait_pull_handler(&sub, out);
    if (out->status != ZCL_COMMAND_STATUS_PASSED)
        return true;
    rows = json_get(&out->data, "rows");
    if (rows && rows->type == JSON_ARR && json_size(rows) > 0)
        return true;
    zcl_command_reply_free(out);
    return false;
}

/* Hand the final pull reply to the caller. */
static void wait_move_reply(struct zcl_command_reply *reply,
                            struct zcl_command_reply *final_reply)
{
    const char *schema = reply->data_schema;
    zcl_command_reply_free(reply);
    *reply = *final_reply;
    reply->data_schema = schema;
}

static void wait_timed_out(const struct json_value *input,
                           struct zcl_command_reply *reply)
{
    const struct json_value *since = json_get(input, "since");
    char evidence[256];
    char next[512];
    char token[WAIT_TOKEN_CAP];
    token[0] = '\0';
    if (since && since->type == JSON_STR && json_get_str(since))
        (void)snprintf(token, sizeof(token), "%s", json_get_str(since));
    else if (since && since->type == JSON_INT)
        (void)snprintf(token, sizeof(token), "%lld",
                       (long long)json_get_int(since));
    (void)snprintf(evidence, sizeof(evidence), "since=%s", token);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "WAIT_TIMEOUT", "wait",
                           true, false,
                           "no matching mail row arrived before timeout",
                           evidence);
    struct json_value pull = {0};
    size_t written = 0;
    if (wait_build_pull(input, &pull))
        written = json_write(&pull, next, sizeof(next));
    if (written > 0 && written < sizeof(next))
        (void)zcl_command_reply_add_next(
            reply, "dev.agent.mail", next,
            "pull from the same cursor and filters; nothing was consumed");
    json_free(&pull);
}

/* Sleep until the mail dir changes, the poll interval passes, or the
 * deadline does; re-arms the watcher when it is not open. */
static void wait_sleep(struct platform_directory_watcher *w, bool *armed,
                       const char *dir, bool have_dir,
                       const struct zcl_bounded_wait *bw)
{
    uint32_t slice = (uint32_t)zcl_bounded_wait_slice(bw, WAIT_POLL_MS);
    if (!*armed && have_dir)
        *armed = platform_directory_watcher_open(w, dir);
    if (*armed) {
        if (platform_directory_watcher_wait(w, slice, NULL, NULL) ==
            PLATFORM_DIRECTORY_WATCH_ERROR) {
            platform_directory_watcher_close(w);
            platform_directory_watcher_init(w);
            *armed = false;
            platform_sleep_ms((int)slice);
        }
        return;
    }
    platform_sleep_ms((int)slice);
}

void zcl_native_handle_dev_agent_mail_wait(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct platform_directory_watcher watcher;
    struct zcl_command_reply found;
    struct json_value pull;
    char dir[4096];
    int64_t timeout_ms;
    struct zcl_bounded_wait bw;
    bool armed = false, done = false;

    if (!reply)
        return;
    if (!request || !request->input || !json_get(request->input, "since")) {
        wait_invalid(reply, "since is required: a pull next_since token",
                     "input.since");
        return;
    }
    if (!wait_timeout_ms(request->input, reply, &timeout_ms))
        return;
    if (!wait_build_pull(request->input, &pull)) {
        json_free(&pull);
        wait_invalid(reply, "filters could not be forwarded", "input");
        return;
    }
    platform_directory_watcher_init(&watcher);
    zcl_bounded_wait_begin(&bw, timeout_ms);

    for (;;) {
        int64_t remaining;
        bool have_dir = wait_mail_dir(dir, sizeof(dir));
        /* Arm before the pull so an append in between wakes the next wait. */
        if (!armed && have_dir)
            armed = platform_directory_watcher_open(&watcher, dir);
        if (wait_pull_once(request, &pull, &found)) {
            wait_move_reply(reply, &found);
            done = true;
            break;
        }
        remaining = (int64_t)zcl_bounded_wait_remaining(&bw);
        if (remaining <= 0)
            break;
        wait_sleep(&watcher, &armed, dir, have_dir, &bw);
    }
    if (!done)
        wait_timed_out(request->input, reply);
    if (armed)
        platform_directory_watcher_close(&watcher);
    json_free(&pull);
}
