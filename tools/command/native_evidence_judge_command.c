/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The leaves `ops.host.slo.soak` and `ops.host.slo.stopwatch`: run
 *          the C6 soak window judge or the C3 stopwatch last-row judge over
 *          a ledger and return its report lines and verdict.
 *
 * WHAT IT DECIDES. Nothing the ledger did not already state: the judges read
 * parsed rows and print a verdict, never a guessed pass. The call passes
 * whenever the ledger was judged; `verdict` and `judge_rc` carry the result,
 * with the exit code the judge scripts used (0 pass, 1 refusal, 2 stale or
 * insufficient). */

#include "native_evidence_judge.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

#define JUDGE_PATH_MAX 512
#define JUDGE_ERR_MAX 160

static const struct json_value *judge_in(const struct zcl_command_request *r,
                                         const char *key)
{
    return r && r->input ? json_get(r->input, key) : NULL;
}

static const char *judge_str(const struct zcl_command_request *r, const char *key)
{
    const struct json_value *v = judge_in(r, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && s[0] ? s : NULL;
}

static void judge_set_int(const struct zcl_command_request *r, const char *key,
                          int64_t *dst)
{
    const struct json_value *v = judge_in(r, key);
    if (v && v->type == JSON_INT)
        *dst = json_get_int(v);
}

static void judge_invalid(struct zcl_command_reply *reply, const char *what,
                          const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "INVALID_JUDGE_INPUT",
                           "validate", false, false, what, evidence);
}

/* The one report line that carries `VERDICT=`, without its newline. */
static void judge_verdict_line(const char *text, char *line, size_t cap)
{
    const char *p = strstr(text, "VERDICT=");
    size_t n = 0;
    line[0] = '\0';
    if (!p)
        return;
    while (p > text && p[-1] != '\n')
        p--;
    while (p[n] && p[n] != '\n' && n + 1 < cap) {
        line[n] = p[n];
        n++;
    }
    line[n] = '\0';
}

static void judge_reply(struct zcl_command_reply *reply, const char *schema,
                        const struct zcl_judge_result *res)
{
    char line[JUDGE_PATH_MAX];
    bool ok;
    judge_verdict_line(res->text, line, sizeof(line));
    ok = json_push_kv_str(&reply->data, "schema", schema) &&
              json_push_kv_str(&reply->data, "verdict", res->verdict) &&
              json_push_kv_str(&reply->data, "reason", res->reason) &&
              json_push_kv_str(&reply->data, "verdict_line", line) &&
              json_push_kv_int(&reply->data, "judge_rc", res->exit_code) &&
              json_push_kv_str(&reply->data, "text", res->text) &&
              json_push_kv_str(&reply->data, "alarm", res->alarm);
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "JUDGE_REPLY_FAILED",
                               "render", false, false,
                               "the judge report could not be assembled", "");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_ops_soak_judge(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    static struct zcl_judge_result res;
    struct zcl_soak_judge_opts opts;
    char path[JUDGE_PATH_MAX], dir_path[JUDGE_PATH_MAX], err[JUDGE_ERR_MAX];
    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_SOAK_JUDGE_SCHEMA);
    const struct json_value *stale = judge_in(request, "allow_stale");
    const char *dir = judge_str(request, "dir");
    if (!zcl_soak_judge_defaults(&opts, path, sizeof(path), err, sizeof(err))) {
        judge_invalid(reply, "a ZCL_SOAK variable is malformed", err);
        return;
    }
    if (dir) {
        (void)snprintf(dir_path, sizeof(dir_path), "%s/evidence.jsonl", dir);
        opts.file = dir_path;
    }
    judge_set_int(request, "window_hours", &opts.window_hours);
    judge_set_int(request, "now", &opts.now_unix);
    opts.allow_stale = stale && stale->type == JSON_BOOL && json_get_bool(stale);
    if (opts.window_hours < 0) {
        judge_invalid(reply, "window_hours must be a positive integer", "");
        return;
    }
    if (!zcl_soak_judge(&opts, &res)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "JUDGE_UNAVAILABLE",
                               "read", false, false,
                               "the soak ledger could not be judged", opts.file);
        return;
    }
    judge_reply(reply, ZCL_SOAK_JUDGE_SCHEMA, &res);
}

static bool judge_sha_ok(const char *sha)
{
    if (strlen(sha) != 64)
        return false;
    for (const char *p = sha; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
            return false;
    return true;
}

void zcl_native_handle_ops_stopwatch_judge(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static struct zcl_judge_result res;
    struct zcl_stopwatch_judge_opts opts;
    char slo[JUDGE_PATH_MAX], err[JUDGE_ERR_MAX];
    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_STOPWATCH_JUDGE_SCHEMA);
    const char *history = judge_str(request, "history");
    const char *sha = judge_str(request, "expect_artifact_sha256");
    const char *slo_in = judge_str(request, "slo_ledger");
    if (!zcl_stopwatch_judge_defaults(&opts, slo, sizeof(slo), err, sizeof(err))) {
        judge_invalid(reply, "a ZCL_STOPWATCH variable is malformed", err);
        return;
    }
    judge_set_int(request, "max_age_secs", &opts.max_age_secs);
    judge_set_int(request, "now", &opts.now_unix);
    opts.history = history;
    opts.slo_ledger = slo_in ? slo_in : opts.slo_ledger;
    opts.expect_sha256 = sha;
    if (!history || opts.max_age_secs < 0 || (sha && !judge_sha_ok(sha))) {
        judge_invalid(reply,
                      "history is required, max_age_secs must be non-negative "
                      "and expect_artifact_sha256 must be 64 lowercase hex "
                      "digits",
                      "");
        return;
    }
    if (!zcl_stopwatch_judge(&opts, &res)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "JUDGE_UNAVAILABLE",
                               "read", false, false,
                               "the stopwatch ledger could not be judged",
                               history);
        return;
    }
    judge_reply(reply, ZCL_STOPWATCH_JUDGE_SCHEMA, &res);
}
