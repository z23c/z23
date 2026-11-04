/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The leaves `ops.host.slo.soak`, `ops.host.slo.stopwatch` and
 *          `ops.host.slo.tip_agreement`: run the C6 soak window judge, the C3
 *          stopwatch last-row judge or the windowed tip-hash agreement judge
 *          over a ledger and return its report lines and verdict.
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
    const struct json_value *now = judge_in(request, "now");
    if (now && now->type == JSON_INT) opts.now_supplied = true;
    opts.allow_stale = stale && stale->type == JSON_BOOL && json_get_bool(stale);
    if (opts.window_hours < 0 || opts.window_hours > ZCL_SOAK_WINDOW_HOURS_MAX) {
        judge_invalid(reply, "window_hours must fit nonnegative whole seconds", "");
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
    char slo[ZCL_STOPWATCH_LEDGER_PATH_CAP], err[JUDGE_ERR_MAX];
    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_STOPWATCH_JUDGE_SCHEMA);
    const char *history = judge_str(request, "history");
    const char *sha = judge_str(request, "expect_artifact_sha256");
    const char *slo_in = judge_str(request, "slo_ledger");
    if (!zcl_stopwatch_judge_defaults(&opts, slo_in, slo, sizeof(slo), err, sizeof(err))) {
        judge_invalid(reply, "a ZCL_STOPWATCH variable is malformed", err);
        return;
    }
    judge_set_int(request, "max_age_secs", &opts.max_age_secs);
    judge_set_int(request, "now", &opts.now_unix);
    opts.history = history;
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

/* A knob that is present must be a non-negative JSON integer; a wrong type is
 * refused rather than silently falling back to the default. */
static bool tip_knob(const struct zcl_command_request *r, const char *key,
                     int64_t *dst)
{
    const struct json_value *v = judge_in(r, key);
    if (!v)
        return true;
    if (v->type != JSON_INT || json_get_int(v) < 0)
        return false;
    *dst = json_get_int(v);
    return true;
}

static bool tip_read_opts(const struct zcl_command_request *r,
                          struct zcl_tip_judge_opts *o)
{
    int64_t now = 0;
    bool ok = tip_knob(r, "window_hours", &o->window_hours) &&
              tip_knob(r, "max_age_secs", &o->max_age_secs) &&
              tip_knob(r, "min_agree", &o->min_agree) &&
              tip_knob(r, "min_distinct_peers", &o->min_distinct_peers) &&
              tip_knob(r, "max_disagree", &o->max_disagree) &&
              tip_knob(r, "min_span_secs", &o->min_span_secs);
    if (ok && judge_in(r, "now")) {
        ok = tip_knob(r, "now", &now);
        o->now_unix = now;
        o->now_set = ok;
    }
    return ok;
}

void zcl_native_handle_ops_tip_agreement_judge(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static struct zcl_judge_result res;
    struct zcl_tip_judge_opts opts;
    char err[JUDGE_ERR_MAX];
    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_TIP_AGREEMENT_JUDGE_SCHEMA);
    const char *ledger = judge_str(request, "ledger");
    if (!ledger) {
        judge_invalid(reply, "ledger is required", "");
        return;
    }
    if (!zcl_tip_judge_defaults(&opts, err, sizeof(err))) {
        judge_invalid(reply, "ZCL_PARITY_JUDGE_NOW is malformed", err);
        return;
    }
    opts.file = ledger;
    if (!tip_read_opts(request, &opts)) {
        judge_invalid(reply, "every tip-agreement knob must be a non-negative integer", "");
        return;
    }
    if (!zcl_tip_judge_check(&opts, err, sizeof(err))) {
        judge_invalid(reply, "the knob loosens the shipped contract", err);
        return;
    }
    if (!zcl_tip_agreement_judge(&opts, &res)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "JUDGE_UNAVAILABLE",
                               "read", false, false,
                               "the tip-agreement ledger could not be judged", "");
        return;
    }
    judge_reply(reply, ZCL_TIP_AGREEMENT_JUDGE_SCHEMA, &res);
}
