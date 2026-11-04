/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The MVP C3 stopwatch judge. Grades the last row of a stopwatch
 *          ledger as PASS, FAIL, STALE, THIN_FIXTURE, LAGGING_FIXTURE,
 *          UNBOUND, WRONG_ARTIFACT or INCOMPLETE, with the same report lines
 *          the stopwatch_evidence_judge.sh judge printed.
 *
 * A stopwatch run is a point-in-time proof, so only the last row is read and
 * only freshness is checked. A pass is downgraded when its fixture peer was
 * thin or lagging, and a qualification request binds it to exact bytes. The
 * skip-streak report is additive: it never moves the verdict. */

#include "native_evidence_judge_util.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "services/stopwatch_skip_watch.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SW_LAST_LINE_MAX ((size_t)1 << 20)
#define SW_SLO_MAX ((size_t)64 << 20)
#define SW_SLO_TAIL_LINES 500
#define SW_FIELD_MAX 512
#define SW_SHA_HEX 64

static uint64_t sw_timestamp_distance(int64_t a, int64_t b)
{
    return a >= b ? (uint64_t)a - (uint64_t)b : (uint64_t)b - (uint64_t)a;
}

static bool sw_row_age(int64_t now, int64_t then, int64_t *age)
{
    if ((then > 0 && now < INT64_MIN + then) ||
        (then < 0 && now > INT64_MAX + then))
        return false;
    *age = now - then;
    return true;
}

static void sw_emit(struct zcl_judge_result *out, int code, const char *verdict,
                    const char *reason, const char *extra, const char *artifact)
{
    ej_cat(out, "stopwatch-judge: VERDICT=%s reason=%s%s artifact=%s\n", verdict,
           reason, extra, artifact);
    ej_verdict(out, code, verdict, reason);
    (void)snprintf(out->artifact, sizeof(out->artifact), "%s", artifact);
}

enum sw_tail { SW_NO_DATA, SW_EMPTY, SW_INVALID, SW_ROW };

static enum sw_tail sw_decode_tail(const char *buf, size_t n, bool prefix_missing,
                                   struct json_value *row)
{
    if (n && buf[n - 1] == '\n') n--;
    size_t start = n;
    while (start && buf[start - 1] != '\n') start--;
    size_t len = n - start;
    if ((!start && prefix_missing) || len > SW_LAST_LINE_MAX) return SW_INVALID;
    if (!len) return SW_EMPTY;
    if (!zutf8_validate_n(buf + start, len)) return SW_INVALID;
    if (!json_read(row, buf + start, len) || row->type != JSON_OBJ) return SW_INVALID;
    return SW_ROW;
}

static enum sw_tail sw_last_row(const char *path, struct json_value *row)
{
    FILE *f = fopen(path, "rb");
    if (!f) return SW_NO_DATA;
    enum sw_tail status = SW_NO_DATA;
    long size;
    if (fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) > 0) {
        /* Include room for both the final LF and the preceding delimiter. */
        size_t take = (size_t)size < SW_LAST_LINE_MAX + 2 ? (size_t)size : SW_LAST_LINE_MAX + 2;
        char *buf = zcl_malloc(take, "stopwatch tail");
        if (buf && fseek(f, size - (long)take, SEEK_SET) == 0 &&
            fread(buf, 1, take, f) == take)
            status = sw_decode_tail(buf, take, (size_t)size > take, row);
        free(buf);
    }
    return fclose(f) == 0 ? status : SW_NO_DATA;
}

/* Only guarded fields participate in the verdict. Their order is immaterial. */
static bool sw_unambiguous(const struct json_value *row)
{
    static const char *const fields[] = {
        "ts", "verdict", "artifact_dir", "node_bin_sha256", "final_network_tip", "result_class"
    };
    for (size_t j = 0; j < sizeof fields / sizeof fields[0]; j++) {
        unsigned count = 0;
        for (size_t i = 0; i < row->num_children; i++)
            if (strcmp(row->keys[i], fields[j]) == 0 && ++count > 1) return false;
    }
    return true;
}

/* The oracle height of the newest SLO row that carries one, if that row is
 * within `max_age` of now. The first row with a height decides. */
enum sw_oracle_state { SW_NO_HEIGHT, SW_OLD_HEIGHT, SW_FRESH_HEIGHT, SW_BAD_HEIGHT, SW_NEED_PREFIX };

static size_t sw_key_count(const struct json_value *row, const char *name)
{
    size_t count = 0;
    for (size_t i = 0; i < row->num_children; ++i)
        if (strcmp(row->keys[i], name) == 0) ++count;
    return count;
}

static enum sw_oracle_state sw_oracle_value(const struct json_value *row, int64_t now,
                                             int64_t max_age, int64_t *height)
{
    if (row->type != JSON_OBJ || sw_key_count(row, "oracle_height") > 1)
        return SW_BAD_HEIGHT;
    const struct json_value *oh = json_get(row, "oracle_height");
    if (json_is_null(oh)) return SW_NO_HEIGHT;
    if (oh->type != JSON_INT || oh->val.i < 0 || sw_key_count(row, "ts") != 1)
        return SW_BAD_HEIGHT;
    const struct json_value *ts = json_get(row, "ts");
    if (ts->type != JSON_INT) return SW_BAD_HEIGHT;
    if (max_age <= 0 || sw_timestamp_distance(now, ts->val.i) >= (uint64_t)max_age)
        return SW_OLD_HEIGHT;
    *height = oh->val.i;
    return SW_FRESH_HEIGHT;
}

static enum sw_oracle_state sw_oracle_record(const char *line, size_t len, int64_t now,
                                              int64_t max_age, int64_t *height)
{
    if (len == 0) return SW_NO_HEIGHT;
    if (len > SW_SLO_MAX || !zutf8_validate_n(line, len)) return SW_BAD_HEIGHT;
    struct json_value row = {0};
    enum sw_oracle_state state = json_read(&row, line, len)
        ? sw_oracle_value(&row, now, max_age, height) : SW_BAD_HEIGHT;
    json_free(&row);
    return state;
}

/* A partial first record can be judged only after its delimiter or file start is known. */
static enum sw_oracle_state sw_oracle_scan(const char *buf, size_t len, bool partial,
                                           int64_t now, int64_t max_age, int64_t *height)
{
    const char *end = buf + len;
    if (end > buf && end[-1] == '\n') end--;
    for (int i = 0; i < SW_SLO_TAIL_LINES; i++) {
        const char *start = end;
        while (start > buf && start[-1] != '\n') start--;
        if (start == buf && partial) return SW_NEED_PREFIX;
        enum sw_oracle_state state = sw_oracle_record(start, (size_t)(end - start),
                                                       now, max_age, height);
        if (state != SW_NO_HEIGHT || start == buf) return state;
        end = start - 1;
    }
    return SW_NO_HEIGHT;
}

static enum sw_oracle_state sw_oracle_tail(FILE *fp, long size, int64_t now,
                                           int64_t max_age, int64_t *height)
{
    const size_t limit = SW_SLO_MAX + 2; /* record plus both delimiting LFs */
    size_t take = (size_t)size < 4096 ? (size_t)size : 4096;
    char *buf = NULL;
    enum sw_oracle_state state = SW_BAD_HEIGHT;
    size_t have = 0;
    while (take > have) {
        char *larger = zcl_realloc(buf, take, "stopwatch oracle tail");
        if (!larger) break;
        buf = larger;
        size_t extra = take - have;
        if (have) memmove(buf + extra, buf, have);
        if (fseek(fp, size - (long)take, SEEK_SET) != 0 || fread(buf, 1, extra, fp) != extra)
            break;
        state = sw_oracle_scan(buf, take, take < (size_t)size, now, max_age, height);
        if (state != SW_NEED_PREFIX) break;
        state = SW_BAD_HEIGHT;
        have = take;
        take = take > limit / 2 ? limit : take * 2;
        if (take > (size_t)size) take = (size_t)size;
    }
    free(buf);
    return state;
}

static enum sw_oracle_state sw_oracle(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                                      int64_t *height)
{
    if (!o->slo_ledger) return SW_NO_HEIGHT;
    FILE *fp = fopen(o->slo_ledger, "rb");
    if (!fp) return errno == ENOENT ? SW_NO_HEIGHT : SW_BAD_HEIGHT;
    enum sw_oracle_state state = SW_BAD_HEIGHT;
    long size;
    if (fseek(fp, 0, SEEK_END) == 0 && (size = ftell(fp)) >= 0)
        state = size ? sw_oracle_tail(fp, size, now, o->oracle_max_age_secs, height) : SW_NO_HEIGHT;
    return fclose(fp) == 0 ? state : SW_BAD_HEIGHT;
}



static bool sw_proof_root_pass(const struct json_value *proof)
{
    if (proof->type != JSON_OBJ) return false;
    const struct json_value *verdict = json_get(proof, "verdict");
    return sw_key_count(proof, "verdict") == 1 && verdict && verdict->type == JSON_STR &&
           strcmp(json_get_str(verdict), "pass") == 0;
}

/* A complete JSON object with exactly one root string verdict of "pass". */
static bool sw_proof_says_pass(const char *artifact)
{
    char path[SW_FIELD_MAX + 16];
    size_t len = 0;
    char *buf;
    bool pass = false;
    int n = snprintf(path, sizeof(path), "%s/proof.json", artifact);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    buf = ej_slurp(path, (size_t)16 << 20, &len);
    struct json_value proof = {0};
    if (buf && zutf8_validate_n(buf, len) && json_read(&proof, buf, len))
        pass = sw_proof_root_pass(&proof);
    json_free(&proof);
    free(buf);
    return pass;
}

static bool sw_qualify(const struct zcl_stopwatch_judge_opts *o, const struct json_value *row,
                       const char *artifact, struct zcl_judge_result *out)
{
    const char *sha = json_get_str(json_get(row, "node_bin_sha256"));
    char reason[ZCL_JUDGE_REASON_MAX];
    if (!sha[0]) {
        sw_emit(out, 1, "UNBOUND", "row_names_no_executable_digest", "", artifact);
        return false;
    }
    if (strcmp(sha, o->expect_sha256) != 0) {
        (void)snprintf(reason, sizeof(reason), "measured_%s_not_%s", sha,
                       o->expect_sha256);
        sw_emit(out, 1, "WRONG_ARTIFACT", reason, "", artifact);
        return false;
    }
    if (!json_get_str(json_get(row, "artifact_dir"))[0] || !sw_proof_says_pass(artifact)) {
        sw_emit(out, 1, "INCOMPLETE", "artifact_proof_json_missing_or_not_pass",
                "", artifact);
        return false;
    }
    return true;
}

static bool sw_gate_fixture(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                            const struct json_value *row, const char *artifact, bool *ledger,
                            struct zcl_judge_result *out)
{
    const struct json_value *tip = json_get(row, "final_network_tip");
    char reason[ZCL_JUDGE_REASON_MAX];
    int64_t oracle = 0;
    if (tip && tip->type != JSON_INT && tip->type != JSON_NULL) {
        sw_emit(out, 1, "INCOMPLETE", "invalid_final_network_tip", "", artifact);
        return false;
    }
    if (tip && tip->type == JSON_INT && tip->val.i < o->checkpoint_height) {
        (void)snprintf(reason, sizeof(reason),
                       "final_network_tip_%lld_below_checkpoint_%lld",
                       (long long)tip->val.i, (long long)o->checkpoint_height);
        sw_emit(out, 1, "THIN_FIXTURE", reason, "", artifact);
        return false;
    }
    enum sw_oracle_state observed = sw_oracle(o, now, &oracle);
    if (observed == SW_BAD_HEIGHT) {
        sw_emit(out, 1, "INCOMPLETE", "invalid_oracle_evidence", " ledger_available=false", artifact);
        return false;
    }
    *ledger = observed == SW_FRESH_HEIGHT;
    if (*ledger && tip && tip->type == JSON_INT && oracle - tip->val.i > o->oracle_lag_budget) {
        (void)snprintf(reason, sizeof(reason),
                       "final_network_tip_%lld_lags_oracle_%lld_by_%lld_gt_budget_%lld",
                       (long long)tip->val.i, (long long)oracle,
                       (long long)(oracle - tip->val.i),
                       (long long)o->oracle_lag_budget);
        sw_emit(out, 1, "LAGGING_FIXTURE", reason, " ledger_available=true",
                artifact);
        return false;
    }
    return true;
}

static void sw_judge_pass(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                          int64_t age, const struct json_value *row, const char *artifact,
                          struct zcl_judge_result *out)
{
    char reason[ZCL_JUDGE_REASON_MAX], extra[SW_FIELD_MAX];
    bool ledger = false, bound = o->expect_sha256 && o->expect_sha256[0];
    if (!sw_gate_fixture(o, now, row, artifact, &ledger, out))
        return;
    if (bound && !sw_qualify(o, row, artifact, out))
        return;
    (void)snprintf(reason, sizeof(reason), "last_run_verdict_pass_age_%llds",
                   (long long)age);
    if (bound)
        (void)snprintf(extra, sizeof(extra),
                       " qualification=bound executable=%s ledger_available=%s",
                       o->expect_sha256, ledger ? "true" : "false");
    else
        (void)snprintf(extra, sizeof(extra),
                       " qualification=unbound ledger_available=%s",
                       ledger ? "true" : "false");
    sw_emit(out, 0, "PASS", reason, extra, artifact);
}

static void sw_report_streaks(const struct zcl_stopwatch_judge_opts *o,
                              int64_t now, struct zcl_judge_result *out)
{
    struct stopwatch_skip_report rep;
    char age[32] = "none", text[ZCL_JUDGE_ALARM_MAX];
    if (!stopwatch_skip_read_ledger(o->history, &rep))
        return;
    if (rep.last_pass_ts >= 0)
        (void)snprintf(age, sizeof(age), "%lld", (long long)(now - rep.last_pass_ts));
    ej_cat(out, "stopwatch-judge: SKIP_STREAK skip_streak=%u no_pass_streak=%u class=%s threshold=%u last_pass_age=%s rows_scanned=%u\n",
           rep.skip_streak, rep.no_pass_streak,
           rep.skip_streak > 0 ? rep.skip_class : "-",
           rep.skip_streak > 0 ? rep.threshold : 0u, age, rep.rows_scanned);
    if (rep.alarm || rep.no_pass_alarm)
        (void)snprintf(out->alarm, sizeof(out->alarm), "stopwatch-judge: %s",
                       stopwatch_skip_alarm_text(&rep, text, sizeof(text)));
}

static void sw_judge_row(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                         const struct json_value *row, struct zcl_judge_result *out)
{
    const char *verdict = json_get_str(json_get(row, "verdict"));
    const char *artifact = json_get_str(json_get(row, "artifact_dir"));
    const char *klass = json_get_str(json_get(row, "result_class"));
    char reason[ZCL_JUDGE_REASON_MAX], extra[SW_FIELD_MAX];
    const struct json_value *ts = json_get(row, "ts");
    int64_t age;
    if (!artifact[0])
        artifact = "-";
    if (!ts || ts->type != JSON_INT) {
        sw_emit(out, 2, "STALE", "malformed_last_line_no_ts", "", artifact);
        return;
    }
    if (!sw_row_age(now, ts->val.i, &age)) {
        sw_emit(out, 2, "STALE", "last_sample_age_unrepresentable", "", artifact);
        return;
    }
    if (age > o->max_age_secs) {
        (void)snprintf(reason, sizeof(reason), "last_sample_age_%llds_gt_%llds",
                       (long long)age, (long long)o->max_age_secs);
        sw_emit(out, 2, "STALE", reason, "", artifact);
        return;
    }
    if (!verdict[0]) {
        sw_emit(out, 2, "STALE", "missing_verdict_field", "", artifact);
        return;
    }
    if (strcmp(verdict, "pass") == 0) {
        sw_judge_pass(o, now, age, row, artifact, out);
        return;
    }
    (void)snprintf(reason, sizeof(reason), "last_run_verdict_%s_age_%llds",
                   verdict, (long long)age);
    (void)snprintf(extra, sizeof(extra), " class=%s", klass[0] ? klass : "unrecorded");
    (void)snprintf(out->result_class, sizeof(out->result_class), "%s", klass);
    sw_emit(out, 1, "FAIL", reason, extra, artifact);
}

bool zcl_stopwatch_judge(const struct zcl_stopwatch_judge_opts *opts,
                         struct zcl_judge_result *out)
{
    struct json_value row = {0};
    if (!opts || !opts->history || !out)
        return false;
    memset(out, 0, sizeof(*out));
    enum sw_tail have = sw_last_row(opts->history, &row);
    int64_t now = ej_now(opts->now_unix);
    if (have == SW_ROW || have == SW_INVALID) sw_report_streaks(opts, now, out);
    if (have == SW_NO_DATA)
        sw_emit(out, 2, "STALE", "no_evidence_file", "", "-");
    else if (have == SW_EMPTY)
        sw_emit(out, 2, "STALE", "empty_last_line", "", "-");
    else if (have == SW_INVALID)
        sw_emit(out, 2, "STALE", "malformed_last_line_no_ts", "", "-");
    else if (!sw_unambiguous(&row))
        sw_emit(out, 2, "STALE", "ambiguous_last_row", "", "-");
    else
        sw_judge_row(opts, now, &row, out);
    json_free(&row);
    return true;
}

static bool sw_env(const char *name, const char *text, int64_t *value, char *err,
                   size_t err_cap)
{
    return ej_env_int(name, text, value, err, err_cap) >= 0;
}

bool zcl_stopwatch_judge_defaults(struct zcl_stopwatch_judge_opts *opts,
                                  char *slo_path, size_t cap, char *err,
                                  size_t err_cap)
{
    const char *slo = getenv("ZCL_STOPWATCH_SLO_LEDGER");
    const char *home = getenv("HOME");
    memset(opts, 0, sizeof(*opts));
    opts->max_age_secs = ZCL_STOPWATCH_MAX_AGE_SECS;
    opts->checkpoint_height = ZCL_STOPWATCH_CHECKPOINT_HEIGHT;
    opts->oracle_lag_budget = ZCL_STOPWATCH_ORACLE_LAG_BUDGET;
    opts->oracle_max_age_secs = ZCL_STOPWATCH_ORACLE_MAX_AGE_SECS;
    if (!sw_env("ZCL_STOPWATCH_CHECKPOINT_HEIGHT", getenv("ZCL_STOPWATCH_CHECKPOINT_HEIGHT"), &opts->checkpoint_height, err, err_cap) ||
        !sw_env("ZCL_STOPWATCH_ORACLE_LAG_BUDGET", getenv("ZCL_STOPWATCH_ORACLE_LAG_BUDGET"), &opts->oracle_lag_budget, err, err_cap) ||
        !sw_env("ZCL_STOPWATCH_ORACLE_MAX_AGE_SECS", getenv("ZCL_STOPWATCH_ORACLE_MAX_AGE_SECS"), &opts->oracle_max_age_secs, err, err_cap) ||
        !sw_env("ZCL_STOPWATCH_JUDGE_NOW", getenv("ZCL_STOPWATCH_JUDGE_NOW"), &opts->now_unix, err, err_cap))
        return false;
    if (slo && slo[0])
        (void)snprintf(slo_path, cap, "%s", slo);
    else
        (void)snprintf(slo_path, cap,
                       "%s/.local/state/zclassic23-slo/uptime-ledger.jsonl",
                       home && home[0] ? home : "/root");
    opts->slo_ledger = slo_path;
    return true;
}
