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
#include "services/stopwatch_skip_watch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SW_LAST_LINE_MAX ((size_t)1 << 20)
#define SW_SLO_MAX ((size_t)64 << 20)
#define SW_SLO_TAIL_LINES 500
#define SW_FIELD_MAX 512
#define SW_SHA_HEX 64

static void sw_emit(struct zcl_judge_result *out, int code, const char *verdict,
                    const char *reason, const char *extra, const char *artifact)
{
    ej_cat(out, "stopwatch-judge: VERDICT=%s reason=%s%s artifact=%s\n", verdict,
           reason, extra, artifact);
    ej_verdict(out, code, verdict, reason);
    (void)snprintf(out->artifact, sizeof(out->artifact), "%s", artifact);
}

/* Last line of the file as `tail -n 1` prints it. 0 = no data, 1 = empty
 * last line, 2 = read. */
static int sw_last_line(const char *path, char *line, size_t cap)
{
    FILE *f = fopen(path, "rb");
    long size;
    size_t take, n, start;
    char *buf;
    if (!f)
        return 0;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0) {
        (void)fclose(f);
        return 0;
    }
    take = (size_t)size < SW_LAST_LINE_MAX ? (size_t)size : SW_LAST_LINE_MAX;
    buf = zcl_malloc(take + 1, "stopwatch tail");
    if (!buf || fseek(f, size - (long)take, SEEK_SET) != 0) {
        free(buf);
        (void)fclose(f);
        return 0;
    }
    n = fread(buf, 1, take, f);
    (void)fclose(f);
    if (n > 0 && buf[n - 1] == '\n')
        n--;
    buf[n] = '\0';
    for (start = n; start > 0 && buf[start - 1] != '\n'; start--)
        ;
    (void)snprintf(line, cap, "%s", buf + start);
    free(buf);
    return line[0] ? 2 : 1;
}

/* The oracle height of the newest SLO row that carries one, if that row is
 * within `max_age` of now. The first row with a height decides. */
static bool sw_oracle(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                      int64_t *height)
{
    size_t len = 0;
    char *buf = o->slo_ledger ? ej_slurp(o->slo_ledger, SW_SLO_MAX, &len) : NULL;
    char *end;
    bool found = false;
    if (!buf)
        return false;
    end = buf + len;
    if (end > buf && end[-1] == '\n')
        end--;
    for (int i = 0; i < SW_SLO_TAIL_LINES && end >= buf; i++) {
        char *start = end;
        struct ej_num oh, ts;
        while (start > buf && start[-1] != '\n')
            start--;
        *end = '\0';
        oh = ej_field_num(start, "oracle_height", false);
        ts = ej_field_num(start, "ts", false);
        if (oh.kind == EJ_NUM && ts.kind == EJ_NUM) {
            int64_t age = now > ts.n ? now - ts.n : ts.n - now;
            found = age < o->oracle_max_age_secs;
            *height = oh.n;
            break;
        }
        if (start == buf)
            break;
        end = start - 1;
    }
    free(buf);
    return found;
}

/* `"verdict": "pass"` anywhere on one line of the proof file. */
static bool sw_proof_says_pass(const char *artifact)
{
    char path[SW_FIELD_MAX + 16];
    size_t len = 0;
    char *buf;
    const char *p;
    bool pass = false;
    (void)snprintf(path, sizeof(path), "%s/proof.json", artifact);
    buf = ej_slurp(path, (size_t)16 << 20, &len);
    for (p = buf; p && (p = strstr(p, "\"verdict\"")) != NULL; p++) {
        const char *q = p + strlen("\"verdict\"");
        while (*q == ' ' || *q == '\t' || *q == '\r')
            q++;
        if (*q++ != ':')
            continue;
        while (*q == ' ' || *q == '\t' || *q == '\r')
            q++;
        if (strncmp(q, "\"pass\"", 6) == 0) {
            pass = true;
            break;
        }
    }
    free(buf);
    return pass;
}

static bool sw_qualify(const struct zcl_stopwatch_judge_opts *o, const char *line,
                       const char *artifact, struct zcl_judge_result *out)
{
    char sha[SW_FIELD_MAX], reason[ZCL_JUDGE_REASON_MAX];
    if (!ej_field_str(line, "node_bin_sha256", sha, sizeof(sha)) || !sha[0]) {
        sw_emit(out, 1, "UNBOUND", "row_names_no_executable_digest", "", artifact);
        return false;
    }
    if (strcmp(sha, o->expect_sha256) != 0) {
        (void)snprintf(reason, sizeof(reason), "measured_%s_not_%s", sha,
                       o->expect_sha256);
        sw_emit(out, 1, "WRONG_ARTIFACT", reason, "", artifact);
        return false;
    }
    if (!sw_proof_says_pass(artifact)) {
        sw_emit(out, 1, "INCOMPLETE", "artifact_proof_json_missing_or_not_pass",
                "", artifact);
        return false;
    }
    return true;
}

static bool sw_gate_fixture(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                            const char *line, const char *artifact, bool *ledger,
                            struct zcl_judge_result *out)
{
    struct ej_num tip = ej_field_num(line, "final_network_tip", false);
    char reason[ZCL_JUDGE_REASON_MAX];
    int64_t oracle = 0;
    if (tip.kind == EJ_NUM && tip.n < o->checkpoint_height) {
        (void)snprintf(reason, sizeof(reason),
                       "final_network_tip_%lld_below_checkpoint_%lld",
                       (long long)tip.n, (long long)o->checkpoint_height);
        sw_emit(out, 1, "THIN_FIXTURE", reason, "", artifact);
        return false;
    }
    *ledger = sw_oracle(o, now, &oracle);
    if (*ledger && tip.kind == EJ_NUM && oracle - tip.n > o->oracle_lag_budget) {
        (void)snprintf(reason, sizeof(reason),
                       "final_network_tip_%lld_lags_oracle_%lld_by_%lld_gt_budget_%lld",
                       (long long)tip.n, (long long)oracle,
                       (long long)(oracle - tip.n),
                       (long long)o->oracle_lag_budget);
        sw_emit(out, 1, "LAGGING_FIXTURE", reason, " ledger_available=true",
                artifact);
        return false;
    }
    return true;
}

static void sw_judge_pass(const struct zcl_stopwatch_judge_opts *o, int64_t now,
                          int64_t age, const char *line, const char *artifact,
                          struct zcl_judge_result *out)
{
    char reason[ZCL_JUDGE_REASON_MAX], extra[SW_FIELD_MAX];
    bool ledger = false, bound = o->expect_sha256 && o->expect_sha256[0];
    if (!sw_gate_fixture(o, now, line, artifact, &ledger, out))
        return;
    if (bound && !sw_qualify(o, line, artifact, out))
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
                         const char *line, struct zcl_judge_result *out)
{
    char verdict[SW_FIELD_MAX] = "", artifact[SW_FIELD_MAX] = "";
    char klass[SW_FIELD_MAX] = "", reason[ZCL_JUDGE_REASON_MAX], extra[SW_FIELD_MAX];
    struct ej_num ts = ej_field_num(line, "ts", false);
    int64_t age;
    (void)ej_field_str(line, "verdict", verdict, sizeof(verdict));
    (void)ej_field_str(line, "artifact_dir", artifact, sizeof(artifact));
    if (!artifact[0])
        (void)snprintf(artifact, sizeof(artifact), "-");
    sw_report_streaks(o, now, out);
    if (ts.kind != EJ_NUM) {
        sw_emit(out, 2, "STALE", "malformed_last_line_no_ts", "", artifact);
        return;
    }
    age = now - ts.n;
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
        sw_judge_pass(o, now, age, line, artifact, out);
        return;
    }
    (void)ej_field_str(line, "result_class", klass, sizeof(klass));
    (void)snprintf(reason, sizeof(reason), "last_run_verdict_%s_age_%llds",
                   verdict, (long long)age);
    (void)snprintf(extra, sizeof(extra), " class=%s", klass[0] ? klass : "unrecorded");
    (void)snprintf(out->result_class, sizeof(out->result_class), "%s", klass);
    sw_emit(out, 1, "FAIL", reason, extra, artifact);
}

bool zcl_stopwatch_judge(const struct zcl_stopwatch_judge_opts *opts,
                         struct zcl_judge_result *out)
{
    static char line[SW_LAST_LINE_MAX + 1];
    int have;
    if (!opts || !opts->history || !out)
        return false;
    memset(out, 0, sizeof(*out));
    have = sw_last_line(opts->history, line, sizeof(line));
    if (have == 0)
        sw_emit(out, 2, "STALE", "no_evidence_file", "", "-");
    else if (have == 1)
        sw_emit(out, 2, "STALE", "empty_last_line", "", "-");
    else
        sw_judge_row(opts, ej_now(opts->now_unix), line, out);
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
