/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grades the public-node rows C3 and C6 of `fleet.goals` from the
 *          newest durable receipt each already has: the cold-start
 *          stopwatch ledger and the soak evidence ledger.
 *
 * The verdict comes from the same judges `make mvp` runs
 * (stopwatch_evidence_judge.sh, soak_evidence.sh judge); this file maps a
 * verdict line to a grade and reports the receipt and its age. A receipt
 * older than its row's window is stale and the row is unmeasured. No
 * threshold lives here. */

#include "native_fleet_goals.h"

#include "platform/time_compat.h"
#include "util/spawn.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RC_HOUR_S 3600
#define RC_C3_WINDOW_S 86400
#define RC_C6_WINDOW_H 168
#define RC_OUT_MAX 8192
#define RC_TAIL_MAX 32768
#define RC_TOKEN_MAX 128
#define RC_PATH_MAX 512
#define RC_JUDGE_MS 20000

static struct zcl_goal_result rc_result(enum zcl_goal_grade grade,
                                        const char *next, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static struct zcl_goal_result rc_result(enum zcl_goal_grade grade,
                                        const char *next, const char *fmt, ...)
{
    struct zcl_goal_result r = {0};
    va_list args;
    r.grade = grade;
    va_start(args, fmt);
    (void)vsnprintf(r.evidence, sizeof(r.evidence), fmt, args);
    va_end(args);
    (void)snprintf(r.next, sizeof(r.next), "%s", next);
    return r;
}

static int64_t rc_now(const struct zcl_goals_options *o)
{
    return o && o->now_unix > 0 ? o->now_unix
                                : (int64_t)platform_time_wall_time_t();
}

/* The explicit option, else the environment, else the state-dir default.
 * NULL when a fixture run (skip_probes) gave no explicit path. */
static const char *rc_path(const char *given, const char *env_name,
                           const char *tail, bool skip, char *buf, size_t cap)
{
    const char *env;
    const char *home;
    if (given)
        return given;
    if (skip)
        return NULL;
    env = getenv(env_name);
    if (env && env[0])
        return env;
    home = getenv("HOME");
    if (!home || !home[0])
        return NULL;
    if (snprintf(buf, cap, "%s/%s", home, tail) >= (int)cap)
        return NULL;
    return buf;
}

static bool rc_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    (void)fclose(f);
    return true;
}

/* Copies the value after `key` up to a space or newline. */
static bool rc_token(const char *text, const char *key, char *out, size_t cap)
{
    const char *p = strstr(text, key);
    size_t n = 0;
    if (!p)
        return false;
    for (p += strlen(key); p[n] && p[n] != ' ' && p[n] != '\n' && n + 1 < cap;
         n++)
        out[n] = p[n];
    out[n] = '\0';
    return n > 0;
}

/* The single line holding `VERDICT=`; other report lines share keys such as
 * `class=` with different meanings. */
static bool rc_verdict_line(const char *text, char *line, size_t cap)
{
    const char *p = strstr(text, "VERDICT=");
    size_t n = 0;
    if (!p)
        return false;
    while (p > text && p[-1] != '\n')
        p--;
    while (p[n] && p[n] != '\n' && n + 1 < cap) {
        line[n] = p[n];
        n++;
    }
    line[n] = '\0';
    return true;
}

static bool rc_run(const char *const argv[], char *out, size_t cap)
{
    out[0] = '\0';
    (void)zcl_spawn_capture(argv, out, cap, RC_JUDGE_MS);
    return out[0] != '\0';
}

/* `ts` of the last timestamped row of a JSON-lines ledger; -1 if none. */
static int64_t rc_last_ts(const char *path)
{
    static char buf[RC_TAIL_MAX + 1];
    FILE *f = fopen(path, "rb");
    long size, start;
    size_t n;
    int64_t ts = -1;
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
        (void)fclose(f);
        return -1;
    }
    start = size > RC_TAIL_MAX ? size - RC_TAIL_MAX : 0;
    if (fseek(f, start, SEEK_SET) != 0) {
        (void)fclose(f);
        return -1;
    }
    n = fread(buf, 1, RC_TAIL_MAX, f);
    (void)fclose(f);
    buf[n] = '\0';
    for (char *line = buf; *line;) {
        char *nl = strchr(line, '\n');
        const char *k;
        if (nl)
            *nl = '\0';
        k = (start > 0 && line == buf) ? NULL : strstr(line, "\"ts\":");
        if (k) {
            char *end;
            long long v = strtoll(k + 5, &end, 10);
            if (end != k + 5)
                ts = v;
        }
        if (!nl)
            break;
        line = nl + 1;
    }
    return ts;
}

static int64_t rc_age_h(int64_t now, int64_t ts)
{
    return now > ts ? (now - ts) / RC_HOUR_S : 0;
}

static const char *rc_base(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* One judge run: its verdict line and the report lines it prints. */
struct rc_judged {
    char verdict[RC_TOKEN_MAX];
    char reason[RC_TOKEN_MAX];
    char klass[RC_TOKEN_MAX];
    char artifact[RC_PATH_MAX];
    double covered_h;
    int64_t age_s;
};

static bool rc_judge(const char *const argv[], struct rc_judged *j)
{
    static char out[RC_OUT_MAX];
    char line[1024], num[RC_TOKEN_MAX];
    memset(j, 0, sizeof(*j));
    if (!rc_run(argv, out, sizeof(out)) ||
        !rc_verdict_line(out, line, sizeof(line)) ||
        !rc_token(line, "VERDICT=", j->verdict, sizeof(j->verdict)))
        return false;
    (void)rc_token(line, "reason=", j->reason, sizeof(j->reason));
    (void)rc_token(line, "class=", j->klass, sizeof(j->klass));
    (void)rc_token(line, "artifact=", j->artifact, sizeof(j->artifact));
    if (rc_token(out, "window_covered_hours=", num, sizeof(num)))
        j->covered_h = strtod(num, NULL);
    if (rc_token(out, "last_sample_age_sec=", num, sizeof(num)))
        j->age_s = strtoll(num, NULL, 10);
    return true;
}

/* ── C3: cold-start stopwatch ledger ──────────────────────────────────── */

static struct zcl_goal_result rc_c3_grade(const struct rc_judged *j,
                                          const char *hist, int64_t now,
                                          int64_t ts)
{
    static const char next[] = "make c3-stopwatch-report";
    const char *id = j->artifact[0] ? rc_base(j->artifact) : "newest row";
    long long age = (long long)rc_age_h(now, ts);

    if (strcmp(j->verdict, "STALE") == 0 || now - ts > RC_C3_WINDOW_S)
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "stale: newest receipt %s is %lld h old, window 24 h; "
                         "ledger %s",
                         id, age, hist);
    if (strcmp(j->verdict, "PASS") == 0)
        return rc_result(ZCL_GOAL_PASS, next,
                         "stopwatch judge PASS on receipt %s, age %lld h of "
                         "24 h; ledger %s (not bound to a candidate "
                         "executable)",
                         id, age, hist);
    if (strcmp(j->verdict, "FAIL") == 0 &&
        strcmp(j->klass, "PRODUCT_FAILURE") == 0)
        return rc_result(ZCL_GOAL_FAIL, next,
                         "stopwatch judge FAIL (%s) on receipt %s, age %lld h "
                         "of 24 h; ledger %s",
                         j->reason, id, age, hist);
    return rc_result(ZCL_GOAL_UNMEASURED, next,
                     "newest receipt %s, age %lld h, is not a measurement: "
                     "%s %s class %s; ledger %s",
                     id, age, j->verdict, j->reason,
                     j->klass[0] ? j->klass : "none", hist);
}

static struct zcl_goal_result rc_c3(const struct zcl_goals_options *o)
{
    static const char next[] = "make c3-stopwatch-report";
    char hist_buf[RC_PATH_MAX], script[RC_PATH_MAX], now_arg[48], age_arg[48];
    struct rc_judged j;
    int64_t now = rc_now(o), ts;
    const char *hist =
        rc_path(o ? o->c3_history : NULL, "ZCL_C3_STOPWATCH_HISTORY",
                ".local/state/zclassic23-c3-stopwatch/history.jsonl",
                o && o->skip_probes, hist_buf, sizeof(hist_buf));
    const char *repo = o && o->repo ? o->repo : ".";
    const char *argv[] = {"env", now_arg, "bash", script, NULL, age_arg, NULL};

    if (!hist)
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "cold-start receipt probe skipped");
    ts = rc_last_ts(hist);
    if (ts < 0)
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "no receipt: %s is missing or has no timestamped row",
                         hist);
    (void)snprintf(script, sizeof(script),
                   "%s/tools/scripts/stopwatch_evidence_judge.sh", repo);
    if (!rc_exists(script))
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "the stopwatch judge %s is not present", script);
    (void)snprintf(now_arg, sizeof(now_arg), "ZCL_STOPWATCH_JUDGE_NOW=%lld",
                   (long long)now);
    (void)snprintf(age_arg, sizeof(age_arg), "--max-age-secs=%d",
                   RC_C3_WINDOW_S);
    argv[4] = hist;
    if (!rc_judge(argv, &j))
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "the stopwatch judge printed no verdict for %s", hist);
    return rc_c3_grade(&j, hist, now, ts);
}

/* ── C6: soak evidence ledger ─────────────────────────────────────────── */

static struct zcl_goal_result rc_c6_grade(const struct rc_judged *j,
                                          const char *file)
{
    static const char next[] = "make soak-evidence-report";
    long long age_h = (long long)(j->age_s / RC_HOUR_S);

    if (j->age_s > (int64_t)RC_C6_WINDOW_H * RC_HOUR_S ||
        strncmp(j->reason, "stale_evidence_age", 18) == 0)
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "stale: newest sample is %lld h old, window %d h; "
                         "needs %d h of observation, have %.1f h; %s",
                         age_h, RC_C6_WINDOW_H, RC_C6_WINDOW_H, j->covered_h,
                         file);
    if (strcmp(j->verdict, "MET") == 0)
        return rc_result(ZCL_GOAL_PASS, next,
                         "soak judge MET over %.1f h of %d h, newest sample "
                         "%lld h old; receipt %s",
                         j->covered_h, RC_C6_WINDOW_H, age_h, file);
    if (strcmp(j->verdict, "NOT_MET") == 0)
        return rc_result(ZCL_GOAL_FAIL, next,
                         "soak judge NOT_MET (%s) over %.1f h, newest sample "
                         "%lld h old; receipt %s",
                         j->reason, j->covered_h, age_h, file);
    return rc_result(ZCL_GOAL_UNMEASURED, next,
                     "needs %d h of observation, have %.1f h (%s); receipt %s",
                     RC_C6_WINDOW_H, j->covered_h, j->reason, file);
}

static struct zcl_goal_result rc_c6(const struct zcl_goals_options *o)
{
    static const char next[] = "make soak-evidence-report";
    char dir_buf[RC_PATH_MAX], file[RC_PATH_MAX], script[RC_PATH_MAX];
    char now_arg[48], dir_arg[RC_PATH_MAX + 32], hours_arg[16];
    struct rc_judged j;
    const char *dir =
        rc_path(o ? o->soak_dir : NULL, "ZCL_SOAK_EVIDENCE_DIR",
                ".local/state/zclassic23-soak-evidence", o && o->skip_probes,
                dir_buf, sizeof(dir_buf));
    const char *repo = o && o->repo ? o->repo : ".";
    const char *argv[] = {"env",   now_arg,         dir_arg,   "bash", script,
                          "judge", "--window-hours", hours_arg, NULL};

    if (!dir)
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "soak receipt probe skipped");
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", dir);
    if (!rc_exists(file))
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "needs %d h of observation, have 0 h: no receipt at "
                         "%s",
                         RC_C6_WINDOW_H, file);
    (void)snprintf(script, sizeof(script), "%s/tools/scripts/soak_evidence.sh",
                   repo);
    if (!rc_exists(script))
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "the soak judge %s is not present", script);
    (void)snprintf(now_arg, sizeof(now_arg), "ZCL_SOAK_NOW=%lld",
                   (long long)rc_now(o));
    (void)snprintf(dir_arg, sizeof(dir_arg), "ZCL_SOAK_EVIDENCE_DIR=%s", dir);
    (void)snprintf(hours_arg, sizeof(hours_arg), "%d", RC_C6_WINDOW_H);
    if (!rc_judge(argv, &j))
        return rc_result(ZCL_GOAL_UNMEASURED, next,
                         "the soak judge printed no verdict for %s", file);
    return rc_c6_grade(&j, file);
}

bool zcl_goals_receipt_measure(const struct zcl_goals_options *options,
                               const char *id, struct zcl_goal_result *out)
{
    if (!id || !out)
        return false;
    if (strcmp(id, "C3") == 0)
        *out = rc_c3(options);
    else if (strcmp(id, "C6") == 0)
        *out = rc_c6(options);
    else
        return false;
    return true;
}
