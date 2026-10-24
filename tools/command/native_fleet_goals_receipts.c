/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grades the public-node rows C1 C2 C3 C4 C5 C6 C7 of `fleet.goals` from the
 *          newest durable receipt each already has: the cold-start
 *          stopwatch ledger and the soak evidence ledger.
 *
 * The verdict comes from the in-process stopwatch and soak judges
 * (native_stopwatch_judge.c, native_soak_judge.c); this file maps a verdict
 * to a grade and reports the receipt and its age. A receipt older than its
 * row's window is stale and the row is unmeasured. No threshold lives
 * here. */

#include "native_fleet_goals.h"

#include "native_evidence_judge.h"

#include "platform/time_compat.h"
#include "util/path_leaf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RC_HOUR_S 3600
#define RC_C3_WINDOW_S 86400
#define RC_C6_WINDOW_H 168
#define RC_TAIL_MAX 32768
#define RC_PATH_MAX 512
#define RC_ERR_MAX 160

/* The explicit option, else the environment, else the state-dir default.
 * NULL when a fixture run (skip_probes) gave no explicit path. */
const char *zcl_goals_state_path(const char *given, const char *env_name,
                                 const char *tail, bool skip, char *buf,
                                 size_t cap)
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

/* ── C3: cold-start stopwatch ledger ──────────────────────────────────── */

static struct zcl_goal_result rc_c3_grade(const struct zcl_judge_result *j,
                                          const char *hist, int64_t now,
                                          int64_t ts)
{
    static const char next[] = "make c3-stopwatch-report";
    const char *id = j->artifact[0] && strcmp(j->artifact, "-") != 0
                         ? zcl_path_leaf(j->artifact)
                         : "newest row";
    long long age = (long long)rc_age_h(now, ts);

    if (strcmp(j->verdict, "STALE") == 0 || now - ts > RC_C3_WINDOW_S)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "stale: newest receipt %s is %lld h old, window 24 h; "
                             "ledger %s",
                             id, age, hist);
    if (strcmp(j->verdict, "PASS") == 0)
        return zcl_goal_make(ZCL_GOAL_PASS, next,
                             "PASS on receipt %s, age %lld h of "
                             "24 h; ledger %s (not candidate-bound)",
                             id, age, hist);
    if (strcmp(j->verdict, "FAIL") == 0 &&
        strcmp(j->result_class, "PRODUCT_FAILURE") == 0)
        return zcl_goal_make(ZCL_GOAL_FAIL, next,
                             "stopwatch judge FAIL (%s) on receipt %s, age %lld h "
                             "of 24 h; ledger %s",
                             j->reason, id, age, hist);
    return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                         "newest receipt %s, age %lld h, is not a measurement: "
                         "%s %s class %s; ledger %s",
                         id, age, j->verdict, j->reason,
                         j->result_class[0] ? j->result_class : "none", hist);
}

static struct zcl_goal_result rc_c3(const struct zcl_goals_options *o)
{
    static const char next[] = "make c3-stopwatch-report";
    static struct zcl_judge_result j;
    char hist_buf[RC_PATH_MAX], slo[RC_PATH_MAX], err[RC_ERR_MAX];
    struct zcl_stopwatch_judge_opts opts;
    const char *hist =
        zcl_goals_state_path(o ? o->c3_history : NULL, "ZCL_C3_STOPWATCH_HISTORY",
                ".local/state/zclassic23-c3-stopwatch/history.jsonl",
                o && o->skip_probes, hist_buf, sizeof(hist_buf));
    int64_t ts;
    int64_t now = o && o->now_unix > 0 ? o->now_unix : (int64_t)platform_time_wall_time_t();

    if (!hist)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "cold-start receipt probe skipped");
    ts = rc_last_ts(hist);
    if (ts < 0)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "no receipt: %s is missing or has no timestamped row",
                             hist);
    if (!zcl_stopwatch_judge_defaults(&opts, slo, sizeof(slo), err, sizeof(err)))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "the stopwatch judge settings are invalid: %s", err);
    opts.history = hist;
    opts.max_age_secs = RC_C3_WINDOW_S;
    opts.now_unix = now;
    if (!zcl_stopwatch_judge(&opts, &j))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "the stopwatch judge could not read %s", hist);
    return rc_c3_grade(&j, hist, now, ts);
}

/* ── C6: soak evidence ledger ─────────────────────────────────────────── */

static struct zcl_goal_result rc_c6_grade(const struct zcl_judge_result *j,
                                          const char *file)
{
    static const char next[] = "make soak-evidence-report";
    long long age_h = (long long)(j->newest_age_sec / RC_HOUR_S);

    if (j->newest_age_sec > (int64_t)RC_C6_WINDOW_H * RC_HOUR_S ||
        strncmp(j->reason, "stale_evidence_age", 18) == 0)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "stale: newest sample is %lld h old, window %d h; "
                             "needs %d h of observation, have %.1f h; %s",
                             age_h, RC_C6_WINDOW_H, RC_C6_WINDOW_H,
                             j->covered_hours, file);
    if (strcmp(j->verdict, "MET") == 0)
        return zcl_goal_make(ZCL_GOAL_PASS, next,
                             "soak judge MET over %.1f h of %d h, newest sample "
                             "%lld h old; receipt %s",
                             j->covered_hours, RC_C6_WINDOW_H, age_h, file);
    if (strcmp(j->verdict, "NOT_MET") == 0)
        return zcl_goal_make(ZCL_GOAL_FAIL, next,
                             "soak judge NOT_MET (%s) over %.1f h, newest sample "
                             "%lld h old; receipt %s",
                             j->reason, j->covered_hours, age_h, file);
    return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                         "needs %d h of observation, have %.1f h (%s); receipt %s",
                         RC_C6_WINDOW_H, j->covered_hours, j->reason, file);
}

static struct zcl_goal_result rc_c6(const struct zcl_goals_options *o)
{
    static const char next[] = "make soak-evidence-report";
    static struct zcl_judge_result j;
    char dir_buf[RC_PATH_MAX], file[RC_PATH_MAX], dflt[RC_PATH_MAX], err[RC_ERR_MAX];
    struct zcl_soak_judge_opts opts;
    const char *dir =
        zcl_goals_state_path(o ? o->soak_dir : NULL, "ZCL_SOAK_EVIDENCE_DIR",
                ".local/state/zclassic23-soak-evidence", o && o->skip_probes,
                dir_buf, sizeof(dir_buf));

    if (!dir)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "soak receipt probe skipped");
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", dir);
    if (!zcl_soak_judge_defaults(&opts, dflt, sizeof(dflt), err, sizeof(err)))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "the soak judge settings are invalid: %s", err);
    (void)snprintf(file, sizeof(file), "%s/evidence.jsonl", dir);
    opts.file = file;
    opts.window_hours = RC_C6_WINDOW_H;
    if (o && o->now_unix > 0)
        opts.now_unix = o->now_unix;
    if (!zcl_soak_judge(&opts, &j))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "the soak judge could not read %s", file);
    if (strcmp(j.reason, "no_evidence_file") == 0)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "needs %d h of observation, have 0 h: no receipt at "
                             "%s",
                             RC_C6_WINDOW_H, file);
    return rc_c6_grade(&j, file);
}

/* ── C1 C2 C4 C5 C7: the newest line of <item>.jsonl ─────────────────── */

static const struct {
    const char *id;
    const char *target;
} k_receipt_items[] = {
    {"C1", "make ci-install-linger"},
    {"C2", "make mvp-onion-local"},
    {"C4", "make test-shielded-payment"},
    {"C5", "make ci-mvp-gates"},
    {"C7", "make test-crash-bootstrap"},
};

const char *zcl_goals_receipt_target(const char *item)
{
    size_t n = sizeof(k_receipt_items) / sizeof(k_receipt_items[0]);
    for (size_t i = 0; item && i < n; i++)
        if (strcmp(k_receipt_items[i].id, item) == 0)
            return k_receipt_items[i].target;
    return NULL;
}

bool zcl_goals_receipt_path(const char *dir_given, bool skip, const char *item,
                            char *buf, size_t cap)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    int n;
    if (!item || !buf)
        return false;
    if (dir_given)
        n = snprintf(buf, cap, "%s/%s.jsonl", dir_given, item);
    else if (skip)
        return false;
    else if (xdg && xdg[0] == '/')
        n = snprintf(buf, cap, "%s/zclassic23-receipts/%s.jsonl", xdg, item);
    else if (home && home[0])
        n = snprintf(buf, cap,
                     "%s/.local/state/zclassic23-receipts/%s.jsonl", home,
                     item);
    else
        return false;
    return n > 0 && (size_t)n < cap;
}

/* The last non-empty line of the file, NUL-terminated in buf; false if the
 * file is unreadable or empty. A receipt line is far shorter than the tail
 * read. */
static bool rc_last_line(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    long size;
    size_t n, end;
    if (!f)
        return false;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 ||
        fseek(f, size > (long)(cap - 1) ? size - (long)(cap - 1) : 0,
              SEEK_SET) != 0) {
        (void)fclose(f);
        return false;
    }
    n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        n--;
    buf[n] = '\0';
    end = n;
    while (n > 0 && buf[n - 1] != '\n')
        n--;
    if (end == n)
        return false;
    memmove(buf, buf + n, end - n + 1);
    return true;
}

static struct zcl_goal_result rc_item_grade(const struct json_value *row,
                                            const char *path, const char *next,
                                            int64_t now)
{
    int64_t ts = json_get_int(json_get(row, "ts"));
    const char *verdict = json_get_str(json_get(row, "verdict"));
    long long wall = (long long)json_get_int(json_get(row, "wall_s"));
    const char *commit = json_get_str(json_get(row, "build_commit"));
    long long age = (long long)rc_age_h(now, ts);

    if (!commit || !commit[0])
        commit = "unknown";
    if (!verdict || !verdict[0] || ts <= 0)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "newest line of %s has no ts and verdict", path);
    if (now - ts > RC_C3_WINDOW_S)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                             "stale: newest receipt is %lld h old, window 24 h; "
                             "receipt %s",
                             age, path);
    if (strcmp(verdict, "pass") == 0 || strcmp(verdict, "fail") == 0)
        return zcl_goal_make(verdict[0] == 'p' ? ZCL_GOAL_PASS : ZCL_GOAL_FAIL,
                             next,
                             "%s receipt ts %lld, wall_s %lld, build_commit "
                             "%s, age %lld h of 24 h; receipt %s",
                             verdict[0] == 'p' ? "PASS" : "FAIL",
                             (long long)ts, wall, commit, age, path);
    return zcl_goal_make(ZCL_GOAL_UNMEASURED, next,
                         "newest receipt, age %lld h, is %s, not a "
                         "measurement; receipt %s",
                         age, verdict, path);
}

static struct zcl_goal_result rc_item(const struct zcl_goals_options *o,
                                      const char *id, const char *target)
{
    char path[RC_PATH_MAX];
    static char line[RC_TAIL_MAX];
    struct json_value row;
    struct zcl_goal_result res;
    int64_t now = o && o->now_unix > 0 ? o->now_unix
                                       : (int64_t)platform_time_wall_time_t();
    if (!zcl_goals_receipt_path(o ? o->receipts_dir : NULL,
                                o && o->skip_probes, id, path, sizeof(path)))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, target,
                             "receipt probe skipped");
    if (!rc_last_line(path, line, sizeof(line)))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, target,
                             "no receipt yet: run %s; it appends one line to "
                             "%s",
                             target, path);
    json_init(&row);
    if (!json_read(&row, line, strlen(line)) || row.type != JSON_OBJ)
        res = zcl_goal_make(ZCL_GOAL_UNMEASURED, target,
                            "newest line of %s is not a receipt", path);
    else
        res = rc_item_grade(&row, path, target, now);
    json_free(&row);
    return res;
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
    else if (zcl_goals_receipt_target(id))
        *out = rc_item(options, id, zcl_goals_receipt_target(id));
    else
        return false;
    return true;
}
