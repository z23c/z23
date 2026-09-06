/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Render the fleet-agents answer as aligned plain-English columns —
 *          the default output of `z23-dev fleet agents`.
 *
 * It reads the SAME data object the JSON envelope carries and nothing else,
 * so `--json` and the plain text can never disagree: there is one measurement
 * and two presentations of it. Every number arrives here already decided;
 * this file formats and never computes.
 */

#include "command/native_dev_agents.h"

#include "json/json.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct rd_buf {
    char *at;
    size_t left;
    size_t written;
};

static void rd_put(struct rd_buf *b, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void rd_put(struct rd_buf *b, const char *format, ...)
{
    va_list args;
    int n;
    if (b->left <= 1) return;
    va_start(args, format);
    n = vsnprintf(b->at, b->left, format, args);
    va_end(args);
    if (n < 0) return;
    if ((size_t)n >= b->left) n = (int)b->left - 1;
    b->at += n;
    b->left -= (size_t)n;
    b->written += (size_t)n;
}

/* Ages read as a person would say them. A negative age means the reader did
 * not measure it, which is a different fact from zero and is printed as such. */
static const char *rd_age(int64_t seconds, char *out, size_t cap)
{
    if (seconds < 0) (void)snprintf(out, cap, "%s", "-");
    else if (seconds < 90) (void)snprintf(out, cap, "%llds", (long long)seconds);
    else if (seconds < 5400)
        (void)snprintf(out, cap, "%lldm", (long long)(seconds / 60));
    else if (seconds < 172800)
        (void)snprintf(out, cap, "%lldh", (long long)(seconds / 3600));
    else (void)snprintf(out, cap, "%lldd", (long long)(seconds / 86400));
    return out;
}

static const char *rd_pct(int64_t bp, char *out, size_t cap)
{
    if (bp < 0) (void)snprintf(out, cap, "%s", "-");
    else (void)snprintf(out, cap, "%lld%%", (long long)((bp + 50) / 100));
    return out;
}

static const char *rd_ratio(int64_t bp, char *out, size_t cap)
{
    if (bp < 0) (void)snprintf(out, cap, "%s", "-");
    else
        (void)snprintf(out, cap, "%lld.%02lld", (long long)(bp / 10000),
                       (long long)((bp % 10000) / 100));
    return out;
}

static const char *rd_num(int64_t value, char *out, size_t cap)
{
    if (value < 0) (void)snprintf(out, cap, "%s", "-");
    else (void)snprintf(out, cap, "%lld", (long long)value);
    return out;
}

static const char *rd_str(const struct json_value *object, const char *key)
{
    const char *s = json_get_str(json_get(object, key));
    return s ? s : "";
}

static int64_t rd_int(const struct json_value *object, const char *key)
{
    const struct json_value *v = json_get(object, key);
    return v ? json_get_int(v) : -1;
}

/* "z23-dev(12345) bash(9911)" — whole entries only. A column cut mid-number
 * would print a pid that does not exist, so the rendering stops at the last
 * entry that fits and says how many it did not name. */
static void rd_processes(const struct json_value *row, char *out, size_t cap)
{
    const struct json_value *arr = json_get(row, "processes");
    int64_t total = rd_int(row, "process_count");
    size_t used = 0, shown = 0;
    size_t room = cap > 6 ? cap - 6 : 0;
    out[0] = 0;
    if (!arr || arr->type != JSON_ARR) return;
    for (size_t i = 0; i < arr->num_children; i++) {
        const struct json_value *p = json_at(arr, i);
        char one[80];
        int n = snprintf(one, sizeof(one), "%s%s(%lld)", used ? " " : "",
                         rd_str(p, "exe"), (long long)rd_int(p, "pid"));
        if (n < 0 || used + (size_t)n > room) break;
        memcpy(out + used, one, (size_t)n + 1);
        used += (size_t)n;
        shown++;
    }
    if (total > (int64_t)shown)
        (void)snprintf(out + used, cap - used, "%s+%lld", used ? " " : "",
                       (long long)(total - (int64_t)shown));
    else if (!used)
        (void)snprintf(out, cap, "%s", "-");
}

static void rd_running(struct rd_buf *b, const struct json_value *running)
{
    const struct json_value *rows = json_get(running, "rows");
    const struct json_value *units = json_get(running, "units");
    size_t count = rows && rows->type == JSON_ARR ? rows->num_children : 0;

    rd_put(b, "RUNNING NOW — agent workspaces on this box (%s)\n",
           rd_str(running, "root"));
    if (count == 0) {
        rd_put(b, "  no agent workspace has moved in the last %lld hours\n",
               (long long)rd_int(running, "window_hours"));
    } else {
        rd_put(b, "  %-18s %-8s %-10s %5s %7s %7s  %-26.26s %s\n", "NAME", "KIND",
               "HEAD", "DIRTY", "EDITED", "GIT", "PROCESSES", "READY");
    }
    for (size_t i = 0; i < count; i++) {
        const struct json_value *row = json_at(rows, i);
        char edited[16], git[16], dirty[16], procs[27];
        const char *ready = rd_str(row, "ready");
        rd_processes(row, procs, sizeof(procs));
        rd_put(b, "  %-18s %-8s %-10s %5s %7s %7s  %-26.26s %s\n",
               rd_str(row, "name"), rd_str(row, "kind"), rd_str(row, "head"),
               rd_num(rd_int(row, "dirty"), dirty, sizeof(dirty)),
               rd_age(rd_int(row, "newest_source_age_s"), edited,
                      sizeof(edited)),
               rd_age(rd_int(row, "git_age_s"), git, sizeof(git)),
               procs[0] ? procs : "-", ready[0] ? ready : "-");
    }
    rd_put(b,
           "  %lld workspaces scanned: %lld with a live process, %lld more "
           "changed in the last %lld hours, %lld idle.\n",
           (long long)rd_int(running, "scanned"),
           (long long)rd_int(running, "with_process"),
           (long long)(rd_int(running, "active") -
                       rd_int(running, "with_process")),
           (long long)rd_int(running, "window_hours"),
           (long long)rd_int(running, "idle"));
    if (json_get_bool(json_get(running, "truncated")))
        rd_put(b, "  showing %lld of %lld active workspaces.\n",
               (long long)rd_int(running, "count"),
               (long long)rd_int(running, "total"));
    if (units) {
        const struct json_value *urows = json_get(units, "rows");
        size_t un = urows && urows->type == JSON_ARR ? urows->num_children : 0;
        if (strcmp(rd_str(units, "state"), "observed") != 0) {
            rd_put(b, "  units: not collected\n");
        } else if (un == 0) {
            rd_put(b, "  units: none of this box's z23- user services is "
                      "loaded\n");
        } else {
            rd_put(b, "  units: %lld", (long long)rd_int(units, "total"));
            for (size_t i = 0; i < un; i++)
                rd_put(b, "  %s", rd_str(json_at(urows, i), "name"));
            rd_put(b, "\n");
        }
    }
}

/* One grade line. Every cell gets its OWN buffer: they are all arguments to
 * one printf, so a shared scratch buffer would be overwritten by a later
 * conversion before the first was ever read. */
static void rd_grade_row(struct rd_buf *b, const char *name,
                         const struct json_value *row, const char *grade)
{
    char tasks[16], ok[16], bad[16], other[16], rate[16];
    char wall[16], ratio[16], tok[24], last[16];
    rd_put(b, "  %-16s %6s %8s %5s %6s %6s %9s %10s %11s %6s  %s\n", name,
           rd_num(rd_int(row, "tasks"), tasks, sizeof(tasks)),
           rd_num(rd_int(row, "success"), ok, sizeof(ok)),
           rd_num(rd_int(row, "failure"), bad, sizeof(bad)),
           rd_num(rd_int(row, "other"), other, sizeof(other)),
           rd_pct(rd_int(row, "success_rate_bp"), rate, sizeof(rate)),
           rd_num(rd_int(row, "median_wall_s"), wall, sizeof(wall)),
           rd_ratio(rd_int(row, "median_ratio_bp"), ratio, sizeof(ratio)),
           rd_num(rd_int(row, "tokens_per_success"), tok, sizeof(tok)),
           rd_age(rd_int(row, "last_activity_age_s"), last, sizeof(last)),
           grade);
}

static void rd_grades(struct rd_buf *b, const struct json_value *grades)
{
    const struct json_value *rows = json_get(grades, "rows");
    const struct json_value *totals = json_get(grades, "totals");
    size_t count = rows && rows->type == JSON_ARR ? rows->num_children : 0;
    int64_t window = rd_int(grades, "window_hours");
    int64_t skipped = rd_int(grades, "skipped_rows");

    rd_put(b, "\nGRADES — every delegation this box recorded, by %s",
           rd_str(grades, "group_by"));
    if (window > 0) rd_put(b, ", last %lld hours\n", (long long)window);
    else rd_put(b, ", whole ledger\n");
    rd_put(b, "  %-16s %6s %8s %5s %6s %6s %9s %10s %11s %6s  %s\n",
           rd_str(grades, "group_by"), "TASKS", "SUCCESS", "FAIL", "OTHER",
           "RATE", "MED WALL", "MED RATIO", "TOK/SUCCESS", "LAST", "GRADE");
    for (size_t i = 0; i < count; i++) {
        const struct json_value *row = json_at(rows, i);
        rd_grade_row(b, rd_str(row, "key"), row, rd_str(row, "grade"));
    }
    if (totals) rd_grade_row(b, "ALL", totals, "-");
    rd_put(b,
           "  ledger: %s\n"
           "  %lld lines, %lld result rows (%lld in this window), "
           "%lld predictions",
           rd_str(grades, "ledger"), (long long)rd_int(grades, "ledger_lines"),
           (long long)rd_int(grades, "result_rows_total"),
           (long long)rd_int(grades, "result_rows_in_window"),
           (long long)rd_int(grades, "predict_rows"));
    if (skipped > 0) {
        const struct json_value *bad = json_get(grades, "skipped_lines");
        size_t bn = bad && bad->type == JSON_ARR ? bad->num_children : 0;
        rd_put(b, ", %lld malformed row%s skipped", (long long)skipped,
               skipped == 1 ? "" : "s");
        for (size_t i = 0; i < bn; i++)
            rd_put(b, "%s%lld", i ? ", " : " (line ",
                   (long long)json_get_int(json_at(bad, i)));
        if (bn) rd_put(b, "%s", ")");
    }
    rd_put(b, ".\n");
    if (json_get_bool(json_get(grades, "truncated")))
        rd_put(b, "  showing %lld of %lld groups.\n",
               (long long)rd_int(grades, "count"),
               (long long)rd_int(grades, "total"));
    rd_put(b,
           "  grade: A needs 90%% success and a median actual/predicted wall "
           "of 1.50 or better; B, 80%% and 2.00;\n"
           "         C, 65%%; D, 50%%; F below. Fewer than 3 results, or no "
           "prediction to compare against, earns no letter.\n");
}

size_t zcl_agents_render_text(const struct json_value *data, char *out,
                              size_t cap)
{
    struct rd_buf b;
    const struct json_value *running, *grades;
    if (!out || cap == 0) return 0;
    b.at = out;
    b.left = cap;
    b.written = 0;
    out[0] = 0;
    if (!data || data->type != JSON_OBJ) return 0;
    running = json_get(data, "running");
    grades = json_get(data, "grades");
    if (running) rd_running(&b, running);
    if (grades) rd_grades(&b, grades);
    rd_put(&b, "\nOTHER HOSTS\n  %s\n",
           ZCL_AGENTS_OTHER_HOSTS_NOTE);
    return b.written;
}
