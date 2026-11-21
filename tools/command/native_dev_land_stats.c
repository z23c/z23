/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.stats: a measured reading of the land queue from its outcomes
 * ledger, so any agent can see where landing throughput stands without
 * recomputing it by hand. Read-only; writes nothing.
 *
 * Input (zcl.land_stats_input.v1): hours (window, default 168 = 7 days,
 * 1..720), now (epoch override for tests), outcomes (ledger path override;
 * default <state root>/land/outcomes.jsonl).
 *
 * Output (zcl.land_stats.v1): source{} says exactly what was read and whether
 * the read was capped; totals{} counts rows by state in the window and the
 * failure rate; days[] gives per UTC day the proof slot's busy time; the
 * failures_by[] rows give the slot time each phase/dimension burned;
 * landed_duration{} the median and p90; screen is the short human report.
 *
 * Definitions, all from the row's own fields:
 *   end       terminal_recorded_at, else landed_at, else the ts stamp.
 *   duration  end - started for a row with started > 0 and end >= started;
 *             rows without both contribute no slot time.
 *   window    a row is in the window when its end >= now - hours * 3600.
 *   day       the UTC day a row ended on (a run across midnight is counted
 *             whole on the day it ended). busy_permille = busy_s / 86400
 *             for every day, including the current partial day.
 *   failure rate = failed / (landed + failed); conflict and cancelled rows
 *             never reached a verdict on the candidate and are excluded.
 *   percentiles use the nearest rank.
 * The ledger is read from its tail, at most LS_BYTES_MAX bytes; when the file
 * is larger, source.capped is true and source.window_covered says whether
 * the oldest row read still predates the window start. */

#include "command/native_command.h"
#include "command/native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LS_DEFAULT_HOURS 168
#define LS_MAX_HOURS 720
#define LS_BYTES_MAX (32u << 20)
#define LS_ROWS_MAX 200000u
#define LS_LINE_MAX 65536u
#define LS_DAYS_MAX 40u
#define LS_FAIL_MAX 32u
#define LS_DAY_S 86400
#define LS_FAIL_TARGET_PERMILLE 50
#define LS_PATH 1024u

enum ls_state { LS_LANDED, LS_FAILED, LS_CONFLICT, LS_CANCELLED, LS_OTHER, LS_NSTATES };

static const char *const ls_state_names[LS_NSTATES] = {
    "landed", "failed", "conflict", "cancelled", "other"};

struct ls_day {
    int64_t day; /* epoch day */
    int64_t busy_s;
    int64_t rows[LS_NSTATES];
};

struct ls_fail {
    char phase[24];
    char dimension[64];
    int64_t rows;
    int64_t slot_s;
};

struct ls_stats {
    int64_t window_start;
    int64_t rows[LS_NSTATES];
    int64_t busy_s;
    int64_t read_rows, skipped, oversized;
    int64_t oldest_end;
    struct ls_day days[LS_DAYS_MAX];
    size_t ndays;
    int64_t day_overflow;
    struct ls_fail fails[LS_FAIL_MAX];
    size_t nfails;
    int64_t fail_overflow;
    int64_t *landed_s;
    size_t nlanded, cap_landed;
    bool oom;
};

struct ls_src {
    int64_t bytes_total, bytes_read;
    bool capped, rows_capped, absent;
};

static int64_t ls_int(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_INT ? json_get_int(v) : 0;
}

static const char *ls_text(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    if (!v || v->type != JSON_STR || !json_get_str(v))
        return "";
    return json_get_str(v);
}

static enum ls_state ls_state_of(const char *s)
{
    for (int i = 0; i < LS_OTHER; i++)
        if (strcmp(s, ls_state_names[i]) == 0)
            return (enum ls_state)i;
    return LS_OTHER;
}

/* The row's end epoch, or 0 when it carries none. */
static int64_t ls_end(const struct json_value *row)
{
    int64_t t = ls_int(row, "terminal_recorded_at");
    if (t <= 0)
        t = ls_int(row, "landed_at");
    if (t <= 0 && !zcl_objectives_parse_iso8601(ls_text(row, "ts"), &t))
        t = 0;
    return t;
}

static struct ls_day *ls_day_for(struct ls_stats *s, int64_t day)
{
    for (size_t i = 0; i < s->ndays; i++)
        if (s->days[i].day == day)
            return &s->days[i];
    if (s->ndays >= LS_DAYS_MAX)
        return NULL;
    memset(&s->days[s->ndays], 0, sizeof(s->days[0]));
    s->days[s->ndays].day = day;
    return &s->days[s->ndays++];
}

static void ls_note_failure(struct ls_stats *s, const struct json_value *row,
                            int64_t dur)
{
    const char *phase = ls_text(row, "phase"), *dim = ls_text(row, "dimension");
    struct ls_fail *f = NULL;
    for (size_t i = 0; i < s->nfails && !f; i++)
        if (strncmp(s->fails[i].phase, phase, sizeof(f->phase) - 1) == 0 &&
            strncmp(s->fails[i].dimension, dim, sizeof(f->dimension) - 1) == 0)
            f = &s->fails[i];
    if (!f && s->nfails < LS_FAIL_MAX) {
        f = &s->fails[s->nfails++];
        memset(f, 0, sizeof(*f));
        (void)snprintf(f->phase, sizeof(f->phase), "%s", phase);
        (void)snprintf(f->dimension, sizeof(f->dimension), "%s", dim);
    }
    if (!f) {
        s->fail_overflow++;
        return;
    }
    f->rows++;
    f->slot_s += dur;
}

/* Room for one more landed duration; false (and s->oom) when it cannot grow. */
static bool ls_landed_room(struct ls_stats *s)
{
    size_t want = s->cap_landed == 0 ? 1024 : s->cap_landed * 2;
    int64_t *grown;
    if (s->nlanded < s->cap_landed)
        return true;
    grown = zcl_realloc(s->landed_s, want * sizeof(*grown), "dev_land_stats_landed");
    s->oom = grown == NULL;
    if (grown) {
        s->landed_s = grown;
        s->cap_landed = want;
    }
    return grown != NULL;
}

static void ls_note_landed(struct ls_stats *s, int64_t dur)
{
    if (ls_landed_room(s))
        s->landed_s[s->nlanded++] = dur;
}

static void ls_row(struct ls_stats *s, const struct json_value *row)
{
    int64_t end = ls_end(row), start = ls_int(row, "started"), dur = 0;
    enum ls_state st = ls_state_of(ls_text(row, "state"));
    struct ls_day *d;
    if (end <= 0) {
        s->skipped++;
        return;
    }
    if (s->oldest_end == 0 || end < s->oldest_end)
        s->oldest_end = end;
    if (end < s->window_start)
        return;
    if (start > 0 && end >= start)
        dur = end - start;
    s->rows[st]++;
    s->busy_s += dur;
    d = ls_day_for(s, end / LS_DAY_S);
    if (d) {
        d->rows[st]++;
        d->busy_s += dur;
    } else {
        s->day_overflow++;
    }
    if (st == LS_FAILED)
        ls_note_failure(s, row, dur);
    else if (st == LS_LANDED && dur > 0)
        ls_note_landed(s, dur);
}

static void ls_drain_line(FILE *fp)
{
    int c = fgetc(fp);
    while (c != EOF && c != '\n')
        c = fgetc(fp);
}

/* Position fp at the first whole line of the last LS_BYTES_MAX bytes. */
static bool ls_seek_tail(FILE *fp, struct ls_src *src)
{
    long size, start;
    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0)
        return false;
    src->bytes_total = size;
    start = size > (long)LS_BYTES_MAX ? size - (long)LS_BYTES_MAX : 0;
    src->capped = start > 0;
    src->bytes_read = size - start;
    if (fseek(fp, start > 0 ? start - 1 : 0, SEEK_SET) != 0)
        return false;
    if (start > 0)
        ls_drain_line(fp);
    return true;
}

static void ls_line(struct ls_stats *s, const char *line, size_t len)
{
    struct json_value row;
    json_init(&row);
    if (json_read(&row, line, len) && row.type == JSON_OBJ)
        ls_row(s, &row);
    else
        s->skipped++;
    s->read_rows++;
    json_free(&row);
}

static bool ls_read(const char *path, struct ls_stats *s, struct ls_src *src)
{
    FILE *fp = fopen(path, "rb");
    char *buf = zcl_malloc(LS_LINE_MAX + 2u, "dev_land_stats_line");
    if (!fp || !buf) {
        if (fp)
            (void)fclose(fp);
        free(buf);
        src->absent = true;
        return false;
    }
    if (!ls_seek_tail(fp, src))
        src->absent = true;
    while (!src->absent && fgets(buf, (int)(LS_LINE_MAX + 2u), fp)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[--len] = '\0';
        else if (len > LS_LINE_MAX) {
            s->oversized++;
            ls_drain_line(fp);
            continue;
        }
        if (len == 0)
            continue;
        if (s->read_rows >= (int64_t)LS_ROWS_MAX) {
            src->rows_capped = true;
            break;
        }
        ls_line(s, buf, len);
    }
    free(buf);
    (void)fclose(fp);
    return !src->absent;
}

static int ls_cmp_i64(const void *a, const void *b)
{
    const int64_t *x = a, *y = b;
    if (*x == *y)
        return 0;
    return *x < *y ? -1 : 1;
}

/* Nearest-rank percentile of a sorted array; p in percent. */
static int64_t ls_pct(const int64_t *sorted, size_t n, int p)
{
    size_t rank = ((size_t)p * n + 99) / 100;
    if (n == 0)
        return 0;
    return sorted[(rank < 1 ? 1 : rank) - 1];
}

/* Rounded permille of num over den; den > 0. */
static int64_t ls_permille(int64_t num, int64_t den)
{
    return (num * 1000 + den / 2) / den;
}

static void ls_ymd(int64_t day, char *out, size_t cap)
{
    int64_t z = day + 719468, era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    int64_t d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    int64_t y = yoe + era * 400 + (m <= 2);
    (void)snprintf(out, cap, "%04lld-%02lld-%02lld", (long long)y,
                   (long long)m, (long long)d);
}

static int ls_cmp_day(const void *a, const void *b)
{
    const struct ls_day *x = a, *y = b;
    return (x->day > y->day) - (x->day < y->day);
}

static int ls_cmp_fail(const void *a, const void *b)
{
    const struct ls_fail *x = a, *y = b;
    int c;
    if (x->slot_s != y->slot_s)
        return x->slot_s > y->slot_s ? -1 : 1;
    c = strcmp(x->phase, y->phase);
    return c ? c : strcmp(x->dimension, y->dimension);
}

/* Failure rate in permille, or -1 when no row reached a verdict. */
static int64_t ls_failure_permille(const struct ls_stats *s)
{
    int64_t verdicts = s->rows[LS_LANDED] + s->rows[LS_FAILED];
    return verdicts > 0 ? ls_permille(s->rows[LS_FAILED], verdicts) : -1;
}

static void ls_push_null(struct json_value *obj, const char *key)
{
    struct json_value nul;
    json_init(&nul);
    json_set_null(&nul);
    (void)json_push_kv(obj, key, &nul);
    json_free(&nul);
}

static void ls_attach(struct json_value *obj, const char *key,
                      struct json_value *child)
{
    (void)json_push_kv(obj, key, child);
    json_free(child);
}

static void ls_new_obj(struct json_value *v)
{
    json_init(v);
    json_set_object(v);
}

static int64_t ls_mean_busy(const struct ls_stats *s)
{
    int64_t sum = 0;
    for (size_t i = 0; i < s->ndays; i++)
        sum += ls_permille(s->days[i].busy_s, LS_DAY_S);
    return s->ndays ? (sum + (int64_t)s->ndays / 2) / (int64_t)s->ndays : 0;
}

static void ls_totals(const struct ls_stats *s, struct json_value *out)
{
    int64_t rate = ls_failure_permille(s);
    for (int i = 0; i < LS_NSTATES; i++)
        (void)json_push_kv_int(out, ls_state_names[i], s->rows[i]);
    if (rate < 0)
        ls_push_null(out, "failure_rate_permille");
    else
        (void)json_push_kv_int(out, "failure_rate_permille", rate);
    (void)json_push_kv_int(out, "failure_target_permille", LS_FAIL_TARGET_PERMILLE);
    (void)json_push_kv_int(out, "busy_s", s->busy_s);
    (void)json_push_kv_int(out, "days_with_rows", (int64_t)s->ndays);
    (void)json_push_kv_int(out, "busy_permille_mean_of_days", ls_mean_busy(s));
}

static void ls_days(const struct ls_stats *s, struct json_value *out)
{
    json_init(out);
    json_set_array(out);
    for (size_t i = 0; i < s->ndays; i++) {
        struct json_value row;
        char ymd[16];
        ls_new_obj(&row);
        ls_ymd(s->days[i].day, ymd, sizeof(ymd));
        (void)json_push_kv_str(&row, "day", ymd);
        (void)json_push_kv_int(&row, "busy_s", s->days[i].busy_s);
        (void)json_push_kv_int(&row, "busy_permille",
                               ls_permille(s->days[i].busy_s, LS_DAY_S));
        for (int k = 0; k < LS_NSTATES; k++)
            (void)json_push_kv_int(&row, ls_state_names[k], s->days[i].rows[k]);
        (void)json_push_back(out, &row);
        json_free(&row);
    }
}

static void ls_fails(const struct ls_stats *s, struct json_value *out)
{
    json_init(out);
    json_set_array(out);
    for (size_t i = 0; i < s->nfails; i++) {
        struct json_value row;
        ls_new_obj(&row);
        (void)json_push_kv_str(&row, "phase", s->fails[i].phase);
        (void)json_push_kv_str(&row, "dimension", s->fails[i].dimension);
        (void)json_push_kv_int(&row, "rows", s->fails[i].rows);
        (void)json_push_kv_int(&row, "slot_s", s->fails[i].slot_s);
        (void)json_push_kv_int(&row, "slot_min", (s->fails[i].slot_s + 30) / 60);
        (void)json_push_back(out, &row);
        json_free(&row);
    }
}

static bool ls_covered(const struct ls_stats *s, const struct ls_src *src)
{
    return !src->capped || (s->oldest_end > 0 && s->oldest_end < s->window_start);
}

static void ls_source(const struct ls_stats *s, const struct ls_src *src,
                      const char *path, struct json_value *out)
{
    (void)json_push_kv_str(out, "path", path);
    (void)json_push_kv_int(out, "bytes_total", src->bytes_total);
    (void)json_push_kv_int(out, "bytes_read", src->bytes_read);
    (void)json_push_kv_int(out, "bytes_max", LS_BYTES_MAX);
    (void)json_push_kv_bool(out, "capped", src->capped);
    (void)json_push_kv_bool(out, "rows_capped", src->rows_capped);
    (void)json_push_kv_bool(out, "window_covered", ls_covered(s, src));
    (void)json_push_kv_int(out, "rows_read", s->read_rows);
    (void)json_push_kv_int(out, "rows_skipped", s->skipped);
    (void)json_push_kv_int(out, "lines_oversized", s->oversized);
    (void)json_push_kv_int(out, "days_dropped_rows", s->day_overflow);
    (void)json_push_kv_int(out, "failure_groups_dropped_rows", s->fail_overflow);
}

struct ls_buf {
    char *out;
    size_t cap, n;
};

static void ls_put(struct ls_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void ls_put(struct ls_buf *b, const char *fmt, ...)
{
    va_list ap;
    int w;
    va_start(ap, fmt);
    w = vsnprintf(b->out + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    if (w > 0)
        b->n = (size_t)w < b->cap - b->n ? b->n + (size_t)w : b->cap - 1;
}

static void ls_screen_head(struct ls_buf *b, const struct ls_stats *s,
                           int64_t hours, int64_t med, int64_t p90)
{
    int64_t rate = ls_failure_permille(s);
    ls_put(b, "land stats, last %lld h: landed %lld, failed %lld, conflict %lld, "
              "cancelled %lld\n",
           (long long)hours, (long long)s->rows[LS_LANDED],
           (long long)s->rows[LS_FAILED], (long long)s->rows[LS_CONFLICT],
           (long long)s->rows[LS_CANCELLED]);
    if (rate < 0)
        ls_put(b, "failure rate: none (no landed or failed row), target under 5.0%%\n");
    else
        ls_put(b, "failure rate: %lld.%lld%% of landed+failed, target under 5.0%%\n",
               (long long)(rate / 10), (long long)(rate % 10));
    ls_put(b, "landed duration: median %lld s, p90 %lld s\n", (long long)med,
           (long long)p90);
}

/* The short human screen, written to out (cap bytes, always terminated). */
static void ls_screen(const struct ls_stats *s, const struct ls_src *src,
                      int64_t hours, int64_t med, int64_t p90, char *out,
                      size_t cap)
{
    struct ls_buf b = {out, cap, 0};
    out[0] = '\0';
    ls_screen_head(&b, s, hours, med, p90);
    for (size_t i = 0; i < s->ndays; i++) {
        char ymd[16];
        int64_t pm = ls_permille(s->days[i].busy_s, LS_DAY_S);
        ls_ymd(s->days[i].day, ymd, sizeof(ymd));
        ls_put(&b, "slot %s: %lld.%lld%% busy\n", ymd, (long long)(pm / 10),
               (long long)(pm % 10));
    }
    for (size_t i = 0; i < s->nfails; i++)
        ls_put(&b, "failed %s/%s: %lld row(s), %lld slot min\n",
               s->fails[i].phase[0] ? s->fails[i].phase : "-",
               s->fails[i].dimension[0] ? s->fails[i].dimension : "-",
               (long long)s->fails[i].rows,
               (long long)((s->fails[i].slot_s + 30) / 60));
    if (src->capped || src->rows_capped)
        ls_put(&b, "capped: read the last %lld of %lld bytes%s\n",
               (long long)src->bytes_read, (long long)src->bytes_total,
               ls_covered(s, src) ? "" : "; the window is only partly covered");
}

static void ls_report(struct ls_stats *s, const struct ls_src *src,
                      const char *path, int64_t hours, int64_t now,
                      struct zcl_command_reply *reply)
{
    struct json_value totals, days, fails, landed, source;
    int64_t med, p90;
    char screen[4096];
    qsort(s->days, s->ndays, sizeof(s->days[0]), ls_cmp_day);
    qsort(s->fails, s->nfails, sizeof(s->fails[0]), ls_cmp_fail);
    if (s->nlanded)
        qsort(s->landed_s, s->nlanded, sizeof(*s->landed_s), ls_cmp_i64);
    med = ls_pct(s->landed_s, s->nlanded, 50);
    p90 = ls_pct(s->landed_s, s->nlanded, 90);
    ls_new_obj(&totals);
    ls_new_obj(&landed);
    ls_new_obj(&source);
    ls_totals(s, &totals);
    ls_days(s, &days);
    ls_fails(s, &fails);
    (void)json_push_kv_int(&landed, "n", (int64_t)s->nlanded);
    (void)json_push_kv_int(&landed, "median_s", med);
    (void)json_push_kv_int(&landed, "p90_s", p90);
    ls_source(s, src, path, &source);
    ls_screen(s, src, hours, med, p90, screen, sizeof(screen));
    (void)json_push_kv_int(&reply->data, "hours", hours);
    (void)json_push_kv_int(&reply->data, "window_s", hours * 3600);
    (void)json_push_kv_int(&reply->data, "now", now);
    ls_attach(&reply->data, "source", &source);
    ls_attach(&reply->data, "totals", &totals);
    ls_attach(&reply->data, "days", &days);
    ls_attach(&reply->data, "failures_by", &fails);
    ls_attach(&reply->data, "landed_duration", &landed);
    (void)json_push_kv_str(&reply->data, "screen", screen);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

/* A refused request: code names the class, stage where it was refused. */
static void ls_refuse(struct zcl_command_reply *reply, int exit_code,
                      const char *code, const char *stage, const char *msg,
                      const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           stage, false, false, msg, evidence);
}

static void ls_invalid(struct zcl_command_reply *reply, const char *msg,
                       const char *evidence)
{
    ls_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT", "normalize",
              msg, evidence);
}

/* An absent key keeps *out; a present one must be an integer in [lo, hi]. */
static bool ls_input_int(const struct json_value *in, const char *key,
                         int64_t lo, int64_t hi, int64_t *out)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type != JSON_INT || json_get_int(v) < lo || json_get_int(v) > hi)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool ls_path(const struct json_value *in, char *out, size_t cap)
{
    const struct json_value *v = in ? json_get(in, "outcomes") : NULL;
    char root[512];
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return snprintf(out, cap, "%s", json_get_str(v)) < (int)cap;
    return platform_state_root(root, sizeof(root)) &&
           snprintf(out, cap, "%s/land/outcomes.jsonl", root) < (int)cap;
}

void zcl_native_handle_dev_land_stats(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    int64_t hours = LS_DEFAULT_HOURS, now;
    struct ls_stats *s;
    struct ls_src src = {0};
    char path[LS_PATH];
    if (!reply)
        return;
    now = (int64_t)platform_time_wall_unix();
    if (!ls_input_int(in, "hours", 1, LS_MAX_HOURS, &hours)) {
        ls_invalid(reply, "hours is an integer in 1..720", "input.hours");
        return;
    }
    if (!ls_input_int(in, "now", 1, INT64_MAX, &now)) {
        ls_invalid(reply, "now is a positive epoch in seconds", "input.now");
        return;
    }
    if (!ls_path(in, path, sizeof(path))) {
        ls_invalid(reply, "the outcomes ledger path cannot be resolved", "input.outcomes");
        return;
    }
    s = zcl_calloc(1, sizeof(*s), "dev_land_stats");
    if (!s) {
        ls_invalid(reply, "cannot allocate the stats", "oom");
        return;
    }
    s->window_start = now - hours * 3600;
    if (!ls_read(path, s, &src))
        ls_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "LEDGER_UNREADABLE", "read",
                  "the land outcomes ledger cannot be read", path);
    else if (s->oom)
        ls_invalid(reply, "out of memory collecting landed durations", "oom");
    else
        ls_report(s, &src, path, hours, now, reply);
    free(s->landed_s);
    free(s);
}
