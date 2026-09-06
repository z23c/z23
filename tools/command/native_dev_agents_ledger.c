/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grade every AI executor from the delegation ledger — the `grades`
 *          section of `z23-dev fleet agents`.
 *
 * WHAT IT READS. One tab-separated append-only ledger, 22 columns, written by
 * whoever dispatches a delegation. Column order is fixed and named in
 * docs/FLEET_AGENTS.md; the two that carry the measurement are `kind`
 * (predict or result) and `task_id` (the string the two rows of ONE
 * delegation share).
 *
 * WHAT A GRADE IS. Success rate over the rows whose outcome word this file
 * recognizes, and the median of actual-over-predicted wall time for the
 * results that had a prediction to be compared against. Both halves are
 * required for the top two grades on purpose: an executor that always lands
 * but takes four times as long as promised is not an A, because every plan
 * built on its estimate was wrong. An executor with fewer than three results
 * gets no grade at all — three points is already generous, and a letter over
 * one sample would be read as a fact.
 *
 * WHAT IT NEVER DOES. It never writes the ledger, never contacts a peer, and
 * never decides anything: a grade is a report, and no gate may cite one.
 * It reads no clock either — `now` arrives in the options, so the window and
 * every age here are decided by the caller and are exactly reproducible.
 */

#include "command/native_dev_agents.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AG_COLUMNS 22u
#define AG_COL_TS 0u
#define AG_COL_KIND 1u
#define AG_COL_TASK_ID 3u
#define AG_COL_TASK_CLASS 4u
#define AG_COL_STORY 5u
#define AG_COL_EXECUTOR 6u
#define AG_COL_TOKENS_IN 10u
#define AG_COL_TOKENS_OUT 11u
#define AG_COL_WALL_S 16u
#define AG_COL_OUTCOME 17u

#define AG_LINE_MAX 8192u
#define AG_MAX_LINES 400000u
#define AG_MAX_RESULTS 32768u
#define AG_MAX_PREDICTS 32768u
#define AG_MAX_GROUPS 64u
#define AG_KEY_MAX 48u
#define AG_ID_MAX 48u
#define AG_OUTCOME_MAX 16u
#define AG_MAX_REPORTED_BAD_LINES 8u

struct ag_result {
    int64_t ts;
    int64_t wall_s;
    int64_t tokens;
    char key[AG_KEY_MAX];
    char task_id[AG_ID_MAX];
    char outcome[AG_OUTCOME_MAX];
};

struct ag_predict {
    int64_t ts;
    int64_t wall_s;
    char task_id[AG_ID_MAX];
};

struct ag_group {
    char key[AG_KEY_MAX];
    int64_t tasks, success, failure, other, tokens, last_ts;
};

/* The outcome vocabulary, split the only way that matters to a caller: the
 * work landed, the work did not land, or the row says something this grade
 * does not know how to score. `unknown` rows are real and numerous — they are
 * reported as `other` and kept OUT of the rate rather than quietly counted as
 * either, because a denominator that includes rows nobody scored is a rate
 * nobody can act on. */
static bool ag_is_success(const char *outcome)
{
    return strcmp(outcome, "LAND") == 0 || strcmp(outcome, "READY") == 0 ||
           strcmp(outcome, "landed") == 0 || strcmp(outcome, "PASS") == 0;
}

static bool ag_is_failure(const char *outcome)
{
    return strcmp(outcome, "HOLD") == 0 || strcmp(outcome, "FAIL") == 0 ||
           strcmp(outcome, "failed") == 0 || strcmp(outcome, "timeout") == 0;
}

/* Days since the unix epoch for a proleptic Gregorian date. Integer only, so
 * the ledger's timestamps parse identically on every platform and in every
 * time zone; the ledger writes UTC and nothing here consults a zone. */
static int64_t ag_days_from_civil(int64_t y, int64_t m, int64_t d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* The fixed-width separators an ISO instant must carry before any digit is
 * worth reading. */
static bool ag_ts_shape_ok(const char *text)
{
    static const unsigned char at[6] = {4, 7, 10, 13, 16, 19};
    static const char want[6] = {'-', '-', 'T', ':', ':', 'Z'};
    if (!text || strlen(text) < 20) return false;
    for (size_t i = 0; i < 6; i++)
        if (text[at[i]] != want[i]) return false;
    return true;
}

/* One fixed-width run of decimal digits. Anything else fails the row. */
static bool ag_ts_digits(const char *text, size_t offset, size_t width,
                         int64_t *out)
{
    int64_t value = 0;
    for (size_t i = 0; i < width; i++) {
        char c = text[offset + i];
        if (c < '0' || c > '9') return false;
        value = value * 10 + (c - '0');
    }
    *out = value;
    return true;
}

/* Calendar ranges, leap second included. Day-of-month is bounded at 31 and
 * not per-month: this rejects nonsense without pretending to be a calendar. */
static bool ag_ts_in_range(const int64_t f[6])
{
    if (f[1] < 1 || f[1] > 12) return false;
    if (f[2] < 1 || f[2] > 31) return false;
    if (f[3] > 23 || f[4] > 59 || f[5] > 60) return false;
    return true;
}

/* "2026-09-06T18:09:45Z" -> unix seconds. Returns false on any other shape:
 * a timestamp this reader cannot place in time makes the whole row
 * unusable, and guessing one would put a row in the wrong window. */
static bool ag_parse_ts(const char *text, int64_t *out)
{
    static const unsigned char offs[6] = {0, 5, 8, 11, 14, 17};
    static const unsigned char widths[6] = {4, 2, 2, 2, 2, 2};
    int64_t f[6];
    if (!ag_ts_shape_ok(text)) return false;
    for (size_t i = 0; i < 6; i++)
        if (!ag_ts_digits(text, offs[i], widths[i], &f[i])) return false;
    if (!ag_ts_in_range(f)) return false;
    *out = ag_days_from_civil(f[0], f[1], f[2]) * 86400 + f[3] * 3600 +
           f[4] * 60 + f[5];
    return true;
}

static int64_t ag_int(const char *text)
{
    if (!text || !text[0]) return 0;
    return strtoll(text, NULL, 10);
}

static void ag_copy(char *dst, size_t cap, const char *src)
{
    (void)snprintf(dst, cap, "%s", src ? src : "");
}

static int ag_cmp_int64(const void *left, const void *right)
{
    int64_t a = *(const int64_t *)left, b = *(const int64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Median of a sorted-in-place array. Even counts take the lower of the two
 * middles rather than their mean: every value here is a whole second or a
 * whole basis point, and an average would invent a value the ledger never
 * recorded. */
static int64_t ag_median(int64_t *values, size_t count)
{
    if (count == 0) return -1;
    qsort(values, count, sizeof(*values), ag_cmp_int64);
    return values[(count - 1) / 2];
}

static const char *ag_grade(int64_t tasks, int64_t graded, int64_t success,
                            int64_t ratio_bp)
{
    if (tasks < 3) return "n/a (n<3)";
    if (graded <= 0) return "n/a";
    int64_t rate_bp = success * 10000 / graded;
    bool ratio_known = ratio_bp >= 0;
    if (rate_bp >= 9000 && ratio_known && ratio_bp <= 15000) return "A";
    if (rate_bp >= 8000 && ratio_known && ratio_bp <= 20000) return "B";
    if (rate_bp >= 6500) return "C";
    if (rate_bp >= 5000) return "D";
    return "F";
}

void zcl_agents_default_ledger(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    (void)snprintf(out, cap, "%s/.local/state/zclassic23/experiments/rows.tsv",
                   home && home[0] ? home : ".");
}

/* Split one line into at most AG_COLUMNS tab-separated fields IN PLACE.
 * Returns the field count; a line with fewer than AG_COLUMNS is malformed and
 * the caller reports its line number. */
static size_t ag_split(char *line, char *fields[AG_COLUMNS])
{
    size_t n = 0;
    char *at = line;
    while (n < AG_COLUMNS) {
        char *tab = strchr(at, '\t');
        fields[n++] = at;
        if (!tab) break;
        *tab = 0;
        at = tab + 1;
    }
    return n;
}

static size_t ag_column_for(const char *group_by)
{
    if (group_by && strcmp(group_by, "lane") == 0) return AG_COL_STORY;
    if (group_by && strcmp(group_by, "class") == 0) return AG_COL_TASK_CLASS;
    return AG_COL_EXECUTOR;
}

struct ag_scan {
    struct ag_result *results;
    struct ag_predict *predicts;
    size_t result_count, predict_count;
    size_t line_count, bad_count, result_total;
    int64_t bad_lines[AG_MAX_REPORTED_BAD_LINES];
    bool truncated;
};

/* A row the reader could not use. The first few line numbers are kept so the
 * report can name them; the count is kept for all of them. */
static void ag_note_bad(struct ag_scan *scan)
{
    if (scan->bad_count < AG_MAX_REPORTED_BAD_LINES)
        scan->bad_lines[scan->bad_count] = (int64_t)scan->line_count;
    scan->bad_count++;
}

/* One line, newline stripped. A line longer than the buffer is consumed to
 * its newline and reported as INCOMPLETE, so an oversized row can never be
 * re-read as several well-formed ones. */
static bool ag_read_line(FILE *file, char *line, size_t cap, size_t *len_out,
                         bool *complete)
{
    size_t len;
    if (!fgets(line, (int)cap, file)) return false;
    len = strlen(line);
    *complete = len > 0 && line[len - 1] == '\n';
    if (!*complete && !feof(file)) {
        int c;
        while ((c = fgetc(file)) != EOF && c != '\n') { }
    }
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    *len_out = len;
    return true;
}

static void ag_take_predict(struct ag_scan *scan, char *const fields[],
                            int64_t ts)
{
    struct ag_predict *p;
    if (scan->predict_count >= AG_MAX_PREDICTS) return;
    p = &scan->predicts[scan->predict_count++];
    p->ts = ts;
    p->wall_s = ag_int(fields[AG_COL_WALL_S]);
    ag_copy(p->task_id, sizeof(p->task_id), fields[AG_COL_TASK_ID]);
}

/* Every result is counted in the ledger total; only the ones inside the
 * window are kept for grading, so the report can say how much of the ledger
 * the window covered. */
static void ag_take_result(struct ag_scan *scan,
                           const struct zcl_agents_options *options,
                           char *const fields[], size_t key_column,
                           int64_t cutoff, int64_t ts)
{
    struct ag_result *r;
    scan->result_total++;
    if (options->since_hours > 0 && ts < cutoff) return;
    if (scan->result_count >= AG_MAX_RESULTS) {
        scan->truncated = true;
        return;
    }
    r = &scan->results[scan->result_count++];
    r->ts = ts;
    r->wall_s = ag_int(fields[AG_COL_WALL_S]);
    r->tokens = ag_int(fields[AG_COL_TOKENS_IN]) +
                ag_int(fields[AG_COL_TOKENS_OUT]);
    ag_copy(r->key, sizeof(r->key), fields[key_column]);
    ag_copy(r->task_id, sizeof(r->task_id), fields[AG_COL_TASK_ID]);
    ag_copy(r->outcome, sizeof(r->outcome), fields[AG_COL_OUTCOME]);
}

/* Classify one already-read line. The header is skipped, a blank line is
 * nothing, and everything the vocabulary does not cover is reported by line
 * number rather than guessed at. */
static void ag_scan_row(struct ag_scan *scan,
                        const struct zcl_agents_options *options, char *line,
                        size_t len, bool complete, size_t key_column,
                        int64_t cutoff)
{
    char *fields[AG_COLUMNS];
    int64_t ts = 0;
    if (scan->line_count == 1 && strncmp(line, "ts\t", 3) == 0) return;
    if (!len) return;
    if (!complete || ag_split(line, fields) < AG_COLUMNS) {
        ag_note_bad(scan);
        return;
    }
    if (!ag_parse_ts(fields[AG_COL_TS], &ts)) {
        ag_note_bad(scan);
        return;
    }
    if (strcmp(fields[AG_COL_KIND], "predict") == 0) {
        ag_take_predict(scan, fields, ts);
        return;
    }
    if (strcmp(fields[AG_COL_KIND], "result") != 0) {
        ag_note_bad(scan);
        return;
    }
    ag_take_result(scan, options, fields, key_column, cutoff, ts);
}

/* One streaming pass over the ledger. */
static void ag_scan_file(FILE *file, const struct zcl_agents_options *options,
                         size_t key_column, int64_t cutoff,
                         struct ag_scan *scan)
{
    char line[AG_LINE_MAX];
    size_t len = 0;
    bool complete = false;
    while (scan->line_count < AG_MAX_LINES &&
           ag_read_line(file, line, sizeof(line), &len, &complete)) {
        scan->line_count++;
        ag_scan_row(scan, options, line, len, complete, key_column, cutoff);
    }
}

/* The prediction this result should be compared against: the LATEST predict
 * carrying the same task_id that is not newer than the result itself. A
 * later re-prediction of the same id belongs to a later attempt, and grading
 * an attempt against a promise made after it finished would flatter it. */
static int64_t ag_predicted_wall(const struct ag_scan *scan,
                                 const struct ag_result *result)
{
    int64_t best_ts = -1, best_wall = -1;
    if (!result->task_id[0]) return -1;
    for (size_t i = 0; i < scan->predict_count; i++) {
        const struct ag_predict *p = &scan->predicts[i];
        if (p->ts > result->ts || strcmp(p->task_id, result->task_id) != 0)
            continue;
        if (p->ts >= best_ts) { best_ts = p->ts; best_wall = p->wall_s; }
    }
    return best_wall > 0 ? best_wall : -1;
}

static int ag_group_compare(const void *left, const void *right)
{
    const struct ag_group *a = left, *b = right;
    if (a->tasks != b->tasks) return a->tasks < b->tasks ? 1 : -1;
    return strcmp(a->key, b->key);
}

static void ag_push_row(struct json_value *rows, const char *key,
                        const struct ag_group *g, int64_t median_wall,
                        int64_t median_ratio, int64_t now_unix)
{
    struct json_value row;
    int64_t graded = g->success + g->failure;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "key", key);
    (void)json_push_kv_int(&row, "tasks", g->tasks);
    (void)json_push_kv_int(&row, "success", g->success);
    (void)json_push_kv_int(&row, "failure", g->failure);
    (void)json_push_kv_int(&row, "other", g->other);
    (void)json_push_kv_int(&row, "success_rate_bp",
                           graded > 0 ? g->success * 10000 / graded : -1);
    (void)json_push_kv_int(&row, "median_wall_s", median_wall);
    (void)json_push_kv_int(&row, "median_ratio_bp", median_ratio);
    (void)json_push_kv_int(&row, "tokens_per_success",
                           g->success > 0 ? g->tokens / g->success : -1);
    (void)json_push_kv_int(&row, "last_activity_age_s",
                           g->last_ts > 0 && now_unix >= g->last_ts
                               ? now_unix - g->last_ts
                               : -1);
    (void)json_push_kv_str(&row, "grade",
                           ag_grade(g->tasks, graded, g->success, median_ratio));
    (void)json_push_back(rows, &row);
    json_free(&row);
}

/* The group name a result belongs to. A row whose grouping column is blank
 * is still a delegation and is reported under one honest name rather than
 * dropped. */
static const char *ag_key_of(const struct ag_result *result)
{
    return result->key[0] ? result->key : "(unnamed)";
}

struct ag_buffers {
    struct ag_group *groups;
    int64_t *walls;
    int64_t *ratios;
};

static void ag_free_buffers(struct ag_scan *scan, struct ag_buffers *buf)
{
    free(scan->results);
    free(scan->predicts);
    free(buf->groups);
    free(buf->walls);
    free(buf->ratios);
    scan->results = NULL;
    scan->predicts = NULL;
    buf->groups = NULL;
    buf->walls = NULL;
    buf->ratios = NULL;
}

/* Every buffer this read will ever need, taken up front and bounded. */
static bool ag_alloc_buffers(struct ag_scan *scan, struct ag_buffers *buf)
{
    scan->results = zcl_calloc(AG_MAX_RESULTS, sizeof(*scan->results),
                               "agents_ledger_results");
    scan->predicts = zcl_calloc(AG_MAX_PREDICTS, sizeof(*scan->predicts),
                                "agents_ledger_predicts");
    buf->groups = zcl_calloc(AG_MAX_GROUPS, sizeof(*buf->groups),
                             "agents_ledger_groups");
    buf->walls = zcl_calloc(AG_MAX_RESULTS, sizeof(*buf->walls),
                            "agents_ledger_walls");
    buf->ratios = zcl_calloc(AG_MAX_RESULTS, sizeof(*buf->ratios),
                             "agents_ledger_ratios");
    if (scan->results && scan->predicts && buf->groups && buf->walls &&
        buf->ratios)
        return true;
    ag_free_buffers(scan, buf);
    return false;
}

/* Fold one result into a tally: the counts, the tokens, and the newest row. */
static void ag_tally(struct ag_group *g, const struct ag_result *r)
{
    g->tasks++;
    g->tokens += r->tokens;
    if (r->ts > g->last_ts) g->last_ts = r->ts;
    if (ag_is_success(r->outcome)) g->success++;
    else if (ag_is_failure(r->outcome)) g->failure++;
    else g->other++;
}

/* The tally for one key, created on first sight. NULL once the group table
 * is full — a group past the bound is left out of the table rather than
 * merged into a neighbour's numbers. */
static struct ag_group *ag_group_for(struct ag_group *groups, size_t *count,
                                     const char *key)
{
    for (size_t i = 0; i < *count; i++)
        if (strcmp(groups[i].key, key) == 0) return &groups[i];
    if (*count >= AG_MAX_GROUPS) return NULL;
    ag_copy(groups[*count].key, sizeof(groups[*count].key), key);
    return &groups[(*count)++];
}

/* Every result counted twice: once into its own group, once into the total. */
static size_t ag_accumulate(const struct ag_scan *scan, struct ag_group *groups,
                            struct ag_group *all)
{
    size_t count = 0;
    for (size_t i = 0; i < scan->result_count; i++) {
        const struct ag_result *r = &scan->results[i];
        struct ag_group *g = ag_group_for(groups, &count, ag_key_of(r));
        if (!g) continue;
        ag_tally(g, r);
        ag_tally(all, r);
    }
    return count;
}

/* Median wall time and median actual-over-predicted wall for one key, or for
 * every result when `key` is NULL. Both walk the same rows through the same
 * pairing rule, so the total line is computed exactly like a group line. */
static void ag_medians(const struct ag_scan *scan, const char *key,
                       struct ag_buffers *buf, int64_t *wall, int64_t *ratio)
{
    size_t walls = 0, rats = 0;
    for (size_t i = 0; i < scan->result_count; i++) {
        const struct ag_result *r = &scan->results[i];
        int64_t predicted;
        if (key && strcmp(ag_key_of(r), key) != 0) continue;
        buf->walls[walls++] = r->wall_s;
        predicted = ag_predicted_wall(scan, r);
        if (predicted > 0 && r->wall_s >= 0)
            buf->ratios[rats++] = r->wall_s * 10000 / predicted;
    }
    *wall = ag_median(buf->walls, walls);
    *ratio = ag_median(buf->ratios, rats);
}

static void ag_push_totals(struct json_value *total,
                           const struct ag_group *all, int64_t wall,
                           int64_t ratio)
{
    int64_t graded = all->success + all->failure;
    (void)json_push_kv_int(total, "tasks", all->tasks);
    (void)json_push_kv_int(total, "success", all->success);
    (void)json_push_kv_int(total, "failure", all->failure);
    (void)json_push_kv_int(total, "other", all->other);
    (void)json_push_kv_int(total, "success_rate_bp",
                           graded > 0 ? all->success * 10000 / graded : -1);
    (void)json_push_kv_int(total, "median_wall_s", wall);
    (void)json_push_kv_int(total, "median_ratio_bp", ratio);
}

static void ag_push_bad_lines(struct json_value *bad,
                              const struct ag_scan *scan)
{
    size_t shown = scan->bad_count < AG_MAX_REPORTED_BAD_LINES
                       ? scan->bad_count
                       : AG_MAX_REPORTED_BAD_LINES;
    for (size_t i = 0; i < shown; i++) {
        struct json_value n;
        json_init(&n);
        json_set_int(&n, scan->bad_lines[i]);
        (void)json_push_back(bad, &n);
        json_free(&n);
    }
}

/* One row per group, newest-heaviest first, up to the transport bound. */
static size_t ag_push_group_rows(const struct ag_scan *scan,
                                 struct ag_buffers *buf, size_t group_count,
                                 int64_t now_unix, struct json_value *rows)
{
    size_t emitted = 0;
    while (emitted < group_count && emitted < ZCL_AGENTS_MAX_GRADE_ROWS) {
        const struct ag_group *g = &buf->groups[emitted];
        int64_t wall = -1, ratio = -1;
        ag_medians(scan, g->key, buf, &wall, &ratio);
        ag_push_row(rows, g->key, g, wall, ratio, now_unix);
        emitted++;
    }
    return emitted;
}

/* Which file this read used, and which rows of it were usable. */
static void ag_push_provenance(struct json_value *out,
                               const struct zcl_agents_options *options,
                               const char *path, const struct ag_scan *scan)
{
    const char *by = options->group_by && options->group_by[0]
                         ? options->group_by
                         : "executor";
    (void)json_push_kv_str(out, "state", "observed");
    (void)json_push_kv_str(out, "ledger", path);
    (void)json_push_kv_str(out, "group_by", by);
    (void)json_push_kv_int(out, "window_hours", options->since_hours);
    (void)json_push_kv_int(out, "ledger_lines", (int64_t)scan->line_count);
    (void)json_push_kv_int(out, "result_rows_total",
                           (int64_t)scan->result_total);
    (void)json_push_kv_int(out, "result_rows_in_window",
                           (int64_t)scan->result_count);
    (void)json_push_kv_int(out, "predict_rows", (int64_t)scan->predict_count);
    (void)json_push_kv_int(out, "skipped_rows", (int64_t)scan->bad_count);
}

/* Resolve the ledger path and open it. The refusal names the exact file,
 * because "no ledger" and "the wrong ledger" need different next actions. */
static FILE *ag_open_ledger(const struct zcl_agents_options *options,
                            char *path, size_t cap, char *why, size_t why_size)
{
    FILE *file;
    if (options->ledger && options->ledger[0])
        (void)snprintf(path, cap, "%s", options->ledger);
    else
        zcl_agents_default_ledger(path, cap);
    file = fopen(path, "rb");
    if (!file && why)
        (void)snprintf(why, why_size,
                       "no delegation ledger to grade: %s does not exist or "
                       "cannot be read", path);
    return file;
}

bool zcl_agents_grades_json(const struct zcl_agents_options *options,
                            struct json_value *out, char *why,
                            size_t why_size)
{
    char path[ZCL_AGENTS_PATH_MAX];
    struct ag_scan scan;
    struct ag_buffers buf;
    struct ag_group all;
    struct json_value rows, bad, total;
    int64_t all_wall = -1, all_ratio = -1;
    size_t group_count, emitted;
    FILE *file;

    if (!options || !out) return false;
    file = ag_open_ledger(options, path, sizeof(path), why, why_size);
    if (!file) return false;

    memset(&scan, 0, sizeof(scan));
    memset(&buf, 0, sizeof(buf));
    memset(&all, 0, sizeof(all));
    if (!ag_alloc_buffers(&scan, &buf)) {
        (void)fclose(file);
        if (why)
            (void)snprintf(why, why_size,
                           "cannot allocate the ledger buffers for %s", path);
        return false;
    }

    ag_scan_file(file, options, ag_column_for(options->group_by),
                 options->now_unix - options->since_hours * 3600, &scan);
    (void)fclose(file);

    group_count = ag_accumulate(&scan, buf.groups, &all);
    qsort(buf.groups, group_count, sizeof(*buf.groups), ag_group_compare);

    json_init(&rows); json_set_array(&rows);
    json_init(&bad); json_set_array(&bad);
    json_init(&total); json_set_object(&total);

    emitted = ag_push_group_rows(&scan, &buf, group_count, options->now_unix,
                                 &rows);
    ag_medians(&scan, NULL, &buf, &all_wall, &all_ratio);
    ag_push_totals(&total, &all, all_wall, all_ratio);
    ag_push_bad_lines(&bad, &scan);

    json_set_object(out);
    ag_push_provenance(out, options, path, &scan);
    (void)json_push_kv(out, "skipped_lines", &bad);
    (void)json_push_kv_int(out, "count", (int64_t)emitted);
    (void)json_push_kv_int(out, "total", (int64_t)group_count);
    (void)json_push_kv_bool(out, "truncated",
                            scan.truncated || emitted < group_count);
    (void)json_push_kv(out, "rows", &rows);
    (void)json_push_kv(out, "totals", &total);

    json_free(&rows); json_free(&bad); json_free(&total);
    ag_free_buffers(&scan, &buf);
    return true;
}
