/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The producers behind `fleet.objectives` — small static readers
 *          of outcomes.jsonl, a proof attempt's phases.txt, `git log`
 *          through the no-shell spawn seam, and two line counts. Every
 *          producer answers UNMEASURED, never a fabricated zero, when its
 *          one named input is missing or unreadable.
 *
 * CONVERGENCE NOTE (matches tools/dev/fleet_observe.c's own note): a
 * stricter RFC 3339 parser already ships in
 * contexts/commons/packages/ztime, but that package is not wired into any
 * Makefile target that reaches this binary. obj_parse_iso8601() below is
 * the same small, dependency-free parser duplicated a second time rather
 * than widening this leaf's link graph to pull in an orphaned package. */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/state_root.h"
#include "util/spawn.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define OBJ_LINE_MAX 4096u
#define OBJ_LINT_CEILING_LINES 1500

/* ── timestamp parsing ────────────────────────────────────────────────── */

static bool obj_digits(const char *s, int n, int *out)
{
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

static int64_t obj_days_from_civil(int64_t y, int m, int d)
{
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* "YYYY-MM-DDTHH:MM:SSZ": the six punctuation bytes at their fixed offsets. */
static bool obj_iso8601_punctuation_ok(const char *s)
{
    static const int pos[] = {4, 7, 10, 13, 16, 19};
    static const char want[] = {'-', '-', 'T', ':', ':', 'Z'};
    for (size_t i = 0; i < sizeof(pos) / sizeof(pos[0]); i++)
        if (s[pos[i]] != want[i])
            return false;
    return true;
}

struct obj_iso8601_field {
    int offset;
    int width;
    int *out;
};

static bool obj_iso8601_digits_ok(const char *s, int *y, int *mo, int *d,
                                  int *h, int *mi, int *se)
{
    const struct obj_iso8601_field fields[] = {
        {0, 4, y}, {5, 2, mo}, {8, 2, d}, {11, 2, h}, {14, 2, mi}, {17, 2, se},
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (!obj_digits(s + fields[i].offset, fields[i].width, fields[i].out))
            return false;
    return true;
}

static bool obj_iso8601_ranges_ok(int mo, int d, int h, int mi, int se)
{
    if (mo < 1 || mo > 12)
        return false;
    if (d < 1 || d > 31)
        return false;
    if (h > 23)
        return false;
    if (mi > 59)
        return false;
    return se <= 60;
}

static bool obj_parse_iso8601(const char *s, int64_t *out)
{
    int y, mo, d, h, mi, se;
    if (!s || strlen(s) != 20)
        return false;
    if (!obj_iso8601_punctuation_ok(s))
        return false;
    if (!obj_iso8601_digits_ok(s, &y, &mo, &d, &h, &mi, &se))
        return false;
    if (!obj_iso8601_ranges_ok(mo, d, h, mi, se))
        return false;
    *out = obj_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

/* ── shared paths ─────────────────────────────────────────────────────── */

static void obj_set_reason(struct zcl_objective_value *out, const char *fmt,
                           const char *arg)
{
    out->measured = false;
    (void)snprintf(out->reason, sizeof(out->reason), fmt, arg);
}

static bool obj_default_outcomes(char *out, size_t cap)
{
    char root[512];
    if (!platform_state_root(root, sizeof(root)))
        return false;
    return snprintf(out, cap, "%s/land/outcomes.jsonl", root) > 0;
}

static bool obj_default_attempts_dir(char *out, size_t cap)
{
    char root[512];
    if (!platform_state_root(root, sizeof(root)))
        return false;
    return snprintf(out, cap,
                    "%s/land/wt/.cache/zcl-dev-proof/attempts", root) > 0;
}

/* ── outcomes.jsonl scan ──────────────────────────────────────────────── */

/* A TRAIN's identity is its `note` (e.g. "traintrain43"), the one field
 * that stays constant across every attempt of one train even though `tip`
 * and `base` both change on every rebase. A row with an empty `note` falls
 * back to `worktree`. landing_latency_s and landing_attempts_per_train are
 * both properties of the newest train that finished landing, not of its
 * final row alone. */
#define OBJ_NOTE_MAX 256u

static void obj_row_group_key(const struct json_value *row, char *out,
                              size_t cap)
{
    const char *note = json_get_str(json_get(row, "note"));
    const char *key = note[0] ? note : json_get_str(json_get(row, "worktree"));
    (void)snprintf(out, cap, "%s", key);
}

struct obj_outcomes_stats {
    bool have_last_landed;
    int64_t last_landed_ts;
    char last_landed_note[OBJ_NOTE_MAX];
};

static void obj_outcomes_row(const struct json_value *row,
                             struct obj_outcomes_stats *stats)
{
    const char *state = json_get_str(json_get(row, "state"));
    const char *ts = json_get_str(json_get(row, "ts"));
    int64_t ts_unix;

    if (strcmp(state, "landed") != 0 || !ts[0])
        return;
    if (!obj_parse_iso8601(ts, &ts_unix))
        return;
    stats->have_last_landed = true;
    stats->last_landed_ts = ts_unix;
    obj_row_group_key(row, stats->last_landed_note,
                      sizeof(stats->last_landed_note));
}

/* The newest `landed` row's train identity and timestamp: `landed` rows
 * are rare relative to the rest of the ledger, so tracking only that one
 * fact keeps this pass a single field update per matching row. */
static bool obj_scan_outcomes(const char *path, struct obj_outcomes_stats *out,
                              char *reason, size_t reason_cap)
{
    char line[OBJ_LINE_MAX];
    FILE *fp;

    memset(out, 0, sizeof(*out));
    fp = fopen(path, "r");
    if (!fp) {
        (void)snprintf(reason, reason_cap, "missing outcomes file %s", path);
        return false;
    }
    while (fgets(line, sizeof(line), fp)) {
        struct json_value row;
        json_init(&row);
        if (json_read(&row, line, strlen(line)) && row.type == JSON_OBJ)
            obj_outcomes_row(&row, out);
        json_free(&row);
    }
    (void)fclose(fp);
    return true;
}

/* ── one train's own rows ────────────────────────────────────────────── */

/* A growable set of distinct (attempt, started) pairs: the measured
 * outcomes ledger writes exactly one row per real attempt (each row's
 * `started` differs), so this dedup is a defensive no-op today, kept so a
 * future writer that re-logs one attempt (a retried phase under the same
 * started time) cannot double-count it. */
struct obj_pair_set {
    int64_t (*items)[2];
    size_t n;
    size_t cap;
};

static bool obj_pair_add_new(struct obj_pair_set *set, int64_t attempt,
                             int64_t started)
{
    for (size_t i = 0; i < set->n; i++)
        if (set->items[i][0] == attempt && set->items[i][1] == started)
            return false;
    if (set->n == set->cap) {
        size_t next = set->cap ? set->cap * 2u : 16u;
        int64_t (*grown)[2] = zcl_realloc(
            set->items, next * sizeof(*grown), "fleet_objectives_pairs");
        if (!grown)
            return false;
        set->items = grown;
        set->cap = next;
    }
    set->items[set->n][0] = attempt;
    set->items[set->n][1] = started;
    set->n++;
    return true;
}

struct obj_train_stats {
    bool found;
    int64_t earliest_epoch; /* the earliest row's `started`, or its `ts` */
    struct obj_pair_set attempts; /* distinct (attempt, started) landed/failed */
};

/* `started` present wins; a row with no `started` key falls back to its
 * own `ts`. */
static bool obj_row_start_epoch(const struct json_value *row, int64_t *out)
{
    const struct json_value *started_v = json_get(row, "started");
    if (started_v) {
        *out = json_get_int(started_v);
        return true;
    }
    const char *ts = json_get_str(json_get(row, "ts"));
    return ts[0] && obj_parse_iso8601(ts, out);
}

static void obj_train_stats_row(const struct json_value *row,
                                const char *note,
                                struct obj_train_stats *out)
{
    char key[OBJ_NOTE_MAX];
    const char *state;

    obj_row_group_key(row, key, sizeof(key));
    if (strcmp(key, note) != 0)
        return;
    if (!out->found)
        out->found = obj_row_start_epoch(row, &out->earliest_epoch);
    state = json_get_str(json_get(row, "state"));
    if (strcmp(state, "landed") == 0 || strcmp(state, "failed") == 0)
        (void)obj_pair_add_new(&out->attempts,
                               json_get_int(json_get(row, "attempt")),
                               json_get_int(json_get(row, "started")));
}

/* Every row whose train identity is `note`, in file order: the earliest
 * row's start (any state), and the count of distinct landed/failed
 * attempts. */
static bool obj_train_stats_for_note(const char *path, const char *note,
                                     struct obj_train_stats *out)
{
    char line[OBJ_LINE_MAX];
    FILE *fp;

    memset(out, 0, sizeof(*out));
    fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp)) {
        struct json_value row;
        json_init(&row);
        if (json_read(&row, line, strlen(line)) && row.type == JSON_OBJ)
            obj_train_stats_row(&row, note, out);
        json_free(&row);
    }
    (void)fclose(fp);
    return true;
}

static void obj_train_stats_free(struct obj_train_stats *stats)
{
    free(stats->attempts.items);
    stats->attempts.items = NULL;
}

static bool obj_resolve_outcomes(const struct zcl_objectives_options *options,
                                 char *buf, size_t cap, const char **out)
{
    const char *use = options && options->outcomes ? options->outcomes : NULL;
    if (use) {
        *out = use;
        return true;
    }
    if (!obj_default_outcomes(buf, cap))
        return false;
    *out = buf;
    return true;
}

/* Both landing_latency_s and landing_attempts_per_train answer about the
 * newest train that finished landing; this pins down which train that is,
 * or names why neither can answer. */
static bool obj_newest_landed_train(
    const struct zcl_objectives_options *options, const char **use_out,
    char *path_buf, size_t path_cap, struct obj_outcomes_stats *stats,
    struct zcl_objective_value *v)
{
    if (!obj_resolve_outcomes(options, path_buf, path_cap, use_out)) {
        obj_set_reason(v, "%s", "state root unavailable");
        return false;
    }
    if (!obj_scan_outcomes(*use_out, stats, v->reason, sizeof(v->reason)))
        return false;
    if (!stats->have_last_landed) {
        obj_set_reason(v, "no landed row in %s", *use_out);
        return false;
    }
    return true;
}

static struct zcl_objective_value obj_landing_latency_s(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct obj_outcomes_stats stats;
    struct obj_train_stats train;
    char path[512];
    const char *use;

    if (!obj_newest_landed_train(options, &use, path, sizeof(path), &stats,
                                 &v))
        return v;
    if (!obj_train_stats_for_note(use, stats.last_landed_note, &train) ||
        !train.found) {
        obj_set_reason(&v, "no rows for the landed train in %s", use);
        obj_train_stats_free(&train);
        return v;
    }
    v.measured = true;
    v.value = stats.last_landed_ts - train.earliest_epoch;
    obj_train_stats_free(&train);
    return v;
}

static struct zcl_objective_value obj_landing_attempts_per_train(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct obj_outcomes_stats stats;
    struct obj_train_stats train;
    char path[512];
    const char *use;

    if (!obj_newest_landed_train(options, &use, path, sizeof(path), &stats,
                                 &v))
        return v;
    if (!obj_train_stats_for_note(use, stats.last_landed_note, &train) ||
        train.attempts.n == 0) {
        obj_set_reason(&v, "no rows for the landed train in %s", use);
        obj_train_stats_free(&train);
        return v;
    }
    v.measured = true;
    v.value = (int64_t)train.attempts.n;
    obj_train_stats_free(&train);
    return v;
}

/* ── phases.txt ───────────────────────────────────────────────────────── */

static bool obj_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* The most recently modified attempt directory under `dir`, or false when
 * none exists. */
static bool obj_newest_attempt(const char *dir, char *out, size_t cap)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    time_t best = 0;
    bool found = false;
    if (!d)
        return false;
    while ((e = readdir(d))) {
        char path[1024];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) <= 0)
            continue;
        if (!obj_is_dir(path) || stat(path, &st) != 0)
            continue;
        if (!found || st.st_mtime > best) {
            best = st.st_mtime;
            found = snprintf(out, cap, "%s", path) > 0;
        }
    }
    (void)closedir(d);
    return found;
}

/* The elapsed_ms value on the "step=<name> ..." line, or -1 when the file
 * has no such line. */
static int64_t obj_phase_elapsed_ms(const char *phases_path, const char *step)
{
    char prefix[64];
    char line[OBJ_LINE_MAX];
    FILE *fp = fopen(phases_path, "r");
    int64_t result = -1;
    if (!fp)
        return -1;
    (void)snprintf(prefix, sizeof(prefix), "step=%s ", step);
    while (fgets(line, sizeof(line), fp)) {
        const char *at;
        if (strncmp(line, prefix, strlen(prefix)) != 0)
            continue;
        at = strstr(line, " elapsed_ms=");
        if (!at)
            continue;
        result = strtoll(at + strlen(" elapsed_ms="), NULL, 10);
        break;
    }
    (void)fclose(fp);
    return result;
}

static struct zcl_objective_value obj_phase_wall_s(
    const struct zcl_objectives_options *options, const char *step)
{
    struct zcl_objective_value v = {0};
    char dirbuf[512], attempt[1024], phases[1088];
    int64_t elapsed_ms;
    const char *dir = options && options->attempts_dir ? options->attempts_dir
                                                        : NULL;
    if (!dir) {
        if (!obj_default_attempts_dir(dirbuf, sizeof(dirbuf))) {
            obj_set_reason(&v, "%s", "state root unavailable");
            return v;
        }
        dir = dirbuf;
    }
    if (!obj_newest_attempt(dir, attempt, sizeof(attempt))) {
        obj_set_reason(&v, "no attempt directories under %s", dir);
        return v;
    }
    if (snprintf(phases, sizeof(phases), "%s/phases.txt", attempt) <= 0) {
        obj_set_reason(&v, "%s", "attempt path too long");
        return v;
    }
    elapsed_ms = obj_phase_elapsed_ms(phases, step);
    if (elapsed_ms < 0) {
        obj_set_reason(&v, "no matching step line in %s", phases);
        return v;
    }
    v.measured = true;
    v.value = (elapsed_ms + 500) / 1000;
    return v;
}

static struct zcl_objective_value obj_proof_lint_wall_s(
    const struct zcl_objectives_options *options)
{
    return obj_phase_wall_s(options, "lint");
}

static struct zcl_objective_value obj_proof_test_wall_s(
    const struct zcl_objectives_options *options)
{
    return obj_phase_wall_s(options, "test");
}

/* ── git log ──────────────────────────────────────────────────────────── */

static int64_t obj_count_nonblank_lines(const char *buf)
{
    int64_t count = 0;
    bool in_line = false;
    for (const char *p = buf; *p; p++) {
        if (*p == '\n') {
            if (in_line)
                count++;
            in_line = false;
        } else if (*p != '\r') {
            in_line = true;
        }
    }
    if (in_line)
        count++;
    return count;
}

static struct zcl_objective_value obj_commits_landed_today(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    const char *repo = options && options->repo ? options->repo : ".";
    const char *argv[] = {"git",  "-C",     repo,   "log", "--since=midnight",
                          "--pretty=oneline", "HEAD", NULL};
    char out[65536];
    int rc = zcl_spawn_capture(argv, out, sizeof(out), 5000);
    if (rc != 0) {
        obj_set_reason(&v, "git log failed in %s", repo);
        return v;
    }
    v.measured = true;
    v.value = obj_count_nonblank_lines(out);
    return v;
}

/* ── lintc line ceiling ───────────────────────────────────────────────── */

static bool obj_ends_with(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

static int64_t obj_file_line_count(const char *path)
{
    FILE *fp = fopen(path, "r");
    int64_t lines = 0;
    int c, last = '\n';
    if (!fp)
        return -1;
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n')
            lines++;
        last = c;
    }
    if (last != '\n' && lines >= 0)
        lines++; /* count a final unterminated line */
    (void)fclose(fp);
    return lines;
}

static struct zcl_objective_value obj_lint_families_over_ceiling(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    const char *dir = options && options->lintc_dir ? options->lintc_dir
                                                     : "tools/lint/lintc";
    DIR *d = opendir(dir);
    struct dirent *e;
    int64_t over = 0;
    if (!d) {
        obj_set_reason(&v, "cannot open %s", dir);
        return v;
    }
    while ((e = readdir(d))) {
        char path[1024];
        int64_t lines;
        if (!obj_ends_with(e->d_name, ".c"))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) <= 0)
            continue;
        lines = obj_file_line_count(path);
        if (lines > OBJ_LINT_CEILING_LINES)
            over++;
    }
    (void)closedir(d);
    v.measured = true;
    v.value = over;
    return v;
}

/* ── cyclomatic complexity baseline ──────────────────────────────────── */

static struct zcl_objective_value obj_functions_over_complexity_cap(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    const char *path = options && options->baseline
                          ? options->baseline
                          : "tools/lint/cyclomatic_complexity_baseline.txt";
    int64_t lines = obj_file_line_count(path);
    if (lines < 0) {
        obj_set_reason(&v, "no baseline file at %s", path);
        return v;
    }
    v.measured = true;
    v.value = lines;
    return v;
}

/* ── not producible from this tree today ─────────────────────────────── */

static struct zcl_objective_value obj_fresh_node_sync_eta_s(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    (void)options;
    obj_set_reason(&v, "%s", "producer is a future leaf");
    return v;
}

static struct zcl_objective_value obj_tokens_per_landed_commit(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    (void)options;
    obj_set_reason(&v, "%s", "producer is the experiment ledger");
    return v;
}

/* ── dispatch ─────────────────────────────────────────────────────────── */

struct obj_producer {
    const char *id;
    struct zcl_objective_value (*fn)(const struct zcl_objectives_options *);
};

static const struct obj_producer k_producers[] = {
    {"landing_latency_s", obj_landing_latency_s},
    {"landing_attempts_per_train", obj_landing_attempts_per_train},
    {"proof_lint_wall_s", obj_proof_lint_wall_s},
    {"proof_test_wall_s", obj_proof_test_wall_s},
    {"commits_landed_today", obj_commits_landed_today},
    {"lint_families_over_ceiling", obj_lint_families_over_ceiling},
    {"functions_over_complexity_cap", obj_functions_over_complexity_cap},
    {"fresh_node_sync_eta_s", obj_fresh_node_sync_eta_s},
    {"tokens_per_landed_commit", obj_tokens_per_landed_commit},
};

struct zcl_objective_value zcl_objectives_measure(
    const struct zcl_objectives_options *options, const char *id)
{
    struct zcl_objective_value v = {0};
    size_t n = sizeof(k_producers) / sizeof(k_producers[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(k_producers[i].id, id) == 0)
            return k_producers[i].fn(options);
    }
    obj_set_reason(&v, "no producer wired for id %s", id);
    return v;
}
