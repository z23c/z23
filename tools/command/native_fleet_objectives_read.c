/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The producers behind `fleet.objectives` — small static readers
 *          of outcomes.jsonl, a completed proof attempt's phases.txt and
 *          lint and test logs, `git log origin/main`
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
#include "platform/time_compat.h"
#include "util/spawn.h"
#include "util/path_util.h"

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
    int64_t last_landed_at; /* the row's landed_at, 0 when it has none */

    char last_landed_note[OBJ_NOTE_MAX];
};

/* The landing instant the outcome writer stamps (unix seconds), 0 for a row
 * written before that field existed. The row's `ts` is the SUBMIT time (the
 * land queue stamps it once at enqueue) and `started` is when its proof began,
 * so neither says when the train landed. */
static int64_t obj_row_landed_at(const struct json_value *row)
{
    const struct json_value *v = json_get(row, "landed_at");
    return v && v->type == JSON_INT && json_get_int(v) > 0 ? json_get_int(v) : 0;
}

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
    stats->last_landed_at = obj_row_landed_at(row);
    obj_row_group_key(row, stats->last_landed_note,
                      sizeof(stats->last_landed_note));
}

/* 1: complete record (including final EOF record), 0: EOF, -1: unavailable. */
static int obj_ledger_line(FILE *fp, char *line, size_t cap, size_t *len)
{
    *len = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        if (ch == 0 || *len == cap - 1)
            return -1;
        line[(*len)++] = (char)ch;
        if (ch == '\n')
            break;
    }
    line[*len] = 0;
    if (ferror(fp))
        return -1;
    return *len ? 1 : 0;
}

/* Track the newest landed train only after verifying the whole ledger. */
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
    size_t len;
    int status;
    while ((status = obj_ledger_line(fp, line, sizeof line, &len)) == 1) {
        struct json_value row;
        json_init(&row);
        bool valid = json_read(&row, line, len) && row.type == JSON_OBJ;
        if (valid)
            obj_outcomes_row(&row, out);
        json_free(&row);
        if (!valid) { status = -1; break; }
    }
    if (fclose(fp) != 0 || status < 0) {
        memset(out, 0, sizeof *out);
        (void)snprintf(reason, reason_cap, "incomplete outcomes file %s", path);
        return false;
    }
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
    bool invalid_start;
    int64_t earliest_epoch; /* the earliest row's `ts`: its submit time */
    struct obj_pair_set attempts; /* distinct (attempt, started) landed/failed */
};

/* The row's submit time: `ts`, stamped once at enqueue. A row whose `ts`
 * is absent or unparseable makes the train unmeasured. */
static bool obj_row_start_epoch(const struct json_value *row, int64_t *out)
{
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
    if (!out->found && !out->invalid_start) {
        out->found = obj_row_start_epoch(row, &out->earliest_epoch);
        out->invalid_start = !out->found;
    }
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
    size_t len;
    int status;
    while ((status = obj_ledger_line(fp, line, sizeof line, &len)) == 1) {
        struct json_value row;
        json_init(&row);
        bool valid = json_read(&row, line, len) && row.type == JSON_OBJ;
        if (valid)
            obj_train_stats_row(&row, note, out);
        json_free(&row);
        if (!valid) { status = -1; break; }
    }
    bool closed = fclose(fp) == 0;
    return closed && status == 0;
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
        obj_set_reason(&v, "unavailable rows for the landed train in %s", use);
        obj_train_stats_free(&train);
        return v;
    }
    if (stats.last_landed_at <= 0) {
        obj_set_reason(&v, "newest landed row in %s has no landed_at (written "
                       "before the field existed)", use);
        obj_train_stats_free(&train);
        return v;
    }
    if (train.earliest_epoch < 0 ||
        stats.last_landed_at < train.earliest_epoch) {
        obj_set_reason(&v, "invalid landing chronology in %s", use);
        obj_train_stats_free(&train);
        return v;
    }
    v.measured = true;
    v.value = stats.last_landed_at - train.earliest_epoch;
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
        obj_set_reason(&v, "unavailable rows for the landed train in %s", use);
        obj_train_stats_free(&train);
        return v;
    }
    v.measured = true;
    v.value = (int64_t)train.attempts.n;
    obj_train_stats_free(&train);
    return v;
}

static bool obj_ends_with(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

/* ── the newest completed proof attempt ───────────────────────────────── */

/* Where the proof numbers live, read-only, written by tools/dev/dev_proof.c
 * and tools/lint/run_lint.sh into <attempt>/logs/:
 *
 *   phases.txt     "zcl.dev_proof_phase.v1 <phase> <ms> ms (cumulative <ms> ms)",
 *                  one row per finished phase. The dimension_lint_and_test
 *                  row is written when lint and test are both done (a later
 *                  phase, docs_fresh_join, follows it), so its presence marks
 *                  a COMPLETED attempt (an in-flight one is skipped) and its
 *                  cumulative is the proof wall through lint and test.
 *   *.lint.log     "-- lint timing: N gates, wall W ms, jobs J --" (the
 *                  rule is U+2500 dashes), run_lint.sh's own wall.
 *   *.test.log     "ALL TESTS PASSED ... (S.Ss wall, N workers)" or
 *                  "SOME TESTS FAILED ...", test_parallel's suite wall.
 *
 * Lint and test run CONCURRENTLY inside the single dimension_lint_and_test
 * phase, so no phase row can split them, and the attempt's phases.txt
 * "step=test" row spans the whole dimension, lint included. Each wall is
 * therefore taken from the log of the tool that ran it: proof_lint_wall_s
 * from the lint log, proof_test_wall_s from the test log, proof_wall_s from
 * the final cumulative. */
#define OBJ_DIMENSION_PHASE "zcl.dev_proof_phase.v1 dimension_lint_and_test "

/* Calls fn for each line, once, from its first OBJ_LINE_MAX bytes; the rest
 * of an over-long line is skipped. False when the file cannot be read. */
static bool obj_log_lines(const char *path,
                          void (*fn)(const char *line, void *user),
                          void *user)
{
    char line[OBJ_LINE_MAX];
    bool at_start = true;
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp)) {
        size_t n = strlen(line);
        if (at_start)
            fn(line, user);
        at_start = n > 0 && line[n - 1] == '\n';
    }
    bool ok = !ferror(fp);
    (void)fclose(fp);
    return ok;
}

static void obj_dimension_line(const char *line, void *user)
{
    const char *at;
    char *end;
    long long ms;
    if (strncmp(line, OBJ_DIMENSION_PHASE, strlen(OBJ_DIMENSION_PHASE)) != 0)
        return;
    at = strstr(line, "(cumulative");
    if (!at)
        return;
    at += strlen("(cumulative");
    ms = strtoll(at, &end, 10);
    if (end != at && ms >= 0)
        *(int64_t *)user = ms;
}

static void obj_lint_wall_line(const char *line, void *user)
{
    const char *at = strstr(line, "lint timing:");
    char *end;
    long long ms;
    if (!at || !(at = strstr(at, ", wall ")))
        return;
    at += strlen(", wall ");
    ms = strtoll(at, &end, 10);
    if (end != at && ms >= 0)
        *(int64_t *)user = ms;
}

static void obj_test_wall_line(const char *line, void *user)
{
    const char *at;
    char *end;
    double s;
    /* A cached pass replayed stored results; its time is not a suite wall. */
    if (strncmp(line, "ALL TESTS PASSED (CACHED)", 25) == 0)
        return;
    if (strncmp(line, "ALL TESTS PASSED", 16) != 0 &&
        strncmp(line, "SOME TESTS FAILED", 17) != 0)
        return;
    at = strstr(line, "s wall,");
    if (!at)
        return;
    while (at > line && ((at[-1] >= '0' && at[-1] <= '9') || at[-1] == '.'))
        at--;
    s = strtod(at, &end);
    if (end != at && s >= 0.0 && s < 1e9)
        *(int64_t *)user = (int64_t)(s * 1000.0 + 0.5);
}

/* One completed attempt directory, <local>-<base>.<random>: the proof's pair
 * key (dev_proof.c) plus mkdtemp's random suffix, which carries no order. */
struct obj_attempt {
    char logs[1100];
    char key[200];     /* "<local>-<base>", the producer's pair key */
    int64_t proof_ms;
    int64_t recorded;  /* newest started/landed_at of the pair's outcome rows,
                        * 0 when the ledger has no row for the pair */
    time_t mtime;      /* phases.txt mtime, the last-resort order only */
};

struct obj_proof {
    char logs[1100];
    char key[200];
    int64_t proof_ms;
};

struct obj_attempts {
    struct obj_attempt *items;
    size_t n;
    size_t cap;
};

/* The pair key out of an attempt directory name: everything before the last
 * dot, or the whole name when it has none. */
static bool obj_attempt_key(const char *name, char *out, size_t cap)
{
    const char *dot = strrchr(name, '.');
    size_t n = dot && dot != name ? (size_t)(dot - name) : strlen(name);
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, name, n);
    out[n] = '\0';
    return true;
}

static bool obj_attempts_add(struct obj_attempts *set,
                             const struct obj_attempt *a)
{
    if (set->n == set->cap) {
        size_t cap = set->cap ? set->cap * 2 : 16;
        struct obj_attempt *items = realloc(set->items, cap * sizeof(*items));
        if (!items)
            return false;
        set->items = items;
        set->cap = cap;
    }
    set->items[set->n++] = *a;
    return true;
}

/* Folds the outcome ledger into the candidates: each outcome row names its
 * tip pair (local, base), and the proof's attempt directory is named for the
 * same pair, so the newest started/landed_at of a pair's rows is the time
 * that attempt was recorded. A missing or unreadable ledger leaves every
 * candidate unrecorded. */
static void obj_attempts_record(struct obj_attempts *set, const char *outcomes)
{
    char line[OBJ_LINE_MAX];
    FILE *fp = outcomes ? fopen(outcomes, "r") : NULL;
    size_t len;
    if (!fp)
        return;
    while (obj_ledger_line(fp, line, sizeof line, &len) == 1) {
        struct json_value row;
        json_init(&row);
        if (json_read(&row, line, len) && row.type == JSON_OBJ) {
            char pair[200];
            const char *local = json_get_str(json_get(&row, "local"));
            const char *base = json_get_str(json_get(&row, "base"));
            int64_t at = json_get_int(json_get(&row, "started"));
            int64_t landed = obj_row_landed_at(&row);
            if (landed > at)
                at = landed;
            if (local[0] && base[0] && at > 0 &&
                snprintf(pair, sizeof(pair), "%s-%s", local, base) <
                    (int)sizeof(pair)) {
                for (size_t i = 0; i < set->n; i++)
                    if (strcmp(set->items[i].key, pair) == 0 &&
                        at > set->items[i].recorded)
                        set->items[i].recorded = at;
            }
        }
        json_free(&row);
    }
    (void)fclose(fp);
}

/* True when a ranks after b. phases.txt carries no wall-clock stamp (its rows
 * are durations from a monotonic clock) and the directory name's random
 * suffix carries no order, so the order is the attempt's recorded time: the
 * newest started/landed_at of its pair's outcome rows. An attempt with a
 * recorded time outranks one without. The phases.txt mtime is the LAST
 * fallback only, for attempts the ledger never saw or ties; anything that
 * rewrites the file can touch it, so it never overrides a recorded key. */
static bool obj_attempt_newer(const struct obj_attempt *a,
                              const struct obj_attempt *b)
{
    if (a->recorded != b->recorded)
        return a->recorded > b->recorded;
    if (a->mtime != b->mtime)
        return a->mtime > b->mtime;
    return strcmp(a->logs, b->logs) > 0;
}

/* The newest completed attempt, or false. */
static bool obj_newest_completed_attempt(const char *dir,
                                         const char *outcomes,
                                         struct obj_proof *out)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    struct obj_attempts set = {0};
    size_t best = 0;
    if (!d)
        return false;
    while ((e = readdir(d))) {
        struct obj_attempt a = {0};
        char phases[1200];
        struct stat st;
        int64_t ms = -1;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (!obj_attempt_key(e->d_name, a.key, sizeof(a.key)) ||
            snprintf(a.logs, sizeof(a.logs), "%s/%s/logs", dir, e->d_name) >=
                (int)sizeof(a.logs) ||
            snprintf(phases, sizeof(phases), "%s/phases.txt", a.logs) >=
                (int)sizeof(phases))
            continue;
        if (stat(phases, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (!obj_log_lines(phases, obj_dimension_line, &ms) || ms < 0)
            continue;
        a.proof_ms = ms;
        a.mtime = st.st_mtime;
        if (!obj_attempts_add(&set, &a))
            break;
    }
    (void)closedir(d);
    if (set.n == 0) {
        free(set.items);
        return false;
    }
    obj_attempts_record(&set, outcomes);
    for (size_t i = 1; i < set.n; i++)
        if (obj_attempt_newer(&set.items[i], &set.items[best]))
            best = i;
    memcpy(out->logs, set.items[best].logs, sizeof(out->logs));
    memcpy(out->key, set.items[best].key, sizeof(out->key));
    out->proof_ms = set.items[best].proof_ms;
    free(set.items);
    return true;
}

/* The wall of one log kind (".lint.log" / ".test.log") in an attempt. The
 * producer names it exactly "<key><suffix>" (dev_proof.c writes
 * "<logs>/<pair key>.<dimension>.log"), so that file is read first. A
 * directory that does not follow that name is scanned for every file with the
 * suffix, and the one that carries the wall line wins, the smallest name
 * first, so readdir order never decides. */
static bool obj_log_wall(const struct obj_proof *proof, const char *suffix,
                         void (*fn)(const char *line, void *user),
                         char *path, size_t cap, int64_t *ms)
{
    DIR *d;
    struct dirent *e;
    char best[256] = "";
    int64_t found = -1;
    *ms = -1;
    if (snprintf(path, cap, "%s/%s%s", proof->logs, proof->key, suffix) <
            (int)cap &&
        obj_log_lines(path, fn, ms) && *ms >= 0)
        return true;
    d = opendir(proof->logs);
    if (!d)
        return false;
    while ((e = readdir(d))) {
        char cand[1400];
        int64_t v = -1;
        if (!obj_ends_with(e->d_name, suffix) ||
            strlen(e->d_name) >= sizeof(best) ||
            snprintf(cand, sizeof(cand), "%s/%s", proof->logs, e->d_name) >=
                (int)sizeof(cand) ||
            !obj_log_lines(cand, fn, &v) || v < 0)
            continue;
        if (best[0] == '\0' || strcmp(e->d_name, best) < 0) {
            (void)snprintf(best, sizeof(best), "%s", e->d_name);
            found = v;
        }
    }
    (void)closedir(d);
    if (best[0] == '\0' ||
        snprintf(path, cap, "%s/%s", proof->logs, best) >= (int)cap)
        return false;
    *ms = found;
    return true;
}

static bool obj_completed_attempt(const struct zcl_objectives_options *options,
                                  struct obj_proof *proof,
                                  struct zcl_objective_value *v)
{
    char dirbuf[512], outbuf[512];
    const char *outcomes = NULL;
    const char *dir = options && options->attempts_dir ? options->attempts_dir
                                                        : NULL;
    if (!dir) {
        if (!obj_default_attempts_dir(dirbuf, sizeof(dirbuf))) {
            obj_set_reason(v, "%s", "state root unavailable");
            return false;
        }
        dir = dirbuf;
    }
    if (!obj_resolve_outcomes(options, outbuf, sizeof(outbuf), &outcomes))
        outcomes = NULL;
    if (!obj_newest_completed_attempt(dir, outcomes, proof)) {
        obj_set_reason(v, "no completed proof attempt under %s", dir);
        return false;
    }
    return true;
}

static struct zcl_objective_value obj_log_wall_s(
    const struct zcl_objectives_options *options, const char *suffix,
    void (*fn)(const char *line, void *user))
{
    struct zcl_objective_value v = {0};
    struct obj_proof proof;
    char log[1300];
    int64_t ms = -1;
    if (!obj_completed_attempt(options, &proof, &v))
        return v;
    if (!obj_log_wall(&proof, suffix, fn, log, sizeof(log), &ms)) {
        obj_set_reason(&v, "no wall line in any *%s of the newest completed "
                           "attempt", suffix);
        return v;
    }
    v.measured = true;
    v.value = (ms + 500) / 1000;
    return v;
}

static struct zcl_objective_value obj_proof_lint_wall_s(
    const struct zcl_objectives_options *options)
{
    return obj_log_wall_s(options, ".lint.log", obj_lint_wall_line);
}

static struct zcl_objective_value obj_proof_test_wall_s(
    const struct zcl_objectives_options *options)
{
    return obj_log_wall_s(options, ".test.log", obj_test_wall_line);
}

static struct zcl_objective_value obj_proof_wall_s(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct obj_proof proof;
    if (!obj_completed_attempt(options, &proof, &v))
        return v;
    v.measured = true;
    v.value = (proof.proof_ms + 500) / 1000;
    return v;
}

/* ── outcomes.jsonl windows ───────────────────────────────────────────── */

#define OBJ_DAY_S 86400
#define OBJ_HISTORY_DAYS_RATE 7
#define OBJ_HISTORY_DAYS_PRODUCT 7
#define OBJ_HISTORY_DAYS_CHURN 10

static int64_t obj_now(const struct zcl_objectives_options *options)
{
    return options && options->now > 0 ? options->now : platform_time_wall_unix();
}

static int64_t obj_utc_midnight(int64_t t)
{
    int64_t rem = t % OBJ_DAY_S;
    return t - (rem < 0 ? rem + OBJ_DAY_S : rem);
}

/* When an outcome row happened: landed_at when the writer stamped one, else
 * its ts (the submit time, the best a row from before landed_at can give). */
static bool obj_row_when(const struct json_value *row, int64_t *out)
{
    int64_t at = obj_row_landed_at(row);
    if (at > 0) {
        *out = at;
        return true;
    }
    return obj_parse_iso8601(json_get_str(json_get(row, "ts")), out);
}

struct obj_window {
    int64_t today_start;
    int64_t week_start;
    int64_t landed_today;
    int64_t landed_week;
    int64_t failed_week;
};

static void obj_window_row(const struct json_value *row, void *user)
{
    struct obj_window *w = user;
    const char *state = json_get_str(json_get(row, "state"));
    bool landed = strcmp(state, "landed") == 0;
    int64_t when;
    if ((!landed && strcmp(state, "failed") != 0) || !obj_row_when(row, &when))
        return;
    if (when >= w->week_start) {
        if (landed)
            w->landed_week++;
        else
            w->failed_week++;
    }
    if (landed && when >= w->today_start)
        w->landed_today++;
}

static bool obj_outcomes_window(const struct zcl_objectives_options *options,
                                struct obj_window *w,
                                struct zcl_objective_value *v)
{
    char path[512];
    const char *use;
    int64_t now = obj_now(options);
    memset(w, 0, sizeof(*w));
    w->today_start = obj_utc_midnight(now);
    w->week_start = now - (int64_t)OBJ_HISTORY_DAYS_RATE * OBJ_DAY_S;
    if (!obj_resolve_outcomes(options, path, sizeof(path), &use)) {
        obj_set_reason(v, "%s", "state root unavailable");
        return false;
    }
    return zcl_objectives_ledger_walk(use, obj_window_row, w, v->reason,
                                      sizeof(v->reason));
}

static struct zcl_objective_value obj_landed_rows_today(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct obj_window w;
    if (!obj_outcomes_window(options, &w, &v))
        return v;
    v.measured = true;
    v.value = w.landed_today;
    return v;
}

static struct zcl_objective_value obj_land_success_rate_7d(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct obj_window w;
    int64_t total;
    if (!obj_outcomes_window(options, &w, &v))
        return v;
    total = w.landed_week + w.failed_week;
    if (total == 0) {
        obj_set_reason(&v, "%s", "no landed or failed outcome in 7 days");
        return v;
    }
    v.measured = true;
    v.value = (w.landed_week * 100 + total / 2) / total;
    return v;
}

/* ── git log ──────────────────────────────────────────────────────────── */

/* The repo's origin/main, never fetched; HEAD only when it is absent. */
static const char *obj_git_main_ref(const char *repo)
{
    const char *argv[] = {"git", "-C", repo, "rev-parse", "--verify",
                          "--quiet", "refs/remotes/origin/main", NULL};
    char out[256];
    return zcl_spawn_capture(argv, out, sizeof(out), 5000) == 0
               ? "refs/remotes/origin/main"
               : "HEAD";
}

#define OBJ_GIT_OUT_MAX 65536u
#define OBJ_GIT_PATHS_MAX 8u

/* Commits reachable from the main ref with a committer time at or after
 * `since`, limited to `paths` when any. One %ct per commit keeps the output
 * small; the count is a bounded read, and a full buffer is a failure rather
 * than a short count. */
static bool obj_git_count_since(const char *repo, int64_t since,
                                const char *const *paths, size_t npaths,
                                int64_t *count)
{
    const char *argv[8 + OBJ_GIT_PATHS_MAX + 2];
    char since_arg[48];
    char *out = zcl_malloc(OBJ_GIT_OUT_MAX, "fleet_objectives_git");
    size_t n = 0;
    int64_t seen = 0;
    bool ok;
    if (!out || npaths > OBJ_GIT_PATHS_MAX ||
        snprintf(since_arg, sizeof(since_arg), "--since=%lld",
                 (long long)since) >= (int)sizeof(since_arg)) {
        free(out);
        return false;
    }
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = repo;
    argv[n++] = "log";
    argv[n++] = "--format=%ct";
    argv[n++] = since_arg;
    argv[n++] = obj_git_main_ref(repo);
    if (npaths) {
        argv[n++] = "--";
        for (size_t i = 0; i < npaths; i++)
            argv[n++] = paths[i];
    }
    argv[n] = NULL;
    ok = zcl_spawn_capture(argv, out, OBJ_GIT_OUT_MAX, 5000) == 0 &&
         strlen(out) < OBJ_GIT_OUT_MAX - 1u;
    for (const char *p = out; ok && *p;) {
        char *end;
        long long ct = strtoll(p, &end, 10);
        if (end != p && ct >= since)
            seen++;
        p = strchr(end, '\n');
        p = p ? p + 1 : end + strlen(end);
    }
    free(out);
    *count = seen;
    return ok;
}

static struct zcl_objective_value obj_git_window(
    const struct zcl_objectives_options *options, int64_t since,
    const char *const *paths, size_t npaths, int64_t *count)
{
    struct zcl_objective_value v = {0};
    const char *repo = options && options->repo ? options->repo : ".";
    if (!obj_git_count_since(repo, since, paths, npaths, count))
        obj_set_reason(&v, "git log failed in %s", repo);
    else
        v.measured = true;
    return v;
}

static struct zcl_objective_value obj_commits_landed_today(
    const struct zcl_objectives_options *options)
{
    int64_t count = 0;
    struct zcl_objective_value v = obj_git_window(
        options, obj_utc_midnight(obj_now(options)), NULL, 0, &count);
    v.value = count;
    return v;
}

static const char *const k_product_paths[] = {"core/", "engine/", "contexts/",
                                              "apps/", "platform/"};
static const char *const k_generated_paths[] = {
    "docs/CAPABILITY_INVENTORY.jsonl", "docs/API_REFERENCE.md"};

/* Share, in percent, of the window's commits that touch a product path. */
static struct zcl_objective_value obj_product_commit_share_7d(
    const struct zcl_objectives_options *options)
{
    int64_t since = obj_now(options) - (int64_t)OBJ_HISTORY_DAYS_PRODUCT * OBJ_DAY_S;
    int64_t total = 0, product = 0;
    struct zcl_objective_value v = obj_git_window(options, since, NULL, 0, &total);
    if (!v.measured)
        return v;
    v = obj_git_window(options, since, k_product_paths,
                       sizeof(k_product_paths) / sizeof(k_product_paths[0]),
                       &product);
    if (!v.measured)
        return v;
    if (total == 0) {
        obj_set_reason(&v, "%s", "no origin/main commit in 7 days");
        return v;
    }
    v.value = (product * 100 + total / 2) / total;
    return v;
}

static struct zcl_objective_value obj_generated_churn_10d(
    const struct zcl_objectives_options *options)
{
    int64_t count = 0;
    struct zcl_objective_value v = obj_git_window(
        options, obj_now(options) - (int64_t)OBJ_HISTORY_DAYS_CHURN * OBJ_DAY_S,
        k_generated_paths,
        sizeof(k_generated_paths) / sizeof(k_generated_paths[0]), &count);
    v.value = count;
    return v;
}

/* ── lintc line ceiling ───────────────────────────────────────────────── */

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
    if (ferror(fp))
        lines = -1;
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
        if (lines < 0) {
            obj_set_reason(&v, "cannot read lint family %s", path);
            (void)closedir(d);
            return v;
        }
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
    {"proof_wall_s", obj_proof_wall_s},
    {"commits_landed_today", obj_commits_landed_today},
    {"lint_families_over_ceiling", obj_lint_families_over_ceiling},
    {"functions_over_complexity_cap", obj_functions_over_complexity_cap},
    {"fresh_node_sync_eta_s", obj_fresh_node_sync_eta_s},
    {"tokens_per_landed_commit", obj_tokens_per_landed_commit},
    {"landed_rows_today", obj_landed_rows_today},
    {"land_success_rate_7d", obj_land_success_rate_7d},
    {"product_commit_share_7d", obj_product_commit_share_7d},
    {"generated_churn_10d", obj_generated_churn_10d},
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

/* ── shared with fleet.goals ──────────────────────────────────────────── */

bool zcl_objectives_parse_iso8601(const char *s, int64_t *out)
{
    return obj_parse_iso8601(s, out);
}

bool zcl_objectives_outcomes_path(const struct zcl_objectives_options *options,
                                  char *buf, size_t cap, const char **out)
{
    return obj_resolve_outcomes(options, buf, cap, out);
}

bool zcl_objectives_ledger_walk(const char *path,
                                void (*row)(const struct json_value *, void *),
                                void *user, char *reason, size_t reason_cap)
{
    char line[OBJ_LINE_MAX];
    size_t len;
    int status;
    FILE *fp = fopen(path, "r");
    if (!fp) {
        (void)snprintf(reason, reason_cap, "missing ledger %s", path);
        return false;
    }
    while ((status = obj_ledger_line(fp, line, sizeof line, &len)) == 1) {
        struct json_value value;
        json_init(&value);
        bool valid = json_read(&value, line, len) && value.type == JSON_OBJ;
        if (valid)
            row(&value, user);
        json_free(&value);
        if (!valid)
            status = -1;
        if (status < 0)
            break;
    }
    if (fclose(fp) != 0 || status < 0) {
        (void)snprintf(reason, reason_cap, "incomplete ledger %s", path);
        return false;
    }
    return true;
}
