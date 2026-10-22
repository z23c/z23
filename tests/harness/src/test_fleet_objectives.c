/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.objectives
 * (tools/command/native_fleet_objectives*.c).
 *
 * Every path a producer reads is overridable, so the whole leaf runs against
 * fixtures built here. Nothing asserts a clock-dependent
 * value: the day and window readers take their clock from options.now, and
 * the git readers run over a throwaway repo whose commits carry dated
 * GIT_COMMITTER_DATE values.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet_objectives.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>

#define FOX_PATH "fleet.objectives"

/* ── fixture helpers ─────────────────────────────────────────────────── */

static bool fox_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool fox_mkdir(const char *path) { return mkdir(path, 0700) == 0; }

/* One catalog row's line count of 'X' repeated, terminated, to push a lintc
 * fixture file over or under the 1500-line ceiling without a real source
 * file. */
static bool fox_write_n_lines(const char *path, int64_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    for (int64_t i = 0; i < n; i++) {
        if (fputs("x\n", f) < 0) {
            (void)fclose(f);
            return false;
        }
    }
    return fclose(f) == 0;
}

static bool fox_set_mtime(const char *path, long sec)
{
    struct timeval tv[2] = {{sec, 0}, {sec, 0}};
    return utimes(path, tv) == 0;
}

/* One proof attempt in the layout the proof writes it: <dir>/<name>/logs/
 * holding phases.txt, <key>.lint.log and <key>.test.log, where the attempt
 * directory is named <key>.<random> exactly as the proof names it. An in-flight
 * attempt has no dimension_lint_and_test row. The lint and test logs carry
 * decoy lines (the budget NOTE, an indented child suite line) that a reader
 * must not mistake for the wall lines. */
static bool fox_attempt(const char *dir, const char *name, bool complete,
                        long long cumulative_ms, long long lint_ms,
                        const char *test_wall_s, long mtime)
{
    char path[1400], logs[1200], attempt[1100], text[4096];
    size_t n;
    char key[200];
    const char *dot = strrchr(name, '.');
    (void)snprintf(key, sizeof(key), "%.*s", dot ? (int)(dot - name) : (int)strlen(name), name);
    (void)snprintf(attempt, sizeof(attempt), "%s/%s", dir, name);
    (void)snprintf(logs, sizeof(logs), "%s/logs", attempt);
    if (!fox_mkdir(attempt) || !fox_mkdir(logs))
        return false;
    n = (size_t)snprintf(
        text, sizeof(text),
        "zcl.dev_proof_phase.v1 worktree_exact_root               167 ms  "
        "(cumulative      167 ms)\n"
        "zcl.dev_proof_phase.v1 prefork_inputs_and_build       202395 ms  "
        "(cumulative   972798 ms)\n");
    if (complete)
        (void)snprintf(text + n, sizeof(text) - n,
                       "zcl.dev_proof_phase.v1 dimension_lint_and_test "
                       "%10lld ms  (cumulative %10lld ms)\n",
                       cumulative_ms - 972798, cumulative_ms);
    (void)snprintf(path, sizeof(path), "%s/phases.txt", logs);
    if (!fox_write(path, text) || !fox_set_mtime(path, mtime))
        return false;
    (void)snprintf(text, sizeof(text),
        "make[1]: warning: jobserver unavailable: using -j1.\n"
        "PASS check-toolchain                               1607 ms\n"
        "\xe2\x94\x80\xe2\x94\x80 lint timing: 222 gates, wall %lld ms, jobs 21 "
        "\xe2\x94\x80\xe2\x94\x80\n"
        "run_lint.sh: NOTE \xe2\x80\x94 wall 539041 ms exceeds the 75s soft "
        "budget\n", lint_ms);
    (void)snprintf(path, sizeof(path), "%s/%s.lint.log", logs, key);
    if (!fox_write(path, text))
        return false;
    (void)snprintf(text, sizeof(text),
        "    image child: ALL TESTS PASSED \xe2\x80\x94 0/1 groups failed, 0 "
        "skipped (97.9s wall, 1 workers)\n"
        "ALL TESTS PASSED \xe2\x80\x94 0/1359 groups failed, 0 skipped "
        "(%ss wall, 28 workers) [--exact filtered]\n"
        "    image child: ALL TESTS PASSED \xe2\x80\x94 0/1 groups failed, 0 "
        "skipped (5.7s wall, 1 workers)\n", test_wall_s);
    (void)snprintf(path, sizeof(path), "%s/%s.test.log", logs, key);
    return fox_write(path, text);
}

/* ── a throwaway git repo with dated commits ───────────────────────── */

static int fox_git(const char *repo, const char *a, const char *b,
                   const char *c, const char *d)
{
    const char *argv[] = {"git", "-C", repo, "-c", "user.name=fixture",
                          "-c", "user.email=fixture@example.invalid",
                          "-c", "commit.gpgsign=false", a, b, c, d, NULL};
    char out[4096];
    return zcl_spawn_capture(argv, out, sizeof(out), 20000);
}

/* Writes `rel` with a fresh body and commits it at unix time `when`. */
static bool fox_commit(const char *repo, const char *rel, long long when,
                       int serial)
{
    char path[1200], body[32], date[64];
    bool ok;
    (void)snprintf(path, sizeof(path), "%s/%s", repo, rel);
    (void)snprintf(body, sizeof(body), "%d\n", serial);
    (void)snprintf(date, sizeof(date), "%lld +0000", when);
    if (!fox_write(path, body))
        return false;
    (void)setenv("GIT_AUTHOR_DATE", date, 1);
    (void)setenv("GIT_COMMITTER_DATE", date, 1);
    ok = fox_git(repo, "add", rel, NULL, NULL) == 0 &&
         fox_git(repo, "commit", "-q", "-m", "fixture") == 0;
    (void)unsetenv("GIT_AUTHOR_DATE");
    (void)unsetenv("GIT_COMMITTER_DATE");
    return ok;
}


/* ── one in-process invocation ──────────────────────────────────────── */

struct fox_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void fox_begin(struct fox_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), FOX_PATH, NULL);
    zcl_command_reply_init(&c->reply, ZCL_OBJECTIVES_SCHEMA);
}

static void fox_set(struct fox_call *c, const char *key, const char *value)
{
    if (value)
        (void)json_push_kv_str(&c->input, key, value);
}

static bool fox_run(struct fox_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_objectives(&c->request, &c->reply);
    return true;
}

static void fox_end(struct fox_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const struct json_value *fox_row(const struct fox_call *c,
                                        const char *id)
{
    const struct json_value *rows = json_get(&c->reply.data, "objectives");
    if (!rows || rows->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        const char *rid = json_get_str(json_get(row, "id"));
        if (rid && strcmp(rid, id) == 0)
            return row;
    }
    return NULL;
}

static const char *fox_row_str(const struct json_value *row, const char *key)
{
    const char *s = json_get_str(json_get(row, key));
    return s ? s : "";
}

static int64_t fox_row_int(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static int64_t fox_count_lines(const char *text)
{
    int64_t n = 0;
    for (const char *p = text; *p; p++)
        if (*p == '\n')
            n++;
    return n;
}

/* ── the fixture tree ───────────────────────────────────────────────── */

static int fox_line_read_error(void)
{
    int failures = 0;
    char root[512], path[600];
    struct zcl_objectives_options options = {0};
    struct zcl_objective_value value;
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "read_error");
    (void)snprintf(path, sizeof(path), "%s/unreadable.c", root);
    options.lintc_dir = root;
    options.baseline = path;
    TEST("objectives: a line-count read error is unmeasured") {
        ASSERT(fox_mkdir(path)); /* fgetc on a directory fails, not clean EOF. */
        value = zcl_objectives_measure(&options, "lint_families_over_ceiling");
        ASSERT(!value.measured);
        ASSERT(strstr(value.reason, path) != NULL);
        value = zcl_objectives_measure(&options, "functions_over_complexity_cap");
        ASSERT(!value.measured);
        ASSERT(value.reason[0] != '\0');
        ASSERT_EQ(rmdir(path), 0);
        ASSERT(fox_write(path, "x\nx"));
        value = zcl_objectives_measure(&options, "functions_over_complexity_cap");
        ASSERT(value.measured);
        ASSERT_EQ(value.value, 2);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int fox_case_ledger_extent(void)
{
    int failures = 0;
    char root[512], path[1024], raw[5000];
    const char row[] = "{\"state\":\"landed\",\"note\":\"extent\","
        "\"ts\":\"2026-09-06T10:00:00Z\",\"attempt\":1,\"started\":1788688800,"
        "\"landed_at\":1788692400}";
    const char *ids[] = {"landing_latency_s", "landing_attempts_per_train"};
    test_make_tmpdir(root, sizeof root, "fleet_objectives", "extent");
    for (size_t i = 0; i < 6; i++) {
        (void)snprintf(path, sizeof path, "%s/case%zu", root, i);
        if (i == 5) {
            ASSERT(fox_mkdir(path)); /* fopen succeeds, reading a directory fails */
        } else {
            size_t n = sizeof row - 1;
            memcpy(raw, row, n);
            if (i != 1) raw[n++] = '\n';
            if (i >= 2) {
                memcpy(raw + n, row, sizeof row - 1);
                n += sizeof row - 1;
                if (i == 2) { raw[n++] = 0; raw[n++] = 'x'; }
                if (i == 3) { memset(raw + n, ' ', 4200); n += 4200; }
                if (i == 4) raw[n - 1] = 'x'; /* unfinished JSON */
                raw[n++] = '\n';
            }
            FILE *f = fopen(path, "wb");
            ASSERT(f != NULL);
            ASSERT_EQ(fwrite(raw, 1, n, f), n);
            ASSERT_EQ(fclose(f), 0);
        }
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", path);
        ASSERT(fox_run(&c));
        for (size_t j = 0; j < 2; j++) {
            const struct json_value *v = fox_row(&c, ids[j]);
            ASSERT(v != NULL);
            ASSERT_EQ(json_get_bool(json_get(v, "measured")), i < 2);
            if (i >= 2) ASSERT(fox_row_str(v, "reason")[0] != 0);
        }
        fox_end(&c);
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

/* 2026-10-22T10:00:00Z, and the UTC midnight ten hours before it. */
#define FOX_NOW 1792663200LL
#define FOX_MIDNIGHT 1792627200LL
#define FOX_DAY 86400LL

static int fox_case_windows(void)
{
    int failures = 0;
    char root[512], outcomes[1024], thin[1024], missing[1024], text[4096];
    struct zcl_objectives_options o = {0};
    struct zcl_objective_value v;
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "windows");
    (void)snprintf(outcomes, sizeof(outcomes), "%s/outcomes.jsonl", root);
    (void)snprintf(thin, sizeof(thin), "%s/thin.jsonl", root);
    (void)snprintf(missing, sizeof(missing), "%s/none.jsonl", root);
    /* now is 2026-10-22T10:00Z. A landed an hour ago but was submitted ten
     * days ago (landed_at wins over ts); B landed two hours ago; C is an old
     * row dated by its ts, today; D landed one second before midnight; E is
     * an old row from three days ago. F failed two days ago. G, H are ten
     * days old; I was cancelled today. */
    (void)snprintf(text, sizeof(text),
        "{\"state\":\"landed\",\"ts\":\"2026-10-12T09:00:00Z\",\"landed_at\":%lld}\n"
        "{\"state\":\"landed\",\"ts\":\"2026-10-22T08:00:00Z\",\"landed_at\":%lld}\n"
        "{\"state\":\"landed\",\"ts\":\"2026-10-22T02:00:00Z\"}\n"
        "{\"state\":\"landed\",\"ts\":\"2026-10-21T23:00:00Z\",\"landed_at\":%lld}\n"
        "{\"state\":\"landed\",\"ts\":\"2026-10-19T10:00:00Z\"}\n"
        "{\"state\":\"failed\",\"ts\":\"2026-10-20T10:00:00Z\"}\n"
        "{\"state\":\"failed\",\"ts\":\"2026-10-12T10:00:00Z\"}\n"
        "{\"state\":\"landed\",\"ts\":\"2026-10-12T10:00:00Z\"}\n"
        "{\"state\":\"cancelled\",\"ts\":\"2026-10-22T09:30:00Z\"}\n",
        FOX_NOW - 3600, FOX_NOW - 7200, FOX_MIDNIGHT - 1);
    o.now = FOX_NOW;
    o.outcomes = outcomes;
    TEST("objectives: landed_rows_today counts landed rows since UTC "
         "midnight, dated by landed_at and else ts") {
        ASSERT(fox_write(outcomes, text));
        v = zcl_objectives_measure(&o, "landed_rows_today");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 3);
        PASS();
    }
    TEST("objectives: land_success_rate_7d is landed over landed plus "
         "failed in the last 7 days") {
        v = zcl_objectives_measure(&o, "land_success_rate_7d");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 83); /* 5 landed, 1 failed in the window */
        PASS();
    }
    TEST("objectives: a window with no landed or failed row, or no ledger, "
         "is unmeasured") {
        ASSERT(fox_write(thin,
            "{\"state\":\"landed\",\"ts\":\"2026-10-12T10:00:00Z\"}\n"
            "{\"state\":\"cancelled\",\"ts\":\"2026-10-22T09:30:00Z\"}\n"));
        o.outcomes = thin;
        v = zcl_objectives_measure(&o, "land_success_rate_7d");
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "no landed or failed") != NULL);
        v = zcl_objectives_measure(&o, "landed_rows_today");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 0);
        o.outcomes = missing;
        v = zcl_objectives_measure(&o, "landed_rows_today");
        ASSERT(!v.measured);
        ASSERT(v.reason[0] != '\0');
        v = zcl_objectives_measure(&o, "land_success_rate_7d");
        ASSERT(!v.measured);
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int fox_case_git(void)
{
    int failures = 0;
    char root[512], repo[1024];
    struct zcl_objectives_options o = {0};
    struct zcl_objective_value v;
    const char *dirs[] = {"core", "engine", "contexts", "apps", "docs", "tools"};
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "git");
    (void)snprintf(repo, sizeof(repo), "%s/repo", root);
    o.repo = repo;
    o.now = FOX_NOW;
    TEST("objectives: the git readers count dated commits on origin/main, "
         "not HEAD, and fall back to HEAD only without it") {
        ASSERT(fox_mkdir(repo));
        ASSERT_EQ(fox_git(repo, "init", "-q", NULL, NULL), 0);
        for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
            char d[1100];
            (void)snprintf(d, sizeof(d), "%s/%s", repo, dirs[i]);
            ASSERT(fox_mkdir(d));
        }
        ASSERT(fox_commit(repo, "docs/x.md", FOX_NOW - 12 * FOX_DAY, 1));
        ASSERT(fox_commit(repo, "docs/API_REFERENCE.md", FOX_NOW - 9 * FOX_DAY, 2));
        ASSERT(fox_commit(repo, "core/a.c", FOX_NOW - 6 * FOX_DAY, 3));
        ASSERT(fox_commit(repo, "tools/t.c", FOX_NOW - 5 * FOX_DAY, 4));
        ASSERT(fox_commit(repo, "docs/CAPABILITY_INVENTORY.jsonl", FOX_NOW - 3 * FOX_DAY, 5));
        ASSERT(fox_commit(repo, "engine/b.c", FOX_NOW - 2 * FOX_DAY, 6));
        ASSERT(fox_commit(repo, "contexts/c.c", FOX_NOW - 3600, 7));
        ASSERT(fox_commit(repo, "docs/API_REFERENCE.md", FOX_NOW - 3500, 8));
        ASSERT_EQ(fox_git(repo, "update-ref", "refs/remotes/origin/main", "HEAD", NULL), 0);
        /* One commit that exists only on HEAD, after origin/main. */
        ASSERT(fox_commit(repo, "apps/d.c", FOX_NOW - 1800, 9));

        v = zcl_objectives_measure(&o, "commits_landed_today");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 2); /* commits 7 and 8; HEAD's commit 9 is not on origin/main */
        v = zcl_objectives_measure(&o, "product_commit_share_7d");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 50); /* 3 of the 6 commits since day -7 touch a product dir */
        v = zcl_objectives_measure(&o, "generated_churn_10d");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 3); /* commits 2, 5 and 8 */

        ASSERT_EQ(fox_git(repo, "update-ref", "-d", "refs/remotes/origin/main", NULL), 0);
        v = zcl_objectives_measure(&o, "commits_landed_today");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 3); /* HEAD fallback sees commit 9 too */
        PASS();
    }
    TEST("objectives: the git readers are unmeasured outside a repository "
         "and when the window holds no commit") {
        char plain[1024];
        (void)setenv("GIT_CEILING_DIRECTORIES", root, 1);
        (void)snprintf(plain, sizeof(plain), "%s/plain", root);
        ASSERT(fox_mkdir(plain));
        o.repo = plain;
        v = zcl_objectives_measure(&o, "commits_landed_today");
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "git log failed") != NULL);
        v = zcl_objectives_measure(&o, "product_commit_share_7d");
        ASSERT(!v.measured);
        o.repo = repo;
        o.now = FOX_NOW + 400 * FOX_DAY;
        v = zcl_objectives_measure(&o, "product_commit_share_7d");
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "no origin/main commit") != NULL);
        v = zcl_objectives_measure(&o, "generated_churn_10d");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, 0);
        (void)unsetenv("GIT_CEILING_DIRECTORIES");
        PASS();
    }
_test_next:;
    (void)test_rm_rf_recursive(root);
    return failures;
}

static void fox_screen_row(struct json_value *rows, const char *id,
                           const char *direction, int64_t target,
                           bool measured, int64_t value, const char *status,
                           const char *unit, const char *why)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "id", id);
    (void)json_push_kv_str(&row, "direction", direction);
    (void)json_push_kv_int(&row, "target", target);
    (void)json_push_kv_str(&row, "unit", unit);
    (void)json_push_kv_str(&row, "why", why);
    (void)json_push_kv_bool(&row, "measured", measured);
    if (measured)
        (void)json_push_kv_int(&row, "value", value);
    (void)json_push_kv_str(&row, "status", status);
    (void)json_push_back(rows, &row);
    json_free(&row);
}

static int fox_case_screen(void)
{
    int failures = 0;
    struct json_value rows;
    char screen[2048], want[2048];
    json_init(&rows);
    json_set_array(&rows);
    TEST("objectives: the report card draws a 20-cell bar toward each "
         "target, in the row's own direction, in ASCII, with a summary") {
        fox_screen_row(&rows, "alpha_max", "max", 12, true, 6, "unmet", "n",
                       "half of the target");
        fox_screen_row(&rows, "beta_min", "min", 600, true, 1200, "unmet", "s",
                       "twice the \xc3\xa9 budget");
        fox_screen_row(&rows, "gamma_zero", "min", 0, true, 0, "met", "n", "x");
        fox_screen_row(&rows, "delta_gap", "max", 900, false, 0,
                       "unmeasured(bad \xc3\xa9 x)", "n", "never measured");
        fox_screen_row(&rows, "eps_over", "max", 12, true, 15, "met", "n", "x");
        (void)zcl_objectives_render_screen(&rows, screen, sizeof(screen));
        (void)snprintf(want, sizeof(want),
            "%-30s [##########----------] 6/12 UNMET\n"
            "%-30s [##########----------] 1200/600 UNMET\n"
            "%-30s [####################] 0/0 met\n"
            "%-30s [????????????????????] -/900 unmeasured(bad ?? x)\n"
            "%-30s [####################] 15/12 met\n"
            "lab: met 2 of 5, unmeasured 1\n"
            "next: beta_min  1200 vs 600 s - twice the ?? budget\n",
            "alpha_max", "beta_min", "gamma_zero", "delta_gap", "eps_over");
        ASSERT_STR_EQ(screen, want);
        PASS();
    }
_test_next:;
    json_free(&rows);
    return failures;
}

/* A row for the next-target cases; the status follows from value and target
 * (equal to target is met), so each case states only the numbers. */
static void fox_next_row(struct json_value *rows, const char *id,
                         const char *direction, int64_t target, bool measured,
                         int64_t value, const char *unit, const char *why)
{
    bool is_max = strcmp(direction, "max") == 0;
    bool met = is_max ? value >= target : value <= target;
    fox_screen_row(rows, id, direction, target, measured, value,
                   !measured ? "unmeasured(no data)" : met ? "met" : "unmet",
                   unit, why);
}

/* The reply's gap in thousandths, from the rounded real. */
static int64_t fox_gap_milli(const struct json_value *next)
{
    const struct json_value *gap = json_get(next, "gap");
    if (!gap || gap->type != JSON_REAL)
        return -12345;
    return (int64_t)(json_get_real(gap) * 1000.0 + 0.5);
}

/* Asserts that `rows` picks `id` with this gap; the macro keeps the failing
 * line in the report. */
#define FOX_ASSERT_NEXT(rows, next, want_id, want_milli)                      \
    do {                                                                      \
        ASSERT(zcl_objectives_next((rows), (next)));                          \
        ASSERT_EQ((next)->type, JSON_OBJ);                                    \
        ASSERT_STR_EQ(fox_row_str((next), "id"), (want_id));                  \
        ASSERT_EQ(fox_gap_milli(next), (int64_t)(want_milli));                \
    } while (0)

static int fox_case_next(void)
{
    int failures = 0;
    struct json_value rows, next;
    char screen[4096];
    json_init(&rows);
    json_init(&next);
    TEST("objectives: next is the unmet row with the largest gap, in either "
         "catalog order, and carries that row's fields") {
        json_set_array(&rows);
        fox_next_row(&rows, "small_gap", "min", 100, true, 150, "s", "half over");
        fox_next_row(&rows, "big_gap", "min", 100, true, 300, "s", "triple");
        FOX_ASSERT_NEXT(&rows, &next, "big_gap", 2000);
        ASSERT_EQ(fox_row_int(&next, "value"), (int64_t)300);
        ASSERT_EQ(fox_row_int(&next, "target"), (int64_t)100);
        ASSERT_STR_EQ(fox_row_str(&next, "direction"), "min");
        ASSERT_STR_EQ(fox_row_str(&next, "unit"), "s");
        ASSERT_STR_EQ(fox_row_str(&next, "why"), "triple");
        (void)zcl_objectives_render_screen(&rows, screen, sizeof(screen));
        ASSERT(strstr(screen, "\nnext: big_gap  300 vs 100 s - triple\n") != NULL);

        json_set_array(&rows);
        fox_next_row(&rows, "big_gap", "min", 100, true, 300, "s", "triple");
        fox_next_row(&rows, "small_gap", "min", 100, true, 150, "s", "half over");
        FOX_ASSERT_NEXT(&rows, &next, "big_gap", 2000);
        PASS();
    }
    TEST("objectives: next computes the gap in each row's own direction, "
         "against max(|target|, 1)") {
        json_set_array(&rows); /* a max row 80% short beats a min row 50% over */
        fox_next_row(&rows, "min_row", "min", 10, true, 15, "n", "min");
        fox_next_row(&rows, "max_row", "max", 10, true, 2, "n", "max");
        FOX_ASSERT_NEXT(&rows, &next, "max_row", 800);
        ASSERT_STR_EQ(fox_row_str(&next, "direction"), "max");

        json_set_array(&rows); /* a min row 200% over beats a max row 10% short */
        fox_next_row(&rows, "max_row", "max", 10, true, 9, "n", "max");
        fox_next_row(&rows, "min_row", "min", 10, true, 30, "n", "min");
        FOX_ASSERT_NEXT(&rows, &next, "min_row", 2000);

        json_set_array(&rows); /* a zero target divides by 1, not by 0 */
        fox_next_row(&rows, "big_target", "min", 1000, true, 2500, "n", "x");
        fox_next_row(&rows, "zero_target", "min", 0, true, 3, "n", "x");
        FOX_ASSERT_NEXT(&rows, &next, "zero_target", 3000);

        json_set_array(&rows); /* a negative target divides by its magnitude */
        fox_next_row(&rows, "pos_min", "min", 100, true, 130, "n", "x");
        fox_next_row(&rows, "neg_max", "max", -50, true, -80, "n", "x");
        FOX_ASSERT_NEXT(&rows, &next, "neg_max", 600);

        json_set_array(&rows); /* one third rounds to three decimals */
        fox_next_row(&rows, "third", "min", 3, true, 4, "n", "x");
        FOX_ASSERT_NEXT(&rows, &next, "third", 333);
        PASS();
    }
    TEST("objectives: equal gaps go to the earlier catalog row") {
        json_set_array(&rows);
        fox_next_row(&rows, "tie_min", "min", 100, true, 200, "n", "x");
        fox_next_row(&rows, "tie_max", "max", 200, true, 0, "n", "x");
        FOX_ASSERT_NEXT(&rows, &next, "tie_min", 1000);
        json_set_array(&rows);
        fox_next_row(&rows, "tie_max", "max", 200, true, 0, "n", "x");
        fox_next_row(&rows, "tie_min", "min", 100, true, 200, "n", "x");
        FOX_ASSERT_NEXT(&rows, &next, "tie_max", 1000);
        PASS();
    }
    TEST("objectives: when every measured row is met, next is null and the "
         "screen says so") {
        json_set_array(&rows);
        fox_next_row(&rows, "at_target", "min", 100, true, 100, "s", "x");
        fox_next_row(&rows, "far_past", "max", 10, true, 99, "n", "x");
        fox_next_row(&rows, "ghost", "max", 1000000, false, 0, "n", "x");
        ASSERT(zcl_objectives_next(&rows, &next));
        ASSERT_EQ(next.type, JSON_NULL);
        (void)zcl_objectives_render_screen(&rows, screen, sizeof(screen));
        ASSERT(strstr(screen, "lab: met 2 of 3, unmeasured 1\n"
                              "next: none - every measured objective is met\n") != NULL);
        PASS();
    }
    TEST("objectives: an unmeasured row is never the next target, whatever "
         "its target, and with nothing measured next is null") {
        json_set_array(&rows);
        fox_next_row(&rows, "ghost_a", "max", 1000000, false, 0, "n", "x");
        fox_next_row(&rows, "real_unmet", "min", 100, true, 101, "n", "x");
        fox_next_row(&rows, "ghost_b", "min", 0, false, 0, "n", "x");
        FOX_ASSERT_NEXT(&rows, &next, "real_unmet", 10);

        json_set_array(&rows);
        fox_next_row(&rows, "ghost_a", "max", 1000000, false, 0, "n", "x");
        fox_next_row(&rows, "ghost_b", "min", 0, false, 0, "n", "x");
        ASSERT(zcl_objectives_next(&rows, &next));
        ASSERT_EQ(next.type, JSON_NULL);
        (void)zcl_objectives_render_screen(&rows, screen, sizeof(screen));
        ASSERT(strstr(screen, "next: none - no objective is measured yet\n") != NULL);
        PASS();
    }
_test_next:;
    json_free(&next);
    json_free(&rows);
    return failures;
}

int test_fleet_objectives(void);
int test_fleet_objectives(void)
{
    int failures = 0;
    failures += fox_case_ledger_extent();
    failures += fox_case_windows();
    failures += fox_case_git();
    failures += fox_case_screen();
    failures += fox_case_next();
    char root[512];
    char outcomes_ok[1024], outcomes_missing[1024];
    char attempts_dir[1024], inflight_dir[1024];
    char lintc_dir[1024], lintc_big[1200], lintc_small[1200];
    char baseline_ok[1024], baseline_missing[1024];

    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "root");
    (void)snprintf(outcomes_ok, sizeof(outcomes_ok), "%s/outcomes.jsonl",
                  root);
    (void)snprintf(outcomes_missing, sizeof(outcomes_missing),
                  "%s/no_such_outcomes.jsonl", root);
    (void)snprintf(attempts_dir, sizeof(attempts_dir), "%s/attempts", root);
    (void)snprintf(inflight_dir, sizeof(inflight_dir), "%s/inflight_only", root);
    (void)snprintf(lintc_dir, sizeof(lintc_dir), "%s/lintc", root);
    (void)snprintf(lintc_big, sizeof(lintc_big), "%s/big.c", lintc_dir);
    (void)snprintf(lintc_small, sizeof(lintc_small), "%s/small.c", lintc_dir);
    (void)snprintf(baseline_ok, sizeof(baseline_ok), "%s/baseline.txt",
                  root);
    (void)snprintf(baseline_missing, sizeof(baseline_missing),
                  "%s/no_such_baseline.txt", root);

    /* One TRAIN is identified by its `note` ("traintrainX"), never by `tip`
     * or `base` (both change on every rebase). Each row's `ts` is its SUBMIT
     * time and `started` its proof start; only the landed row's `landed_at`
     * says when it landed. The train is first submitted at epoch 36030,
     * fails twice, then lands at epoch 38490: latency 2460, 3 attempts. A row
     * for a different train ("traintrainY") sits first in the file and must
     * not count toward either number. */
    ASSERT(fox_write(
        outcomes_ok,
        "{\"tip\":\"tipY1\",\"note\":\"traintrainY\",\"state\":\"conflict\","
        "\"ts\":\"1970-01-01T09:00:00Z\",\"started\":32000}\n"
        "{\"tip\":\"tipX1\",\"note\":\"traintrainX\",\"state\":\"failed\","
        "\"ts\":\"1970-01-01T10:00:30Z\",\"started\":36100,\"attempt\":1}\n"
        "{\"tip\":\"tipX2\",\"note\":\"traintrainX\",\"state\":\"failed\","
        "\"ts\":\"1970-01-01T10:20:00Z\",\"started\":37200,\"attempt\":1}\n"
        "{\"tip\":\"tipX3\",\"note\":\"traintrainX\",\"state\":\"landed\","
        "\"ts\":\"1970-01-01T10:41:00Z\",\"started\":38460,\"attempt\":1,"
        "\"landed_at\":38490}\n"
        "{\"note\":\"pairold\",\"state\":\"failed\",\"local\":\"o1\","
        "\"base\":\"b1\",\"ts\":\"1970-01-01T00:20:00Z\",\"started\":1000}\n"
        "{\"note\":\"pairdone\",\"state\":\"failed\",\"local\":\"d1\","
        "\"base\":\"b2\",\"ts\":\"1970-01-01T00:40:00Z\",\"started\":2000}\n"));

    /* Three attempts in the real layout. "o1-b1" and "d1-b2" are complete;
     * the ledger records d1-b2 later (started 2000 vs 1000), but o1-b1 has
     * the NEWER phases.txt mtime (a touched old attempt), so only a recorded
     * key lets d1-b2 win. "inflight" is the newest by mtime but has no
     * dimension_lint_and_test row yet, so it must be skipped. */
    ASSERT(fox_mkdir(attempts_dir));
    ASSERT(fox_attempt(attempts_dir, "o1-b1.aaaaaa", true, 797605, 177718, "470.7",
                       1100000000));
    ASSERT(fox_attempt(attempts_dir, "d1-b2.bbbbbb", true, 2506718, 178400, "1727.9",
                       1000000000));
    ASSERT(fox_attempt(attempts_dir, "newest_inflight", false, 0, 1, "1.0",
                       1200000000));
    ASSERT(fox_mkdir(inflight_dir));
    ASSERT(fox_attempt(inflight_dir, "only_inflight", false, 0, 1, "1.0",
                       1200000000));

    ASSERT(fox_mkdir(lintc_dir));
    ASSERT(fox_write_n_lines(lintc_big, 1501));
    ASSERT(fox_write_n_lines(lintc_small, 10));

    ASSERT(fox_write_n_lines(baseline_ok, 7));

    TEST("objectives: the catalog and the answer have the same row count") {
        const struct zcl_objective_row *catalog;
        size_t n = zcl_objectives_catalog(&catalog);
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *rows = json_get(&c.reply.data, "objectives");
        ASSERT(rows && rows->type == JSON_ARR);
        ASSERT_EQ(rows->num_children, n);
        /* One line per row plus the header, in the rendered text. */
        const char *text = fox_row_str(&c.reply.data, "text");
        ASSERT_EQ(fox_count_lines(text), (int64_t)n + 1);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: every row is either produced or declared unmeasured") {
        const struct zcl_objective_row *catalog;
        size_t n = zcl_objectives_catalog(&catalog);
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = fox_row(&c, catalog[i].id);
            ASSERT(row != NULL);
            const struct json_value *measured = json_get(row, "measured");
            ASSERT(measured && measured->type == JSON_BOOL);
            if (!json_get_bool(measured))
                ASSERT(json_get_str(json_get(row, "reason"))[0] != '\0');
        }
        fox_end(&c);
        PASS();
    }

    TEST("objectives: a three-attempt train yields its exact latency and "
        "attempt count, never counting the other train") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *latency = fox_row(&c, "landing_latency_s");
        ASSERT(latency != NULL);
        ASSERT(json_get_bool(json_get(latency, "measured")));
        ASSERT_EQ(fox_row_int(latency, "value"), (int64_t)2460);
        const struct json_value *attempts =
            fox_row(&c, "landing_attempts_per_train");
        ASSERT(attempts != NULL);
        ASSERT(json_get_bool(json_get(attempts, "measured")));
        ASSERT_EQ(fox_row_int(attempts, "value"), (int64_t)3);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: landing chronology rejects an invalid landed_at and "
         "preserves valid durations") {
        /* The submit ts is 36000; latency is landed_at - 36000. A landed_at
         * before the submit, zero, negative, a string or null is no landing
         * instant at all. */
        const char *landed[] = {"36001", "36000", "35999", "0", "-1",
                                "\"36000\"", "null"};
        const int64_t expected[] = {1, 0, -1, -1, -1, -1, -1};
        for (size_t i = 0; i < sizeof(landed) / sizeof(landed[0]); i++) {
            char fixture[256];
            (void)snprintf(fixture, sizeof(fixture),
                          "{\"note\":\"chronology\",\"state\":\"landed\","
                          "\"ts\":\"1970-01-01T10:00:00Z\",\"started\":36500,"
                          "\"landed_at\":%s,\"attempt\":1}\n", landed[i]);
            ASSERT(fox_write(outcomes_missing, fixture));
            struct fox_call c;
            fox_begin(&c);
            fox_set(&c, "outcomes", outcomes_missing);
            ASSERT(fox_run(&c));
            const struct json_value *row = fox_row(&c, "landing_latency_s");
            ASSERT(row != NULL);
            ASSERT_EQ(json_get_bool(json_get(row, "measured")), expected[i] >= 0);
            if (expected[i] < 0) {
                ASSERT(json_get(row, "value") == NULL);
                ASSERT(fox_row_str(row, "reason")[0] != '\0');
                ASSERT(strncmp(fox_row_str(row, "status"), "unmeasured(", 11) == 0);
            } else {
                ASSERT_EQ(fox_row_int(row, "value"), expected[i]);
                ASSERT_STR_EQ(fox_row_str(row, "status"), "met");
            }
            fox_end(&c);
        }
        ASSERT(remove(outcomes_missing) == 0);
        PASS();
    }

    TEST("objectives: an old landed row without landed_at stays unmeasured "
         "with a clear reason, never a latency from ts or started") {
        ASSERT(fox_write(outcomes_missing,
            "{\"note\":\"old\",\"state\":\"landed\","
            "\"ts\":\"1970-01-01T10:00:00Z\",\"started\":36900,"
            "\"attempt\":1}\n"));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_missing);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "landing_latency_s");
        ASSERT(row != NULL);
        ASSERT(!json_get_bool(json_get(row, "measured")));
        ASSERT(strstr(fox_row_str(row, "reason"), "no landed_at") != NULL);
        fox_end(&c);
        ASSERT(remove(outcomes_missing) == 0);
        PASS();
    }

    TEST("objectives: an unparseable first-row submit time cannot fall "
         "through to a later row") {
        ASSERT(fox_write(outcomes_missing,
            "{\"note\":\"chronology\",\"state\":\"failed\","
            "\"ts\":\"not a time\"}\n"
            "{\"note\":\"chronology\",\"state\":\"landed\","
            "\"ts\":\"1970-01-01T10:00:00Z\",\"landed_at\":36001}\n"));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_missing);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "landing_latency_s");
        ASSERT(row != NULL);
        ASSERT(!json_get_bool(json_get(row, "measured")));
        ASSERT(json_get(row, "value") == NULL);
        ASSERT(fox_row_str(row, "reason")[0] != '\0');
        ASSERT(strncmp(fox_row_str(row, "status"), "unmeasured(", 11) == 0);
        fox_end(&c);
        ASSERT(remove(outcomes_missing) == 0);
        PASS();
    }

    TEST("objectives: latency runs from the train's first submission, not "
         "the landed row's own ts") {
        ASSERT(fox_write(outcomes_missing,
            "{\"note\":\"chronology\",\"state\":\"failed\","
            "\"ts\":\"1970-01-01T09:59:59Z\"}\n"
            "{\"note\":\"chronology\",\"state\":\"landed\","
            "\"ts\":\"1970-01-01T10:00:00Z\",\"landed_at\":36001}\n"));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_missing);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "landing_latency_s");
        ASSERT(row != NULL);
        ASSERT(json_get_bool(json_get(row, "measured")));
        ASSERT_EQ(fox_row_int(row, "value"), (int64_t)2);
        ASSERT_STR_EQ(fox_row_str(row, "status"), "met");
        fox_end(&c);
        ASSERT(remove(outcomes_missing) == 0);
        PASS();
    }

    TEST("objectives: a missing outcomes file yields unmeasured, never zero") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_missing);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *latency = fox_row(&c, "landing_latency_s");
        ASSERT(latency != NULL);
        ASSERT(!json_get_bool(json_get(latency, "measured")));
        const char *reason = fox_row_str(latency, "reason");
        ASSERT(strstr(reason, "missing outcomes file") != NULL);
        ASSERT(strstr(reason, outcomes_missing) != NULL);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: the real proof logs give lint, test and whole-proof "
         "walls from the newest COMPLETED attempt") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *lint = fox_row(&c, "proof_lint_wall_s");
        ASSERT(lint != NULL);
        ASSERT(json_get_bool(json_get(lint, "measured")));
        ASSERT_EQ(fox_row_int(lint, "value"), (int64_t)178);
        const struct json_value *test_row = fox_row(&c, "proof_test_wall_s");
        ASSERT(test_row != NULL);
        ASSERT(json_get_bool(json_get(test_row, "measured")));
        ASSERT_EQ(fox_row_int(test_row, "value"), (int64_t)1728);
        const struct json_value *proof = fox_row(&c, "proof_wall_s");
        ASSERT(proof != NULL);
        ASSERT(json_get_bool(json_get(proof, "measured")));
        ASSERT_EQ(fox_row_int(proof, "value"), (int64_t)2507);
        ASSERT_EQ(fox_row_int(proof, "target"), (int64_t)900);
        ASSERT_STR_EQ(fox_row_str(proof, "status"), "unmet");
        fox_end(&c);
        PASS();
    }

    TEST("objectives: only an in-flight attempt is unmeasured, never zero") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", inflight_dir);
        ASSERT(fox_run(&c));
        const char *ids[] = {"proof_lint_wall_s", "proof_test_wall_s",
                             "proof_wall_s"};
        for (size_t i = 0; i < 3; i++) {
            const struct json_value *row = fox_row(&c, ids[i]);
            ASSERT(row != NULL);
            ASSERT(!json_get_bool(json_get(row, "measured")));
            ASSERT(strstr(fox_row_str(row, "reason"),
                          "no completed proof attempt") != NULL);
        }
        fox_end(&c);
        PASS();
    }

    TEST("objectives: the test wall comes from the producer's own "
         "<key>.test.log, not another *.test.log in the directory") {
        char dir[1024], decoy[1400];
        (void)snprintf(dir, sizeof(dir), "%s/two_test_logs", root);
        ASSERT(fox_mkdir(dir));
        ASSERT(fox_attempt(dir, "e1-b5.cccccc", true, 797605, 177718, "100.0",
                           1000000000));
        (void)snprintf(decoy, sizeof(decoy),
                       "%s/e1-b5.cccccc/logs/aaa.test.log", dir);
        ASSERT(fox_write(decoy, "ALL TESTS PASSED \xe2\x80\x94 0/1 groups "
                                "failed, 0 skipped (9.0s wall, 1 workers)\n"));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", dir);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "proof_test_wall_s");
        ASSERT(row != NULL);
        ASSERT(json_get_bool(json_get(row, "measured")));
        ASSERT_EQ(fox_row_int(row, "value"), (int64_t)100);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: with no producer-named log, the smallest-named "
         "*.test.log that carries a wall line wins") {
        char dir[1024], path[1400];
        (void)snprintf(dir, sizeof(dir), "%s/scan_test_logs", root);
        ASSERT(fox_mkdir(dir));
        ASSERT(fox_attempt(dir, "s1-b6.dddddd", true, 797605, 177718, "1.0",
                           1000000000));
        (void)snprintf(path, sizeof(path), "%s/s1-b6.dddddd/logs/s1-b6.test.log",
                       dir);
        ASSERT(unlink(path) == 0);
        (void)snprintf(path, sizeof(path), "%s/s1-b6.dddddd/logs/zzz.test.log",
                       dir);
        ASSERT(fox_write(path, "no wall line here\n"));
        (void)snprintf(path, sizeof(path), "%s/s1-b6.dddddd/logs/nnn.test.log",
                       dir);
        ASSERT(fox_write(path, "ALL TESTS PASSED \xe2\x80\x94 0/1 groups "
                               "failed, 0 skipped (77.0s wall, 1 workers)\n"));
        (void)snprintf(path, sizeof(path), "%s/s1-b6.dddddd/logs/mmm.test.log",
                       dir);
        ASSERT(fox_write(path, "ALL TESTS PASSED \xe2\x80\x94 0/1 groups "
                               "failed, 0 skipped (55.0s wall, 1 workers)\n"));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", dir);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "proof_test_wall_s");
        ASSERT(row != NULL);
        ASSERT(json_get_bool(json_get(row, "measured")));
        ASSERT_EQ(fox_row_int(row, "value"), (int64_t)55);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: a cached test pass is never reported as the test "
         "wall") {
        char dir[1024], path[1400];
        (void)snprintf(dir, sizeof(dir), "%s/cached_test_log", root);
        ASSERT(fox_mkdir(dir));
        ASSERT(fox_attempt(dir, "c1-b7.eeeeee", true, 797605, 177718, "1.0",
                           1000000000));
        (void)snprintf(path, sizeof(path), "%s/c1-b7.eeeeee/logs/c1-b7.test.log",
                       dir);
        ASSERT(fox_write(path, "ALL TESTS PASSED (CACHED) \xe2\x80\x94 0/1 "
                               "groups failed, 0 skipped (0.1s wall, 1 "
                               "workers)\n"));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", dir);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "proof_test_wall_s");
        ASSERT(row != NULL);
        ASSERT(!json_get_bool(json_get(row, "measured")));
        fox_end(&c);
        PASS();
    }

    TEST("objectives: the lint ceiling count is exact, and the cyclomatic "
        "baseline count matches its file") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *ceiling =
            fox_row(&c, "lint_families_over_ceiling");
        ASSERT(ceiling != NULL);
        ASSERT(json_get_bool(json_get(ceiling, "measured")));
        ASSERT_EQ(fox_row_int(ceiling, "value"), (int64_t)1);
        const struct json_value *cap =
            fox_row(&c, "functions_over_complexity_cap");
        ASSERT(cap != NULL);
        ASSERT(json_get_bool(json_get(cap, "measured")));
        ASSERT_EQ(fox_row_int(cap, "value"), (int64_t)7);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: an absent cyclomatic baseline is unmeasured by name") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_missing);
        ASSERT(fox_run(&c));
        const struct json_value *cap =
            fox_row(&c, "functions_over_complexity_cap");
        ASSERT(cap != NULL);
        ASSERT(!json_get_bool(json_get(cap, "measured")));
        fox_end(&c);
        PASS();
    }

    TEST("objectives: the two undeclared objectives are always unmeasured, "
        "by name") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *eta = fox_row(&c, "fresh_node_sync_eta_s");
        ASSERT(eta != NULL);
        ASSERT_STR_EQ(fox_row_str(eta, "status"),
                     "unmeasured(producer is a future leaf)");
        const struct json_value *tok =
            fox_row(&c, "tokens_per_landed_commit");
        ASSERT(tok != NULL);
        ASSERT_STR_EQ(fox_row_str(tok, "status"),
                     "unmeasured(producer is the experiment ledger)");
        fox_end(&c);
        PASS();
    }

    TEST("objectives: --json parses field by field, one row at a time") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        ASSERT_STR_EQ(fox_row_str(&c.reply.data, "schema"),
                     ZCL_OBJECTIVES_SCHEMA);
        const struct json_value *row = fox_row(&c, "proof_lint_wall_s");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(fox_row_str(row, "source"), "lint.log");
        ASSERT_STR_EQ(fox_row_str(row, "direction"), "min");
        ASSERT_STR_EQ(fox_row_str(row, "unit"), "s");
        ASSERT_EQ(fox_row_int(row, "target"), (int64_t)300);
        ASSERT(fox_row_str(row, "why")[0] != '\0');
        ASSERT_STR_EQ(fox_row_str(row, "status"), "met");
        fox_end(&c);
        PASS();
    }

    TEST("objectives: a commits-landed row exists over a fixture repo, its "
        "VALUE never asserted") {
        char repo[1024];
        (void)snprintf(repo, sizeof(repo), "%s/repo", root);
        ASSERT(fox_mkdir(repo));
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        fox_set(&c, "repo", repo);
        ASSERT(fox_run(&c));
        const struct json_value *row = fox_row(&c, "commits_landed_today");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(fox_row_str(row, "id"), "commits_landed_today");
        ASSERT_STR_EQ(fox_row_str(row, "source"), "git_log");
        fox_end(&c);
        PASS();
    }

    TEST("objectives: the command result carries a screen, one ASCII line "
         "per objective plus the lab summary") {
        const struct zcl_objective_row *catalog;
        size_t n = zcl_objectives_catalog(&catalog);
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const char *screen = fox_row_str(&c.reply.data, "screen");
        ASSERT_EQ(fox_count_lines(screen), (int64_t)n + 2);
        for (const char *p = screen; *p; p++)
            ASSERT(*p == '\n' || (*p >= 0x20 && *p <= 0x7e));
        ASSERT(strstr(screen, "proof_lint_wall_s") != NULL);
        ASSERT(strstr(screen, "[####################] 178/300 met") != NULL);
        const char *last = strstr(screen, "lab: met ");
        ASSERT(last != NULL);
        ASSERT(strstr(last, " of 14, unmeasured ") != NULL);
        /* The whole reply must fit the leaf's declared response budget. */
        ASSERT(c.request.spec != NULL);
        ASSERT(c.request.spec->budget_bytes >= 0);
        ASSERT(json_size(&c.reply.data) + 1024 <= (size_t)c.request.spec->budget_bytes);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: the command result names the next target, the same "
         "row the screen closes on") {
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", outcomes_ok);
        fox_set(&c, "attempts_dir", attempts_dir);
        fox_set(&c, "lintc_dir", lintc_dir);
        fox_set(&c, "baseline", baseline_ok);
        ASSERT(fox_run(&c));
        const struct json_value *next = json_get(&c.reply.data, "next");
        ASSERT(next != NULL);
        ASSERT_EQ(next->type, JSON_OBJ);
        const char *id = fox_row_str(next, "id");
        const struct json_value *row = fox_row(&c, id);
        ASSERT(row != NULL);
        ASSERT_STR_EQ(fox_row_str(row, "status"), "unmet");
        ASSERT_EQ(fox_row_int(next, "value"), fox_row_int(row, "value"));
        ASSERT_EQ(fox_row_int(next, "target"), fox_row_int(row, "target"));
        ASSERT_STR_EQ(fox_row_str(next, "direction"), fox_row_str(row, "direction"));
        ASSERT_STR_EQ(fox_row_str(next, "unit"), fox_row_str(row, "unit"));
        ASSERT_STR_EQ(fox_row_str(next, "why"), fox_row_str(row, "why"));
        /* The fixture ledger's train needs 3 attempts against a target of 1,
         * a gap of 2; whatever else is unmet, the pick is at least that big. */
        ASSERT(fox_gap_milli(next) >= 2000);
        char want[160];
        (void)snprintf(want, sizeof(want), "\nnext: %s  %lld vs %lld ", id,
                       (long long)fox_row_int(next, "value"),
                       (long long)fox_row_int(next, "target"));
        ASSERT(strstr(fox_row_str(&c.reply.data, "screen"), want) != NULL);
        fox_end(&c);
        PASS();
    }

    TEST("objectives: with nothing measurable next is null in the reply and "
         "the screen says nothing is measured") {
        char none_outcomes[1024], none_baseline[1024], none_attempts[1024];
        char none_lintc[1024], plain[1024];
        (void)snprintf(none_outcomes, sizeof(none_outcomes), "%s/none.jsonl", root);
        (void)snprintf(none_baseline, sizeof(none_baseline), "%s/none.txt", root);
        (void)snprintf(none_attempts, sizeof(none_attempts), "%s/none_attempts",
                       root);
        (void)snprintf(none_lintc, sizeof(none_lintc), "%s/none_lintc", root);
        (void)snprintf(plain, sizeof(plain), "%s/plain_repo", root);
        ASSERT(fox_mkdir(plain));
        (void)setenv("GIT_CEILING_DIRECTORIES", root, 1);
        struct fox_call c;
        fox_begin(&c);
        fox_set(&c, "outcomes", none_outcomes);
        fox_set(&c, "attempts_dir", none_attempts);
        fox_set(&c, "lintc_dir", none_lintc);
        fox_set(&c, "baseline", none_baseline);
        fox_set(&c, "repo", plain);
        ASSERT(fox_run(&c));
        (void)unsetenv("GIT_CEILING_DIRECTORIES");
        const struct json_value *next = json_get(&c.reply.data, "next");
        ASSERT(next != NULL);
        ASSERT_EQ(next->type, JSON_NULL);
        ASSERT(strstr(fox_row_str(&c.reply.data, "screen"),
                      "next: none - no objective is measured yet\n") != NULL);
        fox_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    failures += fox_line_read_error();
    if (failures == 0)
        printf("test_fleet_objectives: all passed\n");
    else
        printf("test_fleet_objectives: %d FAILED\n", failures);
    return failures;
}
