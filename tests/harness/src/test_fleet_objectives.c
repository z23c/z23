/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.objectives
 * (tools/command/native_fleet_objectives*.c).
 *
 * Every path a producer reads is overridable, so this file drives the whole
 * leaf against fixtures built here — never against this checkout's own
 * outcomes ledger, proof attempts, or lint tree. Nothing here reads a real
 * clock and nothing asserts a value that depends on one; `commits_landed_today`
 * is exercised against a fixture repository but its VALUE is never asserted,
 * because "since midnight" is real-clock-relative by definition.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet_objectives.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

int test_fleet_objectives(void);
int test_fleet_objectives(void)
{
    int failures = 0;
    char root[512];
    char outcomes_ok[1024], outcomes_missing[1024];
    char attempts_dir[1024], attempt1[1200], phases_path[1300];
    char lintc_dir[1024], lintc_big[1200], lintc_small[1200];
    char baseline_ok[1024], baseline_missing[1024];

    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "root");
    (void)snprintf(outcomes_ok, sizeof(outcomes_ok), "%s/outcomes.jsonl",
                  root);
    (void)snprintf(outcomes_missing, sizeof(outcomes_missing),
                  "%s/no_such_outcomes.jsonl", root);
    (void)snprintf(attempts_dir, sizeof(attempts_dir), "%s/attempts", root);
    (void)snprintf(attempt1, sizeof(attempt1), "%s/only", attempts_dir);
    (void)snprintf(phases_path, sizeof(phases_path), "%s/phases.txt",
                  attempt1);
    (void)snprintf(lintc_dir, sizeof(lintc_dir), "%s/lintc", root);
    (void)snprintf(lintc_big, sizeof(lintc_big), "%s/big.c", lintc_dir);
    (void)snprintf(lintc_small, sizeof(lintc_small), "%s/small.c", lintc_dir);
    (void)snprintf(baseline_ok, sizeof(baseline_ok), "%s/baseline.txt",
                  root);
    (void)snprintf(baseline_missing, sizeof(baseline_missing),
                  "%s/no_such_baseline.txt", root);

    /* One TRAIN is identified by its `note` ("traintrainX"), NEVER by `tip`
     * or `base` — both of those change on every rebase in the real ledger,
     * so the fixture deliberately gives every row of "traintrainX" its OWN
     * distinct tip, to mirror reality. It starts at epoch 36000
     * (1970-01-01T10:00:00Z, the earliest row's `started`), fails twice,
     * then lands at 1970-01-01T10:41:00Z (epoch 38460): latency
     * == 38460 - 36000 == 2460, and 3 attempts (all three rows are
     * landed/failed, none is a pure rebase "conflict"). A fourth row for a
     * DIFFERENT train ("traintrainY", its own distinct tip) sits first in
     * the file and must not be pulled into either number. */
    ASSERT(fox_write(
        outcomes_ok,
        "{\"tip\":\"tipY1\",\"note\":\"traintrainY\",\"state\":\"conflict\","
        "\"ts\":\"1970-01-01T09:00:00Z\",\"started\":32000}\n"
        "{\"tip\":\"tipX1\",\"note\":\"traintrainX\",\"state\":\"failed\","
        "\"ts\":\"1970-01-01T10:00:30Z\",\"started\":36000,\"attempt\":1}\n"
        "{\"tip\":\"tipX2\",\"note\":\"traintrainX\",\"state\":\"failed\","
        "\"ts\":\"1970-01-01T10:20:00Z\",\"started\":37200,\"attempt\":1}\n"
        "{\"tip\":\"tipX3\",\"note\":\"traintrainX\",\"state\":\"landed\","
        "\"ts\":\"1970-01-01T10:41:00Z\",\"started\":38460,\"attempt\":1}\n"));

    ASSERT(fox_mkdir(attempts_dir));
    ASSERT(fox_mkdir(attempt1));
    ASSERT(fox_write(
        phases_path,
        "generation_storage=ram\n"
        "step=bundle budget_ms=1000 elapsed_ms=500 cause=none exit=0\n"
        "step=lint budget_ms=999999 elapsed_ms=12345 cause=none exit=0\n"
        "step=test budget_ms=999999 elapsed_ms=67890 cause=none exit=0\n"));

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

    TEST("objectives: phases.txt yields the exact rounded wall seconds") {
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
        ASSERT_EQ(fox_row_int(lint, "value"), (int64_t)12);
        const struct json_value *test_row = fox_row(&c, "proof_test_wall_s");
        ASSERT(test_row != NULL);
        ASSERT(json_get_bool(json_get(test_row, "measured")));
        ASSERT_EQ(fox_row_int(test_row, "value"), (int64_t)68);
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
        ASSERT_STR_EQ(fox_row_str(row, "source"), "phases.txt");
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

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_fleet_objectives: all passed\n");
    else
        printf("test_fleet_objectives: %d FAILED\n", failures);
    return failures;
}
