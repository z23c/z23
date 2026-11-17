/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for the lint gate-catch telemetry feed:
 *   writer — tools/lint/lintc/run_report.c (one zcl.lint_gate_catches.v1
 *            JSONL line per EXECUTED gate, appended beside last-run.json;
 *            its half is proven in test_lint_run.c)
 *   reader — tools/command/native_dev_lint_catches.c (dev.proof.lint_catches)
 *
 * The reader is called through its bound handler (as the CLI does after
 * input validation) and its input keys are validated through the real
 * registry, always against a local fixture ledger built here — never the
 * checkout the test runs in. Fixture rows carry timestamps relative to
 * the current instant, so since-window cases can cut real edges.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define DLC_PATH "dev.proof.lint_catches"
#define DLC_LEDGER_NAME "gate-catches.jsonl"
#define DLC_TS_LEN 20u
#define DLC_DAY_S 86400LL

/* ── fixture helpers ─────────────────────────────────────────────── */

static bool dlc_write_text(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
        return false;
    bool ok = fputs(text, fp) != EOF;
    return fclose(fp) == 0 && ok;
}

/* "YYYY-MM-DDTHH:MM:SSZ" of (now - ago_s): the ledger's own ts shape. */
static void dlc_iso_ago(long long ago_s, char *buf, size_t cap)
{
    time_t t = time(NULL) - (time_t)ago_s;
    struct tm tm;
    (void)gmtime_r(&t, &tm);
    (void)strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* One ledger row; ts is derived at run time so `days` windows bite. */
static void dlc_row(char *buf, size_t cap, const char *gate, int rc,
                    long long ago_s)
{
    char ts[DLC_TS_LEN + 1];
    dlc_iso_ago(ago_s, ts, sizeof(ts));
    (void)snprintf(buf, cap,
                   "{\"ts\":\"%s\",\"gate\":\"%s\",\"rc\":%d,\"ms\":%d}\n",
                   ts, gate, rc, 12);
}

/* The ledger every window case reads: alpha (1 catch of 3 attempts),
 * beta (2 catches), gamma (passes only), delta (one catch far outside
 * the default 28-day window) and one malformed line. */
static bool dlc_build_fixture(const char *path)
{
    char rows[2048], one[160];
    rows[0] = '\0';
    dlc_row(one, sizeof(one), "alpha", 3, 3600);          /* 1h ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "alpha", 0, 7200);          /* 2h ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "alpha", 0, 10800);         /* 3h ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "beta", 2, 1800);           /* 30min ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "beta", 4, 30LL * 3600);    /* 30h ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "gamma", 0, 900);           /* 15min ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "gamma", 0, 5LL * 3600);    /* 5h ago */
    (void)strcat(rows, one);
    dlc_row(one, sizeof(one), "delta", 1, 40LL * 86400);  /* 40d ago */
    (void)strcat(rows, one);
    (void)strcat(rows, "not one json object\n");
    return dlc_write_text(path, rows);
}

/* ── reader call harness (mirrors the devtesthistory test) ────────── */

struct dlc_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlc_begin(struct dlc_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DLC_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_lint_catches.v1");
}

static void dlc_end(struct dlc_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dlc_run(struct dlc_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_lint_catches(&c->request, &c->reply);
    return true;
}

static bool dlc_ok(const struct dlc_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dlc_str(const struct dlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dlc_int(const struct dlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static bool dlc_bool(const struct dlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL ? json_get_bool(v) : false;
}

static const struct json_value *dlc_array(const struct dlc_call *c,
                                          const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

static const char *dlc_entry_str(const struct json_value *e, const char *key)
{
    const struct json_value *v = json_get(e, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dlc_entry_int(const struct json_value *e, const char *key)
{
    const struct json_value *v = json_get(e, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

/* ── reader: dev.proof.lint_catches ─────────────────────────────────────── */

static int dlc_case_registered(void)
{
    int failures = 0;
    TEST_CASE("catches: the leaf is registered and accepts ledger, since, limit") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DLC_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "ledger") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "limit") != NULL);
    } TEST_END;
    return failures;
}

static int dlc_case_aggregate(const char *ledger)
{
    int failures = 0;
    struct dlc_call c;
    char alpha_ts[DLC_TS_LEN + 1], beta_ts[DLC_TS_LEN + 1];
    dlc_iso_ago(3600, alpha_ts, sizeof(alpha_ts));
    dlc_iso_ago(1800, beta_ts, sizeof(beta_ts));
    TEST_CASE("catches: counts per gate, catches first, zero-catch gates named") {
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        ASSERT(dlc_run(&c) && dlc_ok(&c));
        ASSERT_STR_EQ(dlc_str(&c, "leaf"), DLC_PATH);
        ASSERT_STR_EQ(dlc_str(&c, "ledger"), ledger);
        ASSERT(dlc_bool(&c, "exists"));
        ASSERT_EQ(dlc_int(&c, "rows"), 8);
        ASSERT_EQ(dlc_int(&c, "malformed"), 1);
        ASSERT_EQ(dlc_int(&c, "kept"), 8);
        ASSERT_EQ(dlc_int(&c, "zero_catch_count"), 1);
        ASSERT(!dlc_bool(&c, "truncated"));
        const struct json_value *g = dlc_array(&c, "gates");
        ASSERT(g != NULL && g->num_children == 4);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[0], "gate"), "beta");
        ASSERT_EQ(dlc_entry_int(&g->children[0], "attempts"), 2);
        ASSERT_EQ(dlc_entry_int(&g->children[0], "catches"), 2);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[0], "last_catch_ts"), beta_ts);
        ASSERT_EQ(dlc_entry_int(&g->children[0], "last_catch_rc"), 2);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[1], "gate"), "alpha");
        ASSERT_EQ(dlc_entry_int(&g->children[1], "attempts"), 3);
        ASSERT_EQ(dlc_entry_int(&g->children[1], "catches"), 1);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[1], "last_catch_ts"), alpha_ts);
        ASSERT_EQ(dlc_entry_int(&g->children[1], "last_catch_rc"), 3);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[2], "gate"), "delta");
        ASSERT_EQ(dlc_entry_int(&g->children[2], "catches"), 1);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[3], "gate"), "gamma");
        ASSERT_EQ(dlc_entry_int(&g->children[3], "attempts"), 2);
        ASSERT_EQ(dlc_entry_int(&g->children[3], "catches"), 0);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[3], "last_catch_ts"), "");
        const struct json_value *z = dlc_array(&c, "zero_catch");
        ASSERT(z != NULL && z->num_children == 1);
        ASSERT_STR_EQ(json_get_str(&z->children[0]), "gamma");
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_since_narrow(const char *ledger)
{
    int failures = 0;
    struct dlc_call c;
    char since[DLC_TS_LEN + 1];
    TEST_CASE("catches: a newer since drops old rows, not honesty") {
        /* 30h-old beta row and the 40d-old delta row fall before 1 day ago */
        dlc_iso_ago(DLC_DAY_S, since, sizeof(since));
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "since", since);
        ASSERT(dlc_run(&c) && dlc_ok(&c));
        ASSERT_EQ(dlc_int(&c, "rows"), 8);
        ASSERT_EQ(dlc_int(&c, "kept"), 6);
        ASSERT_STR_EQ(dlc_str(&c, "since"), since);
        const struct json_value *g = dlc_array(&c, "gates");
        ASSERT(g != NULL && g->num_children == 3);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[0], "gate"), "beta");
        ASSERT_EQ(dlc_entry_int(&g->children[0], "attempts"), 1);
        ASSERT_EQ(dlc_entry_int(&g->children[0], "catches"), 1);
        ASSERT_EQ(dlc_int(&c, "zero_catch_count"), 1);
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_since_wide(const char *ledger)
{
    int failures = 0;
    struct dlc_call c;
    char since[DLC_TS_LEN + 1];
    TEST_CASE("catches: an older since admits the old catch as evidence") {
        /* 45 days ago keeps the 40d-old delta row in the table */
        dlc_iso_ago(45LL * DLC_DAY_S, since, sizeof(since));
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "since", since);
        ASSERT(dlc_run(&c) && dlc_ok(&c));
        ASSERT_EQ(dlc_int(&c, "kept"), 8);
        const struct json_value *g = dlc_array(&c, "gates");
        ASSERT(g != NULL && g->num_children == 4);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[3], "gate"), "gamma");
        ASSERT_EQ(dlc_int(&c, "zero_catch_count"), 1);
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_bad_since(const char *ledger)
{
    int failures = 0;
    struct dlc_call c;
    TEST_CASE("catches: a misshapen since is refused, never a silent unfilter") {
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "since", "2026-11-16");
        ASSERT(dlc_run(&c) && !dlc_ok(&c));
        ASSERT_STR_EQ(dlc_str(&c, "leaf"), DLC_PATH);
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_missing(const char *root)
{
    int failures = 0;
    struct dlc_call c;
    TEST_CASE("catches: a missing ledger is a true zero, never a guess") {
        char absent[1024];
        (void)snprintf(absent, sizeof(absent), "%s/definitely-absent.jsonl",
                       root);
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", absent);
        ASSERT(dlc_run(&c) && dlc_ok(&c));
        ASSERT_STR_EQ(dlc_str(&c, "ledger"), absent);
        ASSERT(!dlc_bool(&c, "exists"));
        ASSERT_EQ(dlc_int(&c, "rows"), 0);
        ASSERT_EQ(dlc_int(&c, "malformed"), 0);
        ASSERT_EQ(dlc_int(&c, "kept"), 0);
        ASSERT_EQ(dlc_int(&c, "zero_catch_count"), 0);
        ASSERT(!dlc_bool(&c, "truncated"));
        ASSERT(dlc_array(&c, "gates") != NULL &&
               dlc_array(&c, "gates")->num_children == 0);
        ASSERT(dlc_array(&c, "zero_catch") != NULL &&
               dlc_array(&c, "zero_catch")->num_children == 0);
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_limit(const char *ledger)
{
    int failures = 0;
    struct dlc_call c;
    TEST_CASE("catches: limit bounds the reply and reports the cut") {
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "limit", 2);
        ASSERT(dlc_run(&c) && dlc_ok(&c));
        const struct json_value *g = dlc_array(&c, "gates");
        ASSERT(g != NULL && g->num_children == 2);
        ASSERT_STR_EQ(dlc_entry_str(&g->children[0], "gate"), "beta");
        ASSERT_EQ(dlc_int(&c, "zero_catch_count"), 1);
        ASSERT(dlc_bool(&c, "truncated"));
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_bad_limit(const char *ledger)
{
    int failures = 0;
    struct dlc_call c;
    TEST_CASE("catches: an out-of-range limit is refused, never a silent clamp") {
        /* 0 is refused by the registry's shared integer rule before the
         * handler; 100000 passes that rule (1..1000000) and is refused by
         * the leaf's own 1..200 bound. Neither may yield a passed reply. */
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "limit", 0);
        ASSERT(!(dlc_run(&c) && dlc_ok(&c)));
        dlc_end(&c);
        dlc_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "limit", 100000);
        ASSERT(dlc_run(&c) && !dlc_ok(&c));
        dlc_end(&c);
    } TEST_END;
    return failures;
}

static int dlc_case_default_path(void)
{
    int failures = 0;
    struct dlc_call c;
    TEST_CASE("catches: no ledger key reads the driver's conventional path") {
        dlc_begin(&c);
        ASSERT(dlc_run(&c) && dlc_ok(&c));
        ASSERT_STR_EQ(dlc_str(&c, "ledger"),
                      ".cache/lint-timing/gate-catches.jsonl");
        /* Whatever that file holds here, the counts are honest integers
         * and the reply stays bounded; a missing file is the true-zero
         * case proven above. */
        ASSERT(dlc_int(&c, "rows") >= 0);
        ASSERT(dlc_int(&c, "zero_catch_count") >= 0);
        dlc_end(&c);
    } TEST_END;
    return failures;
}

/* ── impact routing: the feed's files select this group ───────────── */

static bool dlc_group_in(const char groups[][ZCL_DEVLOOP_GROUP_MAX],
                         size_t n, const char *want)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(groups[i], want) == 0)
            return true;
    }
    return false;
}

static int dlc_case_impact(void)
{
    int failures = 0;
    TEST_CASE("catches: each feed path selects its regression") {
        /* The writer's half stays routed to lint_run by the existing
         * shared rule; the reader's files select this group, and the
         * audited test translation unit is its own semantic-leaf floor. */
        static const struct { const char *path, *group; } cases[] = {
            {"tools/lint/lintc/run_report.c", "lint_run"},
            {"tools/command/native_dev_lint_catches.c", "devlintcatches"},
            {"tests/harness/src/test_devlintcatches.c", "test_devlintcatches"},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            const char *files[] = {cases[i].path};
            struct zcl_devloop_plan plan;
            ASSERT(zcl_devloop_plan_files(files, 1, &plan));
            ASSERT(dlc_group_in(plan.path_groups, plan.path_groups_len,
                                cases[i].group));
        }
    } TEST_END;
    return failures;
}

int test_devlintcatches(void);
int test_devlintcatches(void)
{
    int failures = 0;
    char root[512], ledger[1024];

    test_make_tmpdir(root, sizeof(root), "devlintcatches", "fixtures");
    (void)snprintf(ledger, sizeof(ledger), "%s/%s", root, DLC_LEDGER_NAME);
    if (!dlc_build_fixture(ledger)) {
        printf("test_devlintcatches: fixture ledger write failed: %s\n",
               strerror(errno));
        failures++;
    }
    failures += dlc_case_registered();
    failures += dlc_case_aggregate(ledger);
    failures += dlc_case_since_narrow(ledger);
    failures += dlc_case_since_wide(ledger);
    failures += dlc_case_missing(root);
    failures += dlc_case_limit(ledger);
    failures += dlc_case_bad_since(ledger);
    failures += dlc_case_bad_limit(ledger);
    failures += dlc_case_default_path();
    failures += dlc_case_impact();

    if (failures == 0) printf("test_devlintcatches: all passed\n");
    else printf("test_devlintcatches: %d FAILED\n", failures);
    return failures;
}
