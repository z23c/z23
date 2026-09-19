/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.outcomes
 * (tools/command/native_devagent_outcomes.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_outcomes.c and nothing else. It is written
 * against a fixture ledger built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.outcomes is a dev-lane leaf
 * and an in-process call is exactly what the CLI does after input validation,
 * so the input keys are additionally validated through the real registry.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define DVX_PATH "dev.agent.outcomes"
#define DVX_CLOSING \
    "verdicts come from receipts; a model's own report is never evidence"

/* ── fixture helpers (deliberately local: this group owns its own rig) ──── */

static bool dvx_write(const char *dir, const char *rel, const char *text)
{
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) < 0)
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dvx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dvx_begin(struct dvx_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_outcomes.v1");
}

/* Validate through the REAL registry first, so a key the .def never declared
 * is caught here rather than passing in-process and failing from a shell. */
static bool dvx_run(struct dvx_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_agent_outcomes(&c->request, &c->reply);
    return true;
}

static void dvx_end(struct dvx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dvx_ok(const struct dvx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dvx_str(const struct dvx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dvx_int(const struct dvx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static const struct json_value *dvx_arr(const struct dvx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

/* The by_model entry naming `model`, or NULL when the leaf reported none. */
static const struct json_value *dvx_model(const struct dvx_call *c,
                                          const char *model)
{
    const struct json_value *arr = dvx_arr(c, "by_model");
    if (!arr)
        return NULL;
    for (size_t i = 0; i < arr->num_children; i++) {
        const struct json_value *e = &arr->children[i];
        const char *name = json_get_str(json_get(e, "model"));
        if (e->type == JSON_OBJ && name && strcmp(name, model) == 0)
            return e;
    }
    return NULL;
}

static int64_t dvx_entry_int(const struct json_value *e, const char *key)
{
    const struct json_value *v = json_get(e, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static double dvx_entry_real(const struct json_value *e, const char *key)
{
    const struct json_value *v = json_get(e, key);
    return v && v->type == JSON_REAL ? json_get_real(v) : -12345.0;
}

static bool dvx_rec_has(const struct dvx_call *c, const char *needle)
{
    const struct json_value *arr = dvx_arr(c, "recommendation");
    if (!arr)
        return false;
    for (size_t i = 0; i < arr->num_children; i++) {
        const char *s = json_get_str(&arr->children[i]);
        if (arr->children[i].type == JSON_STR && s && strcmp(s, needle) == 0)
            return true;
    }
    return false;
}

static const char *dvx_rec_last(const struct dvx_call *c)
{
    const struct json_value *arr = dvx_arr(c, "recommendation");
    if (!arr || arr->num_children == 0)
        return "";
    const struct json_value *last = &arr->children[arr->num_children - 1];
    return last->type == JSON_STR && json_get_str(last) ? json_get_str(last)
                                                       : "";
}

static void dvx_call_on(struct dvx_call *c, const char *ledger,
                        const char *model, const char *since)
{
    dvx_begin(c);
    if (ledger)
        (void)json_push_kv_str(&c->input, "ledger", ledger);
    if (model)
        (void)json_push_kv_str(&c->input, "model", model);
    if (since)
        (void)json_push_kv_str(&c->input, "since", since);
}

/* ── usage_log: per-event model usage (native_devagent_usage.c) ─────────── */

static bool dvx_mkdir(const char *path)
{
#if defined(_WIN32)
    return mkdir(path) == 0;
#else
    return mkdir(path, 0700) == 0;
#endif
}

static const struct json_value *dvx_usage(const struct dvx_call *c)
{
    const struct json_value *u = json_get(&c->reply.data, "usage");
    return u && u->type == JSON_OBJ ? u : NULL;
}

/* The usage by_model row for (format, model), or NULL. */
static const struct json_value *dvx_usage_model(const struct dvx_call *c,
                                                const char *format,
                                                const char *model)
{
    const struct json_value *u = dvx_usage(c);
    const struct json_value *arr = u ? json_get(u, "by_model") : NULL;
    for (size_t i = 0; arr && arr->type == JSON_ARR && i < arr->num_children;
         i++) {
        const struct json_value *e = &arr->children[i];
        if (strcmp(json_get_str(json_get(e, "format")), format) == 0 &&
            strcmp(json_get_str(json_get(e, "model")), model) == 0)
            return e;
    }
    return NULL;
}

static int64_t dvx_unreported(const struct json_value *row, const char *field)
{
    return dvx_entry_int(json_get(row, "unreported"), field);
}

static void dvx_usage_call(struct dvx_call *c, const char *ledger,
                           const char *usage_log, const char *model)
{
    dvx_call_on(c, ledger, model, NULL);
    (void)json_push_kv_str(&c->input, "usage_log", usage_log);
}

/* Muse host log: event ev-a twice (one event), ev-b without a cache_read
 * counter, one model_completed with no id, one malformed usage line. The
 * Claude transcript repeats msg_1 with a larger output count: the latest
 * line replaces, never adds. A symlink back to the Muse file is not
 * followed, so nothing is counted twice. */
static bool dvx_usage_fixture(const char *dir)
{
    char sub[1024];
    (void)snprintf(sub, sizeof(sub), "%s/muse", dir);
    if (!dvx_mkdir(sub))
        return false;
    bool ok = dvx_write(dir, "muse/session.jsonl",
        "{\"id\":\"ev-a\",\"recorded_at\":1789762861658881,\"payload\":{\"run_id\":\"r1\","
        "\"event\":{\"kind\":\"model_completed\",\"model\":\"m1\",\"usage\":"
        "{\"input_tokens\":1000,\"output_tokens\":50,\"cache_read_tokens\":800,"
        "\"cache_write_tokens\":0,\"reasoning_tokens\":10}}}}\n"
        "{\"id\":\"ev-a\",\"recorded_at\":1789762861658881,\"payload\":{\"run_id\":\"r1\","
        "\"event\":{\"kind\":\"model_completed\",\"model\":\"m1\",\"usage\":"
        "{\"input_tokens\":1000,\"output_tokens\":50,\"cache_read_tokens\":800,"
        "\"cache_write_tokens\":0,\"reasoning_tokens\":10}}}}\n"
        "{\"id\":\"ev-b\",\"recorded_at\":1789762900000000,\"payload\":{\"run_id\":\"r1\","
        "\"event\":{\"kind\":\"model_completed\",\"model\":\"m1\",\"usage\":"
        "{\"input_tokens\":500,\"output_tokens\":20,\"cache_write_tokens\":0}}}}\n"
        "{\"recorded_at\":1789762900000000,\"payload\":{\"event\":{\"kind\":"
        "\"model_completed\",\"model\":\"m1\",\"usage\":{\"input_tokens\":7}}}}\n"
        "{\"id\":\"ev-c\",\"payload\":{\"event\":{\"kind\":\"model_started\"}}}\n"
        "{\"usage\": broken\n");
    ok = ok && dvx_write(dir, "claude.jsonl",
        "{\"type\":\"user\",\"message\":{\"content\":\"usage\"}}\n"
        "{\"type\":\"assistant\",\"timestamp\":\"2026-09-19T01:02:03.000Z\","
        "\"message\":{\"id\":\"msg_1\",\"model\":\"claude-x\",\"usage\":"
        "{\"input_tokens\":10,\"output_tokens\":5,\"cache_read_input_tokens\":1000,"
        "\"cache_creation_input_tokens\":200}}}\n"
        "{\"type\":\"assistant\",\"timestamp\":\"2026-09-19T01:02:04.000Z\","
        "\"message\":{\"id\":\"msg_1\",\"model\":\"claude-x\",\"usage\":"
        "{\"input_tokens\":10,\"output_tokens\":7,\"cache_read_input_tokens\":1000,"
        "\"cache_creation_input_tokens\":200}}}\n");
    ok = ok && dvx_write(dir, "notes.txt", "{\"id\":\"x\",\"usage\":{}}\n");
#if !defined(_WIN32)
    char link[1024];
    (void)snprintf(link, sizeof(link), "%s/muse/again.jsonl", dir);
    char target[1024];
    (void)snprintf(target, sizeof(target), "%s/muse/session.jsonl", dir);
    ok = ok && symlink(target, link) == 0;
#endif
    return ok;
}

static int dvx_usage_checks(const char *root, const char *ledger)
{
    int failures = 0;
    char dir[1024];
    char absent[1024];
    (void)snprintf(dir, sizeof(dir), "%s/usage", root);
    (void)snprintf(absent, sizeof(absent), "%s/no-such-usage", root);

    TEST("usage: fixture builds") {
        ASSERT(dvx_mkdir(dir));
        ASSERT(dvx_usage_fixture(dir));
        PASS();
    }

    TEST("usage: events dedup by id, the latest line wins, unknowns stay "
         "unreported") {
        struct dvx_call c;
        dvx_usage_call(&c, ledger, dir, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *u = dvx_usage(&c);
        ASSERT(u != NULL);
        ASSERT_EQ(dvx_entry_int(u, "files"), 2);
        ASSERT_EQ(dvx_entry_int(u, "events"), 3);
        ASSERT_EQ(dvx_entry_int(u, "duplicate_lines"), 2);
        ASSERT_EQ(dvx_entry_int(u, "unkeyed"), 1);
        ASSERT_EQ(dvx_entry_int(u, "malformed"), 1);
        const struct json_value *m = dvx_usage_model(&c, "muse", "m1");
        ASSERT(m != NULL);
        ASSERT(json_get_bool(json_get(m, "input_includes_cache_read")));
        ASSERT_EQ(dvx_entry_int(m, "events"), 2);
        ASSERT_EQ(dvx_entry_int(m, "input_tokens"), 1500);
        ASSERT_EQ(dvx_entry_int(m, "output_tokens"), 70);
        ASSERT_EQ(dvx_entry_int(m, "cache_read_tokens"), 800);
        ASSERT_EQ(dvx_unreported(m, "cache_read_tokens"), 1);
        /* Muse input already contains its cache reads: uncached is
         * 1000 - 800 for ev-a, and unknown (not 500) for ev-b. */
        ASSERT_EQ(dvx_entry_int(m, "uncached_input_tokens"), 200);
        ASSERT_EQ(dvx_unreported(m, "uncached_input_tokens"), 1);
        const struct json_value *k = dvx_usage_model(&c, "claude", "claude-x");
        ASSERT(k != NULL);
        ASSERT(!json_get_bool(json_get(k, "input_includes_cache_read")));
        ASSERT_EQ(dvx_entry_int(k, "events"), 1);
        ASSERT_EQ(dvx_entry_int(k, "output_tokens"), 7);
        ASSERT_EQ(dvx_entry_int(k, "cache_read_tokens"), 1000);
        ASSERT_EQ(dvx_entry_int(k, "cache_write_tokens"), 200);
        ASSERT_EQ(dvx_entry_int(k, "uncached_input_tokens"), 10);
        ASSERT_EQ(dvx_unreported(k, "reasoning_tokens"), 1);
        const struct json_value *hours = json_get(u, "by_hour");
        ASSERT(hours && hours->type == JSON_ARR && hours->num_children == 2);
        ASSERT_STR_EQ(json_get_str(json_get(&hours->children[0], "hour")),
                      "2026-09-19T01");
        ASSERT_STR_EQ(json_get_str(json_get(&hours->children[1], "hour")),
                      "2026-09-18T20");
        dvx_end(&c);
        PASS();
    }

    TEST("usage: the same input read twice gives the same fold") {
        struct dvx_call a;
        struct dvx_call b;
        dvx_usage_call(&a, ledger, dir, NULL);
        dvx_usage_call(&b, ledger, dir, NULL);
        ASSERT(dvx_run(&a) && dvx_run(&b));
        ASSERT(dvx_ok(&a) && dvx_ok(&b));
        const struct json_value *ma = dvx_usage_model(&a, "muse", "m1");
        const struct json_value *mb = dvx_usage_model(&b, "muse", "m1");
        ASSERT(ma && mb);
        ASSERT_EQ(dvx_entry_int(ma, "input_tokens"),
                  dvx_entry_int(mb, "input_tokens"));
        ASSERT_EQ(dvx_entry_int(dvx_usage(&a), "events"),
                  dvx_entry_int(dvx_usage(&b), "events"));
        dvx_end(&a);
        dvx_end(&b);
        PASS();
    }

    TEST("usage: the model filter narrows usage too") {
        struct dvx_call c;
        dvx_usage_call(&c, ledger, dir, "claude-x");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_EQ(dvx_entry_int(dvx_usage(&c), "events"), 1);
        ASSERT(dvx_usage_model(&c, "muse", "m1") == NULL);
        dvx_end(&c);
        PASS();
    }

    TEST("usage: a usage_log that is not there is refused by name") {
        struct dvx_call c;
        dvx_usage_call(&c, ledger, absent, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "USAGE_LOG_NOT_FOUND");
        dvx_end(&c);
        PASS();
    }

    TEST("usage: without usage_log the reply carries no usage object") {
        struct dvx_call c;
        dvx_call_on(&c, ledger, NULL, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT(dvx_usage(&c) == NULL);
        dvx_end(&c);
        PASS();
    }

_test_next:;
    return failures;
}

int test_devagent_outcomes(void);
int test_devagent_outcomes(void)
{
    int failures = 0;
    char root[512];
    char ledger[1024];
    char ledger_b[1024];
    char absent[1024];
    test_make_tmpdir(root, sizeof(root), "devagent_outcomes", "ledger");
    (void)snprintf(ledger, sizeof(ledger), "%s/outcomes.jsonl", root);
    (void)snprintf(ledger_b, sizeof(ledger_b), "%s/docs.jsonl", root);
    (void)snprintf(absent, sizeof(absent), "%s/absent.jsonl", root);

    static const char *const rows_main =
        "{\"ts\":\"2026-09-04T02:25:37Z\",\"unit\":\"pace/a1\",\"model\":\"flash\","
        "\"verdict\":\"PASS\",\"files_changed\":1,\"groups_ran\":1,"
        "\"groups_failed\":0,\"completion_tokens\":22844,\"why\":\"\"}\n"
        "{\"ts\":\"2026-09-04T02:26:10Z\",\"unit\":\"pace/a2\",\"model\":\"flash\","
        "\"verdict\":\"PASS\",\"files_changed\":1,\"groups_ran\":1,"
        "\"groups_failed\":0,\"completion_tokens\":100,\"why\":\"\"}\n"
        "{\"ts\":\"2026-09-04T02:27:44Z\",\"unit\":\"pace/a3\",\"model\":\"flash\","
        "\"verdict\":\"PASS\",\"files_changed\":2,\"groups_ran\":1,"
        "\"groups_failed\":0,\"completion_tokens\":50,\"why\":\"\"}\n"
        "{\"ts\":\"2026-09-03T10:00:00Z\",\"unit\":\"pace/a4\",\"model\":\"flash\","
        "\"verdict\":\"NO_RECEIPT\",\"files_changed\":0,\"groups_ran\":0,"
        "\"groups_failed\":0,\"completion_tokens\":0,\"why\":\"rate_limited\"}\n"
        "{\"ts\":\"2026-09-04T02:25:37Z\",\"unit\":\"triage/b1\","
        "\"model\":\"glm-5.3\",\"verdict\":\"UNVERIFIED\",\"files_changed\":3,"
        "\"groups_ran\":0,\"groups_failed\":0,\"completion_tokens\":5000,"
        "\"why\":\"\"}\n"
        "{\"ts\":\"2026-09-04T02:28:01Z\",\"unit\":\"triage/b2\","
        "\"model\":\"glm-5.3\",\"verdict\":\"UNVERIFIED\",\"files_changed\":1,"
        "\"groups_ran\":0,\"groups_failed\":0,\"completion_tokens\":7000,"
        "\"why\":\"response_refused\"}\n"
        "this is not json\n"
        "\n";

    /* Three receipts for one model, none of them passing: the doc-only
     * routing this leaf exists to read off. */
    static const char *const rows_docs =
        "{\"ts\":\"2026-09-04T03:00:01Z\",\"unit\":\"doc/c1\","
        "\"model\":\"glm-5.3\",\"verdict\":\"UNVERIFIED\",\"files_changed\":1,"
        "\"groups_ran\":0,\"groups_failed\":0,\"completion_tokens\":10,"
        "\"why\":\"\"}\n"
        "{\"ts\":\"2026-09-04T03:01:02Z\",\"unit\":\"doc/c2\","
        "\"model\":\"glm-5.3\",\"verdict\":\"UNVERIFIED\",\"files_changed\":1,"
        "\"groups_ran\":0,\"groups_failed\":0,\"completion_tokens\":20,"
        "\"why\":\"\"}\n"
        "{\"ts\":\"2026-09-04T03:02:03Z\",\"unit\":\"doc/c3\","
        "\"model\":\"glm-5.3\",\"verdict\":\"UNVERIFIED\",\"files_changed\":1,"
        "\"groups_ran\":0,\"groups_failed\":0,\"completion_tokens\":30,"
        "\"why\":\"\"}\n";

    TEST("outcomes: the leaf is registered and accepts ledger, model, since") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "ledger") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "model") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since") != NULL);
        PASS();
    }

    ASSERT(dvx_write(root, "outcomes.jsonl", rows_main));
    ASSERT(dvx_write(root, "docs.jsonl", rows_docs));

    TEST("outcomes: six rows aggregate, one malformed line is counted") {
        struct dvx_call c;
        dvx_call_on(&c, ledger, NULL, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "ledger"), ledger);
        ASSERT_EQ(dvx_int(&c, "rows"), 6);
        ASSERT_EQ(dvx_int(&c, "malformed"), 1);
        const struct json_value *flash = dvx_model(&c, "flash");
        ASSERT(flash != NULL);
        ASSERT_EQ(dvx_entry_int(flash, "attempts"), 4);
        ASSERT_EQ(dvx_entry_int(flash, "pass"), 3);
        ASSERT_EQ(dvx_entry_int(flash, "no_receipt"), 1);
        ASSERT_EQ(dvx_entry_int(flash, "fail"), 0);
        double rate = dvx_entry_real(flash, "pass_rate");
        ASSERT(rate > 0.74 && rate < 0.76);
        ASSERT_EQ(dvx_entry_int(flash, "completion_tokens_total"), 22994);
        const struct json_value *glm = dvx_model(&c, "glm-5.3");
        ASSERT(glm != NULL);
        ASSERT_EQ(dvx_entry_int(glm, "attempts"), 2);
        ASSERT_EQ(dvx_entry_int(glm, "unverified"), 2);
        ASSERT_EQ(dvx_entry_int(glm, "pass"), 0);
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: a .75 model routes one-file units; receipts close the list") {
        struct dvx_call c;
        dvx_call_on(&c, ledger, NULL, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        /* pass_rate 0.75 clears the one-file bar even though the only named
         * failure class is rate_limited: the pass-rate rule reads first. */
        ASSERT(dvx_rec_has(&c, "flash: route one-file units with a pinned test"));
        /* Two attempts is not enough evidence to route on: no glm-5.3 line. */
        ASSERT(!dvx_rec_has(&c, "glm-5.3: route doc-only units"));
        ASSERT_STR_EQ(dvx_rec_last(&c), DVX_CLOSING);
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: three unverified receipts route doc-only units") {
        struct dvx_call c;
        dvx_call_on(&c, ledger_b, NULL, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "rows"), 3);
        ASSERT_EQ(dvx_int(&c, "malformed"), 0);
        const struct json_value *glm = dvx_model(&c, "glm-5.3");
        ASSERT(glm != NULL);
        ASSERT_EQ(dvx_entry_int(glm, "attempts"), 3);
        ASSERT_EQ(dvx_entry_int(glm, "unverified"), 3);
        ASSERT(dvx_rec_has(&c, "glm-5.3: route doc-only units"));
        ASSERT_STR_EQ(dvx_rec_last(&c), DVX_CLOSING);
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: since excludes older rows from the table, not the counts") {
        struct dvx_call c;
        dvx_call_on(&c, ledger, NULL, "2026-09-04T00:00:00Z");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        /* rows/malformed still describe the file that was read. */
        ASSERT_EQ(dvx_int(&c, "rows"), 6);
        ASSERT_EQ(dvx_int(&c, "malformed"), 1);
        /* The 09-03 NO_RECEIPT row falls out: flash is 3 for 3 now. */
        const struct json_value *flash = dvx_model(&c, "flash");
        ASSERT(flash != NULL);
        ASSERT_EQ(dvx_entry_int(flash, "attempts"), 3);
        ASSERT_EQ(dvx_entry_int(flash, "pass"), 3);
        double rate = dvx_entry_real(flash, "pass_rate");
        ASSERT(rate > 0.99 && rate < 1.01);
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: a model filter narrows the table") {
        struct dvx_call c;
        dvx_call_on(&c, ledger, "flash", NULL);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT(dvx_model(&c, "flash") != NULL);
        ASSERT(dvx_model(&c, "glm-5.3") == NULL);
        ASSERT_EQ(dvx_int(&c, "rows"), 6);
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: a call with no ledger at all is refused") {
        struct dvx_call c;
        dvx_call_on(&c, NULL, NULL, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: a ledger that is not there is refused by name") {
        struct dvx_call c;
        dvx_call_on(&c, absent, NULL, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "LEDGER_NOT_FOUND");
        dvx_end(&c);
        PASS();
    }

    TEST("outcomes: a misshapen since is refused, never silently ignored") {
        struct dvx_call c;
        dvx_call_on(&c, ledger, NULL, "yesterday");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    failures += dvx_usage_checks(root, ledger);

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_outcomes: all passed\n");
    else printf("test_devagent_outcomes: %d FAILED\n", failures);
    return failures;
}
