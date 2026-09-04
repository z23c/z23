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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_outcomes: all passed\n");
    else printf("test_devagent_outcomes: %d FAILED\n", failures);
    return failures;
}
