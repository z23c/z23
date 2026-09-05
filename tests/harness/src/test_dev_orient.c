/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.orient (tools/command/native_dev_orient.c) and for
 * the gate that keeps its rows honest (tools/lint/check_orient_facts.sh).
 *
 * The leaf half calls the bound handler DIRECTLY — the leaf is a dev-lane
 * leaf and an in-process call is exactly what the CLI does after input
 * validation — but every input first crosses the REAL registry validator, so
 * a key the .def never declared fails here rather than only from a shell.
 *
 * The gate half builds a fixture facts tree in the test's own temp dir and
 * runs the checker against it. It asserts the property that matters: a row
 * whose anchor no longer exists in its file FAILS. A gate that only ever
 * sees true rows has never been shown to reject a false one.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVO_PATH "dev.agent.orient"

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dvo_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dvo_begin(struct dvo_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DVO_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_orient.v1");
}

static bool dvo_run(struct dvo_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_orient(&c->request, &c->reply);
    return true;
}

static void dvo_end(struct dvo_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dvo_ok(const struct dvo_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dvo_str(const struct dvo_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static long long dvo_int(const struct dvo_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const struct json_value *dvo_arr(const struct dvo_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

static const char *dvo_row_str(const struct json_value *row, const char *key)
{
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

/* The topics the table must answer. A named topic that vanished is a map an
 * agent will go re-derive by hand, which is the whole cost this removes. */
static const char *const dvo_required_topics[] = {
    "landing.proof", "landing.queue", "lint.gates",
    "tests.routing", "fleet.board",   "fleet.swarm",
    "naming",
};
#define DVO_REQUIRED_COUNT                                                   \
    (sizeof(dvo_required_topics) / sizeof(dvo_required_topics[0]))

static bool dvo_topics_contain(const struct json_value *topics,
                               const char *want)
{
    for (size_t i = 0; i < topics->num_children; i++) {
        if (strcmp(dvo_row_str(&topics->children[i], "topic"), want) == 0)
            return true;
    }
    return false;
}

/* ── the gate half: a fixture facts tree the checker is run against ─────── */

static bool dvo_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    (void)fputs(text, f);
    return fclose(f) == 0;
}

/* Run the real gate over a fixture facts dir. Returns its exit status. The
 * dir travels in the environment the checker documents, so nothing about the
 * gate is stubbed or re-implemented here: this is the script the umbrella
 * runs. */
static int dvo_run_checker(const char *facts_dir)
{
    const char *const argv[] = {"./tools/lint/check_orient_facts.sh", NULL};
    char out[4096];
    int rc;

    if (setenv("ZCL_ORIENT_FACTS_DIR", facts_dir, 1) != 0)
        return -1;
    rc = zcl_spawn_capture(argv, out, sizeof(out), 60000);
    (void)unsetenv("ZCL_ORIENT_FACTS_DIR");
    return rc;
}

int test_dev_orient(void);
int test_dev_orient(void)
{
    int failures = 0;

    TEST("orient: the leaf is registered and declares topic and query") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVO_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "topic") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "query") != NULL);
        PASS();
    }

    TEST("orient: with no input it lists every topic with a nonzero count") {
        struct dvo_call c;
        dvo_begin(&c);
        ASSERT(dvo_run(&c));
        ASSERT(dvo_ok(&c));
        ASSERT_STR_EQ(dvo_str(&c, "leaf"), DVO_PATH);
        ASSERT_STR_EQ(dvo_str(&c, "source"),
                      "engine/composition/facts/index.def");
        ASSERT_STR_EQ(dvo_str(&c, "mode"), "topics");

        const struct json_value *topics = dvo_arr(&c, "topics");
        ASSERT(topics != NULL);
        ASSERT_EQ((long long)topics->num_children,
                  dvo_int(&c, "total_topics"));
        for (size_t i = 0; i < DVO_REQUIRED_COUNT; i++)
            ASSERT(dvo_topics_contain(topics, dvo_required_topics[i]));

        long long summed = 0;
        for (size_t i = 0; i < topics->num_children; i++) {
            const struct json_value *rows =
                json_get(&topics->children[i], "rows");
            ASSERT(rows && rows->type == JSON_INT);
            ASSERT(json_get_int(rows) > 0);
            ASSERT(dvo_row_str(&topics->children[i], "blurb")[0] != '\0');
            summed += json_get_int(rows);
        }
        /* The listing is derived from the rows, so it cannot disagree. */
        ASSERT_EQ(summed, dvo_int(&c, "total_rows"));
        ASSERT(dvo_int(&c, "total_rows") >= 40);

        /* The human view has one line per topic and nothing else. */
        const struct json_value *lines = dvo_arr(&c, "lines");
        ASSERT(lines != NULL);
        ASSERT_EQ((long long)lines->num_children,
                  (long long)topics->num_children);
        ASSERT_EQ(dvo_int(&c, "count"), 0);
        dvo_end(&c);
        PASS();
    }

    TEST("orient: one topic returns that topic's rows, fully populated") {
        struct dvo_call c;
        dvo_begin(&c);
        (void)json_push_kv_str(&c.input, "topic", "landing.proof");
        ASSERT(dvo_run(&c));
        ASSERT(dvo_ok(&c));
        ASSERT_STR_EQ(dvo_str(&c, "mode"), "topic");
        ASSERT_STR_EQ(dvo_str(&c, "topic"), "landing.proof");

        const struct json_value *facts = dvo_arr(&c, "facts");
        ASSERT(facts != NULL);
        ASSERT(facts->num_children > 0);
        ASSERT_EQ((long long)facts->num_children, dvo_int(&c, "count"));
        for (size_t i = 0; i < facts->num_children; i++) {
            const struct json_value *row = &facts->children[i];
            ASSERT_STR_EQ(dvo_row_str(row, "topic"), "landing.proof");
            ASSERT(dvo_row_str(row, "key")[0] != '\0');
            /* A claim without a path and an anchor is not a fact. */
            ASSERT(strlen(dvo_row_str(row, "claim")) > 12);
            ASSERT(strlen(dvo_row_str(row, "claim")) <= 160);
            ASSERT(dvo_row_str(row, "path")[0] != '\0');
            ASSERT(strlen(dvo_row_str(row, "anchor")) <= 80);
            ASSERT(dvo_row_str(row, "anchor")[0] != '\0');
        }
        /* The topic listing stays complete even when one topic was asked for. */
        const struct json_value *topics = dvo_arr(&c, "topics");
        ASSERT(topics != NULL);
        ASSERT_EQ((long long)topics->num_children,
                  dvo_int(&c, "total_topics"));
        dvo_end(&c);
        PASS();
    }

    TEST("orient: query filters across topics and matches key, claim, path") {
        struct dvo_call c;
        dvo_begin(&c);
        (void)json_push_kv_str(&c.input, "query", "anchor-that-matches-nothing");
        ASSERT(dvo_run(&c));
        /* An empty result is a TRUE answer, not a failure. */
        ASSERT(dvo_ok(&c));
        ASSERT_STR_EQ(dvo_str(&c, "mode"), "query");
        ASSERT_EQ(dvo_int(&c, "count"), 0);
        ASSERT_EQ(dvo_int(&c, "matched"), 0);
        dvo_end(&c);

        dvo_begin(&c);
        (void)json_push_kv_str(&c.input, "query", "Makefile");
        ASSERT(dvo_run(&c));
        ASSERT(dvo_ok(&c));
        const struct json_value *facts = dvo_arr(&c, "facts");
        ASSERT(facts != NULL);
        ASSERT(facts->num_children > 0);
        for (size_t i = 0; i < facts->num_children; i++) {
            const struct json_value *row = &facts->children[i];
            /* every returned row really does mention the query somewhere */
            ASSERT(strstr(dvo_row_str(row, "path"), "Makefile") != NULL ||
                   strstr(dvo_row_str(row, "claim"), "Makefile") != NULL ||
                   strstr(dvo_row_str(row, "key"), "Makefile") != NULL);
        }
        ASSERT_EQ((long long)facts->num_children, dvo_int(&c, "count"));
        dvo_end(&c);
        PASS();
    }

    TEST("orient: query is case-insensitive and composes with topic") {
        struct dvo_call c;
        dvo_begin(&c);
        (void)json_push_kv_str(&c.input, "topic", "lint.gates");
        (void)json_push_kv_str(&c.input, "query", "MAKEFILE");
        ASSERT(dvo_run(&c));
        ASSERT(dvo_ok(&c));
        const struct json_value *facts = dvo_arr(&c, "facts");
        ASSERT(facts != NULL);
        ASSERT(facts->num_children > 0);
        for (size_t i = 0; i < facts->num_children; i++)
            ASSERT_STR_EQ(dvo_row_str(&facts->children[i], "topic"),
                          "lint.gates");
        dvo_end(&c);
        PASS();
    }

    TEST("orient: an undeclared topic is refused by name, never emptied") {
        struct dvo_call c;
        dvo_begin(&c);
        (void)json_push_kv_str(&c.input, "topic", "landing.proofs");
        ASSERT(dvo_run(&c));
        ASSERT(!dvo_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_TOPIC");
        ASSERT(strstr(c.reply.error.message, "landing.proofs") != NULL);
        /* and it says what DOES exist, so the caller needs no second call */
        ASSERT(strstr(c.reply.error.message, "landing.proof") != NULL);
        dvo_end(&c);
        PASS();
    }

    TEST("orient: the banner counts the same table the leaf renders") {
        char banner[192];
        struct dvo_call c;
        char needle[64];

        zcl_dev_orient_banner(banner, sizeof(banner));
        dvo_begin(&c);
        ASSERT(dvo_run(&c));
        ASSERT(dvo_ok(&c));
        (void)snprintf(needle, sizeof(needle), "%lld rows",
                       dvo_int(&c, "total_rows"));
        ASSERT(strstr(banner, needle) != NULL);
        ASSERT(strstr(banner, "dev agent orient") != NULL);
        dvo_end(&c);
        PASS();
    }

    TEST("gate: a row whose anchor is gone from its file FAILS the checker") {
        char dir[512];
        char index[600];
        char topic[600];

        test_make_tmpdir(dir, sizeof(dir), "dev_orient", "facts");
        (void)snprintf(index, sizeof(index), "%s/index.def", dir);
        (void)snprintf(topic, sizeof(topic), "%s/t_fixture.def", dir);

        ASSERT(dvo_write(index, "ZCL_FACT_TOPIC(\"t.fixture\", \"blurb\")\n"
                                "#include \"t_fixture.def\"\n"));

        /* A true row passes. */
        ASSERT(dvo_write(topic,
                         "ZCL_FACT(\"t.fixture\", \"true_row\",\n"
                         "         \"The lint umbrella's gate list lives in "
                         "the Makefile.\",\n"
                         "         \"Makefile\",\n"
                         "         \"LINT_GATES :=\")\n"));
        ASSERT_EQ(dvo_run_checker(dir), 0);

        /* The same row with an anchor that is not in that file FAILS. */
        ASSERT(dvo_write(topic,
                         "ZCL_FACT(\"t.fixture\", \"stale_row\",\n"
                         "         \"A claim whose anchor has moved out of "
                         "the file it names.\",\n"
                         "         \"Makefile\",\n"
                         "         \"ZZ_NO_SUCH_ANCHOR_IN_THE_MAKEFILE\")\n"));
        ASSERT_EQ(dvo_run_checker(dir), 1);

        /* So does a row naming a file that does not exist. */
        ASSERT(dvo_write(topic,
                         "ZCL_FACT(\"t.fixture\", \"gone_file\",\n"
                         "         \"A claim about a file that was "
                         "deleted.\",\n"
                         "         \"no/such/file/at/all.c\",\n"
                         "         \"anything\")\n"));
        ASSERT_EQ(dvo_run_checker(dir), 1);

        /* And a row claiming a topic the index never declared. */
        ASSERT(dvo_write(topic,
                         "ZCL_FACT(\"t.undeclared\", \"drifted\",\n"
                         "         \"A row that drifted into a topic nobody "
                         "declared.\",\n"
                         "         \"Makefile\",\n"
                         "         \"LINT_GATES :=\")\n"));
        ASSERT_EQ(dvo_run_checker(dir), 1);

        /* Scan floor: zero rows must never be reported as success. */
        ASSERT(dvo_write(topic, "\n"));
        ASSERT_EQ(dvo_run_checker(dir), 1);
        test_rm_rf_recursive(dir);
        PASS();
    }

_test_next:;
    if (failures == 0) printf("test_dev_orient: all passed\n");
    else printf("test_dev_orient: %d FAILED\n", failures);
    return failures;
}
