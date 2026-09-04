/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.rules (tools/command/native_devagent_rules.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_rules.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.rules is a dev-lane leaf and
 * an in-process call is exactly what the CLI does after input validation, so
 * the input keys are additionally validated through the real registry.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVX_PATH "dev.agent.rules"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_rules.v1");
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
    zcl_native_handle_dev_agent_rules(&c->request, &c->reply);
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

static const struct json_value *dvx_arr(const struct dvx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

static const char *dvx_row_str(const struct json_value *row, const char *key)
{
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

/* Every topic the table must answer, in both situations. A topic answered in
 * only one of them is a hole an agent falls straight through. */
static const char *const dvx_topics[] = {
    "push_target", "commit_scope", "gate_command",
    "gate_skip",   "force_push",   "history",
};

int test_devagent_rules(void);
int test_devagent_rules(void)
{
    int failures = 0;

    TEST("rules: the leaf is registered and accepts cwd and situation") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "situation") != NULL);
        PASS();
    }

    TEST("rules: unfiltered, the whole table is twelve rows over two situations") {
        struct dvx_call c;
        dvx_begin(&c);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "source"), "engine/composition/agent_rules.def");
        const struct json_value *rules = dvx_arr(&c, "rules");
        ASSERT(rules != NULL);
        ASSERT_EQ((long long)rules->num_children, 12);
        const struct json_value *count = json_get(&c.reply.data, "count");
        ASSERT(count && count->type == JSON_INT);
        ASSERT_EQ(json_get_int(count), 12);
        const struct json_value *sits = dvx_arr(&c, "situations");
        ASSERT(sits != NULL);
        ASSERT_EQ((long long)sits->num_children, 2);
        /* The situation rows must carry the test that decides them, not just
         * their names — the name alone is unverifiable. */
        for (size_t i = 0; i < sits->num_children; i++) {
            ASSERT(dvx_row_str(&sits->children[i], "id")[0] != '\0');
            ASSERT(dvx_row_str(&sits->children[i], "test")[0] != '\0');
        }
        const struct json_value *topics = dvx_arr(&c, "topics");
        ASSERT(topics != NULL);
        ASSERT_EQ((long long)topics->num_children, 6);
        dvx_end(&c);
        PASS();
    }

    TEST("rules: a value is a machine answer and never contains a space") {
        struct dvx_call c;
        dvx_begin(&c);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *rules = dvx_arr(&c, "rules");
        ASSERT(rules != NULL);
        for (size_t i = 0; i < rules->num_children; i++) {
            const char *value = dvx_row_str(&rules->children[i], "value");
            ASSERT(value[0] != '\0');
            ASSERT(strchr(value, ' ') == NULL);
            /* and the whole reason travels with it */
            ASSERT(strlen(dvx_row_str(&rules->children[i], "say")) > 20);
        }
        dvx_end(&c);
        PASS();
    }

    for (int which = 0; which < 2; which++) {
        const char *situation = which == 0 ? "standalone" : "shared_checkout_lane";
        TEST(which == 0 ? "rules: standalone answers all six topics"
                        : "rules: shared_checkout_lane answers all six topics") {
            struct dvx_call c;
            dvx_begin(&c);
            (void)json_push_kv_str(&c.input, "situation", situation);
            ASSERT(dvx_run(&c));
            ASSERT(dvx_ok(&c));
            const struct json_value *rules = dvx_arr(&c, "rules");
            ASSERT(rules != NULL);
            ASSERT_EQ((long long)rules->num_children, 6);
            for (size_t t = 0; t < sizeof(dvx_topics) / sizeof(dvx_topics[0]);
                 t++) {
                bool found = false;
                for (size_t i = 0; i < rules->num_children; i++) {
                    if (strcmp(dvx_row_str(&rules->children[i], "id"),
                               dvx_topics[t]) != 0)
                        continue;
                    found = true;
                    ASSERT_STR_EQ(dvx_row_str(&rules->children[i], "when"),
                                  situation);
                }
                ASSERT(found);
            }
            /* situations is the whole table even when rules is filtered. */
            const struct json_value *sits = dvx_arr(&c, "situations");
            ASSERT(sits != NULL);
            ASSERT_EQ((long long)sits->num_children, 2);
            dvx_end(&c);
            PASS();
        }
    }

    TEST("rules: standalone pushes to origin/main and says why") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "situation", "standalone");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *rules = dvx_arr(&c, "rules");
        ASSERT(rules != NULL);
        bool checked = false;
        for (size_t i = 0; i < rules->num_children; i++) {
            if (strcmp(dvx_row_str(&rules->children[i], "id"), "push_target") != 0)
                continue;
            ASSERT_STR_EQ(dvx_row_str(&rules->children[i], "value"), "origin/main");
            ASSERT(strstr(dvx_row_str(&rules->children[i], "say"),
                          "shared integration blackboard") != NULL);
            checked = true;
        }
        ASSERT(checked);
        dvx_end(&c);
        PASS();
    }

    TEST("rules: a lane never pushes, and never stashes") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "situation", "shared_checkout_lane");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *rules = dvx_arr(&c, "rules");
        ASSERT(rules != NULL);
        bool push_seen = false, stash_seen = false;
        for (size_t i = 0; i < rules->num_children; i++) {
            const char *id = dvx_row_str(&rules->children[i], "id");
            if (strcmp(id, "push_target") == 0) {
                ASSERT_STR_EQ(dvx_row_str(&rules->children[i], "value"),
                              "lane_branch_no_push");
                push_seen = true;
            }
            if (strcmp(id, "commit_scope") == 0 &&
                strstr(dvx_row_str(&rules->children[i], "say"), "git stash"))
                stash_seen = true;
        }
        ASSERT(push_seen);
        ASSERT(stash_seen);
        dvx_end(&c);
        PASS();
    }

    TEST("rules: an unknown situation is refused, never answered empty") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "situation", "not_a_situation");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_SITUATION");
        dvx_end(&c);
        PASS();
    }

_test_next:;
    if (failures == 0) printf("test_devagent_rules: all passed\n");
    else printf("test_devagent_rules: %d FAILED\n", failures);
    return failures;
}
