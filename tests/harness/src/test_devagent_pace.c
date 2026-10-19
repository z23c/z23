/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.pace (tools/command/native_devagent_pace.c).
 *
 * Runs against a fixture repository built here, not the checkout. It calls
 * the bound handler directly (as the CLI does after input validation), and
 * validates the input keys through the real registry.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVX_PATH "dev.agent.pace"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_pace.v1");
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
    zcl_native_handle_dev_agent_pace(&c->request, &c->reply);
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

static int64_t dvx_int(const struct dvx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

static bool dvx_bool(const struct dvx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool dvx_arr_has(const struct json_value *arr, const char *needle)
{
    if (!arr)
        return false;
    for (size_t i = 0; i < arr->num_children; i++) {
        const char *s = json_get_str(&arr->children[i]);
        if (arr->children[i].type == JSON_STR && s && strcmp(s, needle) == 0)
            return true;
    }
    return false;
}

/* Real opencode headless markers, each wrapped in the SGR reset the terminal
 * writer emits; a parser that matches before stripping sees none of them. */
#define E "\x1b[0m"
#define SHELL   E "$ " E
#define READ    E "\xe2\x86\x92 " E
#define WRITE   E "\xe2\x86\x90 " E
#define SEARCH  E "\xe2\x9c\xb1 " E

/* The handler runs on a 512 KiB stack, far below the 8 MiB default, so a
 * large automatic object in its frame faults on entry as it did from the CLI. */
static void *dvx_small_stack_main(void *arg)
{
    struct dvx_call *c = arg;
    zcl_native_handle_dev_agent_pace(&c->request, &c->reply);
    return NULL;
}

static bool dvx_run_small_stack(struct dvx_call *c)
{
    pthread_attr_t attr;
    pthread_t th;
    bool ok = false;
    if (pthread_attr_init(&attr) != 0)
        return false;
    if (pthread_attr_setstacksize(&attr, 512u * 1024u) == 0 &&
        pthread_create(&th, &attr, dvx_small_stack_main, c) == 0)
        ok = pthread_join(th, NULL) == 0;
    (void)pthread_attr_destroy(&attr);
    return ok;
}

static void dvx_call_on(struct dvx_call *c, const char *dir, const char *log)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "cwd", dir);
    if (log)
        (void)json_push_kv_str(&c->input, "log", log);
}

int test_devagent_pace(void);
int test_devagent_pace(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_pace", "logs");

    /* A run that read a great deal and wrote nothing — exits 0 and delivers
     * no work, the single most common way a lane reports a false success. */
    static const char *const log_nothing =
        "cwd=/work/z23-lane-x\n"
        READ "Read AGENTS.md\n"
        READ "Read docs/dev/DEVELOPING.md\n"
        SEARCH "Grep zcl_native_handle\n"
        SHELL "git status --short\n"
        SHELL "make -s lint-fast\n"
        "ALL TESTS PASSED\n"
        "rc=0 DONE\n";

    /* A run that DID write, but only after twelve tool calls. */
    static const char *const log_slow =
        READ "Read a1\n" READ "Read a2\n" READ "Read a3\n"
        READ "Read a4\n" READ "Read a5\n" READ "Read a6\n"
        SEARCH "Glob tools/**\n"
        READ "Read a7\n" READ "Read a8\n" READ "Read a9\n"
        SHELL "ls tools\n"
        SHELL "cat Makefile\n"
        WRITE "Edit tools/lint/run_lint.sh\n"
        SHELL "git commit -m fix\n"
        "rc=0 DONE\n";

    /* A run that wrote almost immediately, edited two distinct files (one of
     * them twice), committed once, and did NOT record an exit code. */
    static const char *const log_paced =
        READ "Read Makefile\n"
        WRITE "Write tools/x.c\n"
        WRITE "Edit tools/x.c\n"
        WRITE "Edit tools/y.c\n"
        SHELL "git commit -m work\n"
        "done\n";

    TEST("pace: the leaf is registered and accepts cwd and log") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "log") != NULL);
        PASS();
    }

    ASSERT(dvx_write(root, "nothing.out", log_nothing));
    ASSERT(dvx_write(root, "slow.out", log_slow));
    ASSERT(dvx_write(root, "paced.out", log_paced));

    TEST("pace: a run that wrote nothing says so, whatever it exited") {
        struct dvx_call c;
        dvx_call_on(&c, root, "nothing.out");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "verdict"), "WROTE_NOTHING");
        ASSERT(dvx_bool(&c, "no_edit"));
        ASSERT(!dvx_bool(&c, "pace_ok"));
        ASSERT_EQ(dvx_int(&c, "edits"), 0);
        ASSERT_EQ(dvx_int(&c, "tool_calls"), 5);
        /* With no edit at all, "calls before the first edit" is every call
         * that was made — never zero, which would read as "edited at once". */
        ASSERT_EQ(dvx_int(&c, "calls_before_first_edit"), 5);
        ASSERT_EQ(dvx_int(&c, "commits"), 0);
        ASSERT_EQ(dvx_int(&c, "rc"), 0);
        dvx_end(&c);
        PASS();
    }

    TEST("pace: an edit after the tenth tool call is a slow start") {
        struct dvx_call c;
        dvx_call_on(&c, root, "slow.out");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "verdict"), "SLOW_START");
        ASSERT(!dvx_bool(&c, "no_edit"));
        ASSERT(!dvx_bool(&c, "pace_ok"));
        ASSERT_EQ(dvx_int(&c, "edits"), 1);
        ASSERT_EQ(dvx_int(&c, "tool_calls"), 14);
        ASSERT_EQ(dvx_int(&c, "calls_before_first_edit"), 12);
        ASSERT_EQ(dvx_int(&c, "commits"), 1);
        ASSERT(dvx_arr_has(dvx_arr(&c, "files_edited"),
                           "tools/lint/run_lint.sh"));
        dvx_end(&c);
        PASS();
    }

    TEST("pace: an early edit is paced, and each file is listed once") {
        struct dvx_call c;
        dvx_call_on(&c, root, "paced.out");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "verdict"), "PACED");
        ASSERT(dvx_bool(&c, "pace_ok"));
        ASSERT_EQ(dvx_int(&c, "edits"), 3);
        ASSERT_EQ(dvx_int(&c, "calls_before_first_edit"), 1);
        ASSERT_EQ(dvx_int(&c, "commits"), 1);
        const struct json_value *edited = dvx_arr(&c, "files_edited");
        ASSERT(edited != NULL);
        ASSERT_EQ((long long)edited->num_children, 2);
        ASSERT(dvx_arr_has(edited, "tools/x.c"));
        ASSERT(dvx_arr_has(edited, "tools/y.c"));
        /* No "rc=<n> DONE" line was written, so the exit code is UNKNOWN and
         * must read as -1 — never as the number zero, which downstream means
         * "the run succeeded". */
        ASSERT_EQ(dvx_int(&c, "rc"), -1);
        dvx_end(&c);
        PASS();
    }

    TEST("pace: a log that is not there is refused by name") {
        struct dvx_call c;
        dvx_call_on(&c, root, "absent.out");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "LOG_UNREADABLE");
        dvx_end(&c);
        PASS();
    }

    TEST("pace: a call with no log at all is refused") {
        struct dvx_call c;
        dvx_call_on(&c, root, NULL);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    TEST("pace: no input at all returns a typed refusal on a small stack") {
        struct dvx_call c;
        dvx_begin(&c);
        c.request.input = NULL;
        ASSERT(dvx_run_small_stack(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    TEST("pace: an empty input object returns a typed refusal on a small stack") {
        struct dvx_call c;
        dvx_begin(&c);
        ASSERT(dvx_run_small_stack(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    TEST("pace: a valid log succeeds on a small stack") {
        struct dvx_call c;
        dvx_call_on(&c, root, "paced.out");
        ASSERT(dvx_run_small_stack(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "verdict"), "PACED");
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_pace: all passed\n");
    else printf("test_devagent_pace: %d FAILED\n", failures);
    return failures;
}
