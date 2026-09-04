/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.situation (tools/command/native_devagent_situation.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_situation.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.situation is a dev-lane leaf and
 * an in-process call is exactly what the CLI does after input validation, so
 * the input keys are additionally validated through the real registry.
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

#define DVX_PATH "dev.agent.situation"

/* ── fixture helpers (deliberately local: this group owns its own rig) ──── */

/* Run one git command in `dir`. Never a shell: zcl_spawn_capture execs git
 * itself, which is the only process rail this tree allows. */
static bool dvx_git(const char *dir, const char *const args[])
{
    const char *argv[32];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    char out[8192];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

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
    zcl_command_reply_init(&c->reply, "zcl.agent_situation.v1");
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
    zcl_native_handle_dev_agent_situation(&c->request, &c->reply);
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

/* A repository with one commit on `main`, owned by this test. */
static bool dvx_fixture(const char *dir)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", NULL};
    const char *add[] = {"add", "--", "a.c", NULL};
    const char *commit[] = {"-c", "user.name=Z23 Test",
                            "-c", "user.email=z23-test@example.invalid",
                            "-c", "commit.gpgsign=false",
                            "commit", "-q", "-m", "base", NULL};
    return dvx_git(dir, init) && dvx_write(dir, "a.c", "int a(void){return 1;}\n") &&
           dvx_git(dir, add) && dvx_git(dir, commit);
}

static bool dvx_hex40(const char *s)
{
    if (!s || strlen(s) != 40)
        return false;
    for (const char *p = s; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
            return false;
    return true;
}

int test_devagent_situation(void);
int test_devagent_situation(void)
{
    int failures = 0;
    char root[512], linked[600];
    test_make_tmpdir(root, sizeof(root), "devagent_situation", "repo");
    (void)snprintf(linked, sizeof(linked), "%s-lane", root);
    (void)test_rm_rf_recursive(linked);

    TEST("situation: the leaf is registered and accepts cwd") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        PASS();
    }

    ASSERT(dvx_fixture(root));

    TEST("situation: a fresh repository owns its own checkout") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "situation"), "standalone");
        ASSERT(dvx_str(&c, "git_dir")[0] != '\0');
        ASSERT(dvx_str(&c, "git_common_dir")[0] != '\0');
        ASSERT(dvx_str(&c, "worktree")[0] != '\0');
        ASSERT_STR_EQ(dvx_str(&c, "branch"), "main");
        ASSERT(dvx_hex40(dvx_str(&c, "head")));
        /* The verdict must carry the shell test that produced it, so a reader
         * can rerun the decision instead of trusting the word. */
        ASSERT(strstr(dvx_str(&c, "test"), "git rev-parse --git-common-dir") !=
               NULL);
        dvx_end(&c);
        PASS();
    }

    TEST("situation: a linked worktree answers shared_checkout_lane") {
        const char *wt[] = {"worktree", "add", "-q", "-b", "lane", linked, NULL};
        ASSERT(dvx_git(root, wt));
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", linked);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "situation"), "shared_checkout_lane");
        /* The two paths are what decided it; they must differ, and both must
         * be reported so the caller can see WHY. */
        ASSERT(strcmp(dvx_str(&c, "git_dir"), dvx_str(&c, "git_common_dir")) !=
               0);
        ASSERT_STR_EQ(dvx_str(&c, "branch"), "lane");
        ASSERT(strstr(dvx_str(&c, "test"), "FALSE") != NULL);
        dvx_end(&c);
        PASS();
    }

    TEST("situation: a detached HEAD reports an empty branch, never HEAD") {
        const char *detach[] = {"checkout", "-q", "--detach", NULL};
        ASSERT(dvx_git(root, detach));
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "branch"), "");
        ASSERT(dvx_hex40(dvx_str(&c, "head")));
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(linked);
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_situation: all passed\n");
    else printf("test_devagent_situation: %d FAILED\n", failures);
    return failures;
}
