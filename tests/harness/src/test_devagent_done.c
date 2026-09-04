/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.done (tools/command/native_devagent_done.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_done.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.done is a dev-lane leaf and
 * an in-process call is exactly what the CLI does after input validation, so
 * the input keys are additionally validated through the real registry.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVX_PATH "dev.agent.done"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_done.v1");
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
    zcl_native_handle_dev_agent_done(&c->request, &c->reply);
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

/* Fixture commits are made with commit.gpgsign=false on purpose: `%G?` then
 * prints N, which is exactly the unsigned state this leaf must refuse to
 * hand back. */
static bool dvx_commit(const char *dir, const char *message)
{
    const char *add[] = {"add", "-A", NULL};
    const char *commit[] = {"-c", "user.name=Z23 Test",
                            "-c", "user.email=z23-test@example.invalid",
                            "-c", "commit.gpgsign=false",
                            "commit", "-q", "-m", message, NULL};
    return dvx_git(dir, add) && dvx_git(dir, commit);
}

static bool dvx_fixture(const char *dir)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", NULL};
    return dvx_git(dir, init) &&
           dvx_write(dir, "a.c", "int a(void){return 1;}\n") &&
           dvx_commit(dir, "base");
}

int test_devagent_done(void);
int test_devagent_done(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_done", "repo");

    TEST("done: the leaf is registered and accepts cwd and base") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "base") != NULL);
        PASS();
    }

    ASSERT(dvx_fixture(root));

    TEST("done: sitting on main is named, however clean the tree is") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "branch"), "main");
        ASSERT_EQ((long long)strlen(dvx_str(&c, "head")), 40);
        ASSERT(!dvx_bool(&c, "ready"));
        ASSERT(dvx_arr_has(dvx_arr(&c, "reasons"), "on_main"));
        /* Every failing condition is named, not just the first one: this
         * branch is also zero commits ahead of itself. */
        ASSERT(dvx_arr_has(dvx_arr(&c, "reasons"), "no_commits_ahead"));
        dvx_end(&c);
        PASS();
    }

    TEST("done: an uncommitted change is a dirty tree, never a hand-back") {
        const char *branch[] = {"checkout", "-q", "-b", "lane", NULL};
        ASSERT(dvx_git(root, branch));
        ASSERT(dvx_write(root, "a.c", "int a(void){return 7;}\n"));
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT(!dvx_bool(&c, "ready"));
        ASSERT(!dvx_bool(&c, "tree_clean"));
        ASSERT(dvx_arr_has(dvx_arr(&c, "reasons"), "tree_dirty"));
        dvx_end(&c);
        PASS();
    }

    TEST("done: build output alone does not make the tree dirty") {
        ASSERT(dvx_commit(root, "lane work"));
        char build_dir[600];
        (void)snprintf(build_dir, sizeof(build_dir), "%s/build", root);
        ASSERT(platform_directory_ensure(build_dir, 0700));
        ASSERT(dvx_write(root, "build/artifact.o", "not source\n"));
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        /* An untracked object under build/ is build output. Calling it a
         * dirty tree would refuse every hand-back on a checkout that has
         * ever been built. */
        ASSERT(dvx_bool(&c, "tree_clean"));
        ASSERT(!dvx_arr_has(dvx_arr(&c, "reasons"), "tree_dirty"));
        dvx_end(&c);
        PASS();
    }

    TEST("done: an unsigned commit is listed, not summarized away") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *ahead = json_get(&c.reply.data, "ahead");
        ASSERT(ahead && ahead->type == JSON_INT);
        ASSERT_EQ(json_get_int(ahead), 1);
        const struct json_value *unsigned_commits = dvx_arr(&c, "unsigned");
        ASSERT(unsigned_commits != NULL);
        ASSERT_EQ((long long)unsigned_commits->num_children, 1);
        ASSERT(dvx_arr_has(dvx_arr(&c, "reasons"), "unsigned_commits"));
        ASSERT(!dvx_bool(&c, "ready"));
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_done: all passed\n");
    else printf("test_devagent_done: %d FAILED\n", failures);
    return failures;
}
