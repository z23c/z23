/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.start (tools/command/native_devagent_start.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_start.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.start is a dev-lane leaf and
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

#define DVX_PATH "dev.agent.start"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_start.v1");
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
    zcl_native_handle_dev_agent_start(&c->request, &c->reply);
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

static int64_t dvx_sub_int(const struct dvx_call *c, const char *obj,
                           const char *key)
{
    const struct json_value *o = json_get(&c->reply.data, obj);
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const char *dvx_sub_str(const struct dvx_call *c, const char *obj,
                               const char *key)
{
    const struct json_value *o = json_get(&c->reply.data, obj);
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static bool dvx_sub_bool(const struct dvx_call *c, const char *obj,
                         const char *key)
{
    const struct json_value *o = json_get(&c->reply.data, obj);
    const struct json_value *v = o ? json_get(o, key) : NULL;
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

/* One commit on `main`, then ONE dirty tracked file and ONE untracked file —
 * the two counts this leaf exists to report without an agent parsing
 * porcelain by hand. */
static bool dvx_fixture(const char *dir)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", NULL};
    const char *add[] = {"add", "--", "a.c", "b.c", NULL};
    const char *commit[] = {"-c", "user.name=Z23 Test",
                            "-c", "user.email=z23-test@example.invalid",
                            "-c", "commit.gpgsign=false",
                            "commit", "-q", "-m", "base", NULL};
    return dvx_git(dir, init) &&
           dvx_write(dir, "a.c", "int a(void){return 1;}\n") &&
           dvx_write(dir, "b.c", "int b(void){return 2;}\n") &&
           dvx_git(dir, add) && dvx_git(dir, commit) &&
           dvx_write(dir, "a.c", "int a(void){return 99;}\n") &&
           dvx_write(dir, "untracked.c", "int u(void){return 0;}\n");
}

int test_devagent_start(void);
int test_devagent_start(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_start", "repo");

    TEST("start: the leaf is registered and accepts cwd, files and base") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "files") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "base") != NULL);
        PASS();
    }

    ASSERT(dvx_fixture(root));

    TEST("start: one dirty tracked file and one untracked file are counted apart") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_EQ(dvx_sub_int(&c, "worktree", "dirty_tracked"), 1);
        ASSERT_EQ(dvx_sub_int(&c, "worktree", "untracked"), 1);
        /* No core.hooksPath is set in this fixture, so the hooks are not
         * armed — and saying so is the point: a lane that believes hooks are
         * armed when they are not commits past every gate. */
        ASSERT_STR_EQ(dvx_sub_str(&c, "worktree", "hooks_path"), "");
        ASSERT(!dvx_sub_bool(&c, "worktree", "hooks_armed"));
        dvx_end(&c);
        PASS();
    }

    TEST("start: the situation and its rules arrive in the same answer") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_sub_str(&c, "situation", "situation"), "standalone");
        ASSERT_STR_EQ(dvx_sub_str(&c, "situation", "branch"), "main");
        ASSERT(dvx_sub_str(&c, "situation", "git_common_dir")[0] != '\0');
        const struct json_value *rules = dvx_arr(&c, "rules");
        ASSERT(rules != NULL);
        ASSERT_EQ((long long)rules->num_children, 6);
        dvx_end(&c);
        PASS();
    }

    TEST("start: a base that does not exist here is reported, never invented") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        /* The fixture has no remote at all, so the default origin/main is
         * absent. That is an ordinary state, not a failure. */
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_sub_str(&c, "base", "ref"), "origin/main");
        ASSERT(!dvx_sub_bool(&c, "base", "base_known"));
        ASSERT_STR_EQ(dvx_sub_str(&c, "base", "head"), "");
        dvx_end(&c);
        PASS();
    }

    TEST("start: a base that DOES exist carries its head") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT(dvx_sub_bool(&c, "base", "base_known"));
        ASSERT_EQ((long long)strlen(dvx_sub_str(&c, "base", "head")), 40);
        dvx_end(&c);
        PASS();
    }

    TEST("start: each named file is reported present or absent") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        struct json_value files;
        json_init(&files);
        json_set_array(&files);
        struct json_value item;
        json_init(&item);
        json_set_str(&item, "a.c");
        ASSERT(json_push_back(&files, &item));
        json_set_str(&item, "does_not_exist.c");
        ASSERT(json_push_back(&files, &item));
        json_free(&item);
        ASSERT(json_push_kv(&c.input, "files", &files));
        json_free(&files);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *out = dvx_arr(&c, "files");
        ASSERT(out != NULL);
        ASSERT_EQ((long long)out->num_children, 2);
        const struct json_value *first = json_get(&out->children[0], "exists");
        const struct json_value *second = json_get(&out->children[1], "exists");
        ASSERT(first && first->type == JSON_BOOL && json_get_bool(first));
        ASSERT(second && second->type == JSON_BOOL && !json_get_bool(second));
        dvx_end(&c);
        PASS();
    }

    TEST("start: the next actions always name the inner-loop gate") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT(dvx_arr_has(dvx_arr(&c, "next"), "make lint-fast"));
        /* A standalone clone is not a lane, so the lane sentence must NOT be
         * offered here — advice for the other shape is worse than none. */
        ASSERT(!dvx_arr_has(dvx_arr(&c, "next"),
                            "commit on your lane branch; do not push"));
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_start: all passed\n");
    else printf("test_devagent_start: %d FAILED\n", failures);
    return failures;
}
