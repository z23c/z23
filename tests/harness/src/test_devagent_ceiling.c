/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.ceiling (tools/command/native_devagent_ceiling.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_ceiling.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.ceiling is a dev-lane leaf and
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

#define DVX_PATH "dev.agent.ceiling"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_ceiling.v1");
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
    zcl_native_handle_dev_agent_ceiling(&c->request, &c->reply);
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

static bool dvx_push_requested(struct dvx_call *c, const char *const paths[])
{
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&item);
    bool ok = true;
    for (size_t i = 0; paths[i] && ok; i++) {
        json_set_str(&item, paths[i]);
        ok = json_push_back(&arr, &item);
    }
    json_free(&item);
    ok = ok && json_push_kv(&c->input, "requested", &arr);
    json_free(&arr);
    return ok;
}

/* Does the refusal name this path with this reason? */
static bool dvx_violation(const struct dvx_call *c, const char *path,
                          const char *reason)
{
    const struct json_value *v = dvx_arr(c, "violations");
    if (!v)
        return false;
    for (size_t i = 0; i < v->num_children; i++) {
        const struct json_value *p = json_get(&v->children[i], "path");
        const struct json_value *r = json_get(&v->children[i], "reason");
        if (p && r && p->type == JSON_STR && r->type == JSON_STR &&
            strcmp(json_get_str(p), path) == 0 &&
            strcmp(json_get_str(r), reason) == 0)
            return true;
    }
    return false;
}

/* `count` lines of the form "line <n>\n", joined. */
static bool dvx_write_lines(const char *dir, const char *rel, int count,
                            const char *tag)
{
    char *text = malloc((size_t)count * 32u + 1u);
    if (!text)
        return false;
    size_t used = 0;
    for (int i = 0; i < count; i++) {
        int n = snprintf(text + used, (size_t)count * 32u + 1u - used,
                         "%s %d\n", tag, i);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    text[used] = '\0';
    bool ok = dvx_write(dir, rel, text);
    free(text);
    return ok;
}

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
    return dvx_git(dir, init) && dvx_write_lines(dir, "big.c", 100, "old") &&
           dvx_write_lines(dir, "small.c", 40, "small") &&
           dvx_write_lines(dir, "other.c", 40, "other") &&
           dvx_commit(dir, "base");
}

int test_devagent_ceiling(void);
int test_devagent_ceiling(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_ceiling", "repo");

    static const char *const want_small[] = {"small.c", NULL};
    static const char *const want_big[] = {"big.c", NULL};

    TEST("ceiling: the leaf is registered and accepts its four keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "base") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "requested") != NULL);
        ASSERT(spec->input_keys &&
               strstr(spec->input_keys, "ceiling_lines") != NULL);
        PASS();
    }

    ASSERT(dvx_fixture(root));

    TEST("ceiling: a small edit to the file that was asked for passes") {
        /* Ten lines appended to small.c: 10 added, 0 deleted. */
        ASSERT(dvx_write_lines(root, "small.c", 40, "small"));
        {
            char path[700];
            (void)snprintf(path, sizeof(path), "%s/small.c", root);
            FILE *f = fopen(path, "ab");
            ASSERT(f != NULL);
            for (int i = 0; i < 10; i++)
                (void)fprintf(f, "added %d\n", i);
            ASSERT(fclose(f) == 0);
        }
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_push_requested(&c, want_small));
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "status"), "WITHIN_CEILING");
        ASSERT_EQ(dvx_sub_int(&c, "summary", "changed"), 1);
        ASSERT_EQ(dvx_sub_int(&c, "summary", "unrequested"), 0);
        ASSERT_EQ(dvx_sub_int(&c, "summary", "rewrites"), 0);
        ASSERT_EQ(dvx_sub_int(&c, "summary", "over_ceiling"), 0);
        dvx_end(&c);
        PASS();
    }

    TEST("ceiling: a file nobody asked for is named as the violation") {
        {
            char path[700];
            (void)snprintf(path, sizeof(path), "%s/other.c", root);
            FILE *f = fopen(path, "ab");
            ASSERT(f != NULL);
            (void)fprintf(f, "sneaky\n");
            ASSERT(fclose(f) == 0);
        }
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_push_requested(&c, want_small));
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CEILING_EXCEEDED");
        ASSERT_STR_EQ(dvx_str(&c, "status"), "CEILING_EXCEEDED");
        ASSERT(dvx_violation(&c, "other.c", "unrequested"));
        /* The whole measurement still travels with the refusal — a refusal
         * that hides the numbers cannot be argued with. */
        ASSERT_EQ(dvx_sub_int(&c, "summary", "changed"), 2);
        ASSERT_EQ(dvx_sub_int(&c, "summary", "unrequested"), 1);
        dvx_end(&c);
        PASS();
    }

    TEST("ceiling: replacing a file wholesale is a rewrite, not an edit") {
        const char *restore[] = {"checkout", "-q", "--", ".", NULL};
        ASSERT(dvx_git(root, restore));
        /* 100 lines at base, all 100 deleted and 200 new ones written. */
        ASSERT(dvx_write_lines(root, "big.c", 200, "new"));
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        (void)json_push_kv_int(&c.input, "ceiling_lines", 100000);
        ASSERT(dvx_push_requested(&c, want_big));
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CEILING_EXCEEDED");
        ASSERT(dvx_violation(&c, "big.c", "rewrite"));
        ASSERT_EQ(dvx_sub_int(&c, "summary", "rewrites"), 1);
        /* The ceiling was raised out of the way on purpose, so `rewrite` is
         * the ONLY thing that fired. */
        ASSERT_EQ(dvx_sub_int(&c, "summary", "over_ceiling"), 0);
        ASSERT(!dvx_violation(&c, "big.c", "over_ceiling"));
        dvx_end(&c);
        PASS();
    }

    TEST("ceiling: a change larger than the per-file ceiling is refused") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        (void)json_push_kv_int(&c.input, "ceiling_lines", 80);
        ASSERT(dvx_push_requested(&c, want_big));
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT(dvx_violation(&c, "big.c", "over_ceiling"));
        dvx_end(&c);
        PASS();
    }

    TEST("ceiling: a call with no requested scope is refused, never allowed") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_ceiling: all passed\n");
    else printf("test_devagent_ceiling: %d FAILED\n", failures);
    return failures;
}
