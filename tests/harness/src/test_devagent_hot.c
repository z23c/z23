/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.hot (tools/command/native_devagent_hot.c).
 *
 * Runs against a fixture repository built here, not the checkout. It calls
 * the bound handler directly (as the CLI does after input validation), and
 * validates the input keys through the real registry. No case needs a
 * resident dev loop or spawns the test runner: every fixture file resolves to
 * no owning group.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"
#include "zutf8/zutf8.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVX_PATH "dev.agent.hot"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_hot.v1");
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
    zcl_native_handle_dev_agent_hot(&c->request, &c->reply);
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
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const struct json_value *dvx_arr(const struct dvx_call *c,
                                        const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_ARR ? v : NULL;
}

/* A repository with one commit, owned by this test. The leaf never runs git
 * itself; the repo exists so `cwd` points at a real checkout-shaped fixture
 * instead of the tree this test runs in. */
static bool dvx_fixture(const char *dir)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", NULL};
    const char *add[] = {"add", "--", "notes.txt", NULL};
    const char *commit[] = {"-c", "user.name=Z23 Test",
                            "-c", "user.email=z23-test@example.invalid",
                            "-c", "commit.gpgsign=false",
                            "commit", "-q", "-m", "base", NULL};
    return dvx_git(dir, init) &&
           dvx_write(dir, "notes.txt", "no rule owns this file\n") &&
           dvx_git(dir, add) && dvx_git(dir, commit);
}

int test_devagent_hot(void);
/* Seed a file the call must refuse and name the refusal expected for it. APFS
 * refuses a non-UTF-8 file name (EILSEQ), so that file cannot exist and the
 * call is refused as an absent file instead of as bad input. */
static bool dvx_seed_refused(const char *root, const char *name,
                             const char **want_code)
{
    *want_code = "BAD_INPUT";
    if (dvx_write(root, name, "/* unresolved */\n"))
        return true;
#if defined(__APPLE__)
    if (errno == EILSEQ && !zutf8_validate_n(name, strlen(name))) {
        *want_code = "FILE_NOT_FOUND";
        return true;
    }
#endif
    return false;
}

int test_devagent_hot(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_hot", "repo");

    TEST("hot: the leaf is registered and declares path, group, cwd") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "path") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "group") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        PASS();
    }

    TEST("hot: a call with no path is refused with BAD_INPUT") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    ASSERT(dvx_fixture(root));

    TEST("hot: a saved file no rule owns is UNRESOLVED, never a pass") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "path", "notes.txt");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "path"), "notes.txt");
        ASSERT_STR_EQ(dvx_str(&c, "group"), "");
        ASSERT_STR_EQ(dvx_str(&c, "mode"), "unresolved");
        ASSERT_STR_EQ(dvx_str(&c, "verdict"), "UNRESOLVED");
        ASSERT_EQ(dvx_int(&c, "groups_ran"), 0);
        ASSERT_EQ(dvx_int(&c, "groups_failed"), 0);
        ASSERT_EQ(dvx_int(&c, "self_skips"), 0);
        const struct json_value *next = dvx_arr(&c, "next");
        ASSERT(next != NULL && next->num_children == 1);
        ASSERT(strstr(json_get_str(&next->children[0]), "code tests") !=
               NULL);
        ASSERT(strstr(json_get_str(&next->children[0]), "notes.txt") !=
               NULL);
        dvx_end(&c);
        PASS();
    }

    TEST("hot: unresolved next input preserves foreign path text") {
        const char *paths[] = {"a\"b.c", "a\\n.c", "a\n\001.c", "a\xc3\xa9.c"};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            struct dvx_call c;
            struct json_value decoded;
            ASSERT(dvx_write(root, paths[i], "/* unresolved */\n"));
            dvx_begin(&c);
            (void)json_push_kv_str(&c.input, "cwd", root);
            (void)json_push_kv_str(&c.input, "path", paths[i]);
            ASSERT(dvx_run(&c) && dvx_ok(&c));
            const struct json_value *next = dvx_arr(&c, "next");
            ASSERT(next && next->num_children == 1);
            const char *command = json_get_str(&next->children[0]);
            const char *input = strstr(command, "--input='");
            ASSERT(input != NULL);
            input += strlen("--input='");
            size_t n = strlen(input);
            ASSERT(n > 1 && input[n - 1] == '\'');
            ASSERT(zutf8_validate_n(input, n - 1));
            json_init(&decoded);
            ASSERT(json_read(&decoded, input, n - 1));
            ASSERT_STR_EQ(json_get_str(json_get(&decoded, "path")), paths[i]);
            json_free(&decoded);
            dvx_end(&c);
        }
        char expanded[100];
        memset(expanded, 1, sizeof(expanded) - 1);
        expanded[sizeof(expanded) - 1] = '\0';
        const char *refused[] = {"a\xff.c", "a'b.c", expanded};
        for (size_t i = 0; i < 3; i++) {
            struct dvx_call c;
            const char *want_code;
            ASSERT(dvx_seed_refused(root, refused[i], &want_code));
            dvx_begin(&c);
            (void)json_push_kv_str(&c.input, "cwd", root);
            (void)json_push_kv_str(&c.input, "path", refused[i]);
            ASSERT(dvx_run(&c) && !dvx_ok(&c) && dvx_arr(&c, "next") == NULL);
            ASSERT_STR_EQ(c.reply.error.code, want_code);
            dvx_end(&c);
        }
        PASS();
    }
    TEST("hot: a group override that names nothing is UNRESOLVED") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "path", "notes.txt");
        (void)json_push_kv_str(&c.input, "group", "no_such_group_xyz");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "verdict"), "UNRESOLVED");
        ASSERT_STR_EQ(dvx_str(&c, "mode"), "unresolved");
        dvx_end(&c);
        PASS();
    }

    TEST("hot: elapsed_ms exists and mode is honest with no loop resident") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "path", "notes.txt");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        /* No resident dev loop watches a fresh fixture, so the only
         * honest modes are the runner path and the unresolved path. */
        ASSERT(dvx_int(&c, "elapsed_ms") >= 0);
        const char *mode = dvx_str(&c, "mode");
        ASSERT(strcmp(mode, "rebuild") == 0 ||
               strcmp(mode, "unresolved") == 0);
        dvx_end(&c);
        PASS();
    }

    TEST("hot: a path that was never saved is FILE_NOT_FOUND") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "path", "absent.c");
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "FILE_NOT_FOUND");
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_hot: all passed\n");
    else printf("test_devagent_hot: %d FAILED\n", failures);
    return failures;
}
