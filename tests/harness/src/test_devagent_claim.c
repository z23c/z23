/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.claim (tools/command/native_devagent_claim.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_claim.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.claim is a dev-lane leaf and
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

#define DVX_PATH "dev.agent.claim"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_claim.v1");
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
    zcl_native_handle_dev_agent_claim(&c->request, &c->reply);
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
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

/* Push one bounded array of paths onto the input under `key`. */
static bool dvx_push_files(struct dvx_call *c, const char *key,
                           const char *const paths[])
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
    ok = ok && json_push_kv(c ? &c->input : NULL, key, &arr);
    json_free(&arr);
    return ok;
}

/* One claim call from `dir`, run to completion. */
static void dvx_claim(struct dvx_call *c, const char *dir, const char *story,
                      const char *const files[], bool release)
{
    dvx_begin(c);
    (void)json_push_kv_str(&c->input, "cwd", dir);
    if (story)
        (void)json_push_kv_str(&c->input, "story", story);
    if (files)
        (void)dvx_push_files(c, "files", files);
    if (release)
        (void)json_push_kv_bool(&c->input, "release", true);
}

static bool dvx_fixture(const char *dir)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", NULL};
    const char *add[] = {"add", "--", "a.c", NULL};
    const char *commit[] = {"-c", "user.name=Z23 Test",
                            "-c", "user.email=z23-test@example.invalid",
                            "-c", "commit.gpgsign=false",
                            "commit", "-q", "-m", "base", NULL};
    return dvx_git(dir, init) &&
           dvx_write(dir, "a.c", "int a(void){return 1;}\n") &&
           dvx_git(dir, add) && dvx_git(dir, commit);
}

int test_devagent_claim(void);
int test_devagent_claim(void)
{
    int failures = 0;
    char one[512], two[600];
    test_make_tmpdir(one, sizeof(one), "devagent_claim", "repo");
    (void)snprintf(two, sizeof(two), "%s-lane", one);
    (void)test_rm_rf_recursive(two);

    static const char *const files_a[] = {"engine/a.c", NULL};
    static const char *const files_b[] = {"engine/b.c", NULL};
    static const char *const files_none[] = {NULL};

    TEST("claim: the leaf is registered and accepts its four keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "story") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "files") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "release") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        PASS();
    }

    ASSERT(dvx_fixture(one));
    {
        const char *wt[] = {"worktree", "add", "-q", "-b", "lane", two, NULL};
        ASSERT(dvx_git(one, wt));
    }

    TEST("claim: a first claim is recorded in the shared ledger") {
        struct dvx_call c;
        dvx_claim(&c, one, "hex-codec", files_a, false);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT(strstr(dvx_str(&c, "ledger"), "z23-agent-claims.jsonl") != NULL);
        ASSERT_EQ(dvx_int(&c, "live"), 1);
        const struct json_value *claimed = dvx_arr(&c, "claimed");
        ASSERT(claimed != NULL);
        ASSERT_EQ((long long)claimed->num_children, 1);
        dvx_end(&c);
        PASS();
    }

    TEST("claim: the SAME worktree re-claiming replaces its own line") {
        struct dvx_call c;
        dvx_claim(&c, one, "hex-codec", files_a, false);
        ASSERT(dvx_run(&c));
        /* Idempotent: a lane must be able to restate its claim without
         * conflicting with itself and without stacking a second line. */
        ASSERT(dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "live"), 1);
        dvx_end(&c);
        PASS();
    }

    TEST("claim: another worktree wanting the same file is refused by name") {
        struct dvx_call c;
        dvx_claim(&c, two, "other-story", files_a, false);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CLAIM_OVERLAP");
        const struct json_value *conflicts = dvx_arr(&c, "conflicts");
        ASSERT(conflicts != NULL);
        ASSERT_EQ((long long)conflicts->num_children, 1);
        const struct json_value *file =
            json_get(&conflicts->children[0], "file");
        const struct json_value *wt =
            json_get(&conflicts->children[0], "worktree");
        const struct json_value *story =
            json_get(&conflicts->children[0], "story");
        ASSERT(file && file->type == JSON_STR);
        ASSERT_STR_EQ(json_get_str(file), "engine/a.c");
        ASSERT(wt && wt->type == JSON_STR && json_get_str(wt)[0] != '\0');
        ASSERT(story && story->type == JSON_STR);
        ASSERT_STR_EQ(json_get_str(story), "hex-codec");
        dvx_end(&c);
        PASS();
    }

    TEST("claim: a disjoint claim from the other worktree is allowed") {
        struct dvx_call c;
        dvx_claim(&c, two, "other-story", files_b, false);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "live"), 2);
        dvx_end(&c);
        PASS();
    }

    TEST("claim: release frees this worktree's files for everyone else") {
        struct dvx_call c;
        dvx_claim(&c, one, "hex-codec", files_none, true);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "released"), 1);
        ASSERT_EQ(dvx_int(&c, "live"), 1);
        dvx_end(&c);

        struct dvx_call after;
        dvx_claim(&after, two, "other-story", files_a, false);
        ASSERT(dvx_run(&after));
        ASSERT(dvx_ok(&after));
        dvx_end(&after);
        PASS();
    }

    TEST("claim: a claim with no story is refused, not silently anonymous") {
        struct dvx_call c;
        dvx_claim(&c, one, NULL, files_a, false);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

    TEST("claim: a claim with no files is refused, not an empty reservation") {
        struct dvx_call c;
        dvx_claim(&c, one, "hex-codec", files_none, false);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(two);
    (void)test_rm_rf_recursive(one);
    if (failures == 0) printf("test_devagent_claim: all passed\n");
    else printf("test_devagent_claim: %d FAILED\n", failures);
    return failures;
}
