/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.triage (tools/command/native_devagent_triage.c).
 *
 * This file is the contract that one single-file unit must satisfy by editing
 * tools/command/native_devagent_triage.c and nothing else. It is written
 * against a fixture repository built here, never against the checkout it runs
 * in, so it proves behavior rather than the state of this machine. Do not
 * edit this file to make the implementation pass.
 *
 * It calls the bound handler DIRECTLY: dev.agent.triage is a dev-lane leaf and
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

#define DVX_PATH "dev.agent.triage"

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
    zcl_command_reply_init(&c->reply, "zcl.agent_triage.v1");
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
    zcl_native_handle_dev_agent_triage(&c->request, &c->reply);
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

/* The bin this run gave one branch, or "" when the branch is absent. */
static const char *dvx_bin_of(const struct dvx_call *c, const char *branch)
{
    const struct json_value *branches = dvx_arr(c, "branches");
    if (!branches)
        return "";
    for (size_t i = 0; i < branches->num_children; i++) {
        const struct json_value *name =
            json_get(&branches->children[i], "branch");
        if (!name || name->type != JSON_STR || !json_get_str(name) ||
            strcmp(json_get_str(name), branch) != 0)
            continue;
        const struct json_value *bin = json_get(&branches->children[i], "bin");
        return bin && bin->type == JSON_STR && json_get_str(bin)
                   ? json_get_str(bin)
                   : "";
    }
    return "";
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

/* One repository holding exactly the three shapes the bins exist for:
 *   merged   — branched off main and never moved (nothing ahead)
 *   ahead    — one clean new file, so it merges into main untouched
 *   conflict — edits the same line main then edited differently */
static bool dvx_fixture(const char *dir)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", NULL};
    const char *branch_merged[] = {"branch", "merged", NULL};
    const char *co_ahead[] = {"checkout", "-q", "-b", "ahead", NULL};
    const char *co_main[] = {"checkout", "-q", "main", NULL};
    const char *co_conflict[] = {"checkout", "-q", "-b", "conflict", NULL};
    return dvx_git(dir, init) &&
           dvx_write(dir, "a.c", "int a(void){return 1;}\n") &&
           dvx_commit(dir, "base") && dvx_git(dir, branch_merged) &&
           dvx_git(dir, co_ahead) &&
           dvx_write(dir, "new.c", "int n(void){return 0;}\n") &&
           dvx_commit(dir, "add new.c") && dvx_git(dir, co_main) &&
           dvx_git(dir, co_conflict) &&
           dvx_write(dir, "a.c", "int a(void){return 111;}\n") &&
           dvx_commit(dir, "conflict side") && dvx_git(dir, co_main) &&
           dvx_write(dir, "a.c", "int a(void){return 222;}\n") &&
           dvx_commit(dir, "main side");
}

int test_devagent_triage(void);
int test_devagent_triage(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "devagent_triage", "repo");

    TEST("triage: the leaf is registered and accepts its four keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "base") != NULL);
        ASSERT(spec->input_keys &&
               strstr(spec->input_keys, "max_age_days") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "limit") != NULL);
        PASS();
    }

    ASSERT(dvx_fixture(root));

    TEST("triage: each of the three shapes lands in its own bin") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_STR_EQ(dvx_str(&c, "leaf"), DVX_PATH);
        ASSERT_STR_EQ(dvx_str(&c, "base"), "main");
        /* Nothing ahead of the base is finished work, whatever it merges
         * like. */
        ASSERT_STR_EQ(dvx_bin_of(&c, "merged"), "delete");
        ASSERT_STR_EQ(dvx_bin_of(&c, "ahead"), "land");
        ASSERT_STR_EQ(dvx_bin_of(&c, "conflict"), "rebase");
        dvx_end(&c);
        PASS();
    }

    TEST("triage: main is never binned, and the counts add up") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *branches = dvx_arr(&c, "branches");
        ASSERT(branches != NULL);
        ASSERT_EQ((long long)branches->num_children, 3);
        ASSERT_STR_EQ(dvx_bin_of(&c, "main"), "");
        ASSERT_EQ(dvx_sub_int(&c, "counts", "land"), 1);
        ASSERT_EQ(dvx_sub_int(&c, "counts", "rebase"), 1);
        ASSERT_EQ(dvx_sub_int(&c, "counts", "delete"), 1);
        const struct json_value *truncated =
            json_get(&c.reply.data, "truncated");
        ASSERT(truncated && truncated->type == JSON_BOOL);
        ASSERT(!json_get_bool(truncated));
        dvx_end(&c);
        PASS();
    }

    TEST("triage: each row carries the numbers the bin was decided from") {
        struct dvx_call c;
        dvx_begin(&c);
        (void)json_push_kv_str(&c.input, "cwd", root);
        (void)json_push_kv_str(&c.input, "base", "main");
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        const struct json_value *branches = dvx_arr(&c, "branches");
        ASSERT(branches != NULL);
        for (size_t i = 0; i < branches->num_children; i++) {
            const struct json_value *row = &branches->children[i];
            const struct json_value *ahead = json_get(row, "ahead");
            const struct json_value *behind = json_get(row, "behind");
            const struct json_value *age =
                json_get(row, "last_commit_age_days");
            const struct json_value *clean = json_get(row, "merge_clean");
            const struct json_value *head = json_get(row, "head");
            ASSERT(ahead && ahead->type == JSON_INT);
            ASSERT(behind && behind->type == JSON_INT);
            ASSERT(age && age->type == JSON_INT && json_get_int(age) >= 0);
            ASSERT(clean && clean->type == JSON_BOOL);
            ASSERT(head && head->type == JSON_STR &&
                   strlen(json_get_str(head)) >= 4);
        }
        /* And the one branch that cannot merge says so. */
        for (size_t i = 0; i < branches->num_children; i++) {
            const struct json_value *name = json_get(&branches->children[i],
                                                     "branch");
            if (!name || strcmp(json_get_str(name), "conflict") != 0)
                continue;
            const struct json_value *clean =
                json_get(&branches->children[i], "merge_clean");
            ASSERT(clean && clean->type == JSON_BOOL && !json_get_bool(clean));
        }
        dvx_end(&c);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(root);
    if (failures == 0) printf("test_devagent_triage: all passed\n");
    else printf("test_devagent_triage: %d FAILED\n", failures);
    return failures;
}
