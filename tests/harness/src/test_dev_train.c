/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.train.* (tools/command/native_dev_train_command.c).
 *
 * Builds a temporary bare "origin" plus a main checkout and three source
 * clones, then drives the four handlers directly (in-process, the way the
 * CLI calls them after input validation) against that fixture — never
 * against the real checkout this test runs in.
 *
 * The fixture's checked-out Makefile defines worktree-prime,
 * docs-capability-inventory, and docs-api-reference as no-ops: dev.train.build
 * calls exactly those targets, and a fixture repository has none of the real
 * tree's vendor/doc machinery to run them for real.
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

/* ── fixture helpers ──────────────────────────────────────────────────── */

static bool dvt_git(const char *dir, const char *const args[])
{
    const char *argv[32];
    size_t n = 0;
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    char out[8192];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

static bool dvt_git_capture(const char *dir, const char *const args[],
                            char *out, size_t cap)
{
    const char *argv[32];
    size_t n = 0;
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, cap, 30000) == 0;
}

static bool dvt_write(const char *dir, const char *rel, const char *text)
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

static bool dvt_commit(const char *dir, const char *message)
{
    const char *add[] = {"add", "-A", NULL};
    const char *commit[] = {"-c", "user.name=Z23 Test",
                            "-c", "user.email=z23-test@example.invalid",
                            "-c", "commit.gpgsign=false",
                            "commit", "-q", "-m", message, NULL};
    return dvt_git(dir, add) && dvt_git(dir, commit);
}

static bool dvt_head(const char *dir, char sha[41])
{
    const char *args[] = {"rev-parse", "HEAD", NULL};
    char out[128];
    if (!dvt_git_capture(dir, args, out, sizeof(out)))
        return false;
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    if (strlen(out) != 40)
        return false;
    memcpy(sha, out, 41);
    return true;
}

/* The fixture Makefile: dev.train.build's only non-git dependency. Its
 * three targets are exactly the ones the handler calls; each is a no-op so
 * the fixture never needs the real tree's vendor/doc machinery. */
static const char *const dvt_makefile =
    "worktree-prime:\n\t@true\n\n"
    "docs-capability-inventory:\n\t@true\n\n"
    "docs-api-reference:\n\t@true\n";

static bool dvt_fixture_root(const char *root, const char *bare)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q",
                          root, NULL};
    if (!dvt_git(NULL, init))
        return false;
    if (!dvt_write(root, "shared.txt", "line1\n") ||
        !dvt_write(root, "other.txt", "o\n") ||
        !dvt_write(root, "Makefile", dvt_makefile) ||
        !dvt_commit(root, "base"))
        return false;
    const char *bare_init[] = {"-c", "init.defaultBranch=main", "init", "-q",
                              "--bare", bare, NULL};
    if (!dvt_git(NULL, bare_init))
        return false;
    const char *remote[] = {"remote", "add", "origin", bare, NULL};
    const char *push[] = {"push", "-q", "origin", "main", NULL};
    const char *fetch[] = {"fetch", "-q", "origin", NULL};
    return dvt_git(root, remote) && dvt_git(root, push) &&
           dvt_git(root, fetch);
}

static bool dvt_clone(const char *bare, const char *dest)
{
    const char *args[] = {"clone", "-q", bare, dest, NULL};
    return dvt_git(NULL, args);
}

/* ── in-process invocation ────────────────────────────────────────────── */

static void dvt_call(zcl_command_handler_fn handler, const char *root,
                     struct json_value *input, struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.source_root = root;
    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.context = &ctx;
    request.input = input;
    zcl_command_reply_init(reply, "zcl.test.train.v1");
    handler(&request, reply);
}

static struct json_value dvt_input_build(const char *name,
                                         const char *sources_joined)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "name", name);
    (void)json_push_kv_str(&input, "sources", sources_joined);
    return input;
}

static const char *dvt_str(const struct zcl_command_reply *reply,
                           const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dvt_int(const struct zcl_command_reply *reply, const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool dvt_array_has_sha(const struct json_value *arr, const char *sha)
{
    if (!arr || arr->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < arr->num_children; i++) {
        const char *got = json_get_str(json_get(&arr->children[i], "sha"));
        if (got && strcmp(got, sha) == 0)
            return true;
    }
    return false;
}

int test_dev_train(void);
int test_dev_train(void)
{
    int failures = 0;
    /* dev.train.build/check run `make` through zcl_devloop_process_run(),
     * which refuses to exec anything in a test binary unless the fixture
     * explicitly opts in — this group's whole point is proving that path. */
    (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    char parent[512];
    test_make_tmpdir(parent, sizeof(parent), "dev_train", "fixture");

    char root[600], bare[600], src_a[600], src_b[600], src_c[600];
    (void)snprintf(root, sizeof(root), "%s/root", parent);
    (void)snprintf(bare, sizeof(bare), "%s/origin.git", parent);
    (void)snprintf(src_a, sizeof(src_a), "%s/srcA", parent);
    (void)snprintf(src_b, sizeof(src_b), "%s/srcB", parent);
    (void)snprintf(src_c, sizeof(src_c), "%s/srcC", parent);

    ASSERT(dvt_fixture_root(root, bare));
    ASSERT(dvt_clone(bare, src_a));
    ASSERT(dvt_clone(bare, src_b));
    ASSERT(dvt_clone(bare, src_c));

    char sha_a1[41], sha_a2[41], sha_b1[41], sha_c1[41];
    ASSERT(dvt_write(src_a, "shared.txt", "A change\n"));
    ASSERT(dvt_commit(src_a, "srcA: change shared"));
    ASSERT(dvt_head(src_a, sha_a1));
    ASSERT(dvt_write(src_a, "unrelated_new_file.txt", "x\n"));
    ASSERT(dvt_commit(src_a, "Regenerate the generated docs for test"));
    ASSERT(dvt_head(src_a, sha_a2));

    ASSERT(dvt_write(src_b, "other.txt", "B change\n"));
    ASSERT(dvt_commit(src_b, "srcB: change other"));
    ASSERT(dvt_head(src_b, sha_b1));

    ASSERT(dvt_write(src_c, "shared.txt", "C change\n"));
    ASSERT(dvt_commit(src_c, "srcC: change shared too"));
    ASSERT(dvt_head(src_c, sha_c1));

    TEST("train: the four leaves are registered with their declared keys") {
        static const char *const paths[] = {
            "dev.train.build", "dev.train.check", "dev.train.status",
            "dev.train.drop", NULL};
        for (size_t i = 0; paths[i]; i++) {
            const struct zcl_command_spec *spec =
                zcl_command_registry_find(zcl_command_catalog(), paths[i],
                                          NULL);
            ASSERT(spec != NULL);
        }
        const struct zcl_command_spec *build_spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.train.build", NULL);
        ASSERT(strstr(build_spec->input_keys, "sources") != NULL);
        PASS();
    }

    TEST("train build: stacks two lanes oldest-first, skipping the regen commit") {
        char joined[1200];
        (void)snprintf(joined, sizeof(joined), "%s\n%s", src_a, src_b);
        struct json_value input = dvt_input_build("alpha", joined);

        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_build, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dvt_str(&reply, "state"), "ok");
        ASSERT(dvt_int(&reply, "commits") == 2);

        const struct json_value *picked = json_get(&reply.data, "picked");
        ASSERT(picked && picked->type == JSON_ARR && picked->num_children == 2);
        ASSERT_STR_EQ(json_get_str(json_get(&picked->children[0], "sha")),
                     sha_a1);
        ASSERT_STR_EQ(json_get_str(json_get(&picked->children[1], "sha")),
                     sha_b1);

        const struct json_value *skipped = json_get(&reply.data, "skipped");
        ASSERT(skipped && skipped->type == JSON_ARR &&
              skipped->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&skipped->children[0], "sha")),
                     sha_a2);
        ASSERT(strncmp(json_get_str(json_get(&skipped->children[0], "subject")),
                      "Regenerate the generated docs",
                      strlen("Regenerate the generated docs")) == 0);
        ASSERT(!dvt_array_has_sha(picked, sha_a2));

        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train status: lists the built stack, unchecked") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "alpha");
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_status, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *stacks = json_get(&reply.data, "stacks");
        ASSERT(stacks && stacks->type == JSON_ARR && stacks->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&stacks->children[0], "name")),
                     "alpha");
        ASSERT(json_get_int(json_get(&stacks->children[0], "commits")) == 2);
        ASSERT_STR_EQ(json_get_str(json_get(&stacks->children[0], "check")),
                     "unavailable");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train drop: refuses unpushed commits, then --force removes it") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "alpha");
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_drop, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "UNPUSHED_COMMITS");
        ASSERT(dvt_int(&reply, "unpushed_commits") == 2);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "alpha");
        (void)json_push_kv_bool(&input, "force", true);
        dvt_call(zcl_native_handle_dev_train_drop, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        char stack_dir[700];
        (void)snprintf(stack_dir, sizeof(stack_dir), "%s/z23-stackalpha",
                      parent);
        ASSERT(platform_directory_probe_real(stack_dir) !=
              PLATFORM_DIRECTORY_PROBE_OK);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train build: a real conflict names the source and sha, worktree left conflicted") {
        char joined[1200];
        (void)snprintf(joined, sizeof(joined), "%s\n%s", src_a, src_c);
        struct json_value input = dvt_input_build("beta", joined);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_build, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "CHERRY_PICK_CONFLICT");
        ASSERT_STR_EQ(dvt_str(&reply, "state"), "conflict");
        ASSERT_STR_EQ(dvt_str(&reply, "source"), src_c);
        ASSERT_STR_EQ(dvt_str(&reply, "sha"), sha_c1);
        const struct json_value *paths = json_get(&reply.data, "paths");
        ASSERT(paths && paths->type == JSON_ARR);
        bool saw_shared = false;
        for (size_t i = 0; i < paths->num_children; i++)
            if (strcmp(json_get_str(&paths->children[i]), "shared.txt") == 0)
                saw_shared = true;
        ASSERT(saw_shared);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train status: the conflicted stack is still listed") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "beta");
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_status, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *stacks = json_get(&reply.data, "stacks");
        ASSERT(stacks && stacks->type == JSON_ARR && stacks->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&stacks->children[0], "name")),
                     "beta");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train drop: the conflicted stack also refuses, then --force removes it") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "beta");
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_drop, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "UNPUSHED_COMMITS");
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "name", "beta");
        (void)json_push_kv_bool(&input, "force", true);
        dvt_call(zcl_native_handle_dev_train_drop, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(parent);
    if (failures == 0) printf("test_dev_train: all passed\n");
    else printf("test_dev_train: %d FAILED\n", failures);
    return failures;
}
