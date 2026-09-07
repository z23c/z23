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
#include "command/native_dev_train_command.h"
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

static bool dvt_mkdir_p(const char *path)
{
    const char *argv[] = {"mkdir", "-p", path, NULL};
    char out[256];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

static bool dvt_chmod_x(const char *dir, const char *rel)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    const char *argv[] = {"chmod", "755", path, NULL};
    char out[256];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
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
    "docs-api-reference:\n\t@true\n\n"
    /* dev.train.keep's gate and regen sequence, same no-op treatment. */
    "dev-bin:\n\t@true\n\n"
    "check-cyclomatic-complexity:\n\t@true\n\n"
    "t-fast:\n\t@true\n\n"
    "lint:\n\t@true\n\n"
    "docs-executor-routing:\n\t@true\n";

static bool dvt_fixture_root(const char *root, const char *bare)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q",
                          root, NULL};
    if (!dvt_git(NULL, init))
        return false;
    char lintdir[1024];
    (void)snprintf(lintdir, sizeof(lintdir), "%s/tools/lint", root);
    if (!dvt_write(root, "shared.txt", "line1\n") ||
        !dvt_write(root, "other.txt", "o\n") ||
        !dvt_write(root, "Makefile", dvt_makefile) ||
        !dvt_mkdir_p(lintdir) ||
        !dvt_write(root, "tools/lint/check_doc_counts.sh",
                  "#!/bin/sh\nexit 0\n") ||
        !dvt_chmod_x(root, "tools/lint/check_doc_counts.sh") ||
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

/* ── keeper fixture helpers ───────────────────────────────────────────── */

static bool dvt_append(const char *dir, const char *rel, const char *text)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool dvt_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    (void)fclose(f);
    return true;
}

static bool dvt_slurp(const char *dir, const char *rel, char *out, size_t cap)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    (void)fclose(f);
    out[n] = '\0';
    return true;
}

static bool dvt_first_line(const char *dir, const char *rel, char *out,
                           size_t cap)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    bool ok = fgets(out, (int)cap, f) != NULL;
    (void)fclose(f);
    size_t n = ok ? strlen(out) : 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return ok;
}

static bool dvt_rev(const char *dir, const char *rev, char sha[41])
{
    const char *args[] = {"rev-parse", "--verify", rev, NULL};
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

static struct json_value dvt_keep_input(const char *train, bool dry_run)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "train", train);
    if (dry_run)
        (void)json_push_kv_bool(&input, "dry_run", true);
    return input;
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

    /* ── dev.train.keep ───────────────────────────────────────────────────
     * The keeper is driven against a scratch state root, a scratch trains
     * root and a scratch helper directory holding stand-ins for land_pre.sh
     * and land_unit.sh. Nothing below can reach the real ~/.z23, the real
     * landing queue or the real northstar helpers: every one of those three
     * roots is an env var precisely so this test can own them. */
    char keep_scratch[700], keep_trains[700], keep_helpers[700];
    char keep_state[700], keep_dir[760], keep_land[760];
    (void)snprintf(keep_scratch, sizeof(keep_scratch), "%s/kscratch", parent);
    (void)snprintf(keep_trains, sizeof(keep_trains), "%s/ktrains", parent);
    (void)snprintf(keep_helpers, sizeof(keep_helpers), "%s/khelpers", parent);
    (void)snprintf(keep_state, sizeof(keep_state), "%s/kstate", parent);
    (void)snprintf(keep_dir, sizeof(keep_dir), "%s/train7", keep_scratch);
    (void)snprintf(keep_land, sizeof(keep_land), "%s/z23/dev/land", keep_state);
    ASSERT(dvt_mkdir_p(keep_dir) && dvt_mkdir_p(keep_trains) &&
          dvt_mkdir_p(keep_helpers) && dvt_mkdir_p(keep_land));
    (void)setenv("ZCL_TRAIN_SCRATCH_ROOT", keep_scratch, 1);
    (void)setenv("ZCL_TRAIN_WORKTREE_ROOT", keep_trains, 1);
    (void)setenv("ZCL_TRAIN_HELPER_DIR", keep_helpers, 1);
    (void)setenv("XDG_STATE_HOME", keep_state, 1);
    /* The injected clock: every KEEP.json row and keep.log line this group
     * writes carries this exact stamp, so the test can assert on the state
     * file without ever reading a real clock. */
    (void)setenv("ZCL_TRAIN_KEEP_NOW", "2026-01-02T03:04:05Z", 1);
    ASSERT(dvt_write(keep_helpers, "land_pre.sh",
                    "#!/bin/sh\necho \"PRECHECK: OK\"\n"));
    ASSERT(dvt_write(keep_helpers, "land_unit.sh",
                    "#!/bin/sh\necho started $1\n"));
    ASSERT(dvt_chmod_x(keep_helpers, "land_pre.sh") &&
          dvt_chmod_x(keep_helpers, "land_unit.sh"));
    /* Signing is not optional for a train — land_pre.sh refuses a train with
     * an unsigned commit — so the keeper cherry-picks with -S and this
     * fixture must be able to sign. A stub gpg.program keeps that real code
     * path exercised without demanding a keyring on every dev box. */
    ASSERT(dvt_write(parent, "fakegpg.sh",
                    "#!/bin/sh\n"
                    "printf '[GNUPG:] SIG_CREATED \\n' >&2\n"
                    "echo '-----BEGIN PGP SIGNATURE-----'\n"
                    "echo 'fixture'\n"
                    "echo '-----END PGP SIGNATURE-----'\n"));
    ASSERT(dvt_chmod_x(parent, "fakegpg.sh"));
    {
        char gpgpath[800];
        (void)snprintf(gpgpath, sizeof(gpgpath), "%s/fakegpg.sh", parent);
        const char *set_gpg[] = {"config", "gpg.program", gpgpath, NULL};
        const char *set_key[] = {"config", "user.signingkey", "fixture", NULL};
        const char *set_name[] = {"config", "user.name", "Z23 Test", NULL};
        const char *set_mail[] = {"config", "user.email",
                                  "z23-test@example.invalid", NULL};
        ASSERT(dvt_git(root, set_gpg) && dvt_git(root, set_key) &&
              dvt_git(root, set_name) && dvt_git(root, set_mail));
    }

    char origin_main[41];
    ASSERT(dvt_rev(root, "origin/main", origin_main));

    TEST("train: the skip list covers the pin as well as the regens") {
        ASSERT(zcl_dev_train_skip_subject("Regenerate the generated docs"));
        ASSERT(zcl_dev_train_skip_subject(
            "Regenerate the capability inventory after the merge"));
        /* The one this list was missing: a lane's own baseline pin describes
         * that lane's tree, never the assembled train's. */
        ASSERT(zcl_dev_train_skip_subject("Pin today's complexity baseline"));
        ASSERT(zcl_dev_train_skip_subject("Count what the stacked lanes added"));
        ASSERT(zcl_dev_train_skip_subject("Regenerate the catalogs"));
        ASSERT(!zcl_dev_train_skip_subject("Pin the release tag"));
        ASSERT(!zcl_dev_train_skip_subject("srcA: change shared"));
        PASS();
    }

    TEST("train status: the land queue path comes from dev.land's state root") {
        char want[900], queue_file[900];
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_status, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(want, sizeof(want), "%s/z23/dev/land/queue.jsonl",
                      keep_state);
        /* The bug this pins: the field used to answer from a hardcoded
         * ~/.local/state/zclassic23/land path that dev.land never wrote. */
        ASSERT_STR_EQ(dvt_str(&reply, "land_queue_path"), want);
        const struct json_value *present =
            json_get(&reply.data, "land_queue_present");
        ASSERT(present && present->type == JSON_BOOL &&
              json_get_bool(present) == false);
        zcl_command_reply_free(&reply);
        json_free(&input);

        (void)snprintf(queue_file, sizeof(queue_file), "%s/queue.jsonl",
                      keep_land);
        ASSERT(dvt_write(keep_land, "queue.jsonl", "{}\n"));
        ASSERT(dvt_exists(queue_file));
        json_init(&input);
        json_set_object(&input);
        dvt_call(zcl_native_handle_dev_train_status, root, &input, &reply);
        present = json_get(&reply.data, "land_queue_present");
        ASSERT(present && present->type == JSON_BOOL &&
              json_get_bool(present) == true);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: the leaf is registered and declares its own keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.train.keep", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "train") != NULL);
        ASSERT(strstr(spec->input_keys, "dry_run") != NULL);
        PASS();
    }

    TEST("train keep: a train number outside 1..9999 is refused, typed") {
        struct json_value input = dvt_keep_input("0", false);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "INVALID_TRAIN");
        ASSERT(strncmp(reply.error.message, "keep: refused: ",
                      strlen("keep: refused: ")) == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: an empty queue refuses instead of building nothing") {
        ASSERT(dvt_write(keep_dir, "late_picks.txt", "# header only\n"));
        struct json_value input = dvt_keep_input("7", true);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "NO_PICKS");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: only rows whose verdict says LAND at the queued sha are taken") {
        char q[2048];
        ASSERT(dvt_write(keep_dir, "v_land.txt", "LAND ") &&
              dvt_append(keep_dir, "v_land.txt", sha_a1) &&
              dvt_append(keep_dir, "v_land.txt", "\n"));
        ASSERT(dvt_write(keep_dir, "v_pending.txt", "LAND ") &&
              dvt_append(keep_dir, "v_pending.txt", sha_b1) &&
              dvt_append(keep_dir, "v_pending.txt", "\n"));
        ASSERT(dvt_write(keep_dir, "v_hold.txt", "HOLD ") &&
              dvt_append(keep_dir, "v_hold.txt", sha_c1) &&
              dvt_append(keep_dir, "v_hold.txt", "\n"));
        ASSERT(dvt_write(keep_dir, "v_wrong.txt", "LAND ") &&
              dvt_append(keep_dir, "v_wrong.txt", sha_c1) &&
              dvt_append(keep_dir, "v_wrong.txt", "\n"));
        (void)snprintf(q, sizeof(q),
                      "lanea %s %s/v_land.txt\n"      /* explicit, agreeing */
                      "laneb PENDING %s/v_pending.txt\n" /* verdict decides */
                      "lanec %s %s/v_hold.txt\n"      /* no LAND verdict */
                      "laned %s %s/v_wrong.txt\n",    /* queue disagrees */
                      sha_a1, keep_dir, keep_dir, sha_c1, keep_dir, sha_b1,
                      keep_dir);
        ASSERT(dvt_write(keep_dir, "late_picks.txt", q));
        ASSERT(dvt_write(keep_dir, "BASE", origin_main) &&
              dvt_append(keep_dir, "BASE", "\n"));

        struct json_value input = dvt_keep_input("7", true);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *plan = json_get(&reply.data, "plan");
        ASSERT(plan && plan->type == JSON_ARR && plan->num_children == 2);
        ASSERT(dvt_array_has_sha(plan, sha_a1));
        ASSERT(dvt_array_has_sha(plan, sha_b1));
        const struct json_value *skipped = json_get(&reply.data, "skipped");
        ASSERT(skipped && skipped->num_children == 2);
        /* --dry-run wrote no state at all. */
        char probe[900];
        (void)snprintf(probe, sizeof(probe), "%s/KEEP.json", keep_dir);
        ASSERT(!dvt_exists(probe));
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a base that no longer equals origin/main refuses") {
        ASSERT(dvt_write(keep_dir, "BASE",
                        "0000000000000000000000000000000000000000\n"));
        struct json_value input = dvt_keep_input("7", true);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "BASE_MOVED");
        zcl_command_reply_free(&reply);
        json_free(&input);
        ASSERT(dvt_write(keep_dir, "BASE", origin_main) &&
              dvt_append(keep_dir, "BASE", "\n"));
        PASS();
    }

    TEST("train keep: a real run assembles, gates, writes READY and hands off") {
        char q[1200], ready[128], wt[800];
        (void)snprintf(q, sizeof(q), "lanea %s %s/v_land.txt\n", sha_a1,
                      keep_dir);
        ASSERT(dvt_write(keep_dir, "late_picks.txt", q));
        struct json_value input = dvt_keep_input("7", false);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dvt_str(&reply, "state"), "landing");
        ASSERT(dvt_int(&reply, "picks") == 1);
        (void)snprintf(wt, sizeof(wt), "%s/train7", keep_trains);
        ASSERT(platform_directory_probe_real(wt) ==
              PLATFORM_DIRECTORY_PROBE_OK);
        /* READY carries the assembled tip on line 1, and that tip is a
         * descendant of the base carrying exactly the picked commit. */
        ASSERT(dvt_first_line(keep_dir, "READY", ready, sizeof(ready)));
        ASSERT(strlen(ready) == 40);
        ASSERT_STR_EQ(dvt_str(&reply, "tip"), ready);
        char picks_line[256];
        ASSERT(dvt_first_line(keep_dir, "picks.txt", picks_line,
                             sizeof(picks_line)));
        ASSERT(strncmp(picks_line, "lanea ", 6) == 0);
        /* The injected clock, not a real one, is what the state file holds. */
        char state_raw[1024];
        ASSERT(dvt_slurp(keep_dir, "KEEP.json", state_raw,
                        sizeof(state_raw)));
        ASSERT(strstr(state_raw, "2026-01-02T03:04:05Z") != NULL);
        ASSERT(strstr(state_raw, "\"state\":\"landing\"") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a second pass while landing re-assembles nothing") {
        char tip_before[128], tip_after[128], head_before[41], head_after[41];
        char wt[800];
        (void)snprintf(wt, sizeof(wt), "%s/train7", keep_trains);
        ASSERT(dvt_first_line(keep_dir, "READY", tip_before,
                             sizeof(tip_before)));
        ASSERT(dvt_rev(wt, "HEAD", head_before));
        struct json_value input = dvt_keep_input("7", false);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        /* Still landing, same tip, same assembled HEAD: the pass observed
         * dev.land and did not touch the train. Only `reason` moves, and it
         * says why the pass had nothing to do. */
        ASSERT_STR_EQ(dvt_str(&reply, "state"), "landing");
        ASSERT(strstr(dvt_str(&reply, "reason"), "not finished") != NULL);
        ASSERT(dvt_first_line(keep_dir, "READY", tip_after,
                             sizeof(tip_after)));
        ASSERT_STR_EQ(tip_before, tip_after);
        ASSERT(dvt_rev(wt, "HEAD", head_after));
        ASSERT_STR_EQ(head_before, head_after);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: dev.land reporting landed retires the refs and opens the next train") {
        char tip[128], row[512], next_queue[900];
        ASSERT(dvt_first_line(keep_dir, "READY", tip, sizeof(tip)));
        (void)snprintf(row, sizeof(row),
                      "{\"tip\":\"%s\",\"state\":\"landed\"}\n", tip);
        ASSERT(dvt_write(keep_land, "outcomes.jsonl", row));
        struct json_value input = dvt_keep_input("7", false);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dvt_str(&reply, "state"), "landed");
        (void)snprintf(next_queue, sizeof(next_queue),
                      "%s/train8/late_picks.txt", keep_scratch);
        ASSERT(dvt_exists(next_queue));
        char post[512];
        ASSERT(dvt_first_line(keep_dir, "board_post.txt", post, sizeof(post)));
        ASSERT(strstr(post, "[problem]") == NULL);
        ASSERT(strstr(post, "train7 LANDED") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a cherry-pick conflict blocks, and blocked does not retry") {
        char q[1600], dir9[760], state_a[1024], state_b[1024];
        (void)snprintf(dir9, sizeof(dir9), "%s/train9", keep_scratch);
        ASSERT(dvt_mkdir_p(dir9));
        ASSERT(dvt_write(dir9, "BASE", origin_main) &&
              dvt_append(dir9, "BASE", "\n"));
        ASSERT(dvt_write(dir9, "v_a.txt", "LAND ") &&
              dvt_append(dir9, "v_a.txt", sha_a1) &&
              dvt_append(dir9, "v_a.txt", "\n"));
        ASSERT(dvt_write(dir9, "v_c.txt", "LAND ") &&
              dvt_append(dir9, "v_c.txt", sha_c1) &&
              dvt_append(dir9, "v_c.txt", "\n"));
        (void)snprintf(q, sizeof(q), "lanea %s %s/v_a.txt\nlanec %s %s/v_c.txt\n",
                      sha_a1, dir9, sha_c1, dir9);
        ASSERT(dvt_write(dir9, "late_picks.txt", q));

        struct json_value input = dvt_keep_input("9", false);
        struct zcl_command_reply reply;
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "ASSEMBLY_BLOCKED");
        ASSERT(strstr(reply.error.message, "conflict") != NULL);
        ASSERT(dvt_slurp(dir9, "KEEP.json", state_a, sizeof(state_a)));
        ASSERT(strstr(state_a, "\"state\":\"blocked\"") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* The whole point of blocked: the next tick reports, and does not
         * try the same failing assembly again. */
        input = dvt_keep_input("9", false);
        dvt_call(zcl_native_handle_dev_train_keep, root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dvt_str(&reply, "state"), "blocked");
        ASSERT(dvt_slurp(dir9, "KEEP.json", state_b, sizeof(state_b)));
        ASSERT_STR_EQ(state_a, state_b);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    (void)unsetenv("ZCL_TRAIN_SCRATCH_ROOT");
    (void)unsetenv("ZCL_TRAIN_WORKTREE_ROOT");
    (void)unsetenv("ZCL_TRAIN_HELPER_DIR");
    (void)unsetenv("ZCL_TRAIN_KEEP_NOW");
    (void)unsetenv("XDG_STATE_HOME");

_test_next:;
    (void)test_rm_rf_recursive(parent);
    if (failures == 0) printf("test_dev_train: all passed\n");
    else printf("test_dev_train: %d FAILED\n", failures);
    return failures;
}
