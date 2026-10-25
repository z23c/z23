/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.train.* (tools/command/native_dev_train_command.c).
 *
 * Builds a temporary bare "origin" plus a main checkout and three source
 * clones, then drives the four handlers directly (in-process, the way the
 * CLI calls them after input validation) against that fixture — never
 * against the real checkout this test runs in.
 *
 * The fixture's checked-out Makefile defines worktree-prime as a no-op:
 * dev.train.build calls exactly that target, and a fixture repository has none of the real
 * tree's vendor/doc machinery to run them for real.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_train_command.h"
#include "config/command_catalog.h"
#include "controllers/agent_impact_rules.h"
#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* The fixture Makefile: worktree-prime as a no-op, the only target
 * dev.train.build calls. */
static const char *const dvt_makefile =
    "worktree-prime:\n\t@true\n";

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

static int dvt_cli_production_route(void)
{
    int failures = 0;
    TEST("train production path selects its CLI boundary regression") {
        struct agent_impact_acc impact = {0};
        bool consensus_risk = true;
        ASSERT_STR_EQ(zcl_native_code_route_for_path(
                          "tools/command/native_dev_train_command.c",
                          &impact, &consensus_risk), "dev_train");
        ASSERT(!consensus_risk);
        ASSERT(!impact.groups_lost);
        bool lint_selected = false;
        for (size_t i = 0; i < impact.groups_len; i++)
            if (strcmp(impact.groups[i], "make_lint_gates") == 0)
                lint_selected = true;
        ASSERT(lint_selected);
        PASS();
    }
_test_next:;
    return failures;
}

static int dvt_cli_name_boundary(void)
{
    int failures = 0;
    TEST("train CLI reader refuses overlong names and unknown flags") {
        char word[sizeof("--name=") + 64];
        memcpy(word, "--name=", 7);
        memset(word + 7, 'a', 64);
        word[71] = '\0';
        const char *words[] = {word};
        char why[192];
        struct json_value input;
        json_init(&input);
        ASSERT(!zcl_native_dev_train_cli_input(words, 1, 0, &input, why,
                                               sizeof(why)));
        ASSERT(strstr(why, "--name") != NULL);
        ASSERT(strstr(why, "at most 63 bytes") != NULL);
        json_free(&input);

        word[70] = '\0';
        json_init(&input);
        ASSERT(zcl_native_dev_train_cli_input(words, 1, 0, &input, why,
                                              sizeof(why)));
        ASSERT_STR_EQ(json_get_str(json_get(&input, "name")), word + 7);
        json_free(&input);

        const char *bad[] = {"--bogus"};
        json_init(&input);
        ASSERT(!zcl_native_dev_train_cli_input(bad, 1, 0, &input, why,
                                               sizeof(why)));
        ASSERT_STR_EQ(why, "unknown flag --bogus");
        json_free(&input);
        PASS();
    }
_test_next:;
    return failures;
}

static bool dvt_call_implicit(zcl_command_handler_fn handler,
                              const char *cwd, struct json_value *input,
                              struct zcl_command_reply *reply)
{
    char saved_cwd[4096], saved_env[4096];
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    bool had_env = env != NULL;
    zcl_command_reply_init(reply, "zcl.test.train.v1");
    if (!getcwd(saved_cwd, sizeof(saved_cwd)) ||
        (env && strlen(env) >= sizeof(saved_env)))
        return false;
    if (env) memcpy(saved_env, env, strlen(env) + 1);
    if (chdir(cwd) != 0) return false;
    bool ready = unsetenv("ZCL_DEV_SOURCE_ROOT") == 0;
    if (ready) dvt_call(handler, NULL, input, reply);
    bool cwd_restored = chdir(saved_cwd) == 0;
    bool env_restored = (had_env ? setenv("ZCL_DEV_SOURCE_ROOT", saved_env, 1)
                                : unsetenv("ZCL_DEV_SOURCE_ROOT")) == 0;
    return ready && cwd_restored && env_restored;
}

static int dvt_implicit_root_case(const char *parent, const char *root,
                                  const char *cwd, const char *source,
                                  const char *name)
{
    int failures = 0;
    char expected[4096], nested[4096];
    struct json_value input = dvt_input_build(name, source);
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.train.v1");
    ASSERT(snprintf(expected, sizeof(expected), "%s/z23-stack%s", parent,
                    name) < (int)sizeof(expected));
    ASSERT(snprintf(nested, sizeof(nested), "%s/z23-stack%s", cwd,
                    name) < (int)sizeof(nested));
    ASSERT(dvt_call_implicit(zcl_native_handle_dev_train_build, cwd, &input, &reply));
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_STR_EQ(dvt_str(&reply, "path"), expected);
    ASSERT(platform_directory_probe_real(expected) == PLATFORM_DIRECTORY_PROBE_OK);
    ASSERT(platform_directory_probe_real(nested) == PLATFORM_DIRECTORY_PROBE_MISSING);
    zcl_command_reply_free(&reply);
    ASSERT(dvt_call_implicit(zcl_native_handle_dev_train_build, cwd, &input, &reply));
    ASSERT_STR_EQ(reply.error.code, "STACK_EXISTS");
    ASSERT_STR_EQ(dvt_str(&reply, "path"), expected);
    ASSERT(platform_directory_probe_real(nested) == PLATFORM_DIRECTORY_PROBE_MISSING);
    zcl_command_reply_free(&reply);
    json_free(&input);
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "name", name);
    ASSERT(dvt_call_implicit(zcl_native_handle_dev_train_status, cwd, &input, &reply));
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    const struct json_value *stacks = json_get(&reply.data, "stacks");
    ASSERT(stacks && stacks->type == JSON_ARR && stacks->num_children == 1);
    zcl_command_reply_free(&reply);
    (void)json_push_kv_bool(&input, "force", true);
    ASSERT(dvt_call_implicit(zcl_native_handle_dev_train_drop, cwd, &input, &reply));
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT(platform_directory_probe_real(expected) == PLATFORM_DIRECTORY_PROBE_MISSING);
    const char *list[] = {"worktree", "list", "--porcelain", NULL};
    char worktrees[8192];
    ASSERT(dvt_git_capture(root, list, worktrees, sizeof(worktrees)));
    ASSERT(strstr(worktrees, expected) == NULL);
_test_next:;
    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

/* ── gated check: --gates, stop at first red, source attribution ─────────── */

struct dvt_gate_fake {
    char order[64];
    const char *red;
    const char *verdict_json;
    const char *step_log;
    const char *tip_a;
    const char *tip_b;
    const char *universal_tip;
};
static struct dvt_gate_fake dvt_fake;

static bool dvt_fake_run(const char *stack_dir, const char *gate,
                         const char *const argv[], int timeout_ms,
                         struct zcl_devloop_process_result *out)
{
    (void)argv;
    (void)timeout_ms;
    size_t n = strlen(dvt_fake.order);
    (void)snprintf(dvt_fake.order + n, sizeof(dvt_fake.order) - n, "%s%s",
                   n ? "," : "", gate);
    bool red = dvt_fake.red && strcmp(gate, dvt_fake.red) == 0;
    out->exit_code = red ? 2 : 0;
    out->elapsed_ms = 7;
    if (!red)
        return true;
    out->output_len = (size_t)snprintf(out->output, sizeof(out->output),
                                       "FAIL check-fake-%s\n", gate);
    char build[1024], scratch[1024];
    (void)snprintf(build, sizeof(build), "%s/build", stack_dir);
    (void)snprintf(scratch, sizeof(scratch), "%s/build/scratch", stack_dir);
    (void)platform_directory_ensure(build, 0700);
    (void)platform_directory_ensure(scratch, 0700);
    if (dvt_fake.verdict_json)
        (void)dvt_write(stack_dir, "build/test-verdict.json",
                        dvt_fake.verdict_json);
    if (dvt_fake.step_log)
        (void)dvt_write(stack_dir,
                        "build/scratch/agent-verify.t-fast-exact.log",
                        dvt_fake.step_log);
    return true;
}

static bool dvt_fake_select(const char *source_root, const char *tip,
                            char *groups, size_t groups_cap, bool *universal)
{
    (void)source_root;
    const char *own = strcmp(tip, dvt_fake.tip_a) == 0   ? "g_a,g_shared"
                      : strcmp(tip, dvt_fake.tip_b) == 0 ? "g_b,g_shared"
                                                         : "";
    (void)snprintf(groups, groups_cap, "%s", own);
    *universal = dvt_fake.universal_tip &&
                 strcmp(tip, dvt_fake.universal_tip) == 0;
    return true;
}

static void dvt_check_run(const char *root, const char *gates,
                          struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "name", "gate1");
    if (gates)
        (void)json_push_kv_str(&input, "gates", gates);
    dvt_call(zcl_native_handle_dev_train_check, root, &input, reply);
    json_free(&input);
}

static const struct json_value *dvt_row(const struct zcl_command_reply *reply,
                                        const char *key, size_t i)
{
    const struct json_value *arr = json_get(&reply->data, key);
    return arr && arr->type == JSON_ARR && i < arr->num_children
               ? &arr->children[i] : NULL;
}

/* True iff the attribution row for `group` names `guilty` (and carries no
 * candidates), or, with guilty NULL, carries exactly `candidates` of them
 * and no guilty. */
static bool dvt_row_group(const struct zcl_command_reply *reply,
                          const char *group, const char *guilty,
                          size_t candidates)
{
    const struct json_value *attr = json_get(&reply->data, "attribution");
    for (size_t i = 0; attr && i < attr->num_children; i++) {
        const struct json_value *row = &attr->children[i];
        if (strcmp(json_get_str(json_get(row, "group")), group) != 0)
            continue;
        const struct json_value *c = json_get(row, "candidates");
        if (guilty)
            return !c && strcmp(json_get_str(json_get(row, "guilty")),
                                guilty) == 0;
        return !json_get(row, "guilty") && c && c->type == JSON_ARR &&
               c->num_children == candidates;
    }
    return false;
}

static int dvt_gate_cases(const char *root, const char *src_a,
                          const char *src_b, const char *sha_a2,
                          const char *sha_b1)
{
    int failures = 0;
    static const struct zcl_dev_train_gate_hooks hooks = {dvt_fake_run,
                                                         dvt_fake_select};
    struct zcl_command_reply reply;
    char joined[1200];
    (void)snprintf(joined, sizeof(joined), "%s\n%s", src_a, src_b);
    struct json_value build = dvt_input_build("gate1", joined);
    dvt_call(zcl_native_handle_dev_train_build, root, &build, &reply);
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    zcl_command_reply_free(&reply);
    json_free(&build);
    zcl_dev_train_gate_hooks_set(&hooks);
    dvt_fake.tip_a = sha_a2;
    dvt_fake.tip_b = sha_b1;

    TEST("train gates: parsing accepts the three tokens and refuses the rest") {
        unsigned mask = 0;
        char why[320];
        ASSERT(zcl_dev_train_gates_parse("verify,fast", &mask, why, sizeof(why)));
        ASSERT(mask == (ZCL_DEV_TRAIN_GATE_FAST | ZCL_DEV_TRAIN_GATE_VERIFY));
        ASSERT(zcl_dev_train_gates_parse("lint", &mask, why, sizeof(why)));
        ASSERT(mask == ZCL_DEV_TRAIN_GATE_LINT);
        ASSERT(!zcl_dev_train_gates_parse("lint,bogus", &mask, why, sizeof(why)));
        ASSERT(strstr(why, "unknown gate token 'bogus'") != NULL);
        ASSERT(strstr(why, "allowed tokens: fast") != NULL);
        ASSERT(!zcl_dev_train_gates_parse(",", &mask, why, sizeof(why)));
        ASSERT(strstr(why, "no gate named") != NULL);
        dvt_check_run(root, "lint,bogus", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "INVALID_GATES");
        ASSERT(strstr(reply.error.message, "unknown gate token 'bogus'") != NULL);
        ASSERT(dvt_fake.order[0] == '\0');
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("train build: records each source and its original tip in the stack's git dir") {
        char stack_dir[700], gitdir[1024], rec[1100], text[2048] = {0};
        ASSERT(snprintf(stack_dir, sizeof(stack_dir), "%s/../z23-stackgate1",
                        root) < (int)sizeof(stack_dir));
        const char *args[] = {"rev-parse", "--absolute-git-dir", NULL};
        ASSERT(dvt_git_capture(stack_dir, args, gitdir, sizeof(gitdir)));
        gitdir[strcspn(gitdir, "\r\n")] = '\0';
        ASSERT(snprintf(rec, sizeof(rec), "%s/zcl-train-sources", gitdir) <
               (int)sizeof(rec));
        FILE *f = fopen(rec, "rb");
        ASSERT(f != NULL);
        size_t got = fread(text, 1, sizeof(text) - 1, f);
        (void)fclose(f);
        text[got] = '\0';
        char want_a[1100], want_b[1100];
        (void)snprintf(want_a, sizeof(want_a), "%s\t%s\n", src_a, sha_a2);
        (void)snprintf(want_b, sizeof(want_b), "%s\t%s\n", src_b, sha_b1);
        ASSERT(strstr(text, want_a) != NULL);
        ASSERT(strstr(text, want_b) != NULL);
        PASS();
    }

    TEST("train gates: run in fast, lint, verify order whatever the request order") {
        memset(dvt_fake.order, 0, sizeof(dvt_fake.order));
        dvt_check_run(root, "verify,fast,lint", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dvt_fake.order, "fast,lint,verify");
        ASSERT(json_get_bool(json_get(&reply.data, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(dvt_row(&reply, "gates", 2), "gate")), "verify");
        ASSERT_STR_EQ(json_get_str(json_get(dvt_row(&reply, "gates", 2), "verdict")), "passed");
        ASSERT(json_get_int(json_get(dvt_row(&reply, "gates", 0), "wall_ms")) == 7);
        ASSERT(json_get_str(json_get(dvt_row(&reply, "gates", 0), "log_path"))[0] != '\0');
        ASSERT(json_get(&reply.data, "attribution") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("train gates: the first red gate stops the run") {
        memset(dvt_fake.order, 0, sizeof(dvt_fake.order));
        dvt_fake.red = "lint";
        dvt_check_run(root, "fast,lint,verify", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(dvt_fake.order, "fast,lint");
        ASSERT(json_get(&reply.data, "gates")->num_children == 2);
        ASSERT_STR_EQ(json_get_str(json_get(dvt_row(&reply, "gates", 1), "verdict")), "failed");
        ASSERT_STR_EQ(json_get_str(json_get(dvt_row(&reply, "gates", 0), "verdict")), "passed");
        ASSERT_STR_EQ(json_get_str(dvt_row(&reply, "gates_failed", 0)),
                      "check-fake-lint");
        ASSERT(json_get(&reply.data, "attribution") == NULL);
        zcl_command_reply_free(&reply);
        dvt_fake.red = NULL;
        PASS();
    }

    TEST("train gates: a red verify names the guilty lane or the candidates") {
        memset(dvt_fake.order, 0, sizeof(dvt_fake.order));
        dvt_fake.red = "verify";
        dvt_fake.verdict_json =
            "{\"failed_groups\":[\"g_a\",\"g_b\",\"g_shared\",\"g_none\"]}";
        dvt_check_run(root, "verify", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(dvt_str(&reply, "attribution_from"), "verdict");
        ASSERT(json_get(&reply.data, "attribution")->num_children == 4);
        ASSERT(dvt_row_group(&reply, "g_a", src_a, 0));
        ASSERT(dvt_row_group(&reply, "g_b", src_b, 0));
        ASSERT(dvt_row_group(&reply, "g_shared", NULL, 2));
        ASSERT(dvt_row_group(&reply, "g_none", NULL, 0));
        zcl_command_reply_free(&reply);

        /* A universal selection may own any group: never a sole guilty. */
        dvt_fake.universal_tip = sha_b1;
        dvt_check_run(root, "verify", &reply);
        ASSERT(dvt_row_group(&reply, "g_a", NULL, 2));
        ASSERT(dvt_row_group(&reply, "g_b", NULL, 1));
        zcl_command_reply_free(&reply);
        dvt_fake.universal_tip = NULL;

        /* No verdict file: the verify step log names the failed groups. */
        dvt_fake.verdict_json = NULL;
        dvt_fake.step_log = "ok\nFAIL g_a\nFAIL at x.c:1\n";
        dvt_check_run(root, "verify", &reply);
        ASSERT_STR_EQ(dvt_str(&reply, "attribution_from"), "log");
        ASSERT(json_get(&reply.data, "attribution")->num_children == 1);
        ASSERT(dvt_row_group(&reply, "g_a", src_a, 0));
        zcl_command_reply_free(&reply);
        dvt_fake.red = NULL;
        dvt_fake.step_log = NULL;
        PASS();
    }

    TEST("train check: without --gates the lint-fast path runs and no gate fields appear") {
        memset(dvt_fake.order, 0, sizeof(dvt_fake.order));
        dvt_check_run(root, NULL, &reply);
        ASSERT(dvt_fake.order[0] == '\0');
        ASSERT(json_get(&reply.data, "gates") == NULL);
        ASSERT(json_get(&reply.data, "attribution") == NULL);
        ASSERT_STR_EQ(dvt_str(&reply, "leaf"), "dev.train.check");
        zcl_command_reply_free(&reply);
        dvt_check_run(root, "", &reply);
        ASSERT(dvt_fake.order[0] == '\0');
        ASSERT(json_get(&reply.data, "gates") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

_test_next:;
    zcl_dev_train_gate_hooks_set(NULL);
    return failures;
}

int test_dev_train(void);
int test_dev_train(void)
{
    int failures = dvt_cli_name_boundary() + dvt_cli_production_route();
    /* dev.train.build/check run `make` through zcl_devloop_process_run(),
     * which refuses to exec in a test binary unless the fixture opts in. */
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
    ASSERT(dvt_commit(src_a, "Pin today's complexity baseline for test"));
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

    TEST("train build: stacks two lanes oldest-first, skipping the baseline-pin commit") {
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
                      "Pin today's complexity",
                      strlen("Pin today's complexity")) == 0);
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
        char stack_dir[700], conflict[8192];
        ASSERT(snprintf(stack_dir, sizeof(stack_dir), "%s/z23-stackbeta",
                        parent) < (int)sizeof(stack_dir));
        const char *head[] = {"rev-parse", "--verify", "CHERRY_PICK_HEAD", NULL};
        ASSERT(dvt_git_capture(stack_dir, head, conflict, sizeof(conflict)));
        conflict[strcspn(conflict, "\r\n")] = '\0';
        ASSERT_STR_EQ(conflict, sha_c1);
        const char *unmerged[] = {"ls-files", "--unmerged", "--", "shared.txt", NULL};
        ASSERT(dvt_git_capture(stack_dir, unmerged, conflict, sizeof(conflict)));
        ASSERT(strstr(conflict, "\tshared.txt\n") != NULL);
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
        char stack_dir[700], worktrees[8192];
        ASSERT(snprintf(stack_dir, sizeof(stack_dir), "%s/z23-stackbeta",
                        parent) < (int)sizeof(stack_dir));
        ASSERT(platform_directory_probe_real(stack_dir) == PLATFORM_DIRECTORY_PROBE_OK);
        const char *list[] = {"worktree", "list", "--porcelain", NULL};
        ASSERT(dvt_git_capture(root, list, worktrees, sizeof(worktrees)));
        ASSERT(strstr(worktrees, stack_dir) != NULL);
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
        ASSERT(platform_directory_probe_real(stack_dir) == PLATFORM_DIRECTORY_PROBE_MISSING);
        ASSERT(dvt_git_capture(root, list, worktrees, sizeof(worktrees)));
        ASSERT(strstr(worktrees, stack_dir) == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train: omitted source root selects checkout siblings from root and subdirectory") {
        char abs_parent[4096], abs_root[4096], abs_source[4096], subdir[4096];
        ASSERT(platform_directory_canonical_real(parent, abs_parent, sizeof(abs_parent)));
        ASSERT(platform_directory_canonical_real(root, abs_root, sizeof(abs_root)));
        ASSERT(platform_directory_canonical_real(src_a, abs_source, sizeof(abs_source)));
        ASSERT(snprintf(subdir, sizeof(subdir), "%s/subdir", abs_root) < (int)sizeof(subdir));
        ASSERT(platform_directory_ensure(subdir, 0700));
        ASSERT(dvt_implicit_root_case(abs_parent, abs_root, abs_root, abs_source,
                                      "implicit_root") == 0);
        ASSERT(dvt_implicit_root_case(abs_parent, abs_root, subdir, abs_source,
                                      "implicit_subdir") == 0);
        PASS();
    }

    failures += dvt_gate_cases(root, src_a, src_b, sha_a2, sha_b1);

_test_next:;
    (void)test_rm_rf_recursive(parent);
    if (failures == 0) printf("test_dev_train: all passed\n");
    else printf("test_dev_train: %d FAILED\n", failures);
    return failures;
}
