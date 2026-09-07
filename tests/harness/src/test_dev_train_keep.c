/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.train.keep (tools/command/native_dev_train_keep.c),
 * plus the two dev.train.* claims the keeper depends on: the cherry-pick
 * skip list and dev train status's landing-queue path.
 *
 * The keeper is driven against a scratch state root, a scratch trains root
 * and a scratch helper directory holding stand-ins for land_pre.sh and
 * land_unit.sh. Nothing here can reach the real ~/.z23, the real landing
 * queue or the real northstar helpers: those three roots are environment
 * variables precisely so a test can own them, and the keeper's clock is
 * injected the same way, so the state file's timestamp is asserted rather
 * than tolerated.
 *
 * The fixture signs with a stub gpg.program rather than turning signing off.
 * land_pre.sh refuses a train carrying an unsigned commit, so the -S in the
 * keeper's cherry-pick is load-bearing; a fixture that dropped it would be
 * proving a different program than the one that runs at 03:00.
 *
 * Its own group rather than more cases inside test_dev_train: that group's
 * entry point is pinned in the complexity baseline, and a pin may never rise.
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

static bool dtkt_run(const char *const argv[])
{
    char out[8192];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

static bool dtkt_git(const char *dir, const char *const args[])
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
    return dtkt_run(argv);
}

static bool dtkt_mkdir_p(const char *path)
{
    const char *argv[] = {"mkdir", "-p", path, NULL};
    return dtkt_run(argv);
}

static bool dtkt_chmod_x(const char *dir, const char *rel)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    const char *argv[] = {"chmod", "755", path, NULL};
    return dtkt_run(argv);
}

static bool dtkt_put(const char *dir, const char *rel, const char *text,
                     const char *mode)
{
    char path[1024];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, mode);
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool dtkt_write(const char *dir, const char *rel, const char *text)
{
    return dtkt_put(dir, rel, text, "wb");
}

/* One `<name> <sha> <verdict-file>` verdict file, written whole. */
static bool dtkt_verdict(const char *dir, const char *rel, const char *word,
                         const char *sha)
{
    char body[128];
    (void)snprintf(body, sizeof(body), "%s %s\n", word, sha);
    return dtkt_write(dir, rel, body);
}

static bool dtkt_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    (void)fclose(f);
    return true;
}

static bool dtkt_slurp(const char *dir, const char *rel, char *out, size_t cap)
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

static bool dtkt_first_line(const char *dir, const char *rel, char *out,
                            size_t cap)
{
    if (!dtkt_slurp(dir, rel, out, cap))
        return false;
    char *nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    return true;
}

static bool dtkt_rev(const char *dir, const char *rev, char sha[41])
{
    const char *argv[] = {"git", "-C", dir, "rev-parse", "--verify", rev, NULL};
    char out[256];
    if (zcl_spawn_capture(argv, out, sizeof(out), 30000) != 0)
        return false;
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    if (strlen(out) != 40)
        return false;
    memcpy(sha, out, 41);
    return true;
}

static bool dtkt_commit(const char *dir, const char *message)
{
    const char *add[] = {"add", "-A", NULL};
    const char *commit[] = {"commit", "-q", "-m", message, NULL};
    return dtkt_git(dir, add) && dtkt_git(dir, commit);
}

/* The keeper's whole make surface, every target a no-op: a fixture
 * repository has none of the real tree's vendor or doc machinery, and what
 * is under test is the ORDER and the refusals, not what lint prints. */
static const char *const dtkt_makefile =
    "worktree-prime:\n\t@true\n\n"
    "dev-bin:\n\t@true\n\n"
    "check-cyclomatic-complexity:\n\t@true\n\n"
    "t-fast:\n\t@true\n\n"
    "lint:\n\t@true\n\n"
    "docs-capability-inventory:\n\t@true\n\n"
    "docs-executor-routing:\n\t@true\n\n"
    "fix-doc-counts:\n\t@true\n\n"
    "docs-api-reference:\n\t@true\n";

static void dtkt_call(const char *root, struct json_value *input,
                      struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.source_root = root;
    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.context = &ctx;
    request.input = input;
    zcl_command_reply_init(reply, "zcl.test.train_keep.v1");
    zcl_native_handle_dev_train_keep(&request, reply);
}

static struct json_value dtkt_input(const char *train, bool dry_run)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "train", train);
    if (dry_run)
        (void)json_push_kv_bool(&input, "dry_run", true);
    return input;
}

static const char *dtkt_str(const struct zcl_command_reply *reply,
                            const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static bool dtkt_plan_has(const struct json_value *arr, const char *sha)
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

/* Bare origin + a checkout wired to it, with signing that works offline. */
static bool dtkt_fixture_repo(const char *root, const char *bare,
                              const char *parent)
{
    char gpg[1024];
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "-q", root,
                          NULL};
    const char *bare_init[] = {"-c", "init.defaultBranch=main", "init", "-q",
                               "--bare", bare, NULL};
    const char *remote[] = {"remote", "add", "origin", bare, NULL};
    const char *push[] = {"push", "-q", "origin", "main", NULL};
    const char *fetch[] = {"fetch", "-q", "origin", NULL};
    (void)snprintf(gpg, sizeof(gpg), "%s/fakegpg.sh", parent);
    const char *cfg_gpg[] = {"config", "gpg.program", gpg, NULL};
    const char *cfg_key[] = {"config", "user.signingkey", "fixture", NULL};
    const char *cfg_name[] = {"config", "user.name", "Z23 Test", NULL};
    const char *cfg_mail[] = {"config", "user.email",
                              "z23-test@example.invalid", NULL};
    if (!dtkt_write(parent, "fakegpg.sh",
                   "#!/bin/sh\n"
                   "printf '[GNUPG:] SIG_CREATED \\n' >&2\n"
                   "echo '-----BEGIN PGP SIGNATURE-----'\n"
                   "echo 'fixture'\n"
                   "echo '-----END PGP SIGNATURE-----'\n") ||
        !dtkt_chmod_x(parent, "fakegpg.sh") || !dtkt_git(NULL, init) ||
        !dtkt_git(root, cfg_gpg) || !dtkt_git(root, cfg_key) ||
        !dtkt_git(root, cfg_name) || !dtkt_git(root, cfg_mail))
        return false;
    if (!dtkt_write(root, "shared.txt", "line1\n") ||
        !dtkt_write(root, "other.txt", "o\n") ||
        !dtkt_write(root, "Makefile", dtkt_makefile) ||
        !dtkt_commit(root, "base"))
        return false;
    return dtkt_git(NULL, bare_init) && dtkt_git(root, remote) &&
           dtkt_git(root, push) && dtkt_git(root, fetch);
}

/* One reviewed lane, made the way a real one exists: a commit in the ROOT
 * repository published as refs/review/<name>. The keeper never fetches lane
 * objects -- it cherry-picks shas that are already in the repository the
 * train worktree belongs to -- so a fixture built from separate clones would
 * be testing a repository shape production never has. */
static bool dtkt_lane(const char *root, const char *name, const char *file,
                      const char *body, const char *subject, char sha[41])
{
    char branch[128], ref[160];
    (void)snprintf(branch, sizeof(branch), "lane_%s", name);
    (void)snprintf(ref, sizeof(ref), "refs/review/%s", name);
    const char *start[] = {"checkout", "-q", "-b", branch, "origin/main", NULL};
    const char *back[] = {"checkout", "-q", "main", NULL};
    const char *publish[] = {"update-ref", ref, "HEAD", NULL};
    return dtkt_git(root, start) && dtkt_write(root, file, body) &&
           dtkt_commit(root, subject) && dtkt_rev(root, "HEAD", sha) &&
           dtkt_git(root, publish) && dtkt_git(root, back);
}

/* ── the group ────────────────────────────────────────────────────────── */

int test_dev_train_keep(void);
int test_dev_train_keep(void)
{
    int failures = 0;
    /* The keeper runs make through zcl_devloop_process_run(), which refuses
     * to exec anything from a test binary unless the fixture opts in. */
    (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    char parent[512];
    test_make_tmpdir(parent, sizeof(parent), "dev_train_keep", "fixture");

    char root[600], bare[600];
    char scratch[700], trains[700], helpers[700], state[700];
    char dir7[800], dir9[800], land[800];
    (void)snprintf(root, sizeof(root), "%s/root", parent);
    (void)snprintf(bare, sizeof(bare), "%s/origin.git", parent);
    (void)snprintf(scratch, sizeof(scratch), "%s/kscratch", parent);
    (void)snprintf(trains, sizeof(trains), "%s/ktrains", parent);
    (void)snprintf(helpers, sizeof(helpers), "%s/khelpers", parent);
    (void)snprintf(state, sizeof(state), "%s/kstate", parent);
    (void)snprintf(dir7, sizeof(dir7), "%s/train7", scratch);
    (void)snprintf(dir9, sizeof(dir9), "%s/train9", scratch);
    (void)snprintf(land, sizeof(land), "%s/z23/dev/land", state);

    ASSERT(dtkt_fixture_repo(root, bare, parent));
    ASSERT(dtkt_mkdir_p(dir7) && dtkt_mkdir_p(dir9) && dtkt_mkdir_p(trains) &&
          dtkt_mkdir_p(helpers) && dtkt_mkdir_p(land));
    (void)setenv("ZCL_TRAIN_SCRATCH_ROOT", scratch, 1);
    (void)setenv("ZCL_TRAIN_WORKTREE_ROOT", trains, 1);
    (void)setenv("ZCL_TRAIN_HELPER_DIR", helpers, 1);
    (void)setenv("XDG_STATE_HOME", state, 1);
    /* The injected clock: every KEEP.json row this group writes carries this
     * stamp, so the state file is asserted rather than merely tolerated. */
    (void)setenv("ZCL_TRAIN_KEEP_NOW", "2026-01-02T03:04:05Z", 1);
    ASSERT(dtkt_write(helpers, "land_pre.sh",
                     "#!/bin/sh\necho \"PRECHECK: OK\"\n"));
    ASSERT(dtkt_write(helpers, "land_unit.sh",
                     "#!/bin/sh\necho started $1\n"));
    ASSERT(dtkt_chmod_x(helpers, "land_pre.sh") &&
          dtkt_chmod_x(helpers, "land_unit.sh"));

    char origin_main[41], sha_a[41], sha_b[41], sha_c[41];
    ASSERT(dtkt_rev(root, "origin/main", origin_main));
    ASSERT(dtkt_lane(root, "lanea", "a.txt", "A\n", "lanea: add a", sha_a));
    ASSERT(dtkt_lane(root, "laneb", "b.txt", "B\n", "laneb: add b", sha_b));
    ASSERT(dtkt_lane(root, "lanec", "a.txt", "C\n", "lanec: also a", sha_c));

    TEST("train keep: the leaf is registered and declares its own keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.train.keep", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "train") != NULL);
        ASSERT(strstr(spec->input_keys, "dry_run") != NULL);
        PASS();
    }

    TEST("train: the skip list covers the baseline pin, not just the regens") {
        ASSERT(zcl_dev_train_skip_subject("Regenerate the generated docs"));
        ASSERT(zcl_dev_train_skip_subject(
            "Regenerate the capability inventory after the merge"));
        /* The one this list was missing. A lane's own baseline pin describes
         * that lane's tree, never the assembled train's. */
        ASSERT(zcl_dev_train_skip_subject("Pin today's complexity baseline"));
        ASSERT(zcl_dev_train_skip_subject("Count what the stacked lanes added"));
        ASSERT(!zcl_dev_train_skip_subject("Pin the release tag"));
        ASSERT(!zcl_dev_train_skip_subject("lanea: add a"));
        PASS();
    }

    TEST("train status: the land queue path comes from dev.land's state root") {
        char want[900];
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.source_root = root;
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.context = &ctx;
        request.input = &input;
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.train_keep.v1");
        zcl_native_handle_dev_train_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(want, sizeof(want), "%s/queue.jsonl", land);
        /* The bug this pins: the field used to answer from a hardcoded
         * ~/.local/state/zclassic23/land path dev.land never wrote to. */
        ASSERT_STR_EQ(dtkt_str(&reply, "land_queue_path"), want);
        const struct json_value *present =
            json_get(&reply.data, "land_queue_present");
        ASSERT(present && present->type == JSON_BOOL &&
              json_get_bool(present) == false);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a train number outside 1..9999 is refused, typed") {
        struct json_value input = dtkt_input("0", false);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "INVALID_TRAIN");
        ASSERT(strncmp(reply.error.message, "keep: refused: ", 15) == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: an empty queue refuses instead of building nothing") {
        ASSERT(dtkt_write(dir7, "late_picks.txt", "# header only\n"));
        struct json_value input = dtkt_input("7", true);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "NO_PICKS");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: only rows whose verdict says LAND at the queued sha are taken") {
        char q[2048], base_line[64], probe[900];
        ASSERT(dtkt_verdict(dir7, "v_land.txt", "LAND", sha_a));
        ASSERT(dtkt_verdict(dir7, "v_pending.txt", "LAND", sha_b));
        ASSERT(dtkt_verdict(dir7, "v_hold.txt", "HOLD", sha_c));
        ASSERT(dtkt_verdict(dir7, "v_wrong.txt", "LAND", sha_c));
        (void)snprintf(q, sizeof(q),
                      "lanea %s %s/v_land.txt\n"          /* agrees */
                      "laneb PENDING %s/v_pending.txt\n"  /* verdict decides */
                      "lanec %s %s/v_hold.txt\n"          /* not a LAND */
                      "laned %s %s/v_wrong.txt\n",        /* queue disagrees */
                      sha_a, dir7, dir7, sha_c, dir7, sha_b, dir7);
        ASSERT(dtkt_write(dir7, "late_picks.txt", q));
        (void)snprintf(base_line, sizeof(base_line), "%s\n", origin_main);
        ASSERT(dtkt_write(dir7, "BASE", base_line));

        struct json_value input = dtkt_input("7", true);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *plan = json_get(&reply.data, "plan");
        ASSERT(plan && plan->type == JSON_ARR && plan->num_children == 2);
        ASSERT(dtkt_plan_has(plan, sha_a));
        ASSERT(dtkt_plan_has(plan, sha_b));
        const struct json_value *skipped = json_get(&reply.data, "skipped");
        ASSERT(skipped && skipped->num_children == 2);
        /* --dry-run wrote no state at all. */
        (void)snprintf(probe, sizeof(probe), "%s/KEEP.json", dir7);
        ASSERT(!dtkt_exists(probe));
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a base that no longer equals origin/main refuses") {
        char base_line[64];
        ASSERT(dtkt_write(dir7, "BASE",
                         "0000000000000000000000000000000000000000\n"));
        struct json_value input = dtkt_input("7", true);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "BASE_MOVED");
        zcl_command_reply_free(&reply);
        json_free(&input);
        (void)snprintf(base_line, sizeof(base_line), "%s\n", origin_main);
        ASSERT(dtkt_write(dir7, "BASE", base_line));
        PASS();
    }

    TEST("train keep: a real pass assembles, gates, writes READY and hands off") {
        char q[1200], ready[128], wt[900], picks_line[256], raw[1024];
        (void)snprintf(q, sizeof(q), "lanea %s %s/v_land.txt\n", sha_a, dir7);
        ASSERT(dtkt_write(dir7, "late_picks.txt", q));
        struct json_value input = dtkt_input("7", false);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dtkt_str(&reply, "state"), "landing");
        (void)snprintf(wt, sizeof(wt), "%s/train7", trains);
        ASSERT(platform_directory_probe_real(wt) ==
              PLATFORM_DIRECTORY_PROBE_OK);
        ASSERT(dtkt_first_line(dir7, "READY", ready, sizeof(ready)));
        ASSERT(strlen(ready) == 40);
        ASSERT_STR_EQ(dtkt_str(&reply, "tip"), ready);
        ASSERT(dtkt_first_line(dir7, "picks.txt", picks_line,
                              sizeof(picks_line)));
        ASSERT(strncmp(picks_line, "lanea ", 6) == 0);
        ASSERT(dtkt_slurp(dir7, "KEEP.json", raw, sizeof(raw)));
        ASSERT(strstr(raw, "2026-01-02T03:04:05Z") != NULL);
        ASSERT(strstr(raw, "\"state\":\"landing\"") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a second pass while landing re-assembles nothing") {
        char tip_before[128], tip_after[128], head_before[41], head_after[41];
        char wt[900];
        (void)snprintf(wt, sizeof(wt), "%s/train7", trains);
        ASSERT(dtkt_first_line(dir7, "READY", tip_before, sizeof(tip_before)));
        ASSERT(dtkt_rev(wt, "HEAD", head_before));
        struct json_value input = dtkt_input("7", false);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        /* Still landing, same tip, same assembled HEAD: the pass observed
         * dev.land and touched nothing. Only `reason` moves, and it says
         * why the pass had nothing to do. */
        ASSERT_STR_EQ(dtkt_str(&reply, "state"), "landing");
        ASSERT(strstr(dtkt_str(&reply, "reason"), "not finished") != NULL);
        ASSERT(dtkt_first_line(dir7, "READY", tip_after, sizeof(tip_after)));
        ASSERT_STR_EQ(tip_before, tip_after);
        ASSERT(dtkt_rev(wt, "HEAD", head_after));
        ASSERT_STR_EQ(head_before, head_after);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: dev.land reporting landed retires the refs and opens the next train") {
        char tip[128], row[512], next_queue[900], post[512], ref[64];
        ASSERT(dtkt_first_line(dir7, "READY", tip, sizeof(tip)));
        (void)snprintf(row, sizeof(row),
                      "{\"tip\":\"%s\",\"state\":\"landed\"}\n", tip);
        ASSERT(dtkt_write(land, "outcomes.jsonl", row));
        char before_ref[41];
        ASSERT(dtkt_rev(root, "refs/review/lanea", before_ref));
        struct json_value input = dtkt_input("7", false);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dtkt_str(&reply, "state"), "landed");
        /* Only the ref named in picks.txt is retired; laneb's is untouched. */
        ASSERT(!dtkt_rev(root, "refs/review/lanea", ref));
        char survivor[41];
        ASSERT(dtkt_rev(root, "refs/review/laneb", survivor));
        (void)snprintf(next_queue, sizeof(next_queue),
                      "%s/train8/late_picks.txt", scratch);
        ASSERT(dtkt_exists(next_queue));
        ASSERT(dtkt_first_line(dir7, "board_post.txt", post, sizeof(post)));
        ASSERT(strstr(post, "train7 LANDED") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

    TEST("train keep: a cherry-pick conflict blocks, and blocked does not retry") {
        char q[1600], base_line[64], state_a[1024], state_b[1024];
        (void)snprintf(base_line, sizeof(base_line), "%s\n", origin_main);
        ASSERT(dtkt_write(dir9, "BASE", base_line));
        ASSERT(dtkt_verdict(dir9, "v_a.txt", "LAND", sha_a));
        ASSERT(dtkt_verdict(dir9, "v_c.txt", "LAND", sha_c));
        (void)snprintf(q, sizeof(q),
                      "lanea %s %s/v_a.txt\nlanec %s %s/v_c.txt\n", sha_a,
                      dir9, sha_c, dir9);
        ASSERT(dtkt_write(dir9, "late_picks.txt", q));

        struct json_value input = dtkt_input("9", false);
        struct zcl_command_reply reply;
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "ASSEMBLY_BLOCKED");
        ASSERT(strstr(reply.error.message, "conflict") != NULL);
        ASSERT(dtkt_slurp(dir9, "KEEP.json", state_a, sizeof(state_a)));
        ASSERT(strstr(state_a, "\"state\":\"blocked\"") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* The whole point of blocked: the next tick reports and does not try
         * the same failing assembly again. */
        input = dtkt_input("9", false);
        dtkt_call(root, &input, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dtkt_str(&reply, "state"), "blocked");
        ASSERT(dtkt_slurp(dir9, "KEEP.json", state_b, sizeof(state_b)));
        ASSERT_STR_EQ(state_a, state_b);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    }

_test_next:;
    (void)unsetenv("ZCL_TRAIN_SCRATCH_ROOT");
    (void)unsetenv("ZCL_TRAIN_WORKTREE_ROOT");
    (void)unsetenv("ZCL_TRAIN_HELPER_DIR");
    (void)unsetenv("ZCL_TRAIN_KEEP_NOW");
    (void)unsetenv("XDG_STATE_HOME");
    (void)test_rm_rf_recursive(parent);
    if (failures == 0) printf("test_dev_train_keep: all passed\n");
    else printf("test_dev_train_keep: %d FAILED\n", failures);
    return failures;
}
