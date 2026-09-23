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
#include "platform/rng.h"
#include "util/spawn.h"
#include "util/file_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

/* Append `count` synthetic claim rows from foreign worktrees to the ledger. */
static bool dvx_ledger_append_rows(const char *ledger, int first, int count)
{
    FILE *f = fopen(ledger, "ab");
    if (!f)
        return false;
    bool ok = true;
    for (int i = first; i < first + count && ok; i++)
        ok = fprintf(f,
                     "{\"ts\":\"2026-09-18T00:00:00Z\",\"worktree\":"
                     "\"/fake/wt-%d\",\"branch\":\"\",\"story\":\"s%d\","
                     "\"files\":[\"fake/%d.c\"]}\n",
                     i, i, i) > 0;
    return fclose(f) == 0 && ok;
}

/* Count the synthetic foreign rows still present in the ledger. */
static int dvx_ledger_foreign_rows(const char *ledger)
{
    FILE *f = fopen(ledger, "rb");
    if (!f)
        return -1;
    static char line[16384];
    int rows = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, "\"worktree\":\"/fake/wt-") != NULL)
            rows++;
    (void)fclose(f);
    return rows;
}

/* One claim of a single path from `dir`; returns the refusal code or "".
 * When the registry already rejects the input (an empty string, say), the
 * handler is still run on it directly: it must refuse on its own too. */
static void dvx_claim_one(const char *dir, const char *path, char *code,
                          size_t cap)
{
    const char *const files[] = {path, NULL};
    struct dvx_call c;
    dvx_claim(&c, dir, "alias-probe", files, false);
    if (!dvx_run(&c))
        zcl_native_handle_dev_agent_claim(&c.request, &c.reply);
    (void)snprintf(code, cap, "%s", dvx_ok(&c) ? "" : c.reply.error.code);
    dvx_end(&c);
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

static int dvx_lease_tests(void)
{
    int failures = 0;
    static const char *const files[] = {"engine/a.c", NULL};
    TEST("claim: expired lease is reclaimed and renewal stays one row") {
        char repo[512], other[600], row[2048], ledger[1024];
        test_make_tmpdir(repo, sizeof(repo), "devagent_claim", "lease-expired");
        (void)snprintf(other, sizeof(other), "%s-other", repo);
        ASSERT(dvx_fixture(repo));
        const char *wt[] = {"worktree", "add", "-q", "-b", "other", other,
                            NULL};
        ASSERT(dvx_git(repo, wt));
        (void)snprintf(row, sizeof(row),
                       "{\"expires_unix\":1,\"worktree\":\"%s\","
                       "\"story\":\"stalled\",\"files\":[\"engine/a.c\"]}\n",
                       other);
        ASSERT(dvx_write(repo, ".git/z23-agent-claims.jsonl", row));
        struct dvx_call c;
        dvx_claim(&c, repo, "takeover", files, false);
        ASSERT(dvx_run(&c) && dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "expired_reclaimed"), 1);
        ASSERT(dvx_int(&c, "expires_unix") > 1);
        ASSERT_EQ(dvx_int(&c, "live"), 1);
        dvx_end(&c);
        dvx_claim(&c, repo, "renew", files, false);
        ASSERT(dvx_run(&c) && dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "live"), 1);
        dvx_end(&c);
        (void)snprintf(ledger, sizeof(ledger),
                       "%s/.git/z23-agent-claims.jsonl", repo);
        char *text = NULL;
        size_t len = 0;
        ASSERT(zcl_read_whole_file_text(ledger, 8192, &text, &len,
                                        "claim_lease_renew"));
        ASSERT(strstr(text, "stalled") == NULL);
        free(text);
        ASSERT_EQ(test_rm_rf_recursive(other), 0);
        ASSERT_EQ(test_rm_rf_recursive(repo), 0);
        PASS();
    }

    TEST("claim: malformed and legacy expiry never release a foreign file") {
        char repo[512], row[2048];
        static const char *const fields[] = {
            "\"expires_unix\":+1,", "\"expires_unix\":01,",
            "\"expires_unix\":1,\"expires_unix\":2,",
            "\"expires_unix\":\"bad\",", "\"expires_unix\":9223372036854775808,",
            "", NULL};
        test_make_tmpdir(repo, sizeof(repo), "devagent_claim", "lease-bad");
        ASSERT(dvx_fixture(repo));
        for (size_t i = 0; fields[i]; i++) {
            (void)snprintf(row, sizeof(row),
                           "{%s\"worktree\":\"/foreign\",\"story\":"
                           "\"legacy\",\"files\":[\"engine/a.c\"]}\n",
                           fields[i]);
            ASSERT(dvx_write(repo, ".git/z23-agent-claims.jsonl", row));
            struct dvx_call c;
            dvx_claim(&c, repo, "probe", files, false);
            ASSERT(dvx_run(&c) && !dvx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "CLAIM_OVERLAP");
            dvx_end(&c);
        }
        ASSERT_EQ(test_rm_rf_recursive(repo), 0);
        PASS();
    }
_test_next:;
    return failures;
}

static int dvx_metadata_tests(void)
{
    int failures = 0;
    static const char *const files_a[] = {"engine/a.c", NULL};
    TEST("claim: unavailable owner metadata remains empty without admitting overlap") {
        char repo[512];
        test_make_tmpdir(repo, sizeof(repo), "devagent_claim", "metadata");
        ASSERT(dvx_fixture(repo));
        char long_text[400];
        memset(long_text, 'x', sizeof(long_text) - 1);
        long_text[sizeof(long_text) - 1] = '\0';
        for (int variant = 0; variant < 2; variant++) {
            char row[2048];
            if (variant == 0)
                (void)snprintf(row, sizeof(row),
                    "{\"worktree\":\"/foreign\",\"story\":\"owner\","
                    "\"files\":[\"engine/a.c\"]}\n");
            else
                (void)snprintf(row, sizeof(row),
                    "{\"worktree\":\"/foreign\",\"story\":\"owner\","
                    "\"ts\":\"%s\",\"branch\":\"%s\","
                    "\"files\":[\"engine/a.c\"]}\n", long_text, long_text);
            ASSERT(dvx_write(repo, ".git/z23-agent-claims.jsonl", row));
            struct dvx_call c;
            dvx_claim(&c, repo, "metadata-probe", files_a, false);
            ASSERT(dvx_run(&c));
            ASSERT(!dvx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "CLAIM_OVERLAP");
            const struct json_value *conflicts = dvx_arr(&c, "conflicts");
            ASSERT(conflicts && conflicts->num_children == 1);
            ASSERT_STR_EQ(json_get_str(json_get(&conflicts->children[0],
                                                "claimed_at")), "");
            ASSERT_STR_EQ(json_get_str(json_get(&conflicts->children[0],
                                                "branch")), "");
            dvx_end(&c);
        }
        ASSERT_EQ(test_rm_rf_recursive(repo), 0);
        PASS();
    }

_test_next:;
    return failures;
}

struct dvx_interleaved_claim {
    const char *other;
    bool entered;
    bool nested_ok;
    bool nested_locked;
};

/* The stage nonce is requested after the outer read/overlap check. Run a
 * second writer exactly there, without timing-dependent threads or sleeps. */
static bool dvx_interleave_rng(void *self, uint8_t *out, size_t len)
{
    struct dvx_interleaved_claim *state = self;
    bool outer = !state->entered;
    memset(out, outer ? 1 : 2, len);
    if (outer) {
        state->entered = true;
        static const char *const files[] = {"engine/b.c", NULL};
        struct dvx_call c;
        dvx_claim(&c, state->other, "interleaved", files, false);
        bool ran = dvx_run(&c);
        state->nested_ok = ran && dvx_ok(&c);
        state->nested_locked = ran &&
            strcmp(c.reply.error.code, "CLAIM_LOCK_UNAVAILABLE") == 0;
        dvx_end(&c);
    }
    return true;
}

static int dvx_interleaved_tests(void)
{
    int failures = 0;
    TEST("claim: interleaved writers refuse contention and retry without lost rows") {
        char repo[512], other[600];
        test_make_tmpdir(repo, sizeof(repo), "devagent_claim", "interleave");
        (void)snprintf(other, sizeof(other), "%s-other", repo);
        ASSERT(dvx_fixture(repo));
        const char *wt[] = {"worktree", "add", "-q", "-b", "other", other, NULL};
        ASSERT(dvx_git(repo, wt));
        struct dvx_interleaved_claim state = {.other = other};
        rng_iface_t interleaved = {.fill = dvx_interleave_rng, .self = &state};
        const rng_iface_t *saved = rng_default();
        static const char *const files_a[] = {"engine/a.c", NULL};
        static const char *const files_b[] = {"engine/b.c", NULL};
        struct dvx_call c;
        dvx_claim(&c, repo, "outer", files_a, false);
        rng_set_default(&interleaved);
        bool outer_ok = dvx_run(&c) && dvx_ok(&c);
        rng_set_default(saved);
        printf("outer_ok=%d nested_ok=%d nested_locked=%d live=%lld ",
               outer_ok, state.nested_ok, state.nested_locked,
               (long long)dvx_int(&c, "live"));
        dvx_end(&c);
        ASSERT(outer_ok && state.entered);
        ASSERT(!state.nested_ok && state.nested_locked);
        dvx_claim(&c, other, "retry", files_b, false);
        ASSERT(dvx_run(&c) && dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "live"), 2);
        dvx_end(&c);
        dvx_claim(&c, repo, "verify-foreign-owner", files_b, false);
        ASSERT(dvx_run(&c) && !dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CLAIM_OVERLAP");
        dvx_end(&c);
        ASSERT_EQ(test_rm_rf_recursive(other), 0);
        ASSERT_EQ(test_rm_rf_recursive(repo), 0);
        PASS();
    }
_test_next:;
    return failures;
}

static int dvx_write_failure_tests(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("claim: a failed write preserves the previous ledger bytes") {
        char repo[512], ledger[1024];
        test_make_tmpdir(repo, sizeof(repo), "devagent_claim", "write-failure");
        ASSERT(dvx_fixture(repo));
        const char *row = "{\"worktree\":\"foreign\",\"story\":\"keep\","
                          "\"files\":[\"engine/a.c\"]}\n";
        ASSERT(dvx_write(repo, ".git/z23-agent-claims.jsonl", row));
        (void)snprintf(ledger, sizeof(ledger),
                       "%s/.git/z23-agent-claims.jsonl", repo);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct rlimit limit = {0, 0};
            if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR ||
                setrlimit(RLIMIT_FSIZE, &limit) != 0)
                _exit(2);
            static const char *const files[] = {"engine/b.c", NULL};
            struct dvx_call c;
            dvx_claim(&c, repo, "failed-write", files, false);
            bool refused = dvx_run(&c) && !dvx_ok(&c);
            dvx_end(&c);
            _exit(refused ? 0 : 3);
        }
        int status = 0;
        ASSERT_EQ(waitpid(child, &status, 0), child);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        char *after = NULL;
        size_t len = 0;
        ASSERT(zcl_read_whole_file_text(ledger, 8192, &after, &len,
                                        "claim_write_failure"));
        ASSERT_EQ(len, strlen(row));
        ASSERT_STR_EQ(after, row);
        free(after);
        ASSERT_EQ(test_rm_rf_recursive(repo), 0);
        PASS();
    }
_test_next:;
#endif
    return failures;
}

static int dvx_unreadable_tests(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("claim: a ledger open error refuses claim and release without rewriting") {
        char repo[512], ledger[1024];
        test_make_tmpdir(repo, sizeof(repo), "devagent_claim", "unreadable");
        ASSERT(dvx_fixture(repo));
        (void)snprintf(ledger, sizeof(ledger),
                       "%s/.git/z23-agent-claims.jsonl", repo);
        /* ELOOP is deterministic even under root; EACCES needs a normal uid. */
        const char *target = "z23-agent-claims.jsonl";
        ASSERT_EQ(symlink(target, ledger), 0);
        static const char *const files[] = {"engine/a.c", NULL};
        for (int release = 0; release < 2; release++) {
            struct dvx_call c;
            dvx_claim(&c, repo, "unreadable-probe", files, release != 0);
            ASSERT(dvx_run(&c));
            ASSERT(!dvx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "CLAIM_LEDGER_UNREADABLE");
            dvx_end(&c);
            char after[64];
            ssize_t n = readlink(ledger, after, sizeof(after));
            ASSERT_EQ(n, (ssize_t)strlen(target));
            ASSERT(memcmp(after, target, strlen(target)) == 0);
        }
        ASSERT_EQ(test_rm_rf_recursive(repo), 0);
        PASS();
    }
_test_next:;
#endif
    return failures;
}

int test_devagent_claim(void);
int test_devagent_claim(void)
{
    int failures = dvx_lease_tests() + dvx_metadata_tests() + dvx_unreadable_tests() +
                   dvx_write_failure_tests() + dvx_interleaved_tests();
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
        char ledger_path[1024];
        (void)snprintf(ledger_path, sizeof(ledger_path),
                       "%s/.git/z23-agent-claims.jsonl", one);
        char *before = NULL;
        size_t before_len = 0;
        ASSERT(zcl_read_whole_file_text(ledger_path, 8192, &before,
                                        &before_len, "claim_refusal_before"));
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
        const char *claimed_at = json_get_str(
            json_get(&conflicts->children[0], "claimed_at"));
        ASSERT(claimed_at != NULL);
        ASSERT_EQ(strlen(claimed_at), 20);
        ASSERT_STR_EQ(json_get_str(json_get(&conflicts->children[0], "branch")),
                      "main");
        const char *ledger = json_get_str(json_get(&c.reply.data, "ledger"));
        ASSERT(ledger != NULL);
        ASSERT(strstr(ledger, "z23-agent-claims.jsonl") != NULL);
        ASSERT(strstr(c.reply.error.next_action, "dev.agent.mail") != NULL);
        ASSERT(strstr(c.reply.error.next_action, "authorized release") != NULL);
        char *after = NULL;
        size_t after_len = 0;
        ASSERT(zcl_read_whole_file_text(ledger_path, 8192, &after,
                                        &after_len, "claim_refusal_after"));
        ASSERT_EQ(before_len, after_len);
        ASSERT(memcmp(before, after, before_len) == 0);
        free(before);
        free(after);
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

    TEST("claim: a dotted or slashed alias of a held file is an overlap") {
        /* `two` holds engine/a.c. Every spelling below names the same file,
         * so each must be refused rather than granted a second exclusive
         * claim on it. */
        static const char *const aliases[] = {
            "engine/x/../a.c", "./engine/a.c", "engine/a.c/",
            "engine//a.c",     "engine/./a.c", NULL};
        for (size_t i = 0; aliases[i]; i++) {
            char code[64];
            dvx_claim_one(one, aliases[i], code, sizeof(code));
            if (strcmp(code, "CLAIM_OVERLAP") != 0)
                printf("[alias %s -> '%s'] ", aliases[i], code);
            ASSERT_STR_EQ(code, "CLAIM_OVERLAP");
        }
        PASS();
    }

    TEST("claim: absolute, empty and root-escaping paths are refused by name") {
        static const char *const bad[] = {"/etc/passwd", "",   "../escape",
                                          "a/../../escape", ".", "a/..",
                                          NULL};
        for (size_t i = 0; bad[i]; i++) {
            char code[64];
            dvx_claim_one(one, bad[i], code, sizeof(code));
            if (strcmp(code, "CLAIM_PATH_REFUSED") != 0)
                printf("[path '%s' -> '%s'] ", bad[i], code);
            ASSERT_STR_EQ(code, "CLAIM_PATH_REFUSED");
        }
        PASS();
    }

    TEST("claim: a ledger past 256 rows keeps every row over claim and release") {
        struct dvx_call c;
        static const char *const files_c[] = {"engine/c.c", NULL};
        char ledger[1024];
        dvx_claim(&c, one, "ledger-rows", files_c, false);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        (void)snprintf(ledger, sizeof(ledger), "%s", dvx_str(&c, "ledger"));
        dvx_end(&c);
        ASSERT(dvx_ledger_append_rows(ledger, 0, 300));

        dvx_claim(&c, one, "ledger-rows-again", files_c, false);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        dvx_end(&c);
        ASSERT_EQ(dvx_ledger_foreign_rows(ledger), 300);

        dvx_claim(&c, one, "ledger-rows", files_none, true);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        ASSERT_EQ(dvx_int(&c, "released"), 1);
        dvx_end(&c);
        ASSERT_EQ(dvx_ledger_foreign_rows(ledger), 300);

        /* A foreign row past the old 256-line read window still conflicts. */
        static const char *const files_late[] = {"fake/299.c", NULL};
        dvx_claim(&c, one, "late-row", files_late, false);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CLAIM_OVERLAP");
        dvx_end(&c);
        PASS();
    }

    TEST("claim: a ledger over its row cap is refused whole, never truncated") {
        struct dvx_call c;
        static const char *const files_c[] = {"engine/c.c", NULL};
        char ledger[1024];
        dvx_claim(&c, one, "cap-probe", files_c, false);
        ASSERT(dvx_run(&c));
        ASSERT(dvx_ok(&c));
        (void)snprintf(ledger, sizeof(ledger), "%s", dvx_str(&c, "ledger"));
        dvx_end(&c);
        ASSERT(dvx_ledger_append_rows(ledger, 300, 4096));

        dvx_claim(&c, one, "cap-probe-again", files_c, false);
        ASSERT(dvx_run(&c));
        ASSERT(!dvx_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "CLAIM_LEDGER_TOO_LARGE");
        dvx_end(&c);
        ASSERT_EQ(dvx_ledger_foreign_rows(ledger), 4396);
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
