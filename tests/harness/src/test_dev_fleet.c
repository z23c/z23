/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pin the deliberately narrow owner boundary in dev.fleet. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_dev_fleet.h"
#include "command/native_dev_fleet_internal.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── receipt numeric fields, through the production receipts projection ─── */

#define FRX_HEAD "0123456789abcdef0123456789abcdef01234567"
#define FRX_HASH64 \
    "00000000000000000000000000000000000000000000000000000000000000aa"

static bool frx_git(const char *dir, const char *const args[])
{
    const char *argv[24] = {"git", "-C", dir};
    size_t n = 3;
    for (size_t i = 0; args[i] && n + 1 < 24; i++) argv[n++] = args[i];
    argv[n] = NULL;
    char out[4096];
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

/* Writes one sealed receipt: the body, then receipt_sha3 over the body. */
static bool frx_write_receipt(const char *dir, const char *index,
                              const char *exit_status, const char *expect,
                              const char *forbid)
{
    char body[1024], seal[65], digest_hex[65], path[1024], file[2200];
    int n = snprintf(body, sizeof(body),
                     "chain_index=%s\nprev_receipt_sha3=GENESIS\ngate=other\n"
                     "branch=lane/x\nworktree_path=%s\nhead_sha=%s\n"
                     "head_sha_after=%s\ntree_status_sha3=%s\n"
                     "tree_diff_sha3_after=%s\noutput_path=out.log\n"
                     "output_sha3=%s\nverdict=PASS\nexit_status=%s\n"
                     "expect_missing=%s\nforbid_present=%s\n",
                     index, dir, FRX_HEAD, FRX_HEAD, FRX_HASH64, FRX_HASH64,
                     FRX_HASH64, exit_status, expect, forbid);
    if (n <= 0 || (size_t)n >= sizeof(body)) return false;
    unsigned char digest[32];
    sha3_256((const unsigned char *)body, (size_t)n, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_hex);
    (void)snprintf(seal, sizeof(seal), "%s", digest_hex);
    int m = snprintf(file, sizeof(file), "%sreceipt_sha3=%s\n", body, seal);
    if (m <= 0 || (size_t)m >= sizeof(file)) return false;
    (void)snprintf(path, sizeof(path), "%s/.cache/agent-receipts/0.receipt",
                   dir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool wrote = fwrite(file, 1, (size_t)m, f) == (size_t)m;
    return fclose(f) == 0 && wrote;
}

/* The lint_status the projection reports for this receipt, or "" when the
 * projection itself failed. A receipt the reader refuses reads "invalid". */
static bool frx_status(const char *dir, const char *index,
                       const char *exit_status, const char *expect,
                       const char *forbid, char *state, size_t cap)
{
    state[0] = 0;
    if (!frx_write_receipt(dir, index, exit_status, expect, forbid))
        return false;
    struct zcl_fleet_worktree wt = {0};
    wt.present = true;
    (void)snprintf(wt.path, sizeof(wt.path), "%s", dir);
    struct json_value lane;
    json_init(&lane);
    json_set_object(&lane);
    size_t owner_red = 0;
    char why[256] = "";
    bool ok = zcl_dev_fleet_receipts_json(&wt, &lane, &owner_red, why,
                                          sizeof(why));
    const char *s = json_get_str(json_get(&lane, "lint_status"));
    if (ok && s) (void)snprintf(state, cap, "%s", s);
    json_free(&lane);
    return ok && s;
}

static bool frx_fixture(char *dir, size_t cap)
{
    if (!test_mkdtemp(dir, cap, "fleet_receipt")) return false;
    char out[4096];
    const char *argv[] = {"git", "-c", "init.defaultBranch=main", "init", "-q",
                          dir, NULL};
    if (zcl_spawn_capture(argv, out, sizeof(out), 60000) != 0) return false;
    const char *commit[] = {"-c", "user.name=Z23 Test", "-c",
                            "user.email=z23-test@example.invalid", "-c",
                            "commit.gpgsign=false", "commit", "-q",
                            "--allow-empty", "-m", "base", NULL};
    char cache[1100];
    (void)snprintf(cache, sizeof(cache), "%s/.cache", dir);
    if (!frx_git(dir, commit) || mkdir(cache, 0700) != 0) return false;
    (void)snprintf(cache, sizeof(cache), "%s/.cache/agent-receipts", dir);
    return mkdir(cache, 0700) == 0;
}

static int frx_run(void)
{
    int failures = 0;
    char dir[512], state[32];
    bool built = frx_fixture(dir, sizeof(dir));

    TEST("fleet receipts: fixture repository builds") { ASSERT(built); PASS(); }

    TEST("fleet receipts: a well-formed receipt is accepted") {
        ASSERT(frx_status(dir, "0", "0", "0", "0", state, sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        PASS();
    }

    TEST("fleet receipts: valid maxima are accepted") {
        ASSERT(frx_status(dir, "18446744073709551615",
                          "18446744073709551615", "18446744073709551615",
                          "18446744073709551615", state, sizeof(state)));
        /* Accepted by the reader; only the chain (index != 0) refuses. */
        ASSERT(strcmp(state, "invalid") == 0);
        ASSERT(frx_status(dir, "0", "18446744073709551615", "0", "0", state,
                          sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        ASSERT(frx_status(dir, "0", "0", "18446744073709551615", "0", state,
                          sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        ASSERT(frx_status(dir, "0", "0", "0", "18446744073709551615", state,
                          sizeof(state)));
        ASSERT(strcmp(state, "unobserved") == 0);
        PASS();
    }

    static const char *const bad[] = {
        "", "-1", "+5", " 5", "5 ", "1x", "00000000000000000000000",
        "123456789012345678901", "18446744073709551616",
    };
    static const char *const names[] = {"chain_index", "exit_status",
                                        "expect_missing", "forbid_present"};
    for (size_t field = 0; field < 4; field++) {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            const char *v[4] = {"0", "0", "0", "0"};
            v[field] = bad[i];
            TEST("fleet receipts: a malformed numeric field is refused") {
                bool ok = frx_status(dir, v[0], v[1], v[2], v[3], state,
                                     sizeof(state));
                if (!ok || strcmp(state, "invalid") != 0)
                    printf("  not refused: %s=\"%s\" state=%s\n", names[field],
                           bad[i], state);
                ASSERT(ok);
                ASSERT(strcmp(state, "invalid") == 0);
                PASS();
            }
        }
    }
_test_next:;
    if (built) (void)test_rm_rf_recursive(dir);
    return failures;
}

/* ── three-worktree acceptance for the Git/receipt-only dev.fleet command ─
 * Port of the former tools/scripts/dev_fleet_selftest.sh. Fixture repositories
 * (a bare origin, the main checkout, two agent worktrees) live under this
 * test's temp directory. The real build/bin/z23-dev runs with the fixture as
 * its working directory. Only git and that binary are executed; no shell. */

#define ACC_PATH 4096
#define ACC_HEAD 65
#define ACC_OUT_CAP (128u * 1024u)
#define ACC_SCRATCH_CAP (64u * 1024u)
#define ACC_TIMEOUT_MS 120000
#define ACC_LOG "000000-lint-fixture.log"
#define ACC_UNAME "user.name=Fleet Acceptance"
#define ACC_MAIL "user.email=fleet@example.invalid"

struct acc_rig {
    char root[ACC_PATH];
    char bin[ACC_PATH];
    char origin[ACC_PATH];
    char main[ACC_PATH];
    char alpha[ACC_PATH];
    char beta[ACC_PATH];
    char main_head[ACC_HEAD];
    char alpha_head[ACC_HEAD];
    char beta_head[ACC_HEAD];
};

struct acc_verdict {
    const char *word;
    int exit_status;
    int expect_missing;
};

static char acc_out[ACC_OUT_CAP];
static char acc_scratch[ACC_SCRATCH_CAP];

#define ACC_EXEC(...) acc_exec((const char *const[]){__VA_ARGS__, NULL})
#define ACC_GIT(dir, ...) ACC_EXEC("git", "-C", (dir), __VA_ARGS__)
#define ACC_COMMIT(dir, msg)                                                  \
    ACC_GIT((dir), "-c", ACC_UNAME, "-c", ACC_MAIL, "-c",                     \
            "commit.gpgsign=false", "commit", "-q", "-m", (msg))
#define ACC_GIT_RAW(dir, buf, cap, ...)                                       \
    acc_capture_raw((const char *const[]){"git", "-C", (dir), __VA_ARGS__,    \
                                          NULL},                              \
                    (buf), (cap))
#define ACC_GIT_LINE(dir, buf, cap, ...)                                      \
    acc_line((const char *const[]){"git", "-C", (dir), __VA_ARGS__, NULL},    \
             (buf), (cap))

static bool acc_exec(const char *const argv[])
{
    char sink[1024];
    return zcl_spawn_capture(argv, sink, sizeof(sink), ACC_TIMEOUT_MS) == 0;
}

static bool acc_capture_raw(const char *const argv[], char *out, size_t cap)
{
    return zcl_spawn_capture(argv, out, cap, ACC_TIMEOUT_MS) == 0;
}

/* Drops trailing newlines, as the shell's $(...) capture did. */
static void acc_trim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

static bool acc_line(const char *const argv[], char *out, size_t cap)
{
    if (!acc_capture_raw(argv, out, cap)) return false;
    acc_trim(out);
    return true;
}

static void acc_hash(const void *data, size_t len, char out[ACC_HEAD])
{
    unsigned char digest[32];
    sha3_256((const unsigned char *)data, len, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool acc_mkdirs(const char *path)
{
    char buf[ACC_PATH];
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf)) return false;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) return false;
        *p = '/';
    }
    return true;
}

/* Writes (or appends to) dir/rel, creating its parent directories. */
static bool acc_file(const char *dir, const char *rel, const char *text,
                     const char *mode)
{
    char path[ACC_PATH];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    if (!acc_mkdirs(path)) return false;
    FILE *f = fopen(path, mode);
    if (!f) return false;
    size_t n = strlen(text);
    bool wrote = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && wrote;
}

static bool acc_has(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* True when hay contains prefix, arg and suffix as one contiguous run. */
static bool acc_hasf(const char *hay, const char *prefix, const char *arg,
                     const char *suffix)
{
    char needle[1024];
    if (snprintf(needle, sizeof(needle), "%s%s%s", prefix, arg, suffix) >=
        (int)sizeof(needle))
        return false;
    return acc_has(hay, needle);
}

/* The lane object that names `branch` must carry `"lint_status":"state"`
 * before its closing brace, the same shape the shell grep matched. */
static bool acc_lane_is(const char *hay, const char *branch, const char *state)
{
    char key[256], want[128];
    if (snprintf(key, sizeof(key), "\"branch\":\"%s\"", branch) >=
        (int)sizeof(key))
        return false;
    if (snprintf(want, sizeof(want), "\"lint_status\":\"%s\"", state) >=
        (int)sizeof(want))
        return false;
    const char *lane = strstr(hay, key);
    if (!lane) return false;
    const char *close = strchr(lane, '}');
    const char *status = strstr(lane, want);
    return status && (!close || status < close);
}

/* Runs the real binary in the main checkout. Returns its exit status, or -1
 * when it could not be launched. Merged mode keeps stderr for diagnosis. */
static int acc_fleet(const struct acc_rig *r, const char *extra, bool merged,
                     char *out, size_t cap)
{
    const char *argv[6] = {r->bin, "dev", "fleet", "truth", NULL, NULL};
    bool timed_out = false;
    if (extra) argv[4] = extra;
    if (merged)
        return zcl_spawn_capture_merged_in_dir_observed(
            argv, r->main, out, cap, ACC_TIMEOUT_MS, &timed_out);
    return zcl_spawn_capture_in_dir_observed(argv, r->main, out, cap,
                                             ACC_TIMEOUT_MS, &timed_out);
}

/* ── fixture: origin, main checkout, and the two agent worktrees ─────────── */

static bool acc_origin_and_main(struct acc_rig *r)
{
    (void)snprintf(r->origin, sizeof(r->origin), "%s/origin.git", r->root);
    (void)snprintf(r->main, sizeof(r->main), "%s/main", r->root);
    if (!ACC_EXEC("git", "-c", "init.defaultBranch=main", "init", "-q",
                  "--bare", r->origin))
        return false;
    if (!ACC_EXEC("git", "-c", "init.defaultBranch=main", "init", "-q",
                  r->main))
        return false;
    if (!acc_file(r->main, "Makefile", "fixture:\n\t@true\n", "wb") ||
        !acc_file(r->main, "engine/composition/commands/root.def",
                  "/* root marker */\n", "wb") ||
        !acc_file(r->main, "tools/dev/test_group_catalog.def",
                  "/* catalog marker */\n", "wb"))
        return false;
    return ACC_GIT(r->main, "add", "Makefile", "engine", "tools") &&
           ACC_COMMIT(r->main, "base") &&
           ACC_GIT(r->main, "branch", "-M", "main") &&
           ACC_GIT(r->main, "remote", "add", "origin", r->origin) &&
           ACC_GIT(r->main, "push", "-q", "-u", "origin", "main");
}

static bool acc_alpha(struct acc_rig *r)
{
    (void)snprintf(r->alpha, sizeof(r->alpha), "%s/alpha", r->root);
    if (!ACC_GIT(r->main, "worktree", "add", "-q", "-b", "agent/alpha",
                 r->alpha, "main"))
        return false;
    return acc_file(r->alpha, "tools/alpha.c", "alpha\n", "wb") &&
           ACC_GIT(r->alpha, "add", "tools/alpha.c") &&
           ACC_COMMIT(r->alpha, "alpha") &&
           ACC_GIT(r->alpha, "push", "-q", "-u", "origin", "agent/alpha");
}

static bool acc_beta(struct acc_rig *r)
{
    (void)snprintf(r->beta, sizeof(r->beta), "%s/beta", r->root);
    if (!ACC_GIT(r->main, "worktree", "add", "-q", "-b", "agent/beta", r->beta,
                 "main"))
        return false;
    return acc_file(r->beta, "core/beta.c", "beta\n", "wb") &&
           ACC_GIT(r->beta, "add", "core/beta.c") &&
           ACC_COMMIT(r->beta, "beta") &&
           ACC_GIT(r->beta, "push", "-q", "-u", "origin", "agent/beta");
}

/* A non-agent branch that must never reach the fleet, plus
 * alpha's dirty file and the fetch that publishes origin's refs. */
static bool acc_extras(const struct acc_rig *r)
{
    return ACC_GIT(r->main, "branch", "feature/ignored", "main") &&
           ACC_GIT(r->main, "push", "-q", "origin", "feature/ignored") &&
           acc_file(r->alpha, "docs/alpha.txt", "dirty alpha\n", "wb") &&
           ACC_GIT(r->main, "fetch", "-q", "origin");
}

/* Sealed lint receipt: a log, then a body sealed by its SHA3 (the same
 * format the shell wrote). Status hashes trailing newlines removed; the diff
 * hashes raw bytes. */
static bool acc_log_text(const char *const *lines, size_t count, char *text,
                         size_t cap, struct acc_verdict *v)
{
    size_t used = 0;
    text[0] = '\0';
    v->word = "PASS";
    v->exit_status = 0;
    v->expect_missing = 0;
    for (size_t i = 0; i < count; i++) {
        size_t n = strlen(lines[i]);
        if (n + 2 >= cap - used) return false;
        if (strncmp(lines[i], "FAIL check-", 11) == 0) {
            v->word = "FAIL";
            v->exit_status = 1;
            v->expect_missing = 1;
        }
        memcpy(text + used, lines[i], n);
        used += n;
        text[used++] = '\n';
        text[used] = '\0';
    }
    if (strcmp(v->word, "PASS") == 0)
        (void)snprintf(text + used, cap - used, "LINT: all checks passed\n");
    return true;
}

static bool acc_fingerprint(const char *wt, char status[ACC_HEAD],
                            char diff[ACC_HEAD])
{
    if (!ACC_GIT_RAW(wt, acc_scratch, sizeof(acc_scratch), "status",
                     "--porcelain"))
        return false;
    acc_trim(acc_scratch);
    acc_hash(acc_scratch, strlen(acc_scratch), status);
    if (!ACC_GIT_RAW(wt, acc_scratch, sizeof(acc_scratch), "diff", "HEAD"))
        return false;
    acc_hash(acc_scratch, strlen(acc_scratch), diff);
    return true;
}

static bool acc_receipt(const char *wt, const char *const *lines, size_t count)
{
    char text[4096], output[ACC_HEAD], head[ACC_HEAD], branch[256];
    char status[ACC_HEAD], diff[ACC_HEAD], body[4096], seal[ACC_HEAD];
    char sealed[8192];
    struct acc_verdict v;
    if (!acc_log_text(lines, count, text, sizeof(text), &v)) return false;
    if (!acc_file(wt, ".cache/agent-receipts/" ACC_LOG, text, "wb")) return false;
    acc_hash(text, strlen(text), output);
    if (!ACC_GIT_LINE(wt, head, sizeof(head), "rev-parse", "HEAD") ||
        !ACC_GIT_LINE(wt, branch, sizeof(branch), "rev-parse", "--abbrev-ref",
                      "HEAD") ||
        !acc_fingerprint(wt, status, diff))
        return false;
    int n = snprintf(body, sizeof(body),
                     "receipt_schema=zcl.gate_receipt.v1\nchain_index=0\n"
                     "prev_receipt_sha3=GENESIS\ngate=lint\nbranch=%s\n"
                     "worktree_path=%s\nhead_sha=%s\nhead_sha_after=%s\n"
                     "tree_status_sha3=%s\ntree_diff_sha3_after=%s\n"
                     "output_path=%s\noutput_sha3=%s\nexit_status=%d\n"
                     "expect_missing=%d\nforbid_present=0\nverdict=%s\n",
                     branch, wt, head, head, status, diff, ACC_LOG, output,
                     v.exit_status, v.expect_missing, v.word);
    if (n <= 0 || (size_t)n >= sizeof(body)) return false;
    acc_hash(body, (size_t)n, seal);
    if (snprintf(sealed, sizeof(sealed), "%sreceipt_sha3=%s\n", body, seal) >=
        (int)sizeof(sealed))
        return false;
    return acc_file(wt, ".cache/agent-receipts/000000-lint-fixture.receipt",
                    sealed, "wb");
}

static bool acc_receipts(const struct acc_rig *r)
{
    static const char *const pass[] = {"PASS check-format"};
    static const char *const alpha_fail[] = {"FAIL check-format"};
    static const char *const beta_fail[] = {"FAIL check-core-seal",
                                            "FAIL check-git-hooks-installed"};
    return acc_receipt(r->main, pass, 1) &&
           acc_receipt(r->alpha, alpha_fail, 1) &&
           acc_receipt(r->beta, beta_fail, 2);
}

static bool acc_heads(struct acc_rig *r)
{
    return ACC_GIT_LINE(r->main, r->main_head, sizeof(r->main_head), "rev-parse",
                        "HEAD") &&
           ACC_GIT_LINE(r->alpha, r->alpha_head, sizeof(r->alpha_head),
                        "rev-parse", "HEAD") &&
           ACC_GIT_LINE(r->beta, r->beta_head, sizeof(r->beta_head), "rev-parse",
                        "HEAD");
}

static bool acc_rig_build(struct acc_rig *r)
{
    char cwd[ACC_PATH];
    if (!test_mkdtemp(r->root, sizeof(r->root), "dev_fleet_acc")) return false;
    if (!getcwd(cwd, sizeof(cwd))) return false;
    (void)snprintf(r->bin, sizeof(r->bin), "%s/build/bin/z23-dev", cwd);
    return acc_origin_and_main(r) && acc_alpha(r) && acc_beta(r) &&
           acc_extras(r) && acc_heads(r) && acc_receipts(r);
}

/* ── scenarios: each one runs the real CLI against the fixture ───────────── */

static int acc_check_inventory(const struct acc_rig *r)
{
    int failures = 0;
    int rc = acc_fleet(r, NULL, false, acc_out, sizeof(acc_out));
    TEST("fleet acceptance: exactly three lanes, node-free source") {
        ASSERT(rc == 0);
        ASSERT(acc_has(acc_out, "\"lane_count\":3"));
        ASSERT(acc_has(acc_out, "\"live_node_read\":false"));
        PASS();
    }
    TEST("fleet acceptance: exact main, alpha and beta heads") {
        ASSERT(acc_hasf(acc_out, "\"main_head\":\"", r->main_head, "\""));
        ASSERT(acc_has(acc_out, "\"branch\":\"agent/alpha\""));
        ASSERT(acc_hasf(acc_out, "\"head\":\"", r->alpha_head, "\""));
        ASSERT(acc_hasf(acc_out, "\"since_commit\":\"", r->alpha_head, "\""));
        ASSERT(acc_hasf(acc_out, "\"head\":\"", r->beta_head, "\""));
        PASS();
    }
    TEST("fleet acceptance: dirty and remote-only files are listed") {
        ASSERT(acc_has(acc_out, "docs/alpha.txt"));
        ASSERT(acc_has(acc_out, "tools/alpha.c"));
        ASSERT(acc_has(acc_out, "core/beta.c"));
        PASS();
    }
    TEST("fleet acceptance: the non-agent remote branch never leaks") {
        ASSERT(!acc_has(acc_out, "feature/ignored"));
        PASS();
    }
_test_next:;
    return failures;
}

static int acc_check_gates(const struct acc_rig *r)
{
    int failures = 0;
    int rc = acc_fleet(r, NULL, false, acc_out, sizeof(acc_out));
    TEST("fleet acceptance: owner-only red gates are reported") {
        ASSERT(rc == 0);
        ASSERT(acc_hasf(acc_out, "\"gate\":\"check-core-seal\",\"since_commit\"",
                        "", ""));
        ASSERT(acc_hasf(acc_out,
                        "\"gate\":\"check-git-hooks-installed\",\"since_commit\"",
                        "", ""));
        ASSERT(acc_has(acc_out, "\"owner_only_red_gate_count\":2"));
        PASS();
    }
    TEST("fleet acceptance: current lint receipts read green, red, red") {
        ASSERT(acc_lane_is(acc_out, "main", "green"));
        ASSERT(acc_lane_is(acc_out, "agent/alpha", "red"));
        ASSERT(acc_lane_is(acc_out, "agent/beta", "red"));
        PASS();
    }
_test_next:;
    return failures;
}

static int acc_check_freshness(const struct acc_rig *r)
{
    int failures = 0;
    bool touched = acc_file(r->alpha, "tools/alpha.c", "newer tracked dirt\n",
                            "ab");
    int rc = touched ? acc_fleet(r, NULL, false, acc_out, sizeof(acc_out)) : -1;
    TEST("fleet acceptance: an alpha receipt goes stale once its tree moves") {
        ASSERT(touched && rc == 0);
        ASSERT(acc_lane_is(acc_out, "agent/alpha", "stale"));
        PASS();
    }
    bool tampered = acc_file(r->beta, ".cache/agent-receipts/" ACC_LOG,
                             "tamper\n", "ab");
    rc = tampered ? acc_fleet(r, NULL, false, acc_out, sizeof(acc_out)) : -1;
    TEST("fleet acceptance: a tampered beta log is invalid, never green") {
        ASSERT(tampered && rc == 0);
        ASSERT(acc_lane_is(acc_out, "agent/beta", "invalid"));
        PASS();
    }
_test_next:;
    return failures;
}

static bool acc_fill_docs(const struct acc_rig *r, unsigned from, unsigned to)
{
    char rel[256];
    for (unsigned i = from; i < to; i++) {
        (void)snprintf(rel, sizeof(rel),
                       "docs/response-budget/file-%04u-with-a-long-enough-name-"
                       "to-exercise-the-response-budget.txt",
                       i);
        if (!acc_file(r->alpha, rel, "fixture\n", "wb")) return false;
    }
    return true;
}

static int acc_check_budget_fit(const struct acc_rig *r)
{
    int failures = 0;
    bool filled = acc_fill_docs(r, 0, 400);
    int rc = filled ? acc_fleet(r, NULL, false, acc_out, sizeof(acc_out)) : -1;
    size_t bytes = strlen(acc_out);
    TEST("fleet acceptance: a large valid fleet fits its response envelope") {
        ASSERT(filled && rc == 0);
        ASSERT(bytes > 16384u && bytes <= 65536u);
        ASSERT(acc_has(acc_out, "file-0399-"));
        PASS();
    }
    TEST("fleet acceptance: --field=main_head works on a large response") {
        int frc = acc_fleet(r, "--field=main_head", false, acc_out,
                            sizeof(acc_out));
        ASSERT(frc == 0);
        ASSERT(acc_hasf(acc_out, "main_head=", r->main_head, ""));
        PASS();
    }
    TEST("fleet acceptance: an oversized key=value field is refused, not cut") {
        int src = acc_fleet(r, "--field=lanes", false, acc_scratch,
                            sizeof(acc_scratch));
        int mrc = acc_fleet(r, "--field=lanes", true, acc_out, sizeof(acc_out));
        ASSERT(src != 0 && mrc != 0);
        ASSERT(acc_scratch[0] == '\0');
        ASSERT(acc_has(acc_out, "too large"));
        PASS();
    }
_test_next:;
    return failures;
}

static int acc_check_budget_refuse(const struct acc_rig *r)
{
    int failures = 0;
    int brc = acc_fleet(r, "--budget-bytes=8192", false, acc_out, sizeof(acc_out));
    TEST("fleet acceptance: the caller's --budget-bytes is honoured") {
        ASSERT(brc != 0);
        ASSERT(acc_has(acc_out, "RESPONSE_BUDGET_EXCEEDED"));
        PASS();
    }
    bool filled = acc_fill_docs(r, 400, 1000);
    int rc = filled ? acc_fleet(r, NULL, false, acc_out, sizeof(acc_out)) : 0;
    TEST("fleet acceptance: the declared leaf budget refuses an overflow") {
        ASSERT(filled && rc != 0);
        ASSERT(acc_has(acc_out, "RESPONSE_BUDGET_EXCEEDED"));
        PASS();
    }
_test_next:;
    return failures;
}

static int acc_run(void)
{
    int failures = 0;
    struct acc_rig rig = {0};
    bool built = acc_rig_build(&rig);

    TEST("fleet acceptance: the three-worktree fixture builds") {
        ASSERT(built);
        PASS();
    }
    if (built) {
        failures += acc_check_inventory(&rig);
        failures += acc_check_gates(&rig);
        failures += acc_check_freshness(&rig);
        failures += acc_check_budget_fit(&rig);
        failures += acc_check_budget_refuse(&rig);
    }

_test_next:;
    if (rig.root[0]) (void)test_rm_rf_recursive(rig.root);
    return failures;
}

int test_dev_fleet(void);
int test_dev_fleet(void)
{
    int failures = 0;

    TEST("fleet: the consensus seal is owner-only") {
        ASSERT(zcl_dev_fleet_gate_owner_only("check-core-seal"));
        PASS();
    }

    TEST("fleet: repository hooks are owner-only") {
        ASSERT(zcl_dev_fleet_gate_owner_only("check-git-hooks-installed"));
        PASS();
    }

    TEST("fleet: ordinary source gates remain worker-fixable") {
        ASSERT(!zcl_dev_fleet_gate_owner_only("check-format"));
        ASSERT(!zcl_dev_fleet_gate_owner_only("check-command-registry"));
        ASSERT(!zcl_dev_fleet_gate_owner_only(NULL));
        PASS();
    }

    failures += frx_run();
    failures += acc_run();

_test_next:;
    if (failures == 0) printf("test_dev_fleet: all passed\n");
    else printf("test_dev_fleet: %d FAILED\n", failures);
    return failures;
}
