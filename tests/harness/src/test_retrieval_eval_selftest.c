/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict batch adapter mutation checks for build/bin/retrieval-eval,
 * ported from the retired retrieval-eval-selftest shell script. The evaluator and jsonq run
 * as real subprocesses (no shell) over fixtures in this group's temp dir. Every
 * valid batch must reproduce the maintained metrics, and every mutated batch
 * must be refused, with no partial evidence on stdout. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "test/test_core.h"

#include <stdio.h>

#if defined(_WIN32)

int test_retrieval_eval_selftest(void)
{
    printf("retrieval_eval_selftest: SKIP (Windows): POSIX fork/exec child lane\n");
    return 0;
}

#else

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define RE_EVAL_BIN "build/bin/retrieval-eval"
#define RE_JSONQ_BIN "build/bin/jsonq"
#define RE_OUT_MAX 16384u
#define RE_TEXT_MAX 4096u
#define RE_FIELD_MAX 256u

/* Records a failed condition and keeps going, so one run reports every
 * mismatch. TEST blocks share one function scope, so no goto label here. */
#define RE_CHECK(cond_) do {                                                \
    if (!(cond_)) {                                                         \
        printf("FAIL at %s:%d (%s)\n", __FILE__, __LINE__, #cond_);         \
        failures++;                                                         \
    }                                                                       \
} while (0)

#define RE_VALID_BODY                                                       \
    "zcl.retrieval_eval_batch.v3 tasks=1 eligible_relevance_judgments=1\n"  \
    "task task_a 1\n"                                                       \
    "query find a\n"                                                        \
    "relevant a.c\n"                                                        \
    "literal observed 1 2\n"                                                \
    "rank 10 1 0 x.c\n"                                                     \
    "rank 20 1 1 a.c\n"                                                     \
    "bm25 observed 1 1\n"                                                   \
    "rank 5 0 0 a.c\n"
#define RE_VALID RE_VALID_BODY "end\n"

#define RE_EXPERIMENT                                                       \
    "zcl.retrieval_eval_batch.v3 tasks=1 eligible_relevance_judgments=1\n"  \
    "task task_a 1\n"                                                       \
    "query find a\n"                                                        \
    "relevant a.c\n"                                                        \
    "literal observed 1 6\n"                                                \
    "rank 10 1 1 b.c\n"                                                     \
    "rank 20 1 1 c.c\n"                                                     \
    "rank 30 1 1 d.c\n"                                                     \
    "rank 40 1 1 e.c\n"                                                     \
    "rank 50 1 1 f.c\n"                                                     \
    "rank 10 1 1 a.c\n"                                                     \
    "bm25 observed 1 6\n"                                                   \
    "rank 10 1 1 a.c\n"                                                     \
    "rank 10 1 1 b.c\n"                                                     \
    "rank 20 1 1 c.c\n"                                                     \
    "rank 30 1 1 d.c\n"                                                     \
    "rank 40 1 1 e.c\n"                                                     \
    "rank 50 1 1 f.c\n"                                                     \
    "end\n"

#define RE_PROFILE                                                          \
    "5a435250524f310a010000040000000000000000000000000000000000000000"      \
    "010000000000000000000006050000000100000000000000"
#define RE_EVALUATOR_ROOT                                                   \
    "1111111111111111111111111111111111111111111111111111111111111111"

#define RE_RANK_ROOT "b78e5feb676ba4b2d2e3032d269d929a79a49a71ff9932901b037f0466a861ec"
#define RE_RANK_TSV "1\t10\tx.c\n2\t20\ta.c\n"

struct re_capture {
    char out[RE_OUT_MAX];
    size_t len;
};

struct re_expect {
    const char *key;
    const char *want;
};

/* The same overrides the retired shell script honored, so a lane can point
 * this group at another build. Unset or empty falls back to build/bin. */
static const char *re_binary(const char *path)
{
    const char *env = NULL;
    if (strcmp(path, RE_EVAL_BIN) == 0) env = getenv("ZCL_RETRIEVAL_EVAL");
    else if (strcmp(path, RE_JSONQ_BIN) == 0) env = getenv("ZCL_JSONQ");
    return env && env[0] != '\0' ? env : path;
}

/* Child side of fork: stdin from the fixture (or /dev/null), stdout to the
 * capture pipe, stderr silenced so expected refusals stay quiet. */
static void re_child(int out_fd, const char *input, const char *const argv[])
{
    int in = open(input ? input : "/dev/null", O_RDONLY);
    int err = open("/dev/null", O_WRONLY);
    if (in < 0 || err < 0 || dup2(in, STDIN_FILENO) < 0 ||
        dup2(out_fd, STDOUT_FILENO) < 0 || dup2(err, STDERR_FILENO) < 0)
        _exit(127);
    execv(re_binary(argv[0]), (char *const *)argv);
    _exit(127);
}

/* Reads the capture pipe to EOF. Returns true when the output overflowed. */
static bool re_drain(int fd, struct re_capture *cap)
{
    bool overflow = false;
    for (;;) {
        size_t room = RE_OUT_MAX - 1u - cap->len;
        if (room == 0) {
            overflow = true;
            break;
        }
        ssize_t n = read(fd, cap->out + cap->len, room);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            overflow = true;
            break;
        }
        cap->len += (size_t)n;
    }
    cap->out[cap->len] = '\0';
    return overflow;
}

/* Runs argv (argv[0] is the binary) with stdin from input (NULL: /dev/null).
 * Returns the exit status, or -1 when the child did not exit normally or its
 * output overflowed the capture. No shell is involved. */
static int re_run(const char *const argv[], const char *input,
                  struct re_capture *cap)
{
    int fds[2];
    cap->len = 0;
    cap->out[0] = '\0';
    if (pipe(fds) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        (void)close(fds[0]);
        re_child(fds[1], input, argv);
    }
    (void)close(fds[1]);
    bool overflow = re_drain(fds[0], cap);
    (void)close(fds[0]);
    int status = 0;
    pid_t got;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got != pid || overflow || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static bool re_path(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

static bool re_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(text);
    bool written = fwrite(text, 1, length, file) == length;
    return fclose(file) == 0 && written;
}

/* Writes text to dir/name, then runs the evaluator on it. Returns false only
 * when the fixture could not be written; *status carries the child's result. */
static bool re_eval_text(const char *dir, const char *name, const char *text,
                         const char *const argv[], int *status,
                         struct re_capture *cap)
{
    char path[PATH_MAX];
    if (!re_path(path, sizeof path, dir, name) || !re_write(path, text))
        return false;
    *status = re_run(argv, path, cap);
    return true;
}

/* Replaces the nth (1-based) occurrence of old in src with repl. This is the
 * sed `s` used by the shell script on single-occurrence fixture lines. */
static bool re_sub(char *dst, size_t cap, const char *src, const char *old,
                   const char *repl, size_t nth)
{
    const char *hit = NULL, *from = src;
    size_t olen = strlen(old), rlen = strlen(repl), tlen = strlen(src);
    for (size_t i = 0; i < nth; i++) {
        hit = strstr(from, old);
        if (!hit) return false;
        from = hit + olen;
    }
    size_t head = (size_t)(hit - src);
    if (tlen - olen + rlen >= cap) return false;
    memcpy(dst, src, head);
    memcpy(dst + head, repl, rlen);
    memcpy(dst + head + rlen, hit + olen, tlen - head - olen + 1u);
    return true;
}

/* Evaluates a batch in full and reports whether the evaluator refused it. */
static bool re_refused_text(const char *dir, const char *name,
                            const char *text)
{
    static const char *const argv[] = {RE_EVAL_BIN, NULL};
    struct re_capture cap = {};
    int status = 0;
    return re_eval_text(dir, name, text, argv, &status, &cap) && status != 0;
}

/* Substitutes one occurrence in src, then reports whether it was refused. */
static bool re_refused_sub(const char *dir, const char *name, const char *src,
                           const char *old, const char *repl, size_t nth)
{
    char text[RE_TEXT_MAX];
    return re_sub(text, sizeof text, src, old, repl, nth) &&
           re_refused_text(dir, name, text);
}

/* Extracts one jsonq field from a document. The value has trailing newlines
 * removed, matching the shell's $(...) capture. */
static bool re_field(const char *dir, const char *doc, const char *key,
                     char *value, size_t cap)
{
    char path[PATH_MAX];
    struct re_capture got = {};
    const char *argv[] = {RE_JSONQ_BIN, "get", key, NULL};
    if (!re_path(path, sizeof path, dir, "doc.json") || !re_write(path, doc))
        return false;
    if (re_run(argv, path, &got) != 0) return false;
    size_t n = got.len;
    while (n > 0 && got.out[n - 1u] == '\n') got.out[--n] = '\0';
    if (n >= cap) return false;
    memcpy(value, got.out, n + 1u);
    return true;
}

static bool re_is(const char *dir, const char *doc, const char *key,
                  const char *want)
{
    char value[RE_FIELD_MAX];
    if (re_field(dir, doc, key, value, sizeof value) &&
        strcmp(value, want) == 0)
        return true;
    printf("    retrieval_eval_selftest: %s is not %s\n", key, want);
    return false;
}

static bool re_check_table(const char *dir, const char *doc,
                           const struct re_expect *rows, size_t count)
{
    bool ok = true;
    for (size_t i = 0; i < count; i++)
        ok &= re_is(dir, doc, rows[i].key, rows[i].want);
    return ok;
}

/* equal=true requires both documents to agree on key; false requires a split. */
static bool re_compare(const char *dir, const char *left, const char *right,
                       const char *key, bool equal)
{
    char a[RE_FIELD_MAX], b[RE_FIELD_MAX];
    if (!re_field(dir, left, key, a, sizeof a) ||
        !re_field(dir, right, key, b, sizeof b))
        return false;
    return (strcmp(a, b) == 0) == equal;
}

static bool re_trimmed_equals(const struct re_capture *cap, const char *want)
{
    size_t n = cap->len;
    while (n > 0 && cap->out[n - 1u] == '\n') n--;
    return strlen(want) == n && memcmp(cap->out, want, n) == 0;
}

static int re_fixtures_ready(void)
{
    if (access(re_binary(RE_EVAL_BIN), X_OK) == 0 &&
        access(re_binary(RE_JSONQ_BIN), X_OK) == 0)
        return 1;
    printf("retrieval_eval_selftest: FAIL build retrieval-eval and jsonq first\n");
    return 0;
}

static int test_re_valid_batch(const char *dir)
{
    int failures = 0;
    static const struct re_expect metrics[] = {
        {"schema", "zcl.retrieval_eval_batch_result.v3"},
        {"tasks_evaluated", "1"},
        {"aggregation_kind", "macro_equal_task_weight"},
        {"tasks_denominator", "1"},
        {"eligible_relevance_judgments", "1"},
        {"literal.recall_at_5.basis_points", "10000"},
        {"literal.mrr.basis_points", "5000"},
        {"literal.wrong_scope_at_5.available", "true"},
        {"literal.wrong_scope_at_5.basis_points", "5000"},
        {"bm25.wrong_scope_at_5.available", "false"},
    };
    static const char *const argv[] = {RE_EVAL_BIN, NULL};
    struct re_capture cap = {};
    int status = 0;
    TEST("retrieval-eval: valid batch is accepted with maintained metrics") {
        RE_CHECK(re_eval_text(dir, "valid.batch", RE_VALID, argv, &status,
                            &cap));
        RE_CHECK(status == 0);
        RE_CHECK(re_check_table(dir, cap.out, metrics,
                              sizeof metrics / sizeof metrics[0]));
    }
    static const char *const rank_argv[] = {RE_EVAL_BIN, "--rank-root", "1",
                                            NULL};
    TEST("retrieval-eval: ranking root known answer and refusals") {
        RE_CHECK(re_eval_text(dir, "rank.tsv", RE_RANK_TSV, rank_argv, &status,
                            &cap));
        RE_CHECK(status == 0);
        RE_CHECK(re_trimmed_equals(&cap, RE_RANK_ROOT));
        RE_CHECK(re_eval_text(dir, "rank-gap.tsv", "2\t10\tx.c\n", rank_argv,
                            &status, &cap));
        RE_CHECK(status != 0);
        RE_CHECK(re_eval_text(dir, "rank-space.tsv", "1 10 x.c\n", rank_argv,
                            &status, &cap));
        RE_CHECK(status != 0);
    }
    return failures;
}

static int test_re_refused_batches(const char *dir)
{
    int failures = 0;
    TEST("retrieval-eval: duplicate, negative and trailing evidence are refused") {
        RE_CHECK(re_refused_sub(dir, "duplicate.batch", RE_VALID,
                              "rank 20 1 1 a.c", "rank 20 1 1 x.c", 1));
        RE_CHECK(re_refused_sub(dir, "negative.batch", RE_VALID,
                              "rank 10 1 0 x.c", "rank -1 1 0 x.c", 1));
        RE_CHECK(re_refused_text(dir, "trailing.batch",
                               RE_VALID_BODY "end\ntrailing\n"));
    }
    TEST("retrieval-eval: false and overflowing counts are refused") {
        RE_CHECK(re_refused_sub(dir, "task-count.batch", RE_VALID,
                              "tasks=1", "tasks=2", 1));
        RE_CHECK(re_refused_sub(dir, "relevance-count.batch", RE_VALID,
                              "eligible_relevance_judgments=1",
                              "eligible_relevance_judgments=2", 1));
        RE_CHECK(re_refused_sub(dir, "task-count-overflow.batch", RE_VALID,
                              "tasks=1", "tasks=18446744073709551616", 1));
        RE_CHECK(re_refused_sub(dir, "relevance-count-overflow.batch", RE_VALID,
                              "eligible_relevance_judgments=1",
                              "eligible_relevance_judgments=18446744073709551616",
                              1));
    }
    TEST("retrieval-eval: noncanonical, traversal, scope and unobserved are refused") {
        RE_CHECK(re_refused_sub(dir, "noncanonical-number.batch", RE_VALID,
                              "rank 10 1 0 x.c", "rank 010 1 0 x.c", 1));
        RE_CHECK(re_refused_sub(dir, "traversal.batch", RE_VALID,
                              "rank 10 1 0 x.c", "rank 10 1 0 x/..", 1));
        RE_CHECK(re_refused_sub(dir, "scope.batch", RE_VALID,
                              "rank 5 0 0 a.c", "rank 5 0 1 a.c", 1));
        RE_CHECK(re_refused_sub(dir, "unobserved.batch", RE_VALID,
                              "literal observed 1 2",
                              "literal unobserved 1 2", 1));
    }
    return failures;
}

static int test_re_experiment(const char *dir)
{
    int failures = 0;
    static const struct re_expect parent_rows[] = {
        {"schema", "zcl.retrieval_experiment_eval_result.v1"},
        {"candidate.recall_at_5.basis_points", "10000"},
        {"candidate.wrong_scope_at_5.available", "false"},
        {"projector_gold_input", "none"},
        {"promotion_authorized", "false"},
    };
    static const char *const parent_argv[] = {RE_EVAL_BIN, "--experiment-prefix",
                                              "0", NULL};
    static const char *const base_argv[] = {RE_EVAL_BIN, "--experiment-prefix",
                                            "5", NULL};
    static const char *const over_argv[] = {RE_EVAL_BIN, "--experiment-prefix",
                                            "6", NULL};
    struct re_capture parent = {}, base = {}, refused = {};
    int status = 0;
    TEST("retrieval-eval: experiment boundary and metrics match the evaluator") {
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, parent_argv,
                            &status, &parent));
        RE_CHECK(status == 0);
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, base_argv,
                            &status, &base));
        RE_CHECK(status == 0);
        RE_CHECK(re_check_table(dir, parent.out, parent_rows,
                              sizeof parent_rows / sizeof parent_rows[0]));
        RE_CHECK(re_is(dir, base.out, "candidate.recall_at_5.basis_points", "0"));
    }
    TEST("retrieval-eval: out-of-range experiment prefix is refused") {
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, over_argv,
                            &status, &refused));
        RE_CHECK(status != 0);
    }
    return failures;
}

static int test_re_profile_replay(const char *dir)
{
    int failures = 0;
    static const struct re_expect rows[] = {
        {"schema", "zcl.retrieval_context_profile_replay.v1"},
        {"input_arm_binding", "bm25_is_profile_baseline"},
        {"generation_binding", "unavailable_in_frozen_v3"},
        {"projector_relevance_input_channel", "none"},
        {"gold_separation", "api_surface_only_same_process"},
        {"candidate.recall_at_5.basis_points", "10000"},
        {"candidate.wrong_scope_at_5.available", "false"},
        {"replay_hypothesis_root_sha3",
         "863e3921f6e6375d0f6354629334723cb18ef6b14c01be3502244b56605e2354"},
        {"candidate_batch_root_sha3",
         "a6d5b8d292ed781c7ef7b5fd272c850a34bedf0b481144ee9b5207e684e460f5"},
        {"evaluation_result_root_sha3",
         "35faf9e287186608513df3c43f7f0ffb6ad28f21751f3cd4f1b4ad785b1b4bef"},
        {"chronology_status", "unverified"},
        {"holdout_independence_status", "unverified"},
        {"promotion_authorized", "false"},
    };
    static const char *const argv[] = {RE_EVAL_BIN, "--profile-hex", RE_PROFILE,
                                       "--evaluator-root", RE_EVALUATOR_ROOT,
                                       NULL};
    struct re_capture first = {}, second = {};
    int status = 0;
    TEST("retrieval-eval: context-only profile replay identity and boundary") {
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, argv,
                            &status, &first));
        RE_CHECK(status == 0);
        RE_CHECK(re_check_table(dir, first.out, rows,
                              sizeof rows / sizeof rows[0]));
    }
    TEST("retrieval-eval: profile replay is deterministic") {
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, argv,
                            &status, &second));
        RE_CHECK(status == 0);
        RE_CHECK(strcmp(first.out, second.out) == 0);
    }
    return failures;
}

static int test_re_profile_mutations(const char *dir)
{
    int failures = 0;
    static const char *const argv[] = {RE_EVAL_BIN, "--profile-hex", RE_PROFILE,
                                       "--evaluator-root", RE_EVALUATOR_ROOT,
                                       NULL};
    struct re_capture base = {}, gold = {}, literal = {}, scope = {}, bm25 = {};
    char text[RE_TEXT_MAX];
    int status = 0;
    TEST("retrieval-eval: base profile replay accepted for mutation checks") {
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, argv,
                            &status, &base));
        RE_CHECK(status == 0);
    }
    TEST("retrieval-eval: gold label change stays on the evaluation side") {
        RE_CHECK(re_sub(text, sizeof text, RE_EXPERIMENT, "relevant a.c",
                      "relevant f.c", 1));
        RE_CHECK(re_eval_text(dir, "gold.batch", text, argv, &status, &gold));
        RE_CHECK(status == 0);
        RE_CHECK(re_compare(dir, base.out, gold.out,
                          "replay_hypothesis_root_sha3", true));
        RE_CHECK(re_compare(dir, base.out, gold.out,
                          "candidate_batch_root_sha3", true));
        RE_CHECK(re_compare(dir, base.out, gold.out,
                          "evaluation_input_root_sha3", false));
        RE_CHECK(re_compare(dir, base.out, gold.out,
                          "evaluation_result_root_sha3", false));
    }
    TEST("retrieval-eval: irrelevant literal arm change stays off the proposal") {
        RE_CHECK(re_sub(text, sizeof text, RE_EXPERIMENT, "rank 10 1 1 b.c",
                      "rank 11 1 1 b.c", 1));
        RE_CHECK(re_eval_text(dir, "literal.batch", text, argv, &status,
                            &literal));
        RE_CHECK(status == 0);
        RE_CHECK(re_compare(dir, base.out, literal.out,
                          "replay_hypothesis_root_sha3", true));
        RE_CHECK(re_compare(dir, base.out, literal.out,
                          "candidate_batch_root_sha3", true));
        RE_CHECK(re_compare(dir, base.out, literal.out,
                          "evaluation_input_root_sha3", false));
    }
    TEST("retrieval-eval: scope bit change enters evaluation, not proposal") {
        RE_CHECK(re_sub(text, sizeof text, RE_EXPERIMENT, "rank 10 1 1 a.c",
                      "rank 10 0 0 a.c", 2));
        RE_CHECK(re_eval_text(dir, "scope.batch", text, argv, &status, &scope));
        RE_CHECK(status == 0);
        RE_CHECK(re_compare(dir, base.out, scope.out,
                          "replay_hypothesis_root_sha3", true));
        RE_CHECK(re_compare(dir, base.out, scope.out,
                          "candidate_batch_root_sha3", true));
        RE_CHECK(re_compare(dir, base.out, scope.out, "raw_batch_root_sha3",
                          false));
        RE_CHECK(re_compare(dir, base.out, scope.out,
                          "evaluation_result_root_sha3", false));
    }
    TEST("retrieval-eval: BM25 baseline change moves the replay hypothesis") {
        RE_CHECK(re_sub(text, sizeof text, RE_EXPERIMENT, "rank 10 1 1 a.c",
                      "rank 11 1 1 a.c", 2));
        RE_CHECK(re_eval_text(dir, "bm25.batch", text, argv, &status, &bm25));
        RE_CHECK(status == 0);
        RE_CHECK(re_compare(dir, base.out, bm25.out,
                          "replay_hypothesis_root_sha3", false));
    }
    return failures;
}

static int test_re_profile_refusals(const char *dir)
{
    int failures = 0;
    char profile[sizeof RE_PROFILE], top_four[sizeof RE_PROFILE];
    struct re_capture cap = {};
    int status = 0;
    const char *arg_argv[] = {RE_EVAL_BIN, "--profile-hex", profile,
                              "--evaluator-root", RE_EVALUATOR_ROOT, NULL};
    TEST("retrieval-eval: uppercase profile wire is refused with no output") {
        RE_CHECK(re_sub(profile, sizeof profile, RE_PROFILE, "a", "A", 1));
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, arg_argv,
                            &status, &cap));
        RE_CHECK(status != 0);
        RE_CHECK(cap.len == 0);
    }
    TEST("retrieval-eval: top-four profile is not presented as at-five") {
        RE_CHECK(re_sub(top_four, sizeof top_four, RE_PROFILE, "06050000",
                      "06040000", 1));
        arg_argv[2] = top_four;
        RE_CHECK(re_eval_text(dir, "experiment.batch", RE_EXPERIMENT, arg_argv,
                            &status, &cap));
        RE_CHECK(status != 0);
        RE_CHECK(cap.len == 0);
    }
    TEST("retrieval-eval: short baseline is not presented as at-five") {
        arg_argv[2] = RE_PROFILE;
        RE_CHECK(re_eval_text(dir, "short.batch", RE_VALID, arg_argv, &status,
                            &cap));
        RE_CHECK(status != 0);
        RE_CHECK(cap.len == 0);
    }
    return failures;
}

int test_retrieval_eval_selftest(void)
{
    if (!re_fixtures_ready()) return 1;
    char dir[PATH_MAX];
    test_make_tmpdir(dir, sizeof dir, "retrieval_eval_selftest", "fixtures");
    int failures = test_re_valid_batch(dir) + test_re_refused_batches(dir) +
                   test_re_experiment(dir) + test_re_profile_replay(dir) +
                   test_re_profile_mutations(dir) +
                   test_re_profile_refusals(dir);
    test_rm_rf_recursive(dir);
    return failures;
}

#endif
