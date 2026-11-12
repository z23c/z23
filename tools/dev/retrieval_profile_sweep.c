/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay one frozen BM25 cohort across context-window profiles.
 *          The transcript and the sweep receipt go to stdout. Secret-free. */

#include "retrieval_profile_sweep.h"

#include <stdio.h>
#include <string.h>

static int rps_fail(const char *msg)
{
    fprintf(stderr, "retrieval-profile-sweep: FAIL \xe2\x80\x94 %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Byte 43 of the canonical context-only profile is rerank_window.
 * The hex text is 112 characters; the window occupies indexes 86 and 87. */
static const char k_base[] =
    "5a435250524f310a010000040000000000000000000000000000000000000000"
    "010000000000000000000006050000000100000000000000";

static const char *const k_bound_key[] = {
    "schema",
    "tasks_evaluated",
    "input_arm_binding",
    "candidate.recall_at_20.basis_points",
    "candidate.wrong_scope_at_5.available",
    "top20_membership_preserved",
    "full_retained_set_preserved",
    "context_ceiling_preserved",
    "generation_binding",
    "chronology_status",
    "holdout_independence_status",
    "replication_status",
    "promotion_authorized"
};

static const char *const k_bound_want[] = {
    "zcl.retrieval_context_profile_replay.v1",
    "9",
    "bm25_is_profile_baseline",
    "3502",
    "false",
    "true",
    "true",
    "true",
    "unavailable_in_frozen_v3",
    "unverified",
    "unverified",
    "not_run",
    "false"
};

struct rps_job {
    const struct zcl_rps_tools *tools;
    char tmp[PATH_MAX];
    char batch[PATH_MAX];
    char transcript[PATH_MAX];
    char eval_root[80];
    char batch_root[80];
    long recall[21];
    long bytes[21];
};

static int rps_usage(const char *argv0, int argc, char **argv)
{
    const char *name = (argv0 != NULL && argv0[0] != '\0')
                           ? argv0 : "retrieval-profile-sweep";
    if (argc == 2 && argv != NULL && argv[1] != NULL &&
        strcmp(argv[1], "--check") == 0)
        return 0;
    fprintf(stderr, "retrieval-profile-sweep: FAIL \xe2\x80\x94 usage: %s --check\n",
            name);
    return 1;
}

static int rps_exec_ok(const char *path)
{
    return path != NULL && path[0] != '\0' && access(path, X_OK) == 0;
}

static int rps_tools_ready(const struct zcl_rps_tools *tools)
{
    if (tools == NULL || !rps_exec_ok(tools->checker) ||
        !rps_exec_ok(tools->evaluator) || !rps_exec_ok(tools->jsonq) ||
        !rps_exec_ok(tools->sha3))
        return rps_fail("build jsonq, agent-sha3, and retrieval-eval first");
    return 0;
}

static void rps_close2(int fd[2])
{
    if (fd[0] >= 0)
        close(fd[0]);
    if (fd[1] >= 0)
        close(fd[1]);
    fd[0] = -1;
    fd[1] = -1;
}

static int rps_write_all(int fd, const char *text)
{
    const char *cursor = text == NULL ? "" : text;
    while (*cursor != '\0') {
        ssize_t wrote = write(fd, cursor, strlen(cursor));
        if (wrote < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (wrote == 0)
            return -1;
        cursor += wrote;
    }
    return 0;
}

static int rps_wait(pid_t pid)
{
    int status = 0;
    pid_t got = 0;
    while (got == 0) {
        got = waitpid(pid, &status, 0);
        if (got == pid)
            break;
        if (errno != EINTR)
            return -1;
        got = 0;
    }
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int rps_read(int fd, char *out, size_t cap)
{
    size_t used = 0;
    int overflow = 0;
    if (out == NULL || cap == 0)
        return -1;
    out[0] = '\0';
    for (;;) {
        char buf[512];
        ssize_t n = read(fd, buf, sizeof buf);
        size_t take;
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        take = (size_t)n;
        if (used + take >= cap) {
            overflow = 1;
            continue;
        }
        memcpy(out + used, buf, take);
        used += take;
        out[used] = '\0';
    }
    return overflow ? -1 : 0;
}

static void rps_strip(char *text)
{
    char *end;
    if (text == NULL)
        return;
    end = text + strlen(text);
    while (end > text && end[-1] == '\n')
        *--end = '\0';
}

static int rps_hex64(const char *text)
{
    size_t i;
    if (text == NULL || strlen(text) != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = text[i];
        int digit = c >= '0' && c <= '9';
        int lower = c >= 'a' && c <= 'f';
        if (!digit && !lower)
            return 0;
    }
    return 1;
}

static void rps_child(char *const argv[], int in_fd, int out_fd)
{
    if (in_fd >= 0 && dup2(in_fd, STDIN_FILENO) < 0)
        _exit(127);
    if (in_fd > STDERR_FILENO)
        close(in_fd);
    if (out_fd >= 0 && dup2(out_fd, STDOUT_FILENO) < 0)
        _exit(127);
    if (out_fd > STDERR_FILENO)
        close(out_fd);
    if (out_fd < 0) {
        int sink = open("/dev/null", O_WRONLY);
        if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0)
            _exit(127);
        if (sink > STDERR_FILENO)
            close(sink);
    }
    if (setenv("LC_ALL", "C", 1) != 0)
        _exit(127);
    execvp(argv[0], argv);
    _exit(127);
}

static int rps_pipes(const char *in_mem, int capture, int in_pipe[2], int out_pipe[2])
{
    in_pipe[0] = -1;
    in_pipe[1] = -1;
    out_pipe[0] = -1;
    out_pipe[1] = -1;
    if (in_mem != NULL && pipe(in_pipe) != 0)
        return -1;
    if (capture && pipe(out_pipe) != 0) {
        rps_close2(in_pipe);
        return -1;
    }
    return 0;
}

static void rps_as_child(char *const argv[], int in_fd, const char *in_mem,
                         int in_pipe[2], int out_pipe[2], int capture)
{
    int child_in = in_mem != NULL ? in_pipe[0] : in_fd;
    if (in_pipe[1] >= 0)
        close(in_pipe[1]);
    if (out_pipe[0] >= 0)
        close(out_pipe[0]);
    rps_child(argv, child_in, capture ? out_pipe[1] : -1);
    _exit(127);
}

static int rps_parent(pid_t pid, const char *in_mem, char *out, size_t cap,
                      int in_pipe[2], int out_pipe[2], int *status)
{
    int wrote = 0;
    if (in_pipe[0] >= 0)
        close(in_pipe[0]);
    if (out_pipe[1] >= 0)
        close(out_pipe[1]);
    if (in_mem != NULL)
        wrote = rps_write_all(in_pipe[1], in_mem);
    if (wrote == 0 && in_mem != NULL)
        wrote = rps_write_all(in_pipe[1], "\n");
    if (in_pipe[1] >= 0)
        close(in_pipe[1]);
    if (wrote != 0) {
        if (out_pipe[0] >= 0)
            close(out_pipe[0]);
        rps_wait(pid);
        return -1;
    }
    if (out != NULL && rps_read(out_pipe[0], out, cap) != 0) {
        close(out_pipe[0]);
        rps_wait(pid);
        return -1;
    }
    if (out_pipe[0] >= 0)
        close(out_pipe[0]);
    *status = rps_wait(pid);
    return *status < 0 ? -1 : 0;
}

static int rps_run(char *const argv[], int in_fd, const char *in_mem, char *out,
                   size_t cap, int *status)
{
    int in_pipe[2];
    int out_pipe[2];
    pid_t pid;
    if (status == NULL)
        return -1;
    if (rps_pipes(in_mem, out != NULL, in_pipe, out_pipe) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        rps_close2(in_pipe);
        rps_close2(out_pipe);
        return -1;
    }
    if (pid == 0)
        rps_as_child(argv, in_fd, in_mem, in_pipe, out_pipe, out != NULL);
    return rps_parent(pid, in_mem, out, cap, in_pipe, out_pipe, status);
}

static int rps_hash(const char *sha3, const char *path, char *out, size_t cap)
{
    char text[1024];
    char *argv[3];
    char *gap;
    int status = 1;
    argv[0] = (char *)sha3;
    argv[1] = (char *)path;
    argv[2] = NULL;
    if (rps_run(argv, -1, NULL, text, sizeof text, &status) != 0 || status != 0)
        return -1;
    rps_strip(text);
    gap = strchr(text, ' ');
    if (gap != NULL)
        *gap = '\0';
    if (!rps_hex64(text))
        return -1;
    if (strlen(text) + 1 > cap)
        return -1;
    memcpy(out, text, strlen(text) + 1);
    return 0;
}

static int rps_json(const char *jsonq, const char *row, const char *key,
                    char *out, size_t cap)
{
    char *argv[4];
    int status = 1;
    argv[0] = (char *)jsonq;
    argv[1] = "get";
    argv[2] = (char *)key;
    argv[3] = NULL;
    if (rps_run(argv, -1, row, out, cap, &status) != 0 || status != 0)
        return -1;
    rps_strip(out);
    return 0;
}

static int rps_long(const char *text, long *out)
{
    char *end = NULL;
    long value;
    if (text == NULL || text[0] == '\0')
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (end == text || *end != '\0' || errno != 0)
        return -1;
    *out = value;
    return 0;
}

static int rps_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int rps_nonempty(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) && st.st_size > 0;
}

static int rps_tmpdir(struct rps_job *job)
{
    const char *base = getenv("TMPDIR");
    int n;
    if (base == NULL || base[0] == '\0')
        base = "/tmp";
    n = snprintf(job->tmp, sizeof job->tmp,
                 "%s/z23-retrieval-profile-sweep.XXXXXX", base);
    if (n < 0 || (size_t)n >= sizeof job->tmp)
        return -1;
    if (mkdtemp(job->tmp) == NULL)
        return -1;
    return 0;
}

static int rps_rm(const char *dir)
{
    DIR *handle = opendir(dir);
    struct dirent *ent;
    if (handle == NULL)
        return -1;
    while ((ent = readdir(handle)) != NULL) {
        char path[PATH_MAX];
        int n;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        n = snprintf(path, sizeof path, "%s/%s", dir, ent->d_name);
        if (n > 0 && (size_t)n < sizeof path)
            unlink(path);
    }
    closedir(handle);
    return rmdir(dir);
}

static void rps_end(struct rps_job *job)
{
    if (job->tmp[0] != '\0')
        rps_rm(job->tmp);
    job->tmp[0] = '\0';
}

static int rps_begin(struct rps_job *job, const struct zcl_rps_tools *tools)
{
    char *argv[4];
    int status = 1;
    job->tools = tools;
    if (rps_tmpdir(job) != 0)
        return rps_fail("cannot create a work directory");
    argv[0] = (char *)tools->checker;
    argv[1] = "--emit-evaluator-batches";
    argv[2] = job->tmp;
    argv[3] = NULL;
    if (rps_run(argv, -1, NULL, NULL, 0, &status) != 0 || status != 0)
        return rps_fail("frozen BM25 evidence did not verify or decode");
    if (rps_join(job->batch, sizeof job->batch, job->tmp, "evaluator.batch") != 0)
        return rps_fail("verified checker emitted no evaluator batch");
    if (!rps_nonempty(job->batch))
        return rps_fail("verified checker emitted no evaluator batch");
    if (rps_join(job->transcript, sizeof job->transcript, job->tmp,
                 "profile-transcript.jsonl") != 0)
        return rps_fail("verified checker emitted no evaluator batch");
    if (rps_hash(tools->sha3, tools->evaluator, job->eval_root,
                 sizeof job->eval_root) != 0)
        return rps_fail("cannot hash evaluator");
    if (rps_hash(tools->sha3, job->batch, job->batch_root,
                 sizeof job->batch_root) != 0)
        return rps_fail("cannot hash reconstructed batch");
    return 0;
}

static int rps_boundary(const char *jsonq, const char *row)
{
    size_t i;
    size_t n = sizeof k_bound_key / sizeof k_bound_key[0];
    for (i = 0; i < n; i++) {
        char got[128];
        if (rps_json(jsonq, row, k_bound_key[i], got, sizeof got) != 0)
            return -1;
        if (strcmp(got, k_bound_want[i]) != 0)
            return -1;
    }
    return 0;
}

static int rps_roots(struct rps_job *job, const char *row)
{
    char batch[80];
    char evaluator[80];
    char result[80];
    if (rps_json(job->tools->jsonq, row, "raw_batch_root_sha3", batch,
                 sizeof batch) != 0)
        return -1;
    if (strcmp(batch, job->batch_root) != 0)
        return -1;
    if (rps_json(job->tools->jsonq, row, "caller_supplied_evaluator_root_sha3",
                 evaluator, sizeof evaluator) != 0)
        return -1;
    if (strcmp(evaluator, job->eval_root) != 0)
        return -1;
    if (rps_json(job->tools->jsonq, row, "evaluation_result_root_sha3", result,
                 sizeof result) != 0)
        return -1;
    if (!rps_hex64(result))
        return -1;
    return 0;
}

static int rps_metrics(struct rps_job *job, const char *row, int window)
{
    char recall[32];
    char bytes[32];
    long recall_v = 0;
    long bytes_v = 0;
    if (rps_json(job->tools->jsonq, row, "candidate.recall_at_5.basis_points",
                 recall, sizeof recall) != 0)
        return -1;
    if (rps_json(job->tools->jsonq, row, "candidate.projected_context_bytes_at_5",
                 bytes, sizeof bytes) != 0)
        return -1;
    if (rps_long(recall, &recall_v) != 0 || rps_long(bytes, &bytes_v) != 0)
        return -1;
    job->recall[window] = recall_v;
    job->bytes[window] = bytes_v;
    return 0;
}

static int rps_profile(char *out, size_t cap, int window)
{
    int n;
    if (strlen(k_base) != 112)
        return -1;
    n = snprintf(out, cap, "%.*s%02x%s", 86, k_base, window, k_base + 88);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int rps_fail_win(int window, const char *what)
{
    fprintf(stderr, "retrieval-profile-sweep: FAIL \xe2\x80\x94 window %d %s\n",
            window, what);
    return 1;
}

static int rps_append(const char *path, const char *row)
{
    FILE *file = fopen(path, "a");
    int n;
    if (file == NULL)
        return -1;
    n = fprintf(file, "%s\n", row);
    if (n < 0 || fclose(file) != 0)
        return -1;
    return 0;
}

static int rps_eval(struct rps_job *job, const char *profile, char *row, size_t cap)
{
    int fd = open(job->batch, O_RDONLY);
    char *argv[6];
    int status = 1;
    int rc;
    if (fd < 0)
        return -1;
    argv[0] = (char *)job->tools->evaluator;
    argv[1] = "--profile-hex";
    argv[2] = (char *)profile;
    argv[3] = "--evaluator-root";
    argv[4] = job->eval_root;
    argv[5] = NULL;
    rc = rps_run(argv, fd, NULL, row, cap, &status);
    close(fd);
    if (rc != 0 || status != 0)
        return -1;
    rps_strip(row);
    return row[0] == '\0' ? -1 : 0;
}

static int rps_one(struct rps_job *job, int window)
{
    char profile[160];
    char row[8192];
    if (rps_profile(profile, sizeof profile, window) != 0)
        return rps_fail_win(window, "evaluation was refused");
    if (rps_eval(job, profile, row, sizeof row) != 0)
        return rps_fail_win(window, "evaluation was refused");
    if (rps_boundary(job->tools->jsonq, row) != 0)
        return rps_fail_win(window, "evidence boundary differs");
    if (rps_roots(job, row) != 0)
        return rps_fail_win(window, "exact root binding differs");
    if (rps_metrics(job, row, window) != 0)
        return rps_fail_win(window, "evidence boundary differs");
    if (rps_append(job->transcript, row) != 0)
        return rps_fail_win(window, "evaluation was refused");
    return 0;
}

static int rps_all(struct rps_job *job)
{
    int window;
    for (window = 5; window <= 20; window++) {
        if (rps_one(job, window) != 0)
            return 1;
    }
    return 0;
}

static int rps_dominated(const long *recall, const long *bytes, int candidate)
{
    int peer;
    for (peer = 5; peer <= 20; peer++) {
        int recall_ge = recall[peer] >= recall[candidate];
        int bytes_le = bytes[peer] <= bytes[candidate];
        int strict = recall[peer] > recall[candidate] || bytes[peer] < bytes[candidate];
        if (recall_ge && bytes_le && strict)
            return 1;
    }
    return 0;
}

static void rps_collect(const struct rps_job *job, int *pareto, int *count)
{
    int candidate;
    *count = 0;
    for (candidate = 5; candidate <= 20; candidate++) {
        if (rps_dominated(job->recall, job->bytes, candidate))
            continue;
        pareto[(*count)++] = candidate;
    }
}

static int rps_format(const int *pareto, int count, char *out, size_t cap)
{
    size_t used = 0;
    int i;
    out[0] = '\0';
    for (i = 0; i < count; i++) {
        int n = snprintf(out + used, cap - used, "%s%d", i == 0 ? "" : " ",
                         pareto[i]);
        if (n < 0 || (size_t)n >= cap - used)
            return -1;
        used += (size_t)n;
    }
    return 0;
}

static int rps_known(const struct rps_job *job)
{
    if (job->recall[5] != 936 || job->bytes[5] != 853082)
        return -1;
    if (job->recall[7] != 962 || job->bytes[7] != 567606)
        return -1;
    if (job->recall[20] != 555 || job->bytes[20] != 226991)
        return -1;
    return 0;
}

static int rps_cat(const char *path)
{
    FILE *file = fopen(path, "r");
    char buf[4096];
    size_t n;
    if (file == NULL)
        return -1;
    while ((n = fread(buf, 1, sizeof buf, file)) > 0) {
        if (fwrite(buf, 1, n, stdout) != n) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);
    return fflush(stdout) == 0 ? 0 : -1;
}

static void rps_emit(const struct rps_job *job, const char *receipt,
                     const char *jsonq, const char *source, const char *transcript)
{
    printf("{\"schema\":\"zcl.retrieval_context_profile_sweep.v1\","
           "\"input_receipt_sha3\":\"%s\","
           "\"reconstructed_batch_sha3\":\"%s\","
           "\"evaluator_binary_sha3\":\"%s\","
           "\"json_parser_binary_sha3\":\"%s\","
           "\"sweep_script_sha3\":\"%s\","
           "\"candidate_transcript_sha3\":\"%s\","
           "\"windows_evaluated\":16,\"tasks_evaluated\":9,"
           "\"primary_metric\":\"recall_at_5\","
           "\"cost_metric\":\"projected_context_bytes_at_5\","
           "\"baseline_window\":5,\"baseline_recall_at_5_bp\":936,"
           "\"baseline_projected_context_bytes_at_5\":853082,"
           "\"exploratory_window\":7,\"exploratory_recall_at_5_bp\":962,"
           "\"exploratory_projected_context_bytes_at_5\":567606,"
           "\"pareto_windows\":[7,8,9,12,20],"
           "\"claim_scope\":\"counterfactual_replay_conditional_on_frozen_v3_rows\","
           "\"generation_binding\":\"unavailable\","
           "\"chronology_status\":\"unverified\","
           "\"holdout_independence_status\":\"unverified\","
           "\"selection_status\":\"retain_for_independent_replication_not_promotion\","
           "\"replication_status\":\"not_run\","
           "\"promotion_authorized\":false}\n",
           receipt, job->batch_root, job->eval_root, jsonq, source, transcript);
}

static int rps_pareto_fail(const char *list)
{
    fprintf(stderr,
            "retrieval-profile-sweep: FAIL \xe2\x80\x94 "
            "reviewed Pareto window set changed: %s\n",
            list);
    return 1;
}

static int rps_finish(struct rps_job *job)
{
    int pareto[16];
    int count = 0;
    char list[64];
    char receipt[80];
    char jsonq[80];
    char source[80];
    char transcript[80];
    if (rps_known(job) != 0)
        return rps_fail("reviewed window known answers changed");
    rps_collect(job, pareto, &count);
    if (rps_format(pareto, count, list, sizeof list) != 0)
        return rps_pareto_fail("");
    if (strcmp(list, "7 8 9 12 20") != 0)
        return rps_pareto_fail(list);
    if (rps_cat(job->transcript) != 0)
        return rps_fail("cannot read transcript");
    if (rps_hash(job->tools->sha3, job->tools->receipt, receipt, sizeof receipt) != 0)
        return rps_fail("cannot hash receipt");
    if (rps_hash(job->tools->sha3, job->tools->sweep_source, source, sizeof source) != 0)
        return rps_fail("cannot hash sweep script");
    if (rps_hash(job->tools->sha3, job->tools->jsonq, jsonq, sizeof jsonq) != 0)
        return rps_fail("cannot hash JSON parser");
    if (rps_hash(job->tools->sha3, job->transcript, transcript, sizeof transcript) != 0)
        return rps_fail("cannot hash transcript");
    rps_emit(job, receipt, jsonq, source, transcript);
    return 0;
}

static int rps_invoke(const char *argv0, int argc, char **argv,
                      const struct zcl_rps_tools *tools)
{
    struct rps_job job;
    int rc;
    memset(&job, 0, sizeof job);
    if (rps_usage(argv0, argc, argv) != 0)
        return 1;
    if (rps_tools_ready(tools) != 0)
        return 1;
    if (rps_begin(&job, tools) != 0) {
        rps_end(&job);
        return 1;
    }
    rc = rps_all(&job);
    if (rc == 0)
        rc = rps_finish(&job);
    rps_end(&job);
    return rc;
}

#endif /* !_WIN32 */

int zcl_retrieval_profile_sweep(const char *argv0, int argc, char **argv,
                                const struct zcl_rps_tools *tools)
{
#if defined(_WIN32)
    (void)argv0;
    (void)argc;
    (void)argv;
    (void)tools;
    return rps_fail("unavailable on Windows");
#else
    return rps_invoke(argv0, argc, argv, tools);
#endif
}
