/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay synthetic proof-perf logs through the real report script
 *          and require its accounting lines. The report shell stays. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "zcode_async_proof_perf_selftest.h"

#include <stdio.h>
#include <string.h>

static int ppr_fail(const char *msg)
{
    fprintf(stderr, "proof-perf selftest: %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char k_ppr_full[] =
    "{\"foreground_request_creation_us\":1,"
    "\"durable_action_lookup_dedup_us\":2,\"local_submit_us\":3,"
    "\"local_first_feedback_us\":4,\"live_rpc_admission_us\":5,"
    "\"live_rpc_request_bytes\":6,\"live_rpc_response_bytes\":7}\n";
static const char k_ppr_nofg[] =
    "{\"durable_action_lookup_dedup_us\":2,\"local_submit_us\":3,"
    "\"local_first_feedback_us\":4,\"live_rpc_admission_us\":5,"
    "\"live_rpc_request_bytes\":6,\"live_rpc_response_bytes\":7}\n";
static const char k_ppr_empty[] = "{}\n";

static int ppr_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

static int ppr_status(pid_t pid)
{
    int status = 0;
    pid_t got;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got != pid)
        return 127;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 126;
}

static int ppr_write(const char *path, const char *text, const char *mode)
{
    FILE *fp;
    size_t n;
    size_t wrote;
    if (text == NULL || mode == NULL)
        return -1;
    fp = fopen(path, mode);
    if (fp == NULL)
        return -1;
    n = strlen(text);
    wrote = fwrite(text, 1, n, fp);
    if (fclose(fp) != 0 || wrote != n)
        return -1;
    return 0;
}

static int ppr_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return ppr_fit(n, cap) ? 0 : -1;
}

static int ppr_node(const char *scratch)
{
    char path[PATH_MAX];
    if (ppr_join(path, sizeof path, scratch, "node") != 0)
        return -1;
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int ppr_json(const char *scratch, int index, const char *body)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/async-submit-%d-result.json",
                     scratch, index);
    if (!ppr_fit(n, sizeof path))
        return -1;
    return ppr_write(path, body, "w");
}

/* kind 0 appends one lifecycle stage. kind 1 appends one worker sample.
 * field is the stage name or the worker's trailing total_us text. */
static int ppr_emit(const char *log, int kind, int action, const char *field)
{
    char line[768];
    int n;
    if (kind == 0)
        n = snprintf(line, sizeof line,
                     "[zcode.proof_perf] action=%064d stage=%s "
                     "at_unix_us=1000000 retry=0 context_prepare_us=1 "
                     "peer_selection_us=2 request_submit_us=3 context_bytes=4 "
                     "request_wire_bytes=5 context_cache_hit=0 admission_us=6 "
                     "transferred_bytes=7 claim_us=8 queue_us=9 "
                     "receipt_verification_us=10 projection_us=11 "
                     "result_wire_bytes=12 local_verification_us=13\n",
                     action, field);
    else
        n = snprintf(line, sizeof line,
                     "[zcode.proof_perf] action=%064d stage=worker_execute "
                     "at_unix_us=1000005 %s child_cpu_us=0 "
                     "sandbox_prepare_us=1 execution_us=2 output_cas_us=3 "
                     "receipt_sign_us=4 lookup_us=5 input_reconstruction_us=6 "
                     "output_verify_us=7 revalidation_us=8 projection_us=9 "
                     "input_bytes=10 output_bytes=11 processes=1 "
                     "compiler_processes=1 test_processes=0 cache_hit=0\n",
                     action, field);
    if (!ppr_fit(n, sizeof line))
        return -1;
    return ppr_write(log, line, "a");
}

static int ppr_seed(const char *scratch, char *log, size_t cap)
{
    static const char *const stages[] = {
        "foreground_return", "requester_dispatch", "remote_admission",
        "worker_lease", "worker_result_publish", "requester_result",
        "acceptance_ready",
    };
    int action;
    int stage;
    if (ppr_node(scratch) != 0)
        return -1;
    if (ppr_join(log, cap, scratch, "node/node.log") != 0)
        return -1;
    for (action = 1; action <= 3; action++) {
        if (ppr_json(scratch, action, k_ppr_full) != 0)
            return -1;
        for (stage = 0; stage < 7; stage++) {
            if (ppr_emit(log, 0, action, stages[stage]) != 0)
                return -1;
        }
    }
    if (ppr_emit(log, 1, 1, "total_us=9999999") != 0)
        return -1;
    if (ppr_emit(log, 1, 2, "total_us=10000000") != 0)
        return -1;
    if (ppr_emit(log, 1, 3, "total_us=10000001") != 0)
        return -1;
    return 0;
}

static int ppr_scratch(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    int n;
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    n = snprintf(out, cap, "%s/zcl-perf-report-test.XXXXXX", tmp);
    if (!ppr_fit(n, cap))
        return -1;
    return mkdtemp(out) == NULL ? -1 : 0;
}

static void ppr_rm(const char *path)
{
    pid_t pid = fork();
    if (pid < 0)
        return;
    if (pid == 0) {
        execl("/bin/rm", "rm", "-rf", "--", path, (char *)NULL);
        _exit(127);
    }
    (void)ppr_status(pid);
}

static int ppr_exec(const char *report, const char *scratch, const char *out,
                    int *status)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open(out, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0)
            _exit(127);
        if (fd != STDOUT_FILENO)
            close(fd);
        execlp("bash", "bash", report, scratch, (char *)NULL);
        _exit(127);
    }
    *status = ppr_status(pid);
    return 0;
}

static void ppr_cat(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buf[1024];
    if (fp == NULL)
        return;
    while (fgets(buf, (int)sizeof buf, fp) != NULL)
        fputs(buf, stderr);
    fclose(fp);
}

static int ppr_fixed(const char *line, const char *body, size_t n, int end)
{
    if (strncmp(line, body, n) != 0)
        return 0;
    if (end && line[n] != '\0')
        return 0;
    return 1;
}

static int ppr_gap(const char *line, const char *body, size_t n,
                   const char *star, int end)
{
    size_t pre = (size_t)(star - body);
    const char *suf = star + 2;
    size_t suflen;
    const char *at;
    if (n < pre + 2)
        return 0;
    suflen = n - pre - 2;
    if (strncmp(line, body, pre) != 0)
        return 0;
    at = strstr(line + pre, suf);
    if (at == NULL)
        return 0;
    if (end && at[suflen] != '\0')
        return 0;
    return 1;
}

/* Patterns are the shell's grep -E forms: a leading ^, an optional
 * trailing $, and at most one .* . Nothing else is special. */
static int ppr_line_hit(const char *line, const char *pat)
{
    char body[512];
    const char *star;
    size_t n;
    int end = 0;
    if (pat[0] != '^')
        return 0;
    n = strlen(pat + 1);
    if (n >= sizeof body)
        return 0;
    memcpy(body, pat + 1, n + 1);
    if (n > 0 && body[n - 1] == '$') {
        body[--n] = '\0';
        end = 1;
    }
    star = strstr(body, ".*");
    if (star == NULL)
        return ppr_fixed(line, body, n, end);
    return ppr_gap(line, body, n, star, end);
}

static int ppr_grep(const char *path, const char *pattern)
{
    FILE *fp = fopen(path, "r");
    char line[2048];
    int found = 0;
    if (fp == NULL)
        return -1;
    while (fgets(line, (int)sizeof line, fp) != NULL) {
        size_t n = strlen(line);
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (ppr_line_hit(line, pattern))
            found = 1;
    }
    fclose(fp);
    return found ? 0 : -1;
}

static int ppr_miss(const char *out, const char *const *pats, int npat)
{
    int i;
    for (i = 0; i < npat; i++) {
        if (ppr_grep(out, pats[i]) == 0)
            continue;
        fprintf(stderr, "proof-perf selftest: missing %s\n", pats[i]);
        ppr_cat(out);
        return -1;
    }
    return 0;
}

static int ppr_expect(const char *report, const char *scratch, int must_fail,
                      const char *const *pats, int npat, const char *why)
{
    char out[PATH_MAX];
    int status = 0;
    if (ppr_join(out, sizeof out, scratch, "report") != 0)
        return 1;
    if (ppr_exec(report, scratch, out, &status) != 0)
        return 1;
    if (must_fail && status == 0)
        return ppr_fail(why);
    if (!must_fail && status != 0) {
        ppr_cat(out);
        return ppr_fail("report exited");
    }
    return ppr_miss(out, pats, npat) == 0 ? 0 : 1;
}

static int ppr_case_ok(const char *report, const char *scratch)
{
    static const char *const pats[] = {
        "^remote_execution_us n=3 p50_us=10000000 p95_us=10000001 "
        "mean_us=10000000 max_us=10000001",
        "^remote_cpu_us n=3 p50_us=0 p95_us=0 mean_us=0 max_us=0 "
        "expected=3 missing=0 invalid=0 complete=true$",
        "^worker_cache_hits=0/3$",
    };
    return ppr_expect(report, scratch, 0, pats, 3, NULL);
}

static int ppr_case_missing(const char *report, const char *scratch)
{
    static const char *const pats[] = {
        "^foreground_request_creation_us n=2 .* expected=3 missing=1 "
        "invalid=0 complete=false$",
    };
    if (ppr_json(scratch, 3, k_ppr_nofg) != 0)
        return 1;
    return ppr_expect(report, scratch, 1, pats, 1,
                      "missing foreground metric did not refuse");
}

static int ppr_extra(const char *log)
{
    static const char *const extra[] = {
        "", "total_us=0", "total_us=4294967296", "total_us=-1",
        "total_us=bad", "total_us=9007199254740992",
    };
    int i;
    for (i = 0; i < 6; i++) {
        if (ppr_emit(log, 1, 1, extra[i]) != 0)
            return -1;
    }
    return 0;
}

static int ppr_case_invalid(const char *report, const char *scratch)
{
    static const char *const pats[] = {
        "^remote_execution_us n=5 p50_us=10000000 p95_us=4294967296 mean_us=864993459 max_us=4294967296 expected=9 missing=1 invalid=3 complete=false$",
        "^foreground_request_creation_us n=3 .* expected=4 missing=1 invalid=0 complete=false$",
        "^worker_cache_hits=0/9$",
    };
    char log[PATH_MAX];
    if (ppr_json(scratch, 3, k_ppr_full) != 0)
        return 1;
    if (ppr_join(log, sizeof log, scratch, "node/node.log") != 0)
        return 1;
    if (ppr_extra(log) != 0)
        return 1;
    if (ppr_json(scratch, 4, k_ppr_empty) != 0)
        return 1;
    return ppr_expect(report, scratch, 1, pats, 3,
                      "invalid samples did not refuse");
}

static int ppr_replace_log(const char *log)
{
    char line[256];
    int n = snprintf(line, sizeof line,
                     "[zcode.proof_perf] action=%064d stage=worker_execute "
                     "at_unix_us=1000001 total_us=10000000\n",
                     4);
    if (!ppr_fit(n, sizeof line))
        return -1;
    if (ppr_write(log, line, "w") != 0)
        return -1;
    return ppr_write(log,
                     "[zcode.proof_perf] action=invalid stage=worker_execute "
                     "at_unix_us=1 total_us=1\n",
                     "a");
}

static int ppr_case_absent(const char *report, const char *scratch)
{
    static const char *const pats[] = {
        "^remote_execution_us n=1 .* max_us=10000000 expected=1 missing=0 "
        "invalid=0 complete=true$",
        "^remote_cpu_us n=0 .* expected=1 missing=1 invalid=0 complete=false$",
        "^background_total_precise_us n=0 .* expected=1 missing=1 invalid=0 "
        "complete=false$",
        "^lifecycle_records=2 invalid_lifecycle_records=1$",
        "^context_cache_unmeasured=0 worker_cache_unmeasured=1$",
    };
    char log[PATH_MAX];
    if (ppr_join(log, sizeof log, scratch, "node/node.log") != 0)
        return 1;
    if (ppr_replace_log(log) != 0)
        return 1;
    return ppr_expect(report, scratch, 1, pats, 5,
                      "absent metrics did not refuse");
}

static int ppr_cases(const char *report, const char *scratch)
{
    char log[PATH_MAX];
    if (ppr_seed(scratch, log, sizeof log) != 0)
        return ppr_fail("fixture");
    if (ppr_case_ok(report, scratch) != 0)
        return 1;
    if (ppr_case_missing(report, scratch) != 0)
        return 1;
    if (ppr_case_invalid(report, scratch) != 0)
        return 1;
    if (ppr_case_absent(report, scratch) != 0)
        return 1;
    return 0;
}

static const char *ppr_script(const char *report_path)
{
    const char *env = getenv("ZCL_PERF_REPORT_UNDER_TEST");
    if (env != NULL && env[0] != '\0')
        return env;
    return report_path;
}

static int ppr_all(const char *report_path)
{
    char scratch[PATH_MAX];
    const char *report = ppr_script(report_path);
    int rc;
    if (report == NULL || report[0] == '\0')
        return ppr_fail("report path is unset");
    if (ppr_scratch(scratch, sizeof scratch) != 0)
        return ppr_fail("scratch");
    rc = ppr_cases(report, scratch);
    ppr_rm(scratch);
    if (rc != 0)
        return 1;
    printf("proof-perf-report-selftest: PASS (boundary, missing, zero, "
           "retries, invalid, wide values, complete accounting)\n");
    return 0;
}

#endif /* !_WIN32 */

int zcl_zcode_async_proof_perf_selftest(const char *report_path)
{
#if defined(_WIN32)
    (void)report_path;
    return ppr_fail("unavailable on Windows");
#else
    return ppr_all(report_path);
#endif
}
