/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_retrieval_profile_sweep. The live case replays the frozen
 * BM25 cohort through the shipped checker and retrieval-eval. */

#include "test/test_core.h"

#include "retrieval_profile_sweep.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int rps_capture(const char *mode, const struct zcl_rps_tools *tools,
                       const char *log, char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    char *argv[3];
    argv[0] = "retrieval-profile-sweep";
    argv[1] = (char *)mode;
    argv[2] = NULL;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_retrieval_profile_sweep("retrieval-profile-sweep",
                                      mode != NULL ? 2 : 1, argv, tools);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd);
    file = fopen(log, "r");
    if (file == NULL)
        return -1;
    used = fread(got, 1, cap - 1, file);
    fclose(file);
    if (used == cap - 1)
        return -1;
    got[used] = '\0';
    return 0;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int rps_stdout(const struct zcl_rps_tools *tools, const char *log, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved = dup(STDOUT_FILENO);
    char *argv[3];
    argv[0] = "retrieval-profile-sweep";
    argv[1] = "--check";
    argv[2] = NULL;
    if (fd < 0 || saved < 0)
        goto fail;
    fflush(stdout);
    if (dup2(fd, STDOUT_FILENO) < 0)
        goto fail;
    *rc = zcl_retrieval_profile_sweep("retrieval-profile-sweep", 2, argv, tools);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    close(fd);
    return 0;
fail:
    if (saved >= 0) {
        dup2(saved, STDOUT_FILENO);
        close(saved);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int rps_summary(const char *path, char *first, size_t first_cap, char *last,
                       size_t last_cap, int *lines)
{
    FILE *file = fopen(path, "r");
    char buf[8192];
    int n = 0;
    if (file == NULL)
        return -1;
    first[0] = '\0';
    last[0] = '\0';
    while (fgets(buf, sizeof buf, file) != NULL) {
        n++;
        if (n == 1 && strlen(buf) < first_cap)
            memcpy(first, buf, strlen(buf) + 1);
        if (strlen(buf) < last_cap)
            memcpy(last, buf, strlen(buf) + 1);
    }
    fclose(file);
    *lines = n;
    return 0;
}

static int test_rps_refuse(const char *dir)
{
    int failures = 0;
    struct zcl_rps_tools missing;
    missing.checker = "build/bin/missing-checker";
    missing.evaluator = "build/bin/missing-evaluator";
    missing.jsonq = "build/bin/missing-jsonq";
    missing.sha3 = "build/bin/missing-sha3";
    missing.receipt = "build/bin/missing-receipt";
    missing.sweep_source = "build/bin/missing-source";
    TEST("retrieval profile sweep: usage and a missing tool are refused") {
        char log[1024];
        char got[1024];
        int rc = 0;
        ASSERT(snprintf(log, sizeof log, "%s/refuse.log", dir) > 0);
        ASSERT(rps_capture(NULL, &missing, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "usage: retrieval-profile-sweep --check") != NULL);
        ASSERT(rps_capture("status", &missing, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "usage: retrieval-profile-sweep --check") != NULL);
        ASSERT(rps_capture("--check", &missing, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "build jsonq, agent-sha3, and retrieval-eval first") !=
               NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_rps_live(const char *dir)
{
    int failures = 0;
    struct zcl_rps_tools live;
    live.checker = "tools/dev/retrieval-gold-identifier-graph-receipt-check.sh";
    live.evaluator = "build/bin/retrieval-eval";
    live.jsonq = "build/bin/jsonq";
    live.sha3 = "build/bin/agent_sha3";
    live.receipt =
        "docs/work/retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl";
    live.sweep_source = "tools/dev/retrieval_profile_sweep.c";
    TEST("retrieval profile sweep: frozen windows keep the reviewed receipt") {
        char log[1024];
        char first[8192];
        char last[2048];
        int rc = 1;
        int lines = 0;
        ASSERT(access(live.checker, X_OK) == 0);
        ASSERT(access(live.evaluator, X_OK) == 0);
        ASSERT(access(live.jsonq, X_OK) == 0);
        ASSERT(access(live.sha3, X_OK) == 0);
        ASSERT(snprintf(log, sizeof log, "%s/live.log", dir) > 0);
        ASSERT(rps_stdout(&live, log, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(rps_summary(log, first, sizeof first, last, sizeof last, &lines) == 0);
        ASSERT(lines == 17);
        ASSERT(strstr(first, "zcl.retrieval_context_profile_replay.v1") != NULL);
        ASSERT(strstr(last, "\"schema\":\"zcl.retrieval_context_profile_sweep.v1\"") !=
               NULL);
        ASSERT(strstr(last, "\"windows_evaluated\":16") != NULL);
        ASSERT(strstr(last, "\"baseline_recall_at_5_bp\":936") != NULL);
        ASSERT(strstr(last, "\"baseline_projected_context_bytes_at_5\":853082") != NULL);
        ASSERT(strstr(last, "\"exploratory_recall_at_5_bp\":962") != NULL);
        ASSERT(strstr(last, "\"exploratory_projected_context_bytes_at_5\":567606") != NULL);
        ASSERT(strstr(last, "\"pareto_windows\":[7,8,9,12,20]") != NULL);
        ASSERT(strstr(last, "\"promotion_authorized\":false") != NULL);
        ASSERT(strstr(last,
                      "\"input_receipt_sha3\":\"5f1f8ff22867f2937cbffc61200affe30f8aed49c2456e79923f83a212adf455\"") !=
               NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_retrieval_profile_sweep(void);
int test_retrieval_profile_sweep(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "retrieval_profile_sweep", "root");
    failures = test_rps_refuse(dir);
    failures += test_rps_live(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_retrieval_profile_sweep: all passed\n");
    else
        printf("test_retrieval_profile_sweep: %d FAILED\n", failures);
    return failures;
}
