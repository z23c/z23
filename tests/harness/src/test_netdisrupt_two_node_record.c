/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_netdisrupt_two_node_record against a stand-in drill. */

#include "test/test_core.h"

#include "netdisrupt_two_node_record.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int ndt_capture(const char *repo, const char *drill, const char *hist,
                       const char *log, char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_netdisrupt_two_node_record(repo, drill, hist);
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

static int ndt_drill(const char *path, const char *body)
{
    FILE *file = fopen(path, "w");
    if (file == NULL)
        return -1;
    if (fputs(body, file) < 0) {
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0)
        return -1;
    return chmod(path, 0700);
}

static int ndt_ledger(const char *hist, char *out, size_t cap)
{
    char path[1200];
    FILE *file;
    if (snprintf(path, sizeof path, "%s/history.jsonl", hist) >= (int)sizeof path)
        return -1;
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    if (fgets(out, (int)cap, file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

static int test_ndr_pass(const char *dir)
{
    int failures = 0;
    TEST("netdisrupt record: a passing drill appends the last measurements") {
        char drill[1024];
        char hist[1024];
        char log[1024];
        char got[8192];
        char line[2048];
        int rc = 1;
        ASSERT(snprintf(drill, sizeof drill, "%s/pass-drill.sh", dir) > 0);
        ASSERT(snprintf(hist, sizeof hist, "%s/pass-hist", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/pass.log", dir) > 0);
        ASSERT(ndt_drill(drill,
                         "#!/bin/sh\n"
                         "echo WALL_CLOCK_SECONDS=4\n"
                         "echo WALL_CLOCK_SECONDS=15\n"
                         "echo 'netdisrupt-two-node: artifact=run/a\"b'\n"
                         "echo 'early B{dd=old p2p=1 rpc=9} x'\n"
                         "echo 'ready B{dd=abc p2p=39041 rpc=39042} ok'\n"
                         "exit 0\n") == 0);
        ASSERT(ndt_capture(dir, drill, hist, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "bin=build/bin/fixture-node cut=7s budget=11s") != NULL);
        ASSERT(strstr(got, "build_commit=unknown") != NULL);
        ASSERT(strstr(got, "WALL_CLOCK_SECONDS=15") != NULL);
        ASSERT(strstr(got, "verdict=pass rc=0") != NULL);
        ASSERT(ndt_ledger(hist, line, sizeof line) == 0);
        ASSERT(strstr(line, "\"verdict\":\"pass\"") != NULL);
        ASSERT(strstr(line, "\"exit_code\":0") != NULL);
        ASSERT(strstr(line, "\"wall_clock_seconds\":15") != NULL);
        ASSERT(strstr(line, "\"budget_seconds\":11") != NULL);
        ASSERT(strstr(line, "\"cut_seconds\":7") != NULL);
        ASSERT(strstr(line, "\"peer\":\"127.0.0.1:39042\"") != NULL);
        ASSERT(strstr(line, "\"node_bin\":\"build/bin/fixture-node\"") != NULL);
        ASSERT(strstr(line, "\"build_commit\":\"unknown\"") != NULL);
        ASSERT(strstr(line, "\"artifact_dir\":\"run/a\\\"b\"") != NULL);
        ASSERT(strstr(got, line) != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ndr_skip(const char *dir)
{
    int failures = 0;
    TEST("netdisrupt record: a skip is stored and then exits clean") {
        char drill[1024];
        char hist[1024];
        char log[1024];
        char got[4096];
        char line[2048];
        int rc = 1;
        ASSERT(snprintf(drill, sizeof drill, "%s/skip-drill.sh", dir) > 0);
        ASSERT(snprintf(hist, sizeof hist, "%s/skip-hist", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/skip.log", dir) > 0);
        ASSERT(ndt_drill(drill,
                         "#!/bin/sh\n"
                         "echo 'netdisrupt-two-node: artifact='\n"
                         "exit 2\n") == 0);
        ASSERT(ndt_capture(dir, drill, hist, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "verdict=skip rc=2") != NULL);
        ASSERT(strstr(got, "SKIP mapped to clean exit 0") != NULL);
        ASSERT(ndt_ledger(hist, line, sizeof line) == 0);
        ASSERT(strstr(line, "\"verdict\":\"skip\"") != NULL);
        ASSERT(strstr(line, "\"exit_code\":2") != NULL);
        ASSERT(strstr(line, "\"wall_clock_seconds\":null") != NULL);
        ASSERT(strstr(line, "\"peer\":\"127.0.0.1:0\"") != NULL);
        ASSERT(strstr(line, "\"artifact_dir\":\"\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ndr_fail(const char *dir)
{
    int failures = 0;
    TEST("netdisrupt record: fail and seam stay on the ledger and propagate") {
        char drill[1024];
        char hist[1024];
        char log[1024];
        char got[4096];
        char line[2048];
        int rc = 0;
        ASSERT(snprintf(drill, sizeof drill, "%s/fail-drill.sh", dir) > 0);
        ASSERT(snprintf(hist, sizeof hist, "%s/fail-hist", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/fail.log", dir) > 0);
        ASSERT(ndt_drill(drill, "#!/bin/sh\nexit 1\n") == 0);
        ASSERT(ndt_capture(dir, drill, hist, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "verdict=fail rc=1") != NULL);
        ASSERT(ndt_ledger(hist, line, sizeof line) == 0);
        ASSERT(strstr(line, "\"verdict\":\"fail\"") != NULL);
        ASSERT(snprintf(drill, sizeof drill, "%s/seam-drill.sh", dir) > 0);
        ASSERT(snprintf(hist, sizeof hist, "%s/seam-hist", dir) > 0);
        ASSERT(ndt_drill(drill, "#!/bin/sh\nexit 3\n") == 0);
        ASSERT(ndt_capture(dir, drill, hist, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 3);
        ASSERT(strstr(got, "verdict=seam rc=3") != NULL);
        ASSERT(ndt_ledger(hist, line, sizeof line) == 0);
        ASSERT(strstr(line, "\"verdict\":\"seam\"") != NULL);
        ASSERT(snprintf(drill, sizeof drill, "%s/stall-drill.sh", dir) > 0);
        ASSERT(snprintf(hist, sizeof hist, "%s/stall-hist", dir) > 0);
        ASSERT(ndt_drill(drill, "#!/bin/sh\nexit 4\n") == 0);
        ASSERT(ndt_capture(dir, drill, hist, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 4);
        ASSERT(strstr(got, "verdict=stalled-named rc=4") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static void ndt_restore(const char *node, const char *cut, const char *budget)
{
    if (node != NULL && node[0] != '\0')
        setenv("ZCL_ND2_NODE_BIN", node, 1);
    else
        unsetenv("ZCL_ND2_NODE_BIN");
    if (cut != NULL && cut[0] != '\0')
        setenv("ZCL_ND2_CUT_SECS", cut, 1);
    else
        unsetenv("ZCL_ND2_CUT_SECS");
    if (budget != NULL && budget[0] != '\0')
        setenv("ZCL_ND2_BUDGET_SECS", budget, 1);
    else
        unsetenv("ZCL_ND2_BUDGET_SECS");
}

int test_netdisrupt_two_node_record(void);
int test_netdisrupt_two_node_record(void)
{
    char dir[1024];
    char saved_node[512];
    char saved_cut[64];
    char saved_budget[64];
    const char *node = getenv("ZCL_ND2_NODE_BIN");
    const char *cut = getenv("ZCL_ND2_CUT_SECS");
    const char *budget = getenv("ZCL_ND2_BUDGET_SECS");
    int failures;
    int init_rc;
    saved_node[0] = '\0';
    saved_cut[0] = '\0';
    saved_budget[0] = '\0';
    if (node != NULL && strlen(node) < sizeof saved_node)
        memcpy(saved_node, node, strlen(node) + 1);
    if (cut != NULL && strlen(cut) < sizeof saved_cut)
        memcpy(saved_cut, cut, strlen(cut) + 1);
    if (budget != NULL && strlen(budget) < sizeof saved_budget)
        memcpy(saved_budget, budget, strlen(budget) + 1);
    setenv("ZCL_ND2_NODE_BIN", "build/bin/fixture-node", 1);
    setenv("ZCL_ND2_CUT_SECS", "7", 1);
    setenv("ZCL_ND2_BUDGET_SECS", "11", 1);
    test_make_tmpdir(dir, sizeof dir, "netdisrupt_record", "root");
    {
        char cmd[1200];
        init_rc = snprintf(cmd, sizeof cmd, "git init -q '%s'", dir) > 0 ?
            system(cmd) : -1;
    }
    failures = test_ndr_pass(dir);
    failures += test_ndr_skip(dir);
    failures += test_ndr_fail(dir);
    if (init_rc != 0)
        failures++;
    (void)test_rm_rf_recursive(dir);
    ndt_restore(saved_node, saved_cut, saved_budget);
    if (failures == 0)
        printf("test_netdisrupt_two_node_record: all passed\n");
    else
        printf("test_netdisrupt_two_node_record: %d FAILED\n", failures);
    return failures;
}
