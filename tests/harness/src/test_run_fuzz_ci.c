/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_run_fuzz_ci against stand-in harnesses. The stand-ins record
 * the slot, leak mode, and argv the runner actually passes. */

#include "test/test_core.h"

#include "run_fuzz_ci.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_timeout[] =
    "#!/bin/sh\n"
    "printf '%s\\n' \"$1\" >> wall.txt\n"
    "shift\n"
    "exec \"$@\"\n";

static const char k_harness[] =
    "#!/bin/sh\n"
    "prev=\n"
    "seed=\n"
    "art=\n"
    "for a in \"$@\"; do\n"
    "  prev=$seed\n"
    "  seed=$a\n"
    "  case $a in\n"
    "    -artifact_prefix=*) art=${a#-artifact_prefix=} ;;\n"
    "  esac\n"
    "done\n"
    "mkdir -p \"$seed\"\n"
    "{\n"
    "  printf 'asan=%s\\n' \"${ASAN_OPTIONS-unset}\"\n"
    "  printf 'art=%s\\n' \"$art\"\n"
    "  printf 'prev=%s\\n' \"$prev\"\n"
    "  printf 'seed=%s\\n' \"$seed\"\n"
    "  printf 'args'\n"
    "  for a in \"$@\"; do printf ' [%s]' \"$a\"; done\n"
    "  printf '\\n'\n"
    "} > \"$seed/seen\"\n"
    "name=$(basename \"$0\")\n"
    "if [ \"$name\" = fuzz_fast ]; then\n"
    "  parent=$(dirname \"$prev\")\n"
    "  tag=$(basename \"$prev\")\n"
    "  mkdir -p \"$parent/zcl_fuzz_http_home_${tag}_empty\"\n"
    "  mkdir -p \"$parent/zcl_fuzz_http_home_${tag}_full\"\n"
    "  printf 'keep\\n' > \"$parent/zcl_fuzz_http_home_${tag}_full/keep\"\n"
    "  printf '%s\\n' \"$parent/zcl_fuzz_http_home_${tag}_empty\" > \"$seed/empty_home\"\n"
    "  printf '%s\\n' \"$parent/zcl_fuzz_http_home_${tag}_full\" > \"$seed/full_home\"\n"
    "fi\n"
    "case \"$name\" in\n"
    "  fuzz_fast)\n"
    "    printf '%s\\n' 'stat::number_of_executed_units: 10'\n"
    "    printf '%s\\n' 'stat::number_of_executed_units: 2500'\n"
    "    printf '%s\\n' 'stat::average_exec_per_sec: 1'\n"
    "    printf '%s\\n' 'stat::average_exec_per_sec: 4000'\n"
    "    exit 0 ;;\n"
    "  fuzz_slow)\n"
    "    printf '%s\\n' 'stat::number_of_executed_units: 8'\n"
    "    printf '%s\\n' 'stat::average_exec_per_sec: 4'\n"
    "    exit 0 ;;\n"
    "  fuzz_edge)\n"
    "    printf '%s\\n' 'stat::number_of_executed_units: 10'\n"
    "    printf '%s\\n' 'stat::average_exec_per_sec: 10'\n"
    "    exit 0 ;;\n"
    "  fuzz_none)\n"
    "    printf '%s\\n' 'no stats here'\n"
    "    exit 0 ;;\n"
    "  fuzz_crash)\n"
    "    printf '%s\\n' crash-line\n"
    "    exit 9 ;;\n"
    "esac\n"
    "exit 0\n";

struct rfx_env {
    char path[8192];
    char asan[256];
    int have_path;
    int have_asan;
};

static void rfx_save(struct rfx_env *env)
{
    const char *path = getenv("PATH");
    const char *asan = getenv("ASAN_OPTIONS");
    env->have_path = 0;
    env->have_asan = 0;
    env->path[0] = '\0';
    env->asan[0] = '\0';
    if (path != NULL && strlen(path) < sizeof env->path) {
        memcpy(env->path, path, strlen(path) + 1);
        env->have_path = 1;
    }
    if (asan != NULL && strlen(asan) < sizeof env->asan) {
        memcpy(env->asan, asan, strlen(asan) + 1);
        env->have_asan = 1;
    }
}

static void rfx_restore(const struct rfx_env *env)
{
    if (env->have_path)
        setenv("PATH", env->path, 1);
    if (env->have_asan)
        setenv("ASAN_OPTIONS", env->asan, 1);
    else
        unsetenv("ASAN_OPTIONS");
}

static int rfx_write(const char *path, const char *body)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(body, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return chmod(path, 0755);
}

static int rfx_mkdir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int rfx_setup(const char *root)
{
    char path[PATH_MAX];
    char bin[PATH_MAX];
    if (rfx_mkdir("bin") != 0 || rfx_mkdir("tests") != 0)
        return -1;
    if (rfx_mkdir("tests/harness") != 0 || rfx_mkdir("tests/harness/fuzz_seeds") != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/bin/timeout", root) >= (int)sizeof path)
        return -1;
    if (rfx_write(path, k_timeout) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/harness.sh", root) >= (int)sizeof path)
        return -1;
    if (rfx_write(path, k_harness) != 0)
        return -1;
    if (snprintf(bin, sizeof bin, "%s/bin", root) >= (int)sizeof bin)
        return -1;
    if (snprintf(path, sizeof path, "%s:%s", bin, getenv("PATH")) >= (int)sizeof path)
        return -1;
    if (setenv("PATH", path, 1) != 0)
        return -1;
    return 0;
}

static int rfx_link(const char *root, const char *name)
{
    char src[PATH_MAX];
    char dst[PATH_MAX];
    if (snprintf(src, sizeof src, "%s/harness.sh", root) >= (int)sizeof src)
        return -1;
    if (snprintf(dst, sizeof dst, "%s/%s", root, name) >= (int)sizeof dst)
        return -1;
    unlink(dst);
    return symlink(src, dst);
}

static int rfx_capture(int argc, char **argv, const char *log, char *got,
                       size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved = dup(STDOUT_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved < 0)
        goto fail;
    fflush(stdout);
    if (dup2(fd, STDOUT_FILENO) < 0)
        goto fail;
    *rc = zcl_run_fuzz_ci(argc, argv);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
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
    if (saved >= 0) {
        dup2(saved, STDOUT_FILENO);
        close(saved);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int rfx_line(const char *path, char *out, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL || cap < 2)
        return -1;
    if (fgets(out, (int)cap, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    n = strlen(out);
    if (n > 0 && out[n - 1] == '\n')
        out[n - 1] = '\0';
    return 0;
}

static int rfx_seen(const char *kind, const char *key, char *out, size_t cap)
{
    char path[PATH_MAX];
    char body[4096];
    FILE *fp;
    const char *hit;
    size_t n = 0;
    size_t k;
    if (snprintf(path, sizeof path, "tests/harness/fuzz_seeds/%s/seen", kind) >=
        (int)sizeof path)
        return -1;
    fp = fopen(path, "r");
    if (fp == NULL)
        return -1;
    n = fread(body, 1, sizeof body - 1, fp);
    fclose(fp);
    body[n] = '\0';
    k = strlen(key);
    hit = strstr(body, key);
    if (hit == NULL)
        return -1;
    hit += k;
    n = 0;
    while (hit[n] != '\0' && hit[n] != '\n' && n + 1 < cap) {
        out[n] = hit[n];
        n++;
    }
    out[n] = '\0';
    return hit[n] == '\0' || hit[n] == '\n' ? 0 : -1;
}

static void rfx_rm(const char *path)
{
    char cmd[PATH_MAX + 32];
    if (path == NULL || path[0] == '\0')
        return;
    if (snprintf(cmd, sizeof cmd, "rm -rf '%s'", path) > 0 && system(cmd) != 0)
        return;
}

static void rfx_cleanup_kind(const char *kind)
{
    char prev[PATH_MAX];
    char log[PATH_MAX];
    char empty[PATH_MAX];
    char full[PATH_MAX];
    char rel[PATH_MAX];
    if (rfx_seen(kind, "prev=", prev, sizeof prev) == 0) {
        rfx_rm(prev);
        if (snprintf(log, sizeof log, "%s.log", prev) < (int)sizeof log)
            rfx_rm(log);
    }
    if (snprintf(rel, sizeof rel, "tests/harness/fuzz_seeds/%s/empty_home", kind) <
            (int)sizeof rel &&
        rfx_line(rel, empty, sizeof empty) == 0)
        rfx_rm(empty);
    if (snprintf(rel, sizeof rel, "tests/harness/fuzz_seeds/%s/full_home", kind) <
            (int)sizeof rel &&
        rfx_line(rel, full, sizeof full) == 0)
        rfx_rm(full);
}

static int test_rfx_refuse(void)
{
    int failures = 0;
    TEST("fuzz-ci: no harness is a refusal and a short argv is not a run") {
        char *args[] = {"1", "2", "1000", "0", "0", NULL};
        char err[256];
        int saved = dup(STDERR_FILENO);
        int fd = open("refuse.err", O_CREAT | O_TRUNC | O_RDWR, 0600);
        int rc;
        ASSERT(saved >= 0 && fd >= 0);
        fflush(stderr);
        ASSERT(dup2(fd, STDERR_FILENO) >= 0);
        rc = zcl_run_fuzz_ci(5, args);
        fflush(stderr);
        dup2(saved, STDERR_FILENO);
        close(saved);
        close(fd);
        ASSERT(rc == 2);
        ASSERT(rfx_line("refuse.err", err, sizeof err) == 0);
        ASSERT(strcmp(err, "fuzz-ci: FAIL: no targets supplied") == 0);
        ASSERT(zcl_run_fuzz_ci(4, args) == 1);
        {
            char *many[72];
            char over[128];
            int i;
            int fd2 = open("refuse-cap.err", O_CREAT | O_TRUNC | O_RDWR, 0600);
            int saved2 = dup(STDERR_FILENO);
            for (i = 0; i < 5; i++)
                many[i] = "1";
            for (i = 5; i < 70; i++)
                many[i] = "x";
            many[70] = NULL;
            ASSERT(saved2 >= 0 && fd2 >= 0);
            fflush(stderr);
            ASSERT(dup2(fd2, STDERR_FILENO) >= 0);
            rc = zcl_run_fuzz_ci(70, many);
            fflush(stderr);
            dup2(saved2, STDERR_FILENO);
            close(saved2);
            close(fd2);
            ASSERT(rc == 1);
            ASSERT(rfx_line("refuse-cap.err", over, sizeof over) == 0);
            ASSERT(strstr(over, "exceeds 64") != NULL);
        }
        PASS();
    } _test_next:;
    unlink("refuse.err");
    unlink("refuse-cap.err");
    return failures;
}

static int test_rfx_fast(const char *root)
{
    int failures = 0;
    char target[PATH_MAX];
    unlink("wall.txt");
    unsetenv("ASAN_OPTIONS");
    if (snprintf(target, sizeof target, "%s/fuzz_fast", root) >= (int)sizeof target)
        return 1;
    TEST("fuzz-ci: a fast harness passes, records the slot, and clears empty homes") {
        char *args[] = {"5", "auto", "1000", "0", "0", target, NULL};
        char got[8192];
        char seen[1024];
        char row[160];
        char banner[PATH_MAX];
        char empty[PATH_MAX];
        char full[PATH_MAX];
        char wall[64];
        struct stat st;
        int rc = 1;
        ASSERT(rfx_capture(6, args, "fast.log", got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(snprintf(banner, sizeof banner, "=== %s (5s) ===\n", target) > 0);
        ASSERT(strstr(got, banner) != NULL);
        ASSERT(strstr(got, ", leak detection ON") == NULL);
        ASSERT(strstr(got, "UNDER-COVERED") == NULL);
        ASSERT(strstr(got, "Do NOT lower this floor") == NULL);
        ASSERT(snprintf(row, sizeof row, "  %-22s %12s execs  %8s exec/s  %s\n",
                        "fuzz_fast", "2500", "4000", "ok") > 0);
        ASSERT(strstr(got, row) != NULL);
        ASSERT(strstr(got,
                      "\xe2\x94\x80\xe2\x94\x80 fuzz-ci throughput "
                      "(executions in a 5s slot; floor 1000/s) "
                      "\xe2\x94\x80\xe2\x94\x80\n") != NULL);
        ASSERT(rfx_line("wall.txt", wall, sizeof wall) == 0);
        ASSERT(strcmp(wall, "65s") == 0);
        ASSERT(rfx_seen("fast", "asan=", seen, sizeof seen) == 0);
        ASSERT(strcmp(seen, "detect_leaks=0") == 0);
        ASSERT(rfx_seen("fast", "args", seen, sizeof seen) == 0);
        ASSERT(strstr(seen, "[-max_total_time=5]") != NULL);
        ASSERT(strstr(seen, "[-timeout=1]") != NULL);
        ASSERT(strstr(seen, "[-print_final_stats=1]") != NULL);
        ASSERT(strstr(seen, "[-print_funcs=0]") != NULL);
        ASSERT(strstr(seen, "[tests/harness/fuzz_seeds/fast]") != NULL);
        ASSERT(rfx_seen("fast", "art=", seen, sizeof seen) == 0);
        ASSERT(strstr(seen, "zcl_fuzz_fast/") != NULL);
        ASSERT(strstr(seen, "_leaks") == NULL);
        ASSERT(rfx_line("tests/harness/fuzz_seeds/fast/empty_home", empty,
                        sizeof empty) == 0);
        ASSERT(rfx_line("tests/harness/fuzz_seeds/fast/full_home", full,
                        sizeof full) == 0);
        ASSERT(stat(empty, &st) != 0);
        ASSERT(stat(full, &st) == 0 && S_ISDIR(st.st_mode));
        PASS();
    } _test_next:;
    rfx_cleanup_kind("fast");
    return failures;
}

static int test_rfx_slow(const char *root)
{
    int failures = 0;
    char target[PATH_MAX];
    unlink("wall.txt");
    unsetenv("ASAN_OPTIONS");
    if (snprintf(target, sizeof target, "%s/fuzz_slow", root) >= (int)sizeof target)
        return 1;
    TEST("fuzz-ci: leak mode and an under-floor rate fail without lowering the floor") {
        char *args[] = {"5", "9", "10", "2", "1", target, NULL};
        char got[8192];
        char seen[1024];
        char row[160];
        char banner[PATH_MAX];
        char wall[64];
        int rc = 0;
        ASSERT(rfx_capture(6, args, "slow.log", got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(snprintf(banner, sizeof banner, "=== %s (5s, leak detection ON) ===\n",
                        target) > 0);
        ASSERT(strstr(got, banner) != NULL);
        ASSERT(snprintf(row, sizeof row, "  %-22s %12s execs  %8s exec/s  %s\n",
                        "fuzz_slow", "8", "4", "UNDER-COVERED") > 0);
        ASSERT(strstr(got, row) != NULL);
        ASSERT(strstr(got, "fuzz-ci: FAIL: a harness ran under 10 executions/second.\n") !=
               NULL);
        ASSERT(strstr(got, "Do NOT lower this floor.") != NULL);
        ASSERT(rfx_line("wall.txt", wall, sizeof wall) == 0);
        ASSERT(strcmp(wall, "9s") == 0);
        ASSERT(rfx_seen("slow", "asan=", seen, sizeof seen) == 0);
        ASSERT(strcmp(seen, "unset") == 0);
        ASSERT(rfx_seen("slow", "args", seen, sizeof seen) == 0);
        ASSERT(strstr(seen, "[-print_funcs=2]") != NULL);
        ASSERT(rfx_seen("slow", "art=", seen, sizeof seen) == 0);
        ASSERT(strstr(seen, "zcl_fuzz_slow_leaks/") != NULL);
        PASS();
    } _test_next:;
    rfx_cleanup_kind("slow");
    return failures;
}

static int test_rfx_edge(const char *root)
{
    int failures = 0;
    char edge[PATH_MAX];
    char none[PATH_MAX];
    unlink("wall.txt");
    if (snprintf(edge, sizeof edge, "%s/fuzz_edge", root) >= (int)sizeof edge)
        return 1;
    if (snprintf(none, sizeof none, "%s/fuzz_none", root) >= (int)sizeof none)
        return 1;
    TEST("fuzz-ci: the floor is strict less-than, and a missing rate counts as zero") {
        char *edge_args[] = {"3", "", "10", "0", "0", edge, NULL};
        char *none_args[] = {"3", "4", "1", "0", "0", none, NULL};
        char got[4096];
        char row[160];
        char wall[64];
        int rc = 1;
        ASSERT(rfx_capture(6, edge_args, "edge.log", got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(snprintf(row, sizeof row, "  %-22s %12s execs  %8s exec/s  %s\n",
                        "fuzz_edge", "10", "10", "ok") > 0);
        ASSERT(strstr(got, row) != NULL);
        ASSERT(rfx_line("wall.txt", wall, sizeof wall) == 0);
        ASSERT(strcmp(wall, "63s") == 0);
        unlink("wall.txt");
        ASSERT(rfx_capture(6, none_args, "none.log", got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(snprintf(row, sizeof row, "  %-22s %12s execs  %8s exec/s  %s\n",
                        "fuzz_none", "0", "0", "UNDER-COVERED") > 0);
        ASSERT(strstr(got, row) != NULL);
        ASSERT(rfx_line("wall.txt", wall, sizeof wall) == 0);
        ASSERT(strcmp(wall, "4s") == 0);
        PASS();
    } _test_next:;
    rfx_cleanup_kind("edge");
    rfx_cleanup_kind("none");
    return failures;
}

static int test_rfx_pair(const char *root)
{
    int failures = 0;
    char fast[PATH_MAX];
    char slow[PATH_MAX];
    if (snprintf(fast, sizeof fast, "%s/fuzz_fast", root) >= (int)sizeof fast)
        return 1;
    if (snprintf(slow, sizeof slow, "%s/fuzz_slow", root) >= (int)sizeof slow)
        return 1;
    TEST("fuzz-ci: every harness is listed, and one weak rate fails the run") {
        char *args[] = {"5", "8", "100", "0", "0", fast, slow, NULL};
        char got[8192];
        char fast_row[160];
        char slow_row[160];
        const char *fast_at;
        const char *slow_at;
        int rc = 0;
        ASSERT(rfx_capture(7, args, "pair.log", got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(snprintf(fast_row, sizeof fast_row,
                        "  %-22s %12s execs  %8s exec/s  %s\n", "fuzz_fast",
                        "2500", "4000", "ok") > 0);
        ASSERT(snprintf(slow_row, sizeof slow_row,
                        "  %-22s %12s execs  %8s exec/s  %s\n", "fuzz_slow", "8",
                        "4", "UNDER-COVERED") > 0);
        fast_at = strstr(got, fast_row);
        slow_at = strstr(got, slow_row);
        ASSERT(fast_at != NULL && slow_at != NULL && fast_at < slow_at);
        ASSERT(strstr(got, "under 100 executions/second.") != NULL);
        PASS();
    } _test_next:;
    rfx_cleanup_kind("fast");
    rfx_cleanup_kind("slow");
    return failures;
}

static int test_rfx_crash(const char *root)
{
    int failures = 0;
    char target[PATH_MAX];
    if (snprintf(target, sizeof target, "%s/fuzz_crash", root) >= (int)sizeof target)
        return 1;
    TEST("fuzz-ci: a harness failure keeps the log and skips the rate table") {
        char *args[] = {"5", "12", "1000", "0", "0", target, NULL};
        char got[4096];
        char prev[PATH_MAX];
        char log[PATH_MAX];
        char body[1024];
        struct stat st;
        int rc = 0;
        ASSERT(rfx_capture(6, args, "crash.log", got, sizeof got, &rc) == 0);
        ASSERT(rc == 9);
        ASSERT(strstr(got, "crash-line\n") != NULL);
        ASSERT(strstr(got, "fuzz-ci: FAIL: fuzz_crash exited 9 ") != NULL);
        ASSERT(strstr(got, "full output kept at ") != NULL);
        ASSERT(strstr(got, "fuzz-ci throughput") == NULL);
        ASSERT(rfx_seen("crash", "prev=", prev, sizeof prev) == 0);
        ASSERT(stat(prev, &st) == 0 && S_ISDIR(st.st_mode));
        ASSERT(snprintf(log, sizeof log, "%s.log", prev) > 0);
        ASSERT(rfx_line(log, body, sizeof body) == 0);
        ASSERT(strcmp(body, "crash-line") == 0);
        PASS();
    } _test_next:;
    rfx_cleanup_kind("crash");
    return failures;
}

int test_run_fuzz_ci(void);
int test_run_fuzz_ci(void)
{
    char root[PATH_MAX];
    char cwd[PATH_MAX];
    struct rfx_env saved;
    int failures;
    const char *names[] = {"fuzz_fast", "fuzz_slow", "fuzz_edge", "fuzz_none",
                           "fuzz_crash"};
    size_t i;
    if (getcwd(cwd, sizeof cwd) == NULL)
        return 1;
    rfx_save(&saved);
    test_make_tmpdir(root, sizeof root, "run_fuzz_ci", "root");
    if (chdir(root) != 0) {
        rfx_restore(&saved);
        return 1;
    }
    if (rfx_setup(root) != 0) {
        if (chdir(cwd) != 0)
            return 1;
        rfx_restore(&saved);
        (void)test_rm_rf_recursive(root);
        printf("test_run_fuzz_ci: setup failed\n");
        return 1;
    }
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (rfx_link(root, names[i]) != 0) {
            if (chdir(cwd) != 0)
                return 1;
            rfx_restore(&saved);
            (void)test_rm_rf_recursive(root);
            printf("test_run_fuzz_ci: setup failed\n");
            return 1;
        }
    }
    failures = test_rfx_refuse();
    failures += test_rfx_fast(root);
    failures += test_rfx_slow(root);
    failures += test_rfx_edge(root);
    failures += test_rfx_pair(root);
    failures += test_rfx_crash(root);
    if (chdir(cwd) != 0)
        failures += 1;
    rfx_restore(&saved);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_run_fuzz_ci: all passed\n");
    else
        printf("test_run_fuzz_ci: %d FAILED\n", failures);
    return failures;
}
