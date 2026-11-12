/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run each libFuzzer harness for a fixed slot, print the
 *          executions it actually achieved, and fail a rate under the floor.
 *          Writes the per-harness work directory only for the duration of
 *          a passing run; a failing harness keeps that directory and its log. */

#include "run_fuzz_ci.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define RFC_MAX 64

struct rfc_row {
    char name[256];
    char execs[32];
    char rate[32];
};

static int rfc_reap(pid_t child)
{
    int code = 125;
    for (;;) {
        int status = 0;
        pid_t got = waitpid(child, &status, 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got == child && WIFEXITED(status))
            code = WEXITSTATUS(status);
        break;
    }
    return code;
}

static int rfc_quiet(char *const argv[])
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        int sink = open("/dev/null", O_WRONLY);
        if (sink >= 0) {
            if (dup2(sink, STDOUT_FILENO) < 0 || dup2(sink, STDERR_FILENO) < 0)
                _exit(127);
            if (sink > STDERR_FILENO)
                close(sink);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    return rfc_reap(child);
}

static int rfc_pump(int rd, FILE *log)
{
    char buf[4096];
    for (;;) {
        ssize_t n = read(rd, buf, sizeof buf);
        if (n == 0)
            return 0;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n)
            return -1;
        if (log != NULL && fwrite(buf, 1, (size_t)n, log) != (size_t)n)
            return -1;
        fflush(stdout);
        if (log != NULL)
            fflush(log);
    }
}

static int rfc_capture(char *const argv[], const char *log_path)
{
    int fds[2];
    pid_t child;
    FILE *log;
    int pumped;
    if (pipe(fds) != 0)
        return 127;
    log = fopen(log_path, "w");
    if (log == NULL) {
        close(fds[0]);
        close(fds[1]);
        return 127;
    }
    child = fork();
    if (child < 0) {
        fclose(log);
        close(fds[0]);
        close(fds[1]);
        return 127;
    }
    if (child == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0)
            _exit(127);
        if (fds[1] > STDERR_FILENO)
            close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    pumped = rfc_pump(fds[0], log);
    close(fds[0]);
    fclose(log);
    if (pumped != 0) {
        (void)rfc_reap(child);
        return 127;
    }
    return rfc_reap(child);
}

static int rfc_base(const char *target, char *out, size_t cap)
{
    const char *slash = strrchr(target, '/');
    const char *base = target;
    size_t n;
    if (slash != NULL && slash[1] != '\0')
        base = slash + 1;
    n = strlen(base);
    if (n + 1 > cap)
        return -1;
    memcpy(out, base, n + 1);
    return 0;
}

static int rfc_kind(const char *base, char *out, size_t cap)
{
    const char *kind = base;
    size_t n;
    if (strncmp(base, "fuzz_", 5) == 0)
        kind = base + 5;
    n = strlen(kind);
    if (n + 1 > cap)
        return -1;
    memcpy(out, kind, n + 1);
    return 0;
}

static int rfc_wall(const char *slot, const char *wall, char *out, size_t cap)
{
    const char *use = wall;
    char computed[32];
    if (wall == NULL || wall[0] == '\0' || strcmp(wall, "auto") == 0) {
        char *end = NULL;
        long seconds = strtol(slot, &end, 10);
        if (end == slot || *end != '\0' || seconds < 0)
            return -1;
        if (snprintf(computed, sizeof computed, "%ld", seconds + 60) >=
            (int)sizeof computed)
            return -1;
        use = computed;
    }
    if (snprintf(out, cap, "%ss", use) >= (int)cap)
        return -1;
    return 0;
}

static void rfc_last_stat(const char *log_path, const char *key, char *out,
                          size_t cap)
{
    FILE *fp = fopen(log_path, "r");
    char line[1024];
    size_t key_n = strlen(key);
    if (cap == 0)
        return;
    memcpy(out, "0", 2);
    if (fp == NULL)
        return;
    while (fgets(line, sizeof line, fp) != NULL) {
        const char *p;
        size_t n = 0;
        if (strncmp(line, key, key_n) != 0)
            continue;
        p = line + key_n;
        while (*p == ' ')
            p++;
        if (*p < '0' || *p > '9')
            continue;
        while (p[n] >= '0' && p[n] <= '9' && n + 1 < cap)
            n++;
        memcpy(out, p, n);
        out[n] = '\0';
    }
    fclose(fp);
}

static int rfc_less(const char *rate, const char *floor)
{
    char *rate_end = NULL;
    char *floor_end = NULL;
    long left = strtol(rate, &rate_end, 10);
    long right = strtol(floor, &floor_end, 10);
    if (rate_end == rate || *rate_end != '\0')
        return 0;
    if (floor_end == floor || *floor_end != '\0')
        return 0;
    return left < right;
}

static void rfc_clear_work(const char *work)
{
    char *argv[4];
    argv[0] = "rm";
    argv[1] = "-rf";
    argv[2] = (char *)work;
    argv[3] = NULL;
    (void)rfc_quiet(argv);
    if (mkdir(work, 0755) != 0 && errno != EEXIST)
        return;
}

static void rfc_drop(const char *work, const char *log_path)
{
    char *argv[5];
    argv[0] = "rm";
    argv[1] = "-rf";
    argv[2] = (char *)work;
    argv[3] = (char *)log_path;
    argv[4] = NULL;
    (void)rfc_quiet(argv);
}

static void rfc_homes(void)
{
    char *argv[] = {"find", "/tmp", "-maxdepth", "1", "-type", "d",
                    "-name", "zcl_fuzz_http_home_*", "-empty", "-delete",
                    NULL};
    (void)rfc_quiet(argv);
}

static int rfc_launch(const char *wall_s, int leaks, const char *target,
                      const char *slot, const char *print_funcs,
                      const char *art, const char *work, const char *seed,
                      const char *log_path)
{
    char max_time[64];
    char funcs[64];
    char prefix[640];
    char *av[14];
    int n = 0;
    if (snprintf(max_time, sizeof max_time, "-max_total_time=%s", slot) >=
        (int)sizeof max_time)
        return 127;
    if (snprintf(funcs, sizeof funcs, "-print_funcs=%s", print_funcs) >=
        (int)sizeof funcs)
        return 127;
    if (snprintf(prefix, sizeof prefix, "-artifact_prefix=%s", art) >=
        (int)sizeof prefix)
        return 127;
    av[n++] = "timeout";
    av[n++] = (char *)wall_s;
    if (!leaks) {
        av[n++] = "env";
        av[n++] = "ASAN_OPTIONS=detect_leaks=0";
    }
    av[n++] = (char *)target;
    av[n++] = max_time;
    av[n++] = "-timeout=1";
    av[n++] = "-print_final_stats=1";
    av[n++] = funcs;
    av[n++] = prefix;
    av[n++] = (char *)work;
    av[n++] = (char *)seed;
    av[n] = NULL;
    return rfc_capture(av, log_path);
}

static int rfc_one(const char *slot, const char *wall_s, const char *print_funcs,
                   int leaks, const char *target, struct rfc_row *row)
{
    char base[256];
    char kind[256];
    char work[512];
    char log_path[520];
    char seed[512];
    char art[520];
    const char *suffix = leaks ? "_leaks" : "";
    const char *label = leaks ? ", leak detection ON" : "";
    int rc;
    if (rfc_base(target, base, sizeof base) != 0)
        return 1;
    if (rfc_kind(base, kind, sizeof kind) != 0)
        return 1;
    if (snprintf(work, sizeof work, "/tmp/zcl_fuzz_%s%s", kind, suffix) >=
        (int)sizeof work)
        return 1;
    if (snprintf(log_path, sizeof log_path, "%s.log", work) >= (int)sizeof log_path)
        return 1;
    if (snprintf(seed, sizeof seed, "tests/harness/fuzz_seeds/%s", kind) >=
        (int)sizeof seed)
        return 1;
    if (snprintf(art, sizeof art, "%s/", work) >= (int)sizeof art)
        return 1;
    printf("=== %s (%ss%s) ===\n", target, slot, label);
    rfc_clear_work(work);
    rc = rfc_launch(wall_s, leaks, target, slot, print_funcs, art, work, seed,
                    log_path);
    if (rc != 0) {
        printf("fuzz-ci: FAIL: %s exited %d \xe2\x80\x94 full output kept at %s,\n",
               base, rc, log_path);
        printf("fuzz-ci:       any artifact written under %s/\n", work);
        return rc;
    }
    if (snprintf(row->name, sizeof row->name, "%s", base) >= (int)sizeof row->name)
        return 1;
    rfc_last_stat(log_path, "stat::number_of_executed_units:", row->execs,
                  sizeof row->execs);
    rfc_last_stat(log_path, "stat::average_exec_per_sec:", row->rate,
                  sizeof row->rate);
    rfc_drop(work, log_path);
    rfc_homes();
    return 0;
}

static void rfc_sermon(const char *floor)
{
    printf("\n");
    printf("fuzz-ci: FAIL: a harness ran under %s executions/second.\n", floor);
    printf("fuzz-ci:       It did not crash \xe2\x80\x94 it barely ran, which is worse,\n");
    printf("fuzz-ci:       because it reports green while testing almost nothing.\n");
    printf("fuzz-ci:       Profile the harness (strace -c -w is usually enough)\n");
    printf("fuzz-ci:       and hoist whatever it repeats per iteration into\n");
    printf("fuzz-ci:       LLVMFuzzerInitialize. Do NOT lower this floor.\n");
}

static int rfc_summary(const char *slot, const char *floor, struct rfc_row *rows,
                       int n)
{
    int i;
    int status = 0;
    printf("\n");
    printf("\xe2\x94\x80\xe2\x94\x80 fuzz-ci throughput (executions in a %ss slot; floor %s/s) \xe2\x94\x80\xe2\x94\x80\n",
           slot, floor);
    for (i = 0; i < n; i++) {
        const char *verdict = "ok";
        if (rfc_less(rows[i].rate, floor)) {
            verdict = "UNDER-COVERED";
            status = 1;
        }
        printf("  %-22s %12s execs  %8s exec/s  %s\n", rows[i].name,
               rows[i].execs, rows[i].rate, verdict);
    }
    if (status != 0)
        rfc_sermon(floor);
    return status;
}
#endif

int zcl_run_fuzz_ci(int argc, char **argv)
{
#if defined(_WIN32)
    (void)argc;
    (void)argv;
    fputs("fuzz-ci: unavailable on Windows\n", stdout);
    return 1;
#else
    char wall_s[64];
    struct rfc_row rows[RFC_MAX];
    int leaks;
    int i;
    int n;
    if (argc < 5 || argv == NULL)
        return 1;
    n = argc - 5;
    if (n <= 0) {
        fprintf(stderr, "fuzz-ci: FAIL: no targets supplied\n");
        return 2;
    }
    if (n > RFC_MAX) {
        fprintf(stderr, "fuzz-ci: FAIL: %d harnesses exceeds %d\n", n, RFC_MAX);
        return 1;
    }
    if (rfc_wall(argv[0], argv[1], wall_s, sizeof wall_s) != 0)
        return 1;
    leaks = strcmp(argv[4], "1") == 0;
    for (i = 0; i < n; i++) {
        int rc = rfc_one(argv[0], wall_s, argv[3], leaks, argv[5 + i], &rows[i]);
        if (rc != 0)
            return rc;
    }
    return rfc_summary(argv[0], argv[2], rows, n);
#endif
}
