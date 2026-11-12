/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the checkout lock defers a watcher, blocks a second
 *          foreground caller, nests without deadlock, and that the public
 *          test recipes take that lock before they build. */

#include "checkout_lock_selftest.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CLS_OUT 4096

static const char k_lock_phrase[] =
    "$(CHECKOUT_LOCK_TOOL) foreground \"$(CHECKOUT_LOCK)\"";

static const char k_fast_phrase[] =
    "$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) \"$(CHECKOUT_LOCK)\"";

static const char k_exact_build[] =
    "$(call ZCL_TEST_BUILD_NEEDS,$(TEST_PARALLEL_FAST_ACTIVE),--exact=$(EXACT_ONLY_MATCHED) $(T_FAST_EXACT_ARGS))";

static const char k_exact_run[] =
    "$(LINKED_TEST_ENV) $(TEST_PARALLEL_FAST_ACTIVE) --exact=$(EXACT_ONLY_MATCHED) $(T_FAST_EXACT_ARGS)";

static const char k_inner_phrase[] =
    "internal locked test goal requires the checkout lock";

struct cls_pair {
    const char *pub;
    const char *inner;
    const char *need;
};

static const struct cls_pair k_pairs[] = {
    {"test-parallel", "test-parallel-locked", "dev-package-verifier-ensure"},
    {"test-parallel-active", "test-parallel-active-locked", "dev-package-verifier-ensure"},
    {"test-parallel-fast-active", "test-parallel-fast-active-locked",
     "dev-package-verifier-ensure"},
    {"t", "t-locked", "dev-package-verifier-ensure"},
    {"t-fast", "t-fast-locked", "dev-package-verifier-ensure"},
    {"t-fast-exact", "t-fast-exact-locked", "$(TEST_PARALLEL_FAST_CANDIDATE)"},
    {"test", "test-locked", "dev-package-verifier-ensure"},
    {"test-full", "test-full-locked", "test_zcl"},
    {"secure-release-regressions", "secure-release-regressions-locked",
     "dev-package-verifier-ensure"},
};

struct cls_job {
    char root[PATH_MAX];
    char tool[PATH_MAX];
    char work[PATH_MAX];
    char lock[PATH_MAX];
    char make_path[PATH_MAX];
    pid_t kids[4];
    int nkids;
};

static int cls_fail(const char *msg)
{
    fprintf(stderr, "checkout-lock-selftest: FAIL: %s\n", msg);
    return 1;
}

static int cls_fail2(const char *prefix, const char *detail)
{
    fprintf(stderr, "checkout-lock-selftest: FAIL: %s%s\n", prefix, detail);
    return 1;
}

static int cls_path(char *out, size_t cap, const char *root, const char *rel)
{
    size_t nr = strlen(root);
    size_t nl = strlen(rel);
    if (nr + nl + 2 > cap)
        return -1;
    memcpy(out, root, nr);
    out[nr] = '/';
    memcpy(out + nr + 1, rel, nl + 1);
    return 0;
}

static void cls_chomp(char *s)
{
    size_t n;
    if (s == NULL)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static int cls_pause(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

static int cls_reap(pid_t pid)
{
    int code = 0;
    pid_t saw = -1;
    while (saw != pid) {
        saw = waitpid(pid, &code, 0);
        if (saw < 0 && errno == EINTR) {
            saw = -1;
            continue;
        }
        if (saw != pid)
            return 125;
    }
    if (WIFEXITED(code))
        return WEXITSTATUS(code);
    return WIFSIGNALED(code) ? 128 + WTERMSIG(code) : 125;
}

static void cls_load(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    size_t n = 0;
    buf[0] = '\0';
    if (fd < 0)
        return;
    while (n + 1 < cap) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r == 0)
            break;
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            break;
        n += (size_t)r;
    }
    buf[n] = '\0';
    close(fd);
}

static int cls_exec(struct cls_job *job, char *const argv[], char *out, size_t oc,
                    char *err, size_t ec, const char *held)
{
    char outp[PATH_MAX];
    char errp[PATH_MAX];
    pid_t child;
    int rc;
    if (cls_path(outp, sizeof outp, job->work, "child.out") != 0)
        return 127;
    if (cls_path(errp, sizeof errp, job->work, "child.err") != 0)
        return 127;
    unlink(outp);
    unlink(errp);
    child = fork();
    if (child < 0)
        return 127;
    if (child == 0) {
        int fo = open(outp, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        int fe = open(errp, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (fo < 0 || fe < 0)
            _exit(127);
        if (dup2(fo, STDOUT_FILENO) < 0 || dup2(fe, STDERR_FILENO) < 0)
            _exit(127);
        close(fo);
        close(fe);
        if (held != NULL)
            setenv("ZCL_CHECKOUT_LOCK_HELD", held, 1);
        execvp(argv[0], argv);
        _exit(127);
    }
    rc = cls_reap(child);
    cls_load(outp, out, oc);
    cls_load(errp, err, ec);
    cls_chomp(out);
    return rc;
}

static int cls_tool(struct cls_job *job, const char *mode, char *const cmd[],
                    char *out, size_t oc, char *err, size_t ec)
{
    char *argv[12];
    int i = 0;
    int c = 0;
    argv[i++] = job->tool;
    argv[i++] = (char *)mode;
    argv[i++] = job->lock;
    argv[i++] = "--";
    while (cmd[c] != NULL && i + 1 < (int)(sizeof argv / sizeof argv[0]))
        argv[i++] = cmd[c++];
    argv[i] = NULL;
    if (cmd[c] != NULL)
        return 127;
    return cls_exec(job, argv, out, oc, err, ec, NULL);
}

static pid_t cls_bg(struct cls_job *job, char *const cmd[])
{
    char *argv[12];
    int i = 0;
    int c = 0;
    pid_t child;
    argv[i++] = job->tool;
    argv[i++] = "foreground";
    argv[i++] = job->lock;
    argv[i++] = "--";
    while (cmd[c] != NULL && i + 1 < (int)(sizeof argv / sizeof argv[0]))
        argv[i++] = cmd[c++];
    argv[i] = NULL;
    child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (job->nkids < (int)(sizeof job->kids / sizeof job->kids[0]))
        job->kids[job->nkids++] = child;
    return child;
}

static void cls_wait_kids(struct cls_job *job)
{
    int i;
    for (i = 0; i < job->nkids; i++) {
        if (job->kids[i] > 1)
            cls_reap(job->kids[i]);
        job->kids[i] = -1;
    }
    job->nkids = 0;
}

static void cls_stop(struct cls_job *job)
{
    int i;
    for (i = 0; i < job->nkids; i++) {
        if (job->kids[i] > 1)
            kill(job->kids[i], SIGTERM);
    }
    for (i = 0; i < job->nkids; i++) {
        if (job->kids[i] > 1)
            cls_reap(job->kids[i]);
        job->kids[i] = -1;
    }
    job->nkids = 0;
}

static void cls_scrub(struct cls_job *job)
{
    char path[PATH_MAX];
    static const char *names[] = {
        "child.out", "child.err", "fg-holding", "fg-release", "watcher-ran",
        "fg2-start", "fg2-done", "checkout.lock", NULL};
    int i;
    cls_stop(job);
    for (i = 0; names[i] != NULL; i++) {
        if (cls_path(path, sizeof path, job->work, names[i]) == 0)
            unlink(path);
    }
    if (job->work[0] != '\0')
        rmdir(job->work);
}

static int cls_marker(struct cls_job *job, const char *name, char *out, size_t cap)
{
    return cls_path(out, cap, job->work, name);
}

static int cls_wait_file(const char *path, pid_t holder)
{
    for (;;) {
        struct stat st;
        if (stat(path, &st) == 0)
            return 0;
        if (kill(holder, 0) != 0)
            return -1;
        if (cls_pause(10) != 0)
            return -1;
    }
}

static int cls_uncontended(struct cls_job *job)
{
    char out[CLS_OUT];
    char err[CLS_OUT];
    char *cmd[] = {"/bin/echo", "uncontended", NULL};
    int rc = cls_tool(job, "watcher", cmd, out, sizeof out, err, sizeof err);
    if (rc != 0 || strcmp(out, "uncontended") != 0)
        return cls_fail("uncontended watcher call did not run the command");
    return 0;
}

static int cls_defer(struct cls_job *job)
{
    char hold[PATH_MAX];
    char release[PATH_MAX];
    char ran[PATH_MAX];
    char script[PATH_MAX * 2];
    char out[CLS_OUT];
    char err[CLS_OUT];
    char touch[PATH_MAX + 16];
    char *hold_cmd[4];
    char *watch_cmd[4];
    pid_t holder;
    int rc;
    int nw;
    if (cls_marker(job, "fg-holding", hold, sizeof hold) != 0)
        return cls_fail("foreground holder did not start");
    if (cls_marker(job, "fg-release", release, sizeof release) != 0)
        return cls_fail("foreground holder did not start");
    if (cls_marker(job, "watcher-ran", ran, sizeof ran) != 0)
        return cls_fail("foreground holder did not start");
    nw = snprintf(script, sizeof script,
                  ": > '%s'; while [ ! -e '%s' ]; do sleep 0.01; done",
                  hold, release);
    if (nw < 0 || (size_t)nw >= sizeof script)
        return cls_fail("foreground holder did not start");
    hold_cmd[0] = "/bin/sh";
    hold_cmd[1] = "-c";
    hold_cmd[2] = script;
    hold_cmd[3] = NULL;
    holder = cls_bg(job, hold_cmd);
    if (holder < 0)
        return cls_fail("foreground holder did not start");
    if (cls_wait_file(hold, holder) != 0)
        return cls_fail("foreground holder did not start");
    nw = snprintf(touch, sizeof touch, ": > '%s'", ran);
    if (nw < 0 || (size_t)nw >= sizeof touch)
        return cls_fail("watcher must defer with exit 99 under contention, got setup");
    watch_cmd[0] = "/bin/sh";
    watch_cmd[1] = "-c";
    watch_cmd[2] = touch;
    watch_cmd[3] = NULL;
    rc = cls_tool(job, "watcher", watch_cmd, out, sizeof out, err, sizeof err);
    if (rc != 99) {
        fprintf(stderr,
                "checkout-lock-selftest: FAIL: watcher must defer with exit 99 under contention, got %d\n",
                rc);
        return 1;
    }
    if (access(ran, F_OK) == 0)
        return cls_fail("watcher ran the wrapped command instead of deferring");
    if (strstr(err, "deferred: foreground build holds the lock") == NULL)
        return cls_fail2("watcher did not print the documented deferred status: ", err);
    return 0;
}

static int cls_second(struct cls_job *job)
{
    char start[PATH_MAX];
    char done[PATH_MAX];
    char release[PATH_MAX];
    char script[PATH_MAX * 2];
    char *cmd[4];
    pid_t second;
    int nw;
    int fd;
    if (cls_marker(job, "fg2-start", start, sizeof start) != 0)
        return cls_fail("second foreground caller never ran after the holder released");
    if (cls_marker(job, "fg2-done", done, sizeof done) != 0)
        return cls_fail("second foreground caller never ran after the holder released");
    if (cls_marker(job, "fg-release", release, sizeof release) != 0)
        return cls_fail("second foreground caller never ran after the holder released");
    nw = snprintf(script, sizeof script, ": > '%s'; : > '%s'", start, done);
    if (nw < 0 || (size_t)nw >= sizeof script)
        return cls_fail("second foreground caller never ran after the holder released");
    cmd[0] = "/bin/sh";
    cmd[1] = "-c";
    cmd[2] = script;
    cmd[3] = NULL;
    second = cls_bg(job, cmd);
    if (second < 0)
        return cls_fail("second foreground caller never ran after the holder released");
    if (cls_pause(200) != 0)
        return cls_fail("second foreground caller ran while the first still held the lock");
    if (access(start, F_OK) == 0)
        return cls_fail("second foreground caller ran while the first still held the lock");
    fd = open(release, O_CREAT | O_WRONLY, 0600);
    if (fd < 0)
        return cls_fail("second foreground caller never ran after the holder released");
    close(fd);
    cls_wait_kids(job);
    if (access(done, F_OK) != 0)
        return cls_fail("second foreground caller never ran after the holder released");
    return 0;
}

static int cls_nested(struct cls_job *job)
{
    char script[PATH_MAX * 2];
    char out[CLS_OUT];
    char err[CLS_OUT];
    char *cmd[4];
    int nw;
    int rc;
    nw = snprintf(script, sizeof script, "'%s' foreground '%s' -- /bin/echo nested-ok",
                  job->tool, job->lock);
    if (nw < 0 || (size_t)nw >= sizeof script)
        return cls_fail("nested acquisition inside a held lock deadlocked or misbehaved");
    cmd[0] = "/bin/sh";
    cmd[1] = "-c";
    cmd[2] = script;
    cmd[3] = NULL;
    rc = cls_tool(job, "foreground", cmd, out, sizeof out, err, sizeof err);
    if (rc != 0 || strcmp(out, "nested-ok") != 0)
        return cls_fail("nested acquisition inside a held lock deadlocked or misbehaved");
    return 0;
}

static int cls_release(struct cls_job *job)
{
    char out[CLS_OUT];
    char err[CLS_OUT];
    char *bad[] = {"/bin/false", NULL};
    char *ok[] = {"/bin/echo", "released-after-failure", NULL};
    int rc = cls_tool(job, "foreground", bad, out, sizeof out, err, sizeof err);
    (void)rc;
    rc = cls_tool(job, "foreground", ok, out, sizeof out, err, sizeof err);
    if (rc != 0 || strcmp(out, "released-after-failure") != 0)
        return cls_fail("lock was not released after the wrapped command failed");
    return 0;
}

static int cls_append(char *dst, size_t cap, size_t *used, const char *src)
{
    size_t n = strlen(src);
    if (*used + n >= cap)
        return -1;
    memcpy(dst + *used, src, n);
    *used += n;
    dst[*used] = '\0';
    return 0;
}

static int cls_fast_ci(FILE *fp)
{
    char line[2048];
    char block[8192];
    size_t used = 0;
    int seen = 0;
    block[0] = '\0';
    rewind(fp);
    while (fgets(line, sizeof line, fp) != NULL) {
        if (!seen) {
            if (strncmp(line, "fast-ci agent-fast-ci:", 22) == 0)
                seen = 1;
            else
                continue;
        }
        if (cls_append(block, sizeof block, &used, line) != 0)
            return cls_fail("fast-ci source-wide proof is outside the checkout lock");
        if (seen && strncmp(line, "agent-plan:", 11) == 0)
            break;
    }
    if (!seen || strstr(block, k_fast_phrase) == NULL)
        return cls_fail("fast-ci source-wide proof is outside the checkout lock");
    return 0;
}

static int cls_find_exact(FILE *fp, const char *target, char *line, size_t cap)
{
    char want[160];
    int nw = snprintf(want, sizeof want, "%s:", target);
    if (nw < 0 || (size_t)nw >= sizeof want)
        return -1;
    rewind(fp);
    while (fgets(line, (int)cap, fp) != NULL) {
        cls_chomp(line);
        if (strcmp(line, want) == 0)
            return 0;
    }
    return -1;
}

static int cls_block(FILE *fp, const char *header, const char *inner)
{
    char chunk[16384];
    char line[2048];
    size_t used = 0;
    int i;
    const char *at;
    chunk[0] = '\0';
    if (cls_append(chunk, sizeof chunk, &used, header) != 0)
        return 0;
    if (cls_append(chunk, sizeof chunk, &used, "\n") != 0)
        return 0;
    for (i = 0; i < 7; i++) {
        if (fgets(line, sizeof line, fp) == NULL)
            break;
        if (cls_append(chunk, sizeof chunk, &used, line) != 0)
            return 0;
    }
    at = strstr(chunk, k_lock_phrase);
    if (at == NULL)
        return 0;
    return strstr(at, inner) != NULL;
}

static int cls_inner_need(FILE *fp, const char *inner, const char *need)
{
    char line[2048];
    char prefix[160];
    int nw = snprintf(prefix, sizeof prefix, "%s:", inner);
    if (nw < 0 || (size_t)nw >= sizeof prefix)
        return 0;
    rewind(fp);
    while (fgets(line, sizeof line, fp) != NULL) {
        cls_chomp(line);
        if (strncmp(line, prefix, strlen(prefix)) == 0)
            return strstr(line, need) != NULL;
    }
    return 0;
}

static int cls_one_pair(FILE *fp, const struct cls_pair *pair)
{
    char header[2048];
    if (cls_find_exact(fp, pair->pub, header, sizeof header) != 0)
        return cls_fail2(pair->pub, " has prerequisites outside the checkout lock");
    if (!cls_block(fp, header, pair->inner))
        return cls_fail2(pair->pub, " does not delegate construction under the checkout lock");
    if (!cls_inner_need(fp, pair->inner, pair->need)) {
        fprintf(stderr,
                "checkout-lock-selftest: FAIL: %s does not own required prerequisite %s\n",
                pair->inner, pair->need);
        return 1;
    }
    return 0;
}

static int cls_pairs(FILE *fp)
{
    size_t i;
    for (i = 0; i < sizeof k_pairs / sizeof k_pairs[0]; i++) {
        int rc = cls_one_pair(fp, &k_pairs[i]);
        if (rc != 0)
            return rc;
    }
    return 0;
}

static int cls_exact(FILE *fp)
{
    char line[2048];
    char block[16384];
    size_t used = 0;
    const char *build;
    int seen = 0;
    block[0] = '\0';
    rewind(fp);
    while (fgets(line, sizeof line, fp) != NULL) {
        if (!seen) {
            if (strncmp(line, "t-fast-exact-locked:", 20) != 0)
                continue;
            seen = 1;
        }
        cls_chomp(line);
        if (line[0] == '\0')
            break;
        if (cls_append(block, sizeof block, &used, line) != 0)
            return cls_fail("t-fast-exact-locked must build selected needs under the lock before running the same exact selection");
        if (cls_append(block, sizeof block, &used, "\n") != 0)
            return cls_fail("t-fast-exact-locked must build selected needs under the lock before running the same exact selection");
    }
    build = strstr(block, k_exact_build);
    if (!seen || build == NULL || strstr(build, k_exact_run) == NULL)
        return cls_fail("t-fast-exact-locked must build selected needs under the lock before running the same exact selection");
    return 0;
}

static int cls_inner_make(struct cls_job *job)
{
    char err[CLS_OUT];
    char out[64];
    char *argv[] = {
        "make", "-s", "-C", job->root, "-n", "t-fast-locked", "ONLY=build_fabric", NULL};
    int rc = cls_exec(job, argv, out, sizeof out, err, sizeof err, "0");
    if (rc == 0)
        return cls_fail("direct inner target unexpectedly ran unlocked");
    if (strstr(err, k_inner_phrase) == NULL)
        return cls_fail2("direct inner target did not report the lock invariant: ", err);
    return 0;
}

static int cls_prepare(struct cls_job *job, const char *repo)
{
    const char *tmp = getenv("TMPDIR");
    int n;
    memset(job, 0, sizeof *job);
    if (repo == NULL || repo[0] == '\0')
        return cls_fail("repo is required");
    if (snprintf(job->root, sizeof job->root, "%s", repo) >= (int)sizeof job->root)
        return cls_fail("repo is required");
    if (cls_path(job->tool, sizeof job->tool, job->root, "build/bin/checkout-lock") != 0)
        return cls_fail("checkout-lock is not executable");
    if (access(job->tool, X_OK) != 0)
        return cls_fail("checkout-lock is not executable");
    if (cls_path(job->make_path, sizeof job->make_path, job->root, "Makefile") != 0)
        return cls_fail("fast-ci source-wide proof is outside the checkout lock");
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    n = snprintf(job->work, sizeof job->work, "%s/zcl-checkout-lock-selftest.XXXXXX", tmp);
    if (n < 0 || (size_t)n >= sizeof job->work)
        return cls_fail("foreground holder did not start");
    if (mkdtemp(job->work) == NULL)
        return cls_fail("foreground holder did not start");
    if (cls_path(job->lock, sizeof job->lock, job->work, "checkout.lock") != 0)
        return cls_fail("foreground holder did not start");
    return 0;
}

static int cls_body(struct cls_job *job)
{
    FILE *fp;
    int rc = cls_uncontended(job);
    if (rc == 0)
        rc = cls_defer(job);
    if (rc == 0)
        rc = cls_second(job);
    if (rc == 0)
        rc = cls_nested(job);
    if (rc == 0)
        rc = cls_release(job);
    if (rc != 0)
        return rc;
    fp = fopen(job->make_path, "r");
    if (fp == NULL)
        return cls_fail("fast-ci source-wide proof is outside the checkout lock");
    rc = cls_fast_ci(fp);
    if (rc == 0)
        rc = cls_pairs(fp);
    if (rc == 0)
        rc = cls_exact(fp);
    fclose(fp);
    if (rc != 0)
        return rc;
    return cls_inner_make(job);
}

static int cls_go(const char *repo)
{
    struct cls_job job;
    char saved[32];
    const char *held = getenv("ZCL_CHECKOUT_LOCK_HELD");
    int had = held != NULL;
    int rc;
    saved[0] = '\0';
    if (had && strlen(held) + 1 <= sizeof saved)
        memcpy(saved, held, strlen(held) + 1);
    unsetenv("ZCL_CHECKOUT_LOCK_HELD");
    rc = cls_prepare(&job, repo);
    if (rc == 0)
        rc = cls_body(&job);
    cls_scrub(&job);
    if (had)
        setenv("ZCL_CHECKOUT_LOCK_HELD", saved, 1);
    if (rc == 0)
        printf("checkout-lock-selftest: PASS uncontended=true watcher_defers=true foreground_blocks=true nested_no_deadlock=true releases_on_failure=true fast_ci_serialized=true build_and_run_serialized=true inner_bypass_refused=true\n");
    return rc;
}

#endif

int zcl_checkout_lock_selftest(const char *repo)
{
#if defined(_WIN32)
    (void)repo;
    fputs("checkout-lock-selftest: FAIL: unavailable on Windows\n", stdout);
    return 2;
#else
    return cls_go(repo);
#endif
}
