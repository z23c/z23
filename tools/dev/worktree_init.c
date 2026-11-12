/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Copy vendor/lib and vendor/include into a lane worktree, arm
 *          its git hooks, and require the VENDOR_ARCHIVES link set. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "worktree_init.h"
#include "copy_vendor_include.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *const k_archives[] = {
    "libsecp256k1.a", "libcrypto.a", "libssl.a", "libevent.a",
    "libevent_openssl.a", "libevent_pthreads.a", "libleveldb.a",
    "libsqlite3.a", "libz.a", "libtor_stub.a"
};

static int wi_status(pid_t pid)
{
    int status = 0;
    pid_t got = -1;
    while (got != pid) {
        got = waitpid(pid, &status, 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return 1;
    }
    if (!WIFEXITED(status))
        return 1;
    return WEXITSTATUS(status);
}

static int wi_run(const char *cwd, char *const argv[], int quiet)
{
    pid_t pid = fork();
    int sink;
    if (pid < 0)
        return -1;
    if (pid != 0)
        return wi_status(pid);
    if (chdir(cwd) != 0)
        _exit(127);
    if (quiet) {
        sink = open("/dev/null", O_WRONLY);
        if (sink >= 0) {
            (void)dup2(sink, STDOUT_FILENO);
            (void)dup2(sink, STDERR_FILENO);
            if (sink > STDERR_FILENO)
                close(sink);
        }
    }
    execvp(argv[0], argv);
    _exit(127);
}

static void wi_strip(char *line)
{
    char *end = line + strlen(line);
    while (end > line) {
        if (end[-1] != '\n' && end[-1] != '\r')
            break;
        *--end = '\0';
    }
}

static void wi_capture_child(const char *cwd, int wr, char *const argv[])
{
    int sink = open("/dev/null", O_WRONLY);
    if (chdir(cwd) != 0)
        _exit(127);
    if (dup2(wr, STDOUT_FILENO) < 0)
        _exit(127);
    if (sink >= 0)
        (void)dup2(sink, STDERR_FILENO);
    if (wr > STDERR_FILENO)
        close(wr);
    if (sink > STDERR_FILENO)
        close(sink);
    execvp(argv[0], argv);
    _exit(127);
}

static int wi_take(int fd, char *buf, size_t cap)
{
    size_t used = 0;
    if (cap < 2)
        return -1;
    for (;;) {
        ssize_t step = read(fd, buf + used, cap - 1 - used);
        if (step > 0) {
            used += (size_t)step;
            if (used + 1 >= cap)
                return -1;
            continue;
        }
        if (step == 0) {
            buf[used] = '\0';
            return 0;
        }
        if (errno != EINTR)
            return -1;
    }
}

static int wi_read(const char *cwd, char *const argv[], char *out, size_t cap)
{
    int fds[2];
    pid_t pid;
    int taken;
    out[0] = '\0';
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        wi_capture_child(cwd, fds[1], argv);
        _exit(127);
    }
    close(fds[1]);
    taken = wi_take(fds[0], out, cap);
    close(fds[0]);
    if (taken != 0) {
        (void)wi_status(pid);
        return -1;
    }
    wi_strip(out);
    return wi_status(pid);
}

static int wi_real(const char *path, char *out, size_t cap)
{
    char tmp[PATH_MAX];
    size_t n;
    if (realpath(path, tmp) == NULL)
        return -1;
    n = strlen(tmp);
    if (n + 1 > cap)
        return -1;
    memcpy(out, tmp, n + 1);
    return 0;
}

static int wi_parent(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    size_t n;
    if (slash == NULL || slash == path)
        return -1;
    n = (size_t)(slash - path);
    if (n + 1 > cap)
        return -1;
    memcpy(out, path, n);
    out[n] = '\0';
    return 0;
}

static int wi_canonical(const char *worktree, char *out, size_t cap)
{
    char common[PATH_MAX];
    char parent[PATH_MAX];
    char *argv[] = {"git", "rev-parse", "--path-format=absolute",
                    "--git-common-dir", NULL};
    int rc = wi_read(worktree, argv, common, sizeof common);
    if (rc != 0 || common[0] == '\0')
        return rc == 0 ? 1 : rc;
    if (wi_parent(common, parent, sizeof parent) != 0)
        return 1;
    if (wi_real(parent, out, cap) != 0)
        return 1;
    return 0;
}

static int wi_is_dir(const char *candidate)
{
    struct stat info;
    if (stat(candidate, &info) != 0)
        return 0;
    return S_ISDIR(info.st_mode) ? 1 : 0;
}

static int wi_is_file(const char *candidate)
{
    struct stat info;
    if (stat(candidate, &info) != 0)
        return 0;
    return S_ISREG(info.st_mode) ? 1 : 0;
}

static int wi_join(char *dst, size_t cap, const char *dir, const char *name)
{
    int wrote = snprintf(dst, cap, "%s/%s", dir, name);
    if (wrote < 1)
        return -1;
    if ((size_t)wrote >= cap)
        return -1;
    return 0;
}

static int wi_vendor_lib(const char *worktree, const char *canonical, int same)
{
    char src[PATH_MAX];
    char dst[PATH_MAX];
    char vendor[PATH_MAX];
    char *diffv[5];
    char *cpv[5];
    if (same) {
        printf("[1/3] vendor/lib: this IS the canonical checkout -- nothing to copy\n");
        return 0;
    }
    if (wi_join(src, sizeof src, canonical, "vendor/lib") != 0)
        return 1;
    if (!wi_is_dir(src)) {
        fprintf(stderr, "[1/3] vendor/lib: FAIL -- canonical %s is missing\n", src);
        fprintf(stderr, "  Build vendor archives in the canonical checkout first: make vendor-ready\n");
        return 1;
    }
    if (wi_join(vendor, sizeof vendor, worktree, "vendor") != 0)
        return 1;
    if (mkdir(vendor, 0755) != 0 && errno != EEXIST)
        return 1;
    if (wi_join(dst, sizeof dst, worktree, "vendor/lib") != 0)
        return 1;
    diffv[0] = "diff";
    diffv[1] = "-rq";
    diffv[2] = src;
    diffv[3] = dst;
    diffv[4] = NULL;
    if (wi_is_dir(dst) && wi_run(worktree, diffv, 1) == 0) {
        printf("[1/3] vendor/lib: already identical to %s -- skipped\n", src);
        return 0;
    }
    cpv[0] = "cp";
    cpv[1] = "-a";
    cpv[2] = src;
    cpv[3] = "vendor/";
    cpv[4] = NULL;
    if (wi_run(worktree, cpv, 0) != 0)
        return 1;
    printf("[1/3] vendor/lib: copied from %s\n", src);
    return 0;
}

static int wi_vendor_include(const char *worktree, const char *canonical, int same)
{
    char src[PATH_MAX];
    char dst[PATH_MAX];
    char *diffv[5];
    if (same) {
        printf("[1b/3] vendor/include: this IS the canonical checkout -- nothing to copy\n");
        return 0;
    }
    if (wi_join(src, sizeof src, canonical, "vendor/include") != 0)
        return 1;
    if (!wi_is_dir(src)) {
        fprintf(stderr,
                "[1b/3] vendor/include: canonical %s is missing -- openssl/zlib gates will fail until you run make vendor there\n",
                src);
        return 0;
    }
    if (wi_join(dst, sizeof dst, worktree, "vendor/include") != 0)
        return 1;
    diffv[0] = "diff";
    diffv[1] = "-rq";
    diffv[2] = src;
    diffv[3] = dst;
    diffv[4] = NULL;
    if (wi_is_dir(dst) && wi_run(worktree, diffv, 1) == 0) {
        printf("[1b/3] vendor/include: already identical -- skipped\n");
        return 0;
    }
    if (zcl_copy_vendor_include(canonical, worktree, STDERR_FILENO) != 0)
        return 1;
    printf("[1b/3] vendor/include: merged from %s\n", src);
    return 0;
}

static int wi_hooks(const char *worktree)
{
    char before[PATH_MAX];
    char after[PATH_MAX];
    char *getv[] = {"git", "config", "--worktree", "--get", "core.hooksPath", NULL};
    char *makev[] = {"make", "--no-print-directory", "install-hooks", NULL};
    int rc;
    before[0] = '\0';
    (void)wi_read(worktree, getv, before, sizeof before);
    rc = wi_run(worktree, makev, 0);
    if (rc != 0)
        return rc;
    rc = wi_read(worktree, getv, after, sizeof after);
    if (rc != 0)
        return rc;
    if (strcmp(before, after) == 0)
        printf("[2/3] git hooks: native checkout-local hooks already armed -- refreshed\n");
    else
        printf("[2/3] git hooks: native checkout-local hooks armed at %s\n", after);
    return 0;
}

static int wi_missing_add(char *buf, size_t cap, const char *item)
{
    size_t n = strlen(buf);
    size_t m = strlen(item);
    if (n + (n > 0 ? 1 : 0) + m + 1 > cap)
        return -1;
    if (n > 0)
        buf[n++] = ' ';
    memcpy(buf + n, item, m + 1);
    return 0;
}

static int wi_need(char *missing, size_t cap, const char *worktree,
                   const char *rel, int directory)
{
    char path[PATH_MAX];
    int present;
    if (wi_join(path, sizeof path, worktree, rel) != 0)
        return -1;
    present = directory ? wi_is_dir(path) : wi_is_file(path);
    if (present)
        return 0;
    return wi_missing_add(missing, cap, rel);
}

static int wi_prereq(const char *worktree, const char *canonical)
{
    char missing[1024];
    char path[PATH_MAX];
    size_t i;
    missing[0] = '\0';
    if (wi_need(missing, sizeof missing, worktree, "vendor/include", 1) != 0)
        return 1;
    if (wi_need(missing, sizeof missing, worktree, "vendor/include/openssl", 1) != 0)
        return 1;
    if (wi_need(missing, sizeof missing, worktree, "vendor/include/zlib.h", 0) != 0)
        return 1;
    if (wi_need(missing, sizeof missing, worktree, "vendor/include/zconf.h", 0) != 0)
        return 1;
    for (i = 0; i < sizeof k_archives / sizeof k_archives[0]; i++) {
        char rel[64];
        if (snprintf(rel, sizeof rel, "vendor/lib/%s", k_archives[i]) >= (int)sizeof rel)
            return 1;
        if (wi_join(path, sizeof path, worktree, rel) != 0)
            return 1;
        if (!wi_is_file(path) && wi_missing_add(missing, sizeof missing, rel) != 0)
            return 1;
    }
    if (missing[0] != '\0') {
        fprintf(stderr, "[3/3] link prerequisites: FAIL -- missing: %s\n", missing);
        fprintf(stderr, "  vendor/lib gaps: re-run this script, or cp -a %s/vendor/lib vendor/\n",
                canonical);
        fprintf(stderr,
                "  vendor/include gaps: cp -a %s/vendor/include vendor/ (or: make vendor in %s)\n",
                canonical, canonical);
        return 1;
    }
    printf("[3/3] link prerequisites: OK (vendor/include + all %u VENDOR_ARCHIVES present)\n",
           (unsigned)(sizeof k_archives / sizeof k_archives[0]));
    return 0;
}

static int wi_body(const char *worktree)
{
    char root[PATH_MAX];
    char canonical[PATH_MAX];
    int same;
    int rc;
    if (wi_real(worktree, root, sizeof root) != 0)
        return 1;
    rc = wi_canonical(root, canonical, sizeof canonical);
    if (rc != 0)
        return rc;
    same = strcmp(root, canonical) == 0;
    printf("== worktree-init: %s ==\n", root);
    printf("   canonical source: %s\n", canonical);
    rc = wi_vendor_lib(root, canonical, same);
    if (rc != 0)
        return rc;
    rc = wi_vendor_include(root, canonical, same);
    if (rc != 0)
        return rc;
    rc = wi_hooks(root);
    if (rc != 0)
        return rc;
    rc = wi_prereq(root, canonical);
    if (rc != 0)
        return rc;
    printf("== worktree-init: done ==\n");
    return 0;
}
#endif

int zcl_worktree_init(const char *worktree)
{
#if defined(_WIN32)
    (void)worktree;
    fprintf(stderr, "worktree-init: unavailable on Windows\n");
    return 1;
#else
    if (worktree == NULL || worktree[0] == '\0') {
        fprintf(stderr, "worktree-init: missing worktree\n");
        return 1;
    }
    return wi_body(worktree);
#endif
}
