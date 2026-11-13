/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private-directory driver for make-depfile-scope-selftest.
 *          It contributes no node or receipt authority. */

#define _POSIX_C_SOURCE 200809L

#include "depfile_scope_launch.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if !defined(_WIN32)
static volatile sig_atomic_t dsl_stop;

static void dsl_on_stop(int sig)
{
    (void)sig;
    dsl_stop = 1;
}

static int dsl_rm_tree(const char *path)
{
    struct stat st;
    DIR *dir;
    struct dirent *ent;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        char child[PATH_MAX];
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof child, "%s/%s", path, ent->d_name) >=
            (int)sizeof child) {
            closedir(dir);
            return -1;
        }
        if (dsl_rm_tree(child) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return rmdir(path) == 0 || errno == ENOENT ? 0 : -1;
}

static int dsl_status(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 1;
}

static int dsl_wait(pid_t pid)
{
    for (;;) {
        int status = 0;
        pid_t got = waitpid(pid, &status, 0);
        if (got == pid)
            return dsl_status(status);
        if (errno != EINTR)
            return 127;
        if (!dsl_stop)
            continue;
        kill(pid, SIGTERM);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        return 1;
    }
}

static int dsl_run(char *const argv[], const char *linker)
{
    pid_t pid = fork();
    int rc;
    if (pid < 0)
        return 127;
    if (pid == 0) {
        if (linker && setenv("ZCL_DEV_LINKER", linker, 1) != 0)
            _exit(127);
        execvp(argv[0], argv);
        _exit(127);
    }
    rc = dsl_wait(pid);
    return rc;
}

/* Successful empty output is a valid default-linker selection. */
static bool dsl_linker_text(char *out, size_t n)
{
    while (n && out[n - 1] == '\n') --n;
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)out[i] < 32 || (unsigned char)out[i] > 126) return false;
    out[n] = '\0';
    return !strcmp(out, "") || !strcmp(out, "-fuse-ld=mold") ||
        !strcmp(out, "-fuse-ld=lld") ||
        !strcmp(out, "-fuse-ld=gold -Wl,--threads -Wl,--thread-count=9");
}

/* The selector's process group is contained on interruption or overrun. */
static int64_t dsl_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 || // platform-ok: standalone fixture launcher links no platform clock; deadline needs host time
        ts.tv_sec > (INT64_MAX - 999) / 1000) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool dsl_linker_read(int fd, pid_t child, char *out, size_t cap, int64_t deadline)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    size_t used = 0;
    while (!dsl_stop) {
        int64_t now = dsl_now_ms();
        if (now < 0 || now >= deadline) break;
        int rc = poll(&p, 1, 100);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) break;
        if (!rc) continue;
        char buf[128];
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;
        if (!n) return dsl_linker_text(out, used);
        if ((size_t)n >= cap - used) break;
        memcpy(out + used, buf, (size_t)n); used += (size_t)n;
    }
    (void)kill(-child, SIGKILL); (void)kill(child, SIGKILL);
    return false;
}

static bool dsl_linker_wait(pid_t child, int64_t deadline)
{
    while (!dsl_stop) {
        int status = 0;
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (got < 0 && errno != EINTR) return false;
        int64_t now = dsl_now_ms();
        if (now < 0 || now >= deadline) break;
        (void)poll(NULL, 0, 100);
    }
    (void)kill(-child, SIGKILL); (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return false;
}

static bool dsl_linker_select(const char *root, char *out, size_t cap)
{
    int p[2];
    int64_t start = dsl_now_ms();
    if (start < 0 || start > INT64_MAX - 10000) return false;
    if (pipe(p) != 0) return false;
    if (p[1] <= STDERR_FILENO) { close(p[0]); close(p[1]); return false; }
    pid_t child = fork();
    if (child < 0) { close(p[0]); close(p[1]); return false; }
    if (!child) {
        if (setpgid(0, 0) != 0) _exit(127);
        close(p[0]);
        if (chdir(root) != 0 || dup2(p[1], STDOUT_FILENO) < 0) _exit(127);
        close(p[1]);
        execl("./tools/dev/dev-linker-select.sh", "dev-linker-select.sh", (char *)NULL);
        _exit(127);
    }
    (void)setpgid(child, child);
    close(p[1]);
    bool valid = dsl_linker_read(p[0], child, out, cap, start + 10000);
    close(p[0]);
    return dsl_linker_wait(child, start + 10000) && valid;
}

static bool dsl_linker_allowed(void)
{
    if (getenv("ZCL_DEV_LINKER")) return false;
    const char *const controls[] = {"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS",
                                    "MAKEOVERRIDES", "MAKEFILES"};
    for (size_t i = 0; i < sizeof controls / sizeof controls[0]; ++i) {
        const char *v = getenv(controls[i]);
        if (v && *v) return false;
    }
    return true;
}

static int dsl_arm(struct sigaction *old_hup, struct sigaction *old_int,
                   struct sigaction *old_term)
{
    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_handler = dsl_on_stop;
    if (sigaction(SIGHUP, &act, old_hup) != 0 ||
        sigaction(SIGINT, &act, old_int) != 0 ||
        sigaction(SIGTERM, &act, old_term) != 0)
        return -1;
    return 0;
}

static void dsl_disarm(const struct sigaction *old_hup,
                       const struct sigaction *old_int,
                       const struct sigaction *old_term)
{
    (void)sigaction(SIGHUP, old_hup, NULL);
    (void)sigaction(SIGINT, old_int, NULL);
    (void)sigaction(SIGTERM, old_term, NULL);
}

static int dsl_launch(const char *root)
{
    char work[PATH_MAX];
    char target[PATH_MAX];
    char bindir[PATH_MAX];
    char linker[256]; const char *selected = NULL;
    const char *tmp = getenv("TMPDIR");
    char *make_argv[8];
    char *tool_argv[4];
    int rc;
    if (!tmp || !tmp[0])
        tmp = "/tmp";
    if (snprintf(work, sizeof work, "%s/zcl-depfile-scope.XXXXXX", tmp) >=
        (int)sizeof work)
        return 2;
    if (mkdtemp(work) == NULL)
        return 2;
    if (dsl_linker_allowed() && dsl_linker_select(root, linker, sizeof linker))
        selected = linker;
    if (dsl_stop) { (void)dsl_rm_tree(work); return 1; }
    if (snprintf(target, sizeof target, "%s/bin/make-depfile-scope-selftest",
                 work) >= (int)sizeof target ||
        snprintf(bindir, sizeof bindir, "BIN_DIR=%s/bin", work) >=
            (int)sizeof bindir) {
        (void)dsl_rm_tree(work);
        return 2;
    }
    make_argv[0] = "make";
    make_argv[1] = "-C";
    make_argv[2] = (char *)root;
    make_argv[3] = "--no-print-directory";
    make_argv[4] = "ZCL_STANDALONE_CLEAN=1";
    make_argv[5] = bindir;
    make_argv[6] = target;
    make_argv[7] = NULL;
    rc = dsl_run(make_argv, selected);
    if (rc == 0) {
        tool_argv[0] = target;
        tool_argv[1] = (char *)root;
        tool_argv[2] = work;
        tool_argv[3] = NULL;
        rc = dsl_run(tool_argv, selected);
    }
    (void)dsl_rm_tree(work);
    return rc;
}
#endif

int zcl_depfile_scope_launch(const char *root)
{
#if defined(_WIN32)
    (void)root;
    return 2;
#else
    struct sigaction old_hup;
    struct sigaction old_int;
    struct sigaction old_term;
    int rc;
    if (!root || !root[0])
        return 2;
    dsl_stop = 0;
    if (dsl_arm(&old_hup, &old_int, &old_term) != 0)
        return 2;
    rc = dsl_launch(root);
    dsl_disarm(&old_hup, &old_int, &old_term);
    return rc;
#endif
}
