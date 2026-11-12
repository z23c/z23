/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private-directory driver for make-depfile-scope-selftest.
 *          It contributes no node or receipt authority. */

#define _POSIX_C_SOURCE 200809L

#include "depfile_scope_launch.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

static int dsl_run(char *const argv[])
{
    pid_t pid = fork();
    int rc;
    if (pid < 0)
        return 127;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    rc = dsl_wait(pid);
    return rc;
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
    rc = dsl_run(make_argv);
    if (rc == 0) {
        tool_argv[0] = target;
        tool_argv[1] = (char *)root;
        tool_argv[2] = work;
        tool_argv[3] = NULL;
        rc = dsl_run(tool_argv);
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
