/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: execute a parsed gate plan for `z23-lint run` by fork/execvp of
 * each step's argv. No shell is involved; a step's status follows the shell
 * convention (exit code, 128+signal for a kill, 127 for a failed exec) so the
 * rc column of the verdict line matches the shell driver's.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "run_priv.h"

enum { RC_EXEC_FAILED = 127, RC_SIGNAL_BASE = 128 };

static void step_child(const struct lr_step *st)
{
    for (int i = 0; i < st->nenv; i++) {
        char *eq = strchr(st->env[i], '=');
        if (eq) {
            *eq = '\0';
            (void)setenv(st->env[i], eq + 1, 1);
        }
    }
    (void)execvp(st->argv[0], st->argv);
    (void)fprintf(stderr, "z23-lint run: cannot execute '%s': %s\n", st->argv[0],
                  strerror(errno));
    _exit(RC_EXEC_FAILED);
}

/* A shell reports a child's death by signal as 128+N. */
static int status_rc(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        (void)fprintf(stderr, "z23-lint run: step killed by signal %d\n",
                      WTERMSIG(status));
        return RC_SIGNAL_BASE + WTERMSIG(status);
    }
    return 1;
}

static int wait_for(pid_t pid)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return 1;
    }
    return status_rc(status);
}

static int run_step(const struct lr_step *st)
{
    (void)fflush(NULL);
    pid_t pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        struct lr_step copy = *st;      /* step_child edits the env words */
        step_child(&copy);
    }
    return wait_for(pid);
}

int lr_run_plan(const struct lr_plan *plan)
{
    int rc = 0;
    for (int i = 0; i < plan->nsteps && rc == 0; i++)
        rc = run_step(&plan->steps[i]);
    return rc;
}

/* ---- check-core-seal: git ls-files -z PATHS | core_seal check MANIFEST --- */

static const char *const k_seal_paths[] = {
    "core/", "core/modules/validation/src/connect_block.c",
    "core/modules/validation/src/chainstate.c",
    "core/modules/validation/include/validation/connect_block.h",
    "core/modules/validation/include/validation/chainstate.h",
};

static pid_t spawn_ls_files(int wfd)
{
    char *argv[3 + sizeof k_seal_paths / sizeof k_seal_paths[0] + 1];
    int n = 0;
    argv[n++] = "git";
    argv[n++] = "ls-files";
    argv[n++] = "-z";
    for (size_t i = 0; i < sizeof k_seal_paths / sizeof k_seal_paths[0]; i++)
        argv[n++] = (char *)k_seal_paths[i];
    argv[n] = NULL;
    (void)fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        (void)dup2(wfd, STDOUT_FILENO);
        (void)close(wfd);
        (void)execvp("git", argv);
        _exit(RC_EXEC_FAILED);
    }
    return pid;
}

static pid_t spawn_seal_check(int rfd, const char *bin_dir)
{
    char tool[LR_PATH];
    (void)snprintf(tool, sizeof tool, "%s/core_seal", bin_dir);
    (void)fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { tool, "check", "core/MANIFEST.sha3", NULL };
        (void)dup2(rfd, STDIN_FILENO);
        (void)close(rfd);
        (void)execv(tool, argv);
        (void)fprintf(stderr, "z23-lint run: cannot execute '%s': %s\n", tool,
                      strerror(errno));
        _exit(RC_EXEC_FAILED);
    }
    return pid;
}

int lr_core_seal(const char *bin_dir)
{
    int fds[2];
    int unsealed = access(".core-unseal-token", F_OK) == 0;
    if (unsealed) {
        puts("check-core-seal: unseal token present \xe2\x80\x94 seal check lifted for this commit");
        puts("  (owner unseal ritual active; re-run 'make core-seal' to refreeze before commit.)");
    }
    if (pipe(fds) != 0)
        return 1;
    pid_t ls = spawn_ls_files(fds[1]);
    pid_t seal = spawn_seal_check(fds[0], bin_dir);
    (void)close(fds[0]);
    (void)close(fds[1]);
    if (ls < 0 || seal < 0)
        return 1;
    int rc_ls = wait_for(ls);
    int rc_seal = wait_for(seal);
    if (unsealed)
        return 0;
    return rc_seal != 0 ? rc_seal : rc_ls;     /* pipefail: rightmost non-zero */
}
