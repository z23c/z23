/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * devloop_baseline — the dev-loop's detach launcher for the generation-
 * neutral initial ZVCS baseline. This is the ONLY place the POSIX double-fork
 * mechanics live: contexts/commons/modules/vcs/ must stay process-spawn
 * free (check-vcs-no-git — ZVCS sovereignty; contexts/commons/modules/vcs is release-linkable),
 * so it exports a purely synchronous
 * vcs_devloop_run_initial_baseline(repo_root, out) and leaves detaching that
 * call to whoever wants it off their foreground path. The interactive dev
 * loop (tools/dev/devloop_cycle.c:finish_cycle()) is that caller: on a green
 * cycle whose repo has no durable ZVCS history yet, it needs the baseline
 * to run WITHOUT blocking the edit->verdict latency the dev loop is built to
 * keep tight.
 *
 * DEV-ONLY, like the rest of tools/dev's mutating executors
 * (devloop_cycle.c, devloop_watch.c, devloop_process.c): linked only into
 * the dev binary (DEV_ONLY_SRCS in the Makefile), and every process-spawning
 * line lives inside a `#ifdef ZCL_DEV_BUILD` region so a release build never
 * even compiles a fork() here — matching the pattern in devloop_process.c's
 * zcl_devloop_process_run(). check-release-no-dev-symbols proves the release
 * binary carries none of this. */

#define _GNU_SOURCE
#include "devloop.h"

#include "vcs/vcs_devloop.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_DEV_BUILD
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#endif

bool zcl_devloop_baseline_launch(const char *repo_root)
{
    if (!repo_root || !repo_root[0]) {
        fprintf(stderr, "[devloop] baseline: invalid repo_root\n");
        return false;
    }

#ifndef ZCL_DEV_BUILD
    fprintf(stderr, "[devloop] baseline detach is disabled outside a dev build\n");
    return false;
#else
    char dir[PATH_MAX], log_path[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/.zvcs", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        return false;
    n = snprintf(log_path, sizeof(log_path), "%s/bootstrap.log", dir);
    if (n <= 0 || (size_t)n >= sizeof(log_path))
        return false;

#if defined(_WIN32)
    /* There is no qualified detached-process seam on Windows yet. Run the
     * initial baseline synchronously: this preserves repository isolation and
     * completion semantics without sharing mutable VCS state with a detached
     * in-process thread. */
    struct vcs_devloop_anchor_result result;
    vcs_devloop_run_initial_baseline(repo_root, &result);
    FILE *log = fopen(log_path, "ab");
    if (log) {
        fprintf(log, "[vcs.devloop] initial baseline %s%s%s\n",
                result.status == VCS_DEVLOOP_ANCHOR_OK ? "complete" : "failed",
                result.status == VCS_DEVLOOP_ANCHOR_OK ? "" : ": ",
                result.status == VCS_DEVLOOP_ANCHOR_OK ? "" :
                    (result.error[0] ? result.error : "unknown error"));
        fclose(log);
    }
    return result.status == VCS_DEVLOOP_ANCHOR_OK;
#else
    /* Double fork: the immediate child setsid()s and forks again, then
     * exits so the launcher (this process) can reap it right away — the
     * persistent dev-loop watcher never accumulates an unreaped zombie
     * across cycles. The grandchild is the actual baseline worker. */
    pid_t launcher = fork();
    if (launcher < 0) {
        fprintf(stderr, "[devloop] baseline: fork failed: %s\n",
                strerror(errno));
        return false;
    }
    if (launcher == 0) {
        if (setsid() < 0)
            _exit(1);
        pid_t worker = fork();
        if (worker < 0)
            _exit(1);
        if (worker > 0)
            _exit(0);

        int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int log_fd = open(log_path,
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
        if (log_fd >= 0) {
            (void)dup2(log_fd, STDOUT_FILENO);
            (void)dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        struct vcs_devloop_anchor_result result;
        vcs_devloop_run_initial_baseline(repo_root, &result);
        if (result.status == VCS_DEVLOOP_ANCHOR_OK)
            fprintf(stderr, "[vcs.devloop] initial baseline complete\n");
        else
            fprintf(stderr, "[vcs.devloop] initial baseline failed: %s\n",
                    result.error[0] ? result.error : "unknown error");
        _exit(result.status == VCS_DEVLOOP_ANCHOR_OK ? 0 : 1);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(launcher, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == launcher && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
#endif
#endif
}
