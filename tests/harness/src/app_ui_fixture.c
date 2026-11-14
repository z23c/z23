/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: retain and safely stop direct children in Linux app UI fixtures. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include "test/app_ui_fixture.h"
#if defined(__linux__) && defined(ZCL_TESTING)
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
bool app_ui_pipe(int fd[2])
{
    if (pipe(fd) != 0) return false;
    if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) == 0 && fcntl(fd[1], F_SETFD, FD_CLOEXEC) == 0) return true;
    close(fd[0]); close(fd[1]); return false;
}
/* The fork child blocks before exec until its start token and inherited
 * harness executable are observed. Fast driver exits retain direct-child
 * custody, without pretending a post-exec /proc observation occurred. */
static void ru_exec(const char *const *argv, int in, int out, int err, int gate)
{
    char go = 0;
    if (read(gate, &go, 1) != 1 || go != 'G') _exit(126);
    close(gate);
    if (dup2(in, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0) _exit(126);
    execv(argv[0], (char *const *)argv);
    _exit(127);
}
bool app_ui_spawn(struct app_ui_child *c, const char *const *argv, int in, int out, int err)
{
    int gate[2];
    if (!realpath(argv[0], c->image) || !app_ui_pipe(gate)) return false;
    c->pid = fork();
    if (c->pid == 0) { close(gate[1]); ru_exec(argv, in, out, err, gate[0]); }
    close(gate[0]);
    bool pinned = c->pid > 1 && app_proc_identity(c->pid, c->before, &c->token) && c->token;
    bool sent = pinned && write(gate[1], "G", 1) == 1;
    close(gate[1]);
    return sent;
}
/* Identity failure may reap a zombie internally; ECHILD is accepted only for
 * this retained direct child, never for unrelated or adopted grandchildren. */
static bool ru_matches(struct app_ui_child *c)
{
    char exe[APP_LAUNCH_PATH_MAX]; uint64_t token = 0;
    return app_proc_identity(c->pid, exe, &token) && token == c->token &&
        (!strcmp(exe, c->image) || !strcmp(exe, c->before));
}
enum platform_process_wait_result app_ui_wait(struct app_ui_child *c, unsigned ms, uint32_t *code)
{
    if (c->pid <= 1) return PLATFORM_PROCESS_WAIT_EXITED;
    struct platform_process p; platform_process_init(&p);
    p.native = (uintptr_t)c->pid; p.pid = (uint64_t)c->pid;
    enum platform_process_wait_result rc = platform_process_wait(&p, ms, code);
    if (rc == PLATFORM_PROCESS_WAIT_EXITED) c->pid = -1;
    return rc;
}
bool app_ui_reaped_identity_failure(struct app_ui_child *c)
{
    /* Only retained/enumerated direct children reach this fallback. Identity
     * may disappear during exit before waitpid can reap. Observe that exact
     * child with the existing bounded wait; never signal without identity. */
    if (app_ui_wait(c, 2000, NULL) == PLATFORM_PROCESS_WAIT_EXITED) return true;
    pid_t done;
    do { done = waitpid(c->pid, NULL, WNOHANG); } while (done < 0 && errno == EINTR);
    if (done == c->pid || (done < 0 && errno == ECHILD)) { c->pid = -1; return true; }
    return false;
}
bool app_ui_stop(struct app_ui_child *c)
{
    if (c->pid <= 1) return true;
    enum platform_process_wait_result rc = app_ui_wait(c, c->token ? 0 : 2000, NULL);
    if (rc == PLATFORM_PROCESS_WAIT_EXITED) return true;
    if (rc != PLATFORM_PROCESS_WAIT_RUNNING) return app_ui_reaped_identity_failure(c);
    const int signals[] = {SIGTERM, SIGKILL};
    for (size_t i = 0; i < 2; ++i) {
        if (!ru_matches(c)) return app_ui_reaped_identity_failure(c);
        if (kill(c->pid, signals[i]) != 0 && errno != ESRCH) return false;
        rc = app_ui_wait(c, 2000, NULL);
        if (rc == PLATFORM_PROCESS_WAIT_EXITED) return true;
        if (rc != PLATFORM_PROCESS_WAIT_RUNNING) return app_ui_reaped_identity_failure(c);
    }
    return false;
}
bool app_ui_image_live(struct app_ui_child *c)
{
    char exe[APP_LAUNCH_PATH_MAX]; uint64_t token = 0;
    return app_proc_identity(c->pid, exe, &token) && token == c->token && !strcmp(exe, c->image);
}

bool app_ui_drive(const char *driver, const char *title, const char *action,
                  const char *log_path, bool pixels, bool replaced, unsigned timeout_ms)
{
    char option[160], timeout[40];
    int n = snprintf(option, sizeof(option), "--title=%s", title);
    int t = snprintf(timeout, sizeof(timeout), "--timeout-ms=%u", timeout_ms);
    if (n <= 0 || (size_t)n >= sizeof(option) || t <= 0 || (size_t)t >= sizeof(timeout) ||
        timeout_ms > 30000) return false;
    int log = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (log < 0) return false;
    const char *argv[] = {driver, option, action, timeout,
                          pixels ? "--expect-pixels-change" : replaced ? "--expect-window-replaced" : NULL, NULL};
    struct app_ui_child child = {.pid = -1};
    bool ok = app_ui_spawn(&child, argv, log, log, log);
    (void)close(log);
    uint32_t code = UINT32_MAX;
    if (ok) ok = app_ui_wait(&child, timeout_ms + 2000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    bool stopped = app_ui_stop(&child);
    return ok && stopped;
}
#endif
