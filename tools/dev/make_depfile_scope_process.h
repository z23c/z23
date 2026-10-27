/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Exact-argv child launch, log capture and owned-child cleanup for the depfile fixture.
 */
#ifndef Z23_MAKE_DEPFILE_SCOPE_PROCESS_H
#define Z23_MAKE_DEPFILE_SCOPE_PROCESS_H
#include <fcntl.h>
#include <signal.h>
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#include <stdint.h>
#include <windows.h>
#else
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;
#endif

static void fail(const char *message);
static volatile sig_atomic_t probe_signal;
#ifdef _WIN32
static intptr_t probe_children[32];
#else
static pid_t probe_children[32];
#endif
static size_t probe_count;

static void probe_interrupted(int number)
{
    probe_signal = number;
}

static void probe_cleanup(void)
{
    for (size_t i = 0; i < probe_count; ++i) {
        if (!probe_children[i]) continue;
#ifdef _WIN32
        (void)TerminateProcess((HANDLE)probe_children[i], 1);
        int status;
        (void)_cwait(&status, probe_children[i], 0);
#else
        (void)kill(probe_children[i], SIGKILL);
        while (waitpid(probe_children[i], NULL, 0) < 0 && errno == EINTR) {}
#endif
        probe_children[i] = 0;
    }
}

static void probe_install_cleanup(void)
{
    if (atexit(probe_cleanup) != 0) fail("cannot register child cleanup");
#ifdef _WIN32
    if (signal(SIGINT, probe_interrupted) == SIG_ERR ||
        signal(SIGTERM, probe_interrupted) == SIG_ERR)
        fail("cannot install interruption handler");
#else
    struct sigaction action = {0};
    action.sa_handler = probe_interrupted;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0)
        fail("cannot install interruption handler");
#endif
}

#ifdef _WIN32
/* CRT spawn joins argv without quoting. Match process_group_exec.c's
 * backslash/quote rules so spaces and literal quotes retain their bytes. */
static char *probe_quote(const char *arg)
{
    size_t length = strlen(arg);
    if (length > 16380) fail("Windows fixture argument too long");
    /* Standalone fixture: no node allocator/logging linkage; bounded and freed after spawn. */
    char *quoted = malloc(length * 2 + 3); // raw-alloc-ok:standalone-test-fixture
    if (!quoted) fail("Windows argv allocation failed");
    size_t n = 0, slashes = 0;
    quoted[n++] = '"';
    for (const char *p = arg;; ++p) {
        if (*p == '\\') {++slashes; continue;}
        size_t emit = (*p == '"' || !*p) ? slashes * 2 : slashes;
        for (size_t j = 0; j < emit; ++j) quoted[n++] = '\\';
        slashes = 0;
        if (!*p) break;
        if (*p == '"') quoted[n++] = '\\';
        quoted[n++] = *p;
    }
    quoted[n++] = '"';
    quoted[n] = 0;
    return quoted;
}

static bool probe_restore(int saved, int target)
{
    if (saved < 0) return true;
    bool ok = _dup2(saved, target) == 0;
    _close(saved);
    return ok;
}

static intptr_t probe_windows_start(size_t index, const char *const argv[], const char *log, bool quiet_error)
{
    const char *quoted[64] = {0};
    size_t count = 0;
    while (argv[count]) {
        if (count == 63) fail("too many Windows fixture arguments");
        quoted[count] = probe_quote(argv[count]);
        ++count;
    }
    int saved_out = _dup(1), saved_err = _dup(2);
    int out = _open(log, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
    int err = quiet_error ? _open("NUL", _O_WRONLY | _O_BINARY) : -1;
    intptr_t child = -1;
    bool redirected = saved_out >= 0 && saved_err >= 0 && out >= 0 && (!quiet_error || err >= 0);
    if (redirected) redirected = _dup2(out, 1) == 0 && _dup2(quiet_error ? err : out, 2) == 0;
    if (redirected) child = _spawnvp(_P_NOWAIT, argv[0], quoted);
    bool restored_out = probe_restore(saved_out, 1);
    bool restored_err = probe_restore(saved_err, 2);
    if (out >= 0) _close(out);
    if (err >= 0) _close(err);
    for (size_t i = 0; i < count; ++i) free((void *)quoted[i]);
    if (child != -1) probe_children[index] = child;
    if (!restored_out || !restored_err) fail("cannot restore fixture output descriptors");
    if (child == -1) fail("cannot spawn Make probe");
    return child;
}
#else
static pid_t probe_posix_start(const char *const argv[], const char *log, bool quiet_error)
{
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) fail("cannot initialize spawn actions");
    int rc = posix_spawn_file_actions_addopen(&actions, 1, log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!rc) rc = quiet_error ?
        posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0) :
        posix_spawn_file_actions_adddup2(&actions, 1, 2);
    pid_t child = 0;
    if (!rc) rc = posix_spawnp(&child, argv[0], &actions, NULL, (char *const *)argv, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) fail("cannot spawn Make probe");
    return child;
}
#endif

static size_t probe_start(const char *const argv[], const char *log, bool quiet_error)
{
    if (probe_signal) fail("fixture interrupted");
    if (probe_count == 32) fail("too many fixture children");
    size_t index = probe_count++;
#ifdef _WIN32
    probe_children[index] = probe_windows_start(index, argv, log, quiet_error);
#else
    probe_children[index] = probe_posix_start(argv, log, quiet_error);
#endif
    return index;
}

static int probe_wait(size_t index)
{
    if (probe_signal) fail("fixture interrupted");
#ifdef _WIN32
    DWORD result;
    while ((result = WaitForSingleObject((HANDLE)probe_children[index], 100)) == WAIT_TIMEOUT)
        if (probe_signal) fail("fixture interrupted");
    if (result != WAIT_OBJECT_0) fail("Make probe wait failed");
    int status = 0;
    if (_cwait(&status, probe_children[index], 0) == -1) fail("Make probe reap failed");
    probe_children[index] = 0;
    return status;
#else
    int status;
    for (;;) {
        if (probe_signal) fail("fixture interrupted");
        pid_t result = waitpid(probe_children[index], &status, WNOHANG);
        if (result == probe_children[index]) {
            probe_children[index] = 0;
            if (probe_signal) fail("fixture interrupted");
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        }
        if (result < 0 && errno != EINTR) fail("Make probe reap failed");
        /* A signal immediately before this sleep delays cancellation by at
         * most one slice; it cannot race into a blocking child wait. */
        const struct timespec slice = {0, 100000000};
        if (nanosleep(&slice, NULL) != 0 && errno != EINTR)
            fail("Make probe wait sleep failed");
    }
#endif
}
#endif
