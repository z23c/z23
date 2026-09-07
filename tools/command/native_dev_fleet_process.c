/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded shell-free Git capture for the local fleet inventory. */

#include "util/spawn.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static size_t fleet_quote_arg(char *out, size_t cap, const char *arg)
{
    size_t used = 0, slashes = 0;
    bool quote = !arg[0] || strpbrk(arg, " \t\n\v\"") != NULL;
    if (quote && used + 1 < cap) out[used++] = '"';
    for (const char *p = arg;; p++) {
        if (*p == '\\') { slashes++; continue; }
        if (*p == '"') {
            for (size_t i = 0; i < slashes * 2u + 1u && used + 1 < cap; i++)
                out[used++] = '\\';
            if (used + 1 < cap) out[used++] = '"';
        } else {
            if (*p == 0 && quote) slashes *= 2u;
            for (size_t i = 0; i < slashes && used + 1 < cap; i++)
                out[used++] = '\\';
            if (*p == 0) break;
            if (used + 1 < cap) out[used++] = *p;
        }
        slashes = 0;
    }
    if (quote && used + 1 < cap) out[used++] = '"';
    if (cap) out[used < cap ? used : cap - 1] = 0;
    return used;
}

/* Create the redirected-stdout/stderr pipe and spawn command in cwd. On
 * success *out_read owns the read end (caller closes it) and *out_process
 * is filled in (caller closes hProcess; hThread and the write end are
 * already closed here). */
static bool fleet_capture_windows_spawn(const char *cwd, char *command,
                                        HANDLE *out_read,
                                        PROCESS_INFORMATION *out_process)
{
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE read_handle = NULL, write_handle = NULL;
    if (!CreatePipe(&read_handle, &write_handle, &security, 0) ||
        !SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0)) {
        if (read_handle) CloseHandle(read_handle);
        if (write_handle) CloseHandle(write_handle);
        return false;
    }
    STARTUPINFOA startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write_handle;
    startup.hStdError = write_handle;
    if (!CreateProcessA(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, cwd, &startup, out_process)) {
        CloseHandle(read_handle);
        CloseHandle(write_handle);
        return false;
    }
    CloseHandle(out_process->hThread);
    CloseHandle(write_handle);
    *out_read = read_handle;
    return true;
}

/* Drain everything currently buffered in the pipe into out[*length..],
 * honoring cap and setting *truncated once bytes had to be dropped.
 * Returns false on a hard pipe read failure. */
static bool fleet_capture_windows_drain(HANDLE read_handle, char *out,
                                        size_t cap, size_t *length,
                                        bool *truncated)
{
    DWORD available = 0;
    if (!PeekNamedPipe(read_handle, NULL, 0, NULL, &available, NULL) &&
        GetLastError() != ERROR_BROKEN_PIPE)
        return false;
    while (available > 0) {
        char scratch[4096];
        DWORD want =
            available > sizeof(scratch) ? sizeof(scratch) : available;
        DWORD got = 0;
        if (!ReadFile(read_handle, scratch, want, &got, NULL) || got == 0)
            return false;
        size_t room = *length + 1 < cap ? cap - *length - 1 : 0;
        size_t copy = got < room ? (size_t)got : room;
        if (copy) memcpy(out + *length, scratch, copy);
        *length += copy;
        if (copy != got) *truncated = true;
        available -= got;
    }
    return true;
}

struct fleet_capture_windows_wait_result {
    bool exited;
    bool capture_failed;
};

/* Poll for exit and drain the pipe until the child exits or 30s elapse.
 * Observing exit BEFORE peeking matters: a child can write its entire
 * answer and exit during the wait, and a pre-wait empty pipe says nothing
 * about those final bytes, so once exit is observed one final drain runs. */
static struct fleet_capture_windows_wait_result
fleet_capture_windows_wait_and_drain(HANDLE read_handle,
                                     PROCESS_INFORMATION *process, char *out,
                                     size_t cap, bool *truncated,
                                     size_t *out_length)
{
    struct fleet_capture_windows_wait_result r = {0};
    size_t length = 0;
    ULONGLONG started = GetTickCount64();
    while (GetTickCount64() - started < 30000) {
        DWORD wait = WaitForSingleObject(process->hProcess, 10);
        if (wait == WAIT_OBJECT_0) r.exited = true;
        else if (wait != WAIT_TIMEOUT) {
            r.capture_failed = true;
            break;
        }
        if (!fleet_capture_windows_drain(read_handle, out, cap, &length,
                                         truncated)) {
            r.capture_failed = true;
            break;
        }
        if (r.capture_failed || r.exited) break;
    }
    if (!r.exited) {
        (void)TerminateProcess(process->hProcess, 124);
        (void)WaitForSingleObject(process->hProcess, INFINITE);
    }
    *out_length = length;
    return r;
}

static int fleet_capture_windows(const char *cwd, const char *const argv[],
                                 char *out, size_t cap, bool *truncated)
{
    char command[32768];
    size_t used = 0;
    command[0] = 0;
    for (size_t i = 0; argv[i]; i++) {
        if (i && used + 1 < sizeof(command)) command[used++] = ' ';
        size_t wrote = fleet_quote_arg(command + used,
                                       sizeof(command) - used, argv[i]);
        if (wrote + used + 1 >= sizeof(command)) return -1;
        used += wrote;
    }

    HANDLE read_handle = NULL;
    PROCESS_INFORMATION process = {0};
    if (!fleet_capture_windows_spawn(cwd, command, &read_handle, &process))
        return -1;

    size_t length = 0;
    struct fleet_capture_windows_wait_result waited =
        fleet_capture_windows_wait_and_drain(read_handle, &process, out, cap,
                                             truncated, &length);
    DWORD exit_code = 1;
    if (!GetExitCodeProcess(process.hProcess, &exit_code))
        waited.capture_failed = true;
    CloseHandle(read_handle);
    CloseHandle(process.hProcess);
    out[length] = 0;
    if (!waited.exited || waited.capture_failed) {
        fprintf(stderr, "dev.fleet: Git output capture failed or timed out\n");
        return -1;
    }
    return (int)exit_code;
}
#endif

int zcl_dev_fleet_git_capture(const char *cwd, const char *const args[],
                              char *out, size_t cap, bool *truncated)
{
    if (!cwd || !args || !args[0] || !out || cap < 2 || !truncated)
        return -1;
    *truncated = false;
    out[0] = 0;
    const char *argv[20] = {"git", "-c", "core.quotePath=false", "-C", cwd};
    size_t n = 5;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0])) return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
#if defined(_WIN32)
    return fleet_capture_windows(cwd, argv, out, cap, truncated);
#else
    int rc = zcl_spawn_capture(argv, out, cap, 30000);
    if (strlen(out) + 1 == cap) *truncated = true;
    return rc;
#endif
}
