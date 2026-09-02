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

    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE read_handle = NULL, write_handle = NULL;
    if (!CreatePipe(&read_handle, &write_handle, &security, 0) ||
        !SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0)) {
        if (read_handle) CloseHandle(read_handle);
        if (write_handle) CloseHandle(write_handle);
        return -1;
    }
    STARTUPINFOA startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write_handle;
    startup.hStdError = write_handle;
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessA(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, cwd, &startup, &process)) {
        CloseHandle(read_handle); CloseHandle(write_handle); return -1;
    }
    CloseHandle(process.hThread);
    CloseHandle(write_handle);

    size_t length = 0;
    bool exited = false;
    int64_t waited_ms = 0;
    while (waited_ms < 30000) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_handle, NULL, 0, NULL, &available, NULL))
            break;
        while (available > 0) {
            char scratch[4096];
            DWORD want = available > sizeof(scratch) ? sizeof(scratch)
                                                       : available;
            DWORD got = 0;
            if (!ReadFile(read_handle, scratch, want, &got, NULL) || got == 0)
                break;
            size_t room = length + 1 < cap ? cap - length - 1 : 0;
            size_t copy = got < room ? (size_t)got : room;
            if (copy) memcpy(out + length, scratch, copy);
            length += copy;
            if (copy != got) *truncated = true;
            available -= got;
        }
        DWORD wait = WaitForSingleObject(process.hProcess, 10);
        if (wait == WAIT_OBJECT_0) exited = true;
        else if (wait == WAIT_FAILED) break;
        if (exited && available == 0) break;
        waited_ms += 10;
    }
    if (!exited) {
        (void)TerminateProcess(process.hProcess, 124);
        (void)WaitForSingleObject(process.hProcess, INFINITE);
    }
    DWORD exit_code = 1;
    (void)GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(read_handle); CloseHandle(process.hProcess);
    out[length] = 0;
    return exited ? (int)exit_code : -1;
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
