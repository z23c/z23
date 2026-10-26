/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Run Windows build/test process trees without consoles or dialogs. */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "base/safe_alloc.h"

#define Z23_HEADLESS_ERROR_MODE \
    (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)

struct wide_buffer {
    wchar_t *data;
    size_t used;
    size_t capacity;
};

static bool append(struct wide_buffer *buffer, wchar_t value)
{
    if (buffer->used == buffer->capacity) {
        size_t next = buffer->capacity ? buffer->capacity * 2u : 256u;
        if (next < buffer->capacity || next > 32768u) return false;
        wchar_t *grown = zcl_realloc(buffer->data, next * sizeof(*grown),
                                     "win-headless widebuf");
        if (!grown) return false;
        buffer->data = grown;
        buffer->capacity = next;
    }
    buffer->data[buffer->used++] = value;
    return true;
}

static bool append_escaped_argument(struct wide_buffer *line,
                                    const wchar_t *argument, bool quote)
{
    size_t slashes = 0;
    for (const wchar_t *cursor = argument;; cursor++) {
        if (*cursor == L'\\') { slashes++; continue; }
        if (*cursor == L'\"') {
            for (size_t i = 0; i < slashes * 2u + 1u; i++)
                if (!append(line, L'\\')) return false;
            if (!append(line, L'\"')) return false;
        } else {
            if (*cursor == 0 && quote) slashes *= 2u;
            for (size_t i = 0; i < slashes; i++)
                if (!append(line, L'\\')) return false;
            if (*cursor == 0) break;
            if (!append(line, *cursor)) return false;
        }
        slashes = 0;
    }
    return true;
}

/* CommandLineToArgvW-compatible quoting, including trailing backslashes. */
static bool append_argument(struct wide_buffer *line, const wchar_t *argument)
{
    if (line->used && !append(line, L' ')) return false;
    bool quote = !argument[0] || wcspbrk(argument, L" \t\n\v\"") != NULL;
    if (quote && !append(line, L'\"')) return false;
    return append_escaped_argument(line, argument, quote) &&
           (!quote || append(line, L'\"')) && append(line, 0);
}

static wchar_t *make_command_line(int argc, wchar_t **argv, int first)
{
    struct wide_buffer line = {0};
    for (int i = first; i < argc; i++) {
        if (line.used) line.used--; /* replace previous NUL */
        if (!append_argument(&line, argv[i])) {
            free(line.data);
            return NULL;
        }
    }
    return line.data;
}

static bool absolute_path(const wchar_t *path)
{
    return path && ((path[0] && path[1] == L':' &&
                     (path[2] == L'\\' || path[2] == L'/')) ||
                    (path[0] == L'\\' && path[1] == L'\\'));
}

static int selftest_child(int argc, wchar_t **argv)
{
    BOOL in_job = FALSE;
    DWORD mode = GetErrorMode();
    wchar_t desktop[128] = {0};
    DWORD desktop_bytes = 0;
    bool private_desktop = GetUserObjectInformationW(
        GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, desktop,
        sizeof(desktop), &desktop_bytes) &&
        wcsncmp(desktop, L"z23-headless-", 13) == 0;
    bool ok = argc == 4 && wcscmp(argv[2], L"space value") == 0 &&
              wcscmp(argv[3], L"trailing\\") == 0 &&
              GetConsoleWindow() == NULL &&
              private_desktop &&
              GetPriorityClass(GetCurrentProcess()) ==
                  BELOW_NORMAL_PRIORITY_CLASS &&
              (mode & Z23_HEADLESS_ERROR_MODE) == Z23_HEADLESS_ERROR_MODE &&
              IsProcessInJob(GetCurrentProcess(), NULL, &in_job) && in_job;
    fwprintf(stdout, L"headless-selftest:%ls\n", ok ? L"ok" : L"failed");
    fwprintf(stderr, L"headless-selftest-stderr:%ls\n", ok ? L"ok" : L"failed");
    return ok ? 0 : 90;
}

static void usage(void)
{
    fwprintf(stderr, L"usage: z23-headless-run --cwd ABS --log ABS -- ABS_EXE [args...]\n");
}

static bool run_arguments_are_invalid(int argc, wchar_t **argv)
{
    return argc < 7 || wcscmp(argv[1], L"--cwd") != 0 ||
           wcscmp(argv[3], L"--log") != 0 || wcscmp(argv[5], L"--") != 0 ||
           !absolute_path(argv[2]) || !absolute_path(argv[4]) ||
           !absolute_path(argv[6]);
}

static HDESK create_headless_desktop(wchar_t *desktop_name, size_t capacity)
{
    int desktop_length = swprintf(
        desktop_name, capacity,
        L"z23-headless-%lu-%llu", (unsigned long)GetCurrentProcessId(),
        (unsigned long long)GetTickCount64());
    return desktop_length > 0 && (size_t)desktop_length < capacity
        ? CreateDesktopW(desktop_name, NULL, NULL, 0, GENERIC_ALL, NULL)
        : NULL;
}

static bool setup_startup_attributes(STARTUPINFOEXW *startup,
                                     SIZE_T *attribute_size,
                                     HANDLE *inherited, size_t inherited_bytes,
                                     bool *list_initialized)
{
    startup->lpAttributeList = zcl_malloc(*attribute_size,
                                          "win-headless attrlist");
    *list_initialized = startup->lpAttributeList &&
        InitializeProcThreadAttributeList(startup->lpAttributeList, 1, 0,
                                          attribute_size);
    return *list_initialized &&
        UpdateProcThreadAttribute(startup->lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, inherited_bytes,
            NULL, NULL);
}

static bool run_child_in_job(HANDLE job, PROCESS_INFORMATION process,
                             bool started, DWORD *exit_code)
{
    bool assigned = started &&
        AssignProcessToJobObject(job, process.hProcess);
    bool resumed = assigned && ResumeThread(process.hThread) != (DWORD)-1;
    if (started && !resumed) TerminateProcess(process.hProcess, 125);
    if (resumed &&
        WaitForSingleObject(process.hProcess, INFINITE) == WAIT_OBJECT_0)
        (void)GetExitCodeProcess(process.hProcess, exit_code);
    return resumed;
}

static void release_run_resources(bool started, PROCESS_INFORMATION process,
                                  HANDLE job, HDESK desktop,
                                  LPPROC_THREAD_ATTRIBUTE_LIST attributes,
                                  bool list_initialized)
{
    if (started) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if (job) CloseHandle(job);
    if (desktop) CloseDesktop(desktop);
    if (attributes) {
        if (list_initialized)
            DeleteProcThreadAttributeList(attributes);
        free(attributes);
    }
}

int wmain(int argc, wchar_t **argv)
{
    if (argc > 1 && wcscmp(argv[1], L"--selftest-child") == 0)
        return selftest_child(argc, argv);
    if (run_arguments_are_invalid(argc, argv)) {
        usage();
        return 64;
    }

    (void)SetErrorMode(GetErrorMode() | Z23_HEADLESS_ERROR_MODE);
    DWORD previous_thread_mode = 0;
    if (!SetThreadErrorMode(Z23_HEADLESS_ERROR_MODE, &previous_thread_mode))
        return 65;
    wchar_t *line = make_command_line(argc, argv, 6);
    if (!line) return 65;

    SECURITY_ATTRIBUTES inheritable = {
        .nLength = sizeof(inheritable), .bInheritHandle = TRUE};
    HANDLE log = CreateFileW(argv[4], GENERIC_WRITE, FILE_SHARE_READ,
                             &inheritable, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &inheritable, OPEN_EXISTING, 0, NULL);
    if (log == INVALID_HANDLE_VALUE || input == INVALID_HANDLE_VALUE) {
        if (log != INVALID_HANDLE_VALUE) CloseHandle(log);
        if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
        free(line);
        return 66;
    }
    HANDLE inherited[] = {input, log};
    SIZE_T attribute_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = log;
    startup.StartupInfo.hStdError = log;
    wchar_t desktop_name[96];
    HDESK desktop = create_headless_desktop(
        desktop_name, sizeof(desktop_name) / sizeof(desktop_name[0]));
    startup.StartupInfo.lpDesktop = desktop_name;
    bool list_initialized = false;
    bool attributes_ok = setup_startup_attributes(
        &startup, &attribute_size, inherited, sizeof(inherited),
        &list_initialized);
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PRIORITY_CLASS;
    limits.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
    bool job_ok = job && SetInformationJobObject(
        job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    PROCESS_INFORMATION process = {0};
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                  BELOW_NORMAL_PRIORITY_CLASS |
                  CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
    bool started = attributes_ok && job_ok && desktop && CreateProcessW(
        argv[6], line, NULL, NULL, TRUE, flags, NULL, argv[2],
        &startup.StartupInfo, &process);
    (void)SetThreadErrorMode(previous_thread_mode, NULL);
    DWORD exit_code = 125;
    bool resumed = run_child_in_job(job, process, started, &exit_code);
    release_run_resources(started, process, job, desktop,
                          startup.lpAttributeList, list_initialized);
    CloseHandle(input);
    FlushFileBuffers(log);
    CloseHandle(log);
    free(line);
    return resumed ? (int)exit_code : 67;
}
