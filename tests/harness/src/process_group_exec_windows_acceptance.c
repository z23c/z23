/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive the shipped process-group-exec.exe Job Object: a killed
 *          supervisor must reap its ping child. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

static bool find_exe(char *out, size_t cap)
{
    static const char *candidates[] = {
        "build\\bin\\process-group-exec.exe",
        "build/bin/process-group-exec.exe",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        DWORD attr = GetFileAttributesA(candidates[i]);
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            if (strlen(candidates[i]) + 1 > cap) return false;
            memcpy(out, candidates[i], strlen(candidates[i]) + 1);
            return true;
        }
    }
    return false;
}

static bool process_running(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 entry = {.dwSize = sizeof(entry)};
    bool found = false;
    if (Process32First(snap, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                found = true;
                break;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

static bool ping_child_of(DWORD parent)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 entry = {.dwSize = sizeof(entry)};
    bool found = false;
    if (Process32First(snap, &entry)) {
        do {
            if (entry.th32ParentProcessID == parent &&
                _stricmp(entry.szExeFile, "ping.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

int main(void)
{
    char launcher[MAX_PATH];
    if (!find_exe(launcher, sizeof(launcher))) {
        fprintf(stderr, "process_group_exec: missing build/bin/process-group-exec.exe\n");
        return 2;
    }
    char line[32768];
    int n = snprintf(line, sizeof(line),
                     "\"%s\" ping.exe -n 40 127.0.0.1", launcher);
    if (n <= 0 || (size_t)n >= sizeof(line)) return 3;

    STARTUPINFOA startup = {.cb = sizeof(startup)};
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION proc = {0};
    if (!CreateProcessA(NULL, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &proc)) {
        fprintf(stderr, "process_group_exec: CreateProcess failed win32=%lu\n",
                (unsigned long)GetLastError());
        return 4;
    }
    CloseHandle(proc.hThread);
    Sleep(400);
    if (!process_running(proc.dwProcessId)) {
        CloseHandle(proc.hProcess);
        fprintf(stderr, "process_group_exec: supervisor exited before ping\n");
        return 5;
    }
    if (!ping_child_of(proc.dwProcessId)) {
        (void)TerminateProcess(proc.hProcess, 1);
        CloseHandle(proc.hProcess);
        fprintf(stderr, "process_group_exec: ping child not observed\n");
        return 6;
    }
    if (!TerminateProcess(proc.hProcess, 1)) {
        CloseHandle(proc.hProcess);
        return 7;
    }
    (void)WaitForSingleObject(proc.hProcess, 5000);
    CloseHandle(proc.hProcess);
    Sleep(400);
    if (ping_child_of(proc.dwProcessId) || process_running(proc.dwProcessId)) {
        fprintf(stderr, "process_group_exec: child survived supervisor kill\n");
        return 8;
    }
    printf("process_group_exec: Job Object kill-on-close reaped ping child\n");
    return 0;
}
#else
typedef int process_group_exec_windows_acceptance_not_built;
#endif
