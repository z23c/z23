/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify owner-private development state roots. */
#include "platform/private_directory.h"
#include "platform/state_root.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *message)
{
    fprintf(stderr, "state_root_acceptance: %s\n", message);
    return 1;
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>

static bool runtime_is_wine(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

int main(void)
{
    wchar_t temp[MAX_PATH], spoof[MAX_PATH], permissive[MAX_PATH];
    wchar_t target[MAX_PATH], link[MAX_PATH], unicode[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(spoof, MAX_PATH, L"%lsfalso-δ-中-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        swprintf(permissive, MAX_PATH, L"%lspermissive", spoof) <= 0 ||
        swprintf(target, MAX_PATH, L"%lstarget", spoof) <= 0 ||
        swprintf(link, MAX_PATH, L"%lslink", spoof) <= 0 ||
        swprintf(unicode, MAX_PATH, L"%lsprivado-δ-中", spoof) <= 0 ||
        !CreateDirectoryW(spoof, NULL))
        return fail("fixture creation failed");
    char spoof_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, spoof, -1,
                             spoof_utf8, sizeof(spoof_utf8), NULL, NULL) ||
        !SetEnvironmentVariableA("LOCALAPPDATA", spoof_utf8))
        return fail("spoof environment setup failed");

    PWSTR known = NULL;
    char expected[32768], actual[32768];
    if (FAILED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT,
                                    NULL, &known)) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, known, -1,
                             expected, sizeof(expected), NULL, NULL)) {
        if (known) CoTaskMemFree(known);
        return fail("Known Folder lookup failed");
    }
    CoTaskMemFree(known);
    if (!platform_state_root(actual, sizeof(actual)) ||
        strncmp(actual, expected, strlen(expected)) != 0 ||
        strstr(actual, spoof_utf8) != NULL || strlen(actual) < strlen("/z23/dev") ||
        strcmp(actual + strlen(actual) - strlen("/z23/dev"), "/z23/dev") != 0) {
        if (runtime_is_wine()) {
            fputs("state_root_acceptance: REFUSE: Wine cannot prove Known "
                  "Folder independence from LOCALAPPDATA\n", stderr);
            return 77;
        }
        return fail("LOCALAPPDATA spoof influenced authority root");
    }
    uintptr_t retained = 0;
    if (!platform_private_directory_open_validated(actual, &retained))
        return fail("state root is not protected current-SID/private/no-reparse");
    platform_private_directory_close(retained);
    char tiny[4];
    if (platform_state_root(tiny, sizeof(tiny)))
        return fail("truncated state root accepted");

    char path_utf8[MAX_PATH * 3];
    if (!CreateDirectoryW(permissive, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, permissive, -1,
                             path_utf8, sizeof(path_utf8), NULL, NULL) ||
        platform_private_directory_ensure(path_utf8))
        return fail("permissive ACL directory accepted");
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, unicode, -1,
                             path_utf8, sizeof(path_utf8), NULL, NULL) ||
        !platform_private_directory_create(path_utf8))
        return fail("Unicode private directory failed");
    if (!CreateDirectoryW(target, NULL))
        return fail("reparse target creation failed");
    DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(link, target, flags)) {
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, link, -1,
                                 path_utf8, sizeof(path_utf8), NULL, NULL) ||
            platform_private_directory_ensure(path_utf8))
            return fail("directory reparse point accepted");
        RemoveDirectoryW(link);
    }
    RemoveDirectoryW(unicode); RemoveDirectoryW(permissive);
    RemoveDirectoryW(target); RemoveDirectoryW(spoof);
    puts("state_root_acceptance: PASS");
    return 0;
}
#else
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    char fixture[] = "/tmp/z23-state-root-XXXXXX";
    char *base = mkdtemp(fixture);
    char actual[4096], expected[4096];
    if (!base || setenv("XDG_STATE_HOME", base, 1) != 0 ||
        !platform_state_root(actual, sizeof(actual)) ||
        snprintf(expected, sizeof(expected), "%s/z23/dev", base) <= 0 ||
        strcmp(actual, expected) != 0)
        return fail("XDG state policy failed");
    struct stat info;
    if (lstat(actual, &info) != 0 || !S_ISDIR(info.st_mode) ||
        (info.st_mode & 0777) != 0700 || info.st_uid != geteuid())
        return fail("XDG state root is not private");
    if (unsetenv("XDG_STATE_HOME") != 0 || setenv("HOME", base, 1) != 0)
        return fail("HOME fallback setup failed");
    char home_root[4096];
    if (!platform_state_root(home_root, sizeof(home_root)) ||
        strstr(home_root, "/.local/state/z23/dev") == NULL)
        return fail("HOME fallback policy failed");
    puts("state_root_acceptance: PASS");
    return 0;
}
#endif
