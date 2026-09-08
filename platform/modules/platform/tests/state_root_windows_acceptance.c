/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify owner-private development state roots. */
#include "platform/private_directory.h"
#include "platform/state_root.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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

static bool existing_root_missing_is_read_only(const char *actual,
                                                const wchar_t *dev)
{
    char existing[32768], recreated[32768];
    return platform_state_root_existing(existing, sizeof(existing)) &&
           strcmp(existing, actual) == 0 && RemoveDirectoryW(dev) &&
           !platform_state_root_existing(existing, sizeof(existing)) &&
           GetFileAttributesW(dev) == INVALID_FILE_ATTRIBUTES &&
           platform_state_root(recreated, sizeof(recreated));
}

static bool unsafe_root_is_not_repaired(
    const wchar_t *permissive, const wchar_t *base,
    wchar_t unsafe_z23[MAX_PATH], wchar_t unsafe_dev[MAX_PATH])
{
    char path[3 * MAX_PATH], unsafe_z23_utf8[3 * MAX_PATH], actual[32768];
    return swprintf(unsafe_z23, MAX_PATH, L"%ls\\z23", permissive) > 0 &&
           swprintf(unsafe_dev, MAX_PATH, L"%ls\\dev", unsafe_z23) > 0 &&
           CreateDirectoryW(permissive, NULL) &&
           CreateDirectoryW(unsafe_z23, NULL) &&
           CreateDirectoryW(unsafe_dev, NULL) &&
           WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, permissive, -1,
                               path, sizeof(path), NULL, NULL) &&
           WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, unsafe_z23, -1,
                               unsafe_z23_utf8, sizeof(unsafe_z23_utf8), NULL,
                               NULL) &&
           SetEnvironmentVariableW(L"ZCL_STATE_ROOT", permissive) &&
           !platform_state_root_existing(actual, sizeof(actual)) &&
           !platform_private_directory_ensure(unsafe_z23_utf8) &&
           SetEnvironmentVariableW(L"ZCL_STATE_ROOT", base);
}

static bool state_root_read_only_cases(
    const char *actual, const wchar_t *dev, const wchar_t *permissive,
    const wchar_t *base, wchar_t unsafe_z23[MAX_PATH],
    wchar_t unsafe_dev[MAX_PATH])
{
    char tiny[4];
    return !platform_state_root(tiny, sizeof(tiny)) &&
           existing_root_missing_is_read_only(actual, dev) &&
           unsafe_root_is_not_repaired(permissive, base, unsafe_z23,
                                       unsafe_dev);
}

int main(void)
{
    wchar_t temp[MAX_PATH], base[MAX_PATH], spoof[MAX_PATH], permissive[MAX_PATH];
    wchar_t target[MAX_PATH], link[MAX_PATH], unicode[MAX_PATH];
    wchar_t z23[MAX_PATH], dev[MAX_PATH];
    /* Use the current working directory for fixtures.  MSYS2/Cygwin /tmp is
     * mounted noacl, so owner/ACL probes on a path under it fail even though
     * the directory was created by this process.  The working directory is on
     * normal NTFS and exercises the real authority logic. */
    DWORD cwd_len = GetCurrentDirectoryW(MAX_PATH, temp);
    if (cwd_len == 0 || cwd_len >= MAX_PATH)
        return fail("could not get current directory");
    if (temp[cwd_len - 1] != L'\\' && temp[cwd_len - 1] != L'/')
        wcscat(temp, L"\\");
    if (swprintf(base, MAX_PATH, L"%lsz23-state-base-δ-中-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        swprintf(spoof, MAX_PATH, L"%lsfalso-δ-中-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        swprintf(permissive, MAX_PATH, L"%lspermissive", spoof) <= 0 ||
        swprintf(target, MAX_PATH, L"%lstarget", spoof) <= 0 ||
        swprintf(link, MAX_PATH, L"%lslink", spoof) <= 0 ||
        swprintf(unicode, MAX_PATH, L"%lsprivado-δ-中", spoof) <= 0 ||
        swprintf(z23, MAX_PATH, L"%ls\\z23", base) <= 0 ||
        swprintf(dev, MAX_PATH, L"%ls\\dev", z23) <= 0 ||
        !CreateDirectoryW(base, NULL) || !CreateDirectoryW(z23, NULL) ||
        /* Leave dev for platform_state_root to create/repair; that matches
         * real first-boot and avoids an inherited-ACL edge case on Windows. */
        !CreateDirectoryW(spoof, NULL))
        return fail("fixture creation failed");
    char base_utf8[MAX_PATH * 3], spoof_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, base, -1,
                             base_utf8, sizeof(base_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, spoof, -1,
                             spoof_utf8, sizeof(spoof_utf8), NULL, NULL) ||
        !SetEnvironmentVariableW(L"ZCL_STATE_ROOT", base) ||
        !SetEnvironmentVariableA("LOCALAPPDATA", spoof_utf8))
        return fail("environment setup failed");

    char expected[32768], actual[32768];
    if (snprintf(expected, sizeof(expected), "%s", base_utf8) <= 0)
        return fail("expected path construction failed");
    if (!platform_state_root(actual, sizeof(actual)) ||
        strncmp(actual, expected, strlen(expected)) != 0 ||
        strstr(actual, spoof_utf8) != NULL ||
        strlen(actual) < strlen("/z23/dev") ||
        strcmp(actual + strlen(actual) - strlen("/z23/dev"), "/z23/dev") != 0) {
        if (runtime_is_wine()) {
            fputs("state_root_acceptance: REFUSE: Wine cannot prove state-root "
                  "independence from LOCALAPPDATA\n", stderr);
            return 77;
        }
        return fail("LOCALAPPDATA spoof influenced authority root");
    }
    uintptr_t retained = 0;
    if (!platform_private_directory_open_validated(actual, &retained))
        return fail("state root is not protected current-SID/private/no-reparse");
    platform_private_directory_close(retained);
    char path_utf8[MAX_PATH * 3];
    wchar_t unsafe_z23[MAX_PATH], unsafe_dev[MAX_PATH];
    if (!state_root_read_only_cases(actual, dev, permissive, base, unsafe_z23,
                                    unsafe_dev))
        return fail("state root read-only cases failed");
    if (
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
    RemoveDirectoryW(unicode); RemoveDirectoryW(unsafe_dev);
    RemoveDirectoryW(unsafe_z23); RemoveDirectoryW(permissive);
    RemoveDirectoryW(target); RemoveDirectoryW(spoof);
    if (!RemoveDirectoryW(dev) || !RemoveDirectoryW(z23) ||
        !RemoveDirectoryW(base))
        return fail("state-root fixture cleanup failed");
    puts("state_root_acceptance: PASS");
    return 0;
}
#else
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static bool existing_root_modes_are_read_only(char actual[4096])
{
    char existing[4096];
    struct stat info;
    return platform_state_root_existing(existing, sizeof(existing)) &&
           strcmp(existing, actual) == 0 && rmdir(actual) == 0 &&
           !platform_state_root_existing(existing, sizeof(existing)) &&
           lstat(actual, &info) != 0 && errno == ENOENT &&
           platform_state_root(actual, 4096) && chmod(actual, 0755) == 0 &&
           !platform_state_root_existing(existing, sizeof(existing)) &&
           lstat(actual, &info) == 0 && (info.st_mode & 0777) == 0755 &&
           chmod(actual, 0700) == 0;
}

static bool existing_root_refuses_symlink_parent(const char *base)
{
    char target[4096], link[4096], target_root[4096], target_z23[4096];
    char existing[4096];
    return snprintf(target, sizeof(target), "%s/real-state", base) > 0 &&
           snprintf(link, sizeof(link), "%s/linked-state", base) > 0 &&
           mkdir(target, 0700) == 0 &&
           setenv("XDG_STATE_HOME", target, 1) == 0 &&
           platform_state_root(target_root, sizeof(target_root)) &&
           symlink(target, link) == 0 &&
           setenv("XDG_STATE_HOME", link, 1) == 0 &&
           !platform_state_root_existing(existing, sizeof(existing)) &&
           snprintf(target_z23, sizeof(target_z23), "%s/z23", target) > 0 &&
           unlink(link) == 0 && rmdir(target_root) == 0 &&
           rmdir(target_z23) == 0 && rmdir(target) == 0;
}

static bool state_root_read_only_cases(char actual[4096], const char *base)
{
    return existing_root_modes_are_read_only(actual) &&
           existing_root_refuses_symlink_parent(base);
}

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
    if (!state_root_read_only_cases(actual, base))
        return fail("existing XDG state root read-only cases failed");
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
