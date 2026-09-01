/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native Windows acceptance for atomic replacement across UTF-8, spaces,
 * forward-slash caller paths, locked destinations, and paths beyond MAX_PATH. */

#include "platform/path_replace.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static wchar_t g_path[32768];
static wchar_t g_extended[32768];
static char g_staged_utf8[131072];
static char g_destination_utf8[131072];

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s (errno=%d win32=%lu)\n", message, errno,
            (unsigned long)GetLastError());
    return 1;
}

static bool extended_path(const wchar_t *path)
{
    int n = swprintf(g_extended, 32768, L"\\\\?\\%ls", path);
    return n > 0 && n < 32768;
}

static bool write_payload(const wchar_t *path, const char *payload)
{
    if (!extended_path(path)) return false;
    HANDLE file = CreateFileW(g_extended, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    DWORD size = (DWORD)strlen(payload);
    bool ok = file != INVALID_HANDLE_VALUE &&
              WriteFile(file, payload, size, &written, NULL) &&
              written == size && FlushFileBuffers(file);
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file)) ok = false;
    return ok;
}

static bool destination_is(const wchar_t *path, const char *expected)
{
    if (!extended_path(path)) return false;
    HANDLE file = CreateFileW(g_extended, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    char actual[64] = {0};
    DWORD read_bytes = 0;
    bool ok = file != INVALID_HANDLE_VALUE &&
              ReadFile(file, actual, sizeof(actual) - 1, &read_bytes, NULL);
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file)) ok = false;
    return ok && read_bytes == strlen(expected) &&
           memcmp(actual, expected, read_bytes) == 0;
}

static bool path_to_utf8_forward(const wchar_t *wide, char *out,
                                 size_t out_size)
{
    if (out_size > INT_MAX) return false;
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, out,
                                (int)out_size, NULL, NULL);
    if (n <= 0) return false;
    for (int i = 0; i < n - 1; ++i)
        if (out[i] == '\\') out[i] = '/';
    return true;
}

int main(void)
{
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp)) return fail("temporary path");
    int n = swprintf(g_path, 32768, L"%lsz23 replace \x00e9 %lu", temp,
                     (unsigned long)GetCurrentProcessId());
    if (n <= 0 || n >= 32768 || !CreateDirectoryW(g_path, NULL))
        return fail("UTF-8 spaced root");

    /* Keep every component below NTFS's component limit while taking the
     * complete path beyond the legacy MAX_PATH boundary. */
    for (unsigned int i = 0; i < 9; ++i) {
        size_t used = wcslen(g_path);
        n = swprintf(g_path + used, 32768 - used,
                     L"\\segment-%02u-abcdefghijklmnopqr", i);
        if (n <= 0 || !extended_path(g_path) ||
            !CreateDirectoryW(g_extended, NULL))
            return fail("long-path directory");
    }
    if (wcslen(g_path) <= MAX_PATH) return fail("fixture exceeds MAX_PATH");

    wchar_t staged[32768], destination[32768];
    n = swprintf(staged, 32768, L"%ls\\staged.tmp", g_path);
    int dn = swprintf(destination, 32768, L"%ls\\destination.bin", g_path);
    if (n <= 0 || dn <= 0 || !write_payload(staged, "new-state") ||
        !write_payload(destination, "old-state"))
        return fail("fixture files");
    if (!path_to_utf8_forward(staged, g_staged_utf8,
                              sizeof(g_staged_utf8)) ||
        !path_to_utf8_forward(destination, g_destination_utf8,
                              sizeof(g_destination_utf8)))
        return fail("UTF-8 conversion");

    if (!extended_path(destination)) return fail("destination path");
    HANDLE lock = CreateFileW(g_extended, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (lock == INVALID_HANDLE_VALUE) return fail("destination lock");
    errno = 0;
    if (platform_path_replace(g_staged_utf8, g_destination_utf8) == 0 ||
        (errno != EBUSY && errno != EACCES) ||
        !destination_is(destination, "old-state")) {
        CloseHandle(lock);
        return fail("locked destination refusal");
    }
    if (!CloseHandle(lock)) return fail("unlock destination");

    if (platform_path_replace(g_staged_utf8, g_destination_utf8) != 0 ||
        !destination_is(destination, "new-state"))
        return fail("atomic replacement");
    if (!extended_path(staged) ||
        GetFileAttributesW(g_extended) != INVALID_FILE_ATTRIBUTES)
        return fail("staging path consumed");

    if (!extended_path(destination) || !DeleteFileW(g_extended))
        return fail("file cleanup");
    for (unsigned int i = 0; i < 9; ++i) {
        if (!extended_path(g_path) || !RemoveDirectoryW(g_extended))
            return fail("long-path cleanup");
        wchar_t *slash = wcsrchr(g_path, L'\\');
        if (!slash) return fail("cleanup traversal");
        *slash = L'\0';
    }
    if (!RemoveDirectoryW(g_path)) return fail("root cleanup");

    puts("path_replace_windows_acceptance: PASS");
    return 0;
}
