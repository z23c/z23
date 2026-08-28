/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify Windows codeindex build surfaces refuse without I/O. */
#if defined(_WIN32)

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool unexpected_enum(const char *path, const struct stat *st, void *ctx)
{
    (void)path;
    (void)st;
    *(bool *)ctx = true;
    return true;
}

int main(void)
{
    wchar_t temp[MAX_PATH], dir[MAX_PATH], marker[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(dir, MAX_PATH, L"%lsz23-codeindex-refuse-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(dir, NULL))
        return 1;
    (void)swprintf(marker, MAX_PATH, L"%ls\\sentinel", dir);
    const char expected[] = "unchanged";
    DWORD amount = 0;
    HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, expected, sizeof(expected), &amount, NULL) ||
        amount != sizeof(expected) || !CloseHandle(file))
        return 1;
    uint8_t exact[32], stat_root[32], before_exact[32], before_stat[32];
    memset(exact, 0xa5, sizeof(exact));
    memset(stat_root, 0x5a, sizeof(stat_root));
    memcpy(before_exact, exact, sizeof(exact));
    memcpy(before_stat, stat_root, sizeof(stat_root));
    bool callback_ran = false;
    bool refused = !codeindex_rebuild(NULL) &&
                   !ci_codeindex_refresh(NULL) &&
                   !ci_enumerate_sources("must-not-open", unexpected_enum,
                                         &callback_ran) &&
                   !ci_source_roots_sha3("must-not-open", exact, stat_root) &&
                   !callback_ran &&
                   memcmp(exact, before_exact, sizeof(exact)) == 0 &&
                   memcmp(stat_root, before_stat, sizeof(stat_root)) == 0 &&
                   ci_path_is_registry("x.def");
    char actual[sizeof(expected)] = {0};
    file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    amount = 0;
    bool unchanged = file != INVALID_HANDLE_VALUE &&
                     ReadFile(file, actual, sizeof(actual), &amount, NULL) &&
                     amount == sizeof(actual) &&
                     memcmp(actual, expected, sizeof(expected)) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    DeleteFileW(marker);
    RemoveDirectoryW(dir);
    if (!refused || !unchanged) return 1;
    puts("codeindex_build_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int codeindex_build_refusal_acceptance_not_built;
#endif
