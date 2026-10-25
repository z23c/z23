/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify Windows ROM admission refuses without registration. */
#if defined(_WIN32)

#include "config/rom_bundle_admission.h"
#include "net/rom_seed.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool create_isolated_dir(wchar_t *dir)
{
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(dir, MAX_PATH, L"%lsz23-rom-admit-refuse-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(dir, NULL))
        return false;
    return true;
}

static bool write_sentinel(const wchar_t *marker, const char *expected,
                           size_t expected_size)
{
    DWORD amount = 0;
    HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, expected, expected_size, &amount, NULL) ||
        amount != expected_size || !CloseHandle(file))
        return false;
    return true;
}

static bool admission_refused_without_registration(void)
{
    struct rom_artifact artifact;
    memset(&artifact, 0xa5, sizeof(artifact));
    struct rom_artifact before = artifact;
    return rom_bundle_admission_register(
               "must-not-be-opened", "bundle.sqlite", &artifact) ==
               ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT &&
           memcmp(&artifact, &before, sizeof(artifact)) == 0 &&
           rom_bundle_admission_scan("must-not-be-opened") == 0;
}

static bool sentinel_content_unchanged(const wchar_t *marker, char *actual,
                                       size_t actual_size,
                                       const char *expected)
{
    DWORD amount = 0;
    HANDLE file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    bool unchanged = file != INVALID_HANDLE_VALUE &&
                     ReadFile(file, actual, actual_size, &amount, NULL) &&
                     amount == actual_size &&
                     memcmp(actual, expected, actual_size) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return unchanged;
}

int main(void)
{
    wchar_t dir[MAX_PATH], marker[MAX_PATH];
    if (!create_isolated_dir(dir))
        return 1;
    (void)swprintf(marker, MAX_PATH, L"%ls\\sentinel", dir);
    const char expected[] = "unchanged";
    if (!write_sentinel(marker, expected, sizeof(expected)))
        return 1;
    bool refused = admission_refused_without_registration();
    rom_bundle_admission_start_scan("must-not-be-opened");
    rom_bundle_admission_stop_scan();

    char actual[sizeof(expected)] = {0};
    bool unchanged = sentinel_content_unchanged(marker, actual, sizeof(actual),
                                                expected);
    DeleteFileW(marker);
    RemoveDirectoryW(dir);
    if (!refused || !unchanged) return 1;
    puts("rom_bundle_admission_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int rom_bundle_admission_refusal_acceptance_not_built;
#endif
