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

int main(void)
{
    wchar_t temp[MAX_PATH], dir[MAX_PATH], marker[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(dir, MAX_PATH, L"%lsz23-rom-admit-refuse-%lu", temp,
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
    struct rom_artifact artifact;
    memset(&artifact, 0xa5, sizeof(artifact));
    struct rom_artifact before = artifact;
    bool refused = rom_bundle_admission_register(
                       "must-not-be-opened", "bundle.sqlite", &artifact) ==
                       ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT &&
                   memcmp(&artifact, &before, sizeof(artifact)) == 0 &&
                   rom_bundle_admission_scan("must-not-be-opened") == 0;
    rom_bundle_admission_start_scan("must-not-be-opened");
    rom_bundle_admission_stop_scan();

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
    puts("rom_bundle_admission_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int rom_bundle_admission_refusal_acceptance_not_built;
#endif
