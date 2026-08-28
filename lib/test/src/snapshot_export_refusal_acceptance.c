/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify every Windows snapshot export surface refuses inertly. */
#if defined(_WIN32)

#include "consensus_state_snapshot_export_internal.h"

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
        swprintf(dir, MAX_PATH, L"%lsz23-export-refuse-%lu", temp,
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

    struct consensus_state_snapshot_export_request request = {
        .output_dir_fd = 123, .output_name = "must-not-exist.sqlite"};
    struct consensus_export_output_binding output;
    struct consensus_state_export_result result = {0};
    struct consensus_state_bundle_manifest manifest = {0};
    sqlite3 *destination = (sqlite3 *)(uintptr_t)1;
    bool refused =
        !consensus_export_output_open(&request, &output, &result) &&
        output.dirfd == -1 && output.temp_fd == -1 &&
        !consensus_export_open_temp(&output, &destination, &result) &&
        destination == NULL &&
        !consensus_export_prove_write((sqlite3 *)(uintptr_t)1, &request,
                                      &output, &manifest, &result) &&
        !consensus_export_finalize_temp(&output, &manifest, &result) &&
        !consensus_state_snapshot_export((sqlite3 *)(uintptr_t)1, &request,
                                         &result) &&
        result.status == CONSENSUS_EXPORT_REFUSED;

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
    puts("snapshot_export_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int snapshot_export_refusal_acceptance_not_built;
#endif
