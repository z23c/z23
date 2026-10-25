/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify Windows snapshot activation refuses without mutation. */
#if defined(_WIN32)

#include "config/consensus_state_snapshot_install.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool sentinel_directory_setup_failed(wchar_t temp[MAX_PATH],
                                            wchar_t dir[MAX_PATH])
{
    return !GetTempPathW(MAX_PATH, temp) ||
           swprintf(dir, MAX_PATH, L"%lsz23-activate-refuse-%lu", temp,
                    (unsigned long)GetCurrentProcessId()) <= 0 ||
           !CreateDirectoryW(dir, NULL);
}

static bool sentinel_marker_write_failed(const wchar_t *marker,
                                         const char *expected,
                                         size_t expected_size)
{
    DWORD amount = 0;
    HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    return file == INVALID_HANDLE_VALUE ||
           !WriteFile(file, expected, expected_size, &amount, NULL) ||
           amount != expected_size || !CloseHandle(file);
}

static bool activation_refused(
    struct consensus_state_activate_request *request,
    struct consensus_state_activate_result *result)
{
    return !consensus_state_snapshot_install_activate(
               (struct sqlite3 *)(uintptr_t)1, request, result) &&
           result->status == CONSENSUS_INSTALL_REFUSED && !result->activated &&
           result->prior_generation_path[0] == 0;
}

static bool sentinel_content_unchanged(const wchar_t *marker,
                                       const char *expected,
                                       size_t expected_size, char actual[])
{
    DWORD amount = 0;
    HANDLE file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    bool unchanged = file != INVALID_HANDLE_VALUE &&
                     ReadFile(file, actual, expected_size, &amount, NULL) &&
                     amount == expected_size &&
                     memcmp(actual, expected, expected_size) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return unchanged;
}

int main(void)
{
    wchar_t temp[MAX_PATH], dir[MAX_PATH], marker[MAX_PATH];
    if (sentinel_directory_setup_failed(temp, dir))
        return 1;
    (void)swprintf(marker, MAX_PATH, L"%ls\\sentinel", dir);
    const char expected[] = "unchanged";
    if (sentinel_marker_write_failed(marker, expected, sizeof(expected)))
        return 1;

    struct consensus_state_activate_request request = {0};
    request.datadir_fd = 123;
    request.datadir_display = "must-not-be-opened";
    request.bundle_path = "must-not-be-opened.sqlite";
    struct consensus_state_activate_result result = {0};
    bool refused = activation_refused(&request, &result);

    char actual[sizeof(expected)] = {0};
    bool unchanged = sentinel_content_unchanged(marker, expected,
                                                sizeof(expected), actual);
    DeleteFileW(marker);
    RemoveDirectoryW(dir);
    if (!refused || !unchanged) return 1;
    puts("snapshot_install_activate_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int snapshot_install_activate_refusal_acceptance_not_built;
#endif
