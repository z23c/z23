/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify Windows candidate publication refuses without mutation. */
#if defined(_WIN32)

#include "consensus_state_snapshot_install_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

bool consensus_state_candidate_fail(
    struct consensus_state_candidate_result *result,
    enum consensus_state_candidate_status status, const char *fmt, ...)
{
    (void)fmt;
    if (result)
        result->status = status;
    return false;
}

int main(void)
{
    wchar_t temp[MAX_PATH], dir[MAX_PATH], marker[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(dir, MAX_PATH, L"%lsz23-candidate-refuse-%lu", temp,
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

    struct consensus_state_candidate_request request = {0};
    request.output_dir_fd = 123;
    request.output_name = "must-not-exist.sqlite";
    struct consensus_state_candidate_output output;
    struct consensus_state_candidate_result result = {0};
    if (consensus_state_candidate_output_open(&request, &output, &result) ||
        result.status != CONSENSUS_CANDIDATE_REFUSED ||
        output.binding.dirfd != -1 || output.binding.temp_fd != -1)
        return 1;

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
    if (!unchanged) return 1;
    puts("snapshot_candidate_output_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int snapshot_candidate_output_refusal_acceptance_not_built;
#endif
