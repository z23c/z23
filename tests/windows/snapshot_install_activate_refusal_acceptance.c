/* Headless proof that Windows snapshot activation refuses without mutation. */
#include "config/consensus_state_snapshot_install.h"

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
        swprintf(dir, MAX_PATH, L"%lsz23-activate-refuse-%lu", temp,
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

    struct consensus_state_activate_request request = {0};
    request.datadir_fd = 123;
    request.datadir_display = "must-not-be-opened";
    request.bundle_path = "must-not-be-opened.sqlite";
    struct consensus_state_activate_result result = {0};
    bool refused = !consensus_state_snapshot_install_activate(
                       (struct sqlite3 *)(uintptr_t)1, &request, &result) &&
                   result.status == CONSENSUS_INSTALL_REFUSED &&
                   !result.activated && result.prior_generation_path[0] == 0;

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
    puts("snapshot_install_activate_refusal_acceptance: PASS");
    return 0;
}
