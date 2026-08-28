/* Native Windows acceptance: recovery copy refuses before destination mutation. */
#include "services/utxo_recovery_service.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void)
{
    char destination[MAX_PATH];
    char sentinel[MAX_PATH];
    (void)snprintf(destination, sizeof(destination),
                   "build/utxo-copy-refusal-%lu", GetCurrentProcessId());
    (void)snprintf(sentinel, sizeof(sentinel), "%s/sentinel", destination);
    if (!CreateDirectoryA(destination, NULL)) return 1;
    HANDLE file = CreateFileA(sentinel, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 2;
    static const char expected[] = "funds-bearing sentinel";
    DWORD written = 0;
    bool fixture_ok = WriteFile(file, expected, sizeof(expected), &written,
                                NULL) != 0 && written == sizeof(expected);
    CloseHandle(file);
    if (!fixture_ok) return 3;

    struct zcl_result result = utxo_recovery_copy_chainstate_stable(
        "build/source-must-not-be-opened", destination);
    char actual[sizeof(expected)] = {0};
    file = CreateFileA(sentinel, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read = 0;
    bool unchanged = file != INVALID_HANDLE_VALUE &&
                     ReadFile(file, actual, sizeof(actual), &read, NULL) != 0 &&
                     read == sizeof(actual) &&
                     memcmp(actual, expected, sizeof(expected)) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    (void)DeleteFileA(sentinel);
    (void)RemoveDirectoryA(destination);
    if (result.ok || !unchanged) return 4;

    puts("utxo_recovery_ldb_copy_refusal_acceptance: PASS");
    return 0;
}
