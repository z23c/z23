/* Headless proof that Windows mint-anchor preflight refuses without mutation. */
#include "config/boot.h"

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
        swprintf(dir, MAX_PATH, L"%lsz23-mint-refuse-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(dir, NULL))
        return 1;
    (void)swprintf(marker, MAX_PATH, L"%ls\\sentinel", dir);
    HANDLE file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    const char expected[] = "unchanged";
    DWORD written = 0;
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, expected, sizeof(expected), &written, NULL) ||
        written != sizeof(expected) || !CloseHandle(file))
        return 1;
    char utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, dir, -1, utf8,
                             sizeof(utf8), NULL, NULL) ||
        boot_mint_anchor_normal_boot_preflight(utf8) ||
        boot_mint_anchor_preflight_run_all(utf8, NULL))
        return 1;
    char actual[sizeof(expected)] = {0};
    file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read = 0;
    bool unchanged = file != INVALID_HANDLE_VALUE &&
                     ReadFile(file, actual, sizeof(actual), &read, NULL) &&
                     read == sizeof(actual) &&
                     memcmp(actual, expected, sizeof(expected)) == 0;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    DeleteFileW(marker);
    RemoveDirectoryW(dir);
    if (!unchanged)
        return 1;
    puts("mint_anchor_preflight_refusal_acceptance: PASS");
    return 0;
}
