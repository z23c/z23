/* Headless proof that Windows bundle export and retention mutate nothing. */
#include "config/bundle_exporter.h"

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <windows.h>

int main(void)
{
    wchar_t temp[MAX_PATH], candidate[MAX_PATH];
    char utf8[MAX_PATH * 3];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(candidate, MAX_PATH, L"%lsz23-bundle-refusal-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, candidate, -1,
                             utf8, sizeof(utf8), NULL, NULL))
        return 1;
    if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
        return 2;
    if (bundle_exporter_start((sqlite3 *)(uintptr_t)1, utf8))
        return 3;
#ifdef ZCL_TESTING
    bundle_exporter_set_rotate_skip_validate_for_test(true);
    bundle_exporter_rotate_for_test(utf8, 0, utf8);
    bundle_exporter_set_rotate_skip_validate_for_test(false);
#endif
    bundle_exporter_stop();
    if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
        return 4;
    puts("bundle_exporter_refusal_acceptance: PASS");
    return 0;
}
