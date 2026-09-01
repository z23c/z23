/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless native acceptance for UTF-8 caller-available disk capacity. */
#include "platform/disk_space.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

int main(void)
{
    wchar_t temp[MAX_PATH];
    char utf8[4 * MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, temp, -1, utf8,
                             sizeof(utf8), NULL, NULL))
        return 1;

    uint64_t available = 0;
    if (!platform_disk_space_available(utf8, &available) || available == 0)
        return 2;

    /* The same volume spelled with forward slashes. Callers join paths with
     * '/' and plain Win32 rewrites those for them, but the \\?\ prefix this
     * implementation prepends turns every path parse OFF -- a surviving '/'
     * then reaches the object manager as a filename character and the query
     * fails with ERROR_INVALID_NAME. UTF-8 is self-synchronising, so no byte
     * of a multi-byte sequence can be a backslash and this byte-wise rewrite
     * is safe. */
    for (char *cursor = utf8; *cursor; cursor++)
        if (*cursor == '\\') *cursor = '/';
    uint64_t forward = 0;
    if (!platform_disk_space_available(utf8, &forward) || forward == 0)
        return 4;
    if (platform_disk_space_available("\xff", &available) ||
        platform_disk_space_available(NULL, &available) ||
        platform_disk_space_available(utf8, NULL))
        return 3;

    puts("disk_space_acceptance: PASS");
    return 0;
}
