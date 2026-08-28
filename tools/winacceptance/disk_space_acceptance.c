/* Headless native acceptance for UTF-8 caller-available disk capacity. */
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
    if (platform_disk_space_available("\xff", &available) ||
        platform_disk_space_available(NULL, &available) ||
        platform_disk_space_available(utf8, NULL))
        return 3;

    puts("disk_space_acceptance: PASS");
    return 0;
}
