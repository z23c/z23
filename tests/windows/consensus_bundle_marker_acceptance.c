/* Headless replacement acceptance for the sovereign bundle marker. */
#include "config/boot_consensus_bundle_marker.h"
#include "base/log_level.h"

#define WIN32_LEAN_AND_MEAN
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_ALL; }
void zcl_log_emit_at(enum zcl_log_level level, const char *format, ...)
{
    (void)level;
    va_list args;
    va_start(args, format);
    (void)vfprintf(stderr, format, args);
    va_end(args);
}

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], marker[MAX_PATH];
    char root_utf8[MAX_PATH * 3];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-marker-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(root, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root, -1,
                             root_utf8, sizeof(root_utf8), NULL, NULL))
        return 1;
    uint8_t first[32] = {1}, second[32] = {2};
    if (!boot_consensus_bundle_marker_write(root_utf8, 100, first) ||
        !boot_consensus_bundle_marker_write(root_utf8, 200, second) ||
        !boot_consensus_bundle_marker_exists(root_utf8))
        return 2;
    (void)swprintf(marker, MAX_PATH, L"%ls\\%hs", root,
                   BOOT_CONSENSUS_BUNDLE_MARKER_NAME);
    HANDLE file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    char body[512] = {0};
    DWORD read = 0;
    if (file == INVALID_HANDLE_VALUE ||
        !ReadFile(file, body, sizeof(body) - 1, &read, NULL) ||
        !strstr(body, "height=200\n") ||
        !strstr(body, "artifact_digest=02"))
        return 3;
    CloseHandle(file);
    DeleteFileW(marker);
    RemoveDirectoryW(root);
    puts("consensus_bundle_marker_acceptance: PASS");
    return 0;
}
