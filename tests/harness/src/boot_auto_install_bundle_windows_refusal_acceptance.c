/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless proof that native bundle install refuses without mutation. */
#if defined(_WIN32)

#include "config/consensus_state_install_runtime.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <windows.h>

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], failed[MAX_PATH];
    char root_utf8[MAX_PATH * 3], failed_utf8[MAX_PATH * 3], out[64] = "dirty";
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-install-refusal-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(root, NULL) ||
        swprintf(failed, MAX_PATH, L"%ls\\candidate.sqlite.failed", root) <= 0)
        return 1;
    HANDLE marker = CreateFileW(failed, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) return 2;
    CloseHandle(marker);
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root, -1,
                             root_utf8, sizeof(root_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, failed, -1,
                             failed_utf8, sizeof(failed_utf8), NULL, NULL))
        return 3;

    if (boot_install_bundle_request(root_utf8, failed_utf8) != 0 ||
        boot_install_bundle_pending(root_utf8) ||
        boot_install_bundle_consume(root_utf8, out, sizeof(out)) || out[0] ||
        boot_autodetect_consensus_bundle(root_utf8) != NULL ||
        boot_maybe_auto_install_consensus_bundle(NULL, NULL, root_utf8))
        return 4;
    boot_install_bundle_clear(root_utf8);
    boot_auto_install_clear_failed_marker(failed_utf8);
    if (GetFileAttributesW(failed) == INVALID_FILE_ATTRIBUTES)
        return 5;
    wchar_t request[MAX_PATH];
    (void)swprintf(request, MAX_PATH, L"%ls\\install_bundle_request", root);
    if (GetFileAttributesW(request) != INVALID_FILE_ATTRIBUTES)
        return 6;

    DeleteFileW(failed);
    RemoveDirectoryW(root);
    puts("boot_auto_install_bundle_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int boot_auto_install_bundle_windows_refusal_not_built;
#endif
