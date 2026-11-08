/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless proof that native bundle install refuses without mutation. */
#if defined(_WIN32)

#include "config/consensus_state_install_runtime.h"
#include "config/boot.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool create_refusal_root(wchar_t *root, wchar_t *failed)
{
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-install-refusal-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(root, NULL) ||
        swprintf(failed, MAX_PATH, L"%ls\\candidate.sqlite.failed", root) <= 0)
        return false;
    return true;
}

static bool create_failed_marker_file(const wchar_t *failed)
{
    HANDLE marker = CreateFileW(failed, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) return false;
    CloseHandle(marker);
    return true;
}

static bool refusal_contract_violated(char *root_utf8, char *failed_utf8)
{
    char out[64] = "dirty";
    if (boot_install_bundle_request(root_utf8, failed_utf8) != 0 ||
        boot_install_bundle_pending(root_utf8) ||
        boot_install_bundle_consume(root_utf8, out, sizeof(out)) || out[0] ||
        boot_autodetect_consensus_bundle(root_utf8) != NULL ||
        boot_maybe_auto_install_consensus_bundle(NULL, NULL, root_utf8,
                                                 false))
        return true;
    return false;
}

static int verify_refusal_aftermath(const wchar_t *root, const wchar_t *failed)
{
    if (GetFileAttributesW(failed) == INVALID_FILE_ATTRIBUTES)
        return 5;
    wchar_t request[MAX_PATH];
    (void)swprintf(request, MAX_PATH, L"%ls\\install_bundle_request", root);
    if (GetFileAttributesW(request) != INVALID_FILE_ATTRIBUTES)
        return 6;
    return 0;
}

static bool request_write(const wchar_t *path, const char *wire)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0, len = (DWORD)strlen(wire);
    bool ok = WriteFile(file, wire, len, &written, NULL) && written == len;
    return CloseHandle(file) && ok;
}

static bool selection_refuses(const char *dir)
{
    struct app_context ctx = { .datadir = dir, .refold_from_anchor = true };
    struct boot_state_source_selection selection;
    boot_select_state_source(NULL, NULL, &ctx, &selection);
    return selection.refused && !selection.auto_installed_bundle &&
           !selection.consumed_auto_refold && !selection.do_from_anchor;
}

static bool request_refusals(const wchar_t *root, const char *dir)
{
    wchar_t request[MAX_PATH];
    if (swprintf(request, MAX_PATH, L"%ls\\install_bundle_request", root) <= 0)
        return false;
    static const char bound[] =
        "Z23-HISTORY-1\n-1\n/private/snapshot\n"
        "0000000000000000000000000000000000000000000000000000000000000000\n"
        "42\n"
        "0000000000000000000000000000000000000000000000000000000000000000\n"
        "0000000000000000000000000000000000000000000000000000000000000000\n"
        "/private/history\n";
    bool ok = request_write(request, "invalid\n") && selection_refuses(dir) &&
              !boot_install_bundle_terminal(dir, NULL) && request_write(request, bound) &&
              boot_install_bundle_terminal(dir, NULL) && selection_refuses(dir);
    return DeleteFileW(request) && ok;
}

int main(void)
{
    wchar_t root[MAX_PATH], failed[MAX_PATH];
    char root_utf8[MAX_PATH * 3], failed_utf8[MAX_PATH * 3];
    if (!create_refusal_root(root, failed)) return 1;
    if (!create_failed_marker_file(failed)) return 2;
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root, -1,
                             root_utf8, sizeof(root_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, failed, -1,
                             failed_utf8, sizeof(failed_utf8), NULL, NULL))
        return 3;
    if (refusal_contract_violated(root_utf8, failed_utf8)) return 4;
    boot_install_bundle_clear(root_utf8);
    boot_auto_install_clear_failed_marker(failed_utf8);
    int rc = verify_refusal_aftermath(root, failed);
    if (rc != 0) return rc;
    if (!request_refusals(root, root_utf8)) return 7;
    DeleteFileW(failed);
    RemoveDirectoryW(root);
    puts("boot_auto_install_bundle_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int boot_auto_install_bundle_windows_refusal_not_built;
#endif
