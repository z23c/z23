/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless Windows acceptance for recovery datadir creation boundaries. */
#if defined(_WIN32)

#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "services/wallet_recovery_service.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool to_utf8(const wchar_t *wide, char *out, size_t size)
{
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, out,
                               (int)size, NULL, NULL) > 0;
}

static bool create_unique_recovery_root(wchar_t *temp, wchar_t *root)
{
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-wallet-recovery-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        !CreateDirectoryW(root, NULL))
        return false;
    return true;
}

static bool write_sentinel_fixture(const char *path, const char *expected,
                                   size_t expected_size, const char **stage,
                                   DWORD *error)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool fixture = platform_private_file_create(path, &file);
    if (fixture) {
        *stage = "write";
        fixture = platform_private_file_write_at(
            &file, expected, expected_size, 0);
    }
    if (fixture) {
        *stage = "flush";
        fixture = platform_private_file_flush(&file);
    }
    *error = fixture ? ERROR_SUCCESS : GetLastError();
    platform_private_file_close(&file);
    return fixture;
}

static bool sentinel_matches_expected(const char *path, char *actual,
                                      const char *expected, size_t size)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool source_unchanged = platform_private_file_open_locked(path, &file) &&
        platform_private_file_read_at(&file, actual, size, 0) &&
        memcmp(actual, expected, size) == 0;
    platform_private_file_close(&file);
    return source_unchanged;
}

static bool verify_reparse_point_refusal(const wchar_t *link,
                                         const wchar_t *source,
                                         const char *link_utf8)
{
    DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (!CreateSymbolicLinkW(link, source, flags))
        return true;
    struct wallet_recovery_report report;
    memset(&report, 0, sizeof(report));
    struct zcl_result refused =
        wallet_recovery_test_ensure_datadir(link_utf8, &report);
    DWORD attrs = GetFileAttributesW(link);
    if (refused.ok || report.datadir_created ||
        attrs == INVALID_FILE_ATTRIBUTES ||
        !(attrs & FILE_ATTRIBUTE_REPARSE_POINT))
        return false;
    (void)RemoveDirectoryW(link);
    return true;
}

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], source[MAX_PATH], target[MAX_PATH];
    wchar_t link[MAX_PATH];
    if (!create_unique_recovery_root(temp, root))
        return 1;
    (void)swprintf(source, MAX_PATH, L"%ls\\source-wallet", root);
    (void)swprintf(target, MAX_PATH, L"%ls\\new-recovery", root);
    (void)swprintf(link, MAX_PATH, L"%ls\\reparse-recovery", root);
    char source_utf8[MAX_PATH * 3], target_utf8[MAX_PATH * 3];
    char link_utf8[MAX_PATH * 3], sentinel[MAX_PATH * 3 + 16];
    if (!to_utf8(source, source_utf8, sizeof(source_utf8)) ||
        !to_utf8(target, target_utf8, sizeof(target_utf8)) ||
        !to_utf8(link, link_utf8, sizeof(link_utf8)))
        return 2;
    if (!platform_private_directory_ensure(source_utf8)) {
        (void)RemoveDirectoryW(source);
        (void)RemoveDirectoryW(root);
        fputs("wallet_recovery_directory_acceptance: REFUSE: runtime cannot "
              "prove native SID/DACL semantics\n", stderr);
        return 77;
    }
    (void)snprintf(sentinel, sizeof(sentinel), "%s/sentinel", source_utf8);
    static const char expected[] = "source wallet remains untouched";
    const char *fixture_stage = "create";
    DWORD fixture_error = ERROR_SUCCESS;
    if (!write_sentinel_fixture(sentinel, expected, sizeof(expected),
                                &fixture_stage, &fixture_error)) {
        fprintf(stderr, "wallet recovery fixture %s failed: win32=%lu\n",
                fixture_stage, (unsigned long)fixture_error);
        return 3;
    }

    struct wallet_recovery_report report = {0};
    struct zcl_result made =
        wallet_recovery_test_ensure_datadir(target_utf8, &report);
    char actual[sizeof(expected)] = {0};
    bool source_unchanged =
        sentinel_matches_expected(sentinel, actual, expected,
                                  sizeof(expected));
    if (!made.ok || !report.datadir_created || !source_unchanged) return 4;

    if (!verify_reparse_point_refusal(link, source, link_utf8))
        return 5;

    (void)platform_private_file_unlink_missing_ok(sentinel);
    (void)RemoveDirectoryW(target);
    (void)RemoveDirectoryW(source);
    (void)RemoveDirectoryW(root);
    puts("wallet_recovery_directory_acceptance: PASS");
    return 0;
}

#else
typedef int wallet_recovery_directory_windows_acceptance_not_built;
#endif
