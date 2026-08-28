/* Headless Windows acceptance for recovery datadir creation boundaries. */
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

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], source[MAX_PATH], target[MAX_PATH];
    wchar_t link[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-wallet-recovery-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(root, NULL))
        return 1;
    (void)swprintf(source, MAX_PATH, L"%ls\\source-wallet", root);
    (void)swprintf(target, MAX_PATH, L"%ls\\new-recovery", root);
    (void)swprintf(link, MAX_PATH, L"%ls\\reparse-recovery", root);
    char source_utf8[MAX_PATH * 3], target_utf8[MAX_PATH * 3];
    char link_utf8[MAX_PATH * 3], sentinel[MAX_PATH * 3];
    if (!to_utf8(source, source_utf8, sizeof(source_utf8)) ||
        !to_utf8(target, target_utf8, sizeof(target_utf8)) ||
        !to_utf8(link, link_utf8, sizeof(link_utf8)) ||
        !platform_private_directory_ensure(source_utf8))
        return 2;
    (void)snprintf(sentinel, sizeof(sentinel), "%s/sentinel", source_utf8);
    struct platform_private_file file;
    platform_private_file_init(&file);
    static const char expected[] = "source wallet remains untouched";
    bool fixture = platform_private_file_create(sentinel, &file) &&
                   platform_private_file_write_at(&file, expected,
                                                  sizeof(expected), 0) &&
                   platform_private_file_flush(&file);
    platform_private_file_close(&file);
    if (!fixture) return 3;

    struct wallet_recovery_report report = {0};
    struct zcl_result made =
        wallet_recovery_test_ensure_datadir(target_utf8, &report);
    char actual[sizeof(expected)] = {0};
    platform_private_file_init(&file);
    bool source_unchanged = platform_private_file_open_locked(sentinel, &file) &&
        platform_private_file_read_at(&file, actual, sizeof(actual), 0) &&
        memcmp(actual, expected, sizeof(expected)) == 0;
    platform_private_file_close(&file);
    if (!made.ok || !report.datadir_created || !source_unchanged) return 4;

    DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(link, source, flags)) {
        memset(&report, 0, sizeof(report));
        struct zcl_result refused =
            wallet_recovery_test_ensure_datadir(link_utf8, &report);
        DWORD attrs = GetFileAttributesW(link);
        if (refused.ok || report.datadir_created ||
            attrs == INVALID_FILE_ATTRIBUTES ||
            !(attrs & FILE_ATTRIBUTE_REPARSE_POINT))
            return 5;
        (void)RemoveDirectoryW(link);
    }

    (void)platform_private_file_unlink_missing_ok(sentinel);
    (void)RemoveDirectoryW(target);
    (void)RemoveDirectoryW(source);
    (void)RemoveDirectoryW(root);
    puts("wallet_recovery_directory_acceptance: PASS");
    return 0;
}
