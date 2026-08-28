/* Headless native acceptance for UTF-8 directory creation and enumeration. */
#include "platform/directory_compat.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s (win32=%lu)\n", message,
            (unsigned long)GetLastError());
    return 1;
}

int main(void)
{
    wchar_t temp[MAX_PATH], root_wide[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        !GetTempFileNameW(temp, L"zdc", 0, root_wide) ||
        !DeleteFileW(root_wide))
        return fail("temporary name");
    char root[4 * MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root_wide, -1,
                             root, sizeof(root), NULL, NULL) ||
        !platform_directory_ensure(root, 0700))
        return fail("UTF-8 root creation");

    char alpha[4 * MAX_PATH], unicode[4 * MAX_PATH], plain[4 * MAX_PATH];
    snprintf(alpha, sizeof(alpha), "%s/20260101_000000", root);
    snprintf(unicode, sizeof(unicode), "%s/20260101_000002-\xE9\x9B\xAA", root);
    snprintf(plain, sizeof(plain), "%s/plain-file", root);
    if (!platform_directory_ensure(unicode, 0700) ||
        !platform_directory_ensure(alpha, 0700))
        return fail("child creation");
    HANDLE file;
    wchar_t plain_wide[4 * MAX_PATH];
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, plain, -1, plain_wide,
                        4 * MAX_PATH);
    file = CreateFileW(plain_wide, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return fail("file fixture");
    CloseHandle(file);

    wchar_t link_wide[4 * MAX_PATH], alpha_wide[4 * MAX_PATH];
    char link[4 * MAX_PATH];
    snprintf(link, sizeof(link), "%s/20260101_000001", root);
    MultiByteToWideChar(CP_UTF8, 0, link, -1, link_wide, 4 * MAX_PATH);
    MultiByteToWideChar(CP_UTF8, 0, alpha, -1, alpha_wide, 4 * MAX_PATH);
    bool made_link = CreateSymbolicLinkW(link_wide, alpha_wide,
                                         SYMBOLIC_LINK_FLAG_DIRECTORY |
                                         SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;

    struct platform_directory_list list;
    if (!platform_directory_list_real_sorted(root, &list))
        return fail("enumeration");
    if (list.count != 2 || strcmp(list.entries[0].name, "20260101_000000") ||
        strcmp(list.entries[1].name, "20260101_000002-\xE9\x9B\xAA"))
        return fail("sorted real-directory filtering");
    platform_directory_list_free(&list);

    if (!platform_directory_list_regular_sorted(root, &list))
        return fail("regular-file enumeration");
    if (list.count != 1 || strcmp(list.entries[0].name, "plain-file"))
        return fail("sorted regular-file filtering");
    platform_directory_list_free(&list);

    if (made_link) RemoveDirectoryW(link_wide);
    DeleteFileW(plain_wide);
    wchar_t unicode_wide[4 * MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, unicode, -1, unicode_wide, 4 * MAX_PATH);
    RemoveDirectoryW(unicode_wide);
    RemoveDirectoryW(alpha_wide);
    RemoveDirectoryW(root_wide);
    puts("directory_compat_acceptance: PASS");
    return 0;
}
