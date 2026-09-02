/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless native acceptance for UTF-8 directory creation and enumeration. */
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

static bool join_path(char *out, size_t capacity, const char *root,
                      const char *suffix)
{
    size_t root_size = strlen(root), suffix_size = strlen(suffix);
    if (root_size >= capacity || suffix_size >= capacity - root_size)
        return false;
    memcpy(out, root, root_size);
    memcpy(out + root_size, suffix, suffix_size + 1u);
    return true;
}

static void split_ticks(uint64_t ticks, int64_t *seconds,
                        uint32_t *nanoseconds)
{
    const uint64_t epoch = UINT64_C(116444736000000000);
    *seconds = ticks >= epoch
        ? (int64_t)((ticks - epoch) / UINT64_C(10000000))
        : -(int64_t)((epoch - ticks) / UINT64_C(10000000));
    *nanoseconds = (uint32_t)(ticks % UINT64_C(10000000)) * 100u;
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
    if (!join_path(alpha, sizeof(alpha), root, "/20260101_000000") ||
        !join_path(unicode, sizeof(unicode), root,
                   "/20260101_000002-\xE9\x9B\xAA") ||
        !join_path(plain, sizeof(plain), root, "/plain-file") ||
        !platform_directory_ensure(unicode, 0700) ||
        !platform_directory_ensure(alpha, 0700))
        return fail("child creation");
    HANDLE file;
    wchar_t plain_wide[4 * MAX_PATH];
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, plain, -1, plain_wide,
                        4 * MAX_PATH);
    file = CreateFileW(plain_wide, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return fail("file fixture");
    DWORD written = 0;
    if (!WriteFile(file, "abc", 3, &written, NULL) || written != 3) {
        CloseHandle(file);
        return fail("file fixture bytes");
    }
    CloseHandle(file);

    wchar_t link_wide[4 * MAX_PATH], alpha_wide[4 * MAX_PATH];
    char link[4 * MAX_PATH];
    if (!join_path(link, sizeof(link), root, "/20260101_000001"))
        return fail("link path");
    MultiByteToWideChar(CP_UTF8, 0, link, -1, link_wide, 4 * MAX_PATH);
    MultiByteToWideChar(CP_UTF8, 0, alpha, -1, alpha_wide, 4 * MAX_PATH);
    bool made_link = CreateSymbolicLinkW(link_wide, alpha_wide,
                                         SYMBOLIC_LINK_FLAG_DIRECTORY |
                                         SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;

    char canonical[4 * MAX_PATH];
    if (!platform_directory_canonical_real(unicode, canonical,
                                           sizeof(canonical)) ||
        !strstr(canonical, "20260101_000002-\xE9\x9B\xAA") ||
        (made_link && platform_directory_canonical_real(
                          link, canonical, sizeof(canonical))))
        return fail("canonical real-directory resolution");

    struct platform_directory_list list;
    if (!platform_directory_list_real_sorted(root, &list))
        return fail("enumeration");
    if (list.count != 2 || strcmp(list.entries[0].name, "20260101_000000") ||
        strcmp(list.entries[1].name, "20260101_000002-\xE9\x9B\xAA"))
        return fail("sorted real-directory filtering");
    platform_directory_list_free(&list);

    if (!platform_directory_list_regular_sorted(root, &list))
        return fail("regular-file enumeration");
    HANDLE observed = CreateFileW(
        plain_wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION info = {0};
    FILE_BASIC_INFO basic = {0};
    if (observed == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(observed, &info) ||
        !GetFileInformationByHandleEx(observed, FileBasicInfo, &basic,
                                      sizeof(basic))) {
        if (observed != INVALID_HANDLE_VALUE) CloseHandle(observed);
        return fail("regular-file reference metadata");
    }
    CloseHandle(observed);
    ULARGE_INTEGER modified = {
        .LowPart = info.ftLastWriteTime.dwLowDateTime,
        .HighPart = info.ftLastWriteTime.dwHighDateTime,
    };
    int64_t modified_seconds = 0, changed_seconds = 0;
    uint32_t modified_nanoseconds = 0, changed_nanoseconds = 0;
    split_ticks(modified.QuadPart, &modified_seconds, &modified_nanoseconds);
    split_ticks((uint64_t)basic.ChangeTime.QuadPart, &changed_seconds,
                &changed_nanoseconds);
    uint64_t file_id = ((uint64_t)info.nFileIndexHigh << 32) |
                       info.nFileIndexLow;
    if (list.count != 1 || strcmp(list.entries[0].name, "plain-file") ||
        !list.entries[0].snapshot_valid || list.entries[0].size != 3 ||
        list.entries[0].volume != info.dwVolumeSerialNumber ||
        list.entries[0].file_low != file_id ||
        list.entries[0].file_high != 0 ||
        list.entries[0].modified_seconds != modified_seconds ||
        list.entries[0].modified_nanoseconds != modified_nanoseconds ||
        list.entries[0].changed_seconds != changed_seconds ||
        list.entries[0].changed_nanoseconds != changed_nanoseconds)
        return fail("sorted regular-file filtering");
    platform_directory_list_free(&list);

    struct platform_directory_list combined_directories = {0};
    struct platform_directory_list combined_files = {0};
    if (!platform_directory_list_children_sorted(
            root, &combined_directories, &combined_files))
        return fail("single-pass child enumeration");
    if (combined_directories.count != 2 ||
        strcmp(combined_directories.entries[0].name, "20260101_000000") ||
        strcmp(combined_directories.entries[1].name,
               "20260101_000002-\xE9\x9B\xAA") ||
        combined_files.count != 1 ||
        strcmp(combined_files.entries[0].name, "plain-file") ||
        !combined_files.entries[0].snapshot_valid ||
        combined_files.entries[0].size != 3 ||
        combined_files.entries[0].volume != info.dwVolumeSerialNumber ||
        combined_files.entries[0].file_low != file_id)
        return fail("single-pass sorted child filtering");
    platform_directory_list_free(&combined_directories);
    platform_directory_list_free(&combined_files);

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
