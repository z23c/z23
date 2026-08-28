/* Headless acceptance for current-user private directory boundaries. */
#include "platform/private_directory.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "private_directory_acceptance: %s\n", message);
    return 1;
}

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], private_path[MAX_PATH];
    wchar_t permissive[MAX_PATH], target[MAX_PATH], link_path[MAX_PATH];
    wchar_t moved_path[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-private-dir-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(root, NULL))
        return fail("fixture root create failed");
    (void)swprintf(private_path, MAX_PATH, L"%ls\\private", root);
    (void)swprintf(permissive, MAX_PATH, L"%ls\\permissive", root);
    (void)swprintf(target, MAX_PATH, L"%ls\\target", root);
    (void)swprintf(link_path, MAX_PATH, L"%ls\\link", root);
    (void)swprintf(moved_path, MAX_PATH, L"%ls\\private-moved", root);

    char utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, private_path, -1,
                             utf8, sizeof(utf8), NULL, NULL) ||
        !platform_private_directory_ensure(utf8) ||
        !platform_private_directory_ensure(utf8))
        return fail("create/existing validation failed");

    uintptr_t native = (uintptr_t)INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION before = {0}, after = {0};
    if (!platform_private_directory_open_validated(utf8, &native) ||
        !GetFileInformationByHandle((HANDLE)native, &before) ||
        !MoveFileExW(private_path, moved_path, 0) ||
        !GetFileInformationByHandle((HANDLE)native, &after) ||
        before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
        before.nFileIndexHigh != after.nFileIndexHigh ||
        before.nFileIndexLow != after.nFileIndexLow)
        return fail("validated handle did not remain bound across rename");
    platform_private_directory_close(native);
    if (!MoveFileExW(moved_path, private_path, 0))
        return fail("fixture rename restore failed");

    if (!CreateDirectoryW(permissive, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, permissive, -1,
                             utf8, sizeof(utf8), NULL, NULL) ||
        platform_private_directory_ensure(utf8))
        return fail("permissive inherited ACL accepted");

    if (!CreateDirectoryW(target, NULL))
        return fail("reparse target create failed");
    DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(link_path, target, flags)) {
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, link_path, -1,
                                 utf8, sizeof(utf8), NULL, NULL) ||
            platform_private_directory_ensure(utf8))
            return fail("directory reparse point accepted");
        RemoveDirectoryW(link_path);
    }

    RemoveDirectoryW(private_path);
    RemoveDirectoryW(permissive);
    RemoveDirectoryW(target);
    RemoveDirectoryW(root);
    puts("private_directory_acceptance: PASS");
    return 0;
}
