/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Windows acceptance for the consensus progress-store refusal boundary. */
#if defined(_WIN32)

#include "platform/private_directory.h"
#include "storage/progress_store.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "progress_store_windows_refusal_acceptance: %s\n", message);
    return 1;
}

static bool append_leaf(wchar_t *out, size_t cap, const wchar_t *root,
                        const wchar_t *leaf)
{
    int count = swprintf(out, cap, L"%ls\\%ls", root, leaf);
    return count > 0 && (size_t)count < cap;
}

static bool path_absent(const wchar_t *path)
{
    SetLastError(ERROR_SUCCESS);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
        return false;
    DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

static bool consensus_family_absent(const wchar_t *root)
{
    static const wchar_t *const names[] = {
        L"consensus.db",
        L"consensus.db-wal",
        L"consensus.db-shm",
        L"consensus.db-journal",
        L"consensus.db.tmp",
        L"consensus.db.tmp-wal",
        L"consensus.db.tmp-shm",
        L"consensus.db.tmp-journal",
    };
    wchar_t path[MAX_PATH];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (!append_leaf(path, sizeof(path) / sizeof(path[0]), root, names[i]) ||
            !path_absent(path))
            return false;
    }
    return true;
}

static bool same_file_state(const BY_HANDLE_FILE_INFORMATION *before,
                            const BY_HANDLE_FILE_INFORMATION *after)
{
    return before->dwVolumeSerialNumber == after->dwVolumeSerialNumber &&
           before->nFileIndexHigh == after->nFileIndexHigh &&
           before->nFileIndexLow == after->nFileIndexLow &&
           before->nFileSizeHigh == after->nFileSizeHigh &&
           before->nFileSizeLow == after->nFileSizeLow &&
           before->dwFileAttributes == after->dwFileAttributes &&
           CompareFileTime(&before->ftLastWriteTime,
                           &after->ftLastWriteTime) == 0;
}

int main(void)
{
    static const uint8_t sentinel[] = {
        0x5a, 0x32, 0x33, 0x00, 0xff, 0x70, 0x72, 0x6f,
        0x67, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x6b, 0x76,
    };
    wchar_t temp[MAX_PATH], root[MAX_PATH], progress[MAX_PATH];
    DWORD temp_len = GetTempPathW(sizeof(temp) / sizeof(temp[0]), temp);
    int root_len = temp_len > 0 && temp_len < sizeof(temp) / sizeof(temp[0])
        ? swprintf(root, sizeof(root) / sizeof(root[0]),
                   L"%lsz23-progress-refusal-%lu-%llu", temp,
                   (unsigned long)GetCurrentProcessId(),
                   (unsigned long long)GetTickCount64())
        : -1;
    if (root_len <= 0 || (size_t)root_len >= sizeof(root) / sizeof(root[0]) ||
        !append_leaf(progress, sizeof(progress) / sizeof(progress[0]), root,
                     L"progress.kv"))
        return fail("fixture path construction failed");

    char root_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root, -1,
                             root_utf8, sizeof(root_utf8), NULL, NULL) ||
        !platform_private_directory_create(root_utf8)) {
        fputs("progress_store_windows_refusal_acceptance: REFUSE: runtime "
              "cannot create an owner-private datadir\n", stderr);
        return 77;
    }
    uintptr_t retained = 0;
    if (!platform_private_directory_open_validated(root_utf8, &retained))
        return fail("fixture datadir did not validate as owner-private");
    platform_private_directory_close(retained);

    HANDLE file = CreateFileW(progress, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    BY_HANDLE_FILE_INFORMATION before;
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, sentinel, (DWORD)sizeof(sentinel), &written, NULL) ||
        written != sizeof(sentinel) || !FlushFileBuffers(file) ||
        !GetFileInformationByHandle(file, &before) || !CloseHandle(file))
        return fail("sentinel progress.kv creation failed");
    if (!consensus_family_absent(root))
        return fail("consensus.db family was not initially absent");

    HANDLE directory = CreateFileW(
        root, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION directory_before, directory_after;
    if (directory == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(directory, &directory_before))
        return fail("datadir state snapshot failed");

    if (progress_store_open(root_utf8))
        return fail("progress_store_open accepted native Windows");

    if (!GetFileInformationByHandle(directory, &directory_after) ||
        !same_file_state(&directory_before, &directory_after) ||
        !CloseHandle(directory))
        return fail("refusal mutated datadir identity or metadata");
    if (!consensus_family_absent(root))
        return fail("refusal created a consensus.db family member");
    file = CreateFileW(progress, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    uint8_t actual[sizeof(sentinel)];
    DWORD read_count = 0;
    BY_HANDLE_FILE_INFORMATION after;
    if (file == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(file, &after) ||
        !ReadFile(file, actual, (DWORD)sizeof(actual), &read_count, NULL) ||
        read_count != sizeof(actual) || !CloseHandle(file) ||
        !same_file_state(&before, &after) ||
        memcmp(actual, sentinel, sizeof(sentinel)) != 0)
        return fail("refusal mutated sentinel progress.kv");

    if (!DeleteFileW(progress) || !RemoveDirectoryW(root))
        return fail("fixture cleanup failed");
    puts("progress_store_windows_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int progress_store_windows_refusal_not_built;
#endif
