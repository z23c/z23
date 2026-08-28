/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/positioned_file.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <wchar.h>

static HANDLE positioned_handle(const struct platform_positioned_file *file)
{
    return file ? (HANDLE)file->native : INVALID_HANDLE_VALUE;
}

static bool positioned_wide(const char *utf8, wchar_t out[32768])
{
    if (!utf8 || !utf8[0]) return false;
    wchar_t plain[32768];
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                plain, 32768);
    if (n <= 0) return false;
    if (wcsncmp(plain, L"\\\\?\\", 4) == 0) {
        wmemcpy(out, plain, (size_t)n);
        return true;
    }
    if (plain[0] == L'\\' && plain[1] == L'\\') {
        if ((size_t)n + 6 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\UNC\\", 8);
        wmemcpy(out + 8, plain + 2, (size_t)n - 2);
        return true;
    }
    if (plain[0] && plain[1] == L':' &&
        (plain[2] == L'\\' || plain[2] == L'/')) {
        if ((size_t)n + 4 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, plain, (size_t)n);
        return true;
    }
    wmemcpy(out, plain, (size_t)n);
    return true;
}

void platform_positioned_file_init(struct platform_positioned_file *file)
{
    if (file) file->native = (uintptr_t)INVALID_HANDLE_VALUE;
}

bool platform_positioned_file_open(struct platform_positioned_file *file,
                                   const char *path)
{
    wchar_t wide[32768];
    if (!file || !positioned_wide(path, wide)) return false;
    platform_positioned_file_close(file);
    HANDLE handle = CreateFileW(
        wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
            FILE_FLAG_OVERLAPPED,
        NULL);
    if (handle == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info = {0};
    if (!GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        CloseHandle(handle);
        return false;
    }
    file->native = (uintptr_t)handle;
    return true;
}

bool platform_positioned_file_open_beneath(
    struct platform_positioned_file *file, const char *root,
    const char *leaf)
{
    if (!file || !root || !leaf || !leaf[0] || strchr(leaf, '/') ||
        strchr(leaf, '\\') || strcmp(leaf, ".") == 0 ||
        strcmp(leaf, "..") == 0)
        return false;
    wchar_t root_wide[32768], leaf_wide[32768];
    if (!positioned_wide(root, root_wide) ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, leaf, -1,
                            leaf_wide, 32768) <= 0)
        return false;
    HANDLE directory = CreateFileW(
        root_wide, FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    BY_HANDLE_FILE_INFORMATION directory_info = {0};
    if (directory == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(directory, &directory_info) ||
        !(directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (directory_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
        return false;
    }
    typedef NTSTATUS (NTAPI *nt_create_file_fn)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    nt_create_file_fn create_file = ntdll
        ? (nt_create_file_fn)(void *)GetProcAddress(ntdll, "NtCreateFile")
        : NULL;
    size_t leaf_length = wcslen(leaf_wide);
    UNICODE_STRING name = {
        .Length = (USHORT)(leaf_length * sizeof(*leaf_wide)),
        .MaximumLength = (USHORT)(leaf_length * sizeof(*leaf_wide)),
        .Buffer = leaf_wide,
    };
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                               directory, NULL);
    IO_STATUS_BLOCK status = {0};
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS result = create_file ? create_file(
        &handle, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &status, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE,
        NULL, 0) : (NTSTATUS)-1;
    CloseHandle(directory);
    BY_HANDLE_FILE_INFORMATION info = {0};
    if (result < 0 || handle == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        return false;
    }
    platform_positioned_file_close(file);
    file->native = (uintptr_t)handle;
    return true;
}

void platform_positioned_file_close(struct platform_positioned_file *file)
{
    if (!file) return;
    HANDLE handle = positioned_handle(file);
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    platform_positioned_file_init(file);
}

bool platform_positioned_file_size(const struct platform_positioned_file *file,
                                   uint64_t *size)
{
    LARGE_INTEGER value;
    HANDLE handle = positioned_handle(file);
    if (!size || handle == INVALID_HANDLE_VALUE ||
        !GetFileSizeEx(handle, &value) || value.QuadPart < 0)
        return false;
    *size = (uint64_t)value.QuadPart;
    return true;
}

bool platform_positioned_file_snapshot(
    const struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *snapshot)
{
    HANDLE handle = positioned_handle(file);
    BY_HANDLE_FILE_INFORMATION info = {0};
    FILE_BASIC_INFO basic = {0};
    if (!snapshot || handle == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(handle, &info) ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic,
                                      sizeof(basic)) ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
        return false;
    ULARGE_INTEGER size = {
        .LowPart = info.nFileSizeLow,
        .HighPart = info.nFileSizeHigh,
    };
    ULARGE_INTEGER modified = {
        .LowPart = info.ftLastWriteTime.dwLowDateTime,
        .HighPart = info.ftLastWriteTime.dwHighDateTime,
    };
    const uint64_t windows_to_unix_100ns = UINT64_C(116444736000000000);
    int64_t modified_seconds = modified.QuadPart >= windows_to_unix_100ns
        ? (int64_t)((modified.QuadPart - windows_to_unix_100ns) /
                    UINT64_C(10000000))
        : -(int64_t)((windows_to_unix_100ns - modified.QuadPart) /
                     UINT64_C(10000000));
    uint64_t changed_ticks = (uint64_t)basic.ChangeTime.QuadPart;
    int64_t changed_seconds = changed_ticks >= windows_to_unix_100ns
        ? (int64_t)((changed_ticks - windows_to_unix_100ns) /
                    UINT64_C(10000000))
        : -(int64_t)((windows_to_unix_100ns - changed_ticks) /
                     UINT64_C(10000000));
    *snapshot = (struct platform_positioned_file_snapshot){
        .size = size.QuadPart,
        .modified_seconds = modified_seconds,
        .modified_nanoseconds =
            (uint32_t)(modified.QuadPart % UINT64_C(10000000)) * 100u,
        .changed_seconds = changed_seconds,
        .changed_nanoseconds =
            (uint32_t)(changed_ticks % UINT64_C(10000000)) * 100u,
        .volume = info.dwVolumeSerialNumber,
        .file_low = ((uint64_t)info.nFileIndexHigh << 32) |
                    info.nFileIndexLow,
        .file_high = 0,
    };
    return true;
}

bool platform_positioned_file_path(
    const struct platform_positioned_file *file, char *path, size_t path_size)
{
    HANDLE handle = positioned_handle(file);
    if (!path || path_size == 0 || path_size > INT_MAX ||
        handle == INVALID_HANDLE_VALUE)
        return false;
    wchar_t wide[32768];
    DWORD n = GetFinalPathNameByHandleW(handle, wide, 32768,
                                        FILE_NAME_NORMALIZED |
                                            VOLUME_NAME_DOS);
    if (!n || n >= 32768) return false;
    const wchar_t *plain = wide;
    wchar_t unc[32768];
    if (wcsncmp(wide, L"\\\\?\\UNC\\", 8) == 0) {
        size_t length = wcslen(wide + 8);
        if (length + 3 >= 32768) return false;
        unc[0] = L'\\';
        unc[1] = L'\\';
        wmemcpy(unc + 2, wide + 8, length + 1);
        plain = unc;
    } else if (wcsncmp(wide, L"\\\\?\\", 4) == 0) {
        plain = wide + 4;
    }
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, plain, -1,
                               path, (int)path_size, NULL, NULL) > 0;
}

bool platform_positioned_file_is_executable(
    const struct platform_positioned_file *file)
{
    HANDLE handle = positioned_handle(file);
    IMAGE_DOS_HEADER header;
    int64_t read = platform_positioned_file_read(file, &header,
                                                 sizeof(header), 0);
    DWORD signature = 0;
    uint64_t size = 0;
    return handle != INVALID_HANDLE_VALUE && read == (int64_t)sizeof(header) &&
           header.e_magic == IMAGE_DOS_SIGNATURE && header.e_lfanew > 0 &&
           platform_positioned_file_size(file, &size) &&
           (uint64_t)header.e_lfanew <= size &&
           size - (uint64_t)header.e_lfanew >= sizeof(signature) &&
           platform_positioned_file_read(file, &signature, sizeof(signature),
                                         (uint64_t)header.e_lfanew) ==
               (int64_t)sizeof(signature) &&
           signature == IMAGE_NT_SIGNATURE;
}

int64_t platform_positioned_file_read(
    const struct platform_positioned_file *file, void *data, size_t size,
    uint64_t offset)
{
    HANDLE handle = positioned_handle(file);
    if (handle == INVALID_HANDLE_VALUE || (!data && size) ||
        size > UINT32_MAX || offset > INT64_MAX)
        return -1;
    if (!size) return 0;
    OVERLAPPED operation = {0};
    operation.Offset = (DWORD)offset;
    operation.OffsetHigh = (DWORD)(offset >> 32);
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) return -1;
    DWORD read = 0;
    BOOL ok = ReadFile(handle, data, (DWORD)size, &read, &operation);
    if (!ok && GetLastError() == ERROR_IO_PENDING)
        ok = GetOverlappedResult(handle, &operation, &read, TRUE);
    else if (!ok && GetLastError() == ERROR_HANDLE_EOF)
        ok = TRUE;
    CloseHandle(operation.hEvent);
    return ok ? (int64_t)read : -1;
}

#else

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void platform_positioned_file_init(struct platform_positioned_file *file)
{
    if (file) file->native = (uintptr_t)-1;
}

bool platform_positioned_file_open(struct platform_positioned_file *file,
                                   const char *path)
{
    if (!file || !path || !path[0]) return false;
    platform_positioned_file_close(file);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }
    file->native = (uintptr_t)fd;
    return true;
}

bool platform_positioned_file_open_beneath(
    struct platform_positioned_file *file, const char *root,
    const char *leaf)
{
    if (!file || !root || !leaf || !leaf[0] || strchr(leaf, '/') ||
        strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0)
        return false;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                               O_NOFOLLOW);
    if (directory < 0) return false;
    int fd = openat(directory, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(directory);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }
    platform_positioned_file_close(file);
    file->native = (uintptr_t)fd;
    return true;
}

void platform_positioned_file_close(struct platform_positioned_file *file)
{
    if (!file) return;
    int fd = (int)file->native;
    if (fd >= 0) close(fd);
    platform_positioned_file_init(file);
}

bool platform_positioned_file_size(const struct platform_positioned_file *file,
                                   uint64_t *size)
{
    struct stat st;
    int fd = file ? (int)file->native : -1;
    if (!size || fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0)
        return false;
    *size = (uint64_t)st.st_size;
    return true;
}

bool platform_positioned_file_snapshot(
    const struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *snapshot)
{
    struct stat st;
    int fd = file ? (int)file->native : -1;
    if (!snapshot || fd < 0 || fstat(fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size < 0)
        return false;
    *snapshot = (struct platform_positioned_file_snapshot){
        .size = (uint64_t)st.st_size,
        .modified_seconds = (int64_t)st.st_mtime,
        .modified_nanoseconds = (uint32_t)st.st_mtim.tv_nsec,
        .changed_seconds = (int64_t)st.st_ctime,
        .changed_nanoseconds = (uint32_t)st.st_ctim.tv_nsec,
        .volume = (uint64_t)st.st_dev,
        .file_low = (uint64_t)st.st_ino,
        .file_high = 0,
    };
    return true;
}

bool platform_positioned_file_path(
    const struct platform_positioned_file *file, char *path, size_t path_size)
{
    int fd = file ? (int)file->native : -1;
    if (fd < 0 || !path || path_size == 0) return false;
#if defined(__APPLE__)
    return fcntl(fd, F_GETPATH, path) == 0;
#else
    char proc[64];
    int n = snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    if (n <= 0 || (size_t)n >= sizeof(proc)) return false;
    ssize_t got = readlink(proc, path, path_size - 1);
    if (got < 0 || (size_t)got >= path_size) return false;
    path[got] = '\0';
    return true;
#endif
}

bool platform_positioned_file_is_executable(
    const struct platform_positioned_file *file)
{
    struct stat st;
    int fd = file ? (int)file->native : -1;
    return fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
           (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

int64_t platform_positioned_file_read(
    const struct platform_positioned_file *file, void *data, size_t size,
    uint64_t offset)
{
    int fd = file ? (int)file->native : -1;
    if (fd < 0 || (!data && size) || offset > INT64_MAX || size > SSIZE_MAX)
        return -1;
    ssize_t result;
    do {
        result = pread(fd, data, size, (off_t)offset);
    } while (result < 0 && errno == EINTR);
    return (int64_t)result;
}

#endif
