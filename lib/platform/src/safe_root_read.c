/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/safe_root_read.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool relative_path_valid(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || path[0] == '\\') return false;
    const char *component = path;
    for (const char *p = path;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '\\' || (c != 0 && c < 0x20) || c == 0x7f) return false;
        if (c == '/' || c == 0) {
            size_t n = (size_t)(p - component);
            if (n == 0 || (n == 1 && component[0] == '.') ||
                (n == 2 && component[0] == '.' && component[1] == '.'))
                return false;
            if (c == 0) return true;
            component = p + 1;
        }
    }
}

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <wchar.h>

typedef NTSTATUS (NTAPI *nt_create_file_fn)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef ULONG (WINAPI *rtl_status_to_dos_error_fn)(NTSTATUS);

static bool native_file_functions(nt_create_file_fn *create_file,
                                  rtl_status_to_dos_error_fn *to_dos_error)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    *create_file = (nt_create_file_fn)(void *)GetProcAddress(ntdll,
                                                             "NtCreateFile");
    *to_dos_error = (rtl_status_to_dos_error_fn)(void *)GetProcAddress(
        ntdll, "RtlNtStatusToDosError");
    return *create_file != NULL && *to_dos_error != NULL;
}

static enum platform_safe_root_read_result win_error(DWORD error)
{
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        return PLATFORM_SAFE_ROOT_READ_NOT_FOUND;
    if (error == ERROR_ACCESS_DENIED || error == ERROR_CANT_ACCESS_FILE ||
        error == ERROR_INVALID_NAME)
        return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
    return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
}

static bool utf8_to_wide(const char *input, wchar_t **output)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                                NULL, 0);
    if (n <= 0) return false;
    wchar_t *wide = malloc((size_t)n * sizeof(*wide));
    if (!wide) return false;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                             wide, n)) {
        free(wide);
        return false;
    }
    *output = wide;
    return true;
}

enum platform_safe_root_read_result platform_safe_root_read(
    const char *root, const char *rel, size_t maximum, uint8_t **data,
    size_t *size)
{
    if (data) *data = NULL;
    if (size) *size = 0;
    if (!root || !data || !size || !relative_path_valid(rel))
        return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;

    wchar_t *root_wide = NULL, *rel_wide = NULL;
    if (!utf8_to_wide(root, &root_wide) || !utf8_to_wide(rel, &rel_wide)) {
        free(root_wide);
        free(rel_wide);
        return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
    }
    nt_create_file_fn nt_create_file = NULL;
    rtl_status_to_dos_error_fn status_to_error = NULL;
    if (!native_file_functions(&nt_create_file, &status_to_error)) {
        free(root_wide);
        free(rel_wide);
        return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
    }
    enum platform_safe_root_read_result result = PLATFORM_SAFE_ROOT_READ_IO_ERROR;
    HANDLE current = INVALID_HANDLE_VALUE;
    HANDLE root_handle = CreateFileW(root_wide,
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(root_wide);
    if (root_handle == INVALID_HANDLE_VALUE) {
        result = win_error(GetLastError());
        goto done;
    }
    BY_HANDLE_FILE_INFORMATION root_info = {0};
    if (!GetFileInformationByHandle(root_handle, &root_info) ||
        !(root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        result = PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
        goto done;
    }
    current = root_handle;
    wchar_t *part = rel_wide;
    for (;;) {
        wchar_t *slash = wcschr(part, L'/');
        size_t count = slash ? (size_t)(slash - part) : wcslen(part);
        if (count > UINT16_MAX / sizeof(*part)) {
            result = PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
            goto done;
        }
        bool leaf = slash == NULL;
        UNICODE_STRING name = {
            .Length = (USHORT)(count * sizeof(*part)),
            .MaximumLength = (USHORT)(count * sizeof(*part)),
            .Buffer = part
        };
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                                   current, NULL);
        IO_STATUS_BLOCK io_status = {0};
        HANDLE handle = INVALID_HANDLE_VALUE;
        ACCESS_MASK access = FILE_READ_ATTRIBUTES | SYNCHRONIZE |
                             (leaf ? 0 : FILE_TRAVERSE) |
                             (leaf ? FILE_READ_DATA : 0);
        ULONG options = FILE_OPEN_REPARSE_POINT |
                        FILE_SYNCHRONOUS_IO_NONALERT |
                        (leaf ? FILE_NON_DIRECTORY_FILE : FILE_DIRECTORY_FILE);
        NTSTATUS status = nt_create_file(&handle, access, &attributes,
            &io_status, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            FILE_OPEN, options, NULL, 0);
        if (status < 0) {
            result = win_error(status_to_error(status));
            goto done;
        }
        if (current != root_handle) CloseHandle(current);
        current = handle;
        BY_HANDLE_FILE_INFORMATION info = {0};
        if (!GetFileInformationByHandle(handle, &info) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            (leaf ? (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                  : (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
            result = PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
            goto done;
        }
        if (leaf) {
            ULARGE_INTEGER length = {.LowPart = info.nFileSizeLow,
                                     .HighPart = info.nFileSizeHigh};
            if (length.QuadPart > maximum || length.QuadPart > SIZE_MAX) {
                result = PLATFORM_SAFE_ROOT_READ_TOO_LARGE;
                goto done;
            }
            size_t wanted = (size_t)length.QuadPart;
            uint8_t *buffer = malloc(wanted ? wanted : 1);
            if (!buffer) goto done;
            size_t offset = 0;
            while (offset < wanted) {
                DWORD chunk = (DWORD)((wanted - offset) > UINT32_MAX
                    ? UINT32_MAX : (wanted - offset));
                DWORD got = 0;
                if (!ReadFile(handle, buffer + offset, chunk, &got, NULL) || !got) {
                    free(buffer); goto done;
                }
                offset += got;
            }
            *data = buffer;
            *size = wanted;
            result = PLATFORM_SAFE_ROOT_READ_OK;
            goto done;
        }
        part = slash + 1;
    }
done:
    if (current != root_handle && current != INVALID_HANDLE_VALUE)
        CloseHandle(current);
    if (root_handle != INVALID_HANDLE_VALUE) CloseHandle(root_handle);
    free(rel_wide);
    return result;
}

#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static enum platform_safe_root_read_result posix_error(int error)
{
    if (error == ENOENT || error == ENOTDIR)
        return PLATFORM_SAFE_ROOT_READ_NOT_FOUND;
    if (error == EACCES || error == ELOOP)
        return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
    return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
}

enum platform_safe_root_read_result platform_safe_root_read(
    const char *root, const char *rel, size_t maximum, uint8_t **data,
    size_t *size)
{
    if (data) *data = NULL;
    if (size) *size = 0;
    if (!root || !data || !size || !relative_path_valid(rel))
        return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
    int current = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) return posix_error(errno);
    enum platform_safe_root_read_result result = PLATFORM_SAFE_ROOT_READ_IO_ERROR;
    char *copy = strdup(rel);
    if (!copy) { close(current); return result; }
    char *part = copy;
    for (;;) {
        char *slash = strchr(part, '/');
        if (slash) *slash = 0;
        bool leaf = slash == NULL;
        int next = openat(current, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                          (leaf ? 0 : O_DIRECTORY));
        if (next < 0) { result = posix_error(errno); break; }
        close(current);
        current = next;
        if (!leaf) { part = slash + 1; continue; }
        struct stat st;
        if (fstat(current, &st) != 0) break;
        if (!S_ISREG(st.st_mode)) { result = PLATFORM_SAFE_ROOT_READ_FORBIDDEN; break; }
        if (st.st_size < 0 || (uintmax_t)st.st_size > maximum ||
            (uintmax_t)st.st_size > SIZE_MAX) {
            result = PLATFORM_SAFE_ROOT_READ_TOO_LARGE; break;
        }
        size_t wanted = (size_t)st.st_size;
        uint8_t *buffer = malloc(wanted ? wanted : 1);
        if (!buffer) break;
        size_t offset = 0;
        while (offset < wanted) {
            ssize_t got = read(current, buffer + offset, wanted - offset);
            if (got <= 0) { free(buffer); buffer = NULL; break; }
            offset += (size_t)got;
        }
        if (!buffer) break;
        *data = buffer; *size = wanted;
        result = PLATFORM_SAFE_ROOT_READ_OK;
        break;
    }
    free(copy);
    close(current);
    return result;
}
#endif
