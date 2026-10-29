/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: POSIX (openat) and Win32 (NtCreateFile) implementation of
 * platform/safe_root_read.h — walks a relative path one component/handle at
 * a time beneath a trusted root so no component can be a symlink or Windows
 * reparse point. */
#include "platform/safe_root_read.h"
#include "base/safe_alloc.h"

#include "base/safe_alloc.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool relative_path_char_forbidden(unsigned char c)
{
    return c == '\\' || (c != 0 && c < 0x20) || c == 0x7f;
}

static bool relative_path_component_forbidden(const char *component, size_t n)
{
    return n == 0 || (n == 1 && component[0] == '.') ||
           (n == 2 && component[0] == '.' && component[1] == '.');
}

static bool relative_path_valid(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || path[0] == '\\') return false;
    const char *component = path;
    for (const char *p = path;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (relative_path_char_forbidden(c)) return false;
        if (c == '/' || c == 0) {
            size_t n = (size_t)(p - component);
            if (relative_path_component_forbidden(component, n))
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
    FARPROC create_symbol = GetProcAddress(ntdll, "NtCreateFile");
    FARPROC error_symbol = GetProcAddress(ntdll, "RtlNtStatusToDosError");
    static_assert(sizeof(*create_file) == sizeof(create_symbol),
                  "Windows function pointer representations must match");
    static_assert(sizeof(*to_dos_error) == sizeof(error_symbol),
                  "Windows function pointer representations must match");
    memcpy(create_file, &create_symbol, sizeof(*create_file));
    memcpy(to_dos_error, &error_symbol, sizeof(*to_dos_error));
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
    wchar_t *wide = zcl_malloc((size_t)n * sizeof(*wide), "safe_root_read_wide");
    if (!wide) return false;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                             wide, n)) {
        free(wide);
        return false;
    }
    *output = wide;
    return true;
}

/* Opens one path component beneath current without following reparse points. */
static NTSTATUS win_open_component(nt_create_file_fn nt_create_file,
                                   HANDLE current, wchar_t *part, size_t count,
                                   bool leaf, HANDLE *handle)
{
    UNICODE_STRING name = {
        .Length = (USHORT)(count * sizeof(*part)),
        .MaximumLength = (USHORT)(count * sizeof(*part)),
        .Buffer = part
    };
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
                               current, NULL);
    IO_STATUS_BLOCK io_status = {0};
    ACCESS_MASK access = FILE_READ_ATTRIBUTES | SYNCHRONIZE |
                         (leaf ? 0 : FILE_TRAVERSE) |
                         (leaf ? FILE_READ_DATA : 0);
    ULONG options = FILE_OPEN_REPARSE_POINT |
                    FILE_SYNCHRONOUS_IO_NONALERT |
                    (leaf ? FILE_NON_DIRECTORY_FILE : FILE_DIRECTORY_FILE);
    return nt_create_file(handle, access, &attributes,
        &io_status, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, options, NULL, 0);
}

/* True when the opened entry is a reparse point or has the wrong kind. */
static bool win_entry_forbidden(HANDLE handle, bool leaf,
                                BY_HANDLE_FILE_INFORMATION *info)
{
    return !GetFileInformationByHandle(handle, info) ||
           (info->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
           (leaf ? (info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                 : (info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

/* Reads the whole leaf file; any failure leaves the result IO_ERROR. */
static enum platform_safe_root_read_result win_read_leaf(
    HANDLE handle, const BY_HANDLE_FILE_INFORMATION *info, size_t maximum,
    uint8_t **data, size_t *size)
{
    ULARGE_INTEGER length = {.LowPart = info->nFileSizeLow,
                             .HighPart = info->nFileSizeHigh};
    if (length.QuadPart > maximum || length.QuadPart > SIZE_MAX)
        return PLATFORM_SAFE_ROOT_READ_TOO_LARGE;
    size_t wanted = (size_t)length.QuadPart;
    uint8_t *buffer = zcl_malloc(wanted ? wanted : 1, "safe_root_read_buffer");
    if (!buffer) return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
    size_t offset = 0;
    while (offset < wanted) {
        DWORD chunk = (DWORD)((wanted - offset) > UINT32_MAX
            ? UINT32_MAX : (wanted - offset));
        DWORD got = 0;
        if (!ReadFile(handle, buffer + offset, chunk, &got, NULL) || !got) {
            free(buffer);
            return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
        }
        offset += got;
    }
    *data = buffer;
    *size = wanted;
    return PLATFORM_SAFE_ROOT_READ_OK;
}

/* True unless the opened root is a plain (non reparse-point) directory. */
static bool win_root_forbidden(HANDLE root_handle)
{
    BY_HANDLE_FILE_INFORMATION root_info = {0};
    return !GetFileInformationByHandle(root_handle, &root_info) ||
           !(root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
           (root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

/* Walks rel_wide one component at a time; *current tracks the open handle. */
static enum platform_safe_root_read_result win_walk_components(
    nt_create_file_fn nt_create_file,
    rtl_status_to_dos_error_fn status_to_error, HANDLE root_handle,
    HANDLE *current, wchar_t *rel_wide, size_t maximum, uint8_t **data,
    size_t *size)
{
    wchar_t *part = rel_wide;
    for (;;) {
        wchar_t *slash = wcschr(part, L'/');
        size_t count = slash ? (size_t)(slash - part) : wcslen(part);
        if (count > UINT16_MAX / sizeof(*part))
            return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
        bool leaf = slash == NULL;
        HANDLE handle = INVALID_HANDLE_VALUE;
        NTSTATUS status = win_open_component(nt_create_file, *current, part,
                                             count, leaf, &handle);
        if (status < 0) return win_error(status_to_error(status));
        if (*current != root_handle) CloseHandle(*current);
        *current = handle;
        BY_HANDLE_FILE_INFORMATION info = {0};
        if (win_entry_forbidden(handle, leaf, &info))
            return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
        if (leaf) return win_read_leaf(handle, &info, maximum, data, size);
        part = slash + 1;
    }
}

static void win_close_handles(HANDLE current, HANDLE root_handle)
{
    if (current != root_handle && current != INVALID_HANDLE_VALUE)
        CloseHandle(current);
    if (root_handle != INVALID_HANDLE_VALUE) CloseHandle(root_handle);
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
    } else if (win_root_forbidden(root_handle)) {
        result = PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
    } else {
        current = root_handle;
        result = win_walk_components(nt_create_file, status_to_error,
                                     root_handle, &current, rel_wide, maximum,
                                     data, size);
    }
    win_close_handles(current, root_handle);
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

/* Reads exactly wanted bytes from fd into a fresh buffer; NULL on any failure. */
static uint8_t *posix_read_all(int fd, size_t wanted)
{
    uint8_t *buffer = zcl_malloc(wanted ? wanted : 1, "safe_root_read_buffer");
    if (!buffer) return NULL;
    size_t offset = 0;
    while (offset < wanted) {
        ssize_t got = read(fd, buffer + offset, wanted - offset);
        if (got <= 0) { free(buffer); return NULL; }
        offset += (size_t)got;
    }
    return buffer;
}

/* Validates and reads the already-opened leaf descriptor. */
static enum platform_safe_root_read_result posix_read_leaf(
    int current, size_t maximum, uint8_t **data, size_t *size)
{
    struct stat st;
    if (fstat(current, &st) != 0) return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
    if (!S_ISREG(st.st_mode)) return PLATFORM_SAFE_ROOT_READ_FORBIDDEN;
    if (st.st_size < 0 || (uintmax_t)st.st_size > maximum ||
        (uintmax_t)st.st_size > SIZE_MAX)
        return PLATFORM_SAFE_ROOT_READ_TOO_LARGE;
    size_t wanted = (size_t)st.st_size;
    uint8_t *buffer = posix_read_all(current, wanted);
    if (!buffer) return PLATFORM_SAFE_ROOT_READ_IO_ERROR;
    *data = buffer; *size = wanted;
    return PLATFORM_SAFE_ROOT_READ_OK;
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
        result = posix_read_leaf(current, maximum, data, size);
        break;
    }
    free(copy);
    close(current);
    return result;
}
#endif
