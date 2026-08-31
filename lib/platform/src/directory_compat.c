/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: POSIX (dirent/fstatat) and retained-handle Win32/NT directory
 * operations — create/ensure a directory and list real, sorted, non-link
 * children with exact regular-file identity and change metadata. */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include "platform/directory_compat.h"
#include "base/safe_alloc.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int entry_compare(const void *a, const void *b)
{
    const struct platform_directory_entry *ea = a;
    const struct platform_directory_entry *eb = b;
    return strcmp(ea->name, eb->name);
}

static bool append_entry(struct platform_directory_list *list,
                         const char *name,
                         const struct platform_directory_entry *snapshot)
{
    size_t next_count = list->count + 1;
    if (next_count < list->count ||
        next_count > SIZE_MAX / sizeof(*list->entries))
        return false;
    struct platform_directory_entry *next =
        zcl_realloc(list->entries, next_count * sizeof(*next),
                   "platform_directory_entries");
    if (!next) return false;
    list->entries = next;
    size_t name_size = strlen(name) + 1;
    next[list->count] = snapshot ? *snapshot
                                 : (struct platform_directory_entry){0};
    next[list->count].name =
        zcl_malloc(name_size, "platform_directory_entry_name");
    if (!next[list->count].name) return false;
    memcpy(next[list->count].name, name, name_size);
    list->count = next_count;
    return true;
}

void platform_directory_list_free(struct platform_directory_list *list)
{
    if (!list) return;
    for (size_t i = 0; i < list->count; ++i)
        free(list->entries[i].name);
    free(list->entries);
    list->entries = NULL;
    list->count = 0;
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *directory_query_fn)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

static directory_query_fn directory_query_resolve(void)
{
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC symbol = module ? GetProcAddress(module, "NtQueryDirectoryFile")
                            : NULL;
    directory_query_fn query = NULL;
    static_assert(sizeof(query) == sizeof(symbol),
                  "Windows function pointer representations must match");
    memcpy(&query, &symbol, sizeof(query));
    return query;
}

static void windows_ticks_split(LONGLONG ticks, int64_t *seconds,
                                uint32_t *nanoseconds)
{
    const uint64_t epoch = UINT64_C(116444736000000000);
    uint64_t value = (uint64_t)ticks;
    *seconds = value >= epoch
        ? (int64_t)((value - epoch) / UINT64_C(10000000))
        : -(int64_t)((epoch - value) / UINT64_C(10000000));
    *nanoseconds = (uint32_t)(value % UINT64_C(10000000)) * 100u;
}

static char *wide_span_to_utf8(const wchar_t *name, size_t chars)
{
    if (!name || chars > INT_MAX) return NULL;
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name,
                                     (int)chars, NULL, 0, NULL, NULL);
    char *utf8 = needed > 0
        ? zcl_malloc((size_t)needed + 1u, "directory_compat_name") : NULL;
    if (!utf8 || WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name,
                                     (int)chars, utf8, needed, NULL, NULL) !=
                     needed) {
        free(utf8);
        return NULL;
    }
    utf8[needed] = '\0';
    return utf8;
}

static wchar_t *utf8_to_wide(const char *path)
{
    if (!path) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *wide = zcl_malloc((size_t)n * sizeof(*wide), "directory_compat_wide");
    if (!wide || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                      wide, n)) {
        free(wide);
        return NULL;
    }
    return wide;
}

static char *wide_to_utf8(const wchar_t *name)
{
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1,
                                NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *utf8 = zcl_malloc((size_t)n, "directory_compat_utf8");
    if (!utf8 || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1,
                                      utf8, n, NULL, NULL)) {
        free(utf8);
        return NULL;
    }
    return utf8;
}

static void set_errno_from_win32(DWORD error)
{
    switch (error) {
    case ERROR_ALREADY_EXISTS: errno = EEXIST; break;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND: errno = ENOENT; break;
    case ERROR_ACCESS_DENIED: errno = EACCES; break;
    default: errno = EIO; break;
    }
}

int platform_directory_create(const char *path, int mode)
{
    (void)mode;
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) { errno = EINVAL; return -1; }
    BOOL ok = CreateDirectoryW(wide, NULL);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    free(wide);
    if (ok) return 0;
    set_errno_from_win32(error);
    return -1;
}

bool platform_directory_ensure(const char *path, int mode)
{
    if (platform_directory_create(path, mode) != 0 && errno != EEXIST)
        return false;
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) return false;
    HANDLE h = CreateFileW(wide, FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                           NULL);
    free(wide);
    if (h == INVALID_HANDLE_VALUE) return false;
    FILE_ATTRIBUTE_TAG_INFO info;
    bool ok = GetFileInformationByHandleEx(h, FileAttributeTagInfo,
                                           &info, sizeof(info)) &&
              (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
              (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    CloseHandle(h);
    return ok;
}

enum platform_directory_probe_result platform_directory_probe_real(
    const char *path)
{
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) {
        errno = EINVAL;
        return PLATFORM_DIRECTORY_PROBE_REFUSED;
    }
    HANDLE h = CreateFileW(wide, FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                               FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS |
                               FILE_FLAG_OPEN_REPARSE_POINT,
                           NULL);
    free(wide);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            errno = ENOENT;
            return PLATFORM_DIRECTORY_PROBE_MISSING;
        }
        set_errno_from_win32(error);
        return PLATFORM_DIRECTORY_PROBE_REFUSED;
    }
    FILE_ATTRIBUTE_TAG_INFO info;
    bool ok = GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info,
                                            sizeof(info)) &&
              (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
              (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    CloseHandle(h);
    if (ok) return PLATFORM_DIRECTORY_PROBE_OK;
    errno = ENOTDIR;
    return PLATFORM_DIRECTORY_PROBE_REFUSED;
}

static HANDLE open_real_directory_component(const wchar_t *path)
{
    HANDLE directory = CreateFileW(
        path, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    FILE_ATTRIBUTE_TAG_INFO info;
    if (directory == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(directory, FileAttributeTagInfo, &info,
                                      sizeof(info)) ||
        (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
        return INVALID_HANDLE_VALUE;
    }
    return directory;
}

bool platform_directory_canonical_real(const char *path, char *out,
                                       size_t out_size)
{
    wchar_t *input = utf8_to_wide(path);
    wchar_t full[32768], canonical[32768];
    if (!input || !out || !out_size) { free(input); return false; }
    DWORD count = GetFullPathNameW(input, 32768, full, NULL);
    free(input);
    if (!count || count >= 32768 || !full[0] || full[1] != L':' ||
        (full[2] != L'\\' && full[2] != L'/'))
        return false;
    for (wchar_t *p = full; *p; ++p)
        if (*p == L'/') *p = L'\\';
    for (wchar_t *p = full + 3; ; ++p) {
        if (*p != L'\\' && *p != L'\0') continue;
        wchar_t saved = *p;
        *p = L'\0';
        HANDLE component = open_real_directory_component(full);
        *p = saved;
        if (component == INVALID_HANDLE_VALUE) return false;
        if (saved == L'\0') {
            count = GetFinalPathNameByHandleW(
                component, canonical, 32768,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            CloseHandle(component);
            if (!count || count >= 32768) return false;
            const wchar_t *plain = wcsncmp(canonical, L"\\\\?\\", 4) == 0
                                       ? canonical + 4 : canonical;
            int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                             plain, -1, NULL, 0, NULL, NULL);
            return needed > 0 && (size_t)needed <= out_size &&
                   WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, plain,
                                       -1, out, (int)out_size, NULL, NULL) > 0;
        }
        CloseHandle(component);
    }
}

bool platform_directory_list_real_sorted(const char *path,
                                         struct platform_directory_list *out)
{
    if (!out) return false;
    *out = (struct platform_directory_list){0};
    wchar_t *root = utf8_to_wide(path);
    if (!root) return false;
    HANDLE root_handle = CreateFileW(
        root, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    FILE_ATTRIBUTE_TAG_INFO root_info;
    bool root_ok = root_handle != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(root_handle, FileAttributeTagInfo,
                                     &root_info, sizeof(root_info)) &&
        (root_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (root_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    free(root);
    if (!root_ok) {
        if (root_handle != INVALID_HANDLE_VALUE) CloseHandle(root_handle);
        return false;
    }
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) { CloseHandle(root_handle); return false; }
    size_t len = wcslen(wide);
    if (len > SIZE_MAX - 3) {
        free(wide);
        CloseHandle(root_handle);
        return false;
    }
    wchar_t *pattern = zcl_realloc(wide, (len + 3) * sizeof(*pattern),
                                   "directory_compat_pattern");
    if (!pattern) {
        free(wide);
        CloseHandle(root_handle);
        return false;
    }
    if (len && pattern[len - 1] != L'/' && pattern[len - 1] != L'\\')
        pattern[len++] = L'\\';
    pattern[len++] = L'*';
    pattern[len] = L'\0';

    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(pattern, &data);
    free(pattern);
    if (find == INVALID_HANDLE_VALUE) {
        CloseHandle(root_handle);
        return false;
    }
    bool ok = true;
    do {
        DWORD attrs = data.dwFileAttributes;
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            wcscmp(data.cFileName, L".") == 0 ||
            wcscmp(data.cFileName, L"..") == 0)
            continue;
        char *name = wide_to_utf8(data.cFileName);
        if (!name || !append_entry(out, name, NULL)) ok = false;
        free(name);
        if (!ok) break;
    } while (FindNextFileW(find, &data));
    DWORD error = GetLastError();
    FindClose(find);
    CloseHandle(root_handle);
    if (error != ERROR_NO_MORE_FILES) ok = false;
    if (!ok) { platform_directory_list_free(out); return false; }
    qsort(out->entries, out->count, sizeof(*out->entries), entry_compare);
    return true;
}

bool platform_directory_list_regular_sorted(
    const char *path, struct platform_directory_list *out)
{
    if (!out) return false;
    *out = (struct platform_directory_list){0};
    wchar_t *root = utf8_to_wide(path);
    if (!root) return false;
    HANDLE root_handle = CreateFileW(
        root, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION root_info = {0};
    bool root_ok = root_handle != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle(root_handle, &root_info) &&
        (root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    free(root);
    if (!root_ok) {
        if (root_handle != INVALID_HANDLE_VALUE) CloseHandle(root_handle);
        return false;
    }
    directory_query_fn query = directory_query_resolve();
    bool ok = query != NULL;
    const char *failure = ok ? NULL : "resolve NtQueryDirectoryFile";
    ULONG failure_status = 0;
    size_t failure_information = 0, failure_offset = 0;
    bool restart = true;
    unsigned char buffer[64 * 1024];
    while (ok) {
        IO_STATUS_BLOCK status = {0};
        NTSTATUS result = query(root_handle, NULL, NULL, NULL, &status,
                                buffer, sizeof(buffer),
                                FileIdBothDirectoryInformation, FALSE, NULL,
                                restart ? TRUE : FALSE);
        restart = false;
        if ((ULONG)result == 0x80000006u) break; /* STATUS_NO_MORE_FILES */
        bool partial = (ULONG)result == 0x80000005u; /* BUFFER_OVERFLOW */
        if ((result < 0 && !partial) || status.Information == 0 ||
            status.Information > sizeof(buffer)) {
            ok = false;
            failure = "query status or byte count";
            failure_status = (ULONG)result;
            failure_information = status.Information;
            break;
        }
        size_t offset = 0;
        for (;;) {
            const size_t record_bytes =
                offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
            if (status.Information - offset < record_bytes) {
                ok = false;
                failure = "short directory record";
                failure_information = status.Information;
                failure_offset = offset;
                break;
            }
            FILE_ID_BOTH_DIR_INFO *entry =
                (FILE_ID_BOTH_DIR_INFO *)(buffer + offset);
            size_t name_bytes = entry->FileNameLength;
            if ((name_bytes % sizeof(wchar_t)) != 0 ||
                name_bytes > status.Information - offset - record_bytes) {
                ok = false;
                failure = "invalid directory name span";
                failure_information = status.Information;
                failure_offset = offset;
                break;
            }
            DWORD attrs = entry->FileAttributes;
            if ((attrs & (FILE_ATTRIBUTE_DIRECTORY |
                          FILE_ATTRIBUTE_REPARSE_POINT)) == 0) {
                char *name = wide_span_to_utf8(
                    entry->FileName, name_bytes / sizeof(wchar_t));
                struct platform_directory_entry snapshot = {
                    .snapshot_valid = true,
                    .size = (uint64_t)entry->EndOfFile.QuadPart,
                    .volume = root_info.dwVolumeSerialNumber,
                    .file_low = (uint64_t)entry->FileId.QuadPart,
                    .file_high = 0,
                };
                windows_ticks_split(entry->LastWriteTime.QuadPart,
                                    &snapshot.modified_seconds,
                                    &snapshot.modified_nanoseconds);
                windows_ticks_split(entry->ChangeTime.QuadPart,
                                    &snapshot.changed_seconds,
                                    &snapshot.changed_nanoseconds);
                if (!name || !append_entry(out, name, &snapshot)) {
                    ok = false;
                    failure = "append directory record";
                    failure_information = status.Information;
                    failure_offset = offset;
                }
                free(name);
                if (!ok) break;
            }
            if (entry->NextEntryOffset == 0) break;
            if (entry->NextEntryOffset > status.Information - offset) {
                ok = false;
                failure = "invalid next directory record";
                failure_information = status.Information;
                failure_offset = offset;
                break;
            }
            offset += entry->NextEntryOffset;
        }
    }
    CloseHandle(root_handle);
    if (!ok) {
        fprintf(stderr, /* obs-ok:directory-compat-list-refusal */
                "[directory_compat] regular listing failed path=%s "
                "reason=%s ntstatus=0x%08lx information=%zu offset=%zu\n",
                path, failure ? failure : "unknown",
                (unsigned long)failure_status, failure_information,
                failure_offset);
        platform_directory_list_free(out);
        return false;
    }
    qsort(out->entries, out->count, sizeof(*out->entries), entry_compare);
    return true;
}

#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int platform_directory_create(const char *path, int mode)
{
    return mkdir(path, (mode_t)mode);
}

bool platform_directory_ensure(const char *path, int mode)
{
    if (mkdir(path, (mode_t)mode) != 0 && errno != EEXIST) return false;
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode);
}

enum platform_directory_probe_result platform_directory_probe_real(
    const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT || errno == ENOTDIR
                   ? PLATFORM_DIRECTORY_PROBE_MISSING
                   : PLATFORM_DIRECTORY_PROBE_REFUSED;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))
        return PLATFORM_DIRECTORY_PROBE_OK;
    errno = ENOTDIR;
    return PLATFORM_DIRECTORY_PROBE_REFUSED;
}

bool platform_directory_canonical_real(const char *path, char *out,
                                       size_t out_size)
{
    if (!path || !out || !out_size) return false;
    char *resolved = realpath(path, NULL);
    if (!resolved) return false;
    size_t length = strlen(resolved) + 1;
    bool ok = length <= out_size;
    if (ok) memcpy(out, resolved, length);
    free(resolved);
    return ok;
}

bool platform_directory_list_real_sorted(const char *path,
                                         struct platform_directory_list *out)
{
    if (!out) return false;
    *out = (struct platform_directory_list){0};
    struct stat root_st;
    if (lstat(path, &root_st) != 0 || !S_ISDIR(root_st.st_mode) ||
        S_ISLNK(root_st.st_mode))
        return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    int fd = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            ok = false;
            break;
        }
        if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) continue;
        if (!append_entry(out, entry->d_name, NULL)) { ok = false; break; }
    }
    if (closedir(dir) != 0) ok = false;
    if (!ok) { platform_directory_list_free(out); return false; }
    qsort(out->entries, out->count, sizeof(*out->entries), entry_compare);
    return true;
}

bool platform_directory_list_regular_sorted(
    const char *path, struct platform_directory_list *out)
{
    if (!out) return false;
    *out = (struct platform_directory_list){0};
    struct stat root_st;
    if (lstat(path, &root_st) != 0 || !S_ISDIR(root_st.st_mode) ||
        S_ISLNK(root_st.st_mode))
        return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    int fd = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            ok = false;
            break;
        }
        if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) continue;
        struct platform_directory_entry snapshot = {
            .snapshot_valid = true,
            .size = (uint64_t)st.st_size,
            .modified_seconds = (int64_t)st.st_mtime,
            .changed_seconds = (int64_t)st.st_ctime,
            .volume = (uint64_t)st.st_dev,
            .file_low = (uint64_t)st.st_ino,
            .file_high = 0,
        };
#if defined(__APPLE__)
        snapshot.modified_nanoseconds = (uint32_t)st.st_mtimespec.tv_nsec;
        snapshot.changed_nanoseconds = (uint32_t)st.st_ctimespec.tv_nsec;
#else
        snapshot.modified_nanoseconds = (uint32_t)st.st_mtim.tv_nsec;
        snapshot.changed_nanoseconds = (uint32_t)st.st_ctim.tv_nsec;
#endif
        if (!append_entry(out, entry->d_name, &snapshot)) {
            ok = false;
            break;
        }
    }
    if (closedir(dir) != 0) ok = false;
    if (!ok) { platform_directory_list_free(out); return false; }
    qsort(out->entries, out->count, sizeof(*out->entries), entry_compare);
    return true;
}
#endif
