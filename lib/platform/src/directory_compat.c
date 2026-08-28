/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/directory_compat.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int entry_compare(const void *a, const void *b)
{
    const struct platform_directory_entry *ea = a;
    const struct platform_directory_entry *eb = b;
    return strcmp(ea->name, eb->name);
}

static bool append_entry(struct platform_directory_list *list,
                         const char *name)
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
    next[list->count].name = zcl_malloc(name_size, "platform_directory_entry_name");
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
        if (!name || !append_entry(out, name)) ok = false;
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
        if (!append_entry(out, entry->d_name)) { ok = false; break; }
    }
    if (closedir(dir) != 0) ok = false;
    if (!ok) { platform_directory_list_free(out); return false; }
    qsort(out->entries, out->count, sizeof(*out->entries), entry_compare);
    return true;
}
#endif
