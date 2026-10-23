/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_store_fs — filesystem primitives for the local ZCODE package
 * store: recursive mkdir and delete, durable atomic writes, and the
 * open-time sweep of leftover temp files whose owner pid is gone. Split
 * out of package_store_io.c, which keeps layout, CAS presence and crash
 * recovery. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "package_store_priv.h"

#include "base/log_macros.h"
#include "platform/directory_compat.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <wchar.h>
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define STORE_LOG "vcs.store"

/* Join dir and name into child; false when the result does not fit. */
static bool store_sweep_child_path(const char *dir, const char *name,
                                   char *child, size_t child_size)
{
    int n = snprintf(child, child_size, "%s/%s", dir, name);
    return n > 0 && (size_t)n < child_size;
}

#if defined(_WIN32)
void store_set_errno(DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND: errno = ENOENT; break;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION: errno = EACCES; break;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS: errno = EEXIST; break;
    case ERROR_DIR_NOT_EMPTY: errno = ENOTEMPTY; break;
    default: errno = EIO; break;
    }
}

bool store_wide_path(const char *path, wchar_t out[STORE_PATH_MAX])
{
    int count = path ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                            path, -1, NULL, 0) : 0;
    return count > 0 && count <= (int)STORE_PATH_MAX &&
           MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out,
                               count) == count;
}

bool store_win32_real_directory(const wchar_t *path)
{
    HANDLE handle = CreateFileW(
        path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    FILE_ATTRIBUTE_TAG_INFO tag;
    bool ok = handle != INVALID_HANDLE_VALUE &&
              GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
                                            &tag, sizeof(tag)) &&
              (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
              (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    if (handle != INVALID_HANDLE_VALUE)
        CloseHandle(handle);
    return ok;
}

bool store_win32_delete_leaf(const wchar_t *path, DWORD attributes)
{
    if ((attributes & FILE_ATTRIBUTE_READONLY) != 0 &&
        !SetFileAttributesW(path, attributes & ~FILE_ATTRIBUTE_READONLY))
        return false;
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return RemoveDirectoryW(path) != 0;
    return DeleteFileW(path) != 0;
}

/* Build the wildcard pattern that lists the children of wide. */
static bool store_win32_child_pattern(const wchar_t *wide,
                                      wchar_t pattern[STORE_PATH_MAX])
{
    size_t len = wcslen(wide);
    if (len + 3 > STORE_PATH_MAX)
        return false;
    memcpy(pattern, wide, (len + 1) * sizeof(*wide));
    if (len && pattern[len - 1] != L'/' && pattern[len - 1] != L'\\')
        pattern[len++] = L'\\';
    pattern[len++] = L'*';
    pattern[len] = L'\0';
    return true;
}

static bool store_win32_rm_child(const wchar_t *wide,
                                 const WIN32_FIND_DATAW *entry)
{
    wchar_t child[STORE_PATH_MAX];
    int n = swprintf(child, STORE_PATH_MAX, L"%ls\\%ls", wide,
                     entry->cFileName);
    if (n <= 0 || (size_t)n >= STORE_PATH_MAX)
        return false;
    if ((entry->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return store_win32_delete_leaf(child, entry->dwFileAttributes);
    int utf8_count = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, child, -1, NULL, 0, NULL, NULL);
    char child_utf8[STORE_PATH_MAX];
    if (utf8_count <= 0 || utf8_count > (int)STORE_PATH_MAX ||
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, child, -1,
                            child_utf8, utf8_count, NULL, NULL) !=
            utf8_count)
        return false;
    return store_rm_rf(child_utf8);
}

/* Remove every child of wide that the pattern lists; false if any failed. */
static bool store_win32_rm_children(const wchar_t *wide,
                                    const wchar_t *pattern)
{
    WIN32_FIND_DATAW entry;
    HANDLE find = FindFirstFileW(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool ok = true;
    do {
        if (wcscmp(entry.cFileName, L".") == 0 ||
            wcscmp(entry.cFileName, L"..") == 0)
            continue;
        if (!store_win32_rm_child(wide, &entry))
            ok = false;
    } while (FindNextFileW(find, &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        ok = false;
    FindClose(find);
    return ok;
}

static bool store_rm_rf_win32(const char *path)
{
    wchar_t wide[STORE_PATH_MAX];
    if (!store_wide_path(path, wide))
        return false;
    DWORD attrs = GetFileAttributesW(wide);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            return true;
        store_set_errno(error);
        return false;
    }
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return store_win32_delete_leaf(wide, attrs);
    if (!store_win32_real_directory(wide))
        return false;
    wchar_t pattern[STORE_PATH_MAX];
    if (!store_win32_child_pattern(wide, pattern))
        return false;
    bool ok = store_win32_rm_children(wide, pattern);
    if (!store_win32_delete_leaf(wide, attrs))
        ok = false;
    return ok;
}

/* Temp and final wide paths for an atomic write. The temp name carries the
 * owner pid and a process-wide sequence number. */
static bool store_temp_names_win32(const char *path, uint64_t seq,
                                   char tmp[STORE_PATH_MAX],
                                   wchar_t wide_tmp[STORE_PATH_MAX],
                                   wchar_t wide_path[STORE_PATH_MAX])
{
    int tn = snprintf(tmp, STORE_PATH_MAX, "%s%s.%lu.%llu", path,
                      STORE_TEMP_SUFFIX, (unsigned long)GetCurrentProcessId(),
                      (unsigned long long)seq);
    return tn > 0 && (size_t)tn < STORE_PATH_MAX &&
           store_wide_path(tmp, wide_tmp) && store_wide_path(path, wide_path);
}

static bool store_write_all_win32(HANDLE file, const uint8_t *data,
                                  size_t data_len)
{
    size_t off = 0;
    while (off < data_len) {
        DWORD amount = data_len - off > UINT32_MAX
                           ? UINT32_MAX
                           : (DWORD)(data_len - off);
        DWORD written = 0;
        if (!WriteFile(file, data + off, amount, &written, NULL) ||
            written == 0)
            return false;
        off += written;
    }
    return true;
}

/* Write, flush, close and rename. Each later step runs only while ok still
 * holds, and the close is always attempted, as before the split. */
static bool store_publish_temp_win32(HANDLE file, const uint8_t *data,
                                     size_t data_len,
                                     const wchar_t *wide_tmp,
                                     const wchar_t *wide_path)
{
    bool ok = store_write_all_win32(file, data, data_len);
    if (ok && !atomic_load(&g_store_deferred_sync))
        ok = FlushFileBuffers(file) != 0;
    if (!CloseHandle(file))
        ok = false;
    if (ok)
        ok = MoveFileExW(wide_tmp, wide_path,
                         MOVEFILE_REPLACE_EXISTING |
                             MOVEFILE_WRITE_THROUGH) != 0;
    return ok;
}

/* Live when the owner named in the temp suffix still runs. */
static bool store_temp_live_win32(const char *owner_text)
{
    unsigned long owner = 0;
    unsigned long long sequence = 0;
    int consumed = 0;
    bool live = false;
    if (owner_text &&
        sscanf(owner_text + sizeof(STORE_TEMP_SUFFIX), "%lu.%llu%n", &owner,
               &sequence, &consumed) == 2 &&
        owner > 0 && owner_text[sizeof(STORE_TEMP_SUFFIX) + consumed] == '\0') {
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)owner);
        if (process) {
            DWORD exit_code = 0;
            live = GetExitCodeProcess(process, &exit_code) &&
                   exit_code == STILL_ACTIVE;
            CloseHandle(process);
        } else {
            live = GetLastError() == ERROR_ACCESS_DENIED;
        }
    }
    (void)sequence;
    return live;
}

/* Delete a leftover temp file whose owner is gone; true when it was removed. */
static bool store_sweep_stale_win32(const char *dir, const char *name,
                                    char *child, size_t child_size)
{
    const char *owner_text = strstr(name, STORE_TEMP_SUFFIX ".");
    if (!owner_text || store_temp_live_win32(owner_text))
        return false;
    if (!store_sweep_child_path(dir, name, child, child_size))
        return false;
    wchar_t wide[STORE_PATH_MAX];
    return store_wide_path(child, wide) && DeleteFileW(wide) != 0;
}
#endif

#if !defined(_WIN32)
static bool store_mkdir_real(const char *path)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        LOG_FAIL(STORE_LOG, "create store directory %s: %s", path,
                 strerror(errno));
    struct stat st;
    if (lstat(path, &st) != 0)
        LOG_FAIL(STORE_LOG, "inspect store directory %s: %s", path,
                 strerror(errno));
    if (!S_ISDIR(st.st_mode))
        LOG_FAIL(STORE_LOG, "store path is not a real directory: %s", path);
    return true;
}
#endif

#if defined(_WIN32)
static bool store_mkdir_p_win32(const char *path)
{
    wchar_t wide[STORE_PATH_MAX];
    if (!store_wide_path(path, wide) || !wide[0])
        return false;
    for (wchar_t *p = wide + 1; ; p++) {
        if (*p != L'/' && *p != L'\\' && *p != L'\0')
            continue;
        wchar_t saved = *p;
        if (p == wide + 2 && wide[1] == L':') {
            if (saved == L'\0')
                return store_win32_real_directory(wide);
            continue;
        }
        *p = L'\0';
        bool created = CreateDirectoryW(wide, NULL) != 0;
        DWORD error = created ? ERROR_SUCCESS : GetLastError();
        bool ok = (created || error == ERROR_ALREADY_EXISTS) &&
                  store_win32_real_directory(wide);
        *p = saved;
        if (!ok)
            return false;
        if (saved == L'\0')
            return true;
    }
}
#else
static bool store_mkdir_p_posix(const char *path)
{
    char buf[STORE_PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (!store_mkdir_real(buf))
            return false;
        *p = '/';
    }
    return store_mkdir_real(buf);
}
#endif

bool store_mkdir_p(const char *path)
{
#if defined(_WIN32)
    return store_mkdir_p_win32(path);
#else
    return store_mkdir_p_posix(path);
#endif
}

#if !defined(_WIN32)
static bool store_rm_rf_posix(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[STORE_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!store_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
}
#endif

bool store_rm_rf(const char *path)
{
#if defined(_WIN32)
    return store_rm_rf_win32(path);
#else
    return store_rm_rf_posix(path);
#endif
}

#if !defined(_WIN32)
/* Write all of data; false leaves errno from the failing write(). */
static bool store_write_all_posix(int fd, const uint8_t *data,
                                  size_t data_len)
{
    size_t off = 0;
    while (off < data_len) {
        ssize_t w = write(fd, data + off, data_len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        off += (size_t)w;
    }
    return true;
}

/* Durable sync of the temp file, skipped in deferred-sync mode. */
static bool store_temp_synced_posix(int fd)
{
    return atomic_load(&g_store_deferred_sync) || fsync(fd) == 0;
}
#endif

bool store_atomic_write(const char *path, const uint8_t *data,
                        size_t data_len)
{
    static _Atomic uint64_t g_seq = 0;
    uint64_t seq = atomic_fetch_add(&g_seq, 1);
#if defined(_WIN32)
    char tmp[STORE_PATH_MAX];
    wchar_t wide_tmp[STORE_PATH_MAX], wide_path[STORE_PATH_MAX];
    if (!store_temp_names_win32(path, seq, tmp, wide_tmp, wide_path))
        LOG_FAIL(STORE_LOG, "temp path too long for %s", path);
    HANDLE file = CreateFileW(wide_tmp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL |
                                  FILE_FLAG_WRITE_THROUGH,
                              NULL);
    if (file == INVALID_HANDLE_VALUE)
        LOG_FAIL(STORE_LOG, "open temp %s: Win32 error %lu", tmp,
                 (unsigned long)GetLastError());
    if (!store_publish_temp_win32(file, data, data_len, wide_tmp, wide_path)) {
        DWORD error = GetLastError();
        (void)DeleteFileW(wide_tmp);
        LOG_FAIL(STORE_LOG, "durable write %s: Win32 error %lu", path,
                 (unsigned long)error);
    }
    return true;
#else
    char tmp[STORE_PATH_MAX];
    int tn = snprintf(tmp, sizeof(tmp), "%s%s.%ld.%llu", path,
                      STORE_TEMP_SUFFIX, (long)getpid(),
                      (unsigned long long)seq);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        LOG_FAIL(STORE_LOG, "temp path too long for %s", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(STORE_LOG, "open temp %s: %s", tmp, strerror(errno));
    if (!store_write_all_posix(fd, data, data_len)) {
        close(fd);
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "write temp %s: %s", tmp, strerror(errno));
    }
    if (!store_temp_synced_posix(fd)) {
        close(fd);
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "fsync temp %s: %s", tmp, strerror(errno));
    }
    if (close(fd) != 0) {
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "close temp %s: %s", tmp, strerror(errno));
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "rename %s -> %s: %s", tmp, path,
                 strerror(errno));
    }
    return true;
#endif
}

#if !defined(_WIN32)
enum store_sweep_kind { STORE_SWEEP_SKIP, STORE_SWEEP_DIR, STORE_SWEEP_TEMP };

/* Classify one readdir entry: recurse into a directory, or flag a regular
 * file whose name carries the temp suffix. child receives the full path. */
static enum store_sweep_kind store_sweep_classify_posix(const char *dir,
                                                        const char *name,
                                                        char *child,
                                                        size_t child_size)
{
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return STORE_SWEEP_SKIP;
    if (!store_sweep_child_path(dir, name, child, child_size))
        return STORE_SWEEP_SKIP;
    struct stat st;
    if (lstat(child, &st) != 0)
        return STORE_SWEEP_SKIP;
    if (S_ISDIR(st.st_mode))
        return STORE_SWEEP_DIR;
    return strstr(name, STORE_TEMP_SUFFIX ".") != NULL ? STORE_SWEEP_TEMP
                                                       : STORE_SWEEP_SKIP;
}

/* Live when the owner named in the temp suffix still runs. */
static bool store_temp_owned_live_posix(const char *name)
{
    const char *owner_text = strstr(name, STORE_TEMP_SUFFIX ".");
    long owner = 0;
    unsigned long long sequence = 0;
    int consumed = 0;
    bool owned_by_live_process = owner_text &&
        sscanf(owner_text + sizeof(STORE_TEMP_SUFFIX), "%ld.%llu%n", &owner,
               &sequence, &consumed) == 2 &&
        owner > 0 && owner_text[sizeof(STORE_TEMP_SUFFIX) + consumed] == '\0' &&
        (kill((pid_t)owner, 0) == 0 || errno == EPERM);
    (void)sequence;
    return owned_by_live_process;
}
#endif

void store_sweep_temps(struct vcs_package_store *store,
                              const char *dir)
{
#if defined(_WIN32)
    (void)store;
    struct platform_directory_list dirs = {0};
    struct platform_directory_list files = {0};
    if (!platform_directory_list_real_sorted(dir, &dirs))
        return;
    for (size_t i = 0; i < dirs.count; i++) {
        char child[STORE_PATH_MAX];
        if (store_sweep_child_path(dir, dirs.entries[i].name, child,
                                   sizeof(child)))
            store_sweep_temps(store, child);
    }
    platform_directory_list_free(&dirs);
    if (!platform_directory_list_regular_sorted(dir, &files))
        return;
    for (size_t i = 0; i < files.count; i++) {
        char child[STORE_PATH_MAX];
        if (store_sweep_stale_win32(dir, files.entries[i].name, child,
                                    sizeof(child)))
            LOG_INFO(STORE_LOG, "swept leftover temp %s", child);
    }
    platform_directory_list_free(&files);
#else
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        char child[STORE_PATH_MAX];
        enum store_sweep_kind kind = store_sweep_classify_posix(
            dir, ent->d_name, child, sizeof(child));
        if (kind == STORE_SWEEP_DIR) {
            store_sweep_temps(store, child);
        } else if (kind == STORE_SWEEP_TEMP &&
                   !store_temp_owned_live_posix(ent->d_name) &&
                   unlink(child) == 0) {
            LOG_INFO(STORE_LOG, "swept leftover temp %s", child);
        }
    }
    closedir(d);
#endif
}

