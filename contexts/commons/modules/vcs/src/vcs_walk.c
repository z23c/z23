/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_walk — implementation. See vcs_walk.h. */

#include "vcs_walk.h"

#include "vcs/vcs_object.h"
#include "vcs_priv.h"

#include "platform/positioned_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <sys/stat.h>
#else
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct walk_ctx {
    const char  *repo_root;
    vcs_walk_cb  cb;
    void        *user;
    bool         aborted;
};

#if defined(_WIN32)
typedef NTSTATUS (NTAPI *walk_nt_create_file_fn)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *walk_nt_query_directory_file_fn)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

static bool walk_nt_functions(walk_nt_create_file_fn *create_file,
                              walk_nt_query_directory_file_fn *query_directory)
{
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC create_symbol = module ? GetProcAddress(module, "NtCreateFile") : NULL;
    FARPROC query_symbol = module
        ? GetProcAddress(module, "NtQueryDirectoryFile") : NULL;
    if (!create_symbol || !query_symbol) return false;
    static_assert(sizeof(*create_file) == sizeof(create_symbol));
    static_assert(sizeof(*query_directory) == sizeof(query_symbol));
    memcpy(create_file, &create_symbol, sizeof(*create_file));
    memcpy(query_directory, &query_symbol, sizeof(*query_directory));
    return true;
}

static bool walk_utf8_root(const char *path, wchar_t out[32768])
{
    if (!path || !path[0]) return false;
    wchar_t plain[32768];
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                    plain, 32768);
    if (count <= 0) return false;
    for (int i = 0; i < count - 1; ++i)
        if (plain[i] == L'/') plain[i] = L'\\';
    if (wcsncmp(plain, L"\\\\?\\", 4) == 0) {
        wmemcpy(out, plain, (size_t)count);
        return true;
    }
    if (plain[0] == L'\\' && plain[1] == L'\\') {
        if ((size_t)count + 6u >= 32768u) return false;
        wmemcpy(out, L"\\\\?\\UNC\\", 8);
        wmemcpy(out + 8, plain + 2, (size_t)count - 2u);
        return true;
    }
    if (plain[0] && plain[1] == L':' && plain[2] == L'\\') {
        if ((size_t)count + 4u >= 32768u) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, plain, (size_t)count);
        return true;
    }
    wmemcpy(out, plain, (size_t)count);
    return true;
}

static HANDLE walk_open_child(HANDLE parent, const char *name,
                              walk_nt_create_file_fn create_file,
                              bool *vanished)
{
    if (vanished) *vanished = false;
    wchar_t wide[260];
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1,
                                    wide, 260);
    if (count <= 1 || strchr(name, '/') || strchr(name, '\\') ||
        !strcmp(name, ".") || !strcmp(name, ".."))
        return INVALID_HANDLE_VALUE;
    UNICODE_STRING leaf = {
        .Length = (USHORT)((count - 1) * (int)sizeof(wchar_t)),
        .MaximumLength = (USHORT)((count - 1) * (int)sizeof(wchar_t)),
        .Buffer = wide,
    };
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &leaf, OBJ_CASE_INSENSITIVE,
                               parent, NULL);
    IO_STATUS_BLOCK status = {0};
    HANDLE child = INVALID_HANDLE_VALUE;
    NTSTATUS result = create_file(
        &child, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &status, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (result >= 0) return child;
    if (vanished)
        *vanished = (ULONG)result == 0xC0000034u ||
                    (ULONG)result == 0xC000003Au ||
                    (ULONG)result == 0xC0000056u;
    return INVALID_HANDLE_VALUE;
}

static bool walk_append_name(char ***names, size_t *count, const wchar_t *wide,
                             int wide_count)
{
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide,
                                    wide_count, NULL, 0, NULL, NULL);
    if (bytes <= 0 || *count >= SIZE_MAX / sizeof(**names)) return false;
    char *name = zcl_malloc((size_t)bytes + 1u, "vcs_walk_win_name");
    char **grown = name ? zcl_realloc(
        *names, (*count + 1u) * sizeof(**names), "vcs_walk_win_names") : NULL;
    if (!grown) {
        free(name);
        return false;
    }
    *names = grown;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, wide_count,
                            name, bytes, NULL, NULL) != bytes) {
        free(name);
        return false;
    }
    name[bytes] = 0;
    (*names)[(*count)++] = name;
    return true;
}

static int walk_name_compare(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

static bool walk_windows_time(LARGE_INTEGER value, int64_t *nanoseconds)
{
    constexpr int64_t epoch = INT64_C(116444736000000000);
    if (!nanoseconds || value.QuadPart < epoch ||
        value.QuadPart - epoch > INT64_MAX / 100)
        return false;
    *nanoseconds = (value.QuadPart - epoch) * 100;
    return true;
}

/* An enumeration yielding no non-dot entries reaches the sort with
 * names == NULL and count == 0 (qsort's base is declared nonnull — UB
 * for a no-op sort). Keep the guard in the small sorting helper. */
static void walk_names_sort(char **names, size_t count)
{
    if (count > 1)
        qsort(names, count, sizeof(*names), walk_name_compare);
}

static bool walk_windows_names(HANDLE directory,
    walk_nt_query_directory_file_fn query_directory, char ***names, size_t *count)
{
    bool restart = true, ok = true;
    unsigned char buffer[16384];
    for (;;) {
        IO_STATUS_BLOCK status = {0};
        NTSTATUS result = query_directory(
            directory, NULL, NULL, NULL, &status, buffer, sizeof(buffer),
            FileIdBothDirectoryInformation, FALSE, NULL, restart ? TRUE : FALSE);
        restart = false;
        if ((ULONG)result == 0x80000006u) break;
        if (result < 0 || status.Information == 0) { ok = false; break; }
        FILE_ID_BOTH_DIR_INFO *entry = (FILE_ID_BOTH_DIR_INFO *)buffer;
        for (;;) {
            int chars = (int)(entry->FileNameLength / sizeof(wchar_t));
            bool dot = (chars == 1 && entry->FileName[0] == L'.') ||
                (chars == 2 && entry->FileName[0] == L'.' &&
                 entry->FileName[1] == L'.');
            if (!dot && !walk_append_name(names, count, entry->FileName, chars)) {
                ok = false;
                break;
            }
            if (!entry->NextEntryOffset) break;
            entry = (FILE_ID_BOTH_DIR_INFO *)
                ((unsigned char *)entry + entry->NextEntryOffset);
        }
        if (!ok) break;
    }
    return ok;
}

static bool walk_windows_file(struct walk_ctx *w, const char *childrel,
    const BY_HANDLE_FILE_INFORMATION *file_info, const FILE_BASIC_INFO *file_basic)
{
    BY_HANDLE_FILE_INFORMATION info = *file_info;
    FILE_BASIC_INFO basic = *file_basic;
    bool ok = true;
    uint64_t size = ((uint64_t)info.nFileSizeHigh << 32) |
                    info.nFileSizeLow;
    uint32_t mode = (uint32_t)(_S_IFREG | _S_IREAD);
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
        mode |= (uint32_t)_S_IWRITE;
    int64_t modified = 0, changed = 0;
    if (!walk_windows_time(basic.LastWriteTime, &modified) ||
        !walk_windows_time(basic.ChangeTime, &changed)) {
        ok = false;
    } else if (!w->cb(childrel, mode, size,
                      modified, changed, w->user)) {
        w->aborted = true;
    }
    return ok;
}

static bool walk_dir_windows(struct walk_ctx *w, HANDLE directory,
                             const char *rel,
                             walk_nt_create_file_fn create_file,
                             walk_nt_query_directory_file_fn query_directory);

static bool walk_windows_child(struct walk_ctx *w, HANDLE directory,
    const char *name, const char *childrel, walk_nt_create_file_fn create_file,
    walk_nt_query_directory_file_fn query_directory)
{
    bool ok = true;
    bool vanished = false;
    HANDLE child = walk_open_child(directory, name, create_file,
                                   &vanished);
    BY_HANDLE_FILE_INFORMATION info = {0};
    FILE_BASIC_INFO basic = {0};
    if (child == INVALID_HANDLE_VALUE) {
        return vanished;
    }
    if (!GetFileInformationByHandle(child, &info) ||
        !GetFileInformationByHandleEx(child, FileBasicInfo, &basic,
                                       sizeof(basic))) {
        CloseHandle(child);
        return false;
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        CloseHandle(child);
        return true;
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        ok = walk_dir_windows(w, child, childrel, create_file,
                              query_directory);
    } else if (GetFileType(child) == FILE_TYPE_DISK) {
        ok = walk_windows_file(w, childrel, &info, &basic);
    }
    CloseHandle(child);
    return ok;
}

static bool walk_dir_windows(struct walk_ctx *w, HANDLE directory,
                             const char *rel,
                             walk_nt_create_file_fn create_file,
                             walk_nt_query_directory_file_fn query_directory)
{
    char **names = NULL;
    size_t count = 0;
    bool ok = walk_windows_names(directory, query_directory, &names, &count);
    walk_names_sort(names, count);
    for (size_t i = 0; i < count && ok && !w->aborted; ++i) {
        char childrel[4096];
        int n = rel[0] ? snprintf(childrel, sizeof(childrel), "%s/%s", rel,
                                  names[i])
                       : snprintf(childrel, sizeof(childrel), "%s", names[i]);
        if (n <= 0 || (size_t)n >= sizeof(childrel) ||
            vcs_path_ignored(childrel))
            continue;
        ok = walk_windows_child(w, directory, names[i], childrel,
                                 create_file, query_directory);
    }
    for (size_t i = 0; i < count; ++i) free(names[i]);
    free(names);
    return ok;
}

#else
static bool walk_dir(struct walk_ctx *w, const char *rel);

/* Collect an open directory's entry names, skipping "." and "..". */
static bool walk_read_dir_names(DIR *d, char ***names, size_t *ncount)
{
    size_t ncap = 0;
    struct dirent *de;
    bool ok = true;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (*ncount == ncap) {
            size_t ncap2 = ncap ? ncap * 2 : 64;
            char **nn = zcl_realloc(*names, ncap2 * sizeof(*nn), "vcs_walk_names");
            if (!nn) { ok = false; break; }
            *names = nn;
            ncap = ncap2;
        }
        (*names)[*ncount] = zcl_strdup(de->d_name, "vcs_walk_name");
        if (!(*names)[*ncount]) { ok = false; break; }
        (*ncount)++;
    }
    return ok;
}

static void walk_sort_names(char **names, size_t ncount)
{
    /* deterministic order */
    for (size_t i = 0; i + 1 < ncount; i++)
        for (size_t j = i + 1; j < ncount; j++)
            if (strcmp(names[i], names[j]) > 0) {
                char *t = names[i]; names[i] = names[j]; names[j] = t;
            }
}

/* Free ncount names and the array holding them. */
static void walk_free_names(char **names, size_t ncount)
{
    for (size_t i = 0; i < ncount; i++) free(names[i]);
    free(names);
}

/* Visit one child name; false only when a recursive descent failed. */
static bool walk_visit_child(struct walk_ctx *w, const char *rel,
                             const char *name)
{
    char childrel[4096];
    int cn;
    if (rel[0])
        cn = snprintf(childrel, sizeof(childrel), "%s/%s", rel, name);
    else
        cn = snprintf(childrel, sizeof(childrel), "%s", name);
    if (cn <= 0 || (size_t)cn >= sizeof(childrel))
        return true;  /* skip pathological over-long names */

    if (vcs_path_ignored(childrel))
        return true;

    char childfull[4096];
    int cfn = snprintf(childfull, sizeof(childfull), "%s/%s",
                       w->repo_root, childrel);
    if (cfn <= 0 || (size_t)cfn >= sizeof(childfull))
        return true;

    struct stat st;
    if (lstat(childfull, &st) != 0)
        return true;  /* vanished mid-walk; skip */

    if (S_ISDIR(st.st_mode)) {
        return walk_dir(w, childrel);
    } else if (S_ISREG(st.st_mode)) {
        int64_t mtime_ns = (int64_t)st.st_mtim.tv_sec * 1000000000 +
                           st.st_mtim.tv_nsec;
        int64_t ctime_ns = (int64_t)st.st_ctim.tv_sec * 1000000000 +
                           st.st_ctim.tv_nsec;
        if (!w->cb(childrel, (uint32_t)st.st_mode, (uint64_t)st.st_size,
                   mtime_ns, ctime_ns, w->user)) {
            w->aborted = true;
        }
    }
    /* symlinks / fifos / sockets: not tracked in v1 */
    return true;
}

/* Recurse into <repo_root>/<rel> (rel="" for the root). */
static bool walk_dir(struct walk_ctx *w, const char *rel)
{
    char full[4096];
    int n;
    if (rel[0])
        n = snprintf(full, sizeof(full), "%s/%s", w->repo_root, rel);
    else
        n = snprintf(full, sizeof(full), "%s", w->repo_root);
    if (n <= 0 || (size_t)n >= sizeof(full))
        LOG_FAIL("vcs", "walk path too long");

    DIR *d = opendir(full);
    if (!d)
        LOG_FAIL("vcs", "opendir %s: %s", full, strerror(errno));

    /* Collect names first (sorted) so the walk order is deterministic. */
    char **names = NULL;
    size_t ncount = 0;
    bool ok = walk_read_dir_names(d, &names, &ncount);
    closedir(d);
    if (!ok) {
        walk_free_names(names, ncount);
        LOG_FAIL("vcs", "readdir alloc failed");
    }

    walk_sort_names(names, ncount);

    for (size_t i = 0; i < ncount && ok && !w->aborted; i++) {
        if (!walk_visit_child(w, rel, names[i]))
            ok = false;
    }

    walk_free_names(names, ncount);
    return ok;
}
#endif

bool vcs_walk_tracked(const char *repo_root, vcs_walk_cb cb, void *user)
{
    if (!repo_root || !cb)
        LOG_FAIL("vcs", "null arg to walk_tracked");
#if defined(_WIN32)
    wchar_t root_path[32768];
    walk_nt_create_file_fn create_file = NULL;
    walk_nt_query_directory_file_fn query_directory = NULL;
    if (!walk_utf8_root(repo_root, root_path) ||
        !walk_nt_functions(&create_file, &query_directory))
        return false;
    HANDLE root = CreateFileW(
        root_path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    BY_HANDLE_FILE_INFORMATION info = {0};
    if (root == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(root, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (root != INVALID_HANDLE_VALUE) CloseHandle(root);
        return false;
    }
    struct walk_ctx w = {repo_root, cb, user, false};
    bool ok = walk_dir_windows(&w, root, "", create_file, query_directory);
    CloseHandle(root);
    return ok && !w.aborted;
#else
    struct walk_ctx w = { repo_root, cb, user, false };
    if (!walk_dir(&w, ""))
        return false;
    return !w.aborted;
#endif
}

static bool blob_snapshot_same(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

bool vcs_blob_hash_file(const char *repo_root, const char *relpath,
                        uint8_t out[32])
{
    if (!repo_root || !relpath || !out)
        LOG_FAIL("vcs", "null arg to blob_hash_file");
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, repo_root, relpath) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return false;
    }

    uint8_t tag = VCS_TAG_BLOB;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);

    unsigned char buf[65536];
    uint64_t offset = 0;
    bool ok = true;
    while (offset < before.size) {
        size_t want = before.size - offset > sizeof(buf)
                          ? sizeof(buf) : (size_t)(before.size - offset);
        int64_t r = platform_positioned_file_read(&file, buf, want, offset);
        if (r <= 0) { ok = false; break; }
        if (r == 0)
            break;
        sha3_256_write(&ctx, buf, (size_t)r);
        offset += (uint64_t)r;
    }
    ok = ok && offset == before.size &&
         platform_positioned_file_snapshot(&file, &after) &&
         blob_snapshot_same(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) return false;
    sha3_256_finalize(&ctx, out);
    return true;
}
