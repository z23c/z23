/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Windows acceptance for the retained-directory SQLite VFS
 * (engine/modules/storage/src/sqlite_vfs_dir_windows.c): proves a WAL-mode database
 * served through the handle-bound VFS end to end — writer plus an independent
 * read-only connection through the same VFS (exercising the shared-memory
 * wal-index), sibling containment, handle-binding under a rename-the-path
 * decoy attack, leaf-name escape refusal, reparse-point refusal, and
 * unregister-while-open refcounting — in a real owner-private temp fixture.
 *
 * The attack step renames the datadir's PARENT, not the datadir itself: NT
 * refuses to rename a directory while it has relative-open children (the
 * child file objects hold a RelatedFileObject link to it), and refuses to
 * rename any ancestor of an open handle — both verified empirically on this
 * build. The acceptance therefore asserts that kernel-level containment as
 * the primary arm, and runs the classic decoy-directory proof as the
 * alternative arm should a future Windows ever permit the rename. */
#if defined(_WIN32)

#include "platform/private_directory.h"
#include "storage/sqlite_vfs_dir.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT 0x000900A4u
#endif
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003u
#endif
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2u
#endif

static int fail(const char *message)
{
    fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: %s\n", message);
    return 1;
}

static void sqlite_log_echo(void *context, int rc, const char *message)
{
    (void)context;
    fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: [sqlite rc=%d] %s\n",
            rc, message);
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

/* Write a fresh file with `size` bytes of `seed`-derived content. */
static bool write_seeded_file(const wchar_t *path, uint8_t seed, size_t size)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    uint8_t block[64];
    for (size_t i = 0; i < sizeof(block); ++i)
        block[i] = (uint8_t)(seed + i);
    bool ok = true;
    size_t left = size;
    while (ok && left > 0) {
        DWORD chunk = left < sizeof(block) ? (DWORD)left : (DWORD)sizeof(block);
        DWORD wrote = 0;
        ok = WriteFile(file, block, chunk, &wrote, NULL) && wrote == chunk;
        left -= wrote;
    }
    ok = ok && FlushFileBuffers(file);
    return CloseHandle(file) && ok;
}

static bool file_matches_seed(const wchar_t *path, uint8_t seed, size_t size)
{
    HANDLE file = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    uint8_t block[64];
    bool same = true;
    size_t done = 0;
    while (same && done < size) {
        DWORD want = size - done < sizeof(block) ? (DWORD)(size - done)
                                                 : (DWORD)sizeof(block);
        DWORD got = 0;
        if (!ReadFile(file, block, want, &got, NULL) || got != want)
            same = false;
        for (DWORD i = 0; same && i < got; ++i)
            if (block[i] != (uint8_t)(seed + (done + i) % 64))
                same = false;
        done += got;
    }
    CloseHandle(file);
    return same && done == size;
}

/* Every entry under `root` must be in the allowed family, and every required
 * leaf must be present. */
static bool dir_family_exact(const wchar_t *root,
                             const wchar_t *const *required,
                             size_t required_count,
                             const wchar_t *const *allowed,
                             size_t allowed_count)
{
    wchar_t pattern[MAX_PATH];
    if (!append_leaf(pattern, sizeof(pattern) / sizeof(pattern[0]), root,
                     L"*"))
        return false;
    WIN32_FIND_DATAW found;
    HANDLE scan = FindFirstFileW(pattern, &found);
    if (scan == INVALID_HANDLE_VALUE)
        return false;
    bool ok = true;
    do {
        if (!wcscmp(found.cFileName, L".") || !wcscmp(found.cFileName, L".."))
            continue;
        bool listed = false;
        for (size_t i = 0; i < allowed_count; ++i)
            if (!wcscmp(found.cFileName, allowed[i]))
                listed = true;
        if (!listed)
            ok = false;
    } while (ok && FindNextFileW(scan, &found));
    FindClose(scan);
    for (size_t i = 0; ok && i < required_count; ++i) {
        wchar_t path[MAX_PATH];
        if (!append_leaf(path, sizeof(path) / sizeof(path[0]), root,
                         required[i]) ||
            path_absent(path))
            ok = false;
    }
    return ok;
}

static int count_rows(sqlite3 *db, int *count)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM t", -1, &stmt,
                           NULL) != SQLITE_OK)
        return SQLITE_ERROR;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        *count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW ? SQLITE_OK : SQLITE_ERROR;
}

static bool exec_ok(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: exec failed "
                "(%s): %s\n", sql, error ? error : "(no message)");
        sqlite3_free(error);
    }
    return rc == SQLITE_OK;
}

/* Build a mount-point (junction) reparse point at `link` targeting `target`.
 * Junctions need no privilege, so this is the reparse fixture fallback when
 * unprivileged file symlinks are unavailable. */
static bool create_junction(const wchar_t *link, const wchar_t *target)
{
    /* CreateFile with CREATE_NEW would create a plain file even with
     * FILE_FLAG_BACKUP_SEMANTICS, so the link directory must exist first. */
    if (!CreateDirectoryW(link, NULL)) {
        fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: junction mkdir "
                "failed: win32=%lu\n", (unsigned long)GetLastError());
        return false;
    }
    HANDLE dir = CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS
                                 | FILE_FLAG_OPEN_REPARSE_POINT,
                             NULL);
    if (dir == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: junction open "
                "failed: win32=%lu\n", (unsigned long)GetLastError());
        RemoveDirectoryW(link);
        return false;
    }
    wchar_t substitute[32768];
    int sub_chars = swprintf(substitute,
        sizeof(substitute) / sizeof(substitute[0]), L"\\??\\%ls", target);
    if (sub_chars <= 0) {
        CloseHandle(dir);
        return false;
    }
    size_t sub_bytes = (size_t)sub_chars * sizeof(wchar_t);
    size_t print_bytes = wcslen(target) * sizeof(wchar_t);
    struct {
        ULONG tag;
        USHORT data_length;
        USHORT reserved;
        USHORT sub_offset;
        USHORT sub_length;
        USHORT print_offset;
        USHORT print_length;
        WCHAR paths[2048];
    } buffer;
    if (sub_bytes + 2 + print_bytes + 2 > sizeof(buffer.paths)) {
        CloseHandle(dir);
        return false;
    }
    buffer.tag = IO_REPARSE_TAG_MOUNT_POINT;
    buffer.reserved = 0;
    buffer.sub_offset = 0;
    buffer.sub_length = (USHORT)sub_bytes;
    buffer.print_offset = (USHORT)(sub_bytes + 2);
    buffer.print_length = (USHORT)print_bytes;
    buffer.data_length = (USHORT)(8 + buffer.print_offset + print_bytes + 2);
    memset(buffer.paths, 0, sizeof(buffer.paths));
    memcpy(buffer.paths, substitute, sub_bytes);
    memcpy((char *)buffer.paths + buffer.print_offset, target, print_bytes);
    DWORD returned = 0;
    bool ok = DeviceIoControl(dir, FSCTL_SET_REPARSE_POINT, &buffer,
                              8 + buffer.data_length, NULL, 0, &returned,
                              NULL) != 0;
    if (!ok)
        fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: junction "
                "FSCTL_SET_REPARSE_POINT failed: win32=%lu\n",
                (unsigned long)GetLastError());
    CloseHandle(dir);
    return ok;
}

static const wchar_t *const wal_family[] = {
    L"accept.db", L"accept.db-wal", L"accept.db-shm",
};
static const wchar_t *const final_family[] = { L"accept.db" };

struct win_acc {
    wchar_t base[MAX_PATH];
    wchar_t base_aside[MAX_PATH];
    wchar_t store[MAX_PATH];
    wchar_t store_aside[MAX_PATH];
    uintptr_t retained;
    char vfs_name[SQLITE_VFS_DIR_NAME_MAX];
    sqlite3 *writer;
    sqlite3 *reader;
    sqlite3 *rollback_reader;
    int count;
    uint64_t volume_serial;
    uint64_t file_index;
    uint64_t file_size;
    wchar_t decoy_db[MAX_PATH];
    bool renamed;
    bool decoy_planted;
    const wchar_t *live_store;
    wchar_t reparse_leaf[MAX_PATH];
    wchar_t reparse_target[MAX_PATH];
    bool reparse_is_junction;
    sqlite3_vfs *vtable;
    char second_vfs[SQLITE_VFS_DIR_NAME_MAX];
    wchar_t second_store[MAX_PATH];
    wchar_t race_store[MAX_PATH];
    uintptr_t race_handle;
    sqlite3_vfs *retiring_vtable;
    bool clean;
};

static int win_acc_build_fixture_paths(struct win_acc *acc)
{
    wchar_t temp[MAX_PATH];
    DWORD temp_len = GetTempPathW(sizeof(temp) / sizeof(temp[0]), temp);
    int base_len = temp_len > 0 && temp_len < sizeof(temp) / sizeof(temp[0])
        ? swprintf(acc->base, sizeof(acc->base) / sizeof(acc->base[0]),
                   L"%lsz23-sqlite-vfs-dir-%lu-%llu", temp,
                   (unsigned long)GetCurrentProcessId(),
                   (unsigned long long)GetTickCount64())
        : -1;
    int ok_paths = base_len > 0 &&
        (size_t)base_len < sizeof(acc->base) / sizeof(acc->base[0]) &&
        swprintf(acc->base_aside,
                 sizeof(acc->base_aside) / sizeof(acc->base_aside[0]),
                 L"%ls-aside", acc->base) > 0 &&
        append_leaf(acc->store, sizeof(acc->store) / sizeof(acc->store[0]),
                    acc->base, L"store") &&
        append_leaf(acc->store_aside,
                    sizeof(acc->store_aside) / sizeof(acc->store_aside[0]),
                    acc->base_aside, L"store");
    if (!ok_paths)
        return fail("fixture path construction failed");
    sqlite3_config(SQLITE_CONFIG_LOG, sqlite_log_echo, NULL);
    return 0;
}

static int win_acc_register_private_datadir(struct win_acc *acc)
{
    /* The owner-private datadir is <base>\store; <base> itself is a plain
     * temp directory so the attack step can rename it and plant a decoy. */
    char store_utf8[MAX_PATH * 3];
    if (!CreateDirectoryW(acc->base, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, acc->store, -1,
                             store_utf8, sizeof(store_utf8), NULL, NULL) ||
        !platform_private_directory_create(store_utf8)) {
        fputs("sqlite_vfs_dir_windows_acceptance: REFUSE: runtime cannot "
              "create an owner-private datadir\n", stderr);
        return 77;
    }
    if (!platform_private_directory_open_validated(store_utf8, &acc->retained))
        return fail("fixture datadir did not validate as owner-private");

    char refused_vfs[SQLITE_VFS_DIR_NAME_MAX];
    if (sqlite_vfs_dir_register(acc->retained, "NUL", refused_vfs))
        return fail("device-name registration was admitted");
    if (!sqlite_vfs_dir_register(acc->retained, "accept.db", acc->vfs_name))
        return fail("sqlite_vfs_dir_register failed");
    /* The registration duplicated the handle. Keep the caller's copy only
     * through the file-control identity audit below, then close it so the
     * remainder runs solely on the VFS-owned capability. */
    return 0;
}

static int win_acc_open_writer_wal(struct win_acc *acc)
{
    /* (a) open through the VFS, WAL mode, write and read back. */
    acc->writer = NULL;
    if (sqlite3_open_v2("accept.db", &acc->writer,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            acc->vfs_name) != SQLITE_OK) {
        int rc = fail("writer open through VFS failed");
        if (acc->writer)
            sqlite3_close(acc->writer);
        return rc;
    }
    sqlite3_stmt *mode = NULL;
    if (sqlite3_prepare_v2(acc->writer, "PRAGMA journal_mode=WAL", -1, &mode,
                           NULL) != SQLITE_OK ||
        sqlite3_step(mode) != SQLITE_ROW ||
        strcmp((const char *)sqlite3_column_text(mode, 0), "wal") != 0) {
        sqlite3_finalize(mode);
        return fail("journal_mode=WAL was not honored");
    }
    sqlite3_finalize(mode);
    return 0;
}

static int win_acc_write_and_audit_main_file(struct win_acc *acc)
{
    if (!exec_ok(acc->writer, "CREATE TABLE t(k INTEGER PRIMARY KEY, v TEXT)") ||
        !exec_ok(acc->writer, "INSERT INTO t(v) VALUES('a'),('b'),('c')"))
        return fail("writer schema/insert failed");
    acc->count = 0;
    if (count_rows(acc->writer, &acc->count) != SQLITE_OK || acc->count != 3)
        return fail("writer readback did not see 3 rows");
    acc->volume_serial = 0;
    acc->file_index = 0;
    acc->file_size = 0;
    if (!sqlite_vfs_dir_main_file_info(acc->writer, acc->retained, "accept.db",
                                       &acc->volume_serial,
                                       &acc->file_index, &acc->file_size) ||
        acc->file_index == 0 || acc->file_size == 0)
        return fail("main-file retained identity audit failed");
    if (sqlite_vfs_dir_main_file_info(acc->writer, acc->retained, "other.db",
                                      &acc->volume_serial, &acc->file_index,
                                      &acc->file_size))
        return fail("main-file audit accepted the wrong leaf");
    return 0;
}

static int win_acc_reject_default_vfs(struct win_acc *acc)
{
    sqlite3 *ordinary = NULL;
    if (sqlite3_open(":memory:", &ordinary) != SQLITE_OK || !ordinary)
        return fail("ordinary VFS negative fixture open failed");
    if (sqlite_vfs_dir_main_file_info(ordinary, acc->retained, "accept.db",
                                      &acc->volume_serial, &acc->file_index,
                                      &acc->file_size))
        return fail("main-file audit accepted SQLite's default VFS");
    if (sqlite3_close(ordinary) != SQLITE_OK)
        return fail("ordinary VFS negative fixture close failed");
    sqlite3_file *main_file = NULL;
    if (sqlite3_file_control(acc->writer, "main", SQLITE_FCNTL_FILE_POINTER,
                             &main_file) != SQLITE_OK || !main_file ||
        (main_file->pMethods->xDeviceCharacteristics(main_file) &
         SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN) != 0)
        return fail("VFS falsely advertised undeletable-while-open files");
    platform_private_directory_close(acc->retained);
    return 0;
}

static int win_acc_open_reader(struct win_acc *acc)
{
    /* (b) independent read-only connection through the same VFS. */
    acc->reader = NULL;
    if (sqlite3_open_v2("accept.db", &acc->reader,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            acc->vfs_name) != SQLITE_OK) {
        int rc = fail("read-only open through VFS failed");
        if (acc->reader)
            sqlite3_close(acc->reader);
        return rc;
    }
    if (count_rows(acc->reader, &acc->count) != SQLITE_OK || acc->count != 3)
        return fail("reader did not see the committed 3 rows");
    return 0;
}

static int win_acc_prove_wal_snapshot(struct win_acc *acc)
{
    /* WAL snapshot isolation: an open write transaction must not leak to the
     * reader, and its commit must become visible without reopening — this
     * only works if the shared-memory wal-index really functions across the
     * two connections. */
    if (!exec_ok(acc->writer, "BEGIN IMMEDIATE") ||
        !exec_ok(acc->writer, "INSERT INTO t(v) VALUES('pending')"))
        return fail("writer transaction failed");
    if (count_rows(acc->reader, &acc->count) != SQLITE_OK || acc->count != 3)
        return fail("reader saw an uncommitted row (WAL isolation broken)");
    if (!exec_ok(acc->writer, "COMMIT"))
        return fail("writer commit failed");
    if (count_rows(acc->reader, &acc->count) != SQLITE_OK || acc->count != 4)
        return fail("reader did not see the committed 4th row");

    /* (c) siblings live inside the retained directory, and nothing else. */
    if (!dir_family_exact(acc->store, wal_family, 3, wal_family, 3))
        return fail("WAL/SHM siblings missing or stray files in datadir");
    return 0;
}

static int win_acc_rename_parent_or_plant_decoy(struct win_acc *acc)
{
    /* (d) handle-binding attack proof: rename the datadir's parent aside and
     * plant a decoy datadir at the old path. With the store live this build
     * of NT refuses to rename any ancestor of the relative-open children
     * (and refuses renaming the datadir itself, whose children carry a
     * RelatedFileObject link to it): the primary arm asserts that
     * kernel-level containment and that the store keeps working untouched.
     * If a future Windows ever permits the rename, the second arm runs the
     * decoy proof instead: the binding must follow the directory OBJECT, so
     * the decoy at the old path stays byte-identical and sibling-free while
     * the real family follows the renamed tree. Either way the store must
     * remain fully functional and the real family must sit in exactly one
     * place. */
    acc->renamed = MoveFileExW(acc->base, acc->base_aside, 0) != 0;
    DWORD rename_error = acc->renamed ? NO_ERROR : GetLastError();
    acc->live_store = acc->renamed ? acc->store_aside : acc->store;
    acc->decoy_planted = false;
    if (acc->renamed) {
        if (!CreateDirectoryW(acc->base, NULL) ||
            !CreateDirectoryW(acc->store, NULL))
            return fail("could not plant decoy datadir");
        if (!append_leaf(acc->decoy_db,
                         sizeof(acc->decoy_db) / sizeof(acc->decoy_db[0]),
                         acc->store, L"accept.db") ||
            !write_seeded_file(acc->decoy_db, 0x5a, 4096))
            return fail("could not plant decoy database");
        acc->decoy_planted = true;
    } else if (rename_error != ERROR_ACCESS_DENIED &&
               rename_error != ERROR_SHARING_VIOLATION) {
        fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: rename aside "
                "failed unexpectedly: win32=%lu\n",
                (unsigned long)rename_error);
        return fail("rename attempt failed for an unexpected reason");
    }
    return 0;
}

static int win_acc_prove_attack_family(struct win_acc *acc)
{
    if (!exec_ok(acc->writer, "INSERT INTO t(v) VALUES('d'),('e'),('f'),('g'),"
                              "('h')"))
        return fail("post-attack writer insert failed");
    if (count_rows(acc->reader, &acc->count) != SQLITE_OK || acc->count != 9)
        return fail("post-attack reader did not see 9 rows");
    if (!dir_family_exact(acc->live_store, wal_family, 3, wal_family, 3))
        return fail("real database family is not exactly the WAL trio");
    if (acc->decoy_planted) {
        static const wchar_t *const decoy_family[] = { L"accept.db" };
        if (!file_matches_seed(acc->decoy_db, 0x5a, 4096))
            return fail("decoy database was mutated through the VFS");
        if (!dir_family_exact(acc->store, decoy_family, 1, decoy_family, 1))
            return fail("decoy directory gained a WAL/SHM/journal sibling");
    }
    return 0;
}

static int win_acc_refuse_leaf_escapes(struct win_acc *acc)
{
    /* (e) leaf-name escapes are refused. */
    static const char *const escapes[] = {
        "../evil.db", "..\\evil.db", "..", ".", "accept.db/x",
        "accept.db\\x", "C:\\Windows\\Temp\\z23vfsescape.db",
        "\\\\?\\C:\\z23vfsescape.db", "other.db", "accept.db-walx",
        "NUL", "accept.db ", "accept.db.",
        "zclvfs-tmp-0123456789abcdef",
    };
    for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); ++i) {
        sqlite3 *probe = NULL;
        int rc = sqlite3_open_v2(escapes[i], &probe,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, acc->vfs_name);
        if (probe)
            sqlite3_close(probe);
        if (rc == SQLITE_OK)
            return fail("leaf-name escape was accepted");
    }
    wchar_t evil_wide[MAX_PATH];
    if (!append_leaf(evil_wide, sizeof(evil_wide) / sizeof(evil_wide[0]),
                     acc->base, L"evil.db"))
        return fail("escape probe path construction failed");
    if (!path_absent(evil_wide))
        return fail("escape created ..\\evil.db on disk");
    if (!path_absent(L"C:\\Windows\\Temp\\z23vfsescape.db"))
        return fail("escape created an absolute-path file on disk");
    return 0;
}

static int win_acc_plant_reparse_fixture(struct win_acc *acc)
{
    /* Reparse-point refusal, proven against the live binding: plant a reparse
     * point at a family leaf name inside the live directory and open it
     * directly through the registered vtable. A file symlink is the
     * preferred fixture; where unprivileged symlinks are unavailable, a
     * junction (a reparse point every user may create) carries the same
     * refusal. The symlink target is an inert file outside the datadir whose
     * bytes are verified unchanged after the refused open. */
    if (!append_leaf(acc->reparse_leaf,
                     sizeof(acc->reparse_leaf) / sizeof(acc->reparse_leaf[0]),
                     acc->live_store, L"accept.db-mjABCDEF912") ||
        !append_leaf(acc->reparse_target, sizeof(acc->reparse_target) /
                     sizeof(acc->reparse_target[0]), acc->base,
                     L"reparse-target.bin") ||
        !write_seeded_file(acc->reparse_target, 0xa5, 1024))
        return fail("reparse fixture setup failed");
    bool reparse_planted = CreateSymbolicLinkW(acc->reparse_leaf,
        acc->reparse_target,
        SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;
    acc->reparse_is_junction = false;
    if (!reparse_planted) {
        fprintf(stderr, "sqlite_vfs_dir_windows_acceptance: symlink fixture "
                "unavailable: win32=%lu\n", (unsigned long)GetLastError());
        reparse_planted = create_junction(acc->reparse_leaf, acc->base);
        acc->reparse_is_junction = reparse_planted;
    }
    if (!reparse_planted)
        return fail("could not plant a reparse-point fixture");
    return 0;
}

static int win_acc_refuse_reserved_temp(struct win_acc *acc)
{
    acc->vtable = sqlite3_vfs_find(acc->vfs_name);
    wchar_t reserved_temp[MAX_PATH];
    if (!acc->vtable ||
        !append_leaf(reserved_temp,
                     sizeof(reserved_temp) / sizeof(reserved_temp[0]),
                     acc->live_store, L"zclvfs-tmp-0123456789abcdef") ||
        !write_seeded_file(reserved_temp, 0x5a, 256))
        return fail("reserved temp-name fixture setup failed");
    int reserved_exists = 1;
    int reserved_access_rc = acc->vtable->xAccess(
        acc->vtable, "zclvfs-tmp-0123456789abcdef", SQLITE_ACCESS_EXISTS,
        &reserved_exists);
    int reserved_delete_rc = acc->vtable->xDelete(
        acc->vtable, "zclvfs-tmp-0123456789abcdef", 1);
    if (reserved_access_rc == SQLITE_OK || reserved_delete_rc == SQLITE_OK ||
        reserved_exists != 0 ||
        !file_matches_seed(reserved_temp, 0x5a, 256))
        return fail("named temp pattern gained namespace authority");
    if (!DeleteFileW(reserved_temp))
        return fail("reserved temp-name fixture cleanup failed");
    return 0;
}

static int win_acc_refuse_reparse_leaf(struct win_acc *acc)
{
    sqlite3_file *probe_file =
        acc->vtable ? calloc(1, (size_t)acc->vtable->szOsFile) : NULL;
    if (!probe_file)
        return fail("probe file allocation failed");
    int probe_rc = acc->vtable->xOpen(acc->vtable, "accept.db-mjABCDEF912",
                                      probe_file, SQLITE_OPEN_READWRITE, NULL);
    if (probe_rc == SQLITE_OK) {
        probe_file->pMethods->xClose(probe_file);
        free(probe_file);
        return fail("reparse-point leaf was opened");
    }
    free(probe_file);
    if (!file_matches_seed(acc->reparse_target, 0xa5, 1024))
        return fail("reparse open attempt mutated its target");
    if (acc->reparse_is_junction) {
        if (!RemoveDirectoryW(acc->reparse_leaf))
            return fail("junction fixture cleanup failed");
    } else if (!DeleteFileW(acc->reparse_leaf)) {
        return fail("symlink fixture cleanup failed");
    }
    if (!DeleteFileW(acc->reparse_target))
        return fail("reparse target cleanup failed");
    return 0;
}

static int win_acc_refuse_directory_leaf(struct win_acc *acc)
{
    /* A plain directory at a family leaf name is refused too. */
    wchar_t dir_leaf[MAX_PATH];
    if (!append_leaf(dir_leaf, sizeof(dir_leaf) / sizeof(dir_leaf[0]),
                     acc->live_store, L"accept.db-mj123456978") ||
        !CreateDirectoryW(dir_leaf, NULL))
        return fail("directory fixture creation failed");
    sqlite3_file *probe_file = calloc(1, (size_t)acc->vtable->szOsFile);
    if (!probe_file)
        return fail("probe file allocation failed");
    int probe_rc = acc->vtable->xOpen(acc->vtable, "accept.db-mj123456978",
                                      probe_file, SQLITE_OPEN_READWRITE, NULL);
    if (probe_rc == SQLITE_OK) {
        probe_file->pMethods->xClose(probe_file);
        free(probe_file);
        return fail("directory leaf was opened as a file");
    }
    free(probe_file);
    if (!RemoveDirectoryW(dir_leaf))
        return fail("directory fixture cleanup failed");
    return 0;
}

static int win_acc_register_second_datadir(struct win_acc *acc)
{
    /* Refcount proof: unregister while a connection is still open; the
     * connection keeps working, and the binding outlives it. The second
     * binding gets its own owner-private directory so the accept.db family
     * checks above and below stay exact. */
    {
        const wchar_t *live_base = acc->renamed ? acc->base_aside : acc->base;
        uintptr_t live_handle = 0;
        char live_utf8[MAX_PATH * 3];
        if (!append_leaf(acc->second_store,
                         sizeof(acc->second_store) /
                         sizeof(acc->second_store[0]),
                         live_base, L"second") ||
            !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                 acc->second_store, -1, live_utf8,
                                 sizeof(live_utf8), NULL, NULL) ||
            !platform_private_directory_create(live_utf8) ||
            !platform_private_directory_open_validated(live_utf8,
                                                       &live_handle))
            return fail("second datadir setup failed");
        if (!sqlite_vfs_dir_register(live_handle, "second.db",
                                     acc->second_vfs))
            return fail("second register failed");
        if (sqlite_vfs_dir_main_file_info(acc->writer, live_handle,
                                          "accept.db", &acc->volume_serial,
                                          &acc->file_index, &acc->file_size))
            return fail("main-file audit accepted the wrong directory");
        platform_private_directory_close(live_handle);
    }
    return 0;
}

static int win_acc_unregister_while_open(struct win_acc *acc)
{
    sqlite3 *second = NULL;
    if (sqlite3_open_v2("second.db", &second,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            acc->second_vfs) != SQLITE_OK ||
        !exec_ok(second, "CREATE TABLE s(k INTEGER)") ||
        !exec_ok(second, "INSERT INTO s(k) VALUES(1)"))
        return fail("second binding connection failed");
    sqlite3_vfs *second_vtable = sqlite3_vfs_find(acc->second_vfs);
    if (!second_vtable)
        return fail("second binding vtable lookup failed");
    if (!sqlite_vfs_dir_unregister(acc->second_vfs))
        return fail("unregister-while-open failed");
    if (sqlite_vfs_dir_unregister(acc->second_vfs))
        return fail("double unregister was accepted");
    sqlite3_file *probe_file = calloc(1, (size_t)second_vtable->szOsFile);
    if (!probe_file)
        return fail("post-unregister main-open probe allocation failed");
    int probe_rc = second_vtable->xOpen(
        second_vtable, "second.db", probe_file,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_MAIN_DB, NULL);
    free(probe_file);
    if (probe_rc == SQLITE_OK)
        return fail("post-unregister main database open was admitted");
    if (!exec_ok(second, "INSERT INTO s(k) VALUES(2)"))
        return fail("connection broke after unregister");
    if (sqlite3_close(second) != SQLITE_OK)
        return fail("second connection close failed");
    return 0;
}

static int win_acc_arm_first_open_race(struct win_acc *acc)
{
    /* First-open/unregister race proof: retain the vtable pointer exactly as
     * sqlite3_vfs_find does for an opener, unregister before its xOpen starts,
     * then invoke the stale pointer. The inert binding tombstone must refuse
     * without touching the already-released directory capability. */
    char race_utf8[MAX_PATH * 3];
    char race_vfs[SQLITE_VFS_DIR_NAME_MAX];
    const wchar_t *live_base = acc->renamed ? acc->base_aside : acc->base;
    if (!append_leaf(acc->race_store,
                     sizeof(acc->race_store) / sizeof(acc->race_store[0]),
                     live_base, L"race") ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, acc->race_store,
                             -1, race_utf8, sizeof(race_utf8), NULL, NULL) ||
        !platform_private_directory_create(race_utf8) ||
        !platform_private_directory_open_validated(race_utf8,
                                                   &acc->race_handle) ||
        !sqlite_vfs_dir_register(acc->race_handle, "race.db", race_vfs))
        return fail("first-open race fixture setup failed");
    acc->retiring_vtable = sqlite3_vfs_find(race_vfs);
    if (!acc->retiring_vtable || !sqlite_vfs_dir_unregister(race_vfs))
        return fail("first-open race unregister failed");
    return 0;
}

static int win_acc_prove_stale_callbacks(struct win_acc *acc)
{
    sqlite3_file *probe_file =
        calloc(1, (size_t)acc->retiring_vtable->szOsFile);
    if (!probe_file)
        return fail("first-open race probe allocation failed");
    int probe_rc = acc->retiring_vtable->xOpen(
        acc->retiring_vtable, "race.db", probe_file,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MAIN_DB,
        NULL);
    free(probe_file);
    int stale_access = 1;
    int stale_access_rc = acc->retiring_vtable->xAccess(
        acc->retiring_vtable, "race.db", SQLITE_ACCESS_EXISTS, &stale_access);
    int stale_delete_rc = acc->retiring_vtable->xDelete(
        acc->retiring_vtable, "race.db", 1);
    char stale_full[MAX_PATH];
    int stale_full_rc = acc->retiring_vtable->xFullPathname(
        acc->retiring_vtable, "race.db", (int)sizeof(stale_full), stale_full);
    platform_private_directory_close(acc->race_handle);
    if (probe_rc == SQLITE_OK || stale_access_rc == SQLITE_OK ||
        stale_delete_rc == SQLITE_OK || stale_full_rc == SQLITE_OK)
        return fail("stale VFS callback crossed unregister");
    if (!RemoveDirectoryW(acc->race_store))
        return fail("retired race binding retained its directory handle");
    return 0;
}

static int win_acc_prove_persist_journal(struct win_acc *acc)
{
    /* Rollback-journal path: leave WAL, exercise a persistent journal with an
     * independent reader, then return through DELETE and WAL. The reader must
     * be closed first so the initial mode change can checkpoint. */
    if (sqlite3_close(acc->reader) != SQLITE_OK)
        return fail("reader close failed");
    if (!exec_ok(acc->writer, "PRAGMA journal_mode=PERSIST"))
        return fail("persistent rollback-journal mode failed");
    acc->rollback_reader = NULL;
    if (sqlite3_open_v2("accept.db", &acc->rollback_reader,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            acc->vfs_name) != SQLITE_OK ||
        !exec_ok(acc->writer, "BEGIN IMMEDIATE") ||
        !exec_ok(acc->writer, "INSERT INTO t(v) VALUES('persistent')") ||
        count_rows(acc->rollback_reader, &acc->count) != SQLITE_OK ||
        acc->count != 9 ||
        !exec_ok(acc->writer, "COMMIT") ||
        count_rows(acc->rollback_reader, &acc->count) != SQLITE_OK ||
        acc->count != 10)
        return fail("persistent rollback-journal isolation failed");
    return 0;
}

static int win_acc_restore_wal_after_rollback(struct win_acc *acc)
{
    if (sqlite3_close(acc->rollback_reader) != SQLITE_OK ||
        !exec_ok(acc->writer, "PRAGMA journal_mode=DELETE") ||
        !exec_ok(acc->writer, "INSERT INTO t(v) VALUES('rollback')"))
        return fail("rollback-journal write failed");
    if (!dir_family_exact(acc->live_store, final_family, 1, wal_family, 3))
        return fail("rollback journal left a stray sibling behind");
    if (!exec_ok(acc->writer, "PRAGMA journal_mode=WAL") ||
        !exec_ok(acc->writer, "INSERT INTO t(v) VALUES('again')") ||
        count_rows(acc->writer, &acc->count) != SQLITE_OK || acc->count != 12)
        return fail("WAL re-entry failed");
    if (sqlite3_close(acc->writer) != SQLITE_OK)
        return fail("writer close failed");
    /* Last close checkpoints and deletes the WAL/SHM through the VFS. */
    if (!dir_family_exact(acc->live_store, final_family, 1, wal_family, 3))
        return fail("close did not retire the WAL/SHM siblings");
    return 0;
}

static int win_acc_prove_registration_cap(struct win_acc *acc)
{
    if (!sqlite_vfs_dir_unregister(acc->vfs_name))
        return fail("unregister failed");
    if (sqlite_vfs_dir_unregister(acc->vfs_name))
        return fail("unregister of a dead binding was accepted");

    /* Registration tombstones close a real concurrent stale-vtable race, so
     * they are process-lifetime objects. Prove both the hard bound and that
     * the refused device-name registration above returned its reservation. */
    char live_store_utf8[MAX_PATH * 3];
    uintptr_t cap_handle = 0;
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, acc->live_store,
                             -1, live_store_utf8, sizeof(live_store_utf8),
                             NULL, NULL) ||
        !platform_private_directory_open_validated(live_store_utf8,
                                                   &cap_handle))
        return fail("registration-cap fixture open failed");
    bool cap_ok = true;
    for (unsigned i = 3; i < SQLITE_VFS_DIR_REGISTRATION_LIMIT; ++i) {
        char capped_vfs[SQLITE_VFS_DIR_NAME_MAX];
        if (!sqlite_vfs_dir_register(cap_handle, "cap.db", capped_vfs) ||
            !sqlite_vfs_dir_unregister(capped_vfs)) {
            cap_ok = false;
            break;
        }
    }
    char over_limit_vfs[SQLITE_VFS_DIR_NAME_MAX];
    bool over_limit = sqlite_vfs_dir_register(
        cap_handle, "cap.db", over_limit_vfs);
    if (over_limit)
        (void)sqlite_vfs_dir_unregister(over_limit_vfs);
    platform_private_directory_close(cap_handle);
    if (!cap_ok || over_limit)
        return fail("registration tombstone bound failed");
    return 0;
}

static int win_acc_delete_live_files(struct win_acc *acc)
{
    /* Cleanup: the real database family under the live store (which sits
     * under base_aside when the rename arm ran), then the decoy tree if it
     * was planted, then both roots. */
    wchar_t path[MAX_PATH];
    acc->clean = true;
    static const wchar_t *const aside_files[] = {
        L"accept.db",
    };
    for (size_t i = 0; i < sizeof(aside_files) / sizeof(aside_files[0]); ++i)
        if (append_leaf(path, sizeof(path) / sizeof(path[0]), acc->live_store,
                        aside_files[i]))
            acc->clean = DeleteFileW(path) != 0 && acc->clean;
    acc->clean = RemoveDirectoryW(acc->live_store) != 0 && acc->clean;
    if (append_leaf(path, sizeof(path) / sizeof(path[0]), acc->second_store,
                    L"second.db"))
        acc->clean = DeleteFileW(path) != 0 && acc->clean;
    acc->clean = RemoveDirectoryW(acc->second_store) != 0 && acc->clean;
    return 0;
}

static int win_acc_remove_fixture_dirs(struct win_acc *acc)
{
    if (acc->renamed) {
        acc->clean = RemoveDirectoryW(acc->base_aside) != 0 && acc->clean;
        acc->clean = DeleteFileW(acc->decoy_db) != 0 && acc->clean;
        acc->clean = RemoveDirectoryW(acc->store) != 0 && acc->clean;
    }
    acc->clean = RemoveDirectoryW(acc->base) != 0 && acc->clean;
    if (!acc->clean)
        return fail("fixture cleanup failed");
    return 0;
}

static int (*const win_acc_steps[])(struct win_acc *) = {
    win_acc_build_fixture_paths,
    win_acc_register_private_datadir,
    win_acc_open_writer_wal,
    win_acc_write_and_audit_main_file,
    win_acc_reject_default_vfs,
    win_acc_open_reader,
    win_acc_prove_wal_snapshot,
    win_acc_rename_parent_or_plant_decoy,
    win_acc_prove_attack_family,
    win_acc_refuse_leaf_escapes,
    win_acc_plant_reparse_fixture,
    win_acc_refuse_reserved_temp,
    win_acc_refuse_reparse_leaf,
    win_acc_refuse_directory_leaf,
    win_acc_register_second_datadir,
    win_acc_unregister_while_open,
    win_acc_arm_first_open_race,
    win_acc_prove_stale_callbacks,
    win_acc_prove_persist_journal,
    win_acc_restore_wal_after_rollback,
    win_acc_prove_registration_cap,
    win_acc_delete_live_files,
    win_acc_remove_fixture_dirs,
};

int main(void)
{
    struct win_acc acc;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < sizeof win_acc_steps / sizeof win_acc_steps[0];
         ++i) {
        int rc = win_acc_steps[i](&acc);
        if (rc)
            return rc;
    }
    puts("sqlite_vfs_dir_windows_acceptance: PASS");
    return 0;
}

#else
typedef int sqlite_vfs_dir_windows_acceptance_not_built;
#endif
