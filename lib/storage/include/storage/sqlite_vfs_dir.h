/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sqlite_vfs_dir — retained-directory SQLite VFS for native Windows.
 *
 * Registers a per-store sqlite3_vfs whose entire namespace is one validated,
 * owner-private directory HANDLE plus one bound database basename: xOpen,
 * xDelete, xAccess, and xFullPathname resolve ONLY that basename, its SQLite
 * sibling suffixes (-wal/-shm/-journal/-mj…), and temp names the VFS itself
 * minted, and every resolution is handle-relative (NtCreateFile against the
 * retained handle), so renaming or replacing the directory path afterwards
 * cannot redirect the store. The sqlite3_file methods are full read/write
 * over the HANDLE (positioned I/O, byte-range PENDING/SHARED/RESERVED/
 * EXCLUSIVE locking and shared-memory WAL-index semantics mirroring the
 * vendored os_win.c), which is what WAL mode with a concurrent independent
 * reader needs.
 *
 * This is the capability the native Windows progress_store/consensus_db open
 * path requires before it stops refusing; the wiring is a separate change.
 *
 * Windows-only: the declarations below exist only under _WIN32, matching the
 * platform_private_directory handle-as-uintptr_t convention so this header
 * never exposes windows.h to portable includers. */

#ifndef ZCL_STORAGE_SQLITE_VFS_DIR_H
#define ZCL_STORAGE_SQLITE_VFS_DIR_H

#include <stdbool.h>
#include <stdint.h>

/* Buffer size for the registered VFS name handed back by
 * sqlite_vfs_dir_register (the caller passes it as the zVfs argument of
 * sqlite3_open_v2). Names are "zclvfsdir_<pid>_<sequence>" — well under
 * this bound. */
#define SQLITE_VFS_DIR_NAME_MAX 64

#if defined(_WIN32)

/* Register a SQLite VFS bound to `retained_dir`, which must be a validated,
 * owner-private directory handle (e.g. from
 * platform_private_directory_open_validated); the registration duplicates the
 * handle, so the caller keeps ownership of its own copy. `db_basename` must
 * be a plain leaf name (no separators, no device syntax); the VFS will serve
 * only it and the SQLite sibling files SQLite actually requests. Returns
 * true on success with the unique registered name in `vfs_name_out`; every
 * failure logs context and returns false. */
bool sqlite_vfs_dir_register(uintptr_t retained_dir, const char *db_basename,
                             char vfs_name_out[SQLITE_VFS_DIR_NAME_MAX]);

/* Unregister a VFS previously returned by sqlite_vfs_dir_register. The name
 * leaves the SQLite registry immediately; the binding (and its duplicated
 * directory handle) is refcounted against open connections and freed once the
 * last connection through it closes, so unregister-while-open is safe.
 * Returns false (with a log) when the name is not a live binding. */
bool sqlite_vfs_dir_unregister(const char *vfs_name);

#endif /* _WIN32 */

#endif /* ZCL_STORAGE_SQLITE_VFS_DIR_H */
