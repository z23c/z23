/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * LevelDB snapshot-dir helper: build a read-only view of a LevelDB
 * directory by hardlinking its immutable .ldb SST files and copying
 * the small metadata files (CURRENT, MANIFEST-*, LOG[.old]). The
 * snapshot gets a fresh empty LOCK file → distinct fcntl(F_SETLK)
 * context from the source. The caller may then open the snapshot
 * with leveldb_open while another process (e.g. zclassicd) still
 * holds the source's LOCK.
 *
 * Use case (Stage I of fast-sync plan): read zclassicd's
 * blocks/index/ block-index database without stopping zclassicd. */

#ifndef ZCL_STORAGE_LDB_SNAPSHOT_H
#define ZCL_STORAGE_LDB_SNAPSHOT_H

#include <stdbool.h>
#include <stddef.h>

/* Build a snapshot of `src_dir` at `dst_dir`. `dst_dir` is created
 * (or wiped and recreated if it already exists).
 *
 * Steps:
 *   1. Wipe dst_dir if present (tear down stale hardlinks).
 *   2. mkdir dst_dir.
 *   3. Read src_dir/CURRENT to learn the active MANIFEST name.
 *   4. For each entry in src_dir:
 *        - "*.ldb"             → hardlink into dst_dir (EXDEV → copy).
 *        - "MANIFEST-*"        → copy bytes.
 *        - "CURRENT","LOG"     → copy bytes.
 *        - "LOG.old"           → copy bytes if present.
 *        - "LOCK"              → skipped (leveldb creates ours on open).
 *   5. Re-read src_dir/CURRENT; if it changed during copy,
 *      return false with err_msg="manifest_changed" (retryable).
 *
 * Returns true on success. On failure, err_msg (if non-NULL) is
 * filled with a short diagnostic. Hardlinks are dropped — they're
 * pointers to the same inode, dropping a name just decrements link
 * count.
 *
 * Both src_dir and dst_dir must be absolute or relative paths to
 * existing directory trees on the same filesystem. Cross-FS falls
 * back to byte-copying SST files (slow but correct).
 */
bool ldb_snapshot_make(const char *src_dir,
                       const char *dst_dir,
                       char *err_msg, size_t err_sz);

/* Tear down a snapshot directory previously built by
 * ldb_snapshot_make. Safe to call if dst_dir does not exist. */
void ldb_snapshot_destroy(const char *dst_dir);

#endif /* ZCL_STORAGE_LDB_SNAPSHOT_H */
