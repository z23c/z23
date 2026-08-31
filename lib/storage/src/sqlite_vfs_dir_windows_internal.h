/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private shared state for the native Windows retained-directory
 * SQLite VFS implementation and its registration/lifetime authority. */
#ifndef ZCL_STORAGE_SQLITE_VFS_DIR_WINDOWS_INTERNAL_H
#define ZCL_STORAGE_SQLITE_VFS_DIR_WINDOWS_INTERNAL_H

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "storage/sqlite_vfs_dir.h"

#include <sqlite3.h>
#include <stdbool.h>

#define VFS_DIR_LEAF_MAX     200u
#define VFS_DIR_BASENAME_MAX (VFS_DIR_LEAF_MAX - 16u)
#define VFS_DIR_MX_PATHNAME  260
#define VFS_DIR_TEMP_PREFIX  "zclvfs-tmp-"
#define VFS_DIR_TEMP_HEX     16u

struct sqlite_vfs_dir_binding;

struct vfs_dir_shm_conn {
    struct vfs_dir_shm_conn *next;
    uint16_t shared_mask;
    uint16_t excl_mask;
};

struct vfs_dir_shm_region {
    HANDLE map;
    void *view;
};

struct vfs_dir_shm_node {
    HANDLE file;
    int region_size;
    int region_count;
    struct vfs_dir_shm_region *regions;
    unsigned ref;
    struct vfs_dir_shm_conn *first;
};

struct sqlite_vfs_dir_binding {
    sqlite3_vfs vfs;
    char name[SQLITE_VFS_DIR_NAME_MAX];
    sqlite3_vfs *base;
    HANDLE dir;
    char basename[VFS_DIR_BASENAME_MAX + 1u];
    sqlite3_mutex *mutex;
    unsigned open_files;
    unsigned active_ops;
    bool closing;
    bool resources_retired;
    struct vfs_dir_shm_node shm;
    struct sqlite_vfs_dir_binding *next;
};

struct vfs_dir_file {
    sqlite3_file base;
    struct sqlite_vfs_dir_binding *binding;
    HANDLE h;
    char leaf[VFS_DIR_LEAF_MAX + 1u];
    int lock_type;
    int sector_chunk;
    bool readonly;
    unsigned char ctrl_flags;
    DWORD last_errno;
    struct vfs_dir_shm_conn *shm;
};

bool vfs_dir_valid_leaf(const char *leaf);
bool vfs_dir_is_temp_name(const char *leaf);
void vfs_dir_binding_initialize_vfs(struct sqlite_vfs_dir_binding *binding);
bool vfs_dir_binding_open_begin(struct sqlite_vfs_dir_binding *binding,
                                int flags);
void vfs_dir_binding_open_end(struct sqlite_vfs_dir_binding *binding,
                              bool success);
bool vfs_dir_binding_aux_begin(struct sqlite_vfs_dir_binding *binding);
void vfs_dir_binding_aux_end(struct sqlite_vfs_dir_binding *binding);
void vfs_dir_binding_file_closed(struct sqlite_vfs_dir_binding *binding);

extern const sqlite3_io_methods vfs_dir_io_methods;

#endif /* _WIN32 */

#endif /* ZCL_STORAGE_SQLITE_VFS_DIR_WINDOWS_INTERNAL_H */
