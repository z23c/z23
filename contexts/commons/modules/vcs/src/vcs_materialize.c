/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Safely materialize immutable ZVCS trees for confined consumers. */

#include "vcs/vcs.h"

#include "util/file_tree_ops.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs_object.h"

#if defined(_WIN32)
#include "platform/directory_transaction.h"
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VCS_MATERIALIZE_PATH_MAX 4400
#define VCS_MATERIALIZE_REGULAR 0100000u
#define VCS_MATERIALIZE_TYPEMASK 0170000u

#if defined(_WIN32)
/* Reconstruct one canonical relative path under a retained destination.
 * Modes come from the declared tree; NT metadata is never treated as a
 * POSIX execute-bit authority. */
static bool materialize_write_relative(
    struct platform_directory_transaction *directory, const char *relative,
    const uint8_t *bytes, size_t len)
{
    const char *slash = strchr(relative, '/');
    if (slash) {
        size_t component_len = (size_t)(slash - relative);
        char component[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
        if (component_len == 0 || component_len >= sizeof(component))
            return false;
        memcpy(component, relative, component_len);
        component[component_len] = '\0';
        struct platform_directory_transaction child;
        platform_directory_transaction_init(&child);
        bool ok = platform_directory_transaction_open_child(
                      directory, component, true, &child) ==
                      PLATFORM_DIRECTORY_OK &&
                  materialize_write_relative(&child, slash + 1, bytes, len);
        platform_directory_transaction_close(&child);
        return ok;
    }
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    if (!platform_directory_child_create(directory, relative, &file))
        return false;
    bool ok = platform_directory_child_write_exact(&file, bytes, len, 0) &&
              platform_directory_child_flush(&file);
    platform_directory_child_close(&file);
    if (!ok)
        (void)platform_directory_child_unlink(directory, relative, true);
    return ok;
}
#else
static bool materialize_write(const char *path, const uint8_t *bytes,
                              size_t len, uint32_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  (mode_t)mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool synced = off == len && fsync(fd) == 0;
    bool closed = close(fd) == 0;
    bool ok = synced && closed;
    if (!ok) (void)unlink(path);
    return ok;
}
#endif

int vcs_tree_materialize(const char *object_store_root,
                         const uint8_t tree_hash[32],
                         const char *destination, uint64_t maximum_bytes,
                         uint32_t file_mode)
{
    if (!object_store_root || !tree_hash || !destination ||
        maximum_bytes == 0 ||
        (file_mode != 0u && file_mode != 0400u && file_mode != 0600u))
        return VCS_ERR;
#if defined(_WIN32)
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    if (!platform_directory_transaction_open(&root, destination))
        return VCS_ERR;
    struct vcs_manifest tree;
    if (!vcs_tree_load(object_store_root, tree_hash, &tree)) {
        platform_directory_transaction_close(&root);
        return VCS_ERR;
    }
    uint64_t total = 0;
    int result = VCS_OK;
    for (size_t i = 0; i < tree.count; i++) {
        const struct vcs_entry *entry = &tree.entries[i];
        if ((entry->mode & VCS_MATERIALIZE_TYPEMASK) !=
                VCS_MATERIALIZE_REGULAR ||
            !vcs_package_path_valid(entry->path) ||
            UINT64_MAX - total < entry->size ||
            total + entry->size > maximum_bytes || entry->size > SIZE_MAX) {
            result = VCS_REFUSED;
            break;
        }
        uint8_t *bytes = NULL;
        size_t len = 0;
        if (vcs_object_get(object_store_root, entry->blob, VCS_TAG_BLOB,
                           &bytes, &len) != 0 || len != entry->size) {
            free(bytes);
            result = VCS_ERR;
            break;
        }
        if (!materialize_write_relative(&root, entry->path, bytes, len))
            result = VCS_ERR;
        free(bytes);
        if (result != VCS_OK) break;
        total += entry->size;
    }
    if (result == VCS_OK && !platform_directory_transaction_flush(&root))
        result = VCS_ERR;
    platform_directory_transaction_close(&root);
    vcs_manifest_free(&tree);
    return result;
#else
    struct stat st;
    if (lstat(destination, &st) != 0 || !S_ISDIR(st.st_mode))
        return VCS_ERR;
    struct vcs_manifest tree;
    if (!vcs_tree_load(object_store_root, tree_hash, &tree))
        return VCS_ERR;
    uint64_t total = 0;
    int result = VCS_OK;
    for (size_t i = 0; i < tree.count; i++) {
        const struct vcs_entry *entry = &tree.entries[i];
        if (!S_ISREG(entry->mode) || !vcs_package_path_valid(entry->path) ||
            UINT64_MAX - total < entry->size ||
            total + entry->size > maximum_bytes || entry->size > SIZE_MAX) {
            result = VCS_REFUSED;
            break;
        }
        uint8_t *bytes = NULL;
        size_t len = 0;
        if (vcs_object_get(object_store_root, entry->blob, VCS_TAG_BLOB,
                           &bytes, &len) != 0 || len != entry->size) {
            free(bytes);
            result = VCS_ERR;
            break;
        }
        char path[VCS_MATERIALIZE_PATH_MAX];
        char parent[VCS_MATERIALIZE_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", destination,
                         entry->path);
        if (n <= 0 || (size_t)n >= sizeof(path)) {
            free(bytes);
            result = VCS_REFUSED;
            break;
        }
        (void)snprintf(parent, sizeof(parent), "%s", path);
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0';
        struct zcl_result made = zcl_mkdir_p(parent, 0700);
        uint32_t mode = file_mode ? file_mode : entry->mode & 0777u;
        if (!made.ok || !materialize_write(path, bytes, len, mode))
            result = VCS_ERR;
        free(bytes);
        if (result != VCS_OK) break;
        total += entry->size;
    }
    vcs_manifest_free(&tree);
    return result;
#endif
}
