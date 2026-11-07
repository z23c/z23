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
    const uint8_t *bytes, size_t len, bool durable)
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
                  materialize_write_relative(&child, slash + 1, bytes, len, durable);
        platform_directory_transaction_close(&child);
        return ok;
    }
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    if (!platform_directory_child_create(directory, relative, &file))
        return false;
    bool ok = platform_directory_child_write_exact(&file, bytes, len, 0) &&
              (!durable || platform_directory_child_flush(&file));
    platform_directory_child_close(&file);
    if (!ok)
        (void)platform_directory_child_unlink(directory, relative, true);
    return ok;
}
#else
static bool materialize_write(const char *path, const uint8_t *bytes,
                              size_t len, uint32_t mode, bool durable)
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
    /* open() filters mode through the ambient umask, so restore the exact
     * manifest permission bits: a re-capture must hash identically even
     * when the materializing process runs under a restrictive umask. */
    bool chmodded = off == len &&
                    fchmod(fd, (mode_t)(mode & 0777u)) == 0;
    bool synced = chmodded && (!durable || fsync(fd) == 0);
    bool closed = close(fd) == 0;
    bool ok = synced && closed;
    if (!ok) (void)unlink(path);
    return ok;
}
#endif

/* Keep the canonical-only read choice identical on both host paths. */
static int materialize_blob(const char *root, const struct vcs_entry *entry,
                            bool readonly, uint8_t **bytes, size_t *len)
{
    if (readonly)
        return vcs_object_get_readonly_bounded(root, entry->blob, VCS_TAG_BLOB,
                                               (size_t)entry->size, bytes, len);
    return vcs_object_get(root, entry->blob, VCS_TAG_BLOB, bytes, len);
}

#if defined(_WIN32)
/* One entry of the declared tree, or VCS_REFUSED/VCS_ERR without writing
 * anything if it fails the size/path/type check for this entry alone. */
static int materialize_entry_windows(struct platform_directory_transaction *root,
                                     const char *object_store_root,
                                     const struct vcs_entry *entry,
                                     uint64_t *total, uint64_t maximum_bytes, bool readonly, bool durable)
{
    if ((entry->mode & VCS_MATERIALIZE_TYPEMASK) != VCS_MATERIALIZE_REGULAR ||
        !vcs_package_path_valid(entry->path) ||
        UINT64_MAX - *total < entry->size ||
        *total + entry->size > maximum_bytes || entry->size > SIZE_MAX)
        return VCS_REFUSED;
    uint8_t *bytes = NULL;
    size_t len = 0;
    int got = materialize_blob(object_store_root, entry, readonly, &bytes, &len);
    if (got != 0 || len != entry->size) {
        free(bytes);
        return VCS_ERR;
    }
    int result = materialize_write_relative(root, entry->path, bytes, len, durable)
                     ? VCS_OK : VCS_ERR;
    free(bytes);
    if (result == VCS_OK) *total += entry->size;
    return result;
}

static int vcs_tree_materialize_windows(const char *object_store_root,
                                        const uint8_t tree_hash[32],
                                        const char *destination,
                                        uint64_t maximum_bytes, bool readonly, bool durable)
{
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    if (!platform_directory_transaction_open(&root, destination))
        return VCS_ERR;
    struct vcs_manifest tree;
    if (!(readonly ? vcs_tree_load_readonly_bounded(object_store_root, tree_hash,
            (size_t)maximum_bytes, 16384u, &tree) : vcs_tree_load(object_store_root, tree_hash, &tree))) {
        platform_directory_transaction_close(&root);
        return VCS_ERR;
    }
    uint64_t total = 0;
    int result = VCS_OK;
    for (size_t i = 0; i < tree.count; i++) {
        result = materialize_entry_windows(&root, object_store_root,
                                           &tree.entries[i], &total,
                                           maximum_bytes, readonly, durable);
        if (result != VCS_OK) break;
    }
    if (result == VCS_OK && durable && !platform_directory_transaction_flush(&root))
        result = VCS_ERR;
    platform_directory_transaction_close(&root);
    vcs_manifest_free(&tree);
    return result;
}
#else
/* One entry of the declared tree, or VCS_REFUSED/VCS_ERR without writing
 * anything if it fails the size/path/type check for this entry alone. */
static int materialize_entry_posix(const char *object_store_root,
                                   const char *destination,
                                   const struct vcs_entry *entry,
                                   uint64_t *total, uint64_t maximum_bytes,
                                   uint32_t file_mode, bool readonly, bool durable)
{
    if (!S_ISREG(entry->mode) || !vcs_package_path_valid(entry->path) ||
        UINT64_MAX - *total < entry->size ||
        *total + entry->size > maximum_bytes || entry->size > SIZE_MAX)
        return VCS_REFUSED;
    uint8_t *bytes = NULL;
    size_t len = 0;
    int got = materialize_blob(object_store_root, entry, readonly, &bytes, &len);
    if (got != 0 || len != entry->size) {
        free(bytes);
        return VCS_ERR;
    }
    char path[VCS_MATERIALIZE_PATH_MAX];
    char parent[VCS_MATERIALIZE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", destination, entry->path);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        free(bytes);
        return VCS_REFUSED;
    }
    (void)snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';
    struct zcl_result made = zcl_mkdir_p(parent, 0700);
    uint32_t mode = file_mode ? file_mode : entry->mode & 0777u;
    int result = made.ok && materialize_write(path, bytes, len, mode, durable)
                     ? VCS_OK : VCS_ERR;
    free(bytes);
    if (result == VCS_OK) *total += entry->size;
    return result;
}

static int vcs_tree_materialize_posix(const char *object_store_root,
                                      const uint8_t tree_hash[32],
                                      const char *destination,
                                      uint64_t maximum_bytes,
                                      uint32_t file_mode, bool readonly, bool durable)
{
    struct stat st;
    if (lstat(destination, &st) != 0 || !S_ISDIR(st.st_mode))
        return VCS_ERR;
    struct vcs_manifest tree;
    if (!(readonly ? vcs_tree_load_readonly_bounded(object_store_root, tree_hash,
            (size_t)maximum_bytes, 16384u, &tree) : vcs_tree_load(object_store_root, tree_hash, &tree)))
        return VCS_ERR;
    uint64_t total = 0;
    int result = VCS_OK;
    for (size_t i = 0; i < tree.count; i++) {
        result = materialize_entry_posix(object_store_root, destination,
                                         &tree.entries[i], &total,
                                         maximum_bytes, file_mode, readonly, durable);
        if (result != VCS_OK) break;
    }
    vcs_manifest_free(&tree);
    return result;
}
#endif

static int materialize_tree(const char *object_store_root,
    const uint8_t tree_hash[32], const char *destination, uint64_t maximum_bytes,
    uint32_t file_mode, bool readonly, bool durable)
{
    if (!object_store_root || !tree_hash || !destination || maximum_bytes == 0 ||
        (file_mode != 0u && file_mode != 0400u && file_mode != 0600u))
        return VCS_ERR;
#if SIZE_MAX < UINT64_MAX
    if (readonly && maximum_bytes > SIZE_MAX) return VCS_ERR;
#endif
#if defined(_WIN32)
    return vcs_tree_materialize_windows(object_store_root, tree_hash, destination, maximum_bytes, readonly, durable);
#else
    return vcs_tree_materialize_posix(object_store_root, tree_hash, destination, maximum_bytes, file_mode, readonly, durable);
#endif
}
int vcs_tree_materialize(const char *object_store_root, const uint8_t tree_hash[32],
                         const char *destination, uint64_t maximum_bytes, uint32_t file_mode)
{
    return materialize_tree(object_store_root, tree_hash, destination, maximum_bytes, file_mode, false, true);
}
int vcs_tree_materialize_readonly(const char *object_store_root, const uint8_t tree_hash[32],
                                  const char *destination, uint64_t maximum_bytes, uint32_t file_mode)
{
    return materialize_tree(object_store_root, tree_hash, destination, maximum_bytes, file_mode, true, true);
}

/* Only disposable reconstruction: verified source reads remain strict. */
int vcs_tree_materialize_readonly_disposable(const char *object_store_root,
    const uint8_t tree_hash[32], const char *destination,
    uint64_t maximum_bytes, uint32_t file_mode)
{
    return materialize_tree(object_store_root, tree_hash, destination,
                            maximum_bytes, file_mode, true, false);
}
