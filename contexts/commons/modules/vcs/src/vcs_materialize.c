/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Safely materialize immutable ZVCS trees for confined consumers. */

#include "vcs/vcs.h"

#include "util/file_tree_ops.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs_object.h"

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VCS_MATERIALIZE_PATH_MAX 4400

#if !defined(_WIN32)
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
    /* Materialization feeds confined consumers and may create an executable
     * tree. Refuse before destination or object-store access until Windows
     * has a retained-root, no-reparse immutable generation transaction. */
    return VCS_REFUSED;
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
