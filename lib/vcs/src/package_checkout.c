/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: inert checkout of one verified ordinary ZCODE package tree. */

#define _GNU_SOURCE
#include "vcs/package_checkout.h"

#include "vcs/package_manifest.h"
#include "platform/rename_compat.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PACKAGE_CHECKOUT_PATH_MAX 4096u

const char *vcs_package_checkout_result_string(
    enum vcs_package_checkout_result result)
{
    switch (result) {
    case VCS_PACKAGE_CHECKOUT_OK: return "ok";
    case VCS_PACKAGE_CHECKOUT_NULL: return "null-argument";
    case VCS_PACKAGE_CHECKOUT_INCOMPLETE: return "package-incomplete";
    case VCS_PACKAGE_CHECKOUT_MANIFEST: return "package-manifest";
    case VCS_PACKAGE_CHECKOUT_CHUNK: return "package-chunk";
    case VCS_PACKAGE_CHECKOUT_DESTINATION: return "destination";
    }
    return "unknown";
}

static bool checkout_write_all(int fd, const uint8_t *bytes, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return false;
        off += (size_t)wrote;
    }
    return true;
}

/* Resolve/create every parent component beneath root_fd. Manifest path
 * grammar already rejects traversal and empty segments; openat+O_NOFOLLOW
 * keeps a concurrently introduced symlink from escaping the staging tree. */
static int checkout_parent_fd(int root_fd, const char *path,
                              const char **leaf_out)
{
    char copy[VCS_PACKAGE_PATH_MAX + 1u];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(copy))
        return -1;
    memcpy(copy, path, len + 1u);
    int current = dup(root_fd);
    if (current < 0)
        return -1;
    char *part = copy;
    for (;;) {
        char *slash = strchr(part, '/');
        if (!slash) {
            *leaf_out = path + (part - copy);
            return current;
        }
        *slash = '\0';
        if (mkdirat(current, part, 0700) != 0 && errno != EEXIST) {
            close(current);
            return -1;
        }
        int next = openat(current, part,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(current);
        if (next < 0)
            return -1;
        current = next;
        part = slash + 1;
    }
}

static bool checkout_tree_remove_at(int parent_fd, const char *name)
{
    int fd = openat(parent_fd, name,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno == ENOENT;
    DIR *dir = fdopendir(fd);
    if (!dir) {
        close(fd);
        return false;
    }
    bool ok = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            ok = false;
        } else if (S_ISDIR(st.st_mode)) {
            if (!checkout_tree_remove_at(fd, entry->d_name))
                ok = false;
        } else if (unlinkat(fd, entry->d_name, 0) != 0) {
            ok = false;
        }
    }
    if (closedir(dir) != 0)
        ok = false;
    return unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 && ok;
}

static bool checkout_destination_parts(const char *destination,
                                       char *parent, size_t parent_cap,
                                       char *leaf, size_t leaf_cap)
{
    if (!destination || !destination[0] ||
        strlen(destination) >= PACKAGE_CHECKOUT_PATH_MAX)
        return false;
    const char *slash = strrchr(destination, '/');
    const char *name = slash ? slash + 1 : destination;
    size_t parent_len = slash ? (size_t)(slash - destination) : 1u;
    const char *parent_text = slash ? destination : ".";
    if (!name[0] || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        parent_len >= parent_cap || strlen(name) >= leaf_cap)
        return false;
    if (slash && parent_len == 0) {
        parent_text = "/";
        parent_len = 1u;
    }
    memcpy(parent, parent_text, parent_len);
    parent[parent_len] = '\0';
    memcpy(leaf, name, strlen(name) + 1u);
    return true;
}

static enum vcs_package_checkout_result checkout_materialize(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_manifest *manifest, int stage_fd,
    struct vcs_package_checkout_metrics *metrics)
{
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_package_file *file = &manifest->files[i];
        const char *leaf = NULL;
        int parent_fd = checkout_parent_fd(stage_fd, file->path, &leaf);
        if (parent_fd < 0)
            return VCS_PACKAGE_CHECKOUT_DESTINATION;
        int fd = openat(parent_fd, leaf,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
        close(parent_fd);
        if (fd < 0)
            return VCS_PACKAGE_CHECKOUT_DESTINATION;
        bool ok = true;
        for (uint32_t chunk_index = 0;
             ok && chunk_index < file->chunk_count; chunk_index++) {
            uint8_t *chunk = NULL;
            size_t chunk_len = 0;
            ok = vcs_package_store_get_chunk_at(
                     store, package_root, (uint32_t)i, chunk_index,
                     &chunk, &chunk_len) == VCS_PACKAGE_STORE_OK &&
                 vcs_package_verify_chunk(file, chunk_index, chunk,
                                          chunk_len) &&
                 checkout_write_all(fd, chunk, chunk_len);
            if (ok && metrics) {
                metrics->chunks++;
                metrics->bytes += chunk_len;
            }
            free(chunk);
        }
        mode_t mode = file->mode == VCS_PACKAGE_MODE_EXECUTABLE ? 0755 : 0644;
        enum vcs_package_checkout_result file_result = ok
            ? VCS_PACKAGE_CHECKOUT_OK : VCS_PACKAGE_CHECKOUT_CHUNK;
        if (ok && (fchmod(fd, mode) != 0 || fsync(fd) != 0))
            file_result = VCS_PACKAGE_CHECKOUT_DESTINATION;
        if (close(fd) != 0 && file_result == VCS_PACKAGE_CHECKOUT_OK)
            file_result = VCS_PACKAGE_CHECKOUT_DESTINATION;
        if (file_result != VCS_PACKAGE_CHECKOUT_OK)
            return file_result;
        if (metrics)
            metrics->files++;
    }
    return VCS_PACKAGE_CHECKOUT_OK;
}

enum vcs_package_checkout_result vcs_package_checkout(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *destination, struct vcs_package_checkout_metrics *metrics)
{
    if (metrics)
        memset(metrics, 0, sizeof(*metrics));
    if (!store || !package_root || !destination)
        return VCS_PACKAGE_CHECKOUT_NULL;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, package_root, &status) ||
        !status.complete)
        return VCS_PACKAGE_CHECKOUT_INCOMPLETE;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(
            store, package_root, &wire, &wire_len) != VCS_PACKAGE_STORE_OK)
        return VCS_PACKAGE_CHECKOUT_MANIFEST;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t observed[32];
    bool manifest_ok = vcs_package_manifest_parse(wire, wire_len, &manifest) &&
        vcs_package_manifest_root(&manifest, observed) &&
        memcmp(observed, package_root, 32) == 0;
    free(wire);
    if (!manifest_ok) {
        vcs_package_manifest_free(&manifest);
        return VCS_PACKAGE_CHECKOUT_MANIFEST;
    }

    char parent[PACKAGE_CHECKOUT_PATH_MAX], leaf[NAME_MAX + 1u];
    if (!checkout_destination_parts(destination, parent, sizeof(parent),
                                    leaf, sizeof(leaf))) {
        vcs_package_manifest_free(&manifest);
        return VCS_PACKAGE_CHECKOUT_DESTINATION;
    }
    int parent_fd = open(parent,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (parent_fd < 0 ||
        fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        if (parent_fd >= 0)
            close(parent_fd);
        vcs_package_manifest_free(&manifest);
        return VCS_PACKAGE_CHECKOUT_DESTINATION;
    }
    char stage[NAME_MAX + 1u];
    int n = snprintf(stage, sizeof(stage), ".%s.zcheckout.%ld", leaf,
                     (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(stage) ||
        mkdirat(parent_fd, stage, 0700) != 0) {
        close(parent_fd);
        vcs_package_manifest_free(&manifest);
        return VCS_PACKAGE_CHECKOUT_DESTINATION;
    }
    int stage_fd = openat(parent_fd, stage,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    enum vcs_package_checkout_result result = stage_fd < 0
        ? VCS_PACKAGE_CHECKOUT_DESTINATION
        : checkout_materialize(store, package_root, &manifest, stage_fd,
                               metrics);
    if (stage_fd >= 0 && fsync(stage_fd) != 0 &&
        result == VCS_PACKAGE_CHECKOUT_OK)
        result = VCS_PACKAGE_CHECKOUT_DESTINATION;
    if (stage_fd >= 0)
        close(stage_fd);
    bool published = false;
    if (result == VCS_PACKAGE_CHECKOUT_OK) {
        if (platform_renameat_noreplace(parent_fd, stage, parent_fd,
                                        leaf) != 0) {
            result = VCS_PACKAGE_CHECKOUT_DESTINATION;
        } else {
            published = true;
            if (fsync(parent_fd) != 0)
                result = VCS_PACKAGE_CHECKOUT_DESTINATION;
        }
    }
    if (result != VCS_PACKAGE_CHECKOUT_OK)
        (void)checkout_tree_remove_at(parent_fd, published ? leaf : stage);
    close(parent_fd);
    vcs_package_manifest_free(&manifest);
    return result;
}
