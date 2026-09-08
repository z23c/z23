/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded non-symlink-following dependency link-count traversal. */

#include "dependency_links.h"

#include "platform/directory_compat.h"
#include "platform/file_metadata.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The build/ subdirectories this scan treats as dependency rooms. One table,
 * read by the walk below and by zcl_dependency_build_room_path(), so a warm
 * seeder cannot come to a different conclusion about which files must own
 * their inodes than the gate that grades it. */
static const char *const DEPENDENCY_BUILD_ROOMS[] = {"hotswap", "githooks"};
#define DEPENDENCY_BUILD_ROOM_COUNT \
    (sizeof(DEPENDENCY_BUILD_ROOMS) / sizeof(DEPENDENCY_BUILD_ROOMS[0]))

struct dependency_scan {
    const char *root;
    size_t root_len;
    zcl_dependency_linked_file_fn callback;
    void *context;
    struct zcl_dependency_link_stats *stats;
    char *why;
    size_t why_cap;
};

static bool refuse(struct dependency_scan *scan, const char *format, ...)
{
    if (scan->why && scan->why_cap) {
        va_list args;
        va_start(args, format);
        (void)vsnprintf(scan->why, scan->why_cap, format, args);
        va_end(args);
    }
    return false;
}

static bool join(char out[ZCL_DEPENDENCY_LINK_PATH_MAX], const char *left,
                 const char *right)
{
    const size_t n = strlen(left);
    const int wrote = snprintf(out, ZCL_DEPENDENCY_LINK_PATH_MAX, "%s%s%s", left,
                               n && left[n - 1] == '/' ? "" : "/", right);
    return wrote > 0 && (size_t)wrote < ZCL_DEPENDENCY_LINK_PATH_MAX;
}

static const char *relative_path(const struct dependency_scan *scan,
                                 const char *full)
{
    const char *relative = full + scan->root_len;
    return *relative == '/' ? relative + 1 : relative;
}

static bool scan_directory(struct dependency_scan *scan, const char *path,
                           unsigned depth)
{
    if (depth > ZCL_DEPENDENCY_LINK_DEPTH_MAX)
        return refuse(scan, "traversal_depth_exceeded:%s",
                      relative_path(scan, path));
    if (platform_directory_probe_real(path) != PLATFORM_DIRECTORY_PROBE_OK)
        return refuse(scan, "directory_not_real:%s",
                      relative_path(scan, path));

    struct platform_directory_list directories = {0}, files = {0};
    if (!platform_directory_list_children_sorted(path, &directories, &files)) {
        int walk_errno = errno;
        return refuse(scan, "cannot walk %s: %s", path, strerror(walk_errno));
    }
    bool ok = true;
    for (size_t i = 0; ok && i < files.count; i++) {
        if (++scan->stats->entries > ZCL_DEPENDENCY_LINK_ENTRIES_MAX) {
            ok = refuse(scan, "entry_limit_exceeded");
            break;
        }
        char child[ZCL_DEPENDENCY_LINK_PATH_MAX];
        struct platform_file_metadata metadata = {0};
        if (!join(child, path, files.entries[i].name)) {
            ok = refuse(scan, "path_too_long:%s",
                        relative_path(scan, path));
            break;
        }
        if (platform_file_metadata_read(child, &metadata) !=
            PLATFORM_FILE_METADATA_OK) {
            int walk_errno = errno;
            ok = refuse(scan, "cannot walk %s: %s", child,
                        strerror(walk_errno));
            break;
        }
        if (metadata.links > 1) {
            scan->stats->linked++;
            if (scan->callback &&
                !scan->callback(relative_path(scan, child), metadata.links,
                                scan->context)) {
                ok = refuse(scan, "callback_refused:%s",
                            relative_path(scan, child));
                break;
            }
        }
    }
    for (size_t i = 0; ok && i < directories.count; i++) {
        if (++scan->stats->entries > ZCL_DEPENDENCY_LINK_ENTRIES_MAX) {
            ok = refuse(scan, "entry_limit_exceeded");
            break;
        }
        char child[ZCL_DEPENDENCY_LINK_PATH_MAX];
        if (!join(child, path, directories.entries[i].name)) {
            ok = refuse(scan, "path_too_long:%s",
                        relative_path(scan, path));
            break;
        }
        ok = scan_directory(scan, child, depth + 1u);
    }
    platform_directory_list_free(&files);
    platform_directory_list_free(&directories);
    return ok;
}

static bool scan_optional(struct dependency_scan *scan, const char *parent,
                          const char *relative)
{
    char path[ZCL_DEPENDENCY_LINK_PATH_MAX];
    if (!join(path, parent, relative))
        return refuse(scan, "path_too_long:%s", relative);
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(path);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING)
        return true;
    if (probe != PLATFORM_DIRECTORY_PROBE_OK)
        return refuse(scan, "dependency_root_not_real:%s",
                      relative_path(scan, path));
    return scan_directory(scan, path, 0);
}

static bool scan_build_rooms(struct dependency_scan *scan, const char *build)
{
    for (size_t i = 0; i < DEPENDENCY_BUILD_ROOM_COUNT; i++)
        if (!scan_optional(scan, build, DEPENDENCY_BUILD_ROOMS[i]))
            return false;
    return true;
}

bool zcl_dependency_links_scan(
    const char *root, zcl_dependency_linked_file_fn callback, void *context,
    struct zcl_dependency_link_stats *stats, char *why, size_t why_cap)
{
    if (stats)
        *stats = (struct zcl_dependency_link_stats){0};
    if (why && why_cap)
        why[0] = '\0';
    if (!root || !root[0] || !stats || (!why && why_cap))
        return false;
    struct dependency_scan scan = {
        .root = root, .root_len = strlen(root), .callback = callback,
        .context = context, .stats = stats, .why = why, .why_cap = why_cap,
    };
    if (scan.root_len >= ZCL_DEPENDENCY_LINK_PATH_MAX)
        return refuse(&scan, "worktree_path_too_long");
    if (platform_directory_probe_real(root) != PLATFORM_DIRECTORY_PROBE_OK)
        return refuse(&scan, "worktree_root_not_real");

    char build[ZCL_DEPENDENCY_LINK_PATH_MAX];
    if (!join(build, root, "build"))
        return refuse(&scan, "path_too_long:build");
    enum platform_directory_probe_result build_probe =
        platform_directory_probe_real(build);
    if (build_probe != PLATFORM_DIRECTORY_PROBE_OK &&
        build_probe != PLATFORM_DIRECTORY_PROBE_MISSING)
        return refuse(&scan, "dependency_root_not_real:build");
    if (!scan_optional(&scan, root, "vendor"))
        return false;
    if (build_probe == PLATFORM_DIRECTORY_PROBE_MISSING)
        return true;
    return scan_build_rooms(&scan, build);
}

bool zcl_dependency_build_room_path(const char *relative_to_build)
{
    if (!relative_to_build || !relative_to_build[0])
        return false;
    for (size_t i = 0; i < DEPENDENCY_BUILD_ROOM_COUNT; i++) {
        const size_t n = strlen(DEPENDENCY_BUILD_ROOMS[i]);
        /* A room name matches only as a whole leading component: "hotswaps/x"
         * is a different directory and is not one of these rooms. */
        if (strncmp(relative_to_build, DEPENDENCY_BUILD_ROOMS[i], n) == 0 &&
            relative_to_build[n] == '/' && relative_to_build[n + 1])
            return true;
    }
    return false;
}

#if defined(ZCL_TESTING)
bool zcl_dependency_links_scan_directory_for_testing(
    const char *directory, size_t initial_entries,
    struct zcl_dependency_link_stats *stats, char *why, size_t why_cap)
{
    if (stats)
        *stats = (struct zcl_dependency_link_stats){
            .entries = initial_entries,
        };
    if (why && why_cap)
        why[0] = '\0';
    if (!directory || !directory[0] || !stats || (!why && why_cap))
        return false;
    struct dependency_scan scan = {
        .root = directory, .root_len = strlen(directory), .stats = stats,
        .why = why, .why_cap = why_cap,
    };
    if (initial_entries > ZCL_DEPENDENCY_LINK_ENTRIES_MAX)
        return refuse(&scan, "entry_limit_exceeded");
    return scan_directory(&scan, directory, 0);
}
#endif
