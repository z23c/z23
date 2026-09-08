/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded observation of multiply-linked worktree dependencies. */
#ifndef ZCL_TOOLS_DEV_DEPENDENCY_LINKS_H
#define ZCL_TOOLS_DEV_DEPENDENCY_LINKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_dependency_link_stats {
    size_t entries;
    size_t linked;
};

#define ZCL_DEPENDENCY_LINK_PATH_MAX 4096u
#define ZCL_DEPENDENCY_LINK_DEPTH_MAX 32u
#define ZCL_DEPENDENCY_LINK_ENTRIES_MAX 50000u

typedef bool (*zcl_dependency_linked_file_fn)(const char *relative_path,
                                               uint64_t links,
                                               void *context);

/* Inspect vendor/, build/hotswap/, and build/githooks/ beneath an existing
 * real worktree. Missing optional roots are empty. The callback is optional
 * and runs only for regular files whose current link count exceeds one;
 * relative_path is borrowed and valid only for that callback invocation.
 * This is a bounded pathname observation, not confinement, locking, or proof
 * that another process cannot replace a path after it was inspected. */
bool zcl_dependency_links_scan(
    const char *worktree_root, zcl_dependency_linked_file_fn on_linked,
    void *context, struct zcl_dependency_link_stats *stats,
    char *why, size_t why_cap);

/* Whether `relative_to_build` — a path relative to a checkout's build/
 * directory — falls inside one of the dependency rooms the scan above walks.
 * Every regular file in one of those rooms must own its inode, so no seeding
 * path may reach it by hardlink. The room names live in one table with the
 * scan itself, because a seeder and this gate that disagreed about them would
 * produce exactly the failure the gate exists to report. */
bool zcl_dependency_build_room_path(const char *relative_to_build);

#if defined(ZCL_TESTING)
bool zcl_dependency_links_scan_directory_for_testing(
    const char *directory, size_t initial_entries,
    struct zcl_dependency_link_stats *stats, char *why, size_t why_cap);
#endif

#endif /* ZCL_TOOLS_DEV_DEPENDENCY_LINKS_H */
