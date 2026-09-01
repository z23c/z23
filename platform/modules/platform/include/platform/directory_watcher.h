/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Provide recursive native directory change observation. */
#ifndef ZCL_PLATFORM_DIRECTORY_WATCHER_H
#define ZCL_PLATFORM_DIRECTORY_WATCHER_H

#include <stdbool.h>
#include <stdint.h>

struct platform_directory_watcher { uintptr_t native; };
typedef bool (*platform_directory_watcher_stop)(void *opaque);

enum platform_directory_watch_result {
    PLATFORM_DIRECTORY_WATCH_CHANGED = 0,
    PLATFORM_DIRECTORY_WATCH_TIMEOUT,
    PLATFORM_DIRECTORY_WATCH_STOPPED,
    PLATFORM_DIRECTORY_WATCH_OVERFLOW,
    PLATFORM_DIRECTORY_WATCH_ERROR
};

void platform_directory_watcher_init(struct platform_directory_watcher *watcher);
/* Retains the exact canonical, non-reparse directory until close. */
bool platform_directory_watcher_open(struct platform_directory_watcher *watcher,
                                     const char *root_utf8);
#if defined(__APPLE__)
/* kqueue reports directory-level vnode changes rather than child names. The
 * filtered form lets recursive consumers exclude generated subtrees before
 * descriptors are retained, preventing their own build/cache writes from
 * feeding back as source edits. `descend` receives one directory basename;
 * `include_file` receives one absolute canonical-root child path. */
typedef bool (*platform_directory_watcher_descend)(const char *name,
                                                    void *opaque);
typedef bool (*platform_directory_watcher_include_file)(const char *path_utf8,
                                                         void *opaque);
bool platform_directory_watcher_open_filtered(
    struct platform_directory_watcher *watcher, const char *root_utf8,
    platform_directory_watcher_descend descend,
    platform_directory_watcher_include_file include_file, void *opaque);
#endif
/* Waits at most timeout_ms. The stop predicate is sampled at most every 50ms. */
enum platform_directory_watch_result platform_directory_watcher_wait(
    struct platform_directory_watcher *watcher, uint32_t timeout_ms,
    platform_directory_watcher_stop stop, void *stop_opaque);
void platform_directory_watcher_close(struct platform_directory_watcher *watcher);

#endif
