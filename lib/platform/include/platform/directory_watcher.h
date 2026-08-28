/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
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
/* Waits at most timeout_ms. The stop predicate is sampled at most every 50ms. */
enum platform_directory_watch_result platform_directory_watcher_wait(
    struct platform_directory_watcher *watcher, uint32_t timeout_ms,
    platform_directory_watcher_stop stop, void *stop_opaque);
void platform_directory_watcher_close(struct platform_directory_watcher *watcher);

#endif
