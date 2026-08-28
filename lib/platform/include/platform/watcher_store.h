/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Persist watcher ownership records through retained handles. */
#ifndef ZCL_PLATFORM_WATCHER_STORE_H
#define ZCL_PLATFORM_WATCHER_STORE_H

#include "platform/directory_transaction.h"

enum platform_watcher_store_result {
    PLATFORM_WATCHER_STORE_OK = 0,
    PLATFORM_WATCHER_STORE_BUSY,
    PLATFORM_WATCHER_STORE_IDLE,
    PLATFORM_WATCHER_STORE_MISSING,
    PLATFORM_WATCHER_STORE_EXISTS,
    PLATFORM_WATCHER_STORE_REFUSED,
    PLATFORM_WATCHER_STORE_IO,
    PLATFORM_WATCHER_STORE_INVALID
};

struct platform_watcher_record_identity {
    uint64_t size, volume, file_low, file_high;
    int64_t modified_seconds, changed_seconds;
    uint32_t modified_nanoseconds, changed_nanoseconds;
};

struct platform_watcher_store {
    struct platform_directory_transaction directory;
    struct platform_directory_lock ownership;
    bool owns;
};

void platform_watcher_store_init(struct platform_watcher_store *store);
enum platform_watcher_store_result platform_watcher_store_open(
    struct platform_watcher_store *store, const char *private_state_dir);
enum platform_watcher_store_result platform_watcher_store_try_acquire(
    struct platform_watcher_store *store, const char *lock_leaf, bool create);
void platform_watcher_store_release(struct platform_watcher_store *store);
enum platform_watcher_store_result platform_watcher_store_publish(
    struct platform_watcher_store *store, const char *record_leaf,
    const void *bytes, size_t length,
    const struct platform_watcher_record_identity *expected,
    struct platform_watcher_record_identity *published);
enum platform_watcher_store_result platform_watcher_store_read_while_busy(
    struct platform_watcher_store *store, const char *lock_leaf,
    const char *record_leaf, void *bytes, size_t capacity, size_t *length,
    struct platform_watcher_record_identity *identity);
enum platform_watcher_store_result platform_watcher_store_retire_exact(
    struct platform_watcher_store *store, const char *record_leaf,
    const struct platform_watcher_record_identity *expected);
void platform_watcher_store_close(struct platform_watcher_store *store);

#endif
