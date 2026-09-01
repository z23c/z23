/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Persist watcher ownership records through retained handles. */
#include "platform/watcher_store.h"

#include "platform/rng.h"

#include <stdio.h>
#include <string.h>

static enum platform_watcher_store_result map_result(
    enum platform_directory_result result)
{
    switch (result) {
    case PLATFORM_DIRECTORY_OK: return PLATFORM_WATCHER_STORE_OK;
    case PLATFORM_DIRECTORY_MISSING: return PLATFORM_WATCHER_STORE_MISSING;
    case PLATFORM_DIRECTORY_EXISTS: return PLATFORM_WATCHER_STORE_EXISTS;
    case PLATFORM_DIRECTORY_REFUSED: return PLATFORM_WATCHER_STORE_REFUSED;
    case PLATFORM_DIRECTORY_INVALID: return PLATFORM_WATCHER_STORE_INVALID;
    default: return PLATFORM_WATCHER_STORE_IO;
    }
}

static void identity_from_info(
    const struct platform_directory_child_info *info,
    struct platform_watcher_record_identity *identity)
{
    if (!identity) return;
    *identity = (struct platform_watcher_record_identity){
        .size = info->size, .volume = info->volume,
        .file_low = info->file_low, .file_high = info->file_high,
        .modified_seconds = info->modified_seconds,
        .changed_seconds = info->changed_seconds,
        .modified_nanoseconds = info->modified_nanoseconds,
        .changed_nanoseconds = info->changed_nanoseconds};
}

static bool identity_equal(const struct platform_directory_child_info *info,
                           const struct platform_watcher_record_identity *id)
{
    return id && info->size == id->size && info->volume == id->volume &&
           info->file_low == id->file_low && info->file_high == id->file_high &&
           info->modified_seconds == id->modified_seconds &&
           info->changed_seconds == id->changed_seconds &&
           info->modified_nanoseconds == id->modified_nanoseconds &&
           info->changed_nanoseconds == id->changed_nanoseconds;
}

static bool info_stable(const struct platform_directory_child_info *a,
                        const struct platform_directory_child_info *b)
{
    struct platform_watcher_record_identity id;
    identity_from_info(a, &id);
    return identity_equal(b, &id) &&
           a->current_user_only == b->current_user_only;
}

void platform_watcher_store_init(struct platform_watcher_store *store)
{
    if (!store) return;
    platform_directory_transaction_init(&store->directory);
    platform_directory_lock_init(&store->ownership);
    store->owns = false;
}

enum platform_watcher_store_result platform_watcher_store_open(
    struct platform_watcher_store *store, const char *private_state_dir)
{
    if (!store || !private_state_dir || !private_state_dir[0] ||
        store->directory.native != UINTPTR_MAX)
        return PLATFORM_WATCHER_STORE_INVALID;
    return platform_directory_transaction_open(&store->directory,
                                                private_state_dir)
               ? PLATFORM_WATCHER_STORE_OK : PLATFORM_WATCHER_STORE_REFUSED;
}

enum platform_watcher_store_result platform_watcher_store_try_acquire(
    struct platform_watcher_store *store, const char *lock_leaf, bool create)
{
    if (!store || store->owns) return PLATFORM_WATCHER_STORE_INVALID;
    enum platform_directory_result result = platform_directory_lock_acquire(
        &store->directory, lock_leaf, create,
        PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &store->ownership);
    if (result == PLATFORM_DIRECTORY_REFUSED)
        return PLATFORM_WATCHER_STORE_BUSY;
    store->owns = result == PLATFORM_DIRECTORY_OK;
    return map_result(result);
}

void platform_watcher_store_release(struct platform_watcher_store *store)
{
    if (!store) return;
    platform_directory_lock_release(&store->ownership);
    store->owns = false;
}

static enum platform_watcher_store_result read_record(
    struct platform_watcher_store *store, const char *leaf, void *bytes,
    size_t capacity, size_t *length,
    struct platform_watcher_record_identity *identity)
{
    struct platform_directory_child child;
    platform_directory_child_init(&child);
    enum platform_directory_result opened = platform_directory_child_open_result(
        &store->directory, leaf, false, true, &child, NULL);
    if (opened != PLATFORM_DIRECTORY_OK) return map_result(opened);
    struct platform_directory_child_info before = {0}, after = {0};
    bool ok = platform_directory_child_info(&child, &before) &&
              before.current_user_only && before.size <= capacity &&
              (before.size == 0 || platform_directory_child_read_exact(
                   &child, bytes, (size_t)before.size, 0)) &&
              platform_directory_child_info(&child, &after) &&
              info_stable(&before, &after);
    platform_directory_child_close(&child);
    if (!ok) return PLATFORM_WATCHER_STORE_REFUSED;
    if (length) *length = (size_t)before.size;
    identity_from_info(&before, identity);
    return PLATFORM_WATCHER_STORE_OK;
}

enum platform_watcher_store_result platform_watcher_store_publish(
    struct platform_watcher_store *store, const char *leaf,
    const void *bytes, size_t length,
    const struct platform_watcher_record_identity *expected,
    struct platform_watcher_record_identity *published)
{
    if (!store || !store->owns || !leaf || !leaf[0] || (!bytes && length))
        return PLATFORM_WATCHER_STORE_INVALID;
    if (expected) {
        struct platform_directory_child child;
        platform_directory_child_init(&child);
        if (!platform_directory_child_open(&store->directory, leaf, &child))
            return PLATFORM_WATCHER_STORE_MISSING;
        struct platform_directory_child_info info;
        bool matches = platform_directory_child_info(&child, &info) &&
                       info.current_user_only && identity_equal(&info, expected);
        platform_directory_child_close(&child);
        if (!matches) return PLATFORM_WATCHER_STORE_REFUSED;
    }
    uint8_t random[16]; char staging[96];
    if (!rng_fill(random, sizeof(random))) return PLATFORM_WATCHER_STORE_IO;
    int n = snprintf(staging, sizeof(staging), ".watcher-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.tmp",
        random[0],random[1],random[2],random[3],random[4],random[5],random[6],random[7],
        random[8],random[9],random[10],random[11],random[12],random[13],random[14],random[15]);
    struct platform_directory_child staged;
    platform_directory_child_init(&staged);
    bool ok = n > 0 && n < (int)sizeof(staging) &&
              platform_directory_child_create(&store->directory, staging, &staged) &&
              platform_directory_child_write_exact(&staged, bytes, length, 0) &&
              platform_directory_child_truncate(&staged, length) &&
              platform_directory_child_flush(&staged) &&
              platform_directory_child_replace(&store->directory, &staged,
                                                leaf, false);
    platform_directory_child_close(&staged);
    if (!ok) {
        (void)platform_directory_child_unlink(&store->directory, staging, true);
        return PLATFORM_WATCHER_STORE_IO;
    }
    struct platform_directory_child child;
    struct platform_directory_child_info info;
    platform_directory_child_init(&child);
    bool observed = platform_directory_child_open(&store->directory, leaf,
                                                   &child) &&
                    platform_directory_child_info(&child, &info) &&
                    info.current_user_only;
    platform_directory_child_close(&child);
    if (!observed) return PLATFORM_WATCHER_STORE_REFUSED;
    identity_from_info(&info, published);
    return PLATFORM_WATCHER_STORE_OK;
}

enum platform_watcher_store_result platform_watcher_store_read_while_busy(
    struct platform_watcher_store *store, const char *lock_leaf,
    const char *record_leaf, void *bytes, size_t capacity, size_t *length,
    struct platform_watcher_record_identity *identity)
{
    if (!store || store->owns) return PLATFORM_WATCHER_STORE_INVALID;
    struct platform_directory_lock probe;
    platform_directory_lock_init(&probe);
    enum platform_directory_result lock_result = platform_directory_lock_acquire(
        &store->directory, lock_leaf, false,
        PLATFORM_DIRECTORY_LOCK_SHARED, &probe);
    if (lock_result == PLATFORM_DIRECTORY_OK) {
        platform_directory_lock_release(&probe);
        return PLATFORM_WATCHER_STORE_IDLE;
    }
    if (lock_result != PLATFORM_DIRECTORY_REFUSED)
        return map_result(lock_result);
    return read_record(store, record_leaf, bytes, capacity, length, identity);
}

enum platform_watcher_store_result platform_watcher_store_retire_exact(
    struct platform_watcher_store *store, const char *leaf,
    const struct platform_watcher_record_identity *expected)
{
    if (!store || !store->owns || !expected)
        return PLATFORM_WATCHER_STORE_INVALID;
    struct platform_directory_child child;
    platform_directory_child_init(&child);
    if (!platform_directory_child_open(&store->directory, leaf, &child))
        return PLATFORM_WATCHER_STORE_MISSING;
    struct platform_directory_child_info info;
    bool matches = platform_directory_child_info(&child, &info) &&
                   info.current_user_only && identity_equal(&info, expected);
    platform_directory_child_close(&child);
    if (!matches) return PLATFORM_WATCHER_STORE_REFUSED;
    return map_result(platform_directory_child_unlink_result(
        &store->directory, leaf));
}

void platform_watcher_store_close(struct platform_watcher_store *store)
{
    if (!store) return;
    platform_watcher_store_release(store);
    platform_directory_transaction_close(&store->directory);
    platform_watcher_store_init(store);
}
