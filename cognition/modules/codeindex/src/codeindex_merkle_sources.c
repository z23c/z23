/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Adapt the canonical source inventory to native Merkle cache keys. */

#include "codeindex_priv.h"
#include "util/log_macros.h"
#if defined(_WIN32)
#include "platform/directory_compat.h"
#endif

struct merkle_source_visitor {
    ci_merkle_source_cb callback;
    void *user;
};

#if defined(_WIN32)
static bool merkle_source_visit(const char *relpath,
    const struct platform_directory_entry *snapshot, void *user)
{
    struct merkle_source_visitor *visitor = user;
    if (!snapshot || !snapshot->snapshot_valid || snapshot->file_high != 0)
        LOG_FAIL("codeindex", "unusable Windows source identity: %s", relpath);
    const struct ci_merkle_stat_key key = {
        .dev = snapshot->volume,
        .ino = snapshot->file_low,
        .size = snapshot->size,
        .mtime_sec = (uint64_t)snapshot->modified_seconds,
        .mtime_nsec = snapshot->modified_nanoseconds,
        .ctime_sec = (uint64_t)snapshot->changed_seconds,
        .ctime_nsec = snapshot->changed_nanoseconds,
    };
    return visitor->callback(relpath, &key, visitor->user);
}
#else
static bool merkle_source_visit(const char *relpath,
    const struct stat *st, void *user)
{
    struct merkle_source_visitor *visitor = user;
    const struct ci_merkle_stat_key key = {
        .dev = (uint64_t)st->st_dev,
        .ino = (uint64_t)st->st_ino,
        .size = (uint64_t)st->st_size,
        .mtime_sec = (uint64_t)st->st_mtim.tv_sec,
        .mtime_nsec = (uint64_t)st->st_mtim.tv_nsec,
        .ctime_sec = (uint64_t)st->st_ctim.tv_sec,
        .ctime_nsec = (uint64_t)st->st_ctim.tv_nsec,
    };
    return visitor->callback(relpath, &key, visitor->user);
}
#endif

bool ci_enumerate_merkle_sources(const char *root,
    ci_merkle_source_cb cb, void *user)
{
    if (!root || !cb)
        LOG_FAIL("codeindex", "invalid Merkle source visitor");
    struct merkle_source_visitor visitor = { .callback = cb, .user = user };
#if defined(_WIN32)
    return ci_enumerate_source_snapshots_windows(root, merkle_source_visit,
                                                &visitor);
#else
    return ci_enumerate_sources(root, merkle_source_visit, &visitor);
#endif
}
