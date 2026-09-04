/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * log_rotate — implementation. See util/log_rotate.h for why an append-mode
 * log is bounded by copy-and-truncate rather than by rename.
 *
 * Every file operation goes through the platform private-file seam, so the
 * same source bounds a log on POSIX and on Windows.
 */

#include "util/log_rotate.h"

#include "base/safe_alloc.h"
#include "platform/file_metadata.h"
#include "platform/private_file.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LR_SUBSYS "log_rotate"

/* Copied in chunks rather than in one allocation: the whole point of the
 * module is to run on a memory-constrained box whose log grew to gigabytes,
 * and a rotation that needs the log's size in RAM would be the new defect. */
#define LR_COPY_CHUNK (1024u * 1024u)

int64_t log_rotate_file_size(const char *path)
{
    if (!path || !path[0])
        return -1;
    struct platform_file_metadata md;
    if (platform_file_metadata_read(path, &md) != PLATFORM_FILE_METADATA_OK)
        return -1;
    return (int64_t)md.size;
}

bool log_rotate_if_over(const char *path, int64_t max_bytes,
                        int64_t *out_rotated_bytes)
{
    if (!path || !path[0] || max_bytes <= 0)
        return false;

    int64_t size = log_rotate_file_size(path);
    if (size <= max_bytes)
        return false;

    char previous[1024];
    int n = snprintf(previous, sizeof(previous), "%s.1", path);
    if (n <= 0 || (size_t)n >= sizeof(previous))
        return false;

    struct platform_private_file src;
    platform_private_file_init(&src);
    if (!platform_private_file_open_locked(path, &src)) {
        LOG_WARN(LR_SUBSYS, "cannot open %s to bound it at %lld bytes", path,
                 (long long)max_bytes);
        return false;
    }

    /* Re-measure through the HANDLE. The size that decided to rotate came
     * from a pathname; between then and now the writer appended, and
     * truncating more than was copied would silently drop those lines. */
    uint64_t handle_size = 0;
    if (!platform_private_file_size(&src, &handle_size)) {
        platform_private_file_close(&src);
        return false;
    }

    struct platform_private_file dst;
    platform_private_file_init(&dst);
    /* The previous generation is REPLACED, so remove it first: create is
     * exclusive by design and would otherwise refuse from the second
     * rotation onward, leaving the log unbounded after exactly one round. */
    (void)remove(previous);
    if (!platform_private_file_create(previous, &dst)) {
        LOG_WARN(LR_SUBSYS, "cannot write %s; leaving %s unrotated", previous,
                 path);
        platform_private_file_close(&src);
        return false;
    }

    uint8_t *buf = zcl_malloc(LR_COPY_CHUNK, "log_rotate_copy");
    if (!buf) {
        platform_private_file_close(&dst);
        platform_private_file_close(&src);
        return false;
    }

    bool ok = true;
    uint64_t copied = 0;
    while (ok && copied < handle_size) {
        uint64_t remaining = handle_size - copied;
        size_t want = remaining > LR_COPY_CHUNK ? LR_COPY_CHUNK
                                                : (size_t)remaining;
        ok = platform_private_file_read_at(&src, buf, want, copied) &&
             platform_private_file_write_at(&dst, buf, want, copied);
        if (ok)
            copied += want;
    }
    free(buf);
    ok = ok && platform_private_file_flush(&dst);
    platform_private_file_close(&dst);

    if (!ok) {
        /* The copy failed, so the log is the only surviving record of those
         * lines. Do NOT truncate: an unbounded log is a smaller problem than
         * a lost one. */
        LOG_WARN(LR_SUBSYS, "copy of %s to %s failed; %s left intact", path,
                 previous, path);
        platform_private_file_close(&src);
        return false;
    }

    if (!platform_private_file_truncate(&src, 0)) {
        LOG_WARN(LR_SUBSYS, "cannot truncate %s after copying it to %s", path,
                 previous);
        platform_private_file_close(&src);
        return false;
    }
    platform_private_file_close(&src);

    LOG_INFO(LR_SUBSYS, "rotated %s at %lld bytes (bound %lld); previous "
             "generation kept at %s",
             path, (long long)handle_size, (long long)max_bytes, previous);
    if (out_rotated_bytes)
        *out_rotated_bytes = (int64_t)handle_size;
    return true;
}
