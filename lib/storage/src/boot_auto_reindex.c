/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_reindex — implementation. See header for the contract.
 *
 * Crash-only recovery primitive: a bounded, fsync-durable on-disk request that
 * the next boot consumes to rebuild derived state via -reindex-chainstate
 * (rewind to the consistent reindex target + replay from blocks/). Top-level
 * file <datadir>/auto_reindex_request holding "<anchor_height> <count>",
 * NEVER part of any derived-state wipe set so the attempt budget survives
 * every rebuild tier and a crash mid-rebuild.
 */

#include "storage/boot_auto_reindex.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

static _Atomic uint32_t g_ar_stage_seq;

static void ar_path(const char *datadir, char *out, size_t n)
{
    snprintf(out, n, "%s/auto_reindex_request", datadir);
}

/* Read the on-disk (anchor, count). Returns true iff a well-formed request was
 * read. On any read/parse miss, *anchor=0 and *count=0. */
static bool ar_read(const char *path, int32_t *anchor, int *count)
{
    *anchor = 0;
    *count = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size >= 64) {
        platform_positioned_file_close(&file);
        return false;
    }
    char buf[64];
    int64_t got = platform_positioned_file_read(
        &file, buf, (size_t)before.size, 0);
    bool ok = got == (int64_t)before.size &&
              platform_positioned_file_snapshot(&file, &after) &&
              memcmp(&before, &after, sizeof(before)) == 0;
    platform_positioned_file_close(&file);
    if (ok) {
        buf[before.size] = '\0';
        ok = sscanf(buf, "%d %d", anchor, count) == 2;
    }
    if (!ok) {
        *anchor = 0;
        *count = 0;
    }
    return ok;
}

/* fsync-durable write of "<anchor> <count>\n". Returns true on success. */
static bool ar_write(const char *datadir, const char *path,
                     int32_t anchor, int count)
{
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d %d\n", (int)anchor, count);
    if (len < 0 || len >= (int)sizeof(buf))
        return false;

    char staging[640];
    int staged_len = snprintf(
        staging, sizeof(staging), "%s.%llu-%u.tmp", path,
        (unsigned long long)os_proc_current_pid(),
        (unsigned)atomic_fetch_add(&g_ar_stage_seq, 1));
    if (staged_len < 0 || (size_t)staged_len >= sizeof(staging))
        return false;
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    bool created = platform_private_file_create(staging, &file);
    bool identified = created &&
                      platform_private_file_identity(&file, &identity);
    bool ok = identified &&
              platform_private_file_write_at(&file, buf, (size_t)len, 0) &&
              platform_private_file_truncate(&file, (uint64_t)len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, staging, path) &&
              platform_private_parent_flush(datadir);
    if (!ok) {
        if (identified)
            (void)platform_private_file_retire_if_identity(
                &file, staging, &identity);
        platform_private_file_close(&file);
        fprintf(stderr,  // obs-ok:storage-primitive-error
                "[boot] boot_auto_reindex: durable write(%s) failed\n", path);
        return false;
    }
    platform_private_file_close(&file);
    return true;
}

int boot_auto_reindex_request(const char *datadir, int32_t anchor)
{
    if (!datadir)
        return 0;

    char path[512];
    ar_path(datadir, path, sizeof(path));

    int32_t cur_anchor = 0;
    int cur_count = 0;
    ar_read(path, &cur_anchor, &cur_count);

    /* TERMINAL already written: the budget was exhausted at a stable anchor and
     * the operator was paged. Do NOT re-arm a fresh count — that is exactly the
     * unbounded crash-loop. The caller must stay-up-degraded, not exit/reindex. */
    if (cur_count == BOOT_AUTO_REINDEX_TERMINAL)
        return BOOT_AUTO_REINDEX_TERMINAL;

    /* Budget keys on the MINIMUM anchor seen this episode, NOT exact equality.
     * A partial replay can leave a different tip every boot; keying on exact
     * equality would reset count=1 each time and never hit the cap. Folding the
     * anchor down to the episode minimum keeps the count monotonically climbing
     * toward the cap even as the tip moves. A strictly HIGHER first anchor (the
     * old episode cleared, a genuinely new wedge) starts a fresh episode at 1. */
    int32_t new_anchor;
    int new_count;
    if (cur_count > 0) {
        new_anchor = (anchor < cur_anchor) ? anchor : cur_anchor;
        new_count = cur_count + 1;
    } else {
        new_anchor = anchor;
        new_count = 1;
    }

    if (!ar_write(datadir, path, new_anchor, new_count))
        return 0;
    return new_count;
}

bool boot_auto_reindex_mark_terminal(const char *datadir, int32_t anchor)
{
    if (!datadir)
        return false;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    return ar_write(datadir, path, anchor, BOOT_AUTO_REINDEX_TERMINAL);
}

bool boot_auto_reindex_is_terminal(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    int32_t a = 0;
    int c = 0;
    if (!ar_read(path, &a, &c))
        return false;
    return c == BOOT_AUTO_REINDEX_TERMINAL;
}

bool boot_auto_reindex_pending(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    if (platform_private_path_absent(path))
        return false;
    /* A terminal marker is present-but-not-pending: the budget is spent, so the
     * next boot must NOT consume it as a reindex request. */
    int32_t a = 0;
    int c = 0;
    if (ar_read(path, &a, &c) && c == BOOT_AUTO_REINDEX_TERMINAL)
        return false;
    return true;
}

bool boot_auto_reindex_status(const char *datadir, int32_t *anchor,
                              int *count)
{
    if (anchor)
        *anchor = 0;
    if (count)
        *count = 0;
    if (!datadir)
        return false;

    char path[512];
    ar_path(datadir, path, sizeof(path));
    int32_t a = 0;
    int c = 0;
    if (!ar_read(path, &a, &c))
        return false;
    if (anchor)
        *anchor = a;
    if (count)
        *count = c;
    return true;
}

void boot_auto_reindex_clear(const char *datadir)
{
    if (!datadir)
        return;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    if (platform_private_path_absent(path))
        return;
    struct platform_private_file file;
    struct platform_private_file_identity identity;
    platform_private_file_init(&file);
    if (platform_private_file_open_locked(path, &file) &&
        platform_private_file_identity(&file, &identity) &&
        platform_private_file_retire_if_identity(&file, path, &identity))
        (void)platform_private_parent_flush(datadir);
    platform_private_file_close(&file);
}
