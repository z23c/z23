/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_refold — implementation. See header for the contract.
 *
 * Bounded, fsync-durable on-disk request that the next boot consumes to run
 * boot_refold_from_anchor_reset (re-seed coins_kv from the SHA3-checkpoint-bound
 * anchor snapshot + fold the anchor->tip delta). Top-level file
 * <datadir>/auto_refold_request holding "<anchor_height> <attempts>", NEVER part
 * of any derived-state wipe set so the attempt budget survives a crash / FATAL
 * mid-refold. The attempt count increments at CONSUME (boot) time so a
 * FATAL-looping anchor is bounded even though the arming rung never runs again.
 */

#include "storage/boot_auto_refold.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t g_arf_temp_sequence;

static void arf_path(const char *datadir, char *out, size_t n)
{
    snprintf(out, n, "%s/auto_refold_request", datadir);
}

/* Read the on-disk (anchor, count). Returns true iff a well-formed request was
 * read. On any read/parse miss, *anchor=0 and *count=0. */
static bool arf_read(const char *path, int32_t *anchor, int *count)
{
    *anchor = 0;
    *count = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        !platform_positioned_file_is_private(&file) || before.size == 0 ||
        before.size >= 64) {
        platform_positioned_file_close(&file);
        return false;
    }
    char raw[64];
    int64_t got = platform_positioned_file_read(&file, raw,
                                                (size_t)before.size, 0);
    bool stable = got == (int64_t)before.size &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds &&
                  before.changed_seconds == after.changed_seconds &&
                  before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!stable)
        return false;
    raw[before.size] = '\0';
    bool ok = sscanf(raw, "%d %d", anchor, count) == 2;
    if (!ok) {
        *anchor = 0;
        *count = 0;
    }
    return ok;
}

/* fsync-durable write of "<anchor> <count>\n". Returns true on success. */
static bool arf_write(const char *datadir, const char *path,
                      int32_t anchor, int count)
{
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d %d\n", (int)anchor, count);
    if (len < 0 || len >= (int)sizeof(buf))
        return false;

    char resolved[512], parent[512], staging_path[576];
    if (!platform_private_path_resolve(path, resolved, sizeof(resolved),
                                       parent, sizeof(parent))) {
        fprintf(stderr,  // obs-ok:storage-primitive-error
                "[boot] boot_auto_refold: unsafe destination %s\n", path);
        return false;
    }
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    bool created = false;
    for (unsigned int attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t seq = atomic_fetch_add(&g_arf_temp_sequence, 1);
        int n = snprintf(staging_path, sizeof(staging_path), "%s.tmp.%llu",
                         resolved, (unsigned long long)seq);
        if (n <= 0 || (size_t)n >= sizeof(staging_path))
            break;
        created = platform_private_file_create(staging_path, &staged);
        if (!created && errno != EEXIST)
            break;
    }
    bool ok = created &&
              platform_private_file_write_at(&staged, buf, (size_t)len, 0) &&
              platform_private_file_truncate(&staged, (uint64_t)len) &&
              platform_private_file_flush(&staged) &&
              platform_private_file_replace(&staged, staging_path, resolved);
    platform_private_file_close(&staged);
    if (!ok || !platform_private_parent_flush(parent)) {
        fprintf(stderr,  // obs-ok:storage-primitive-error
                "[boot] boot_auto_refold: durable replace(%s) failed\n", path);
        if (created)
            (void)platform_private_file_unlink_missing_ok(staging_path);
        return false;
    }
    (void)datadir;
    return true;
}

int boot_auto_refold_request(const char *datadir, int32_t anchor)
{
    if (!datadir)
        return 0;

    char path[512];
    arf_path(datadir, path, sizeof(path));

    int32_t cur_anchor = 0;
    int cur_count = 0;
    bool have = arf_read(path, &cur_anchor, &cur_count);

    /* TERMINAL already written: the budget was exhausted at a stable anchor and
     * the operator was paged. Do NOT re-arm — that is exactly the unbounded
     * crash-loop this primitive exists to prevent. */
    if (have && cur_count == BOOT_AUTO_REFOLD_TERMINAL)
        return BOOT_AUTO_REFOLD_TERMINAL;

    /* Already armed (and not terminal): leave it — attempts bump at consume
     * time, never at arm time, so a re-arming rung tick cannot inflate the
     * budget. Report the current attempt count so the caller can HOLD. */
    if (have && cur_count >= 0)
        return cur_count > 0 ? cur_count : 1;

    /* Fresh arm: attempts=0 (armed, not yet attempted by any boot). */
    if (!arf_write(datadir, path, anchor, 0))
        return 0;
    return 1;
}

bool boot_auto_refold_pending(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    arf_path(datadir, path, sizeof(path));
    if (platform_private_path_absent(path))
        return false;
    int32_t a = 0;
    int c = 0;
    if (arf_read(path, &a, &c) && c == BOOT_AUTO_REFOLD_TERMINAL)
        return false;  /* terminal: present-but-not-pending */
    return true;
}

bool boot_auto_refold_consume(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    arf_path(datadir, path, sizeof(path));

    int32_t anchor = 0;
    int count = 0;
    if (!arf_read(path, &anchor, &count))
        return false;  /* no request */
    if (count == BOOT_AUTO_REFOLD_TERMINAL)
        return false;  /* budget already spent */

    if (count >= BOOT_AUTO_REFOLD_MAX) {
        /* Budget exhausted: persist the terminal marker (do NOT delete — a
         * delete would let the next boot re-arm a fresh count and loop) and
         * refuse the refold so the node boots normally + the escalator pages. */
        (void)arf_write(datadir, path, anchor, BOOT_AUTO_REFOLD_TERMINAL);
        fprintf(stderr,  // obs-ok:storage-primitive-error
                "[boot] boot_auto_refold: anchor=%d attempts=%d exhausted the "
                "bounded budget (max=%d) — marking TERMINAL, booting normally "
                "(the escalator will page)\n",
                (int)anchor, count, BOOT_AUTO_REFOLD_MAX);
        return false;
    }

    /* Count this boot's attempt BEFORE running the refold, so a FATAL-exit mid
     * refold still burns the budget (the reset _exit()s on a mismatch). */
    if (!arf_write(datadir, path, anchor, count + 1))
        return false;
    return true;
}

bool boot_auto_refold_status(const char *datadir, int32_t *anchor, int *count)
{
    if (anchor)
        *anchor = 0;
    if (count)
        *count = 0;
    if (!datadir)
        return false;

    char path[512];
    arf_path(datadir, path, sizeof(path));
    int32_t a = 0;
    int c = 0;
    if (!arf_read(path, &a, &c))
        return false;
    if (anchor)
        *anchor = a;
    if (count)
        *count = c;
    return true;
}

bool boot_auto_refold_is_terminal(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    arf_path(datadir, path, sizeof(path));
    int32_t a = 0;
    int c = 0;
    if (!arf_read(path, &a, &c))
        return false;
    return c == BOOT_AUTO_REFOLD_TERMINAL;
}

void boot_auto_refold_clear(const char *datadir)
{
    if (!datadir)
        return;
    char path[512];
    arf_path(datadir, path, sizeof(path));
    (void)platform_private_file_unlink_missing_ok(path);
    (void)platform_private_parent_flush(datadir);
}
