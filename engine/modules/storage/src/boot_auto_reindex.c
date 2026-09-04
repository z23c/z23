/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_reindex — implementation. See header for the contract.
 *
 * Crash-only recovery primitive: a bounded, fsync-durable on-disk request that
 * the next boot consumes to rebuild derived state via -reindex-chainstate
 * (rewind to the consistent reindex target + replay from blocks/). Top-level
 * file <datadir>/auto_reindex_request holding
 * "<anchor_height> <count> <reason>", NEVER part of any derived-state wipe set
 * so the attempt budget survives every rebuild tier and a crash mid-rebuild.
 *
 * FORMAT COMPATIBILITY: a request written before the reason class existed has
 * only two fields. It still parses, and reads back as
 * BOOT_AUTO_REINDEX_REASON_UNSPECIFIED — the class that keeps the historical
 * coins-best stale-clear behaviour. An upgrade therefore never turns an
 * in-flight request into an unclearable one.
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

static bool reason_is_known(int reason)
{
    return reason == BOOT_AUTO_REINDEX_REASON_UNSPECIFIED ||
           reason == BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY;
}

const char *boot_auto_reindex_reason_name(int reason)
{
    switch (reason) {
    case BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY:
        return "index_integrity";
    case BOOT_AUTO_REINDEX_REASON_UNSPECIFIED:
        return "unspecified";
    default:
        /* An unknown class from a NEWER binary that wrote this datadir. Name it
         * rather than silently rendering it as "unspecified", which would tell
         * the reader the opposite of the truth. */
        return "unrecognised";
    }
}

/* Read the on-disk (anchor, count, reason). Returns true iff a well-formed
 * request was read. A legacy 2-field request reads back with
 * *reason = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED. On any read/parse miss,
 * *anchor=0, *count=0 and *reason=UNSPECIFIED. */
static bool ar_read(const char *path, int32_t *anchor, int *count, int *reason)
{
    *anchor = 0;
    *count = 0;
    *reason = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
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
    /* Field-wise, never memcmp: the snapshot struct has alignment padding
     * whose bytes are undefined, so a whole-object compare reports the SAME
     * unchanged file as changed and silently loses the budget count. */
    bool ok = got == (int64_t)before.size &&
              platform_positioned_file_snapshot(&file, &after) &&
              platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok) {
        buf[before.size] = '\0';
        /* Two fields is the legacy request; three carries the reason class.
         * Accept both — refusing the legacy shape would silently drop an
         * in-flight budget across the upgrade and re-arm the loop this module
         * exists to bound. */
        int fields = sscanf(buf, "%d %d %d", anchor, count, reason);
        if (fields == 2)
            *reason = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
        ok = fields >= 2;
    }
    if (!ok) {
        *anchor = 0;
        *count = 0;
        *reason = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    }
    return ok;
}

/* fsync-durable write of "<anchor> <count> <reason>\n". Returns true on
 * success. */
static bool ar_write(const char *datadir, const char *path,
                     int32_t anchor, int count, int reason)
{
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d %d %d\n", (int)anchor, count,
                       reason);
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

int boot_auto_reindex_request(const char *datadir, int32_t anchor, int reason)
{
    if (!datadir)
        return 0;
    if (!reason_is_known(reason))
        reason = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;

    char path[512];
    ar_path(datadir, path, sizeof(path));

    int32_t cur_anchor = 0;
    int cur_count = 0;
    int cur_reason = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    ar_read(path, &cur_anchor, &cur_count, &cur_reason);

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
    int new_reason;
    if (cur_count > 0) {
        new_anchor = (anchor < cur_anchor) ? anchor : cur_anchor;
        new_count = cur_count + 1;
        /* Reason escalates and never demotes within an episode: one boot that
         * saw block-index mismatches is enough to keep the whole episode out of
         * the coins-best stale-clear, even if a later boot re-arms with a
         * weaker class. Demotion would hand the clear path back its veto. */
        new_reason = (reason > cur_reason) ? reason : cur_reason;
    } else {
        new_anchor = anchor;
        new_count = 1;
        new_reason = reason;
    }

    if (!ar_write(datadir, path, new_anchor, new_count, new_reason))
        return 0;
    return new_count;
}

bool boot_auto_reindex_mark_terminal(const char *datadir, int32_t anchor)
{
    if (!datadir)
        return false;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    /* The terminal marker preserves the recorded reason class so an operator
     * (and `boot_auto_reindex_reason_of`) can still see WHY the budget was
     * spent after the node parks. */
    int32_t a = 0;
    int c = 0;
    int r = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    ar_read(path, &a, &c, &r);
    return ar_write(datadir, path, anchor, BOOT_AUTO_REINDEX_TERMINAL, r);
}

bool boot_auto_reindex_is_terminal(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    int32_t a = 0;
    int c = 0;
    int r = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    if (!ar_read(path, &a, &c, &r))
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
    int r = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    if (ar_read(path, &a, &c, &r) && c == BOOT_AUTO_REINDEX_TERMINAL)
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
    int r = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    if (!ar_read(path, &a, &c, &r))
        return false;
    if (anchor)
        *anchor = a;
    if (count)
        *count = c;
    return true;
}

int boot_auto_reindex_reason_of(const char *datadir)
{
    if (!datadir)
        return BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    char path[512];
    ar_path(datadir, path, sizeof(path));
    int32_t a = 0;
    int c = 0;
    int r = BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    if (!ar_read(path, &a, &c, &r))
        return BOOT_AUTO_REINDEX_REASON_UNSPECIFIED;
    return r;
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
