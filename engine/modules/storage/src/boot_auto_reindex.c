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

/* fsync-durable staged replace of `path` with `buf`. Shared by the request
 * file and the repair-episode ledger — both are top-level sentinels that must
 * survive a crash mid-rebuild, so they get one write path, not two. */
static bool ar_durable_write(const char *datadir, const char *path,
                             const char *buf, size_t len)
{
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
              platform_private_file_write_at(&file, buf, len, 0) &&
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
    return ar_durable_write(datadir, path, buf, (size_t)len);
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

/* ── Repair-episode ledger ───────────────────────────────────────────────
 * Contract + why the attempt count cannot live in the request file:
 * storage/boot_auto_reindex.h. */

static void ep_path(const char *datadir, char *out, size_t n)
{
    snprintf(out, n, "%s/boot_repair_episode", datadir);
}

uint64_t boot_repair_episode_signature(int tip_h, int zero_nbits,
                                       int mismatches, int first_mismatch_h)
{
    /* FNV-1a over the four measured fields. The point is only that an
     * IDENTICAL finding hashes identically and a materially different one
     * (the damage moved, or partly healed) does not — never collision
     * resistance against an adversary: nothing here is attacker-chosen, and
     * the worst a collision could do is retire an episode one boot early. */
    uint64_t h = 1469598103934665603ULL;
    const int fields[4] = { tip_h, zero_nbits, mismatches, first_mismatch_h };
    for (size_t i = 0; i < 4; i++) {
        uint32_t v = (uint32_t)fields[i];
        for (int b = 0; b < 4; b++) {
            h ^= (uint64_t)((v >> (8 * b)) & 0xffu);
            h *= 1099511628211ULL;
        }
    }
    /* Never zero: an absent ledger reads back as 0, and the two must not be
     * confusable. */
    return h ? h : 1ULL;
}

/* Read "<signature> <attempts>". Returns true iff a well-formed record was
 * read; on any miss *sig=0 and *attempts=0. Mirrors ar_read's torn-read guard
 * (snapshot before and after, compared field-wise). */
static bool ep_read(const char *path, uint64_t *sig, int *attempts)
{
    *sig = 0;
    *attempts = 0;
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
              platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok) {
        buf[before.size] = '\0';
        unsigned long long s = 0;
        int a = 0;
        ok = sscanf(buf, "%llu %d", &s, &a) == 2 && s != 0 && a > 0;
        if (ok) {
            *sig = (uint64_t)s;
            *attempts = a;
        }
    }
    if (!ok) {
        *sig = 0;
        *attempts = 0;
    }
    return ok;
}

int boot_repair_episode_note(const char *datadir, uint64_t signature)
{
    if (!datadir || !datadir[0] || signature == 0)
        return 0;

    char path[512];
    ep_path(datadir, path, sizeof(path));

    uint64_t cur_sig = 0;
    int cur_attempts = 0;
    (void)ep_read(path, &cur_sig, &cur_attempts);

    /* A DIFFERENT finding is a different episode: the datadir changed under
     * us (the damage moved, healed partly, or a new fault replaced it), so the
     * allowance starts over. Only the IDENTICAL finding climbs — that is the
     * one a further restart provably cannot improve. */
    int attempts = (cur_sig == signature && cur_attempts > 0)
                       ? cur_attempts + 1
                       : 1;

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%llu %d\n",
                       (unsigned long long)signature, attempts);
    if (len < 0 || len >= (int)sizeof(buf))
        return 0;
    if (!ar_durable_write(datadir, path, buf, (size_t)len))
        return 0;
    return attempts;
}

bool boot_repair_episode_status(const char *datadir, uint64_t *signature,
                                int *attempts)
{
    if (signature)
        *signature = 0;
    if (attempts)
        *attempts = 0;
    if (!datadir || !datadir[0])
        return false;
    char path[512];
    ep_path(datadir, path, sizeof(path));
    uint64_t s = 0;
    int a = 0;
    if (!ep_read(path, &s, &a))
        return false;
    if (signature)
        *signature = s;
    if (attempts)
        *attempts = a;
    return true;
}

void boot_repair_episode_clear(const char *datadir)
{
    if (!datadir || !datadir[0])
        return;
    char path[512];
    ep_path(datadir, path, sizeof(path));
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
