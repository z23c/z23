/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Binary A/B fallback — node side. See header for the full rationale and the
 * launcher/node split. This file is pure filesystem + blocker plumbing: no
 * threads, no background service; the two env wrappers are called once each
 * from the boot path (raise-blocker early in observability init, promote at
 * the activation-ready watchdog start).
 */
// one-result-type-ok:small-fs-helpers — these are best-effort filesystem
// steps whose only meaningful signal is success/failure (bool); there is no
// multi-reason surface a zcl_result would carry that the LOG_FAIL context
// line does not already record. Matches the sibling binary_staleness_service.c
// convention for the same class of one-shot IO helpers.

#include "services/binary_ab_fallback.h"

#include "platform/os_binary_slots.h"
#include "platform/os_proc.h"
#include "platform/file_compat.h"
#include "platform/file_sync.h"
#include "util/blocker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/log_macros.h"

#define BINARY_AB_COPY_CHUNK (64 * 1024)

#ifdef ZCL_TESTING
static bool g_binary_ab_fail_before_promote_rename_once;

void binary_ab_test_fail_before_promote_rename_once(void)
{
    g_binary_ab_fail_before_promote_rename_once = true;
}
#endif

/* ── fsync helpers ──────────────────────────────────────────────────── */

/* fsync the directory that contains `path` so a rename into it is durable.
 * Promotion is not successful unless this persistence barrier succeeds. */
static bool binary_ab_fsync_parent_dir(const char *path)
{
#if defined(_WIN32)
    (void)path;
    /* MoveFileExW(MOVEFILE_WRITE_THROUGH) supplies the replacement barrier. */
    return true;
#else
    char dir[1024];
    int dir_len = snprintf(dir, sizeof(dir), "%s", path);
    if (dir_len < 0 || (size_t)dir_len >= sizeof(dir)) {
        LOG_WARN("binary_ab", "parent directory path is too long");
        return false;
    }
    char *slash = strrchr(dir, '/');
    if (!slash) {
        dir[0] = '.';
        dir[1] = '\0';
    } else if (slash == dir) {
        dir[1] = '\0'; /* path was "/x" → parent is "/" */
    } else {
        *slash = '\0';
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        LOG_WARN("binary_ab", "open(%s) for dir fsync failed: %s",
                 dir, strerror(errno));
        return false;
    }
    if (fsync(dfd) != 0) {
        LOG_WARN("binary_ab", "fsync(%s) failed: %s", dir, strerror(errno));
        close(dfd);
        return false;
    }
    if (close(dfd) != 0) {
        LOG_WARN("binary_ab", "close(%s) failed: %s", dir, strerror(errno));
        return false;
    }
    return true;
#endif
}

/* ── Streak reset ───────────────────────────────────────────────────── */

bool binary_ab_reset_streak(const char *streak_file)
{
    if (!streak_file || streak_file[0] == '\0')
        LOG_FAIL("binary_ab", "reset_streak: empty streak_file path");
    char error[OS_BINARY_SLOTS_ERROR_MAX];
    if (!os_binary_slots_reset_streak_file(streak_file, error, sizeof(error))) {
        LOG_WARN("binary_ab", "reset_streak(%s) failed: %s",
                 streak_file, error[0] ? error : "unknown error");
        return false;
    }
    LOG_INFO("binary_ab", "boot-failure streak reset to 0 (%s)", streak_file);
    return true;
}

/* ── Streak increment (self-respawn exits) ─────────────────────────── */

bool binary_ab_note_self_respawn_exit(const char *streak_file)
{
    if (!streak_file || streak_file[0] == '\0')
        LOG_FAIL("binary_ab", "note_self_respawn_exit: empty streak_file path");
    char error[OS_BINARY_SLOTS_ERROR_MAX];
    if (!os_binary_slots_increment_streak_file(streak_file, error,
                                                sizeof(error))) {
        LOG_WARN("binary_ab", "note_self_respawn_exit(%s) refused: %s",
                 streak_file, error[0] ? error : "unknown error");
        return false;
    }
    LOG_WARN("binary_ab",
             "boot-failure streak incremented (self-respawn exit, %s)",
             streak_file);
    return true;
}

/* ── Promotion (current -> last-good) ───────────────────────────────── */

static bool binary_ab_promote_open_file(const char *slots_dir, FILE *input,
                                        const char *source_name)
{
    if (!slots_dir || slots_dir[0] == '\0')
        LOG_FAIL("binary_ab", "promote: empty slots_dir");
    if (!input)
        LOG_FAIL("binary_ab", "promote: empty input stream");

    int input_fd = fileno(input);
    struct stat input_stat;
    if (input_fd < 0 || fstat(input_fd, &input_stat) != 0 ||
        !S_ISREG(input_stat.st_mode) ||
#if !defined(_WIN32)
        (input_stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
#else
        false)
#endif
        LOG_FAIL("binary_ab", "promote: %s is not a regular executable",
                 source_name);

    char dst[1024];
    int dst_len = snprintf(dst, sizeof(dst), "%s/%s", slots_dir,
                           BINARY_AB_LASTGOOD_BASENAME);
    if (dst_len < 0 || (size_t)dst_len >= sizeof(dst))
        LOG_FAIL("binary_ab", "promote: last-good path is too long");
    char tmp[1088];
    int tmp_len = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dst,
                           (long)getpid());
    if (tmp_len < 0 || (size_t)tmp_len >= sizeof(tmp))
        LOG_FAIL("binary_ab", "promote: temporary path is too long");

    (void)unlink(tmp);
    int out = platform_file_open_nofollow(
        tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0)
        LOG_FAIL("binary_ab", "promote: open(%s) failed: %s",
                 tmp, strerror(errno));

    unsigned char buf[BINARY_AB_COPY_CHUNK];
    bool copy_ok = true;
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), input)) > 0) {
        size_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, n - off);
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0) {
                LOG_WARN("binary_ab", "promote: write(%s) failed: %s",
                         tmp, strerror(errno));
                copy_ok = false;
                break;
            }
            off += (size_t)w;
        }
        if (!copy_ok)
            break;
    }
    if (ferror(input)) {
        LOG_WARN("binary_ab", "promote: read(%s) failed: %s",
                 source_name, strerror(errno));
        copy_ok = false;
    }

    if (copy_ok) {
#if !defined(_WIN32)
        if (fchmod(out, 0755) != 0) {
            LOG_WARN("binary_ab", "promote: fchmod(%s) failed: %s",
                     tmp, strerror(errno));
            copy_ok = false;
        }
#endif
        if (platform_data_sync(out) != 0) {
            LOG_WARN("binary_ab", "promote: fsync(%s) failed: %s",
                     tmp, strerror(errno));
            copy_ok = false;
        }
    }
    if (close(out) != 0) {
        LOG_WARN("binary_ab", "promote: close(%s) failed: %s",
                 tmp, strerror(errno));
        copy_ok = false;
    }

    if (!copy_ok) {
        unlink(tmp);
        return false;
    }

#ifdef ZCL_TESTING
    if (g_binary_ab_fail_before_promote_rename_once) {
        g_binary_ab_fail_before_promote_rename_once = false;
        LOG_WARN("binary_ab", "promote: injected failure before rename");
        unlink(tmp);
        return false;
    }
#endif

    if (platform_file_replace_atomic(tmp, dst) != 0) {
        LOG_WARN("binary_ab", "promote: rename(%s->%s) failed: %s",
                 tmp, dst, strerror(errno));
        unlink(tmp);
        return false;
    }
    if (!binary_ab_fsync_parent_dir(dst)) {
        LOG_WARN("binary_ab", "promote: last-good directory sync failed");
        return false;
    }
    LOG_INFO("binary_ab", "promoted current binary to last-good slot (%s)", dst);
    return true;
}

bool binary_ab_promote(const char *slots_dir, const char *current_path)
{
    if (!current_path || current_path[0] == '\0')
        LOG_FAIL("binary_ab", "promote: empty current_path");
    int fd = platform_file_open_nofollow(current_path,
                                         O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        LOG_FAIL("binary_ab", "promote: open(%s) failed: %s",
                 current_path, strerror(errno));
    FILE *input = fdopen(fd, "rb");
    if (!input) {
        int saved_errno = errno;
        close(fd);
        LOG_FAIL("binary_ab", "promote: fdopen(%s) failed: %s",
                 current_path, strerror(saved_errno));
    }
    bool ok = binary_ab_promote_open_file(slots_dir, input, current_path);
    if (fclose(input) != 0 && ok) {
        LOG_WARN("binary_ab", "promote: close(%s) failed: %s",
                 current_path, strerror(errno));
        ok = false;
    }
    return ok;
}

static bool binary_ab_promote_running(const char *slots_dir)
{
    FILE *input = os_proc_open_self_exe();
    if (!input)
        LOG_FAIL("binary_ab", "promote: open running executable failed: %s",
                 strerror(errno));
    bool ok = binary_ab_promote_open_file(slots_dir, input,
                                          "running executable image");
    if (fclose(input) != 0 && ok) {
        LOG_WARN("binary_ab", "promote: close running executable failed: %s",
                 strerror(errno));
        ok = false;
    }
    return ok;
}

/* ── Ready action ───────────────────────────────────────────────────── */

static bool binary_ab_build_streak_path(const char *slots_dir,
                                        char *streak, size_t streak_size)
{
    int n = snprintf(streak, streak_size, "%s/%s", slots_dir,
                     BINARY_AB_STREAK_BASENAME);
    if (n < 0 || (size_t)n >= streak_size)
        LOG_FAIL("binary_ab", "streak path is too long");
    return true;
}

static bool binary_ab_reset_ready_streak(const char *slots_dir)
{
    char streak[1024];
    if (!binary_ab_build_streak_path(slots_dir, streak, sizeof(streak))) {
        LOG_WARN("binary_ab", "ready streak path construction failed");
        return false;
    }
    return binary_ab_reset_streak(streak);
}

static bool binary_ab_ready_under_fallback(const char *slots_dir)
{
    bool ok = binary_ab_reset_ready_streak(slots_dir);
    /* Never replace the known-good slot while it is the recovery image. */
    LOG_WARN("binary_ab",
             "reached ready under FALLBACK slot — streak reset, last-good "
             "left intact (operator must deploy a good binary)");
    return ok;
}

bool binary_ab_on_ready(const char *slots_dir, const char *current_path,
                        bool fallback_active)
{
    if (!slots_dir || slots_dir[0] == '\0')
        return true; /* not launcher-managed */

    if (fallback_active)
        return binary_ab_ready_under_fallback(slots_dir);

    if (!current_path || current_path[0] == '\0')
        LOG_FAIL("binary_ab", "managed normal ready requires current_path");
    if (!binary_ab_promote(slots_dir, current_path)) {
        LOG_WARN("binary_ab", "ready promotion failed; streak preserved");
        return false;
    }

    return binary_ab_reset_ready_streak(slots_dir);
}

/* ── Blocker ────────────────────────────────────────────────────────── */

void binary_ab_raise_fallback_blocker(bool fallback_active)
{
    if (!fallback_active)
        return;

    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "launcher fell back to the last-known-good binary after the "
             "current build failed to reach activation-ready %d times in a "
             "row — node is degraded-but-alive; deploy a working binary and "
             "clear the boot-failure streak",
             3 /* the launcher's fallback threshold; informational */);
    if (!blocker_init(&rec, BINARY_FALLBACK_BLOCKER_ID,
                      BINARY_FALLBACK_BLOCKER_OWNER, BLOCKER_PERMANENT, reason))
        return; /* blocker_init already logged via LOG_FAIL */
    blocker_set(&rec);
    LOG_ERROR("binary_ab",
              "binary.fallback_active raised — running last-good slot");
}

/* ── Env wrappers ───────────────────────────────────────────────────── */

void binary_ab_promote_on_ready_env(void)
{
    const char *slots = getenv(BINARY_AB_ENV_SLOTS_DIR);
    if (!slots || slots[0] == '\0')
        return; /* launched directly, not via the launcher */
    const char *fb = getenv(BINARY_AB_ENV_FALLBACK);
    bool fallback_active = fb && fb[0] == '1' && fb[1] == '\0';
    if (fallback_active) {
        (void)binary_ab_ready_under_fallback(slots);
        return;
    }
    if (!binary_ab_promote_running(slots)) {
        LOG_WARN("binary_ab", "ready promotion from running image failed");
        return;
    }
    if (!binary_ab_reset_ready_streak(slots))
        LOG_WARN("binary_ab", "ready streak reset after promotion failed");
}

void binary_ab_raise_fallback_blocker_env(void)
{
    const char *fb = getenv(BINARY_AB_ENV_FALLBACK);
    binary_ab_raise_fallback_blocker(fb && fb[0] == '1' && fb[1] == '\0');
}

void binary_ab_note_self_respawn_exit_env(void)
{
    const char *slots = getenv(BINARY_AB_ENV_SLOTS_DIR);
    if (!slots || slots[0] == '\0')
        return; /* launched directly, not via the launcher */
    char streak[1024];
    if (!binary_ab_build_streak_path(slots, streak, sizeof(streak))) {
        LOG_WARN("binary_ab", "self-respawn streak path construction failed");
        return;
    }
    binary_ab_note_self_respawn_exit(streak);
}
