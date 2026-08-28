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
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "util/blocker.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/log_macros.h"

#define BINARY_AB_COPY_CHUNK (64 * 1024)

#ifdef ZCL_TESTING
static bool g_binary_ab_fail_before_promote_rename_once;

void binary_ab_test_fail_before_promote_rename_once(void)
{
    g_binary_ab_fail_before_promote_rename_once = true;
}
#endif

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

static bool binary_ab_open_staging(const char *destination,
                                   char staging[1088],
                                   struct platform_private_file *output)
{
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        uint8_t nonce[16];
        if (!rng_fill(nonce, sizeof(nonce)))
            return false;
        char suffix[2 * sizeof(nonce) + 1];
        for (size_t i = 0; i < sizeof(nonce); ++i)
            (void)snprintf(suffix + 2 * i, 3, "%02x", nonce[i]);
        int n = snprintf(staging, 1088, "%s.tmp.%s", destination, suffix);
        if (n <= 0 || n >= 1088)
            return false;
        if (platform_private_file_create(staging, output))
            return true;
    }
    return false;
}

static bool binary_ab_install_staging(struct platform_private_file *output,
                                      const char *staging,
                                      const char *destination,
                                      const char *parent)
{
    if (!platform_private_file_mark_executable(output) ||
        !platform_private_file_flush(output))
        return false;
#ifdef ZCL_TESTING
    if (g_binary_ab_fail_before_promote_rename_once) {
        g_binary_ab_fail_before_promote_rename_once = false;
        LOG_WARN("binary_ab", "promote: injected failure before replace");
        return false;
    }
#endif
    return platform_private_file_replace(output, staging, destination) &&
           platform_private_parent_flush(parent);
}

static bool binary_ab_promote_stream(const char *slots_dir, FILE *input,
                                     const char *source_name)
{
    if (!slots_dir || slots_dir[0] == '\0')
        LOG_FAIL("binary_ab", "promote: empty slots_dir");
    if (!input)
        LOG_FAIL("binary_ab", "promote: empty input stream");

    char requested[1024];
    int dst_len = snprintf(requested, sizeof(requested), "%s/%s", slots_dir,
                           BINARY_AB_LASTGOOD_BASENAME);
    if (dst_len < 0 || (size_t)dst_len >= sizeof(requested))
        LOG_FAIL("binary_ab", "promote: last-good path is too long");
    char dst[1024], parent[1024];
    if (!platform_private_path_resolve(requested, dst, sizeof(dst), parent,
                                       sizeof(parent)))
        LOG_FAIL("binary_ab", "promote: cannot resolve slots directory");
    char tmp[1088];
    struct platform_private_file output;
    platform_private_file_init(&output);
    if (!binary_ab_open_staging(dst, tmp, &output))
        LOG_FAIL("binary_ab", "promote: cannot create exclusive staging file");

    unsigned char buf[BINARY_AB_COPY_CHUNK];
    bool copy_ok = true;
    uint64_t offset = 0;
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), input)) > 0) {
        if (UINT64_MAX - offset < n ||
            !platform_private_file_write_at(&output, buf, n, offset)) {
            copy_ok = false;
            break;
        }
        offset += n;
    }
    if (ferror(input)) {
        LOG_WARN("binary_ab", "promote: read(%s) failed: %s",
                 source_name, strerror(errno));
        copy_ok = false;
    }

    if (copy_ok)
        copy_ok = binary_ab_install_staging(&output, tmp, dst, parent);
    if (!copy_ok && output.native != (uintptr_t)-1)
        (void)platform_private_file_retire(&output, tmp);
    platform_private_file_close(&output);
    if (!copy_ok)
        return false;
    LOG_INFO("binary_ab", "promoted current binary to last-good slot (%s)", dst);
    return true;
}

bool binary_ab_promote(const char *slots_dir, const char *current_path)
{
    if (!current_path || current_path[0] == '\0')
        LOG_FAIL("binary_ab", "promote: empty current_path");
    struct platform_positioned_file input;
    platform_positioned_file_init(&input);
    if (!platform_positioned_file_open(&input, current_path) ||
        !platform_positioned_file_is_executable(&input))
        LOG_FAIL("binary_ab", "promote: %s is not a regular executable",
                 current_path);
    uint64_t size = 0;
    bool ok = platform_positioned_file_size(&input, &size);
    char requested[1024], dst[1024], parent[1024], tmp[1088];
    int requested_len = snprintf(requested, sizeof(requested), "%s/%s",
                                 slots_dir, BINARY_AB_LASTGOOD_BASENAME);
    if (!ok || requested_len <= 0 ||
        (size_t)requested_len >= sizeof(requested) ||
        !platform_private_path_resolve(requested, dst, sizeof(dst), parent,
                                       sizeof(parent)))
        ok = false;
    struct platform_private_file output;
    platform_private_file_init(&output);
    if (ok) ok = binary_ab_open_staging(dst, tmp, &output);
    unsigned char buf[BINARY_AB_COPY_CHUNK];
    for (uint64_t offset = 0; ok && offset < size;) {
        size_t chunk = size - offset > sizeof(buf) ? sizeof(buf) :
                       (size_t)(size - offset);
        int64_t read = platform_positioned_file_read(&input, buf, chunk, offset);
        ok = read == (int64_t)chunk &&
             platform_private_file_write_at(&output, buf, chunk, offset);
        offset += chunk;
    }
    if (ok) ok = binary_ab_install_staging(&output, tmp, dst, parent);
    if (!ok && output.native != (uintptr_t)-1)
        (void)platform_private_file_retire(&output, tmp);
    platform_private_file_close(&output);
    platform_positioned_file_close(&input);
    return ok;
}

static bool binary_ab_promote_running(const char *slots_dir)
{
    FILE *input = os_proc_open_self_exe();
    if (!input)
        LOG_FAIL("binary_ab", "promote: open running executable failed: %s",
                 strerror(errno));
    bool ok = binary_ab_promote_stream(slots_dir, input,
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
