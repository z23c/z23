/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "config/boot_snapshot_failure_memory.h"

#include "config/boot.h"
#include "config/boot_consensus_bundle_marker.h"
#include "platform/private_directory.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUARANTINE_BORROWED_SEED_DIR "quarantine-borrowed-seed"

static bool marker_path_for_snapshot(char *out, size_t cap,
                                     const char *snapshot_path)
{
    if (!out || cap == 0 || !snapshot_path || !snapshot_path[0])
        return false;
    int n = snprintf(out, cap, "%s.failed", snapshot_path);
    return n > 0 && (size_t)n < cap;
}

static bool write_empty_marker(const char *path)
{
    FILE *mf = fopen(path, "we");
    if (!mf)
        return false;
    fclose(mf);
    return true;
}

static bool seed_height_from_snapshot_path(const char *snapshot_path,
                                           int32_t *out)
{
    if (out)
        *out = -1;
    if (!snapshot_path || !snapshot_path[0])
        return false;

    const char *base = strrchr(snapshot_path, '/');
    base = base ? base + 1 : snapshot_path;
    static const char pfx[] = "utxo-seed-";
    static const char sfx[] = ".snapshot";
    const size_t plen = sizeof(pfx) - 1;
    const size_t slen = sizeof(sfx) - 1;
    const size_t len = strlen(base);
    if (len <= plen + slen ||
        strncmp(base, pfx, plen) != 0 ||
        strcmp(base + len - slen, sfx) != 0)
        return false;

    int64_t h = 0;
    for (size_t i = plen; i < len - slen; i++) {
        if (base[i] < '0' || base[i] > '9')
            return false;
        h = h * 10 + (base[i] - '0');
        if (h > INT32_MAX)
            return false;
    }
    if (out)
        *out = (int32_t)h;
    return true;
}

static void forget_autodetected_seed(struct app_context *ctx,
                                     bool *from_autodetect,
                                     char *fail_marker)
{
    if (ctx && ctx->load_snapshot_at_own_height) {
        free((void *)ctx->load_snapshot_at_own_height);
        ctx->load_snapshot_at_own_height = NULL;
    }
    if (from_autodetect)
        *from_autodetect = false;
    if (fail_marker)
        fail_marker[0] = '\0';
}

static void forget_explicit_seed(struct app_context *ctx, char *fail_marker)
{
    if (ctx)
        ctx->load_snapshot_at_own_height = NULL;
    if (fail_marker)
        fail_marker[0] = '\0';
}

/* A sovereign consensus bundle is installed in this datadir (marker present),
 * yet a borrowed starter-pack seed file is still lying in the datadir root.
 * Auto-loading it would flip the installed state back to the borrowed seed.
 * Move it out of the auto-load search path into
 * <datadir>/quarantine-borrowed-seed/ so it is never reselected, and let boot
 * continue on the installed state. Benign auto-remedy: never a blocker, and a
 * failed move only falls through to leaving the seed untouched (the marker
 * still prevents auto-load in maybe_autodetect_seed's caller path). */
static void quarantine_borrowed_seed(const char *datadir, const char *seed_path)
{
    if (!datadir || !datadir[0] || !seed_path || !seed_path[0])
        return;

    const char *slash = strrchr(seed_path, '/');
    const char *backslash = strrchr(seed_path, '\\');
    const char *separator = !slash ? backslash
                            : !backslash || slash > backslash ? slash
                                                              : backslash;
    const char *base = separator ? separator + 1 : seed_path;
    if (!base[0])
        return;

    char qdir[1200];
    int dn = snprintf(qdir, sizeof(qdir), "%s/%s", datadir,
                      QUARANTINE_BORROWED_SEED_DIR);
    if (dn <= 0 || (size_t)dn >= sizeof(qdir)) {
        LOG_WARN("boot",
                 "[boot] borrowed-seed quarantine dir path too long for %s - "
                 "leaving seed in place (marker still blocks auto-load)",
                 datadir);
        return;
    }
    uintptr_t qdir_handle = 0;
    if (!platform_private_directory_ensure(qdir) ||
        !platform_private_directory_open_validated(qdir, &qdir_handle)) {
        LOG_WARN("boot",
                 "[boot] could not create/validate private borrowed-seed "
                 "quarantine dir %s (%s) "
                 "- leaving seed in place (marker still blocks auto-load)",
                 qdir, strerror(errno));
        return;
    }

    char dst[1400];
    int on = snprintf(dst, sizeof(dst), "%s/%s", qdir, base);
    if (on <= 0 || (size_t)on >= sizeof(dst)) {
        LOG_WARN("boot",
                 "[boot] borrowed-seed quarantine target path too long for %s - "
                 "leaving seed in place (marker still blocks auto-load)", base);
        platform_private_directory_close(qdir_handle);
        return;
    }
    if (rename(seed_path, dst) != 0) {
        LOG_WARN("boot",
                 "[boot] could not move borrowed seed %s -> %s (%s) - leaving "
                 "it in place (marker still blocks auto-load)",
                 seed_path, dst, strerror(errno));
        platform_private_directory_close(qdir_handle);
        return;
    }
    platform_private_directory_close(qdir_handle);
    LOG_WARN("boot",
             "[boot] sovereign consensus bundle installed here "
             "(consensus-bundle-installed marker present) — REFUSING to "
             "auto-load leftover borrowed starter-pack seed %s; quarantined it "
             "to %s. Cure doctrine: the installed state is authoritative, a "
             "borrowed zclassicd-minted seed must never overwrite it. Delete "
             "%s manually to reclaim disk once the install is confirmed.",
             base, dst, dst);
}

static void maybe_autodetect_seed(struct app_context *ctx,
                                  bool coins_kv_proven_authority,
                                  int32_t coins_kv_applied_height,
                                  bool *from_autodetect,
                                  char *fail_marker,
                                  size_t fail_marker_cap)
{
    if (!ctx || ctx->load_snapshot_at_own_height)
        return;

    char *auto_snap = boot_autodetect_bundle_snapshot(ctx->datadir);
    if (!auto_snap)
        return;

    /* A sovereign consensus bundle has been installed in this datadir. Never
     * auto-load a leftover borrowed seed over it — quarantine the seed file and
     * continue on the installed state. Only applies to autodetect; an explicit
     * -load-snapshot-at-own-height flag never reaches this path. */
    if (boot_consensus_bundle_marker_exists(ctx->datadir)) {
        quarantine_borrowed_seed(ctx->datadir, auto_snap);
        free(auto_snap);
        return;
    }

    if (coins_kv_proven_authority) {
        int32_t seed_h = -1;
        bool have_seed = seed_height_from_snapshot_path(auto_snap, &seed_h);
        if (!have_seed ||
            (int64_t)coins_kv_applied_height >= (int64_t)seed_h + 1) {
            free(auto_snap);
            return;
        }
        LOG_WARN("boot",
                 "[boot] starter-pack bundle %s detected while coins_kv is "
                 "only proven through h=%d (< seed h=%d) — reloading the "
                 "verified seed instead of treating the low frontier as "
                 "healthy",
                 auto_snap, coins_kv_applied_height - 1, seed_h);
    }

    LOG_INFO("boot",
             "[boot] starter-pack bundle detected in datadir - auto-"
             "loading %s (no -load-snapshot-at-own-height flag needed)",
             auto_snap);
    ctx->load_snapshot_at_own_height = auto_snap;
    if (from_autodetect)
        *from_autodetect = true;

    if (!marker_path_for_snapshot(fail_marker, fail_marker_cap, auto_snap) ||
        !write_empty_marker(fail_marker)) {
        /* Could not write the failure-memory marker (read-only datadir /
         * ENOSPC / EACCES). Do not gamble on an autodetect seed whose failure
         * we cannot remember: a bad bundle _exit()s the loader, and the next
         * Restart=always boot would re-select the same bundle forever. */
        LOG_WARN("boot",
                 "[boot] autodetect seed marker unwritable (%s.failed) - "
                 "skipping snapshot seed, using P2P IBD",
                 auto_snap);
        forget_autodetected_seed(ctx, from_autodetect, fail_marker);
    }
}

static void prepare_explicit_seed_marker(struct app_context *ctx,
                                         bool from_autodetect,
                                         char *fail_marker,
                                         size_t fail_marker_cap)
{
    if (!ctx || !ctx->load_snapshot_at_own_height || from_autodetect)
        return;

    if (!marker_path_for_snapshot(fail_marker, fail_marker_cap,
                                  ctx->load_snapshot_at_own_height)) {
        /* Path too long to form a marker - we could not remember a failure, so
         * do not enter the fail-closed _exit path; degrade to P2P IBD. */
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height marker path too long "
                 "for %s - skipping snapshot seed, using P2P IBD",
                 ctx->load_snapshot_at_own_height);
        forget_explicit_seed(ctx, fail_marker);
        return;
    }

    if (access(fail_marker, F_OK) == 0) {
        /* A prior boot crash-failed seeding this exact bundle. Skip it instead
         * of re-entering the _exit crash-loop. */
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height bundle %s has a .failed "
                 "marker from a prior crashed seed - skipping it; using normal "
                 "P2P IBD. Delete %s to retry the bundle.",
                 ctx->load_snapshot_at_own_height, fail_marker);
        forget_explicit_seed(ctx, fail_marker);
        return;
    }

    if (!write_empty_marker(fail_marker)) {
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height marker unwritable "
                 "(%s) - skipping snapshot seed, using P2P IBD",
                 fail_marker);
        forget_explicit_seed(ctx, fail_marker);
    }
}

bool boot_snapshot_failure_memory_prepare(struct app_context *ctx,
                                          bool coins_kv_proven_authority,
                                          int32_t coins_kv_applied_height,
                                          bool *from_autodetect,
                                          char *fail_marker,
                                          size_t fail_marker_cap)
{
    bool local_from_autodetect = false;
    bool *autodetect_flag = from_autodetect ? from_autodetect
                                            : &local_from_autodetect;
    *autodetect_flag = false;
    if (fail_marker && fail_marker_cap > 0)
        fail_marker[0] = '\0';
    if (!ctx || !fail_marker || fail_marker_cap == 0)
        return false;

    maybe_autodetect_seed(ctx, coins_kv_proven_authority,
                          coins_kv_applied_height, autodetect_flag,
                          fail_marker, fail_marker_cap);
    prepare_explicit_seed_marker(ctx,
                                 *autodetect_flag,
                                 fail_marker,
                                 fail_marker_cap);

    return ctx->load_snapshot_at_own_height != NULL;
}

void boot_snapshot_failure_memory_clear(const char *fail_marker)
{
    if (fail_marker && fail_marker[0])
        (void)remove(fail_marker);
}
