/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/boot_snapshot_failure_memory.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BSFM_CHECK(name, expr) do {                                      \
    printf("boot_snapshot_failure_memory: %s... ", (name));             \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

static void bsfm_touch(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (f)
        fclose(f);
}

static void bsfm_touch_in_dir(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    bsfm_touch(path);
}

int test_boot_snapshot_failure_memory(void)
{
    int failures = 0;

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "explicit");

        char snap[512];
        snprintf(snap, sizeof(snap), "%s/utxo-seed-7.snapshot", dir);
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.load_snapshot_at_own_height = snap;

        bool from_autodetect = true;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, true, -1, &from_autodetect, marker, sizeof(marker));

        char want_marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        snprintf(want_marker, sizeof(want_marker), "%s.failed", snap);
        BSFM_CHECK("explicit seed writes marker",
                   selected && !from_autodetect &&
                   ctx.load_snapshot_at_own_height == snap &&
                   strcmp(marker, want_marker) == 0 &&
                   access(want_marker, F_OK) == 0);

        boot_snapshot_failure_memory_clear(marker);
        BSFM_CHECK("successful seed clears marker",
                   access(want_marker, F_OK) != 0);

        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "prior");

        char snap[512];
        char marker_path[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        snprintf(snap, sizeof(snap), "%s/utxo-seed-8.snapshot", dir);
        snprintf(marker_path, sizeof(marker_path), "%s.failed", snap);
        bsfm_touch(marker_path);

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.load_snapshot_at_own_height = snap;

        bool from_autodetect = false;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, true, -1, &from_autodetect, marker, sizeof(marker));

        BSFM_CHECK("explicit prior marker skips seed",
                   !selected && !from_autodetect &&
                   ctx.load_snapshot_at_own_height == NULL &&
                   marker[0] == '\0' &&
                   access(marker_path, F_OK) == 0);

        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "auto");
        bsfm_touch_in_dir(dir, "block_index.bin");
        bsfm_touch_in_dir(dir, "utxo-seed-11.snapshot");

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = dir;

        bool from_autodetect = false;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, false, -1, &from_autodetect, marker, sizeof(marker));

        char want_snap[512];
        snprintf(want_snap, sizeof(want_snap), "%s/utxo-seed-11.snapshot", dir);
        BSFM_CHECK("autodetect seed writes marker",
                   selected && from_autodetect &&
                   ctx.load_snapshot_at_own_height != NULL &&
                   strcmp(ctx.load_snapshot_at_own_height, want_snap) == 0 &&
                   access(marker, F_OK) == 0);

        boot_snapshot_failure_memory_clear(marker);
        free((void *)ctx.load_snapshot_at_own_height);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "proven");
        bsfm_touch_in_dir(dir, "block_index.bin");
        bsfm_touch_in_dir(dir, "utxo-seed-12.snapshot");

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = dir;

        bool from_autodetect = true;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, true, 13, &from_autodetect, marker, sizeof(marker));

        BSFM_CHECK("proven coins authority disables autodetect",
                   !selected && !from_autodetect &&
                   ctx.load_snapshot_at_own_height == NULL &&
                   marker[0] == '\0');

        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "low");
        bsfm_touch_in_dir(dir, "block_index.bin");
        bsfm_touch_in_dir(dir, "utxo-seed-12.snapshot");

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = dir;

        bool from_autodetect = false;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, true, 1, &from_autodetect, marker, sizeof(marker));

        char want_snap[512];
        snprintf(want_snap, sizeof(want_snap), "%s/utxo-seed-12.snapshot", dir);
        BSFM_CHECK("low proven frontier still autodetects seed",
                   selected && from_autodetect &&
                   ctx.load_snapshot_at_own_height != NULL &&
                   strcmp(ctx.load_snapshot_at_own_height, want_snap) == 0 &&
                   access(marker, F_OK) == 0);

        boot_snapshot_failure_memory_clear(marker);
        free((void *)ctx.load_snapshot_at_own_height);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "toosmall");

        char snap[512];
        snprintf(snap, sizeof(snap), "%s/utxo-seed-13.snapshot", dir);
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.load_snapshot_at_own_height = snap;

        bool from_autodetect = false;
        char marker[8];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, true, -1, &from_autodetect, marker, sizeof(marker));

        BSFM_CHECK("explicit marker path too small skips seed",
                   !selected && !from_autodetect &&
                   ctx.load_snapshot_at_own_height == NULL &&
                   marker[0] == '\0');

        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "nullflag");

        char snap[512];
        snprintf(snap, sizeof(snap), "%s/utxo-seed-14.snapshot", dir);
        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.load_snapshot_at_own_height = snap;

        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, true, -1, NULL, marker, sizeof(marker));

        BSFM_CHECK("NULL autodetect out-param is tolerated",
                   selected &&
                   ctx.load_snapshot_at_own_height == snap &&
                   marker[0] != '\0' &&
                   access(marker, F_OK) == 0);

        boot_snapshot_failure_memory_clear(marker);
        test_rm_rf_recursive(dir);
    }

    /* Installed-bundle marker present: a leftover borrowed starter-pack seed
     * must be REFUSED (never auto-loaded) and quarantined out of the datadir
     * root so it can never be reselected. Benign auto-remedy: no seed selected,
     * no marker, no blocker. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "installed");
        bsfm_touch_in_dir(dir, "block_index.bin");
        bsfm_touch_in_dir(dir, "utxo-seed-99.snapshot");

        uint8_t digest[32];
        for (int i = 0; i < 32; i++)
            digest[i] = (uint8_t)i;
        BSFM_CHECK("marker write succeeds",
                   boot_consensus_bundle_marker_write(dir, 3056758, digest) &&
                   boot_consensus_bundle_marker_exists(dir));

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = dir;

        bool from_autodetect = true;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, false, -1, &from_autodetect, marker, sizeof(marker));

        char seed_src[512];
        char seed_dst[640];
        snprintf(seed_src, sizeof(seed_src), "%s/utxo-seed-99.snapshot", dir);
        snprintf(seed_dst, sizeof(seed_dst),
                 "%s/quarantine-borrowed-seed/utxo-seed-99.snapshot", dir);
        BSFM_CHECK("installed marker quarantines borrowed seed",
                   !selected && !from_autodetect &&
                   ctx.load_snapshot_at_own_height == NULL &&
                   marker[0] == '\0' &&
                   access(seed_src, F_OK) != 0 &&
                   access(seed_dst, F_OK) == 0);

        test_rm_rf_recursive(dir);
    }

    /* No marker: the exact same datadir shape auto-loads the seed (proves the
     * quarantine is gated strictly on the installed-bundle marker). */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "nomarker");
        bsfm_touch_in_dir(dir, "block_index.bin");
        bsfm_touch_in_dir(dir, "utxo-seed-99.snapshot");

        struct app_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.datadir = dir;

        bool from_autodetect = false;
        char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
        bool selected = boot_snapshot_failure_memory_prepare(
            &ctx, false, -1, &from_autodetect, marker, sizeof(marker));

        char want_snap[512];
        char quarantined[640];
        snprintf(want_snap, sizeof(want_snap), "%s/utxo-seed-99.snapshot", dir);
        snprintf(quarantined, sizeof(quarantined),
                 "%s/quarantine-borrowed-seed/utxo-seed-99.snapshot", dir);
        BSFM_CHECK("no marker still auto-loads the seed",
                   selected && from_autodetect &&
                   ctx.load_snapshot_at_own_height != NULL &&
                   strcmp(ctx.load_snapshot_at_own_height, want_snap) == 0 &&
                   access(want_snap, F_OK) == 0 &&
                   access(quarantined, F_OK) != 0);

        boot_snapshot_failure_memory_clear(marker);
        free((void *)ctx.load_snapshot_at_own_height);
        test_rm_rf_recursive(dir);
    }

    return failures;
}
