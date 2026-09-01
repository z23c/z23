/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fast-sync starter-pack (bundle) freshness helpers that back
 * the `bundle_staleness` diagnostic (engine/controllers/src/diagnostics_registry.c).
 *
 * Two pure, read-only helpers are exercised:
 *   - bundle_scan_seed_height(): finds the highest utxo-seed-<digits>.snapshot
 *     in a datadir (the same naming the boot autodetect selects), ignoring
 *     non-matching / malformed names, and reports the count + winning basename.
 *   - bundle_classify(): turns (seed_height, network_header_tip) into a block
 *     gap, an estimated fresh-install catch-up time, and a freshness verdict.
 *
 * Both are I/O-light (the scan touches only a temp dir of empty files) and have
 * no consensus surface — this guards the "is the published bundle stale?" CI /
 * operator signal, not any validation rule.
 */

#include "test/test_core.h"
#include "controllers/diagnostics_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BS_CHECK(name, expr) do { \
    printf("%s... ", (name));     \
    if ((expr)) printf("OK\n");   \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Create an empty file at <dir>/<name>. */
static void bs_touch(const char *dir, const char *name)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (f) fclose(f);
}

int test_bundle_staleness(void)
{
    int failures = 0;

    /* ── 1. classify: empty/unknown inputs ─────────────────────────── */
    {
        long long gap = 7, secs = 7;
        enum bundle_freshness v = bundle_classify(-1, 3000000, &gap, &secs);
        BS_CHECK("bundle: no bundle => UNKNOWN, gap/secs cleared to -1",
                 v == BUNDLE_FRESH_UNKNOWN && gap == -1 && secs == -1);

        gap = 7; secs = 7;
        v = bundle_classify(3000000, -1, &gap, &secs);
        BS_CHECK("bundle: unknown tip => UNKNOWN, gap/secs cleared to -1",
                 v == BUNDLE_FRESH_UNKNOWN && gap == -1 && secs == -1);
    }

    /* ── 2. classify: fresh / aging / stale thresholds ─────────────── */
    {
        long long gap = -1, secs = -1;

        /* gap 0 => fresh. */
        enum bundle_freshness v = bundle_classify(3000000, 3000000, &gap, &secs);
        BS_CHECK("bundle: at-tip => fresh, gap 0",
                 v == BUNDLE_FRESH_OK && gap == 0 && secs == 0);

        /* Bundle above our header tip clamps the gap to 0 (never negative). */
        v = bundle_classify(3000050, 3000000, &gap, &secs);
        BS_CHECK("bundle: seed above tip => gap clamped to 0, fresh",
                 v == BUNDLE_FRESH_OK && gap == 0 && secs == 0);

        /* 60s fresh threshold at 3 blk/s = 180 blocks. 90 blocks => ~30s. */
        v = bundle_classify(3000000, 3000090, &gap, &secs);
        BS_CHECK("bundle: 90 blocks behind => fresh (~30s)",
                 v == BUNDLE_FRESH_OK && gap == 90 && secs == 30);

        /* 600 blocks => ~200s => aging (between 60s and 600s). */
        v = bundle_classify(3000000, 3000600, &gap, &secs);
        BS_CHECK("bundle: 600 blocks behind => aging (~200s)",
                 v == BUNDLE_FRESH_AGING && gap == 600 && secs == 200);

        /* 7000 blocks (the roadmap's stale bundle) => ~2333s => stale. */
        v = bundle_classify(3000000, 3007000, &gap, &secs);
        BS_CHECK("bundle: 7000 blocks behind => stale (re-mint)",
                 v == BUNDLE_FRESH_STALE && gap == 7000 && secs == 2333);
    }

    /* ── 3. classify: NULL out-params are tolerated ────────────────── */
    {
        enum bundle_freshness v = bundle_classify(3000000, 3010000, NULL, NULL);
        BS_CHECK("bundle: NULL gap/secs out-params => still classifies stale",
                 v == BUNDLE_FRESH_STALE);
    }

    /* ── 4. scan: empty / missing datadir ──────────────────────────── */
    {
        int count = 99;
        char name[64];
        memset(name, 'x', sizeof(name));
        long long h = bundle_scan_seed_height("", &count, name, sizeof(name));
        BS_CHECK("bundle: empty datadir => -1, count 0, name cleared",
                 h == -1 && count == 0 && name[0] == '\0');

        h = bundle_scan_seed_height("/no/such/dir/zcl-bundle-test", &count,
                                    NULL, 0);
        BS_CHECK("bundle: missing datadir => -1, count 0",
                 h == -1 && count == 0);

        /* NULL out-params tolerated. */
        h = bundle_scan_seed_height(NULL, NULL, NULL, 0);
        BS_CHECK("bundle: NULL datadir => -1", h == -1);
    }

    /* ── 5. scan: real temp dir with crafted names ─────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bundle_stale", "scan");

        int count = -1;
        char name[64] = {0};

        /* No snapshots yet. */
        long long h = bundle_scan_seed_height(dir, &count, name, sizeof(name));
        BS_CHECK("bundle: dir with no snapshots => -1, count 0",
                 h == -1 && count == 0 && name[0] == '\0');

        /* Add three valid snapshots + decoys; the highest height must win. */
        bs_touch(dir, "utxo-seed-3000000.snapshot");
        bs_touch(dir, "utxo-seed-3157842.snapshot");
        bs_touch(dir, "utxo-seed-42.snapshot");
        bs_touch(dir, "block_index.bin");                 /* not a snapshot */
        bs_touch(dir, "utxo-seed-.snapshot");             /* no digits */
        bs_touch(dir, "utxo-seed-12ab.snapshot");         /* non-digit */
        bs_touch(dir, "utxo-seed-99.snapshot.failed");    /* wrong suffix */
        bs_touch(dir, "notes-utxo-seed-9999999.snapshot");/* wrong prefix */

        h = bundle_scan_seed_height(dir, &count, name, sizeof(name));
        BS_CHECK("bundle: highest valid snapshot wins (3157842), count 3",
                 h == 3157842 && count == 3 &&
                 strcmp(name, "utxo-seed-3157842.snapshot") == 0);

        /* count/name out-params are optional. */
        h = bundle_scan_seed_height(dir, NULL, NULL, 0);
        BS_CHECK("bundle: scan with NULL out-params still returns height",
                 h == 3157842);

        test_cleanup_tmpdir(dir);
    }

    return failures;
}
