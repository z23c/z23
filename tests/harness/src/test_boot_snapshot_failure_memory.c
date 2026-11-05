/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/boot_snapshot_failure_memory.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static int bsfm_explicit_seed_writes_marker(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_explicit_prior_marker_skips_seed(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_autodetect_seed_writes_marker(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_proven_coins_authority_disables_autodetect(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_low_proven_frontier_still_autodetects_seed(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_explicit_marker_path_too_small_skips_seed(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_null_autodetect_outparam_tolerated(void)
{
    int failures = 0;

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

    return failures;
}

static int bsfm_installed_marker_quarantines_borrowed_seed(void)
{
    int failures = 0;

    /* Installed-bundle marker present: a leftover borrowed starter-pack seed
     * must be REFUSED (never auto-loaded) and quarantined out of the datadir
     * root so it can never be reselected. Benign auto-remedy: no seed selected,
     * no marker, no blocker. */
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

    return failures;
}

static int bsfm_no_marker_still_auto_loads_seed(void)
{
    int failures = 0;

    /* No marker: the exact same datadir shape auto-loads the seed (proves the
     * quarantine is gated strictly on the installed-bundle marker). */
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

    return failures;
}

/* ── mutation-sweep follow-ups: marker path limits, seed height parsing,
 *    unwritable marker, borrowed-seed quarantine paths, argument guards ── */

static void bsfm_prepare_dir(char *dir, size_t cap, const char *tag,
                             const char *seed_name)
{
    test_make_tmpdir(dir, cap, "boot_snapshot_failure", tag);
    bsfm_touch_in_dir(dir, "block_index.bin");
    if (seed_name)
        bsfm_touch_in_dir(dir, seed_name);
}

/* A marker path that needs exactly cap bytes with its NUL still fits; one byte
 * less must refuse the seed and leave no truncated marker file behind. */
static int bsfm_explicit_cap_boundary(void)
{
    int failures = 0;
    char dir[256], snap[512], want[600], cut[600];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    struct app_context ctx;
    bool fa = true;

    test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "capx");
    snprintf(snap, sizeof(snap), "%s/utxo-seed-5.snapshot", dir);
    snprintf(want, sizeof(want), "%s.failed", snap);
    snprintf(cut, sizeof(cut), "%s.faile", snap);
    memset(&ctx, 0, sizeof(ctx));
    ctx.load_snapshot_at_own_height = snap;
    memset(marker, 'Z', sizeof(marker));
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, true, -1, &fa, marker, strlen(snap) + 7);
    BSFM_CHECK("explicit: marker cap one short refuses the seed",
               !sel && !fa && ctx.load_snapshot_at_own_height == NULL &&
               marker[0] == '\0' && access(cut, F_OK) != 0);

    ctx.load_snapshot_at_own_height = snap;
    sel = boot_snapshot_failure_memory_prepare(
        &ctx, true, -1, &fa, marker, strlen(snap) + 8);
    BSFM_CHECK("explicit: marker cap that exactly fits keeps the seed",
               sel && strcmp(marker, want) == 0 && access(want, F_OK) == 0);
    test_rm_rf_recursive(dir);
    return failures;
}

static int bsfm_autodetect_cap_boundary(void)
{
    int failures = 0;
    char dir[256], snap[512], cut[600];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    struct app_context ctx;
    bool fa = true;

    bsfm_prepare_dir(dir, sizeof(dir), "autocap", "utxo-seed-11.snapshot");
    snprintf(snap, sizeof(snap), "%s/utxo-seed-11.snapshot", dir);
    snprintf(cut, sizeof(cut), "%s.faile", snap);
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = dir;
    memset(marker, 'Z', sizeof(marker));
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, false, -1, &fa, marker, strlen(snap) + 7);
    BSFM_CHECK("autodetect: marker cap one short drops the seed",
               !sel && !fa && ctx.load_snapshot_at_own_height == NULL &&
               marker[0] == '\0' && access(cut, F_OK) != 0);

    sel = boot_snapshot_failure_memory_prepare(
        &ctx, false, -1, &fa, marker, strlen(snap) + 8);
    BSFM_CHECK("autodetect: marker cap that exactly fits keeps the seed",
               sel && fa && access(marker, F_OK) == 0);
    boot_snapshot_failure_memory_clear(marker);
    free((void *)ctx.load_snapshot_at_own_height);
    test_rm_rf_recursive(dir);
    return failures;
}

/* An unwritable marker (its directory does not exist) must drop the explicit
 * seed: a failure that cannot be remembered would crash-loop. */
static int bsfm_explicit_unwritable_marker(void)
{
    int failures = 0;
    char dir[256], snap[512];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    struct app_context ctx;
    bool fa = true;

    test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "nowrite");
    snprintf(snap, sizeof(snap), "%s/missing/utxo-seed-5.snapshot", dir);
    memset(&ctx, 0, sizeof(ctx));
    ctx.load_snapshot_at_own_height = snap;
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, true, -1, &fa, marker, sizeof(marker));
    BSFM_CHECK("explicit: unwritable marker drops the seed",
               !sel && !fa && ctx.load_snapshot_at_own_height == NULL &&
               marker[0] == '\0');
    test_rm_rf_recursive(dir);
    return failures;
}

/* An explicit seed wins: a seed lying in the datadir is not autodetected over
 * it. */
static int bsfm_explicit_beats_autodetect(void)
{
    int failures = 0;
    char dir[256], snap[512], want[600];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    struct app_context ctx;
    bool fa = true;

    bsfm_prepare_dir(dir, sizeof(dir), "explwin", "utxo-seed-3.snapshot");
    snprintf(snap, sizeof(snap), "%s/explicit.snapshot", dir);
    snprintf(want, sizeof(want), "%s.failed", snap);
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = dir;
    ctx.load_snapshot_at_own_height = snap;
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, false, -1, &fa, marker, sizeof(marker));
    BSFM_CHECK("explicit seed is kept over an autodetectable one",
               sel && !fa && ctx.load_snapshot_at_own_height == snap &&
               strcmp(marker, want) == 0);
    test_rm_rf_recursive(dir);
    return failures;
}

static bool bsfm_seed_selected(const char *seed_name, int32_t applied,
                               const char *tag)
{
    char dir[256];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    struct app_context ctx;
    bool fa = false;

    bsfm_prepare_dir(dir, sizeof(dir), tag, seed_name);
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = dir;
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, true, applied, &fa, marker, sizeof(marker));
    if (sel) {
        boot_snapshot_failure_memory_clear(marker);
        free((void *)ctx.load_snapshot_at_own_height);
    }
    test_rm_rf_recursive(dir);
    return sel;
}

/* The seed height is parsed from the file name and compared with the proven
 * coins frontier: a seed is reloaded only while the frontier is below it. */
static int bsfm_seed_height_parse(void)
{
    int failures = 0;
    BSFM_CHECK("height 909 (digits 0 and 9) is read, frontier 500 reloads",
               bsfm_seed_selected("utxo-seed-909.snapshot", 500, "h909"));
    BSFM_CHECK("height 12 reloads at frontier 12",
               bsfm_seed_selected("utxo-seed-12.snapshot", 12, "h12a"));
    BSFM_CHECK("height 12 is skipped at frontier 13",
               !bsfm_seed_selected("utxo-seed-12.snapshot", 13, "h12b"));
    BSFM_CHECK("height INT32_MAX is a valid seed height",
               bsfm_seed_selected("utxo-seed-2147483647.snapshot", 1, "hmax"));
    BSFM_CHECK("height INT32_MAX+1 is refused, not reloaded",
               !bsfm_seed_selected("utxo-seed-2147483648.snapshot", -1,
                                   "hover"));
    return failures;
}

static bool bsfm_enter(const char *dir, char *saved, size_t cap)
{
    return getcwd(saved, cap) != NULL && chdir(dir) == 0;
}

/* One-character relative paths: the snapshot, the marker and the datadir
 * names are all non-empty even at length one. */
static int bsfm_one_char_paths(void)
{
    int failures = 0;
    char dir[256], saved[1024];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    struct app_context ctx;
    bool fa = true;

    test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_failure", "onechar");
    if (!bsfm_enter(dir, saved, sizeof(saved))) {
        BSFM_CHECK("one-char paths: enter fixture dir", false);
        test_rm_rf_recursive(dir);
        return failures;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.load_snapshot_at_own_height = "s";
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, true, -1, &fa, marker, sizeof(marker));
    BSFM_CHECK("one-char snapshot path still gets its marker",
               sel && strcmp(marker, "s.failed") == 0 &&
               access("s.failed", F_OK) == 0);
    boot_snapshot_failure_memory_clear(marker);
    BSFM_CHECK("clear removes the marker", access("s.failed", F_OK) != 0);
    bsfm_touch("m");
    boot_snapshot_failure_memory_clear("m");
    BSFM_CHECK("clear removes a one-character marker name",
               access("m", F_OK) != 0);

    uint8_t digest[32] = {0};
    (void)mkdir("d", 0700);
    bsfm_touch_in_dir("d", "block_index.bin");
    bsfm_touch_in_dir("d", "utxo-seed-99.snapshot");
    BSFM_CHECK("one-char datadir: bundle marker written",
               boot_consensus_bundle_marker_write("d", 3056758, digest));
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = "d";
    sel = boot_snapshot_failure_memory_prepare(
        &ctx, false, -1, &fa, marker, sizeof(marker));
    BSFM_CHECK("one-char datadir: borrowed seed is quarantined",
               !sel && access("d/utxo-seed-99.snapshot", F_OK) != 0 &&
               access("d/quarantine-borrowed-seed/utxo-seed-99.snapshot",
                      F_OK) == 0);
    if (chdir(saved) != 0)
        BSFM_CHECK("one-char paths: restore cwd", false);
    test_rm_rf_recursive(dir);
    return failures;
}

/* A backslash inside the datadir name does not change the seed's file name. */
static int bsfm_backslash_datadir_quarantine(void)
{
    int failures = 0;
    char base[256], dir[300], moved[600], left[600];
    char marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX];
    uint8_t digest[32] = {0};
    struct app_context ctx;
    bool fa = true;

    test_make_tmpdir(base, sizeof(base), "boot_snapshot_failure", "bslash");
    snprintf(dir, sizeof(dir), "%s/a\\b", base);
    if (mkdir(dir, 0700) != 0) {
        BSFM_CHECK("backslash datadir: mkdir", false);
        test_rm_rf_recursive(base);
        return failures;
    }
    bsfm_touch_in_dir(dir, "block_index.bin");
    bsfm_touch_in_dir(dir, "utxo-seed-99.snapshot");
    BSFM_CHECK("backslash datadir: bundle marker written",
               boot_consensus_bundle_marker_write(dir, 3056758, digest));
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = dir;
    bool sel = boot_snapshot_failure_memory_prepare(
        &ctx, false, -1, &fa, marker, sizeof(marker));
    snprintf(left, sizeof(left), "%s/utxo-seed-99.snapshot", dir);
    snprintf(moved, sizeof(moved),
             "%s/quarantine-borrowed-seed/utxo-seed-99.snapshot", dir);
    BSFM_CHECK("backslash datadir: seed quarantined under its own name",
               !sel && access(left, F_OK) != 0 && access(moved, F_OK) == 0);
    test_rm_rf_recursive(base);
    return failures;
}

static int bsfm_argument_guards(void)
{
    int failures = 0;
    struct app_context ctx;
    char marker[4];
    bool fa = true;

    memset(&ctx, 0, sizeof(ctx));
    memset(marker, 'Z', sizeof(marker));
    BSFM_CHECK("NULL ctx is refused",
               !boot_snapshot_failure_memory_prepare(NULL, false, -1, &fa,
                                                     marker, sizeof(marker)) &&
               !fa && marker[0] == '\0');
    BSFM_CHECK("NULL marker buffer is refused without a write",
               !boot_snapshot_failure_memory_prepare(&ctx, false, -1, &fa,
                                                     NULL, 10));
    memset(marker, 'Z', sizeof(marker));
    BSFM_CHECK("zero marker capacity is refused and leaves the buffer",
               !boot_snapshot_failure_memory_prepare(&ctx, false, -1, &fa,
                                                     marker, 0) &&
               marker[0] == 'Z');
    memset(marker, 'Z', sizeof(marker));
    BSFM_CHECK("capacity 1 still empties the marker string",
               !boot_snapshot_failure_memory_prepare(&ctx, false, -1, &fa,
                                                     marker, 1) &&
               marker[0] == '\0' && marker[1] == 'Z');
    boot_snapshot_failure_memory_clear(NULL);
    boot_snapshot_failure_memory_clear("");
    return failures;
}

static int bsfm_mutation_followups(void)
{
    return bsfm_explicit_cap_boundary() + bsfm_autodetect_cap_boundary() +
           bsfm_explicit_unwritable_marker() + bsfm_explicit_beats_autodetect() +
           bsfm_seed_height_parse() + bsfm_one_char_paths() +
           bsfm_backslash_datadir_quarantine() + bsfm_argument_guards();
}

int test_boot_snapshot_failure_memory(void)
{
    int failures = 0;

    failures += bsfm_explicit_seed_writes_marker();
    failures += bsfm_explicit_prior_marker_skips_seed();
    failures += bsfm_autodetect_seed_writes_marker();
    failures += bsfm_proven_coins_authority_disables_autodetect();
    failures += bsfm_low_proven_frontier_still_autodetects_seed();
    failures += bsfm_explicit_marker_path_too_small_skips_seed();
    failures += bsfm_null_autodetect_outparam_tolerated();
    failures += bsfm_installed_marker_quarantines_borrowed_seed();
    failures += bsfm_no_marker_still_auto_loads_seed();
    failures += bsfm_mutation_followups();

    return failures;
}
