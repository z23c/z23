/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bundle-publish-serve weld — a synced node's on-disk starter artifacts become
 * SERVED. Proves the registration weld the ops.debug.rom_seed.publish command
 * (engine/controllers/src/rom_seed_controller.c) and the standing exporter's
 * post-produce reseed (engine/composition/src/bundle_exporter.c) both rely on:
 *
 *   1. a datadir carrying a valid consensus-state bundle under bundles/ AND a
 *      header-chain seed (block_index.bin) at the root — exactly the shape a
 *      synced node holds — is one idempotent rom_seed_scan_datadir away from
 *      registering BOTH with the right kinds, so the served directory listing
 *      advertises a usable bundle + header-seed manifest to a fresh peer;
 *
 *   2. a corrupt (non-SQLite) bundle and an unknown-kind file are REFUSED at
 *      registration and never offered.
 *
 * Fixtures live under mkdtemp() — never a real datadir, never the network.
 * Touches no consensus predicate. */

#include "test/test_core.h"
#include "net/rom_seed.h"
#include "config/bundle_exporter.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Deterministic content: SQLite magic in the first 16 bytes when `sqlite_ok`,
 * else 0xEE garbage; then a fixed byte pattern. */
static void bps_gen(uint8_t *buf, size_t size, bool sqlite_ok)
{
    static const uint8_t magic[16] = "SQLite format 3"; /* 15 chars + NUL */
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u) & 0xffu);
    if (size >= 16) {
        if (sqlite_ok) memcpy(buf, magic, 16);
        else memset(buf, 0xEE, 16);
    }
}

static bool bps_write(const char *dir, const char *name,
                      const uint8_t *buf, size_t size)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, buf + off, size - off);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    close(fd);
    return true;
}

static bool bps_have_kind(enum rom_artifact_kind k)
{
    struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < n; i++)
        if (arts[i].kind == k) return true;
    return false;
}

/* (a) A synced datadir (bundle under bundles/, header seed at root) serves
 * BOTH artifacts, with the directory-listing kinds discovery requires. */
static int test_bps_serves_both(void)
{
    int failures = 0;
    TEST("bundle-publish-serve: synced datadir serves bundle + header seed") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bundle_publish", "ok");

        char bundles[320];
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);

        /* Header-chain seed at the datadir root (a synced node writes this via
         * save_block_index_flat). No magic; the size band is its only guard. */
        size_t hs_size = 8192;
        uint8_t *hs = malloc(hs_size);
        ASSERT(hs != NULL);
        bps_gen(hs, hs_size, false);
        ASSERT(bps_write(dir, "block_index.bin", hs, hs_size));

        /* A valid consensus-state bundle staged under bundles/ (a fetch or the
         * standing exporter lands it there). SQLite-shaped so the content
         * check passes. */
        size_t b_size = 65536;
        uint8_t *b = malloc(b_size);
        ASSERT(b != NULL);
        bps_gen(b, b_size, true);
        ASSERT(bps_write(dir, "bundles/consensus-state-bundle-100.sqlite",
                         b, b_size));

        /* The single idempotent scan both the publish command and boot run. */
        int reg = rom_seed_scan_datadir(dir);
        ASSERT(reg == 2);
        ASSERT(rom_seed_count() == 2);
        ASSERT(bps_have_kind(ROM_ARTIFACT_CONSENSUS_BUNDLE));
        ASSERT(bps_have_kind(ROM_ARTIFACT_HEADER_SEED));

        /* Re-scan is idempotent: the same two artifacts stay registered. */
        int reg2 = rom_seed_scan_datadir(dir);
        ASSERT(reg2 == 2);
        ASSERT(rom_seed_count() == 2);

        /* The served directory listing carries the exact kind tokens a fresh
         * peer's discovery matches (boot_bundle_pick_manifest /
         * boot_bundle_pick_header_seed_manifest). */
        char json[4096];
        size_t jn = rom_seed_directory_json(json, sizeof(json));
        ASSERT(jn > 0);
        ASSERT(strstr(json, "\"consensus_bundle\"") != NULL);
        ASSERT(strstr(json, "\"header_seed\"") != NULL);

        free(hs);
        free(b);
        rom_seed_reset();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* (a2) A BIG datadir root still serves the header seed. This is the exact
 * shape that made MVP C3 unreachable: the canonical node's datadir root held
 * 5,686 entries with block_index.bin at readdir position 4,499, past
 * rom_seed's 4,096-entry walk cap. The walk stopped early and silently, the
 * node advertised the consensus bundle alone, and every fresh node's
 * checkpoint-bundle install deferred forever waiting for a header chain it
 * had to crawl from genesis. Exactly-named artifacts are now looked up by
 * name, so where they land in readdir order cannot matter. */
static int test_bps_serves_header_seed_in_a_big_datadir(void)
{
    int failures = 0;
    TEST("bundle-publish-serve: header seed survives a datadir past the walk cap") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bundle_publish", "big");

        size_t hs_size = 8192;
        uint8_t *hs = malloc(hs_size);
        ASSERT(hs != NULL);
        bps_gen(hs, hs_size, false);
        ASSERT(bps_write(dir, "block_index.bin", hs, hs_size));

        /* Grow the root past the walk cap. readdir order is the filesystem's,
         * so the seed may still appear early; the product path looks it up by
         * name first and must register it either way. */
        const unsigned extra = ROM_SEED_SCAN_ENTRY_CAP + 64u;
        for (unsigned i = 0; i < extra; i++) {
            char path[384];
            snprintf(path, sizeof(path), "%s/blk%06u.dat", dir, i);
            FILE *f = fopen(path, "wb");
            ASSERT(f != NULL);
            fputc('x', f);
            fclose(f);
        }
        long nent = 0;
        {
            DIR *d = opendir(dir);
            ASSERT(d != NULL);
            while (readdir(d) != NULL)
                nent++;
            closedir(d);
        }
        ASSERT(nent > (long)ROM_SEED_SCAN_ENTRY_CAP);

        /* The walk cannot visit every name; the by-name lookup must. */
        int reg = rom_seed_scan_datadir(dir);
        ASSERT(reg >= 1);
        ASSERT(bps_have_kind(ROM_ARTIFACT_HEADER_SEED));

        /* And the served listing actually offers it, which is what a fresh
         * node's discovery matches on. */
        char json[4096];
        size_t jn = rom_seed_directory_json(json, sizeof(json));
        ASSERT(jn > 0);
        ASSERT(strstr(json, "\"header_seed\"") != NULL);

        free(hs);
        rom_seed_reset();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* (b) A corrupt bundle and an unknown-kind file are refused loudly and never
 * offered — publishing mints no trust, it only serves content-verified bytes. */
static int test_bps_refuses_corrupt(void)
{
    int failures = 0;
    TEST("bundle-publish-serve: corrupt / wrong-kind artifacts are refused") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bundle_publish", "bad");

        char bundles[320];
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);

        size_t size = 65536;
        uint8_t *bad = malloc(size);
        ASSERT(bad != NULL);
        bps_gen(bad, size, false); /* 0xEE header, NOT SQLite magic */

        /* A bundle-named file that is not SQLite → content check fails. */
        ASSERT(bps_write(dir, "bundles/consensus-state-bundle-200.sqlite",
                         bad, size));
        /* An unknown-kind file the classifier ignores entirely. */
        ASSERT(bps_write(dir, "random-file.txt", bad, size));

        /* Direct registration names each refusal precisely. */
        ASSERT(rom_seed_register(dir,
                                 "bundles/consensus-state-bundle-200.sqlite",
                                 NULL, NULL) == ROM_REG_ERR_CORRUPT);
        ASSERT(rom_seed_register(dir, "random-file.txt", NULL, NULL)
               == ROM_REG_ERR_UNKNOWN_KIND);

        /* And the scan registers NEITHER — nothing corrupt/unknown is served. */
        int reg = rom_seed_scan_datadir(dir);
        ASSERT(reg == 0);
        ASSERT(rom_seed_count() == 0);
        ASSERT(!bps_have_kind(ROM_ARTIFACT_CONSENSUS_BUNDLE));

        free(bad);
        rom_seed_reset();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* (c) GAP-1a — the at-tip gate: a starter bundle is only published near the
 * network tip; a still-catching-up node refuses so it never mints a stale one. */
static int test_bx_at_tip_gate(void)
{
    int failures = 0;
    TEST("bundle-exporter: at-tip gate publishes near tip, refuses when behind") {
        /* SYNC_AT_TIP always qualifies regardless of the lag number. */
        ASSERT(bundle_exporter_at_tip_ok_for_test(true, 999, 4));
        /* Within the gap → OK; exactly at the gap → OK; past it → refused. */
        ASSERT(bundle_exporter_at_tip_ok_for_test(false, 0, 4));
        ASSERT(bundle_exporter_at_tip_ok_for_test(false, 4, 4));
        ASSERT(!bundle_exporter_at_tip_ok_for_test(false, 5, 4));
        /* Unknown network tip (gap < 0) while unsynced → fail CLOSED. */
        ASSERT(!bundle_exporter_at_tip_ok_for_test(false, -1, 4));
    } _test_next:;
    return failures;
}

/* (d) GAP-1b — the time+block cadence: block CEILING, daily time CEILING, and
 * the min-secs FLOOR that forbids double-exporting in a burst. */
static int test_bx_cadence(void)
{
    int failures = 0;
    TEST("bundle-exporter: cadence honors block/time ceilings + min-secs floor") {
        const int64_t every_blocks = 5000, every_secs = 86400, min_secs = 900;

        /* Nothing new (h <= last) is never due, however long it has been. */
        ASSERT(!bundle_exporter_export_due_for_test(1000, 1000, INT64_MAX,
                                                    every_blocks, every_secs,
                                                    min_secs));

        /* Block ceiling fires once >= every_blocks accrued AND the floor is
         * clear. */
        ASSERT(bundle_exporter_export_due_for_test(6000, 1000, 1000,
                                                   every_blocks, every_secs,
                                                   min_secs));
        /* ...but the FLOOR suppresses a burst: 5000 blocks in < min_secs. */
        ASSERT(!bundle_exporter_export_due_for_test(6000, 1000, 100,
                                                    every_blocks, every_secs,
                                                    min_secs));

        /* Time CEILING fires on a tiny block delta once every_secs elapsed and
         * the tip advanced (h > last). */
        ASSERT(bundle_exporter_export_due_for_test(1001, 1000, 90000,
                                                   every_blocks, every_secs,
                                                   min_secs));
        /* Time elapsed but tip did NOT advance → not due. */
        ASSERT(!bundle_exporter_export_due_for_test(1000, 1000, 90000,
                                                    every_blocks, every_secs,
                                                    min_secs));
        /* Neither ceiling reached → not due. */
        ASSERT(!bundle_exporter_export_due_for_test(2000, 1000, 1000,
                                                    every_blocks, every_secs,
                                                    min_secs));

        /* First-ever export: last_h = -1, elapsed unbounded → the block ceiling
         * fires and the floor passes. */
        ASSERT(bundle_exporter_export_due_for_test(3056758, -1, INT64_MAX,
                                                   every_blocks, every_secs,
                                                   min_secs));
    } _test_next:;
    return failures;
}

/* (e) GAP-2 — rotation deregisters AND unlinks the rotated-out generations, so a
 * node stops serving a bundle the moment it deletes it. */
static int test_bx_rotation_deregister_unlink(void)
{
    int failures = 0;
    TEST("bundle-exporter: rotation deregisters + unlinks the old generations") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bundle_rotate", "ok");
        char bundles[320];
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);

        /* Four SQLite-shaped generations under bundles/, each with DISTINCT
         * bytes (a unique marker past the magic) so every generation has its own
         * chunk_root — otherwise identical content would collide on one root and
         * find_by_root could not tell a deleted generation from a kept one. */
        static const int heights[] = { 100, 200, 300, 400 };
        size_t bsz = 8192;
        uint8_t *b = malloc(bsz);
        ASSERT(b != NULL);
        bps_gen(b, bsz, true);
        for (size_t i = 0; i < 4; i++) {
            b[100] = (uint8_t)(i + 1); /* index >= 16 keeps the SQLite magic */
            char rel[64];
            snprintf(rel, sizeof(rel), "bundles/consensus-state-bundle-%d.sqlite",
                     heights[i]);
            ASSERT(bps_write(dir, rel, b, bsz));
        }
        free(b);

        /* Scan registers all four under their "bundles/<name>" shape. */
        ASSERT(rom_seed_scan_datadir(dir) == 4);
        ASSERT(rom_seed_count() == 4);

        /* Capture the chunk_root of each generation so we can prove the served
         * lookup follows the deletion. */
        struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
        int na = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
        ASSERT(na == 4);
        uint8_t root_100[32] = {0}, root_400[32] = {0};
        bool have_100 = false, have_400 = false;
        for (int i = 0; i < na; i++) {
            if (strstr(arts[i].filename, "bundle-100.sqlite")) {
                memcpy(root_100, arts[i].chunk_root, 32);
                have_100 = true;
            } else if (strstr(arts[i].filename, "bundle-400.sqlite")) {
                memcpy(root_400, arts[i].chunk_root, 32);
                have_400 = true;
            }
        }
        ASSERT(have_100 && have_400);

        /* Fixtures are SQLite-shaped but not full valid bundles, so bypass the
         * newest-re-validation guard to reach the deletion path. */
        bundle_exporter_set_rotate_skip_validate_for_test(true);
        bundle_exporter_rotate_for_test(bundles, 2, dir);
        bundle_exporter_set_rotate_skip_validate_for_test(false);

        /* The two oldest (100, 200) are gone from disk; the two newest remain. */
        char p[512];
        struct stat st;
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-100.sqlite", bundles);
        ASSERT(stat(p, &st) != 0);
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-200.sqlite", bundles);
        ASSERT(stat(p, &st) != 0);
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-300.sqlite", bundles);
        ASSERT(stat(p, &st) == 0);
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-400.sqlite", bundles);
        ASSERT(stat(p, &st) == 0);

        /* And they are DEREGISTERED: count dropped and the deleted root no
         * longer serves, while a kept one still does. */
        ASSERT(rom_seed_count() == 2);
        ASSERT(rom_seed_serve_lookup(root_100, 0, NULL) == ROM_SERVE_NOT_ARTIFACT);
        ASSERT(rom_seed_serve_lookup(root_400, 0, NULL) == ROM_SERVE_FREE_OK);

        rom_seed_reset();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* (e2) A DEGRADED exporter names itself. This is the regression for a silent
 * production outage: the canonical node last minted a bundle on 2026-07-24 and
 * was still serving it on 2026-08-19, 165,288 blocks behind its own tip,
 * because a binary upgrade left the stored producer session foreign to the
 * running build. That refusal is correct and stays. What was wrong is that it
 * was INVISIBLE — one WARN at boot, then a 30-second tick forever with
 * exports_ok=0 AND exports_failed=0, which is indistinguishable from a healthy
 * node that simply has not hit its cadence. Every cold-starting peer paid for
 * that month as crawl time.
 *
 * A fresh progress store has no proven coins authority, so bx_qualified refuses
 * here for its own (equally real) reason and the exporter comes up degraded —
 * the exact state under test. The assertion is that the degradation is NAMED,
 * carries the staleness numbers an operator needs, and is DEPENDENCY-class so
 * it remains visible without hard-gating the node's unrelated public serving. */
static int test_bx_degraded_names_a_blocker(void)
{
    int failures = 0;
    TEST("bundle-exporter: a degraded exporter names its outage, never sits silent") {
        blocker_reset_for_testing();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bundle_degraded", "ok");

        ASSERT(progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        ASSERT(pdb != NULL);

        /* Nothing here is proven/refolded, so the exporter cannot qualify. It
         * must still ARM (never block boot) and must not export. */
        ASSERT(bundle_exporter_start(pdb, dir));

        struct blocker_snapshot snap[BLOCKER_CAP];
        int n = blocker_snapshot_all(snap, BLOCKER_CAP);
        int found = -1;
        for (int i = 0; i < n; i++)
            if (strcmp(snap[i].id, "bundle_exporter.degraded") == 0)
                found = i;
        /* RED without the fix: the registry stays empty and found == -1. */
        ASSERT(found >= 0);
        ASSERT(strcmp(snap[found].owner_subsystem, "bundle_exporter") == 0);
        /* DEPENDENCY, not TRANSIENT: nothing in this process re-runs the gates,
         * so the record persists, but optional export failure stays a warning
         * rather than a false public-serving refusal. */
        ASSERT(snap[found].class == BLOCKER_DEPENDENCY);
        /* The reason has to be actionable on its own, not a bare label: it says
         * no bundle exists to serve and that no in-process retry will fix it. */
        ASSERT(strstr(snap[found].reason, "consensus-state bundle") != NULL);
        ASSERT(strstr(snap[found].reason, "no in-process retry") != NULL);
        /* The specific refusal (bx_qualified's reason, here "coins not
         * proven authority") must lead the string, not trail it: a
         * BLOCKER_REASON_MAX(256) cap trims the TAIL, so if the generic
         * "no consensus-state bundle minted..." framing came first the
         * actionable detail could be the part that gets lost — as it was
         * for the "datadir session does not exactly match" producer
         * refusal in the field. */
        ASSERT(strncmp(snap[found].reason, "coins not proven authority",
                       strlen("coins not proven authority")) == 0);

        bundle_exporter_stop();
        blocker_reset_for_testing();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* (f) The mint gate is INTACT: the exporter still refuses to publish from a
 * borrowed / unstamped build. bx_qualified's exact-source-identity rung (part of
 * the borrowed-state refusal) accepts ONLY a lowercase 64-hex SHA-256 source
 * identity; the coins-proven / refold rungs are unchanged by GAP-1/2/4. */
static int test_bx_mint_gate_source_rung_intact(void)
{
    int failures = 0;
    TEST("bundle-exporter: mint gate still refuses a borrowed/unstamped source") {
        ASSERT(!bundle_exporter_source_identity_is_exact_for_test(NULL));
        ASSERT(!bundle_exporter_source_identity_is_exact_for_test(""));
        /* Not 64 hex → borrowed/unstamped → refused. */
        ASSERT(!bundle_exporter_source_identity_is_exact_for_test("not-a-sha"));
        ASSERT(!bundle_exporter_source_identity_is_exact_for_test(
            "0123456789abcdef")); /* too short */
        ASSERT(!bundle_exporter_source_identity_is_exact_for_test(
            "0123456789ABCDEF0123456789ABCDEF"
            "0123456789ABCDEF0123456789ABCDEF")); /* uppercase not accepted */
        /* Exactly 64 lowercase hex → the stamped canonical build → accepted. */
        ASSERT(bundle_exporter_source_identity_is_exact_for_test(
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"));
    } _test_next:;
    return failures;
}

int test_bundle_publish_serve(void)
{
    int failures = 0;
    failures += test_bps_serves_both();
    failures += test_bps_serves_header_seed_in_a_big_datadir();
    failures += test_bps_refuses_corrupt();
    failures += test_bx_at_tip_gate();
    failures += test_bx_cadence();
    failures += test_bx_rotation_deregister_unlink();
    failures += test_bx_degraded_names_a_blocker();
    failures += test_bx_mint_gate_source_rung_intact();
    return failures;
}
