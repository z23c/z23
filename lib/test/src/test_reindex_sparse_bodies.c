/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reindex_sparse_bodies — regression gate for the body-coverage-aware
 * auto-reindex-chainstate DECISION (lane 2B, "Track B"): a datadir where
 * coins are seeded near a tip height H but the on-disk block bodies are
 * SPARSE (present only for a tail window [H-k, H], not contiguously from
 * genesis) must REFUSE the destructive -reindex-chainstate remedy instead
 * of consuming the armed auto_reindex_request sentinel — a full
 * reindex-chainstate needs to replay bodies from genesis through the
 * target height, and a sparse-bodies datadir cannot supply that replay, so
 * consuming the request would wipe the seeded coins for a rebuild that
 * cannot even complete (see docs/HANDOFF.md's
 * "destructive auto-reindex-chainstate that wipes seeded coins + re-arms
 * on bodyless datadirs" gap, and 52b440e8f "fix(boot): don't wipe a
 * hash-verified coins-best that covers the reindex anchor" — that landed
 * fix covers the coins-best-vs-anchor-height axis; this gate is the
 * COMPANION axis, body coverage vs. reindex target).
 *
 * WEAK-SYMBOL SEAM (test_always_sync_selfheal.c G1/G3 pattern): the
 * decision predicate this test gates, `boot_reindex_coverage_would_refuse`,
 * is lane 2B's own not-yet-merged work (a sibling worktree, separate from
 * this one). Declared here as a `__attribute__((weak))` extern with the
 * EXACT signature this test ASSUMES:
 *
 *     bool boot_reindex_coverage_would_refuse(int32_t scan_reindex_best,
 *                                             int32_t scan_max_have_data_h)
 *
 * where `scan_reindex_best` is the height the reindex-chainstate replay
 * would need to reach (the coins-best / wedge-tip height a boot pass wants
 * to fully rebuild through) and `scan_max_have_data_h` is the highest
 * height with body coverage CONTIGUOUS FROM GENESIS (-1 if genesis itself
 * lacks a body marker). This assumption is PROMINENT here and in the
 * landing lane's summary — if 2B lands a different name or parameter
 * order, the orchestrator reconciles this file's weak decl (a one-line
 * fix; the rest of the test is contract-shaped, not implementation-shaped).
 *
 * Until that symbol links, this file compiles and SKIPs cleanly (no
 * fixture built, no assertion run) — it becomes the integration
 * regression gate the moment 2B's real decision function links.
 *
 * FIXTURE (a synthetic mini-datadir, NOT a full node datadir — no
 * node.db/progress.kv/block index involved; this test exercises the
 * DECISION given two integers, not the scan that produces them):
 *
 *     <dir>/blocks/h<N>.body   — an empty marker file per height N whose
 *                                body is present on disk. Written only for
 *                                N in [H-k, H] ("sparse bodies").
 *     <dir>/coins_best         — "<height> <hash_verified 0|1>\n", the
 *                                seeded coins-best marker at height H.
 *     <dir>/auto_reindex_request — the REAL on-disk sentinel format (see
 *                                storage/boot_auto_reindex.h), armed via
 *                                the REAL boot_auto_reindex_request().
 *
 * tools/scripts/make-sparse-bodies-fixture.sh builds the IDENTICAL layout
 * for local manual repro against a real binary once 2B's scan lands.
 *
 * This test does NOT call boot.c / boot_index.c / boot_crashonly.c (lane
 * 2B's own files) — it drives the weak decision hook directly and, in its
 * place, simulates the two effects a real boot pass wiring the decision in
 * would perform: clearing the sentinel on a refusal
 * (boot_auto_reindex_clear, a real storage primitive) and re-detecting the
 * same wedge on a second pass (a second boot_auto_reindex_request call). */

#include "test/test_core.h"

#include "storage/boot_auto_reindex.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#define RSB_CHECK(name, expr) do {                                          \
    printf("reindex_sparse_bodies: %s... ", (name));                       \
    if (expr) { printf("OK\n"); }                                          \
    else { printf("FAIL\n"); failures++; }                                 \
} while (0)

/* See this file's header comment for the assumed signature. */
#if defined(__APPLE__)
static bool (*const boot_reindex_coverage_would_refuse)(int32_t, int32_t) =
    NULL;
#else
extern bool boot_reindex_coverage_would_refuse(int32_t scan_reindex_best,
                                               int32_t scan_max_have_data_h)
    __attribute__((weak));
#endif

static bool rsb_touch_body(const char *dir, int32_t height)
{
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/blocks/h%d.body", dir,
                     (int)height);
    if (n < 0 || n >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    return fclose(f) == 0;
}

/* Highest N such that every height in [0, N] has a body marker present
 * (contiguous coverage FROM GENESIS) — the first missing marker terminates
 * the scan. -1 means even genesis (height 0) has no marker. Bounded by
 * `upper_bound` so a fixture bug can never spin this loop unboundedly.
 * TEST-LOCAL scan logic standing in for whatever real coverage scan 2B's
 * boot-reindex decision performs internally — out of scope here; this
 * test only exercises the DECISION given the two resulting integers. */
static int32_t rsb_scan_max_have_data_h(const char *dir, int32_t upper_bound)
{
    char path[600];
    int32_t h = 0;
    for (; h <= upper_bound; h++) {
        int n = snprintf(path, sizeof(path), "%s/blocks/h%d.body", dir,
                         (int)h);
        if (n < 0 || n >= (int)sizeof(path))
            break;
        struct stat st;
        if (stat(path, &st) != 0)
            break;
    }
    return h - 1;
}

static bool rsb_write_coins_best(const char *dir, int32_t height,
                                 bool hash_verified)
{
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/coins_best", dir);
    if (n < 0 || n >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fprintf(f, "%d %d\n", (int)height, hash_verified ? 1 : 0) > 0;
    return fclose(f) == 0 && ok;
}

static bool rsb_read_coins_best(const char *dir, int32_t *height,
                                bool *hash_verified)
{
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/coins_best", dir);
    if (n < 0 || n >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    int h = 0, v = 0;
    bool ok = fscanf(f, "%d %d", &h, &v) == 2;
    fclose(f);
    if (!ok)
        return false;
    *height = (int32_t)h;
    *hash_verified = (v != 0);
    return true;
}

int test_reindex_sparse_bodies(void);
int test_reindex_sparse_bodies(void)
{
    printf("\n=== reindex_sparse_bodies (Track B decision: sparse bodies "
          "refuse reindex) ===\n");
    int failures = 0;

    if (!boot_reindex_coverage_would_refuse) {
        printf("reindex_sparse_bodies: SKIP — "
              "boot_reindex_coverage_would_refuse not yet linked (lane 2B's "
              "body-coverage-aware reindex decision, a sibling worktree, "
              "not yet merged); this becomes the integration regression "
              "gate once that lane lands. ASSUMED SIGNATURE (see this "
              "file's header comment): bool "
              "boot_reindex_coverage_would_refuse(int32_t "
              "scan_reindex_best, int32_t scan_max_have_data_h)\n");
        return 0;
    }

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reindex_sparse_bodies", "main");
    char blocks_dir[300];
    int bn = snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", dir);
    RSB_CHECK("fixture path formatted",
             bn > 0 && bn < (int)sizeof(blocks_dir));
    RSB_CHECK("blocks/ subdir created", mkdir(blocks_dir, 0755) == 0);

    const int32_t H = 5000;   /* coins seeded at this height (the wedge tip) */
    const int32_t K = 100;    /* bodies present only in [H-K, H] */

    bool bodies_ok = true;
    for (int32_t h = H - K; h <= H; h++)
        bodies_ok = rsb_touch_body(dir, h) && bodies_ok;
    RSB_CHECK("sparse bodies fixture written for [H-K, H]", bodies_ok);

    RSB_CHECK("coins-best marker seeded at H (hash-verified)",
             rsb_write_coins_best(dir, H, true));

    int n1 = boot_auto_reindex_request(dir, H);
    RSB_CHECK("auto_reindex_request sentinel armed on pass 1", n1 == 1);
    RSB_CHECK("sentinel PENDS after arming (pass 1)",
             boot_auto_reindex_pending(dir));

    int32_t scan_max_have_data_h = rsb_scan_max_have_data_h(dir, H);
    RSB_CHECK("body coverage has NO contiguous-from-genesis span (sparse: "
             "genesis itself lacks a body marker)",
             scan_max_have_data_h == -1);

    int32_t coins_h = -1;
    bool coins_verified = false;
    RSB_CHECK("coins-best marker reads back",
             rsb_read_coins_best(dir, &coins_h, &coins_verified) &&
             coins_h == H && coins_verified);
    int32_t scan_reindex_best = coins_h;

    bool refuses = boot_reindex_coverage_would_refuse(scan_reindex_best,
                                                       scan_max_have_data_h);
    RSB_CHECK("decision REFUSES reindex — bodies do not cover the target "
             "(a reindex-chainstate replay from genesis cannot complete, "
             "would only wipe the seeded coins)", refuses);

    /* Simulate the wiring a real boot pass will perform once 2B's decision
     * is wired at the sentinel-consume chokepoint: a refusal clears the
     * stale request instead of consuming it. */
    if (refuses)
        boot_auto_reindex_clear(dir);
    RSB_CHECK("sentinel CLEARED after the refusal (pass 1) — never consumed "
             "into a destructive reindex", !boot_auto_reindex_pending(dir));

    /* Simulated SECOND PASS: the node restarts, re-detects the identical
     * wedge (same coins-best, same sparse bodies) and arms a fresh request
     * exactly like the real boot-time detector would — the decision must
     * refuse AGAIN (deterministic on unchanged inputs, not a one-shot
     * fluke) and the sentinel must NOT be left pending once the pass
     * completes: no re-arm, no unbounded reindex-then-clear loop. */
    int n2 = boot_auto_reindex_request(dir, H);
    RSB_CHECK("sentinel re-arms via the boot pass's OWN detection (pass 2, "
             "not a leftover from pass 1)", n2 >= 1);
    bool refuses2 = boot_reindex_coverage_would_refuse(scan_reindex_best,
                                                        scan_max_have_data_h);
    RSB_CHECK("decision refuses again on pass 2 (deterministic on the same "
             "sparse-bodies input)", refuses2);
    if (refuses2)
        boot_auto_reindex_clear(dir);
    RSB_CHECK("sentinel does NOT re-arm — cleared again at the end of pass "
             "2 (no unbounded loop on a bodyless datadir)",
             !boot_auto_reindex_pending(dir));

    test_cleanup_tmpdir(blocks_dir);
    test_cleanup_tmpdir(dir);

    if (failures == 0)
        printf("=== reindex_sparse_bodies: ALL PASS ===\n\n");
    else
        printf("reindex_sparse_bodies: failures=%d\n", failures);
    return failures;
}
