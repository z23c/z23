/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_loader_owns_seed_gate — regression gate for the two DEPLOYED
 * daily-driver fixes that previously had NO test (a refactor could revert
 * either and re-wedge the live node with green CI).
 *
 * FIX 1 — loader_owns_seed (engine/composition/src/boot_services.c app_init_services).
 *   When -load-snapshot-at-own-height is set, the loader at boot.c has already
 *   re-seeded coins_kv from the body-digest-verified assisted snapshot at its
 *   OWN height and
 *   raised the tip_finalize trusted base there; it is the authoritative seed
 *   for this boot. Both fallback seeders
 *   (boot_refold_from_anchor_arm_if_torn AND
 *   block_index_loader_seed_stages_from_cold_import) MUST be skipped — they
 *   re-seed from the COMPILED checkpoint, dropping the trusted base and
 *   re-wedging forward sync. The skip decision is the PURE predicate
 *   boot_loader_owns_seed(ctx): true iff ctx && ctx->load_snapshot_at_own_height
 *   != NULL. This test pins:
 *     (1) flag SET    -> true  (skip fallbacks; loader owns the seed)
 *     (2) flag UNSET  -> false (a normal boot still runs the cold-import seed)
 *     (3) ctx == NULL -> false (no crash, no skip)
 *   REGRESSION: if the gate is reverted to ignore load_snapshot_at_own_height
 *   (e.g. always-false / drop the field from the condition), case (1) flips to
 *   false and this test FAILs — exactly the seed-clobber that re-wedges the
 *   live node.
 *
 * FIX 3 — forged-snapshot anchor-hash FATAL
 *   (engine/composition/src/boot_refold_staged.c boot_load_snapshot_at_own_height_reset).
 *   The loaded snapshot's anchor_block_hash MUST byte-equal the in-binary
 *   PoW-proven header hash at the snapshot height; on mismatch the loader
 *   FATALs (refuses a forged / wrong-chain snapshot) rather than seeding
 *   contaminated coins. The match decision is the PURE predicate
 *   boot_snapshot_anchor_hash_matches(index_hash, snapshot_hash): true iff the
 *   two 32-byte hashes are byte-identical. This test pins:
 *     (1) identical 32 bytes        -> true  (chain location matches)
 *     (2) one differing byte        -> false (forged/wrong chain; FATAL fires)
 *     (3) all-zero vs real          -> false (the empty-anchor forgery)
 *     (4) NULL on either side       -> false (refuse, no deref)
 *   REGRESSION: if the memcmp is weakened to always-pass (return true), case
 *   (2)/(3) flip to true and this test FAILs — exactly the forged-snapshot
 *   acceptance that seeds contaminated coins.
 *
 * Both predicates are PURE (no side effects), so this test runs in-process with
 * no fork, no datadir, no progress store — fully deterministic and fast.
 */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "config/boot.h"          /* struct app_context, boot_snapshot_anchor_hash_matches */
#include "config/boot_internal.h" /* boot_loader_owns_seed */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LOSG_CHECK(name, expr) do {                       \
    printf("loader_owns_seed_gate: %s... ", (name));      \
    if (expr) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

int test_loader_owns_seed_gate(void)
{
    int failures = 0;

    /* ── FIX 1: boot_loader_owns_seed ───────────────────────────────── */
    {
        struct app_context ctx;
        memset(&ctx, 0, sizeof ctx);

        /* (2) flag UNSET — a normal boot: cold-import seed must still run. */
        ctx.load_snapshot_at_own_height = NULL;
        LOSG_CHECK("fix1: flag unset -> false (normal boot keeps cold-import seed)",
                   boot_loader_owns_seed(&ctx) == false);

        /* (1) flag SET — loader owns the seed; BOTH fallbacks must be skipped.
         * This is the load-bearing case: reverting the gate re-wedges sync. */
        ctx.load_snapshot_at_own_height = "/some/snapshot/path";
        LOSG_CHECK("fix1: flag set -> true (skip both fallback seeders)",
                   boot_loader_owns_seed(&ctx) == true);

        /* (3) ctx == NULL — must not crash, must not skip. */
        LOSG_CHECK("fix1: ctx NULL -> false",
                   boot_loader_owns_seed(NULL) == false);
    }

    /* ── FIX 3: boot_snapshot_anchor_hash_matches ───────────────────── */
    {
        unsigned char a[32], b[32];
        for (int i = 0; i < 32; i++) { a[i] = (unsigned char)(0x10 + i); }
        memcpy(b, a, 32);

        /* (1) identical -> chain location matches; payload remains assisted. */
        LOSG_CHECK("fix3: identical hashes -> true (chain location matches)",
                   boot_snapshot_anchor_hash_matches(a, b) == true);

        /* (2) one byte differs -> forged/wrong chain, FATAL must fire. The
         * differing byte is the LAST one (a naive prefix-only compare would
         * miss it). */
        b[31] ^= 0x01;
        LOSG_CHECK("fix3: last byte differs -> false (forged -> FATAL)",
                   boot_snapshot_anchor_hash_matches(a, b) == false);
        b[31] ^= 0x01; /* restore */

        /* a first-byte difference too (full 32-byte compare). */
        b[0] ^= 0xff;
        LOSG_CHECK("fix3: first byte differs -> false",
                   boot_snapshot_anchor_hash_matches(a, b) == false);
        b[0] ^= 0xff; /* restore */

        /* (3) all-zero snapshot anchor (the empty/forged anchor) vs a real
         * index hash -> false. */
        unsigned char zero[32];
        memset(zero, 0, 32);
        LOSG_CHECK("fix3: all-zero anchor vs real -> false",
                   boot_snapshot_anchor_hash_matches(a, zero) == false);

        /* sanity: identical all-zero would match — but the live path never
         * has a zero index hash; this only documents the predicate is a pure
         * byte-compare, not a special-case. */
        LOSG_CHECK("fix3: identical all-zero -> true (pure byte-compare)",
                   boot_snapshot_anchor_hash_matches(zero, zero) == true);

        /* (4) NULL on either side -> refuse, no deref. */
        LOSG_CHECK("fix3: NULL index hash -> false",
                   boot_snapshot_anchor_hash_matches(NULL, b) == false);
        LOSG_CHECK("fix3: NULL snapshot hash -> false",
                   boot_snapshot_anchor_hash_matches(a, NULL) == false);
    }

    /* ── D1: boot_seed_is_shieldless_past_sapling ───────────────────────
     * A v1 (transparent-only) seed on a chain past Sapling activation is a
     * guaranteed delayed wedge (utxo_apply.{anchor,nullifier}_backfill_gap at the
     * first shielded tx). The loader refuses it up front. v2/v3 (live/dev-lane
     * format) carry shielded state and pass. Mainnet Sapling activation = 476969.
     * REGRESSION: weaken the gate to always-false and case (a)/(c) flip -> the
     * shieldless-seed footgun returns (delayed permanent wedge). */
    {
        const int64_t SAPLING = 476969;
        const int64_t PAST    = 3189353;  /* real near-tip height */
        const int64_t BELOW   = 1000;     /* below Sapling activation */

        /* (a) v1 past Sapling -> refuse. */
        LOSG_CHECK("d1: v1 seed past Sapling -> true (refuse)",
                   boot_seed_is_shieldless_past_sapling(1, PAST, SAPLING) == true);
        /* (b) v1 BELOW Sapling -> allow (no shielded history to miss). */
        LOSG_CHECK("d1: v1 seed below Sapling -> false (allow)",
                   boot_seed_is_shieldless_past_sapling(1, BELOW, SAPLING) == false);
        /* (c) v1 exactly AT activation -> refuse (>=). */
        LOSG_CHECK("d1: v1 seed at Sapling activation -> true (refuse)",
                   boot_seed_is_shieldless_past_sapling(1, SAPLING, SAPLING) == true);
        /* (d) v2 (Sapling frontier) past Sapling -> allow (live/dev-lane format). */
        LOSG_CHECK("d1: v2 seed past Sapling -> false (allow)",
                   boot_seed_is_shieldless_past_sapling(2, PAST, SAPLING) == false);
        /* (e) v3 (full shielded) past Sapling -> allow. */
        LOSG_CHECK("d1: v3 seed past Sapling -> false (allow)",
                   boot_seed_is_shieldless_past_sapling(3, PAST, SAPLING) == false);
        /* (f) version 0 (malformed/unknown) past Sapling -> refuse (fail-safe). */
        LOSG_CHECK("d1: v0 seed past Sapling -> true (refuse, fail-safe)",
                   boot_seed_is_shieldless_past_sapling(0, PAST, SAPLING) == true);
        /* (g) unknown/disabled Sapling activation (-1) -> never a false refusal. */
        LOSG_CHECK("d1: activation unknown -> false (defer, never false-refuse)",
                   boot_seed_is_shieldless_past_sapling(1, PAST, -1) == false);
    }

    /* ── D3: boot_seed_oneshot_headers_ready ────────────────────────────
     * The seed one-shot (-coldstart-seed-oneshot) has no P2P/IBD: it can only
     * seed at a height whose header the imported block index already holds.
     * Answerable the instant the block index is loaded, so the loader fails FAST
     * with a named prerequisite instead of burning a full boot then FATAL-ing.
     * REGRESSION: invert the comparison and a fresh (no-header) datadir would be
     * declared "ready" -> burns the boot then FATALs deep in the seed reset. */
    {
        const int64_t SEED = 3189353;

        /* header tip reaches the seed height -> prerequisite met. */
        LOSG_CHECK("d3: header tip == seed -> true (ready)",
                   boot_seed_oneshot_headers_ready(SEED, SEED) == true);
        LOSG_CHECK("d3: header tip above seed -> true (ready)",
                   boot_seed_oneshot_headers_ready(SEED + 10, SEED) == true);
        /* one header short -> not ready (import more headers first). */
        LOSG_CHECK("d3: header tip one short -> false (prerequisite unmet)",
                   boot_seed_oneshot_headers_ready(SEED - 1, SEED) == false);
        /* fresh datadir: header tip pinned at genesis (0) -> not ready. */
        LOSG_CHECK("d3: fresh datadir (tip=0) -> false",
                   boot_seed_oneshot_headers_ready(0, SEED) == false);
        /* no best_header at all (tip = -1) -> not ready, no crash. */
        LOSG_CHECK("d3: no best_header (tip=-1) -> false",
                   boot_seed_oneshot_headers_ready(-1, SEED) == false);
    }

    return failures;
}
