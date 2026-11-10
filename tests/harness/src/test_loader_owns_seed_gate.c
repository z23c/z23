/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_loader_owns_seed_gate — pins two boot gates.
 *
 * loader_owns_seed (engine/composition/src/boot_services.c app_init_services):
 *   with -load-snapshot-at-own-height the loader has already re-seeded
 *   coins_kv from the body-digest-verified snapshot and raised the
 *   tip_finalize trusted base, so both fallback seeders
 *   (boot_refold_from_anchor_arm_if_torn and
 *   block_index_loader_seed_stages_from_cold_import) must be skipped: they
 *   re-seed from the compiled checkpoint and drop the trusted base. The pure
 *   predicate boot_loader_owns_seed(ctx) is true iff ctx &&
 *   ctx->load_snapshot_at_own_height != NULL:
 *     (1) flag SET    -> true
 *     (2) flag UNSET  -> false (a normal boot still runs the cold-import seed)
 *     (3) ctx == NULL -> false (no crash, no skip)
 *
 * forged-snapshot anchor-hash FATAL
 *   (engine/composition/src/boot_refold_staged.c boot_load_snapshot_at_own_height_reset):
 *   the snapshot's anchor_block_hash must byte-equal the in-binary PoW-proven
 *   header hash at the snapshot height, else the loader FATALs. The pure
 *   predicate boot_snapshot_anchor_hash_matches(index_hash, snapshot_hash):
 *     (1) identical 32 bytes        -> true
 *     (2) one differing byte        -> false
 *     (3) all-zero vs real          -> false (the empty-anchor forgery)
 *     (4) NULL on either side       -> false (refuse, no deref)
 *
 * Both predicates are pure: in-process, no fork, no datadir, no progress store.
 */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "config/boot.h"          /* struct app_context, boot_snapshot_anchor_hash_matches */
#include "config/boot_error.h"    /* boot_error_reset_for_testing, first code */
#include "config/boot_internal.h" /* boot_loader_owns_seed */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Calls the shipped preflight. A missing snapshot must latch the typed
 * open refusal; a normal boot (flags false) must not. */
static bool losg_oneshot_snapshot_open_latches(void)
{
    struct app_context ctx;
    char rendered[4096];
    const char *path = "/no/such/z23-seed-snapshot.uss";

    boot_error_reset_for_testing();
    memset(&ctx, 0, sizeof(ctx));
    ctx.cold_start_seed_oneshot = true;
    ctx.load_snapshot_at_own_height = path;
    if (boot_seed_oneshot_headers_preflight(&ctx, NULL) != false)
        return false;
    if (!boot_error_reported())
        return false;
    if (strcmp(boot_error_first_code(),
               "BOOT_SEED_ONESHOT_SNAPSHOT_OPEN_FAILED") != 0)
        return false;
    if (boot_error_last_render(rendered, sizeof(rendered)) == 0)
        return false;
    if (strstr(rendered, "BOOT_SEED_ONESHOT_SNAPSHOT_OPEN_FAILED") == NULL)
        return false;
    if (strstr(rendered, "seed.oneshot") == NULL)
        return false;
    if (strstr(rendered, "/no/such/z23-seed-snapshot.uss") == NULL)
        return false;

    boot_error_reset_for_testing();
    memset(&ctx, 0, sizeof(ctx));
    if (boot_seed_oneshot_headers_preflight(&ctx, NULL) != true)
        return false;
    return !boot_error_reported();
}

/* v1 USS, 104 bytes, count 0: magic, version 1, height 50. uss_open with
 * verify_full_sha3 false accepts it. Header tip -1 is below that height. */
static bool losg_oneshot_headers_unmet_latches(void)
{
    struct app_context ctx;
    char rendered[4096];
    char path[PATH_MAX];
    unsigned char snap[104];
    FILE *out;
    bool ok = false;

    if (!test_ensure_tmproot())
        return false;
    test_fmt_tmpdir(path, sizeof(path), "loader_owns_seed_gate", "headers");
    memset(snap, 0, sizeof(snap));
    memcpy(snap, "ZCLUTXO", 7);
    snap[8] = 1;
    snap[16] = 50;
    out = fopen(path, "wb");
    if (!out)
        goto done;
    if (fwrite(snap, 1, sizeof(snap), out) != sizeof(snap)) {
        (void)fclose(out);
        goto done;
    }
    if (fclose(out) != 0)
        goto done;

    boot_error_reset_for_testing();
    memset(&ctx, 0, sizeof(ctx));
    ctx.cold_start_seed_oneshot = true;
    ctx.load_snapshot_at_own_height = path;
    if (boot_seed_oneshot_headers_preflight(&ctx, NULL) != false)
        goto done;
    if (!boot_error_reported())
        goto done;
    if (strcmp(boot_error_first_code(),
               "BOOT_SEED_ONESHOT_HEADERS_UNMET") != 0)
        goto done;
    if (boot_error_last_render(rendered, sizeof(rendered)) == 0)
        goto done;
    if (strstr(rendered, "BOOT_SEED_ONESHOT_HEADERS_UNMET") == NULL)
        goto done;
    if (strstr(rendered, "seed.oneshot") == NULL)
        goto done;
    if (strstr(rendered, "seed_h=50") == NULL)
        goto done;

    boot_error_reset_for_testing();
    memset(&ctx, 0, sizeof(ctx));
    if (boot_seed_oneshot_headers_preflight(&ctx, NULL) != true)
        goto done;
    ok = !boot_error_reported();
done:
    (void)unlink(path);
    return ok;
}

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
     * A v1 (transparent-only) seed past Sapling activation (mainnet 476969)
     * would wedge at the first shielded tx (utxo_apply.{anchor,nullifier}_backfill_gap),
     * so the loader refuses it up front. v2/v3 carry shielded state and pass. */
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
     * seed at a height whose header the imported block index already holds, so
     * the loader fails fast with a named prerequisite. */
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

    /* Missing -coldstart-seed-oneshot snapshot: the shipped preflight
     * latches BOOT_SEED_ONESHOT_SNAPSHOT_OPEN_FAILED. Flags off do not. */
    LOSG_CHECK("d3: missing oneshot snapshot latches typed open refusal",
               losg_oneshot_snapshot_open_latches());

    /* Opened snapshot, header tip below seed height: typed headers refusal.
     * Flags off do not latch. */
    LOSG_CHECK("d3: oneshot headers unmet latches typed refusal",
               losg_oneshot_headers_unmet_latches());

    return failures;
}
