/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_self_folded_anchor — the Act-3 (the prize) sovereignty fixture.
 *
 * THE PROPERTY THIS PROVES (self-verified-tip-plan.md, Act 3)
 * ----------------------------------------------------------
 * The detective stops carrying a copy of someone else's case file: a FRESH
 * datadir folds genesis -> the baked checkpoint height (3,056,758) on its own
 * temp coins_kv and re-derives the SAME SHA3 UTXO root + the SAME 1,354,769
 * UTXO count as the compiled checkpoint. The block bodies are the authority;
 * the compiled checkpoint is only a notarization of what the fold MUST produce.
 *
 * TWO FALSE-GREEN TRAPS THE PLAN NAMES (Act 3, "stronger gate"):
 *   (1) Borrowed-seed no-op — a stamped coins_kv passes a naive gate while
 *       resting on a borrowed copy. Defeated elsewhere by the G-SOV refold
 *       marker; here we only assert the *baked* numbers are the ones the fold
 *       targets.
 *   (2) Baked-checkpoint byte-match — the fresh test can "pass" by reading the
 *       *compiled* checkpoint instead of folding. Defeated by the
 *       `_no_binary_checkpoint` variant: NULL the compiled checkpoint via the
 *       `checkpoints_set_sha3_override_for_test` seam, re-derive from bodies,
 *       and assert the re-derived root EQUALS the original (bodies are the
 *       authority, not the binary).
 *
 * TWO REAL GROUPS (no skeletons):
 * --------------------------------
 *   (A) ALWAYS-ON light fold-and-compare (section 2). A small in-process
 *       coins_kv set ("the bodies") is committed with the SAME canonical SHA3
 *       encoder the real checkpoint uses (coins_kv_commitment), that root is
 *       installed via the checkpoint override seam as "the notarization", and
 *       the root is RE-DERIVED from the same set and asserted EQUAL. Mutating a
 *       coin must break the match. This proves "re-derive == baked" at fixture
 *       scale on every run — the assertion the old skeleton never made.
 *
 *   (B) HEAVY genesis->3,056,758 fold-and-compare
 *       (`test_self_folded_anchor_heavy`, opt-in). The full
 *       ~3.1M-block fold needs a real datadir + the whole boot pipeline
 *       (`boot_mint_anchor_run`, engine/composition/src/boot_mint_anchor.c:52), so the
 *       bodies-from-genesis fold is run by the BINARY (`-mint-anchor`, which
 *       itself HARD-ASSERTs the fold == the compiled checkpoint) and this test
 *       binds to its USS artifact: when ZCL_SELF_FOLD_ANCHOR_FIXTURE points at
 *       that artifact, `uss_open(verify_full_sha3=true,
 *       expected_sha3=cp->sha3_hash)` RE-HASHES the whole body from the records
 *       (not the header) and binds it to the compiled checkpoint. A real
 *       fold-derived-root vs baked-checkpoint comparison. It is a separate
 *       integration group so an absent external artifact cannot make the
 *       hermetic group only partly observed.
 *
 * Wave-1 Lane E of docs/work/self-verified-tip-plan.md. Authored as Act-3 prep.
 */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"        /* uss_open — re-derive body SHA3 */
#include "storage/coins_kv.h"                   /* fixture fold + commitment */
#include "storage/progress_store.h"             /* temp datadir for the fixture */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The numbers the fold MUST reproduce — independently re-stated here from the
 * checkpoint doctrine (checkpoints.c, "Verified bit-for-bit against zclassicd")
 * so a future edit to the compiled struct that silently changes them trips
 * THIS test, not just the production accessor. */
#define SFA_CHECKPOINT_HEIGHT      3056758
#define SFA_CHECKPOINT_UTXO_COUNT  1354769ULL

/* A deterministic txid for the fixture fold. */
static void sfa_txid(uint8_t out[32], uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = tag; out[1] = 0x5F; out[31] = 0x01;
}

int test_self_folded_anchor(void);
int test_self_folded_anchor(void)
{
    int failures = 0;

    printf("\n=== test_self_folded_anchor ===\n");

    /* NOTE: the TEST_CASE/TEST_END macros allow exactly one per function (each
     * TEST_END emits the shared `_test_next:` label). This test has two
     * sections, so it uses one explicit `_test_next:` label and per-section
     * printf markers — the same single-label pattern as
     * test_keystone_utxo_binding.c. */

    /* (1) Baked-checkpoint invariants the fold must reproduce. REAL assertion
     * (no fixture needed): pins the height + UTXO count the self-fold target
     * depends on, so a drift in the compiled checkpoint trips THIS test before
     * any fold work is attempted. */
    printf("self_folded_anchor: baked checkpoint pins height + 1,354,769 UTXOs... ");
    {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        ASSERT(cp != NULL);
        ASSERT(cp->height == SFA_CHECKPOINT_HEIGHT);
        ASSERT(cp->utxo_count == SFA_CHECKPOINT_UTXO_COUNT);
        /* The SHA3 root must be a real (non-zero) commitment, never the
         * all-zeros sentinel — the fold compares against THIS value. */
        uint8_t zero[32] = {0};
        ASSERT(memcmp(cp->sha3_hash, zero, 32) != 0);
        printf("OK\n");
    }

    /* (2) ALWAYS-ON light fold-and-compare — the bodies-are-the-authority
     * property at fixture scale, in-process, every run. This is the genuine
     * de-skeleton: build a small coins_kv set ("the bodies"), commit it with
     * the SAME canonical SHA3 encoder the real checkpoint uses
     * (coins_kv_commitment == the writer's body SHA3, coins_kv.h:55-58 +
     * :297-299), capture that root as the "baked notarization", install it via
     * the checkpoint override seam, then RE-DERIVE the root from the same set
     * and assert re-derive == baked. A mutated coin must break the match. The
     * checkpoint-override doctrine documents this exact construction: "a
     * scaled-down fixture height whose locally-computed commitment IS the
     * override's sha3_hash by construction" (checkpoints.h:101-108). */
    printf("self_folded_anchor: light fixture fold re-derives the notarized root... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "self_fold_light", "main");
        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(coins_kv_ensure_schema(db));

        /* "The bodies" — a fixed, deterministic UTXO set at a fixture height. */
        const int32_t fixture_h = 100;
        uint8_t ta[32], tb[32], tc[32];
        sfa_txid(ta, 0xA1); sfa_txid(tb, 0xB2); sfa_txid(tc, 0xC3);
        uint8_t sc_a[4] = {0xDE,0xAD,0xBE,0xEF};
        uint8_t sc_b[2] = {0x51,0x87};
        ASSERT(coins_kv_add(db, ta, 0, 5000, fixture_h, true,  sc_a, sizeof(sc_a)));
        ASSERT(coins_kv_add(db, ta, 1, 6000, fixture_h, true,  sc_b, sizeof(sc_b)));
        ASSERT(coins_kv_add(db, tb, 0, 7000, fixture_h, false, sc_a, sizeof(sc_a)));
        ASSERT(coins_kv_add(db, tc, 0, 8000, fixture_h, false, NULL, 0));

        /* The "notarized" root: SHA3 over the folded set. Stand this in for the
         * compiled checkpoint via the override seam. */
        struct sha3_utxo_checkpoint fixture_cp;
        memset(&fixture_cp, 0, sizeof(fixture_cp));
        fixture_cp.height = fixture_h;
        fixture_cp.utxo_count = (uint64_t)coins_kv_count(db);
        ASSERT(coins_kv_commitment(db, fixture_cp.sha3_hash) == 0);
        ASSERT(fixture_cp.utxo_count == 4);

        checkpoints_set_sha3_override_for_test(&fixture_cp);
        const struct sha3_utxo_checkpoint *notarized = get_sha3_utxo_checkpoint();
        ASSERT(notarized == &fixture_cp);

        /* RE-DERIVE from the same bodies (NOT by reading the override field):
         * the property is that folding the bodies reproduces the notarized
         * root. This is the assertion the skeleton never made. */
        uint8_t rederived[32] = {0};
        ASSERT(coins_kv_commitment(db, rederived) == 0);
        ASSERT(memcmp(rederived, notarized->sha3_hash, 32) == 0);
        ASSERT((uint64_t)coins_kv_count(db) == notarized->utxo_count);

        /* Mutate one coin: the re-derived root must NO LONGER match the
         * notarized one — a state-wrong fold is DETECTABLE, not silently
         * accepted (the false-green the skeleton allowed). */
        ASSERT(coins_kv_spend(db, tb, 0));
        ASSERT(coins_kv_add(db, tb, 0, 7001, fixture_h, false, sc_a, sizeof(sc_a)));
        uint8_t mutated[32] = {0};
        ASSERT(coins_kv_commitment(db, mutated) == 0);
        ASSERT(memcmp(mutated, notarized->sha3_hash, 32) != 0);

        checkpoints_reset_sha3_override_for_test();
        progress_store_close();
        test_rm_rf_recursive(dir);
        printf("OK\n");
    }

    goto _done;
_test_next:
    /* An ASSERT failed (it jumped here after failures++). */
    printf("(section aborted)\n");
_done:
    if (failures == 0)
        printf("=== test_self_folded_anchor: all cases passed ===\n");
    else
        printf("=== test_self_folded_anchor: %d failure(s) ===\n", failures);
    return failures;
}

/* The heavyweight external-artifact ceremony is deliberately a distinct
 * registered group. The exact push-proof runner may then claim complete
 * observation of test_self_folded_anchor without silently treating this
 * independently provisioned multi-gigabyte fixture as though it ran. */
int test_self_folded_anchor_heavy(void);
int test_self_folded_anchor_heavy(void)
{
    int failures = 0;

    printf("\n=== test_self_folded_anchor_heavy ===\n");

    /* HEAVY genesis->3,056,758 fold-and-compare — REAL when opted in.
     * The full ~3.1M-block fold needs a real datadir and the whole boot
     * pipeline (boot_mint_anchor_run drives the eight stages under app_init),
     * so the bodies-from-genesis fold is run by the BINARY, not in-process:
     *
     *   ZCL_MINT_ANCHOR_OUT=/path/anchor.snapshot \
     *     build/bin/zclassic23 -datadir=<copy-of-full-history> -mint-anchor
     *
     * That writes a USS artifact whose body SHA3 is what the genesis->anchor
     * fold produced (boot_mint_anchor.c:140-180 already HARD-ASSERTs it == the
     * compiled checkpoint inside the run). Point this test at the artifact:
     *
     *   ZCL_SELF_FOLD_ANCHOR_FIXTURE=/path/anchor.snapshot build/bin/test_parallel
     *
     * uss_open(verify_full_sha3=true, expected_sha3=cp->sha3_hash) RE-HASHES
     * the entire body from the raw records (it does NOT trust the header) and
     * binds it to the compiled checkpoint — i.e. the bodies reproduce the
     * anchor root. We also assert the header height/count == the baked
     * checkpoint. This is a genuine fold-derived-root vs baked-checkpoint
     * comparison, NOT a skeleton. */
    printf("self_folded_anchor: heavy fold artifact re-derives baked root (opt-in)... ");
    {
        const char *artifact = getenv("ZCL_SELF_FOLD_ANCHOR_FIXTURE");
        if (!artifact || !artifact[0] || !strcmp(artifact, "0") ||
            !strcmp(artifact, "1")) {
            printf("SKIP (set ZCL_SELF_FOLD_ANCHOR_FIXTURE=<path to a "
                   "-mint-anchor artifact> to run the genesis->checkpoint "
                   "fold-and-compare)\n");
        } else {
            const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
            ASSERT(cp != NULL);
            struct uss_header hdr;
            memset(&hdr, 0, sizeof(hdr));
            char err[256] = {0};
            /* verify_full_sha3=true re-derives the body SHA3 from the records;
             * expected_sha3=cp->sha3_hash binds the re-derived root to the
             * compiled checkpoint — a forged or stale artifact FAILS here. */
            struct uss_handle *h = uss_open(artifact, /*verify_full_sha3=*/true,
                                            cp->sha3_hash, &hdr, err, sizeof(err));
            if (!h) {
                printf("FAIL\n  uss_open(%s) rejected the artifact: %s\n",
                       artifact, err);
                failures++;
                goto _test_next;
            }
            /* The artifact's own header must also agree with the baked
             * height/count (a fold at a different height is not the anchor). */
            ASSERT(hdr.height == (uint32_t)SFA_CHECKPOINT_HEIGHT);
            ASSERT(hdr.count == cp->utxo_count);
            ASSERT(memcmp(hdr.sha3_hash, cp->sha3_hash, 32) == 0);
            uss_close(h);
            printf("OK (re-derived %llu-UTXO root @ h=%u == baked checkpoint)\n",
                   (unsigned long long)hdr.count, hdr.height);
        }
    }

    goto _done;
_test_next:
    /* An ASSERT failed (it jumped here after failures++). */
    printf("(section aborted)\n");
_done:
    if (failures == 0)
        printf("=== test_self_folded_anchor_heavy: all cases passed ===\n");
    else
        printf("=== test_self_folded_anchor_heavy: %d failure(s) ===\n", failures);
    return failures;
}
