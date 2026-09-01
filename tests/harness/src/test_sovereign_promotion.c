/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for the sovereign-promotion control plane
 * (engine/services/src/sovereign_promotion_service.c): the pure seam verdict, the
 * assisted-tier detector, the duty-cycle gate, and the apply step that flips a
 * matched seam to SOVEREIGN or pages the operator on a mismatch. The isolated
 * re-derivation driver is out of scope (it is the deferred integration); these
 * tests drive the decision + flip logic with a synthetic seam. */

#include "test/test_core.h"
#include "core/uint256.h"

#include "config/boot.h"
#include "config/consensus_state_snapshot_install.h"
#include "services/sovereign_promotion_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SP_CHECK(name, expr) do {                                            \
    if (expr) { printf("  sovereign_promotion: %s... OK\n", (name)); }        \
    else { printf("  sovereign_promotion: %s... FAIL\n", (name)); failures++; }\
} while (0)

/* Build a borrowed RELEASE_ASSISTED fixture: 2 coins, migration-complete marker
 * stamped, self_folded ABSENT, applied=height+1, and an assisted seam recorded
 * carrying the durable coins commitment plus caller-chosen anchor/nullifier
 * digests. Fills *seam and *count. Returns the live db handle. */
static sqlite3 *sp_open_assisted(const char *tag, char *dir, size_t dir_cap,
                                 int32_t height,
                                 struct sovereign_promotion_seam *seam,
                                 uint64_t *count)
{
    test_make_tmpdir(dir, dir_cap, tag, "main");
    if (!progress_store_open(dir))
        return NULL;
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return NULL;

    struct uint256 t; uint256_set_null(&t);
    t.data[0] = 0xC0; t.data[1] = 0xDE; t.data[31] = 0x42;
    const unsigned char sc[3] = {0x51, 0x52, 0x53};
    if (!coins_kv_add(db, t.data, 0, 1000, height, true, sc, sizeof(sc)) ||
        !coins_kv_add(db, t.data, 1, 2000, height, true, sc, sizeof(sc)))
        return NULL;

    memset(seam, 0, sizeof(*seam));
    seam->height = height;
    if (coins_kv_commitment(db, seam->utxo_root) != 0)
        return NULL;
    int64_t n = coins_kv_count(db);
    if (n < 0)
        return NULL;
    *count = (uint64_t)n;
    for (int i = 0; i < 32; i++) {
        seam->anchor_digest[i] = (uint8_t)(0x20 + i);
        seam->nullifier_digest[i] = (uint8_t)(0x40 + i);
    }

    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, height + 1)
              && consensus_state_install_record_assisted_seam(
                     db, height, seam->utxo_root, seam->anchor_digest,
                     seam->nullifier_digest)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    if (!ok)
        return NULL;
    /* Operational tier marker; self_folded intentionally NOT stamped. */
    if (!coins_kv_mark_migration_complete(db))
        return NULL;
    return db;
}

int test_sovereign_promotion(void);
int test_sovereign_promotion(void)
{
    printf("\n=== sovereign_promotion control-plane tests ===\n");
    int failures = 0;
    const int32_t H = 250;

    /* ── Pure verdict ─────────────────────────────────────────────────────── */
    {
        struct sovereign_promotion_seam s;
        memset(&s, 0, sizeof(s));
        s.height = H;
        for (int i = 0; i < 32; i++) {
            s.utxo_root[i] = (uint8_t)(1 + i);
            s.anchor_digest[i] = (uint8_t)(65 + i);
            s.nullifier_digest[i] = (uint8_t)(129 + i);
        }
        struct sovereign_promotion_derived d;
        memset(&d, 0, sizeof(d));
        d.height = s.height;
        d.utxo_count = 5;
        memcpy(d.utxo_root, s.utxo_root, 32);
        memcpy(d.anchor_digest, s.anchor_digest, 32);
        memcpy(d.nullifier_digest, s.nullifier_digest, 32);
        SP_CHECK("evaluate: exact match -> MATCH",
                 sovereign_promotion_evaluate(&d, &s) ==
                     SOVEREIGN_PROMOTION_MATCH);
        struct sovereign_promotion_derived bad;
        bad = d; bad.height ^= 1;
        SP_CHECK("evaluate: height diff -> MISMATCH",
                 sovereign_promotion_evaluate(&bad, &s) ==
                     SOVEREIGN_PROMOTION_MISMATCH);
        bad = d; bad.utxo_root[0] ^= 0xff;
        SP_CHECK("evaluate: utxo_root diff -> MISMATCH",
                 sovereign_promotion_evaluate(&bad, &s) ==
                     SOVEREIGN_PROMOTION_MISMATCH);
        bad = d; bad.anchor_digest[0] ^= 0xff;
        SP_CHECK("evaluate: anchor_digest diff -> MISMATCH",
                 sovereign_promotion_evaluate(&bad, &s) ==
                     SOVEREIGN_PROMOTION_MISMATCH);
        bad = d; bad.nullifier_digest[0] ^= 0xff;
        SP_CHECK("evaluate: nullifier_digest diff -> MISMATCH",
                 sovereign_promotion_evaluate(&bad, &s) ==
                     SOVEREIGN_PROMOTION_MISMATCH);
        SP_CHECK("evaluate: null -> MISMATCH",
                 sovereign_promotion_evaluate(NULL, &s) ==
                     SOVEREIGN_PROMOTION_MISMATCH);
    }

    /* ── Duty cycle ───────────────────────────────────────────────────────── */
    {
        unsetenv("ZCL_PROMOTION_DUTY_PCT"); /* default 25% */
        SP_CHECK("duty: default admits tick 0", sovereign_promotion_duty_admits(0));
        SP_CHECK("duty: default admits tick 24",
                 sovereign_promotion_duty_admits(24));
        SP_CHECK("duty: default denies tick 25",
                 !sovereign_promotion_duty_admits(25));
        SP_CHECK("duty: default denies tick 99",
                 !sovereign_promotion_duty_admits(99));
        setenv("ZCL_PROMOTION_DUTY_PCT", "100", 1);
        SP_CHECK("duty: 100% admits every tick",
                 sovereign_promotion_duty_admits(25) &&
                 sovereign_promotion_duty_admits(99));
        setenv("ZCL_PROMOTION_DUTY_PCT", "1", 1);
        SP_CHECK("duty: 1% admits only tick%100==0",
                 sovereign_promotion_duty_admits(0) &&
                 !sovereign_promotion_duty_admits(1));
        unsetenv("ZCL_PROMOTION_DUTY_PCT");
    }

    /* ── Tier detection + MATCH flip to SOVEREIGN ─────────────────────────── */
    {
        char dir[256];
        struct sovereign_promotion_seam seam;
        uint64_t count = 0;
        sqlite3 *db = sp_open_assisted("sp_match", dir, sizeof(dir), H, &seam,
                                       &count);
        SP_CHECK("match: assisted fixture built", db != NULL);
        if (db) {
            struct sovereign_promotion_seam got;
            SP_CHECK("match: node is detected as assisted tier",
                     sovereign_promotion_tier_is_assisted(db, &got) &&
                     got.height == H &&
                     memcmp(got.utxo_root, seam.utxo_root, 32) == 0);
            SP_CHECK("match: not yet self-folded (borrowed)",
                     !coins_kv_contains_refold_marker(db));

            struct sovereign_promotion_derived derived;
            memset(&derived, 0, sizeof(derived));
            derived.height = H;
            derived.utxo_count = count;
            memcpy(derived.utxo_root, seam.utxo_root, 32);
            memcpy(derived.anchor_digest, seam.anchor_digest, 32);
            memcpy(derived.nullifier_digest, seam.nullifier_digest, 32);
            SP_CHECK("match: apply_verdict(MATCH) flips to SOVEREIGN",
                     sovereign_promotion_apply_verdict(
                         db, SOVEREIGN_PROMOTION_MATCH, &seam, &derived));
            SP_CHECK("match: self_folded (sovereign) marker now stamped",
                     coins_kv_contains_refold_marker(db));
            SP_CHECK("match: tier no longer assisted (now sovereign)",
                     !sovereign_promotion_tier_is_assisted(db, NULL));
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── MISMATCH pages the operator and NEVER promotes ───────────────────── */
    {
        char dir[256];
        struct sovereign_promotion_seam seam;
        uint64_t count = 0;
        sqlite3 *db = sp_open_assisted("sp_mismatch", dir, sizeof(dir), H, &seam,
                                       &count);
        SP_CHECK("mismatch: assisted fixture built", db != NULL);
        if (db) {
            blocker_clear(SOVEREIGN_PROMOTION_MISMATCH_BLOCKER_ID);
            struct sovereign_promotion_derived derived;
            memset(&derived, 0, sizeof(derived));
            derived.height = H;
            derived.utxo_count = count;
            memcpy(derived.utxo_root, seam.utxo_root, 32);
            derived.utxo_root[0] ^= 0xff; /* independent re-fold disagrees */
            memcpy(derived.anchor_digest, seam.anchor_digest, 32);
            memcpy(derived.nullifier_digest, seam.nullifier_digest, 32);
            SP_CHECK("mismatch: apply_verdict(MISMATCH) does NOT promote",
                     !sovereign_promotion_apply_verdict(
                         db, SOVEREIGN_PROMOTION_MISMATCH, &seam, &derived));
            SP_CHECK("mismatch: permanent named blocker raised",
                     blocker_exists(SOVEREIGN_PROMOTION_MISMATCH_BLOCKER_ID));
            SP_CHECK("mismatch: self_folded still ABSENT (kept serving borrowed)",
                     !coins_kv_contains_refold_marker(db));
            SP_CHECK("mismatch: still assisted tier (never self-promoted)",
                     sovereign_promotion_tier_is_assisted(db, NULL));
            blocker_clear(SOVEREIGN_PROMOTION_MISMATCH_BLOCKER_ID);
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    return failures;
}
