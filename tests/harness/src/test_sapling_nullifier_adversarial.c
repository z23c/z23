/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial coverage of the reducer's shielded double-spend gate (C-3):
 * the note-nullifier equivalent of transparent double-spend. Every scenario
 * drives the REAL consensus predicate
 *
 *     utxo_apply_check_and_insert_nullifiers()   (engine/jobs/src/utxo_apply_nullifiers.c)
 *
 * — the exact function utxo_apply_stage runs inside its BEGIN-IMMEDIATE stage
 * transaction to port zclassicd's HaveShieldedRequirements nullifier check
 * (main.cpp:2627) + the per-tx SetNullifiers order (UpdateCoins). No predicate
 * is modified; this file PINS existing behavior against adversarial inputs.
 *
 * WHY THIS FILE EXISTS (the gaps around the existing coverage):
 *   - test_simnet_sapling_shielded_send.c drives one REAL Sapling spend and
 *     replays the SAME block object once (durable-set hit). It never covers
 *     TWO DISTINCT txs in ONE block sharing a nullifier (the intra-block
 *     earlier-tx accumulator, nf_index_seen), the Sprout/JoinSplit pool, the
 *     legal cross-pool byte-reuse ACCEPT control, the exact reject-reason
 *     strings, the revealing-height-preserved property, or the two-pass
 *     "a rejected block leaves NO partial rows" atomicity.
 *   - test_nullifier_backfill_service.c uses the same predicate only to POPULATE
 *     the durable set (populate-only backfill), never to assert the reject.
 *   - The Sapling anchor / note-commitment-root membership predicate
 *     (coins_view_cache_check_shielded_requirements) is already exhaustively
 *     covered by test_parity_lockin_anchor_membership.c (unknown anchor →
 *     MISSING_ANCHOR, known anchor / empty root → OK, history-incomplete), so
 *     this file deliberately does NOT re-test it — see the file-level scope
 *     note near test_sapling_nullifier_adversarial() below.
 *
 * These scenarios are params-FREE: the nullifier gate reads only the 32-byte
 * nullifier of each Sapling spend / Sprout JoinSplit input, never a Groth16
 * proof, so no ~/.zcash-params is required and every outcome is deterministic
 * (fixed synthetic nullifier bytes, in-order block construction). Each scenario
 * gets a FRESH :memory: nullifier_kv db so no durable-set state leaks between
 * them; the group is designed to be re-run byte-identically (run --only twice).
 *
 * REAL PREDICATE each assertion rides on (see nf_check_one / the two passes in
 * utxo_apply_nullifiers.c):
 *   - intra-block reject   → nf_index_seen (earlier-tx accumulator of THIS block)
 *   - inter-block reject   → nullifier_kv_get found in the durable set
 *   - reject reason        → summary.status="shielded_double_spend",
 *                            summary.failure_kind=
 *                            "bad-txns-joinsplit-requirements-not-met"
 *   - pool separation      → PRIMARY KEY(nf,pool): same 32 bytes legal once per pool
 *   - two-pass atomicity   → pass-2 inserts only when the whole block is clean
 */

#include "test/test_core.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "sapling/constants.h"   /* ZC_NUM_JS_INPUTS */
#include "util/safe_alloc.h"

#include "storage/nullifier_kv.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "jobs/utxo_apply_delta.h"   /* struct delta_summary */

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NA_CHECK(name, expr) do {                    \
    printf("  %s... ", (name));                       \
    if (expr) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

/* Deterministic 32-byte nullifier from (tag, mark) — distinct pairs give
 * distinct bytes; identical pairs give byte-identical nullifiers (that is the
 * whole point of a double-spend fixture). */
static void na_nf(uint8_t out[32], uint8_t tag, uint8_t mark)
{
    memset(out, 0, 32);
    out[0] = tag;
    out[1] = mark;
    out[31] = 0xC3;   /* Sapling-nullifier-adversarial tag */
}

/* Deterministic distinct txid per (height, salt) so two txs in one block are
 * genuinely different transactions (the failure_detail carries the txid). */
static void na_txid(struct uint256 *out, int height, int salt)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x40 + height);
    out->data[1] = (uint8_t)salt;
    out->data[31] = 0x9A;
}

/* Attach one Sapling shielded spend carrying nullifier (tag,mark) to a tx. */
static bool na_add_sapling_spend(struct transaction *tx, uint8_t tag, uint8_t mark)
{
    tx->v_shielded_spend =
        zcl_calloc(1, sizeof(struct spend_description), "na_sapling_spend");
    if (!tx->v_shielded_spend)
        return false;
    tx->num_shielded_spend = 1;
    na_nf(tx->v_shielded_spend[0].nullifier.data, tag, mark);
    return true;
}

/* Attach one Sprout JoinSplit carrying two input nullifiers to a tx. */
static bool na_add_joinsplit(struct transaction *tx,
                             uint8_t tag0, uint8_t tag1, uint8_t mark)
{
    tx->v_joinsplit =
        zcl_calloc(1, sizeof(struct js_description), "na_sprout_js");
    if (!tx->v_joinsplit)
        return false;
    tx->num_joinsplit = 1;
    na_nf(tx->v_joinsplit[0].nullifiers[0].data, tag0, mark);
    na_nf(tx->v_joinsplit[0].nullifiers[1].data, tag1, mark);
    return true;
}

/* Allocate a block with `ntx` zero-initialized transactions, each stamped with
 * a distinct txid (salt = 0x10+i). Caller fills shielded fields then frees via
 * block_free. */
static bool na_make_block(struct block *b, int height, size_t ntx)
{
    block_init(b);
    b->header.nVersion = 4;
    b->num_vtx = ntx;
    b->vtx = zcl_calloc(ntx, sizeof(struct transaction), "na_vtx");
    if (!b->vtx) {
        b->num_vtx = 0;
        return false;
    }
    for (size_t i = 0; i < ntx; i++) {
        transaction_init(&b->vtx[i]);
        na_txid(&b->vtx[i].hash, height, (int)(0x10 + i));
    }
    return true;
}

/* Run the REAL gate on one block at `height` against `db`. Returns the
 * predicate's own return value (false only on a STORE error); reports the
 * consensus verdict via *accepted (summary.ok) and hands back the summary so
 * the caller can assert the exact reject reason. Called directly (autocommit),
 * exactly as test_simnet_sapling_shielded_send drives it — a clean block's
 * pass-2 inserts persist for the next block (inter-block scenarios). */
static bool na_apply(sqlite3 *db, const struct block *blk, int height,
                     bool *accepted, struct delta_summary *summary_out)
{
    struct delta_summary summary;
    memset(&summary, 0, sizeof(summary));
    summary.ok = true;
    summary.status = "ok";
    bool rc = utxo_apply_check_and_insert_nullifiers(db, blk, height, &summary);
    if (accepted)
        *accepted = summary.ok;
    if (summary_out)
        *summary_out = summary;
    return rc;
}

static int64_t na_row_count(sqlite3 *db)
{
    /* raw-sql-ok: test-local :memory: db, read-only row count. */
    sqlite3_stmt *st = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM nullifiers", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static sqlite3 *na_fresh_db(int *failures)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    printf("  open fresh :memory: nullifier db... ");
    if (rc == SQLITE_OK && db != NULL)
        printf("OK\n");
    else {
        printf("FAIL\n");
        (*failures)++;
    }
    printf("  nullifier_kv schema... ");
    if (db && nullifier_kv_ensure_schema(db))
        printf("OK\n");
    else {
        printf("FAIL\n");
        (*failures)++;
    }
    return db;
}

/* True iff the reject reason is EXACTLY the shielded double-spend gate's — not
 * an unrelated structural failure. This is the "teeth" assertion: the block
 * must be rejected ON the nullifier check, with zclassicd's exact strings. */
static bool na_reject_is_double_spend(const struct delta_summary *s)
{
    return !s->ok &&
           s->status && strcmp(s->status, "shielded_double_spend") == 0 &&
           s->failure_kind &&
           strcmp(s->failure_kind,
                  "bad-txns-joinsplit-requirements-not-met") == 0;
}

/* ── Scenario A — intra-block Sapling double-spend (earlier-tx accumulator) ──
 * TWO DISTINCT txs in ONE block each spend the SAME Sapling nullifier. Rides on
 * nf_index_seen (utxo_apply_nullifiers.c:153): tx[0]'s nullifier is folded into
 * the per-block accumulator after tx[0], so tx[1]'s identical nullifier is a hit
 * even though the durable set is empty. The block must be rejected and — by the
 * two-pass design — leave NO rows in the durable set. */
static void scenario_intra_block_sapling(int *fp)
{
    int failures = 0;
    printf("  -- Scenario A: intra-block Sapling double-spend (2 distinct txs) --\n");
    sqlite3 *db = na_fresh_db(&failures);

    struct block blk;
    if (db && na_make_block(&blk, 500, 2)) {
        NA_CHECK("tx[0] Sapling spend nf=(0xA1,0x51)",
                 na_add_sapling_spend(&blk.vtx[0], 0xA1, 0x51));
        NA_CHECK("tx[1] Sapling spend SAME nf=(0xA1,0x51)",
                 na_add_sapling_spend(&blk.vtx[1], 0xA1, 0x51));
        NA_CHECK("the two txs are genuinely distinct (different txid)",
                 memcmp(blk.vtx[0].hash.data, blk.vtx[1].hash.data, 32) != 0);

        bool accepted = true;
        struct delta_summary sum;
        bool rc = na_apply(db, &blk, 500, &accepted, &sum);
        NA_CHECK("gate returns true (consensus reject, not store error)", rc);
        NA_CHECK("intra-block double-spend REJECTED (tip must not advance)",
                 !accepted);
        NA_CHECK("reject reason is the shielded double-spend gate (teeth)",
                 na_reject_is_double_spend(&sum));
        NA_CHECK("failure_detail carries the offending txid (tx[1])",
                 memcmp(sum.failure_detail, blk.vtx[1].hash.data, 32) == 0);

        /* Two-pass atomicity: a rejected block writes NO nullifier rows. */
        bool found = false;
        uint8_t nf[32]; na_nf(nf, 0xA1, 0x51);
        NA_CHECK("rejected block left NO durable row (two-pass atomicity)",
                 db && nullifier_kv_get(db, nf, NULLIFIER_POOL_SAPLING, &found,
                                        NULL) && !found);
        NA_CHECK("durable set is completely empty after reject",
                 na_row_count(db) == 0);
        block_free(&blk);
    } else {
        NA_CHECK("scenario A setup", false);
    }
    if (db) sqlite3_close(db);
    *fp += failures;
}

/* ── Scenario B — inter-block Sapling double-spend (distinct blocks/txs) ──
 * Block 1 (height 600) reveals a Sapling nullifier and is ACCEPTED (durable
 * insert). A LATER, genuinely different block/tx (height 605) respends the same
 * nullifier and must be REJECTED. Rides on nullifier_kv_get finding the row in
 * the durable set (utxo_apply_nullifiers.c:146). Asserts the exact reject reason
 * AND that the original revealing height is PRESERVED (a rejected respend never
 * overwrites the durable row). */
static void scenario_inter_block_sapling(int *fp)
{
    int failures = 0;
    printf("  -- Scenario B: inter-block Sapling double-spend (distinct blocks) --\n");
    sqlite3 *db = na_fresh_db(&failures);

    struct block blk1, blk2;
    bool have1 = db && na_make_block(&blk1, 600, 1);
    bool have2 = db && na_make_block(&blk2, 605, 1);
    if (have1 && have2) {
        NA_CHECK("block1 tx Sapling spend nf=(0xB2,0x60)",
                 na_add_sapling_spend(&blk1.vtx[0], 0xB2, 0x60));
        NA_CHECK("block2 tx (distinct txid) respends nf=(0xB2,0x60)",
                 na_add_sapling_spend(&blk2.vtx[0], 0xB2, 0x60));
        NA_CHECK("block1/block2 txs are distinct transactions",
                 memcmp(blk1.vtx[0].hash.data, blk2.vtx[0].hash.data, 32) != 0);

        bool acc1 = false;
        struct delta_summary s1;
        NA_CHECK("block1 applies (gate returns true)",
                 na_apply(db, &blk1, 600, &acc1, &s1));
        NA_CHECK("block1 ACCEPTED (first reveal is legal)", acc1);

        uint8_t nf[32]; na_nf(nf, 0xB2, 0x60);
        bool found = false; int64_t h = -1;
        NA_CHECK("nullifier durable at revealing height 600",
                 db && nullifier_kv_get(db, nf, NULLIFIER_POOL_SAPLING, &found,
                                        &h) && found && h == 600);

        bool acc2 = true;
        struct delta_summary s2;
        NA_CHECK("block2 applies (gate returns true, consensus reject)",
                 na_apply(db, &blk2, 605, &acc2, &s2));
        NA_CHECK("inter-block respend REJECTED (tip must not advance)", !acc2);
        NA_CHECK("reject reason is the shielded double-spend gate (teeth)",
                 na_reject_is_double_spend(&s2));

        bool found2 = false; int64_t h2 = -1;
        NA_CHECK("revealing height PRESERVED at 600 (reject never overwrote)",
                 db && nullifier_kv_get(db, nf, NULLIFIER_POOL_SAPLING, &found2,
                                        &h2) && found2 && h2 == 600);
        NA_CHECK("durable set still holds exactly the one original row",
                 na_row_count(db) == 1);
    } else {
        NA_CHECK("scenario B setup", false);
    }
    if (have1) block_free(&blk1);
    if (have2) block_free(&blk2);
    if (db) sqlite3_close(db);
    *fp += failures;
}

/* ── Scenario C — Sprout (JoinSplit) double-spend, both intra- and inter-block ──
 * The existing sim test exercises only the Sapling pool. Here two distinct
 * JoinSplit txs share a Sprout input nullifier (intra-block), and a later block
 * respends a first-block Sprout nullifier (inter-block). Rides on the SAME gate,
 * NULLIFIER_POOL_SPROUT branch (utxo_apply_nullifiers.c:208-222, the
 * ZC_NUM_JS_INPUTS loop). */
static void scenario_sprout_double_spend(int *fp)
{
    int failures = 0;
    printf("  -- Scenario C: Sprout JoinSplit double-spend (intra + inter) --\n");

    /* C1: intra-block — two distinct JoinSplit txs share input nullifier. */
    {
        sqlite3 *db = na_fresh_db(&failures);
        struct block blk;
        if (db && na_make_block(&blk, 700, 2)) {
            /* tx[0] JS inputs (0xC1,0xC2); tx[1] JS inputs (0xC3,0xC1) —
             * the 0xC1 input is shared → intra-block Sprout double-spend. */
            NA_CHECK("tx[0] JoinSplit inputs (0xC1,0xC2)",
                     na_add_joinsplit(&blk.vtx[0], 0xC1, 0xC2, 0x70));
            NA_CHECK("tx[1] JoinSplit reuses input 0xC1",
                     na_add_joinsplit(&blk.vtx[1], 0xC3, 0xC1, 0x70));
            bool accepted = true;
            struct delta_summary sum;
            NA_CHECK("gate returns true", na_apply(db, &blk, 700, &accepted, &sum));
            NA_CHECK("intra-block Sprout double-spend REJECTED", !accepted);
            NA_CHECK("reject reason is the shielded double-spend gate",
                     na_reject_is_double_spend(&sum));
            NA_CHECK("rejected block left NO Sprout rows (two-pass atomicity)",
                     na_row_count(db) == 0);
            block_free(&blk);
        } else {
            NA_CHECK("scenario C1 setup", false);
        }
        if (db) sqlite3_close(db);
    }

    /* C2: inter-block — block1 reveals a Sprout nullifier, block2 respends it. */
    {
        sqlite3 *db = na_fresh_db(&failures);
        struct block b1, b2;
        bool h1 = db && na_make_block(&b1, 710, 1);
        bool h2 = db && na_make_block(&b2, 712, 1);
        if (h1 && h2) {
            NA_CHECK("block1 JoinSplit inputs (0xD1,0xD2)",
                     na_add_joinsplit(&b1.vtx[0], 0xD1, 0xD2, 0x71));
            /* block2 respends 0xD1 (paired with a fresh 0xD9). */
            NA_CHECK("block2 respends Sprout input 0xD1",
                     na_add_joinsplit(&b2.vtx[0], 0xD1, 0xD9, 0x71));
            bool acc1 = false;
            NA_CHECK("block1 applies", na_apply(db, &b1, 710, &acc1, NULL));
            NA_CHECK("block1 ACCEPTED", acc1);
            NA_CHECK("both block1 Sprout nullifiers durable",
                     na_row_count(db) == ZC_NUM_JS_INPUTS);
            bool acc2 = true;
            struct delta_summary s2;
            NA_CHECK("block2 applies (consensus reject)",
                     na_apply(db, &b2, 712, &acc2, &s2));
            NA_CHECK("inter-block Sprout respend REJECTED", !acc2);
            NA_CHECK("reject reason is the shielded double-spend gate",
                     na_reject_is_double_spend(&s2));
            NA_CHECK("durable set unchanged after reject (still 2 rows)",
                     na_row_count(db) == ZC_NUM_JS_INPUTS);
        } else {
            NA_CHECK("scenario C2 setup", false);
        }
        if (h1) block_free(&b1);
        if (h2) block_free(&b2);
        if (db) sqlite3_close(db);
    }
    *fp += failures;
}

/* ── Scenario D — ACCEPT controls (proves the rejects have teeth) ──
 * D1: a clean block with DISTINCT nullifiers is ACCEPTED and all rows inserted
 *     (the negative rejects are not rejecting for some unrelated reason).
 * D2: the SAME 32 bytes as a Sprout AND a Sapling nullifier in ONE block is
 *     ACCEPTED — legal cross-pool byte reuse. zclassicd keeps DISTINCT per-pool
 *     nullifier maps (coins.cpp:166-180); the durable set's PRIMARY KEY(nf,pool)
 *     preserves that. This is the sharpest teeth: byte-identical nullifiers that
 *     the double-spend gate must NOT confuse across pools. */
static void scenario_accept_controls(int *fp)
{
    int failures = 0;
    printf("  -- Scenario D: ACCEPT controls (distinct nfs + cross-pool reuse) --\n");

    /* D1: clean block, distinct nullifiers → accept + all rows present. */
    {
        sqlite3 *db = na_fresh_db(&failures);
        struct block blk;
        if (db && na_make_block(&blk, 800, 2)) {
            NA_CHECK("tx[0] Sapling nf=(0xE1,0x80)",
                     na_add_sapling_spend(&blk.vtx[0], 0xE1, 0x80));
            NA_CHECK("tx[1] Sapling nf=(0xE2,0x80) (distinct)",
                     na_add_sapling_spend(&blk.vtx[1], 0xE2, 0x80));
            bool accepted = false;
            struct delta_summary sum;
            NA_CHECK("gate returns true", na_apply(db, &blk, 800, &accepted, &sum));
            NA_CHECK("clean block ACCEPTED (control)", accepted && sum.ok);
            NA_CHECK("both distinct nullifiers inserted",
                     na_row_count(db) == 2);
            block_free(&blk);
        } else {
            NA_CHECK("scenario D1 setup", false);
        }
        if (db) sqlite3_close(db);
    }

    /* D2: same 32 bytes as a Sprout AND a Sapling nullifier → legal, accepted. */
    {
        sqlite3 *db = na_fresh_db(&failures);
        struct block blk;
        if (db && na_make_block(&blk, 810, 2)) {
            /* tx[0] Sapling spend with nf bytes (0xF0,0x81). */
            NA_CHECK("tx[0] Sapling nf=(0xF0,0x81)",
                     na_add_sapling_spend(&blk.vtx[0], 0xF0, 0x81));
            /* tx[1] JoinSplit whose FIRST Sprout input reuses the SAME bytes
             * (0xF0,0x81); the second input is unrelated (0xF7,0x81). */
            NA_CHECK("tx[1] Sprout input reuses SAME 32 bytes (0xF0,0x81)",
                     na_add_joinsplit(&blk.vtx[1], 0xF0, 0xF7, 0x81));

            /* Confirm the two nullifiers are byte-identical (the fixture's
             * whole point): the gate must NOT treat this as a double-spend. */
            uint8_t sapling_nf[32], sprout_nf[32];
            na_nf(sapling_nf, 0xF0, 0x81);
            memcpy(sprout_nf, blk.vtx[1].v_joinsplit[0].nullifiers[0].data, 32);
            NA_CHECK("Sapling and Sprout nullifier bytes are identical",
                     memcmp(sapling_nf, sprout_nf, 32) == 0);

            bool accepted = false;
            struct delta_summary sum;
            NA_CHECK("gate returns true", na_apply(db, &blk, 810, &accepted, &sum));
            NA_CHECK("cross-pool byte reuse ACCEPTED (separate namespaces)",
                     accepted && sum.ok);
            bool fs = false, fz = false;
            NA_CHECK("same bytes present in Sapling pool",
                     db && nullifier_kv_get(db, sapling_nf,
                             NULLIFIER_POOL_SAPLING, &fs, NULL) && fs);
            NA_CHECK("same bytes present in Sprout pool",
                     db && nullifier_kv_get(db, sprout_nf,
                             NULLIFIER_POOL_SPROUT, &fz, NULL) && fz);
            /* 1 Sapling + 2 Sprout (the JoinSplit reveals both inputs). */
            NA_CHECK("three rows: 1 Sapling + 2 Sprout",
                     na_row_count(db) == 1 + ZC_NUM_JS_INPUTS);
            block_free(&blk);
        } else {
            NA_CHECK("scenario D2 setup", false);
        }
        if (db) sqlite3_close(db);
    }
    *fp += failures;
}

int test_sapling_nullifier_adversarial(void);
int test_sapling_nullifier_adversarial(void)
{
    printf("\n=== Sapling nullifier adversarial (shielded double-spend gate) ===\n");
    int failures = 0;

    /* SCOPE: this file exercises the DURABLE-SET double-spend gate
     * (utxo_apply_check_and_insert_nullifiers). The ORTHOGONAL Sapling anchor /
     * note-commitment-root membership predicate
     * (coins_view_cache_check_shielded_requirements: unknown anchor →
     * MISSING_ANCHOR, known/empty anchor → OK) is already covered end-to-end by
     * test_parity_lockin_anchor_membership.c and is deliberately NOT duplicated
     * here — re-testing it with a broken spend prover would reject for the
     * prover reason, not the anchor reason (no teeth). See this file's header. */

    scenario_intra_block_sapling(&failures);
    scenario_inter_block_sapling(&failures);
    scenario_sprout_double_spend(&failures);
    scenario_accept_controls(&failures);

    printf("Sapling nullifier adversarial: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
