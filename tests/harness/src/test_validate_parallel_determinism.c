/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_validate_parallel_determinism — proves the parallel script + proof
 * verification paths (engine/jobs/src/script_validate_verify.c,
 * proof_validate_verify.c) produce a verdict BYTE-IDENTICAL to the serial
 * reference: for a spread of blocks with valid/invalid inputs and proofs at
 * various positions, script_verify_block()/proof_verify_block() must return the
 * SAME accept/reject, the SAME first-failing index (vin / txid), the same
 * ScriptError / proof-type, and the same reached-item counts, whether run
 * serial or fanned across the worker pool.
 *
 * The script side drives verify_script over trivial OP_TRUE / OP_FALSE prevout
 * scripts (a fake resolver keyed on prevout.n: 0=valid, 1=script_invalid,
 * 2=unresolved), so no ECDSA keys / params are needed. The proof side installs
 * a pure fake tx verifier keyed on tx->lock_time (0=ok, 1=proof_invalid,
 * 2=verifier-returns-false/internal, 3=report-internal), so no Groth16 / Sapling
 * params are needed. Each scenario is asserted parallel==serial AND
 * serial==expected, and repeated to shake out any ordering race. */

#include "test/test_core.h"
#include "coins/undo.h"

#include "chain/chainparams.h"
#include "core/uint256.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/proof_validate_verify.h"
#include "jobs/script_validate_stage.h"
#include "jobs/script_validate_verify.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/script_error.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define VPD_CHECK(name, expr) do { \
    printf("parallel_determinism: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── fixtures ─────────────────────────────────────────────────────────────── */

/* Script fake resolver: prevout.n selects the outcome. */
static bool vpd_prevout(const struct outpoint *po, struct tx_out *out,
                        void *user)
{
    (void)user;
    if (!po || !out)
        return false;
    if (po->n == 2)
        return false;                 /* unresolved */
    tx_out_set_null(out);
    out->value = 100000000;
    script_init(&out->script_pub_key);
    script_push_op(&out->script_pub_key, po->n == 1 ? OP_FALSE : OP_TRUE);
    return true;                      /* n==0 valid, n==1 script_invalid */
}

/* Build one tx with `n_in` inputs (outcomes[i] -> prevout.n). `uniq` makes the
 * txid distinct. `coinbase` builds a single null-prevout input instead. */
static bool vpd_build_tx(struct transaction *tx, int uniq, bool coinbase,
                         const int *outcomes, int n_in, uint32_t lock_time)
{
    transaction_init(tx);
    if (coinbase) {
        if (!transaction_alloc(tx, 1, 1))
            return false;
        outpoint_set_null(&tx->vin[0].prevout);
        script_init(&tx->vin[0].script_sig);
    } else {
        if (!transaction_alloc(tx, (size_t)n_in, 1))
            return false;
        for (int i = 0; i < n_in; i++) {
            memset(tx->vin[i].prevout.hash.data, 0x10 + (uniq & 0x3f),
                   sizeof(tx->vin[i].prevout.hash.data));
            tx->vin[i].prevout.hash.data[1] = (unsigned char)(i & 0xff);
            tx->vin[i].prevout.n = (uint32_t)outcomes[i];
            script_init(&tx->vin[i].script_sig);
        }
    }
    tx->vout[0].value = 1000;
    script_init(&tx->vout[0].script_pub_key);
    script_push_op(&tx->vout[0].script_pub_key, OP_TRUE);
    tx->lock_time = lock_time;
    transaction_compute_hash(tx);
    return true;
}

static void vpd_block_free(struct block *b)
{
    block_free(b);
}

/* ── comparison ───────────────────────────────────────────────────────────── */

/* Verdict fields only (no reason string) — used to check against a hand-computed
 * expectation, since `reason` embeds the runtime txid hex. */
static bool sv_eq_verdict(const struct script_verify_summary *a,
                          const struct script_verify_summary *b)
{
    return a->ok == b->ok && a->internal_error == b->internal_error &&
           a->tx_count == b->tx_count && a->input_count == b->input_count &&
           a->inputs_verified == b->inputs_verified &&
           a->inputs_failed == b->inputs_failed &&
           a->first_failure_vin == b->first_failure_vin &&
           a->first_failure_serror == b->first_failure_serror &&
           uint256_cmp(&a->first_failure_txid, &b->first_failure_txid) == 0;
}

/* Full equality INCLUDING the reason string — the determinism guarantee
 * (parallel must reproduce the serial verdict byte-for-byte, reason included). */
static bool sv_eq(const struct script_verify_summary *a,
                  const struct script_verify_summary *b)
{
    return sv_eq_verdict(a, b) && strcmp(a->reason, b->reason) == 0;
}

static bool ptype_eq(const char *a, const char *b)
{
    if (!a && !b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

static bool pv_eq(const struct proof_verify_summary *a,
                  const struct proof_verify_summary *b)
{
    return a->ok == b->ok && a->internal_error == b->internal_error &&
           a->sapling_spends_total == b->sapling_spends_total &&
           a->sapling_outputs_total == b->sapling_outputs_total &&
           a->sprout_joinsplits_total == b->sprout_joinsplits_total &&
           uint256_cmp(&a->first_failure_txid, &b->first_failure_txid) == 0 &&
           ptype_eq(a->first_failure_proof_type, b->first_failure_proof_type);
}

/* Run every mode N times; return true iff EVERY run matches the serial
 * reference AND the serial result matches the caller's expectation (checked
 * once). `exp` may be NULL to only assert determinism. The parallel entry is
 * driven under BOTH threshold routings — min forced to 0 (always fan the pool)
 * and min forced very high (always fold serially via the sub-threshold path) —
 * so the small-batch serial threshold is proven verdict-neutral in both
 * directions, and the pool path stays exercised even for the tiny fixtures. */
static bool sv_determinism(const struct block *blk, int height,
                           const struct script_verify_summary *exp)
{
    for (int iter = 0; iter < 16; iter++) {
        struct script_verify_summary s, p_pool, p_thr;
        script_verify_block(blk, height, NULL, NULL, vpd_prevout, NULL,
                            false, &s);
        script_verify_set_parallel_min_inputs_for_test(0);      /* always fan */
        script_verify_block(blk, height, NULL, NULL, vpd_prevout, NULL,
                            true, &p_pool);
        script_verify_set_parallel_min_inputs_for_test(1 << 30); /* always serial */
        script_verify_block(blk, height, NULL, NULL, vpd_prevout, NULL,
                            true, &p_thr);
        script_verify_set_parallel_min_inputs_for_test(-1);      /* restore */
        if (!sv_eq(&s, &p_pool) || !sv_eq(&s, &p_thr))
            return false;
        if (exp && iter == 0 && !sv_eq_verdict(&s, exp))
            return false;
    }
    return true;
}

/* Pure fake proof verifier: lock_time selects the outcome; each ok/failing tx
 * reports fixed proof totals so the reduce's accumulation is exercised. */
static bool vpd_verifier(const struct transaction *tx, int height,
                         struct proof_validate_tx_report *r, void *user)
{
    (void)height; (void)user;
    memset(r, 0, sizeof(*r));
    r->ok = true;
    r->sapling_spends_total = 2;
    r->sapling_outputs_total = 1;
    r->sprout_joinsplits_total = 1;
    switch (tx->lock_time) {
    case 1:
        r->ok = false;
        r->first_failure_proof_type = "sapling_spend";
        return true;
    case 2:
        return false;                 /* verifier-returned-false => internal */
    case 3:
        r->ok = false;
        r->internal_error = true;
        r->first_failure_proof_type = "sapling_ctx";
        return true;
    default:
        return true;                  /* lock_time 0 => ok */
    }
}

static bool pv_determinism(const struct block *blk, int height,
                           const struct proof_verify_summary *exp)
{
    for (int iter = 0; iter < 16; iter++) {
        struct proof_verify_summary s, p_pool, p_thr;
        proof_verify_block(blk, height, vpd_verifier, NULL, false,
                           NULL, NULL, NULL, &s);
        proof_verify_set_parallel_min_shielded_for_test(0);       /* always fan */
        proof_verify_block(blk, height, vpd_verifier, NULL, true,
                           NULL, NULL, NULL, &p_pool);
        proof_verify_set_parallel_min_shielded_for_test(1 << 30); /* always serial */
        proof_verify_block(blk, height, vpd_verifier, NULL, true,
                           NULL, NULL, NULL, &p_thr);
        proof_verify_set_parallel_min_shielded_for_test(-1);      /* restore */
        if (!pv_eq(&s, &p_pool) || !pv_eq(&s, &p_thr))
            return false;
        if (exp && iter == 0 && !pv_eq(&s, exp))
            return false;
    }
    return true;
}

/* ── the tests ────────────────────────────────────────────────────────────── */

int test_validate_parallel_determinism(void);
int test_validate_parallel_determinism(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    const int H = 100;

    /* ---- SCRIPT ---- */

    /* S1: all valid (accept), coinbase first + two spending txs of 2 inputs. */
    {
        struct block b; block_init(&b);
        b.num_vtx = 3;
        b.vtx = zcl_calloc(3, sizeof(struct transaction), "vpd");
        int ok2[2] = {0, 0};
        vpd_build_tx(&b.vtx[0], 0, true, NULL, 0, 0);
        vpd_build_tx(&b.vtx[1], 1, false, ok2, 2, 1);
        vpd_build_tx(&b.vtx[2], 2, false, ok2, 2, 2);
        struct script_verify_summary exp;
        script_verify_summary_init(&exp);
        exp.ok = 1; exp.tx_count = 3; exp.input_count = 4;
        exp.inputs_verified = 4; exp.inputs_failed = 0;
        VPD_CHECK("script all-valid accept", sv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* S2: script_invalid at tx2/vin1 (first failure). */
    {
        struct block b; block_init(&b);
        b.num_vtx = 3;
        b.vtx = zcl_calloc(3, sizeof(struct transaction), "vpd");
        int a[2] = {0, 0};
        int bad[2] = {0, 1};        /* vin1 invalid */
        vpd_build_tx(&b.vtx[0], 0, true, NULL, 0, 0);
        vpd_build_tx(&b.vtx[1], 1, false, a, 2, 1);
        vpd_build_tx(&b.vtx[2], 2, false, bad, 2, 2);
        struct script_verify_summary exp;
        script_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 0; exp.tx_count = 3;
        exp.input_count = 4;        /* t1v0,t1v1,t2v0 pass then t2v1 fails */
        exp.inputs_verified = 3; exp.inputs_failed = 1;
        exp.first_failure_txid = b.vtx[2].hash;
        exp.first_failure_vin = 1;
        exp.first_failure_serror = SCRIPT_ERR_EVAL_FALSE;
        VPD_CHECK("script invalid at t2/vin1",
                  sv_determinism(&b, H, &exp) &&
                  b.vtx[2].hash.data[0] != 0);
        vpd_block_free(&b);
    }

    /* S3: script_invalid BEFORE an unresolved in the same tx (invalid wins). */
    {
        struct block b; block_init(&b);
        b.num_vtx = 2;
        b.vtx = zcl_calloc(2, sizeof(struct transaction), "vpd");
        int mix[2] = {1, 2};        /* vin0 invalid, vin1 unresolved */
        vpd_build_tx(&b.vtx[0], 0, true, NULL, 0, 0);
        vpd_build_tx(&b.vtx[1], 1, false, mix, 2, 1);
        struct script_verify_summary exp;
        script_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 0; exp.tx_count = 2;
        exp.input_count = 1; exp.inputs_verified = 0; exp.inputs_failed = 1;
        exp.first_failure_txid = b.vtx[1].hash;
        exp.first_failure_vin = 0;
        exp.first_failure_serror = SCRIPT_ERR_EVAL_FALSE;
        VPD_CHECK("script invalid-before-unresolved", sv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* S4: unresolved BEFORE an invalid (internal_error wins, no verify count). */
    {
        struct block b; block_init(&b);
        b.num_vtx = 2;
        b.vtx = zcl_calloc(2, sizeof(struct transaction), "vpd");
        int mix[2] = {2, 1};        /* vin0 unresolved, vin1 invalid */
        vpd_build_tx(&b.vtx[0], 0, true, NULL, 0, 0);
        vpd_build_tx(&b.vtx[1], 1, false, mix, 2, 1);
        struct script_verify_summary exp;
        script_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 1; exp.tx_count = 2;
        exp.input_count = 0; exp.inputs_verified = 0; exp.inputs_failed = 0;
        exp.first_failure_txid = b.vtx[1].hash;
        exp.first_failure_vin = 0;
        VPD_CHECK("script unresolved-before-invalid", sv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* S5: big block, many inputs, one invalid deep — stresses the pool. */
    {
        /* enum, not `const int`: a const-qualified object is not a constant
         * expression in C, so `int allok[NI]` below would be a VLA. */
        enum { NT = 120, NI = 8 };
        struct block b; block_init(&b);
        b.num_vtx = (size_t)(NT + 1);
        b.vtx = zcl_calloc(b.num_vtx, sizeof(struct transaction), "vpd");
        vpd_build_tx(&b.vtx[0], 0, true, NULL, 0, 0);
        int allok[NI];
        for (int i = 0; i < NI; i++) allok[i] = 0;
        for (int t = 1; t <= NT; t++)
            vpd_build_tx(&b.vtx[t], t, false, allok, NI, (uint32_t)t);
        /* Flip one input deep in tx 90 to invalid. */
        b.vtx[90].vin[5].prevout.n = 1;
        transaction_compute_hash(&b.vtx[90]);
        struct script_verify_summary exp;
        script_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 0;
        exp.tx_count = 91;          /* coinbase + tx1..tx90 */
        /* tx1..tx89 fully verified (89*8) + tx90 vin0..4 (5) = 717, then vin5 fails */
        exp.input_count = 89 * NI + 6;
        exp.inputs_verified = 89 * NI + 5;
        exp.inputs_failed = 1;
        exp.first_failure_txid = b.vtx[90].hash;
        exp.first_failure_vin = 5;
        exp.first_failure_serror = SCRIPT_ERR_EVAL_FALSE;
        VPD_CHECK("script big-block deep-invalid", sv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* ---- PROOF ---- */

    /* P1: all ok — totals accumulate across every tx. */
    {
        struct block b; block_init(&b);
        b.num_vtx = 4;
        b.vtx = zcl_calloc(4, sizeof(struct transaction), "vpd");
        int one[1] = {0};
        for (int t = 0; t < 4; t++)
            vpd_build_tx(&b.vtx[t], t, false, one, 1, 0);  /* lock_time 0 = ok */
        struct proof_verify_summary exp;
        proof_verify_summary_init(&exp);
        exp.ok = 1;
        exp.sapling_spends_total = 8;   /* 2 * 4 */
        exp.sapling_outputs_total = 4;  /* 1 * 4 */
        exp.sprout_joinsplits_total = 4;
        VPD_CHECK("proof all-ok accumulate", pv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* P2: proof_invalid at tx2 (r.ok=false) — totals added up to & incl tx2. */
    {
        struct block b; block_init(&b);
        b.num_vtx = 4;
        b.vtx = zcl_calloc(4, sizeof(struct transaction), "vpd");
        int one[1] = {0};
        vpd_build_tx(&b.vtx[0], 0, false, one, 1, 0);
        vpd_build_tx(&b.vtx[1], 1, false, one, 1, 0);
        vpd_build_tx(&b.vtx[2], 2, false, one, 1, 1);  /* proof_invalid */
        vpd_build_tx(&b.vtx[3], 3, false, one, 1, 0);
        struct proof_verify_summary exp;
        proof_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 0;
        exp.sapling_spends_total = 6;   /* tx0,1,2 */
        exp.sapling_outputs_total = 3;
        exp.sprout_joinsplits_total = 3;
        exp.first_failure_txid = b.vtx[2].hash;
        exp.first_failure_proof_type = "sapling_spend";
        VPD_CHECK("proof invalid at tx2", pv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* P3: verifier-returns-false at tx1 (internal, no totals for tx1). */
    {
        struct block b; block_init(&b);
        b.num_vtx = 3;
        b.vtx = zcl_calloc(3, sizeof(struct transaction), "vpd");
        int one[1] = {0};
        vpd_build_tx(&b.vtx[0], 0, false, one, 1, 0);
        vpd_build_tx(&b.vtx[1], 1, false, one, 1, 2);  /* verifier false */
        vpd_build_tx(&b.vtx[2], 2, false, one, 1, 0);
        struct proof_verify_summary exp;
        proof_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 1;
        exp.sapling_spends_total = 2;   /* only tx0's totals */
        exp.sapling_outputs_total = 1;
        exp.sprout_joinsplits_total = 1;
        exp.first_failure_txid = b.vtx[1].hash;
        exp.first_failure_proof_type = "internal";
        VPD_CHECK("proof verifier-false at tx1", pv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* P4: report-internal at tx1 (r.ok=false, internal_error) — totals added. */
    {
        struct block b; block_init(&b);
        b.num_vtx = 3;
        b.vtx = zcl_calloc(3, sizeof(struct transaction), "vpd");
        int one[1] = {0};
        vpd_build_tx(&b.vtx[0], 0, false, one, 1, 0);
        vpd_build_tx(&b.vtx[1], 1, false, one, 1, 3);  /* report internal */
        vpd_build_tx(&b.vtx[2], 2, false, one, 1, 0);
        struct proof_verify_summary exp;
        proof_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 1;
        exp.sapling_spends_total = 4;   /* tx0 + tx1 */
        exp.sapling_outputs_total = 2;
        exp.sprout_joinsplits_total = 2;
        exp.first_failure_txid = b.vtx[1].hash;
        exp.first_failure_proof_type = "sapling_ctx";
        VPD_CHECK("proof report-internal at tx1", pv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* P5: big block, one invalid deep — stresses the proof pool. */
    {
        const int NT = 200;
        struct block b; block_init(&b);
        b.num_vtx = (size_t)NT;
        b.vtx = zcl_calloc(b.num_vtx, sizeof(struct transaction), "vpd");
        int one[1] = {0};
        for (int t = 0; t < NT; t++)
            vpd_build_tx(&b.vtx[t], t, false, one, 1, 0);
        b.vtx[150].lock_time = 1;   /* proof_invalid deep */
        transaction_compute_hash(&b.vtx[150]);
        struct proof_verify_summary exp;
        proof_verify_summary_init(&exp);
        exp.ok = 0; exp.internal_error = 0;
        exp.sapling_spends_total = 2 * 151;   /* tx0..tx150 */
        exp.sapling_outputs_total = 151;
        exp.sprout_joinsplits_total = 151;
        exp.first_failure_txid = b.vtx[150].hash;
        exp.first_failure_proof_type = "sapling_spend";
        VPD_CHECK("proof big-block deep-invalid", pv_determinism(&b, H, &exp));
        vpd_block_free(&b);
    }

    /* ---- THROUGHPUT / KEEPS-FED ---- */

    /* The per-block worker-pool fan carries a fixed cost (broadcast cv_take to
     * every worker + the cv_done join) that DOMINATES a light block. Measure
     * script-verify throughput over a long run of light blocks (coinbase + one
     * single-input tx — the common ZClassic history shape) under the two
     * routings: the forced-POOL path (min=0) vs the sub-threshold SERIAL path
     * (the default). The serial routing removes the fan overhead, so it must be
     * at least as fast; both must produce the identical verdict. This is the
     * end-to-end lever the tail-stage drive feels when catch-up keeps it fed. */
    {
        struct block b; block_init(&b);
        b.num_vtx = 2;
        b.vtx = zcl_calloc(2, sizeof(struct transaction), "vpd");
        int one[1] = {0};                          /* single valid input */
        vpd_build_tx(&b.vtx[0], 0, true, NULL, 0, 0);
        vpd_build_tx(&b.vtx[1], 1, false, one, 1, 0);

        struct script_verify_summary ref;
        script_verify_block(&b, H, NULL, NULL, vpd_prevout, NULL, false, &ref);

        const int REPS = 20000;
        bool pool_ok = true, ser_ok = true;

        script_verify_set_parallel_min_inputs_for_test(0);   /* force the fan */
        int64_t t0 = platform_time_monotonic_us();
        for (int i = 0; i < REPS; i++) {
            struct script_verify_summary s;
            script_verify_block(&b, H, NULL, NULL, vpd_prevout, NULL, true, &s);
            if (!sv_eq(&s, &ref)) { pool_ok = false; break; }
        }
        int64_t us_pool = platform_time_monotonic_us() - t0;

        script_verify_set_parallel_min_inputs_for_test(-1);  /* default => serial */
        int64_t t1 = platform_time_monotonic_us();
        for (int i = 0; i < REPS; i++) {
            struct script_verify_summary s;
            script_verify_block(&b, H, NULL, NULL, vpd_prevout, NULL, true, &s);
            if (!sv_eq(&s, &ref)) { ser_ok = false; break; }
        }
        int64_t us_ser = platform_time_monotonic_us() - t1;

        double pool_bps = us_pool > 0 ? (double)REPS * 1e6 / (double)us_pool : 0.0;
        double ser_bps  = us_ser  > 0 ? (double)REPS * 1e6 / (double)us_ser  : 0.0;
        printf("parallel_determinism: light-block script throughput: "
               "pool=%.0f blk/s, serial-threshold=%.0f blk/s (%.2fx)\n",
               pool_bps, ser_bps, pool_bps > 0 ? ser_bps / pool_bps : 0.0);

        VPD_CHECK("light-block routing verdict-identical", pool_ok && ser_ok);
        /* The serial routing eliminates the fan overhead, so it must not be
         * materially slower. Loose bound (1.5x + 5ms slack) keeps the gate
         * stable under scheduler noise while still catching a routing that
         * accidentally kept fanning every light block. */
        VPD_CHECK("light-block serial-threshold not slower than pool",
                  us_ser <= us_pool * 3 / 2 + 5000);
        vpd_block_free(&b);
    }

    /* Join the lazily-started pools so no worker outlives the test. */
    script_verify_pool_shutdown();
    proof_verify_pool_shutdown();

    if (failures)
        printf("test_validate_parallel_determinism: %d FAILURE(S)\n", failures);
    return failures;
}
