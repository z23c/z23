/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate_verify — implementation. See jobs/proof_validate_verify.h.
 *
 * The built-in real-proof verifier (default_verify_tx + pv_sapling_set) plus a
 * serial reference sweep and a pool-parallel sweep that reduces per-tx results
 * back in original order. Serial and parallel are verdict-identical by
 * construction and pinned by test_validate_parallel_determinism. */

#include "jobs/proof_validate_verify.h"
#include "validate_work_pool.h"

#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "primitives/transaction.h"
#include "sapling/bn254.h"
#include "sapling/bls12_381.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/sprout.h"
#include "sapling/params_init.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/sighash.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void tx_report_init(struct proof_validate_tx_report *r)
{
    memset(r, 0, sizeof(*r));
    r->ok = true;
}

static bool tx_has_shielded_proofs(const struct transaction *tx)
{
    return tx && (tx->num_joinsplit > 0 ||
                  tx->num_shielded_spend > 0 ||
                  tx->num_shielded_output > 0);
}

bool proof_verify_block_has_shielded_proofs(const struct block *blk)
{
    if (!blk)
        return false;
    for (size_t i = 0; i < blk->num_vtx; i++) {
        if (tx_has_shielded_proofs(&blk->vtx[i]))
            return true;
    }
    return false;
}

/* Verify one homogeneous Sapling proof set (all spends OR all outputs) with
 * batched Groth16 + a per-proof fallback for attribution. Verdict-identical to
 * the per-description check_* sweep; the accept path — every real block — is
 * just faster. On reject/alloc-failure it sets *out and returns false. */
static bool pv_sapling_set(void *sctx, const struct transaction *tx,
                           const struct uint256 *sighash, bool is_spend,
                           struct proof_validate_tx_report *out)
{
    size_t n = is_spend ? tx->num_shielded_spend : tx->num_shielded_output;
    if (n == 0)
        return true;
    size_t ni = is_spend ? 7 : 5;
    struct groth16_proof *p = zcl_calloc(n, sizeof(*p), "pv sapling proofs");
    uint64_t (*pub)[4] = zcl_calloc(n * ni, sizeof(*pub), "pv sapling pub");
    if (!p || !pub) {
        free(p); free(pub);
        out->ok = false;
        out->internal_error = true;
        out->first_failure_proof_type = "sapling_ctx";
        return false;
    }
    const char *ftype = is_spend ? "sapling_spend" : "sapling_output";
    for (size_t i = 0; i < n; i++) {
        bool ok;
        if (is_spend) {
            const struct spend_description *sd = &tx->v_shielded_spend[i];
            out->sapling_spends_total++;
            ok = zclassic_sapling_spend_prepare(sctx, sd->cv.data,
                    sd->anchor.data, sd->nullifier.data, sd->rk.data,
                    sd->zkproof, sd->spend_auth_sig, sighash->data,
                    &p[i], &pub[i * ni]);
        } else {
            const struct output_description *od = &tx->v_shielded_output[i];
            out->sapling_outputs_total++;
            ok = zclassic_sapling_output_prepare(sctx, od->cv.data,
                    od->cm.data, od->ephemeral_key.data, od->zkproof,
                    &p[i], &pub[i * ni]);
        }
        if (!ok) {
            free(p); free(pub);
            out->ok = false;
            out->first_failure_proof_type = ftype;
            return false;
        }
    }
    bool batch = is_spend ? zclassic_sapling_spend_groth16_batch(p, pub, n)
                          : zclassic_sapling_output_groth16_batch(p, pub, n);
    if (!batch) {
        for (size_t i = 0; i < n; i++) {
            bool one = is_spend
                ? zclassic_sapling_spend_groth16_one(&p[i], &pub[i * ni])
                : zclassic_sapling_output_groth16_one(&p[i], &pub[i * ni]);
            if (!one) {
                free(p); free(pub);
                out->ok = false;
                out->first_failure_proof_type = ftype;
                return false;
            }
        }
    }
    free(p); free(pub);
    return true;
}

static bool default_verify_tx(const struct transaction *tx, int height,
                              struct proof_validate_tx_report *out,
                              void *user)
{
    (void)user;
    tx_report_init(out);
    if (!tx) {
        out->ok = false;
        out->internal_error = true;
        out->first_failure_proof_type = "internal";
        return true;
    }

    if (!tx_has_shielded_proofs(tx))
        return true;

    if (!sapling_params_loaded()) {
        out->ok = false;
        out->internal_error = true;
        out->first_failure_proof_type = "params_not_loaded";
        return true;
    }

    struct uint256 sighash;
    uint256_set_null(&sighash);
    uint32_t branch_id = consensus_current_epoch_branch_id(
        height, &chain_params_get()->consensus);
    struct script empty_script;
    empty_script.size = 0;
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    if (!signature_hash(&empty_script, tx, NOT_AN_INPUT, ht, 0,
                        branch_id, NULL, &sighash)) {
        out->ok = false;
        out->internal_error = true;
        out->first_failure_proof_type = "sighash";
        return true;
    }

    if (tx->num_joinsplit > 0 &&
        !ed25519_verify(tx->joinsplit_sig, sighash.data, 32,
                        tx->joinsplit_pubkey.data)) {
        out->ok = false;
        out->first_failure_proof_type = "joinsplit_sig";
        return true;
    }

    if (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0) {
        void *sctx = zclassic_sapling_verification_ctx_init();
        if (!sctx) {
            out->ok = false;
            out->internal_error = true;
            out->first_failure_proof_type = "sapling_ctx";
            return true;
        }
        if (!pv_sapling_set(sctx, tx, &sighash, true, out) ||
            !pv_sapling_set(sctx, tx, &sighash, false, out)) {
            zclassic_sapling_verification_ctx_free(sctx);
            return true;
        }
        if (!zclassic_sapling_final_check(sctx, tx->value_balance,
                                          tx->binding_sig, sighash.data)) {
            zclassic_sapling_verification_ctx_free(sctx);
            out->ok = false;
            out->first_failure_proof_type = "binding_sig";
            return true;
        }
        zclassic_sapling_verification_ctx_free(sctx);
    }

    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        const struct js_description *js = &tx->v_joinsplit[i];
        out->sprout_joinsplits_total++;
        uint8_t h_sig[32];
        sprout_h_sig(js->random_seed.data, js->nullifiers[0].data,
                     js->nullifiers[1].data, tx->joinsplit_pubkey.data,
                     h_sig);

        bool ok;
        if (js->use_groth) {
            ok = sprout_verify_groth16(js->proof, js->anchor.data, h_sig,
                    js->macs[0].data, js->macs[1].data,
                    js->nullifiers[0].data, js->nullifiers[1].data,
                    js->commitments[0].data, js->commitments[1].data,
                    (uint64_t)js->vpub_old, (uint64_t)js->vpub_new);
            if (!ok) {
                out->ok = false;
                out->first_failure_proof_type = "sprout_groth16";
                return true;
            }
        } else {
            ok = sprout_verify_phgr13(js->proof, js->anchor.data, h_sig,
                    js->macs[0].data, js->macs[1].data,
                    js->nullifiers[0].data, js->nullifiers[1].data,
                    js->commitments[0].data, js->commitments[1].data,
                    (uint64_t)js->vpub_old, (uint64_t)js->vpub_new);
            if (!ok) {
                out->ok = false;
                out->first_failure_proof_type = "sprout_phgr13";
                return true;
            }
        }
    }

    return true;
}

void proof_verify_summary_init(struct proof_verify_summary *s)
{
    memset(s, 0, sizeof(*s));
    s->ok = 1;
    uint256_set_null(&s->first_failure_txid);
}

/* Fold one tx's per-tx report into the running summary + fire the ordered
 * callback. Returns true if this tx STOPS the sweep (a failure). Mirrors the
 * serial validate_block_proofs body exactly. `ret` is the verifier's return. */
static bool pv_reduce_one(const struct transaction *tx, bool ret,
                          const struct proof_validate_tx_report *r,
                          proof_verify_success_cb on_success,
                          proof_verify_failure_cb on_failure, void *cb_user,
                          struct proof_verify_summary *out)
{
    if (!ret) {
        out->ok = 0;
        out->internal_error = 1;
        out->first_failure_txid = tx->hash;
        out->first_failure_proof_type = "internal";
        return true;
    }
    out->sapling_spends_total += r->sapling_spends_total;
    out->sapling_outputs_total += r->sapling_outputs_total;
    out->sprout_joinsplits_total += r->sprout_joinsplits_total;
    if (r->ok) {
        if (on_success)
            on_success(tx, r, cb_user);
        return false;
    }
    out->ok = 0;
    out->internal_error = r->internal_error ? 1 : 0;
    out->first_failure_txid = tx->hash;
    out->first_failure_proof_type = r->first_failure_proof_type
        ? r->first_failure_proof_type : "internal";
    if (on_failure)
        on_failure(out->first_failure_proof_type, cb_user);
    return true;
}

static void pv_serial(const struct block *blk, int height,
                      proof_validate_tx_verify_fn verifier, void *verifier_user,
                      proof_verify_success_cb on_success,
                      proof_verify_failure_cb on_failure, void *cb_user,
                      struct proof_verify_summary *out)
{
    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        struct proof_validate_tx_report r;
        bool ret = verifier(tx, height, &r, verifier_user);
        if (pv_reduce_one(tx, ret, &r, on_success, on_failure, cb_user, out))
            return;
    }
}

/* ── pool-parallel sweep ──────────────────────────────────────────────────── */

/* Proof-verification cost lives almost entirely in SHIELDED txs (Sapling
 * Groth16 spend/output, the binding sig, Sprout Groth16/PHGR13). A transparent
 * tx is a near-free early-out in default_verify_tx, so fanning a block of N
 * transparent txs across the pool is N trivial jobs plus a full thundering-herd
 * cv_take broadcast + cv_done join — pure loss. Cross-tx parallelism only pays
 * once at least this many txs each carry real proof work; a single shielded tx
 * has no sibling to run beside it (its own spends/outputs already batch inside
 * pv_sapling_set). Below the threshold, fold serially (verdict-identical — the
 * serial sweep is the reference the reduce reproduces, pinned by
 * test_validate_parallel_determinism). Default 2. Env
 * ZCL_PV_PARALLEL_MIN_SHIELDED overrides (clamped). */
#define PV_PARALLEL_MIN_SHIELDED_DEFAULT 2

#ifdef ZCL_TESTING
static _Atomic int g_pv_parallel_min_shielded_test = -1;  /* <0 = env/default */
void proof_verify_set_parallel_min_shielded_for_test(int v)
{
    atomic_store(&g_pv_parallel_min_shielded_test, v);
}
#endif

static int pv_parallel_min_shielded(void)
{
#ifdef ZCL_TESTING
    int t = atomic_load(&g_pv_parallel_min_shielded_test);
    if (t >= 0)
        return t;
#endif
    const char *e = getenv("ZCL_PV_PARALLEL_MIN_SHIELDED");
    if (e && e[0]) {
        long n = strtol(e, NULL, 10);
        if (n < 0) n = 0;
        if (n > 1000000) n = 1000000;
        return (int)n;
    }
    return PV_PARALLEL_MIN_SHIELDED_DEFAULT;
}

static size_t pv_shielded_tx_count(const struct block *blk)
{
    size_t c = 0;
    for (size_t i = 0; i < blk->num_vtx; i++)
        if (tx_has_shielded_proofs(&blk->vtx[i]))
            c++;
    return c;
}

struct pv_job {
    const struct transaction *tx;
    int height;
    proof_validate_tx_verify_fn verifier;
    void *verifier_user;
    bool ret;
    struct proof_validate_tx_report r;
};

static void pv_worker(void *j, void *u)
{
    (void)u;
    struct pv_job *job = j;
    job->ret = job->verifier(job->tx, job->height, &job->r, job->verifier_user);
}

static struct vwp_pool g_pv_pool;
static pthread_mutex_t g_pv_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_pv_pool_ready = false;
static bool g_pv_pool_failed = false;

static struct vwp_pool *pv_pool_get(void)
{
    pthread_mutex_lock(&g_pv_pool_lock);
    if (!g_pv_pool_ready && !g_pv_pool_failed) {
        if (vwp_pool_start(&g_pv_pool, pv_worker, 0))
            g_pv_pool_ready = true;
        else
            g_pv_pool_failed = true;
    }
    struct vwp_pool *p = g_pv_pool_ready ? &g_pv_pool : NULL;
    pthread_mutex_unlock(&g_pv_pool_lock);
    return p;
}

void proof_verify_pool_shutdown(void)
{
    pthread_mutex_lock(&g_pv_pool_lock);
    if (g_pv_pool_ready) {
        vwp_pool_stop(&g_pv_pool);
        g_pv_pool_ready = false;
    }
    g_pv_pool_failed = false;
    pthread_mutex_unlock(&g_pv_pool_lock);
}

/* Returns false if it could not run in parallel (alloc/pool failure); the
 * caller then falls back to the verdict-identical serial sweep. */
static bool pv_parallel(const struct block *blk, int height,
                        proof_validate_tx_verify_fn verifier,
                        void *verifier_user,
                        proof_verify_success_cb on_success,
                        proof_verify_failure_cb on_failure, void *cb_user,
                        struct proof_verify_summary *out)
{
    size_t n = blk->num_vtx;
    if (n == 0)
        return true;
    /* Sub-threshold shielded work: fold serially (verdict-identical; see the
     * threshold note above). Returning false before touching `out` lets the
     * caller run the serial sweep exactly as the alloc/pool-failure fallback
     * does. A custom verifier whose cost is not shielded-correlated simply
     * folds serially more often — a perf conservatism, never a wrong verdict. */
    if (pv_shielded_tx_count(blk) < (size_t)pv_parallel_min_shielded())
        return false;

    struct vwp_pool *pool = pv_pool_get();
    if (!pool)
        return false;

    struct pv_job *jobs = zcl_calloc(n, sizeof(*jobs), "pv jobs");
    if (!jobs)
        return false;

    for (size_t ti = 0; ti < n; ti++) {
        jobs[ti].tx = &blk->vtx[ti];
        jobs[ti].height = height;
        jobs[ti].verifier = verifier;
        jobs[ti].verifier_user = verifier_user;
    }

    vwp_pool_run_batch(pool, jobs, sizeof(*jobs), (int)n, NULL);

    /* Reduce — SERIAL, in original tx order. */
    for (size_t ti = 0; ti < n; ti++) {
        if (pv_reduce_one(jobs[ti].tx, jobs[ti].ret, &jobs[ti].r,
                          on_success, on_failure, cb_user, out))
            break;
    }

    free(jobs);
    return true;
}

void proof_verify_block(const struct block *blk, int height,
                        proof_validate_tx_verify_fn verifier,
                        void *verifier_user,
                        bool parallel,
                        proof_verify_success_cb on_success,
                        proof_verify_failure_cb on_failure,
                        void *cb_user,
                        struct proof_verify_summary *out)
{
    proof_verify_summary_init(out);
    if (!blk) {
        out->ok = 0;
        out->internal_error = 1;
        return;
    }
    proof_validate_tx_verify_fn eff = verifier ? verifier : default_verify_tx;

    if (parallel && pv_parallel(blk, height, eff, verifier_user, on_success,
                                on_failure, cb_user, out))
        return;
    pv_serial(blk, height, eff, verifier_user, on_success, on_failure,
              cb_user, out);
}
