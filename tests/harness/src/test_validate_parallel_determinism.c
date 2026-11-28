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
#include "jobs/body_persist_stage.h"
#include "jobs/created_outputs_index.h"
#include "jobs/sv_lookahead.h"
#include "chain/chain.h"
#include "bloom/merkle.h"
#include "storage/progress_store.h"
#include "test/block_fixtures.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include <stdatomic.h>
#include "platform/time_compat.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "test/test_timing_budget.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_decode.h"
#include "primitives/transaction_v6_sighash.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sighashtype.h"
#include "consensus/upgrades.h"
#include "validation/sighash.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"
#include "sapling/fr.h"
#include "sapling/incremental_merkle_tree.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "script/standard.h"

#include <stdbool.h>
#include <stdlib.h>
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

/* ── real single-proof Sapling sets (the n < batch-minimum direct path) ───── */

#define VPD_SHIELDED_VALUE 54321

static bool vpd_real_params(void)
{
    const char *home = getenv("HOME");
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.zcash-params", (home && *home) ? home : ".");
    return (sapling_params_loaded() || sapling_init_params(dir)) &&
           zclassic_sapling_prover_is_ready();
}

static void vpd_sapling_tx_init(struct transaction *tx, int64_t value_balance)
{
    transaction_init(tx);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->value_balance = value_balance;
}

/* The sighash default_verify_tx will recompute for this tx at `height`. */
static bool vpd_sapling_sighash(const struct transaction *tx, int height,
                                struct uint256 *sh)
{
    struct script empty;
    empty.size = 0;
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    uint32_t branch = consensus_current_epoch_branch_id(
        height, &chain_params_get()->consensus);
    return signature_hash(&empty, tx, NOT_AN_INPUT, ht, 0, branch, NULL, sh);
}

/* Optionally turn the proof's C point into -C: still a valid curve point, so
 * it decodes and reaches the pairing check, which it fails. Applied BEFORE the
 * sighash, which covers the proofs, so every signature stays honest. */
static bool vpd_flip_proof(unsigned char *zkproof, bool flip)
{
    if (flip)
        zkproof[144] ^= 0x20;
    return true;
}

/* One output description from the production prover, value in, no spends. */
static bool vpd_one_output_tx(struct transaction *tx, void *pctx, int height,
                              bool flip)
{
    vpd_sapling_tx_init(tx, -VPD_SHIELDED_VALUE);
    tx->v_shielded_output = zcl_calloc(1, sizeof(*tx->v_shielded_output),
                                       "vpd out");
    if (!tx->v_shielded_output)
        return false;
    tx->num_shielded_output = 1;
    uint8_t d[11] = {0}, ask[32], nsk[32], ovk[32], ak[32], nk[32], ivk[32];
    uint8_t pkd[32];
    bool have_d = false;
    for (int i = 0; i < 256 && !have_d; i++) {
        d[0] = (uint8_t)i;
        have_d = sapling_check_diversifier(d);
    }
    sapling_generate_r(ask); sapling_generate_r(nsk); sapling_generate_r(ovk);
    sapling_ask_to_ak(ask, ak); sapling_nsk_to_nk(nsk, nk);
    sapling_crh_ivk(ak, nk, ivk);
    struct output_description *od = &tx->v_shielded_output[0];
    struct uint256 sh;
    return have_d && sapling_ivk_to_pkd(ivk, d, pkd) &&
           sapling_build_output_with_ctx(pctx, ovk, d, pkd, VPD_SHIELDED_VALUE,
               NULL, od->cv.data, od->cm.data, od->ephemeral_key.data,
               od->enc_ciphertext, od->out_ciphertext, od->zkproof) &&
           vpd_flip_proof(od->zkproof, flip) &&
           vpd_sapling_sighash(tx, height, &sh) &&
           zclassic_sapling_binding_sig(pctx, tx->value_balance, sh.data,
                                        tx->binding_sig);
}

struct vpd_note {
    uint8_t ask[32], ak[32], nsk[32], nk[32], ar[32], d[11], pkd[32], rcm[32];
    uint8_t anchor[32], witness[1 + 32 * 33];
    size_t witness_len;
};

/* A fixed-seed note in a one-leaf tree, with its Merkle path. */
static bool vpd_make_note(struct vpd_note *n)
{
    memset(n, 0, sizeof(*n));
    n->ask[0] = 0x40; n->ask[1] = 0x99; n->nsk[0] = 0x08; n->nsk[1] = 0x5A;
    n->ar[0] = 0x03; n->rcm[0] = 0x11; n->rcm[3] = 0x7C;
    bool have_d = false;
    for (int i = 0; i < 256 && !have_d; i++) {
        n->d[0] = (uint8_t)i;
        have_d = sapling_check_diversifier(n->d);
    }
    uint8_t ivk[32], cm[32];
    sapling_ask_to_ak(n->ask, n->ak); sapling_nsk_to_nk(n->nsk, n->nk);
    sapling_crh_ivk(n->ak, n->nk, ivk);
    if (!have_d || !sapling_ivk_to_pkd(ivk, n->d, n->pkd) ||
        !sapling_compute_cm(n->d, n->pkd, VPD_SHIELDED_VALUE, n->rcm, cm))
        return false;
    struct incremental_merkle_tree tree;
    struct incremental_witness w;
    struct uint256 leaf, anchor;
    memcpy(leaf.data, cm, 32);
    sapling_tree_init(&tree);
    incremental_tree_append(&tree, &leaf);
    incremental_witness_init(&w, &tree);
    incremental_witness_root(&w, &anchor);
    memcpy(n->anchor, anchor.data, 32);
    return incremental_witness_merkle_path(&w, n->witness, &n->witness_len);
}

/* One spend description from the production prover, value out, no outputs. */
static bool vpd_one_spend_tx(struct transaction *tx, void *pctx, int height,
                             bool flip)
{
    struct vpd_note n;
    vpd_sapling_tx_init(tx, VPD_SHIELDED_VALUE);
    tx->v_shielded_spend = zcl_calloc(1, sizeof(*tx->v_shielded_spend),
                                      "vpd spend");
    if (!tx->v_shielded_spend || !vpd_make_note(&n))
        return false;
    tx->num_shielded_spend = 1;
    struct spend_description *sd = &tx->v_shielded_spend[0];
    memcpy(sd->anchor.data, n.anchor, 32);
    struct uint256 sh;
    struct fs ask_fs, ar_fs, rsk_fs;
    uint8_t rsk[32];
    fs_from_bytes(&ask_fs, n.ask); fs_from_bytes(&ar_fs, n.ar);
    fs_add(&rsk_fs, &ask_fs, &ar_fs); fs_to_bytes(rsk, &rsk_fs);
    bool ok = zclassic_sapling_spend_proof(pctx, n.ak, n.nsk, n.d, n.rcm, n.ar,
                  VPD_SHIELDED_VALUE, n.anchor, n.witness, n.witness_len,
                  sd->cv.data, sd->rk.data, sd->zkproof) &&
              sapling_compute_nf(n.d, n.pkd, VPD_SHIELDED_VALUE, n.rcm, n.ak,
                                 n.nk, 0, sd->nullifier.data) &&
              vpd_flip_proof(sd->zkproof, flip) &&
              vpd_sapling_sighash(tx, height, &sh) &&
              redjubjub_sign(rsk, sh.data, 32, sd->spend_auth_sig, 5) &&
              zclassic_sapling_binding_sig(pctx, tx->value_balance, sh.data,
                                           tx->binding_sig);
    memory_cleanse(rsk, sizeof(rsk));
    return ok;
}

/* Verify `tx` through the built-in verifier and compare to the expectation. */
static bool vpd_real_verdict(struct transaction *tx, int height, bool want_ok,
                             const char *want_type)
{
    struct block b;
    block_init(&b);
    b.num_vtx = 1;
    b.vtx = tx;
    struct proof_verify_summary s;
    proof_verify_block(&b, height, NULL, NULL, false, NULL, NULL, NULL, &s);
    b.num_vtx = 0;
    b.vtx = NULL;
    block_free(&b);
    return (s.ok != 0) == want_ok && !s.internal_error &&
           (want_ok || (s.first_failure_proof_type &&
                        strcmp(s.first_failure_proof_type, want_type) == 0));
}

/* A set of ONE proof takes the direct per-proof path: honest accepted, one
 * flipped zkproof byte rejected and attributed to the right proof type. */
/* One honest or tampered single-proof tx through the built-in verifier. */
static int vpd_real_one(bool spend, bool bad, int height)
{
    int failures = 0;
    struct transaction tx;
    transaction_init(&tx);
    void *pctx = zclassic_sapling_proving_ctx_init();
    bool built = pctx && (spend ? vpd_one_spend_tx(&tx, pctx, height, bad)
                                : vpd_one_output_tx(&tx, pctx, height, bad));
    const char *kind = spend ? "1 spend" : "1 output";
    char name[96];
    snprintf(name, sizeof(name), "real %s tx built (%s)", kind,
             bad ? "flipped proof" : "honest");
    VPD_CHECK(name, built);
    if (built) {
        snprintf(name, sizeof(name), bad ? "%s, flipped proof byte -> %s"
                                         : "%s accepted%.0s", kind,
                 spend ? "sapling_spend" : "sapling_output");
        VPD_CHECK(name, vpd_real_verdict(&tx, height, !bad,
                      spend ? "sapling_spend" : "sapling_output"));
    }
    if (pctx)
        zclassic_sapling_proving_ctx_free(pctx);
    transaction_free(&tx);
    return failures;
}

/* A set of ONE proof takes the direct per-proof path (below the batch
 * minimum): honest accepted, one tampered proof rejected and attributed. */
static int vpd_real_small_set(bool spend, int height)
{
    return vpd_real_one(spend, false, height) +
           vpd_real_one(spend, true, height);
}

static int vpd_real_sapling_small_sets(int height)
{
    if (!vpd_real_params()) {
        printf("parallel_determinism: SKIP real 1-proof sapling sets "
               "(~/.zcash-params absent)\n");
        return 0;
    }
    return vpd_real_small_set(false, height) + vpd_real_small_set(true, height);
}

/* ── signed P2PKH spends for precompute and full-prevout cases ────────────── */

struct vpd_signed_prev {
    struct script spk[2];
    int64_t value[2];
    size_t count;
};

static bool vpd_signed_prevout(const struct outpoint *po, struct tx_out *out,
                               void *user)
{
    const struct vpd_signed_prev *p = user;
    if (!po || !out || !p || po->n >= p->count)
        return false;
    tx_out_set_null(out);
    out->value = p->value[po->n];
    out->script_pub_key = p->spk[po->n];
    return true;
}

static bool vpd_v6_decode(struct transaction *tx, struct byte_stream *wire)
{
    transaction_free(tx);
    transaction_init(tx);
    struct byte_stream input;
    stream_init_from_data(&input, wire->data, wire->size);
    return transaction_v6_decode_prefix(tx, &input, wire->size) &&
        input.read_pos == wire->size;
}

static bool vpd_v6_reencode(struct transaction *tx, uint32_t branch_id)
{
    struct byte_stream wire;
    stream_init(&wire, 4096);
    bool ok = stream_write_u32_le(&wire,
                                  (uint32_t)IRONWOOD_TX_VERSION | (1u << 31)) &&
        stream_write_u32_le(&wire, IRONWOOD_VERSION_GROUP_ID) &&
        stream_write_u32_le(&wire, branch_id) &&
        stream_write_u32_le(&wire, tx->lock_time) &&
        stream_write_u32_le(&wire, tx->expiry_height) &&
        stream_write_compact_size(&wire, tx->num_vin);
    for (size_t i = 0; ok && i < tx->num_vin; i++)
        ok = tx_in_serialize(&tx->vin[i], &wire);
    ok = stream_write_compact_size(&wire, tx->num_vout) && ok;
    for (size_t i = 0; ok && i < tx->num_vout; i++)
        ok = tx_out_serialize(&tx->vout[i], &wire);
    for (size_t i = 0; i < 4; i++)
        ok = stream_write_compact_size(&wire, 0) && ok;
    if (!ok) {
        stream_free(&wire);
        return false;
    }
    ok = vpd_v6_decode(tx, &wire);
    stream_free(&wire);
    return ok;
}

static bool vpd_signed_hash(const struct transaction *tx,
                            const struct vpd_signed_prev *prev, size_t index,
                            uint32_t branch_id, bool v6, struct uint256 *hash)
{
    struct sighash_type all = { .raw = SIGHASH_ALL };
    if (!v6)
        return signature_hash(&prev->spk[index], tx, (unsigned int)index, all,
                              prev->value[index], branch_id, NULL, hash);
    struct transaction_v6_prevout prevouts[2];
    for (size_t i = 0; i < prev->count; i++) {
        prevouts[i].amount = prev->value[i];
        prevouts[i].script = prev->spk[i].data;
        prevouts[i].script_size = prev->spk[i].size;
    }
    return transaction_v6_sighash(tx, prevouts, prev->count,
                                  (unsigned int)index, all, &prev->spk[index],
                                  prev->value[index], branch_id, hash);
}

static bool vpd_signed_script(struct tx_in *input, const struct privkey *key,
                              const struct pubkey *pub,
                              const struct uint256 *hash, bool corrupt)
{
    unsigned char sig[80];
    size_t siglen = sizeof(sig);
    if (!privkey_sign(key, hash, sig, &siglen) || siglen > 72)
        return false;
    if (corrupt)
        sig[siglen - 4] ^= 0xFF;
    sig[siglen++] = SIGHASH_ALL;
    unsigned char ss[1 + 73 + 1 + 65];
    size_t pklen = pub->size > 65 ? 65 : pub->size;
    size_t n = 0;
    ss[n++] = (unsigned char)siglen;
    memcpy(&ss[n], sig, siglen);
    n += siglen;
    ss[n++] = (unsigned char)pklen;
    memcpy(&ss[n], pub->vch, pklen);
    n += pklen;
    script_set(&input->script_sig, ss, n);
    return true;
}

static bool vpd_signed_block(struct block *b, struct vpd_signed_prev *prev,
                             int height, bool corrupt, bool v6)
{
    struct privkey key;
    privkey_make_new(&key, true);
    struct pubkey pub;
    privkey_get_pubkey(&key, &pub);
    struct key_id kid = pubkey_get_id(&pub);
    prev->count = v6 ? 2 : 1;
    for (size_t i = 0; i < prev->count; i++) {
        script_for_p2pkh(&prev->spk[i], &kid);
        prev->value[i] = 100000000 + (int64_t)i;
    }

    block_init(b);
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "vpd");
    if (!b->vtx)
        return false;
    b->num_vtx = 2;
    int inputs[2] = {0, 1};
    struct transaction *tx = &b->vtx[1];
    if (!vpd_build_tx(&b->vtx[0], 0, true, NULL, 0, 0) ||
        !vpd_build_tx(tx, 1, false, inputs, (int)prev->count, 0))
        return false;
    uint32_t branch_id = consensus_current_epoch_branch_id(
        height, &chain_params_get()->consensus);
    if (v6) {
        if (!vpd_v6_reencode(tx, branch_id))
            return false;
    } else {
        tx->overwintered = true;
        tx->version = SAPLING_TX_VERSION;
        tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    }
    for (size_t i = 0; i < prev->count; i++) {
        struct uint256 hash;
        if (!vpd_signed_hash(tx, prev, i, branch_id, v6, &hash) ||
            !vpd_signed_script(&tx->vin[i], &key, &pub, &hash,
                               corrupt && i == 0))
            return false;
    }
    if (!v6)
        transaction_compute_hash(tx);
    return true;
}

static bool vpd_signed_spend_block(struct block *b,
                                   struct vpd_signed_prev *prev, int height,
                                   bool corrupt)
{
    return vpd_signed_block(b, prev, height, corrupt, false);
}

static bool vpd_signed_v6_block(struct block *b,
                                struct vpd_signed_prev *prev, int height)
{
    return vpd_signed_block(b, prev, height, false, true);
}

static bool vpd_signed_v6_p2sh_block(struct block *b,
                                     struct vpd_signed_prev *prev, int height,
                                     struct script *redeem)
{
    struct privkey key;
    privkey_make_new(&key, true);
    struct pubkey pub;
    privkey_get_pubkey(&key, &pub);
    struct key_id kid = pubkey_get_id(&pub);
    script_for_p2pkh(redeem, &kid);
    struct script_id sid;
    script_id_from_script(&sid, redeem);
    script_for_p2sh(&prev->spk[0], &sid);
    prev->value[0] = 100000000;
    prev->count = 1;

    block_init(b);
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "vpd");
    if (!b->vtx)
        return false;
    b->num_vtx = 2;
    int input[1] = {0};
    struct transaction *tx = &b->vtx[1];
    if (!vpd_build_tx(&b->vtx[0], 0, true, NULL, 0, 0) ||
        !vpd_build_tx(tx, 1, false, input, 1, 0))
        return false;
    uint32_t branch_id = consensus_current_epoch_branch_id(
        height, &chain_params_get()->consensus);
    if (!vpd_v6_reencode(tx, branch_id))
        return false;
    struct uint256 hash;
    return vpd_signed_hash(tx, prev, 0, branch_id, true, &hash) &&
        vpd_signed_script(&tx->vin[0], &key, &pub, &hash, false) &&
        script_push_data(&tx->vin[0].script_sig, redeem->data, redeem->size);
}

/* One script_verify_block call with `label` failing if given, under one
 * routing: 0 = serial entry, 1 = pool fan, 2 = parallel entry folded serially. */
static void vpd_signed_run(const struct block *b, struct vpd_signed_prev *prev,
                           int height, int routing, const char *label,
                           bool *fired, struct script_verify_summary *out)
{
    script_verify_set_parallel_min_inputs_for_test(routing == 1 ? 0 : 1 << 30);
    if (label)
        zcl_alloc_fault_fail_nth(label, 1);
    script_verify_block(b, height, NULL, NULL, vpd_signed_prevout, prev,
                        routing != 0, out);
    if (fired)
        *fired = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    script_verify_set_parallel_min_inputs_for_test(-1);
}

static bool vpd_signed_summary_expected(const struct vpd_signed_prev *prev,
                                        const struct script_verify_summary *s,
                                        bool accepted)
{
    if (accepted)
        return s->ok == 1 && !s->internal_error && s->tx_count == 2 &&
            s->input_count == prev->count && s->inputs_verified == prev->count &&
            s->inputs_failed == 0;
    return s->ok == 0 && !s->internal_error && s->tx_count == 2 &&
        s->input_count == 1 && s->inputs_verified == 0 &&
        s->inputs_failed == 1 && s->first_failure_vin == 0 &&
        s->first_failure_serror != SCRIPT_ERR_OK;
}

static bool vpd_signed_routes_match(const struct block *b,
                                    struct vpd_signed_prev *prev, int height,
                                    bool accepted)
{
    struct script_verify_summary serial;
    for (int iter = 0; iter < 16; iter++) {
        for (int routing = 0; routing < 3; routing++) {
            struct script_verify_summary s;
            vpd_signed_run(b, prev, height, routing, NULL, NULL, &s);
            if (!vpd_signed_summary_expected(prev, &s, accepted))
                return false;
            if (routing == 0)
                serial = s;
            else if (!sv_eq(&s, &serial))
                return false;
        }
    }
    return true;
}

static int vpd_case_v6_full_prevouts(int height)
{
    int failures = 0;
    struct block b;
    struct vpd_signed_prev prev;
    bool built = vpd_signed_v6_block(&b, &prev, height);
    VPD_CHECK("v6 full prevouts: signed two-input fixture", built);
    if (!built)
        return failures;
    VPD_CHECK("v6 full prevouts: serial, pool and threshold accept",
              vpd_signed_routes_match(&b, &prev, height, true));
    prev.value[1]++;
    VPD_CHECK("v6 full prevouts: other amount mismatch rejects identically",
              vpd_signed_routes_match(&b, &prev, height, false));
    prev.value[1]--;
    prev.spk[1].data[4] ^= 1;
    VPD_CHECK("v6 full prevouts: other script mismatch rejects identically",
              vpd_signed_routes_match(&b, &prev, height, false));
    prev.spk[1].data[4] ^= 1;
    vpd_block_free(&b);
    return failures;
}

static int vpd_case_v6_p2sh(int height)
{
    int failures = 0;
    struct block b;
    struct vpd_signed_prev prev;
    struct script redeem;
    bool built = vpd_signed_v6_p2sh_block(&b, &prev, height, &redeem);
    VPD_CHECK("v6 P2SH: signed redemption fixture", built);
    VPD_CHECK("v6 P2SH: prevout scriptPubKey is not the P2PKH redeemScript",
              script_is_p2sh(&prev.spk[0]) && prev.spk[0].size == 23 &&
              !script_is_p2sh(&redeem) && redeem.size == 25);
    if (!built) {
        vpd_block_free(&b);
        return failures;
    }
    VPD_CHECK("v6 P2SH: serial, pool and threshold accept redemption",
              vpd_signed_routes_match(&b, &prev, height, true));
    prev.value[0]++;
    VPD_CHECK("v6 P2SH: amount mismatch rejects identically",
              vpd_signed_routes_match(&b, &prev, height, false));
    prev.value[0]--;
    prev.spk[0].data[2] ^= 1;
    VPD_CHECK("v6 P2SH: prevout script mismatch rejects identically",
              vpd_signed_routes_match(&b, &prev, height, false));
    prev.spk[0].data[2] ^= 1;
    vpd_block_free(&b);
    return failures;
}

/* precompute_tx_data hashes into streams it allocates. One that could not get
 * memory hashed a short stream, so the signature check that reads it fails
 * through no fault of the block. That is no verdict: every routing reports a
 * local failure with no failed input, and the same block verifies with memory
 * back. A corrupt signature still fails on its merits. */
static int vpd_case_precompute_out_of_memory(int height)
{
    int failures = 0;
    struct block b, bad;
    struct vpd_signed_prev prev, bad_prev;
    VPD_CHECK("precompute oom: signed fixture",
              vpd_signed_spend_block(&b, &prev, height, false) &&
              vpd_signed_spend_block(&bad, &bad_prev, height, true));

    struct script_verify_summary ref, s;
    vpd_signed_run(&b, &prev, height, 0, NULL, NULL, &ref);
    VPD_CHECK("precompute oom: the signed spend verifies",
              ref.ok == 1 && ref.inputs_verified == 1);
    vpd_signed_run(&bad, &bad_prev, height, 0, NULL, NULL, &s);
    VPD_CHECK("precompute oom: a corrupt signature fails on its merits",
              s.ok == 0 && !s.internal_error && s.inputs_failed == 1 &&
              s.first_failure_serror != SCRIPT_ERR_OK);

    struct script_verify_summary serial;
    for (int routing = 0; routing < 3; routing++) {
        bool fired = false;
        vpd_signed_run(&b, &prev, height, routing, "stream_data", &fired, &s);
        printf("parallel_determinism: precompute oom routing=%d: %s\n",
               routing, s.reason);
        VPD_CHECK("precompute oom: the precompute hit the failed allocation",
                  fired);
        VPD_CHECK("precompute oom: no script verdict",
                  s.ok == 0 && s.internal_error && s.local_failure &&
                  s.inputs_failed == 0 &&
                  strncmp(s.reason, "out_of_memory", 13) == 0);
        if (routing == 0)
            serial = s;
        else
            VPD_CHECK("precompute oom: parallel matches serial",
                      sv_eq(&s, &serial));
        vpd_signed_run(&b, &prev, height, routing, NULL, NULL, &s);
        VPD_CHECK("precompute oom: verifies with memory back", sv_eq(&s, &ref));
    }
    vpd_block_free(&b);
    vpd_block_free(&bad);
    return failures;
}

/* ── the tests ────────────────────────────────────────────────────────────── */

/* ── cross-height script lookahead (jobs/sv_lookahead.h) ──────────────────────
 *
 * Synthetic chain: block 0 is a lone coinbase; block h>=1 is {coinbase, a
 * "funding" tx spending the output of block h-1's funding tx (block 0: its
 * coinbase)}. So block H spends an output created in H-1 while the drive cursor
 * is still at 0: the in-window spend chain. Scripts are OP_TRUE / OP_FALSE, so
 * no keys are needed. bad_height's spend fails (EVAL_FALSE); unresolved_height's
 * prevout is refused by the resolver. The injected resolver is a pure function
 * of the outpoint hash, like the real created_outputs / coins_kv stores. */

struct vpd_la_chain {
    struct block_index *blocks;
    struct uint256 *hashes;
    struct block *bodies;
    int n;
    int bad_height;
    int unresolved_height;
    int signed_inputs;          /* >0: P2PKH + real ECDSA, this many inputs/tx */
    struct privkey key;
    struct pubkey pub;
    struct script spk;
    _Atomic uint64_t resolver_calls;
};

static struct transaction *vpd_la_funding(struct vpd_la_chain *c, int h)
{
    return &c->bodies[h].vtx[h == 0 ? 0 : 1];
}

/* Real ECDSA: sign every input of block h's funding tx over the P2PKH output it
 * spends (block h-1's funding output). bad_height's input 0 gets a corrupt
 * (still DER) signature. */
static bool vpd_la_sign_inputs(struct vpd_la_chain *c, int h)
{
    struct transaction *tx = vpd_la_funding(c, h);
    uint32_t branch = consensus_current_epoch_branch_id(
        h, &chain_params_get()->consensus);
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    for (size_t i = 0; i < tx->num_vin; i++) {
        struct uint256 sh;
        unsigned char sig[80], ss[1 + 73 + 1 + 65];
        size_t siglen = sizeof(sig), n = 0;
        if (!signature_hash(&c->spk, tx, (unsigned int)i, ht, 5000 + h - 1,
                            branch, NULL, &sh) ||
            !privkey_sign(&c->key, &sh, sig, &siglen) || siglen > 72)
            return false;
        if (h == c->bad_height && i == 0)
            sig[siglen - 4] ^= 0xFF;
        sig[siglen++] = SIGHASH_ALL;
        size_t pklen = c->pub.size > 65 ? 65 : c->pub.size;
        ss[n++] = (unsigned char)siglen;
        memcpy(&ss[n], sig, siglen);
        n += siglen;
        ss[n++] = (unsigned char)pklen;
        memcpy(&ss[n], c->pub.vch, pklen);
        n += pklen;
        script_set(&tx->vin[i].script_sig, ss, n);
    }
    return true;
}

static bool vpd_la_make_body(struct vpd_la_chain *c, int h)
{
    struct block *b = &c->bodies[h];
    block_init(b);
    b->num_vtx = h == 0 ? 1 : 2;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "vpd_la_tx");
    if (!b->vtx)
        return false;
    int none[64] = {0};
    int nin = c->signed_inputs > 0 ? c->signed_inputs : 1;
    if (!vpd_build_tx(&b->vtx[0], 1000 + h, true, none, 0, (uint32_t)h))
        return false;
    if (h > 0) {
        if (!vpd_build_tx(&b->vtx[1], 2000 + h, false, none, nin, 0))
            return false;
        for (int i = 0; i < nin; i++) {
            b->vtx[1].vin[i].prevout.hash = vpd_la_funding(c, h - 1)->hash;
            b->vtx[1].vin[i].prevout.n = 0;
        }
    }
    struct transaction *f = vpd_la_funding(c, h);
    script_init(&f->vout[0].script_pub_key);
    if (c->signed_inputs > 0)
        f->vout[0].script_pub_key = c->spk;
    else
        script_push_op(&f->vout[0].script_pub_key,
                       h + 1 == c->bad_height ? OP_FALSE : OP_TRUE);
    f->vout[0].value = 5000 + h;
    if (c->signed_inputs > 0 && h > 0 && !vpd_la_sign_inputs(c, h))
        return false;
    transaction_compute_hash(&b->vtx[b->num_vtx - 1]);
    if (h > 0)
        transaction_compute_hash(&b->vtx[0]);
    b->header.nVersion = 4;
    b->header.nTime = 1700003000u + (uint32_t)h;
    b->header.nBits = 0x1f07ffff;
    if (h > 0)
        b->header.hashPrevBlock = c->hashes[h - 1];
    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[b->num_vtx - 1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, b->num_vtx);
    block_header_get_hash(&b->header, &c->hashes[h]);
    return true;
}

static void vpd_la_chain_free(struct vpd_la_chain *c)
{
    for (int i = 0; c->bodies && i < c->n; i++)
        block_free(&c->bodies[i]);
    free(c->blocks);
    free(c->hashes);
    free(c->bodies);
    memset(c, 0, sizeof(*c));
}

static bool vpd_la_chain_build(struct vpd_la_chain *c, int n, int bad,
                               int unresolved, int signed_inputs)
{
    memset(c, 0, sizeof(*c));
    c->bad_height = bad;
    c->unresolved_height = unresolved;
    c->signed_inputs = signed_inputs;
    if (signed_inputs > 0) {
        privkey_make_new(&c->key, true);
        privkey_get_pubkey(&c->key, &c->pub);
        struct key_id kid = pubkey_get_id(&c->pub);
        script_for_p2pkh(&c->spk, &kid);
    }
    c->blocks = zcl_calloc((size_t)n, sizeof(*c->blocks), "vpd_la_bi");
    c->hashes = zcl_calloc((size_t)n, sizeof(*c->hashes), "vpd_la_hash");
    c->bodies = zcl_calloc((size_t)n, sizeof(*c->bodies), "vpd_la_body");
    if (!c->blocks || !c->hashes || !c->bodies)
        return false;
    c->n = n;
    for (int i = 0; i < n; i++) {
        if (!vpd_la_make_body(c, i))
            return false;
        block_index_init(&c->blocks[i]);
        c->blocks[i].phashBlock = &c->hashes[i];
        c->blocks[i].nHeight = i;
        c->blocks[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0)
            c->blocks[i].pprev = &c->blocks[i - 1];
    }
    return true;
}

static bool vpd_la_reader(struct block *out, const struct block_index *bi,
                          const char *datadir, void *user)
{
    (void)datadir;
    const struct vpd_la_chain *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= c->n)
        return false;
    return test_block_copy(out, &c->bodies[bi->nHeight], "vpd_la_copy");
}

/* The output a block's input names, by outpoint hash; refused for the one
 * unresolved block. Counts every call so a test can see a sweep NOT run. */
static bool vpd_la_prevout(const struct outpoint *po, struct tx_out *out,
                           void *user)
{
    struct vpd_la_chain *c = user;
    atomic_fetch_add(&c->resolver_calls, 1);
    for (int i = 0; po && out && i < c->n; i++) {
        struct transaction *f = vpd_la_funding(c, i);
        if (uint256_cmp(&f->hash, &po->hash) != 0 || po->n != 0)
            continue;
        if (i + 1 == c->unresolved_height)
            return false;
        tx_out_set_null(out);
        out->value = f->vout[0].value;
        out->script_pub_key = f->vout[0].script_pub_key;
        return true;
    }
    return false;
}

static uint64_t vpd_la_limit_all;
static uint64_t vpd_la_limit(void)
{
    return vpd_la_limit_all;
}

static bool vpd_la_wait_populated(uint64_t want, int timeout_ms)
{
    for (int i = 0; i < timeout_ms / 2 + 1; i++) {
        if (sv_lookahead_populated() >= want)
            return true;
        platform_sleep_ms(2);
    }
    return sv_lookahead_populated() >= want;
}

/* Wrong hash, wrong flags, wrong branch id, another resolver pair: each is a
 * MISS that leaves the slot for the exact key. */
static bool vpd_la_probe_keying(const struct vpd_la_chain *c, int h)
{
    uint32_t flags, branch;
    script_verify_params_for_height(h, &flags, &branch);
    struct script_verify_summary s;
    struct uint256 wrong = c->hashes[h];
    wrong.data[0] ^= 0xff;
    return !sv_lookahead_take(h, &wrong, flags, branch, vpd_la_prevout,
                              (void *)c, &s) &&
           !sv_lookahead_take(h, &c->hashes[h], flags ^ 1u, branch,
                              vpd_la_prevout, (void *)c, &s) &&
           !sv_lookahead_take(h, &c->hashes[h], flags, branch ^ 1u,
                              vpd_la_prevout, (void *)c, &s) &&
           !sv_lookahead_take(h, &c->hashes[h], flags, branch, vpd_prevout,
                              NULL, &s) &&
           !sv_lookahead_take(c->n + 7, &c->hashes[h], flags, branch,
                              vpd_la_prevout, (void *)c, &s);
}

/* Consume every height: each hit must equal the inline reference byte for byte
 * (reason string included); the unresolved height must miss. */
static void vpd_la_take_all(struct vpd_la_chain *c,
                            const struct script_verify_summary *ref, int unres,
                            bool *same, bool *miss_ok)
{
    *same = true;
    *miss_ok = true;
    for (int h = 0; h < c->n; h++) {
        uint32_t flags, branch;
        script_verify_params_for_height(h, &flags, &branch);
        struct script_verify_summary got;
        bool hit = sv_lookahead_take(h, &c->hashes[h], flags, branch,
                                     vpd_la_prevout, c, &got);
        if (h == unres)
            *miss_ok = !hit;
        else
            *same = *same && hit && sv_eq(&got, &ref[h]);
    }
}

static int vpd_la_ref_checks(const struct script_verify_summary *ref, int bad,
                             int unres)
{
    int failures = 0;
    VPD_CHECK("lookahead ref: bad height is script_invalid, not internal",
              !ref[bad].ok && !ref[bad].internal_error &&
              ref[bad].first_failure_vin == 0 &&
              ref[bad].first_failure_serror == SCRIPT_ERR_EVAL_FALSE);
    VPD_CHECK("lookahead ref: refused prevout is internal_error",
              !ref[unres].ok && ref[unres].internal_error);
    return failures;
}

/* Every height's consumed verdict equals the inline serial sweep byte for byte
 * (reason string included); the unresolved height is never cached. */
static int vpd_la_module_diff(void)
{
    int failures = 0;
    struct vpd_la_chain c;
    struct main_state ms;
    const int N = 24, BAD = 9, UNRES = 15;
    main_state_init(&ms);
    bool built = vpd_la_chain_build(&c, N, BAD, UNRES, 0);
    VPD_CHECK("lookahead fixture built", built);
    if (!built) {
        vpd_la_chain_free(&c);
        main_state_free(&ms);
        return 1;
    }
    active_chain_move_window_tip(&ms.chain_active, &c.blocks[N - 1]);

    struct script_verify_summary ref[24];
    for (int h = 0; h < N; h++)
        script_verify_block(&c.bodies[h], h, vpd_la_prevout, &c, NULL, NULL,
                            false, &ref[h]);
    failures += vpd_la_ref_checks(ref, BAD, UNRES);

    vpd_la_limit_all = (uint64_t)N;
    bool started = sv_lookahead_start(&ms, "", vpd_la_reader, &c,
                                      vpd_la_prevout, &c, vpd_la_limit);
    VPD_CHECK("lookahead pool started", started);
    VPD_CHECK("lookahead warms every height but the unresolved one",
              started && vpd_la_wait_populated((uint64_t)N - 1, 10000));
    /* Let every height be swept, then the unresolved one must STAY uncached. */
    for (int i = 0; i < 5000 && sv_lookahead_verified_total() < (uint64_t)N; i++)
        platform_sleep_ms(2);
    VPD_CHECK("lookahead populated excludes the unresolved height",
              sv_lookahead_populated() == (uint64_t)N - 1 &&
              sv_lookahead_skipped_total() >= 1);
    VPD_CHECK("lookahead key probes (hash/flags/branch/resolver/height) miss",
              vpd_la_probe_keying(&c, 4) && vpd_la_probe_keying(&c, BAD));

    uint64_t calls_before = atomic_load(&c.resolver_calls);
    bool same, miss_ok;
    vpd_la_take_all(&c, ref, UNRES, &same, &miss_ok);
    VPD_CHECK("lookahead hit == inline sweep, valid + bad-signature + chain",
              same);
    VPD_CHECK("lookahead refused-prevout height misses", miss_ok);
    VPD_CHECK("lookahead take runs no sweep (resolver untouched)",
              atomic_load(&c.resolver_calls) == calls_before);
    VPD_CHECK("lookahead counters: hits=N-1, sweeps ran on workers",
              sv_lookahead_hit_total() == (uint64_t)N - 1 &&
              sv_lookahead_verified_total() >= (uint64_t)N);
    sv_lookahead_stop();
    struct script_verify_summary late;
    VPD_CHECK("lookahead stopped pool never hits",
              !sv_lookahead_take(3, &c.hashes[3], 0, 0, vpd_la_prevout, &c,
                                 &late));
    vpd_la_chain_free(&c);
    main_state_free(&ms);
    return failures;
}

/* The flags/branch id a verdict is keyed by are the block's own height's: they
 * differ across a network-upgrade activation, and a claim at one height can
 * never satisfy a consume at another. */
static int vpd_la_params_per_height(void)
{
    int failures = 0;
    int act = chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING]
                  .nActivationHeight;
    uint32_t f1, b1, f2, b2;
    script_verify_params_for_height(act - 1, &f1, &b1);
    script_verify_params_for_height(act, &f2, &b2);
    VPD_CHECK("lookahead params follow the claimed height",
              b1 != b2 &&
              b1 == consensus_current_epoch_branch_id(
                        act - 1, &chain_params_get()->consensus) &&
              b2 == consensus_current_epoch_branch_id(
                        act, &chain_params_get()->consensus));
    return failures;
}

/* ── through the real script_validate stage ───────────────────────────────── */

struct vpd_la_fold {
    bool setup_ok;
    int drained;
    uint64_t hits, misses, inputs_verified, inputs_failed, verified, invalid;
    uint64_t resolver_calls_during_drain;
    char rows[24][160];
};

static bool vpd_la_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err)
        sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* One ok=1 body_persist_log row per height plus the created_outputs rows
 * body_persist would have written, so the production resolver reads a real
 * index on the shared connection. */
static bool vpd_la_seed_rows(sqlite3 *db, const struct vpd_la_chain *c)
{
    for (int h = 0; h < c->n; h++) {
        char sql[200];
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO body_persist_log "
                 "(height, source, ok, persisted_at) "
                 "VALUES (%d, 'verified', 1, 1)", h);
        if (!vpd_la_exec(db, sql) ||
            !created_outputs_index_put_block(db, &c->bodies[h], h))
            return false;
    }
    return true;
}

/* script_validate_log rows, minus validated_at, as one comparable string per
 * height. */
static void vpd_la_capture_rows(sqlite3 *db, struct vpd_la_fold *out, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT height, status, ok, tx_count, input_count, "
        "hex(first_failure_txid), first_failure_vin, first_failure_serror, "
        "hex(block_hash) FROM script_validate_log ORDER BY height",
        -1, &st, NULL) != SQLITE_OK)
        return;
    while (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:test-fixture-readback
        int h = sqlite3_column_int(st, 0);
        if (h < 0 || h >= n)
            continue;
        snprintf(out->rows[h], sizeof(out->rows[h]), "%s|%d|%d|%d|%s|%d|%d|%s",
                 (const char *)sqlite3_column_text(st, 1),
                 sqlite3_column_int(st, 2), sqlite3_column_int(st, 3),
                 sqlite3_column_int(st, 4),
                 sqlite3_column_text(st, 5) ? (const char *)
                     sqlite3_column_text(st, 5) : "",
                 sqlite3_column_int(st, 6), sqlite3_column_int(st, 7),
                 sqlite3_column_text(st, 8) ? (const char *)
                     sqlite3_column_text(st, 8) : "");
    }
    sqlite3_finalize(st);
}

/* Fold the chain once through the real stage. `pool` starts the lookahead
 * through script_validate_lookahead_start and waits for every height to warm
 * first, so every consume must be a HIT. `prod_resolver` keeps the stage's
 * production created_outputs resolver; otherwise the counting fake is used. */
static void vpd_la_fold_run(struct vpd_la_fold *out, const char *tag,
                            struct vpd_la_chain *c, bool pool,
                            bool prod_resolver)
{
    memset(out, 0, sizeof(*out));
    char dir[256];
    struct main_state ms;
    test_make_tmpdir(dir, sizeof(dir), "sv_lookahead", tag);
    if (!progress_store_open(dir))
        return;
    main_state_init(&ms);
    active_chain_move_window_tip(&ms.chain_active, &c->blocks[c->n - 1]);
    sqlite3 *db = progress_store_db();
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
             "VALUES('body_persist', %d, 1)", c->n);
    out->setup_ok = vpd_la_exec(db, sql) && body_persist_stage_init(&ms) &&
                    vpd_la_seed_rows(db, c) && script_validate_stage_init(&ms);
    if (out->setup_ok) {
        script_validate_stage_set_reader(vpd_la_reader, c);
        if (!prod_resolver)
            script_validate_stage_set_prevout_resolver(vpd_la_prevout, c);
        vpd_la_limit_all = (uint64_t)c->n;
        script_validate_lookahead_set_limit_for_test(vpd_la_limit);
        if (pool)
            out->setup_ok = script_validate_lookahead_start() &&
                            vpd_la_wait_populated((uint64_t)c->n, 10000);
    }
    uint64_t calls0 = atomic_load(&c->resolver_calls);
    if (out->setup_ok) {
        out->drained = script_validate_stage_drain(1000);
        /* The totals are reset by a start; a pool-off fold reports zero. */
        out->hits = pool ? sv_lookahead_hit_total() : 0;
        out->misses = pool ? sv_lookahead_miss_total() : 0;
        out->inputs_verified = script_validate_stage_inputs_verified_total();
        out->verified = script_validate_stage_verified_total();
        out->invalid = script_validate_stage_script_invalid_total();
        out->resolver_calls_during_drain =
            atomic_load(&c->resolver_calls) - calls0;
        vpd_la_capture_rows(db, out, c->n);
    }
    script_validate_stage_shutdown();     /* stops the pool first */
    script_validate_lookahead_set_limit_for_test(NULL);
    body_persist_stage_shutdown();
    main_state_free(&ms);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

static bool vpd_la_rows_equal(const struct vpd_la_fold *a,
                              const struct vpd_la_fold *b, int n)
{
    for (int h = 0; h < n; h++)
        if (a->rows[h][0] == '\0' || strcmp(a->rows[h], b->rows[h]) != 0)
            return false;
    return true;
}

static int vpd_la_stage_diff(bool prod_resolver, const char *label)
{
    int failures = 0;
    struct vpd_la_chain c;
    const int N = 20, BAD = 9;
    bool built = vpd_la_chain_build(&c, N, BAD, -1, 0);
    struct vpd_la_fold off, on;
    if (built) {
        vpd_la_fold_run(&off, "off", &c, false, prod_resolver);
        vpd_la_fold_run(&on, "on", &c, true, prod_resolver);
    } else {
        memset(&off, 0, sizeof(off));
        memset(&on, 0, sizeof(on));
    }
    char name[96];
    snprintf(name, sizeof(name), "stage %s: setup", label);
    VPD_CHECK(name, built && off.setup_ok && on.setup_ok);
    snprintf(name, sizeof(name), "stage %s: rows identical, lookahead on vs off",
             label);
    VPD_CHECK(name, vpd_la_rows_equal(&off, &on, N) &&
              strstr(off.rows[BAD], "script_invalid|0|") != NULL);
    snprintf(name, sizeof(name), "stage %s: stage counters identical", label);
    VPD_CHECK(name, off.drained == on.drained && off.drained == N &&
              off.inputs_verified == on.inputs_verified &&
              off.verified == on.verified && off.invalid == on.invalid &&
              off.invalid == 1);
    snprintf(name, sizeof(name), "stage %s: every consume hit, none inline",
             label);
    VPD_CHECK(name, on.hits == (uint64_t)N && on.misses == 0 &&
              off.hits == 0);
    if (!prod_resolver) {
        VPD_CHECK("stage fake: sweep ran inline with the pool off",
                  off.resolver_calls_during_drain > 0);
        VPD_CHECK("stage fake: sweep skipped on every hit (zero resolves)",
                  on.resolver_calls_during_drain == 0);
    }
    vpd_la_chain_free(&c);
    return failures;
}

/* Real-ECDSA differential + the drive-thread cost the lookahead removes: the
 * inline sweep (production routing, pool fan) per block vs consuming a warm
 * verdict. Informational timing, no threshold; a corrupt signature at BAD must
 * yield the identical first failure. */
static int vpd_la_bench(void)
{
    int failures = 0;
    struct vpd_la_chain c;
    struct main_state ms;
    const int N = 24, M = 24, BAD = 17;
    main_state_init(&ms);
    bool built = vpd_la_chain_build(&c, N, BAD, -1, M);
    VPD_CHECK("lookahead signed fixture built", built);
    if (!built) {
        vpd_la_chain_free(&c);
        main_state_free(&ms);
        return 1;
    }
    active_chain_move_window_tip(&ms.chain_active, &c.blocks[N - 1]);
    struct script_verify_summary ref[24];
    int64_t t0 = platform_time_monotonic_us();
    for (int h = 0; h < N; h++)
        script_verify_block(&c.bodies[h], h, vpd_la_prevout, &c, NULL, NULL,
                            true, &ref[h]);
    int64_t inline_us = platform_time_monotonic_us() - t0;

    vpd_la_limit_all = (uint64_t)N;
    int64_t t1 = platform_time_monotonic_us();
    bool started = sv_lookahead_start(&ms, "", vpd_la_reader, &c,
                                      vpd_la_prevout, &c, vpd_la_limit) &&
                   vpd_la_wait_populated((uint64_t)N, 30000);
    int64_t warm_us = platform_time_monotonic_us() - t1;
    bool same = started;
    int64_t t2 = platform_time_monotonic_us();
    for (int h = 0; started && h < N; h++) {
        uint32_t flags, branch;
        struct script_verify_summary got;
        script_verify_params_for_height(h, &flags, &branch);
        same = same && sv_lookahead_take(h, &c.hashes[h], flags, branch,
                                         vpd_la_prevout, &c, &got) &&
               sv_eq(&got, &ref[h]);
    }
    int64_t hit_us = platform_time_monotonic_us() - t2;
    sv_lookahead_stop();
    VPD_CHECK("lookahead real-ECDSA hit == inline sweep, corrupt sig included",
              same && !ref[BAD].ok && !ref[BAD].internal_error &&
              ref[BAD].first_failure_vin == 0 && ref[1].inputs_verified == (size_t)M);
    printf("parallel_determinism: lookahead drive-thread script cost, %d blocks x "
           "%d ECDSA inputs: inline %lld us/block, consume warm verdict %lld "
           "us/block; workers warmed all in %lld us\n", N - 1, M,
           (long long)(inline_us / (N - 1)), (long long)(hit_us / N),
           (long long)warm_us);
    vpd_la_chain_free(&c);
    main_state_free(&ms);
    return failures;
}

static int vpd_la_cases(void)
{
    int failures = vpd_la_params_per_height();
    failures += vpd_la_module_diff();
    failures += vpd_la_bench();
    failures += vpd_la_stage_diff(false, "counting resolver");
    failures += vpd_la_stage_diff(true, "created_outputs resolver");
    return failures;
}

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

    failures += vpd_case_precompute_out_of_memory(
        chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING]
            .nActivationHeight + 1);
    failures += vpd_case_v6_full_prevouts(
        chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING]
            .nActivationHeight + 1);
    failures += vpd_case_v6_p2sh(
        chain_params_get()->consensus.vUpgrades[UPGRADE_SAPLING]
            .nActivationHeight + 1);

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
        uint64_t t0 = test_process_cpu_us();
        for (int i = 0; i < REPS; i++) {
            struct script_verify_summary s;
            script_verify_block(&b, H, NULL, NULL, vpd_prevout, NULL, true, &s);
            if (!sv_eq(&s, &ref)) { pool_ok = false; break; }
        }
        uint64_t us_pool = test_process_cpu_us() - t0;

        script_verify_set_parallel_min_inputs_for_test(-1);  /* default => serial */
        uint64_t t1 = test_process_cpu_us();
        for (int i = 0; i < REPS; i++) {
            struct script_verify_summary s;
            script_verify_block(&b, H, NULL, NULL, vpd_prevout, NULL, true, &s);
            if (!sv_eq(&s, &ref)) { ser_ok = false; break; }
        }
        uint64_t us_ser = test_process_cpu_us() - t1;

        double pool_bps = us_pool > 0 ? (double)REPS * 1e6 / (double)us_pool : 0.0;
        double ser_bps  = us_ser  > 0 ? (double)REPS * 1e6 / (double)us_ser  : 0.0;
        printf("parallel_determinism: light-block script throughput: "
               "pool=%.0f blk/s, serial-threshold=%.0f blk/s (%.2fx)\n",
               pool_bps, ser_bps, pool_bps > 0 ? ser_bps / pool_bps : 0.0);

        VPD_CHECK("light-block routing verdict-identical", pool_ok && ser_ok);
        /* The serial routing eliminates the fan overhead, so it must not be
         * materially slower. Both arms are costed in process CPU (user+sys,
         * pool workers included), so a loaded host cannot starve one arm. The
         * loose bound (1.5x + 5ms slack) keeps the gate
         * stable under cache and SMT noise while still catching a routing that
         * accidentally kept fanning every light block. */
        VPD_CHECK("light-block serial-threshold not slower than pool",
                  us_ser <= us_pool * 3 / 2 + 5000);
        vpd_block_free(&b);
    }

    failures += vpd_real_sapling_small_sets(H);
    failures += vpd_la_cases();

    /* Join the lazily-started pools so no worker outlives the test. */
    script_verify_pool_shutdown();
    proof_verify_pool_shutdown();

    if (failures)
        printf("test_validate_parallel_determinism: %d FAILURE(S)\n", failures);
    return failures;
}
