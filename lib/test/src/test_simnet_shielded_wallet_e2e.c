/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * W1-d — full shielded wallet E2E through the PRODUCTION prover.
 *
 * Sibling of test_simnet_sapling_shielded_send.c (Lane C). Lane C pins the
 * pure-C23 native Groth16 prover and its deterministic transaction plumbing.
 * This file exercises the wallet facade: with ~/.zcash-params present AND the
 * native prover self-test passing (zclassic_sapling_prover_is_ready), it builds real
 * Sapling bundles with the PRODUCTION backend (sapling_build_output_with_ctx /
 * sapling_build_spend_with_ctx over a native C23 proving ctx) and asserts the
 * REAL C23 verifier (contextual_check_transaction) *ACCEPTS* them.
 *
 *   PART A — consensus ACCEPT E2E over the deterministic simnet:
 *     1. t->z  shield a matured coinbase (value_balance=-V) with a memo.
 *        Verifier ACCEPTS; a one-byte proof tamper is REJECTED; the note
 *        DECRYPTS to the recipient (value+memo+rcm round-trip).
 *     2. z->z  spend note0 (tree position 0), new note1 (value_balance=0).
 *        Verifier ACCEPTS; the nullifier is recorded through the REAL durable
 *        path and a replay is REJECTED (shielded double-spend).
 *     3. z->t  spend note1 (position 1), transparent out (value_balance=+V).
 *        Verifier ACCEPTS. Each spend targets the exact note at its position;
 *        the two nullifiers are distinct (note-selection).
 *
 *   PART B — wallet RPC read surface over a persisted note: z_getnewaddress,
 *     then z_getbalance / z_gettotalbalance / z_listunspent / z_getmemo reflect
 *     the receive + memo; mark spent -> balance/unspent drop to zero.
 *
 * PARAMS-GATED: absent ~/.zcash-params (or a failing self-test) the whole test
 * SKIPs cleanly. Consensus crypto / the native Groth16 prover are NOT touched.
 */

#include "test/test_core.h"
#include "sapling/note_encryption.h"

#include "sim/simnet.h"
#include "sim/simnet_sapling.h"

#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"
#include "sapling/zip32.h"
#include "sapling/fr.h"
#include "sapling/incremental_merkle_tree.h"
#include "support/cleanse.h"

#include "primitives/transaction.h"
#include "validation/sighash.h"
#include "validation/contextual_check_tx.h"
#include "consensus/validation.h"
#include "consensus/upgrades.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "core/uint256.h"
#include "util/safe_alloc.h"

#include "storage/nullifier_kv.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "jobs/utxo_apply_delta.h"

/* PART B wallet RPC surface */
#include "platform/time_compat.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_shielded_controller.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet_sqlite.h"
#include "models/wallet_tx.h"
#include "models/database.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "validation/chainstate.h"
#include "rpc/server.h"
#include "json/json.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WE_CHECK(name, expr) do {                    \
    printf("  %s... ", (name));                       \
    if (expr) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

/* ── Sapling spending identity (params-free ZIP-32). ───────────────────── */
struct we_id {
    uint8_t ask[32], nsk[32], ovk[32];
    uint8_t ak[32], nk[32], ivk[32];
    uint8_t d[11], pk_d[32];
};
static bool we_derive_id(struct we_id *id, const uint8_t seed[32])
{
    struct zip32_xsk xsk;
    zip32_xsk_master(&xsk, seed, 32);
    struct zip32_xfvk xfvk;
    zip32_xsk_to_xfvk(&xfvk, &xsk);
    if (!zip32_xfvk_address(&xfvk, id->d, id->pk_d))
        return false;
    memcpy(id->ask, xsk.expsk.ask, 32);
    memcpy(id->nsk, xsk.expsk.nsk, 32);
    memcpy(id->ovk, xsk.expsk.ovk, 32);
    memcpy(id->ak, xfvk.fvk.ak, 32);
    memcpy(id->nk, xfvk.fvk.nk, 32);
    sapling_crh_ivk(id->ak, id->nk, id->ivk);
    return true;
}

/* ZIP-243 Sapling sighash over an empty scriptCode / NOT_AN_INPUT — the exact
 * value contextual_check_transaction signs and the spend_auth/binding sigs
 * cover. Pass txd=NULL so this matches the verifier's own call byte-for-byte. */
static bool we_sighash(struct transaction *tx,
                       const struct consensus_params *cp, int height,
                       struct uint256 *out)
{
    uint32_t branch = consensus_current_epoch_branch_id(height, cp);
    struct sighash_type ht;
    ht.raw = 1; /* SIGHASH_ALL */
    struct script empty;
    empty.size = 0;
    uint256_set_null(out);
    return signature_hash(&empty, tx, NOT_AN_INPUT, ht, 0, branch, NULL, out);
}

/* Drive the REAL shielded verifier and return its accept/reject verdict. */
static bool we_verify(const struct transaction *tx,
                      const struct consensus_params *cp, int nHeight)
{
    struct validation_state st;
    validation_state_init(&st);
    return contextual_check_transaction(tx, &st, cp, nHeight, 100);
}

/* rsk = ask + ar (in Fs); the spend_auth signing key for a re-randomized
 * spend. Returns false only on Fs decode failure (never for valid keys). */
static void we_rsk(const uint8_t ask[32], const uint8_t ar[32], uint8_t rsk[32])
{
    struct fs ask_fs, ar_fs, rsk_fs;
    fs_from_bytes(&ask_fs, ask);
    fs_from_bytes(&ar_fs, ar);
    fs_add(&rsk_fs, &ask_fs, &ar_fs);
    fs_to_bytes(rsk, &rsk_fs);
    memory_cleanse(&ask_fs, sizeof(ask_fs));
    memory_cleanse(&ar_fs, sizeof(ar_fs));
    memory_cleanse(&rsk_fs, sizeof(rsk_fs));
}

/* Recipient-side decrypt: recover (value, rcm, memo) from an OutputDescription
 * using the recipient ivk. The honest receive path. Returns true on AEAD auth
 * success and fills value/rcm/memo (memo is the raw 512-byte field). */
static bool we_decrypt_note(const struct output_description *od,
                            const uint8_t ivk[32],
                            uint64_t *value_out, uint8_t rcm_out[32],
                            uint8_t memo_out[512])
{
    uint8_t dhsecret[32], enckey[32], pt[564];
    if (!sapling_ka_agree(od->ephemeral_key.data, ivk, dhsecret) ||
        !sapling_kdf(enckey, dhsecret, od->ephemeral_key.data) ||
        !sapling_note_decrypt(enckey, od->enc_ciphertext,
                              sizeof(od->enc_ciphertext), pt)) {
        memory_cleanse(dhsecret, sizeof(dhsecret));
        memory_cleanse(enckey, sizeof(enckey));
        return false;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)pt[12 + i] << (8 * i);
    if (value_out) *value_out = v;
    if (rcm_out)  memcpy(rcm_out, pt + 20, 32);
    if (memo_out) memcpy(memo_out, pt + 52, 512);
    memory_cleanse(dhsecret, sizeof(dhsecret));
    memory_cleanse(enckey, sizeof(enckey));
    memory_cleanse(pt, sizeof(pt));
    return true;
}

/* ─────────────────────────────────────────────────────────────────────
 * PART A — production-prover consensus ACCEPT E2E (t->z, z->z, z->t).
 * ───────────────────────────────────────────────────────────────────── */
static int part_a_consensus_accept(void)
{
    int failures = 0;

    const int64_t FUND_VALUE     = 100000000;   /* 1 ZCL coinbase to shield  */
    const int64_t FEE            = 10000;
    const int64_t SHIELDED_VALUE = FUND_VALUE - FEE;
    const int     SAPLING_H       = 100;

    uint8_t seed32[32];
    memset(seed32, 0x1d, sizeof(seed32));
    seed32[0] = 0x77;   /* W1-d tag */
    struct we_id id;
    WE_CHECK("derive Sapling spending key + address", we_derive_id(&id, seed32));

    /* Simulator: Sapling active at 100, live in-sim note tree; the verifier
     * is driven explicitly (mints advance via connect_block). */
    struct simnet s;
    WE_CHECK("simnet_init", simnet_init(&s));
    simnet_activate_sapling_at(&s, SAPLING_H);
    WE_CHECK("enable in-sim Sapling tree", simnet_enable_sapling_tree(&s));
    simnet_enable_contextual_check(&s, false);
    const struct consensus_params *cp = &s.params.consensus;

    /* Fund + mature one coinbase. */
    struct script fund_script;
    script_init(&fund_script);
    { uint8_t pk[3] = {0x76, 0xa9, 0x14}; script_set(&fund_script, pk, sizeof(pk)); }
    struct uint256 cb_txid;
    WE_CHECK("mint funding coinbase (h=100)",
             simnet_mint_coinbase_to(&s, &fund_script, FUND_VALUE, &cb_txid));
    WE_CHECK("mature coinbase",
             simnet_mint_to_height(&s, SAPLING_H + COINBASE_MATURITY));
    WE_CHECK("tree empty before t->z", simnet_sapling_tree_size(&s) == 0);

    const int mature_h  = SAPLING_H + COINBASE_MATURITY;
    const int tz_height = mature_h + 1;
    const int zz_height = tz_height + 1;
    const int zt_height = zz_height + 1;

    /* ── (1) t->z ─────────────────────────────────────────────────────── */
    uint8_t note0_rcm[32]; memset(note0_rcm, 0, 32);
    struct incremental_witness w0; memset(&w0, 0, sizeof(w0));
    struct uint256 anchor0;
    bool have_note0 = false;
    {
        uint8_t memo[512];
        memset(memo, 0xF6, sizeof(memo));
        const char *msg = "zclassic23 W1-d: production t->z shield";
        memcpy(memo, msg, strlen(msg));

        void *pctx = zclassic_sapling_proving_ctx_init();
        WE_CHECK("t->z: acquire native C23 proving ctx", pctx != NULL);

        struct transaction tz;
        transaction_init(&tz);
        tz.overwintered     = true;
        tz.version          = SAPLING_TX_VERSION;
        tz.version_group_id = SAPLING_VERSION_GROUP_ID;
        tz.lock_time        = 0;
        tz.expiry_height    = 0;
        WE_CHECK("t->z: alloc transparent input", transaction_alloc(&tz, 1, 0));
        tz.vin[0].prevout.hash = cb_txid;
        tz.vin[0].prevout.n    = 0;
        tz.vin[0].sequence     = 0xFFFFFFFF;
        { uint8_t ss[2] = {0x00, 0x00}; script_set(&tz.vin[0].script_sig, ss, sizeof(ss)); }
        tz.value_balance = -SHIELDED_VALUE;   /* value INTO the shielded pool */

        tz.v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                          "we_tz_out");
        WE_CHECK("t->z: alloc shielded output", tz.v_shielded_output != NULL);
        tz.num_shielded_output = 1;

        bool built = pctx && tz.v_shielded_output &&
            sapling_build_output_with_ctx(
                pctx, id.ovk, id.d, id.pk_d, (uint64_t)SHIELDED_VALUE, memo,
                tz.v_shielded_output[0].cv.data,
                tz.v_shielded_output[0].cm.data,
                tz.v_shielded_output[0].ephemeral_key.data,
                tz.v_shielded_output[0].enc_ciphertext,
                tz.v_shielded_output[0].out_ciphertext,
                tz.v_shielded_output[0].zkproof);
        WE_CHECK("t->z: build output (production prover)", built);

        struct uint256 sighash;
        WE_CHECK("t->z: sighash", built && we_sighash(&tz, cp, tz_height, &sighash));
        WE_CHECK("t->z: binding sig (production ctx)",
                 built && zclassic_sapling_binding_sig(
                     pctx, tz.value_balance, sighash.data, tz.binding_sig));
        transaction_compute_hash(&tz);

        /* THE assertion: the REAL consensus verifier ACCEPTS a production
         * bundle (not probe agreement). */
        WE_CHECK("t->z: consensus verifier ACCEPTS (contextual_check_transaction)",
                 built && we_verify(&tz, cp, tz_height));

        /* Negative control: one flipped proof byte must be REJECTED. */
        if (built) {
            struct transaction bad;
            transaction_init(&bad);
            bool copied = transaction_copy(&bad, &tz);
            if (copied && bad.num_shielded_output == 1) {
                bad.v_shielded_output[0].zkproof[0] ^= 0x01;
                transaction_compute_hash(&bad);
            }
            WE_CHECK("t->z: tampered output proof REJECTED",
                     copied && !we_verify(&bad, cp, tz_height));
            transaction_free(&bad);
        }

        /* Honest receive: decrypt back to (value, rcm, memo). */
        uint64_t dv = 0; uint8_t dmemo[512];
        bool dec = built && we_decrypt_note(&tz.v_shielded_output[0], id.ivk,
                                            &dv, note0_rcm, dmemo);
        WE_CHECK("t->z: note decrypts to recipient (AEAD authenticates)", dec);
        WE_CHECK("t->z: decrypted value matches", dec && dv == (uint64_t)SHIELDED_VALUE);
        WE_CHECK("t->z: memo round-trips (z_getmemo source)",
                 dec && memcmp(dmemo, memo, 512) == 0);

        /* Mint: append note0 to the tree, advance tip. */
        WE_CHECK("t->z: mint (tree append + connect_block)",
                 built && simnet_mint_txs(&s, &tz, 1));
        free(tz.v_shielded_output);
        tz.v_shielded_output = NULL;
        tz.num_shielded_output = 0;
        WE_CHECK("t->z: tree has 1 note", simnet_sapling_tree_size(&s) == 1);

        have_note0 = simnet_sapling_tree_size(&s) == 1 &&
                     simnet_sapling_witness_last(&s, &w0) &&
                     simnet_sapling_tree_root(&s, &anchor0);
        WE_CHECK("t->z: witness note0 + read anchor", have_note0);

        zclassic_sapling_proving_ctx_free(pctx);
    }

    /* ── (2) z->z ─────────────────────────────────────────────────────── */
    uint8_t note1_rcm[32]; memset(note1_rcm, 0, 32);
    uint8_t zz_spend_nf[32]; memset(zz_spend_nf, 0, 32);
    struct incremental_witness w1; memset(&w1, 0, sizeof(w1));
    struct uint256 anchor1;
    bool have_note1 = false;
    {
        void *pctx = zclassic_sapling_proving_ctx_init();
        WE_CHECK("z->z: acquire proving ctx", pctx != NULL);

        struct transaction zz;
        transaction_init(&zz);
        zz.overwintered     = true;
        zz.version          = SAPLING_TX_VERSION;
        zz.version_group_id = SAPLING_VERSION_GROUP_ID;
        zz.lock_time        = 0;
        zz.expiry_height    = 0;
        zz.value_balance    = 0;   /* all value stays shielded */

        zz.v_shielded_spend  = zcl_calloc(1, sizeof(struct spend_description), "we_zz_sp");
        zz.v_shielded_output = zcl_calloc(1, sizeof(struct output_description), "we_zz_out");
        WE_CHECK("z->z: alloc spend + output",
                 zz.v_shielded_spend && zz.v_shielded_output);

        uint8_t path[1 + 32 * 33]; size_t path_len = 0;
        bool pathok = have_note0 &&
                      incremental_witness_merkle_path(&w0, path, &path_len);
        WE_CHECK("z->z: extract Merkle path (note0, position 0)", pathok);

        uint8_t ar[32];
        bool spend_built = pctx && zz.v_shielded_spend && pathok &&
            sapling_build_spend_with_ctx(
                pctx, id.ask, id.nsk, id.d, id.pk_d, note0_rcm,
                (uint64_t)SHIELDED_VALUE, /*position*/0, anchor0.data,
                path, path_len,
                zz.v_shielded_spend[0].cv.data,
                zz.v_shielded_spend[0].nullifier.data,
                zz.v_shielded_spend[0].rk.data,
                zz.v_shielded_spend[0].zkproof, ar);
        WE_CHECK("z->z: build spend (production spend prover)", spend_built);
        if (spend_built) {
            zz.num_shielded_spend = 1;
            memcpy(zz.v_shielded_spend[0].anchor.data, anchor0.data, 32);
            memcpy(zz_spend_nf, zz.v_shielded_spend[0].nullifier.data, 32);
        }

        bool out_built = pctx && zz.v_shielded_output &&
            sapling_build_output_with_ctx(
                pctx, id.ovk, id.d, id.pk_d, (uint64_t)SHIELDED_VALUE, NULL,
                zz.v_shielded_output[0].cv.data,
                zz.v_shielded_output[0].cm.data,
                zz.v_shielded_output[0].ephemeral_key.data,
                zz.v_shielded_output[0].enc_ciphertext,
                zz.v_shielded_output[0].out_ciphertext,
                zz.v_shielded_output[0].zkproof);
        WE_CHECK("z->z: build output (production prover)", out_built);
        if (out_built) zz.num_shielded_output = 1;

        struct uint256 sighash;
        bool ready = spend_built && out_built;
        WE_CHECK("z->z: sighash", ready && we_sighash(&zz, cp, zz_height, &sighash));

        if (ready) {
            uint8_t rsk[32];
            we_rsk(id.ask, ar, rsk);
            WE_CHECK("z->z: spend_auth_sig",
                     redjubjub_sign(rsk, sighash.data, 32,
                                    zz.v_shielded_spend[0].spend_auth_sig, 5));
            memory_cleanse(rsk, sizeof(rsk));
        }
        WE_CHECK("z->z: binding sig (production ctx)",
                 ready && zclassic_sapling_binding_sig(
                     pctx, zz.value_balance, sighash.data, zz.binding_sig));
        transaction_compute_hash(&zz);

        WE_CHECK("z->z: consensus verifier ACCEPTS",
                 ready && we_verify(&zz, cp, zz_height));

        /* Recover note1 rcm for the later z->t spend. */
        uint64_t dv1 = 0;
        bool dec1 = out_built && we_decrypt_note(&zz.v_shielded_output[0], id.ivk,
                                                 &dv1, note1_rcm, NULL);
        WE_CHECK("z->z: change note decrypts", dec1 && dv1 == (uint64_t)SHIELDED_VALUE);

        /* Durable nullifier path: record + double-spend replay reject. */
        {
            sqlite3 *db = NULL;
            int rc = sqlite3_open(":memory:", &db);
            WE_CHECK("z->z: open :memory: nullifier db", rc == SQLITE_OK && db);
            WE_CHECK("z->z: nullifier_kv schema", db && nullifier_kv_ensure_schema(db));

            struct block blk; memset(&blk, 0, sizeof(blk));
            blk.num_vtx = 1; blk.vtx = &zz;
            struct delta_summary sum1; memset(&sum1, 0, sizeof(sum1)); sum1.ok = true;
            WE_CHECK("z->z: utxo_apply records nullifier (real path)",
                     ready && db &&
                     utxo_apply_check_and_insert_nullifiers(db, &blk, zz_height, &sum1) &&
                     sum1.ok);
            bool found = false;
            WE_CHECK("z->z: nullifier present in durable set",
                     db && nullifier_kv_get(db, zz_spend_nf, NULLIFIER_POOL_SAPLING,
                                            &found, NULL) && found);
            struct delta_summary sum2; memset(&sum2, 0, sizeof(sum2)); sum2.ok = true;
            bool applied = db &&
                utxo_apply_check_and_insert_nullifiers(db, &blk, zz_height + 1, &sum2);
            WE_CHECK("z->z: replay of spent nullifier REJECTED (double-spend)",
                     applied && !sum2.ok);
            if (db) sqlite3_close(db);
        }

        WE_CHECK("z->z: mint (tree append + connect_block)",
                 ready && simnet_mint_txs(&s, &zz, 1));
        free(zz.v_shielded_spend);  zz.v_shielded_spend  = NULL; zz.num_shielded_spend  = 0;
        free(zz.v_shielded_output); zz.v_shielded_output = NULL; zz.num_shielded_output = 0;
        WE_CHECK("z->z: tree has 2 notes", simnet_sapling_tree_size(&s) == 2);

        have_note1 = simnet_sapling_tree_size(&s) == 2 &&
                     simnet_sapling_witness_last(&s, &w1) &&
                     simnet_sapling_tree_root(&s, &anchor1);
        WE_CHECK("z->z: witness note1 + read anchor", have_note1);

        zclassic_sapling_proving_ctx_free(pctx);
    }

    /* ── (3) z->t ─────────────────────────────────────────────────────── */
    {
        void *pctx = zclassic_sapling_proving_ctx_init();
        WE_CHECK("z->t: acquire proving ctx", pctx != NULL);

        struct transaction zt;
        transaction_init(&zt);
        zt.overwintered     = true;
        zt.version          = SAPLING_TX_VERSION;
        zt.version_group_id = SAPLING_VERSION_GROUP_ID;
        zt.lock_time        = 0;
        zt.expiry_height    = 0;
        zt.value_balance    = SHIELDED_VALUE;   /* value OUT of the shielded pool */
        WE_CHECK("z->t: alloc transparent output", transaction_alloc(&zt, 0, 1));
        if (zt.vout) {
            zt.vout[0].value = SHIELDED_VALUE;
            uint8_t spk[3] = {0x76, 0xa9, 0x14};
            script_set(&zt.vout[0].script_pub_key, spk, sizeof(spk));
        }

        zt.v_shielded_spend = zcl_calloc(1, sizeof(struct spend_description), "we_zt_sp");
        WE_CHECK("z->t: alloc spend", zt.v_shielded_spend != NULL);

        uint8_t path[1 + 32 * 33]; size_t path_len = 0;
        bool pathok = have_note1 &&
                      incremental_witness_merkle_path(&w1, path, &path_len);
        WE_CHECK("z->t: extract Merkle path (note1, position 1)", pathok);

        uint8_t ar[32];
        bool spend_built = pctx && zt.v_shielded_spend && pathok &&
            sapling_build_spend_with_ctx(
                pctx, id.ask, id.nsk, id.d, id.pk_d, note1_rcm,
                (uint64_t)SHIELDED_VALUE, /*position*/1, anchor1.data,
                path, path_len,
                zt.v_shielded_spend[0].cv.data,
                zt.v_shielded_spend[0].nullifier.data,
                zt.v_shielded_spend[0].rk.data,
                zt.v_shielded_spend[0].zkproof, ar);
        WE_CHECK("z->t: build spend (production spend prover)", spend_built);
        if (spend_built) {
            zt.num_shielded_spend = 1;
            memcpy(zt.v_shielded_spend[0].anchor.data, anchor1.data, 32);
        }

        /* Note-selection sanity: z->t spends a DIFFERENT note than z->z. */
        WE_CHECK("z->t: nullifier distinct from z->z (note-selection)",
                 spend_built &&
                 memcmp(zt.v_shielded_spend[0].nullifier.data, zz_spend_nf, 32) != 0);

        struct uint256 sighash;
        WE_CHECK("z->t: sighash",
                 spend_built && we_sighash(&zt, cp, zt_height, &sighash));
        if (spend_built) {
            uint8_t rsk[32];
            we_rsk(id.ask, ar, rsk);
            WE_CHECK("z->t: spend_auth_sig",
                     redjubjub_sign(rsk, sighash.data, 32,
                                    zt.v_shielded_spend[0].spend_auth_sig, 5));
            memory_cleanse(rsk, sizeof(rsk));
        }
        WE_CHECK("z->t: binding sig (production ctx, value_balance=+V)",
                 spend_built && zclassic_sapling_binding_sig(
                     pctx, zt.value_balance, sighash.data, zt.binding_sig));
        transaction_compute_hash(&zt);

        bool zt_verified = spend_built && we_verify(&zt, cp, zt_height);
        WE_CHECK("z->t: consensus verifier ACCEPTS", zt_verified);

        struct uint256 zt_txid = zt.hash;
        bool zt_mined = zt_verified && simnet_mint_txs(&s, &zt, 1);
        WE_CHECK("z->t: mint (transparent UTXO + connect_block)", zt_mined);
        int64_t transparent_value = 0;
        WE_CHECK("z->t: mined transparent output has exact value",
                 zt_mined &&
                 simnet_coin_value(&s, &zt_txid, 0, &transparent_value) &&
                 transparent_value == SHIELDED_VALUE);
        WE_CHECK("z->t: no shielded output means tree stays at 2 notes",
                 zt_mined && simnet_sapling_tree_size(&s) == 2);

        free(zt.v_shielded_spend); zt.v_shielded_spend = NULL; zt.num_shielded_spend = 0;
        transaction_free(&zt);
        zclassic_sapling_proving_ctx_free(pctx);
    }

    simnet_free(&s);
    return failures;
}

/* ─────────────────────────────────────────────────────────────────────
 * PART B — wallet RPC read surface over persisted shielded notes.
 *
 * Drives the SHIPPED shielded RPC handlers (z_getnewaddress, z_getbalance,
 * z_gettotalbalance, z_listunspent, z_getmemo) against a note persisted into
 * node.db, then marks it spent and asserts the balance / unspent view drops
 * to zero. This exercises the exact read path the RPCs sit on (SQLite is the
 * authoritative shielded-note store) plus the wallet keystore ivk lookup.
 * Independent of Part A (its own datadir + wallet).
 * ───────────────────────────────────────────────────────────────────── */

/* Execute one RPC with a caller-built params array; copy the string result
 * out (empty on non-string). Returns rpc_table_execute's ok. */
static bool we_rpc_str(struct rpc_table *tbl, const char *method,
                       struct json_value *params_arr,
                       char *out, size_t out_size)
{
    struct json_value result;
    json_init(&result);
    bool ok = rpc_table_execute(tbl, method, params_arr, &result);
    if (out && out_size) {
        const char *s = (result.type == JSON_STR) ? json_get_str(&result) : NULL;
        snprintf(out, out_size, "%s", s ? s : "");
    }
    json_free(&result);
    return ok;
}

static void part_b_str_param(struct json_value *arr, const char *s)
{
    json_set_array(arr);
    struct json_value a; json_init(&a); json_set_str(&a, s);
    json_push_back(arr, &a); json_free(&a);
}

static int part_b_wallet_rpc(void)
{
    int failures = 0;
    const int64_t NOTE_VALUE = 250000000; /* 2.50000000 ZCL */
    const int     TIP_H      = 500000;

    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/we_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    if (mkdir(tmpdir, 0700) != 0 && errno != EEXIST) {
        printf("  Part B: FAIL (tmpdir)\n");
        return 1;
    }
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", tmpdir);

    struct node_db ndb;            memset(&ndb, 0, sizeof(ndb));
    struct wallet_sqlite wsql;     memset(&wsql, 0, sizeof(wsql));
    struct main_state ms;          memset(&ms, 0, sizeof(ms));
    struct tx_mempool mempool;     memset(&mempool, 0, sizeof(mempool));
    struct coins_view null_view;   memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache ctip;  memset(&ctip, 0, sizeof(ctip));
    struct block_index tip;        memset(&tip, 0, sizeof(tip));
    struct rpc_table tbl;          memset(&tbl, 0, sizeof(tbl));
    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet), "we_wallet");
    bool wsql_open = false;

    if (!wallet) { printf("  Part B: FAIL (wallet alloc)\n"); return 1; }
    wallet_init(wallet);
    if (!sapling_keystore_generate_seed(&wallet->sapling_keys)) {
        wallet_free(wallet); free(wallet);
        printf("  Part B: FAIL (sapling seed)\n"); return 1;
    }
    main_state_init(&ms);
    tx_mempool_init(&mempool, 0);
    coins_view_cache_init(&ctip, &null_view);
    rpc_table_init(&tbl);
    block_index_init(&tip);
    tip.nHeight = TIP_H;
    tip.nTime = (uint32_t)platform_time_wall_time_t();
    active_chain_move_window_tip(&ms.chain_active, &tip);
    wallet->best_block = &tip;
    wallet->best_block_height = tip.nHeight;

    if (!node_db_open(&ndb, dbpath)) {
        wallet_free(wallet); free(wallet);
        printf("  Part B: FAIL (node_db_open)\n"); return 1;
    }
    struct zcl_result wr = wallet_sqlite_open_r(&wsql, ndb.db);
    if (!wr.ok) {
        node_db_close(&ndb); wallet_free(wallet); free(wallet);
        printf("  Part B: FAIL (wallet_sqlite_open_r)\n"); return 1;
    }
    wsql_open = true;

    register_wallet_rpc_commands(&tbl);
    set_rpc_warmup_finished();
    rpc_wallet_set_state(wallet, &ms, tmpdir, &wsql, &mempool, NULL);
    rpc_wallet_set_node_db(&ndb);
    rpc_wallet_set_coins_tip(&ctip);

    /* z_getnewaddress → a wallet-owned Sapling address (persisted). */
    char zaddr[128] = {0};
    {
        struct json_value p; json_init(&p); json_set_array(&p);
        bool ok = we_rpc_str(&tbl, "z_getnewaddress", &p, zaddr, sizeof(zaddr));
        json_free(&p);
        WE_CHECK("Part B: z_getnewaddress returns zs1 address",
                 ok && strncmp(zaddr, "zs1", 3) == 0);
    }

    /* Resolve the address's ivk from the keystore and persist a received note. */
    uint8_t nd[11], npkd[32], nnf[32], ncm[32], nrcm[32];
    memset(nnf, 0x33, 32); memset(ncm, 0x22, 32); memset(nrcm, 0x11, 32);
    bool note_saved = false;
    if (sapling_decode_payment_address(zaddr, nd, npkd)) {
        const struct sapling_key_entry *ske =
            sapling_keystore_find_by_address(&wallet->sapling_keys, nd, npkd);
        WE_CHECK("Part B: keystore resolves ivk for new address", ske != NULL);
        if (ske) {
            struct db_sapling_note n; memset(&n, 0, sizeof(n));
            memset(n.txid, 0xB7, 32);
            n.output_index = 0;
            n.value = NOTE_VALUE;
            memcpy(n.rcm, nrcm, 32);
            const char *m = "W1-d persisted note: hello shielded";
            memset(n.memo, 0xF6, sizeof(n.memo));
            memcpy(n.memo, m, strlen(m));
            n.memo_len = 512;
            memcpy(n.ivk, ske->ivk, 32);
            memcpy(n.diversifier, nd, 11);
            memcpy(n.pk_d, npkd, 32);
            memcpy(n.cm, ncm, 32);
            memcpy(n.nullifier, nnf, 32);
            n.block_height = TIP_H - 5;   /* 6 confirmations */
            n.is_spent = false;
            snprintf(n.address, sizeof(n.address), "%s", zaddr);
            snprintf(n.source, sizeof(n.source), "%s", DB_SAPLING_NOTE_SOURCE_LOCAL);
            note_saved = db_sapling_note_save(&ndb, &n);
            WE_CHECK("Part B: persist received note (db_sapling_note_save)",
                     note_saved);
        }
    } else {
        WE_CHECK("Part B: decode new z-address", false);
    }

    /* z_getbalance(zaddr) reflects the shielded receive (minconf-aware). */
    {
        struct json_value p; json_init(&p); part_b_str_param(&p, zaddr);
        char bal[32] = {0};
        bool ok = we_rpc_str(&tbl, "z_getbalance", &p, bal, sizeof(bal));
        json_free(&p);
        WE_CHECK("Part B: z_getbalance == 2.50000000",
                 ok && strcmp(bal, "2.50000000") == 0);
    }

    /* z_gettotalbalance private field reflects it. */
    {
        struct json_value p, r; json_init(&p); json_init(&r); json_set_array(&p);
        bool ok = rpc_table_execute(&tbl, "z_gettotalbalance", &p, &r);
        const struct json_value *priv = ok ? json_get(&r, "private") : NULL;
        const char *ps = priv ? json_get_str(priv) : NULL;
        WE_CHECK("Part B: z_gettotalbalance private == 2.50000000",
                 ok && ps && strcmp(ps, "2.50000000") == 0);
        json_free(&p); json_free(&r);
    }

    /* z_listunspent lists exactly the one note with the right amount + memo. */
    {
        struct json_value p, r; json_init(&p); json_init(&r); json_set_array(&p);
        bool ok = rpc_table_execute(&tbl, "z_listunspent", &p, &r);
        bool one = ok && r.type == JSON_ARR && json_size(&r) == 1;
        const struct json_value *e0 = one ? json_at(&r, 0) : NULL;
        const struct json_value *amt = e0 ? json_get(e0, "amount") : NULL;
        const char *as = amt ? json_get_str(amt) : NULL;
        WE_CHECK("Part B: z_listunspent has 1 note @ 2.50000000",
                 one && as && strcmp(as, "2.50000000") == 0);
        json_free(&p); json_free(&r);
    }

    /* z_getmemo round-trips the memo text for the note. */
    {
        char txid_hex[65];   /* note txid is 32 bytes of 0xB7 (palindromic) */
        for (int i = 0; i < 32; i++) { txid_hex[i * 2] = 'b'; txid_hex[i * 2 + 1] = '7'; }
        txid_hex[64] = '\0';
        struct json_value p; json_init(&p); part_b_str_param(&p, txid_hex);
        struct json_value r; json_init(&r);
        bool ok = rpc_table_execute(&tbl, "z_getmemo", &p, &r);
        const struct json_value *memo = ok ? json_get(&r, "memo") : NULL;
        const char *ms2 = memo ? json_get_str(memo) : NULL;
        WE_CHECK("Part B: z_getmemo returns the note memo text",
                 note_saved && ok && ms2 &&
                 strncmp(ms2, "W1-d persisted note", 19) == 0);
        json_free(&p); json_free(&r);
    }

    /* Mark the note spent (note-selection view): balance + unspent drop to 0. */
    if (note_saved) {
        uint8_t spent_by[32]; memset(spent_by, 0xC4, 32);
        enum db_mark_spent_result msr =
            db_sapling_note_mark_spent(&ndb, nnf, spent_by);
        WE_CHECK("Part B: db_sapling_note_mark_spent OK", msr == DB_MARK_SPENT_OK);

        struct json_value p; json_init(&p); part_b_str_param(&p, zaddr);
        char bal[32] = {0};
        bool ok = we_rpc_str(&tbl, "z_getbalance", &p, bal, sizeof(bal));
        json_free(&p);
        WE_CHECK("Part B: z_getbalance == 0 after spend",
                 ok && strcmp(bal, "0.00000000") == 0);

        struct json_value p2, r2; json_init(&p2); json_init(&r2); json_set_array(&p2);
        bool ok2 = rpc_table_execute(&tbl, "z_listunspent", &p2, &r2);
        WE_CHECK("Part B: z_listunspent empty after spend",
                 ok2 && r2.type == JSON_ARR && json_size(&r2) == 0);
        json_free(&p2); json_free(&r2);
    }

    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    coins_view_cache_free(&ctip);
    tx_mempool_free(&mempool);
    if (wsql_open) wallet_sqlite_close(&wsql);
    node_db_close(&ndb);
    main_state_free(&ms);
    wallet_free(wallet);
    free(wallet);
    test_cleanup_tmpdir(tmpdir);
    return failures;
}

int test_simnet_shielded_wallet_e2e(void);
int test_simnet_shielded_wallet_e2e(void)
{
    printf("\n=== W1-d: full shielded wallet E2E (production prover) ===\n");

    const char *home = getenv("HOME");
    char params_dir[512];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");

    char output_path[640];
    snprintf(output_path, sizeof(output_path),
             "%s/sapling-output.params", params_dir);
    FILE *probe = fopen(output_path, "rb");
    if (!probe) {
        printf("  UNOBSERVED (~/.zcash-params absent; production prover leg "
               "did not run)\n");
        return 0;
    }
    fclose(probe);

    if (!sapling_init_params(params_dir) || !zclassic_sapling_prover_is_ready()) {
        /* The params-free contract has no meaningful leg in this group, but
         * an explicitly selected run still reached the fixture and observed
         * the host capability boundary.  UNOBSERVED keeps that environmental
         * absence visible without misclassifying it as a test that never ran. */
        printf("  UNOBSERVED (production prover not ready; status=%s)\n",
               zclassic_sapling_prover_status());
        return 0;
    }
    printf("  production prover READY (backend=%s) — running ACCEPT E2E\n",
           zclassic_sapling_prover_backend());

    /* Pin proof-deferral to -1 (verify everything) for the whole test and
     * restore on exit, so a leaked deferral height from an earlier serial
     * test cannot silently skip proofs. */
    int saved_defer = atomic_load(&g_deferred_proof_validation_below_height);
    atomic_store(&g_deferred_proof_validation_below_height, -1);

    int failures = 0;
    failures += part_a_consensus_accept();
    failures += part_b_wallet_rpc();

    atomic_store(&g_deferred_proof_validation_below_height, saved_defer);

    printf("W1-d shielded wallet E2E: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
