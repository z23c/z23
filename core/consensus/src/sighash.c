/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure transaction signature-hash computation. Replays bit-for-bit
 * from inputs alone. No clock, RNG, allocation, or I/O. */

#include "domain/consensus/sighash.h"

#include "core/hash.h"
#include "core/serialize.h"
#include "crypto/blake2b.h"
#include "util/log_macros.h"

#include <string.h>

static const unsigned char PREVOUTS_PERSONAL[16] =
    {'Z','c','a','s','h','P','r','e','v','o','u','t','H','a','s','h'};
static const unsigned char SEQUENCE_PERSONAL[16] =
    {'Z','c','a','s','h','S','e','q','u','e','n','c','H','a','s','h'};
static const unsigned char OUTPUTS_PERSONAL[16] =
    {'Z','c','a','s','h','O','u','t','p','u','t','s','H','a','s','h'};
static const unsigned char JOINSPLITS_PERSONAL[16] =
    {'Z','c','a','s','h','J','S','p','l','i','t','s','H','a','s','h'};
static const unsigned char SHIELDED_SPENDS_PERSONAL[16] =
    {'Z','c','a','s','h','S','S','p','e','n','d','s','H','a','s','h'};
static const unsigned char SHIELDED_OUTPUTS_PERSONAL[16] =
    {'Z','c','a','s','h','S','O','u','t','p','u','t','H','a','s','h'};

static void blake2b_hash_personal(const unsigned char *data, size_t len,
                                   const unsigned char personal[16],
                                   struct uint256 *out)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, personal);
    blake2b_update(&ctx, data, len);
    blake2b_final(&ctx, out->data, 32);
}

static void get_prevout_hash(const struct transaction *tx, struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 256);
    for (size_t i = 0; i < tx->num_vin; i++)
        outpoint_serialize(&tx->vin[i].prevout, &s);
    blake2b_hash_personal(s.data, s.size, PREVOUTS_PERSONAL, out);
    stream_free(&s);
}

static void get_sequence_hash(const struct transaction *tx, struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 256);
    for (size_t i = 0; i < tx->num_vin; i++)
        stream_write_u32_le(&s, tx->vin[i].sequence);
    blake2b_hash_personal(s.data, s.size, SEQUENCE_PERSONAL, out);
    stream_free(&s);
}

static void get_outputs_hash(const struct transaction *tx, struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 256);
    for (size_t i = 0; i < tx->num_vout; i++)
        tx_out_serialize(&tx->vout[i], &s);
    blake2b_hash_personal(s.data, s.size, OUTPUTS_PERSONAL, out);
    stream_free(&s);
}

static void get_joinsplits_hash(const struct transaction *tx, struct uint256 *out)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, JOINSPLITS_PERSONAL);
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        const struct js_description *js = &tx->v_joinsplit[i];
        blake2b_update(&ctx, &js->vpub_old, 8);
        blake2b_update(&ctx, &js->vpub_new, 8);
        blake2b_update(&ctx, js->anchor.data, 32);
        for (int j = 0; j < ZC_NUM_JS_INPUTS; j++)
            blake2b_update(&ctx, js->nullifiers[j].data, 32);
        for (int j = 0; j < ZC_NUM_JS_OUTPUTS; j++)
            blake2b_update(&ctx, js->commitments[j].data, 32);
        blake2b_update(&ctx, js->ephemeral_key.data, 32);
        blake2b_update(&ctx, js->random_seed.data, 32);
        for (int j = 0; j < ZC_NUM_JS_INPUTS; j++)
            blake2b_update(&ctx, js->macs[j].data, 32);
        size_t proof_size = js->use_groth ? GROTH_PROOF_SIZE : PHGR_PROOF_SIZE;
        blake2b_update(&ctx, js->proof, proof_size);
        for (int j = 0; j < ZC_NUM_JS_OUTPUTS; j++)
            blake2b_update(&ctx, js->ciphertexts[j], ZC_SPROUT_CIPHERTEXT_SIZE);
    }
    blake2b_update(&ctx, tx->joinsplit_pubkey.data, 32);
    blake2b_final(&ctx, out->data, 32);
}

static void get_shielded_spends_hash(const struct transaction *tx, struct uint256 *out)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, SHIELDED_SPENDS_PERSONAL);
    for (size_t i = 0; i < tx->num_shielded_spend; i++) {
        const struct spend_description *sd = &tx->v_shielded_spend[i];
        blake2b_update(&ctx, sd->cv.data, 32);
        blake2b_update(&ctx, sd->anchor.data, 32);
        blake2b_update(&ctx, sd->nullifier.data, 32);
        blake2b_update(&ctx, sd->rk.data, 32);
        blake2b_update(&ctx, sd->zkproof, GROTH_PROOF_SIZE);
        /* Note: spendAuthSig is NOT included in sighash */
    }
    blake2b_final(&ctx, out->data, 32);
}

static void get_shielded_outputs_hash(const struct transaction *tx, struct uint256 *out)
{
    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, SHIELDED_OUTPUTS_PERSONAL);
    for (size_t i = 0; i < tx->num_shielded_output; i++) {
        const struct output_description *od = &tx->v_shielded_output[i];
        blake2b_update(&ctx, od->cv.data, 32);
        blake2b_update(&ctx, od->cm.data, 32);
        blake2b_update(&ctx, od->ephemeral_key.data, 32);
        blake2b_update(&ctx, od->enc_ciphertext, ZC_SAPLING_ENCCIPHERTEXT_SIZE);
        blake2b_update(&ctx, od->out_ciphertext, ZC_SAPLING_OUTCIPHERTEXT_SIZE);
        blake2b_update(&ctx, od->zkproof, GROTH_PROOF_SIZE);
    }
    blake2b_final(&ctx, out->data, 32);
}

void domain_consensus_precompute_tx_data(
        const struct transaction *tx,
        struct domain_consensus_precomputed_tx_data *out)
{
    get_prevout_hash(tx, &out->hash_prevouts);
    get_sequence_hash(tx, &out->hash_sequence);
    get_outputs_hash(tx, &out->hash_outputs);
    if (tx->num_joinsplit > 0)
        get_joinsplits_hash(tx, &out->hash_joinsplits);
    else
        uint256_set_null(&out->hash_joinsplits);
    if (tx->num_shielded_spend > 0)
        get_shielded_spends_hash(tx, &out->hash_shielded_spends);
    else
        uint256_set_null(&out->hash_shielded_spends);
    if (tx->num_shielded_output > 0)
        get_shielded_outputs_hash(tx, &out->hash_shielded_outputs);
    else
        uint256_set_null(&out->hash_shielded_outputs);
}

enum domain_consensus_sig_version
domain_consensus_signature_hash_version(const struct transaction *tx)
{
    if (tx->overwintered) {
        if (tx->version_group_id == SAPLING_VERSION_GROUP_ID)
            return DOMAIN_CONSENSUS_SIGVERSION_SAPLING;
        return DOMAIN_CONSENSUS_SIGVERSION_OVERWINTER;
    }
    return DOMAIN_CONSENSUS_SIGVERSION_SPROUT;
}

static uint32_t tx_get_header(const struct transaction *tx)
{
    return tx->version | (tx->overwintered ? (1U << 31) : 0);
}

/* Prevout and sequence digests for this sighash type, or null when omitted. */
static void sighash_overwinter_prevout_sequence(
    const struct transaction *tx,
    struct sighash_type hash_type,
    const struct domain_consensus_precomputed_tx_data *cache,
    struct uint256 *hash_prevouts,
    struct uint256 *hash_sequence)
{
    memset(hash_prevouts, 0, sizeof(*hash_prevouts));
    memset(hash_sequence, 0, sizeof(*hash_sequence));

    struct uint256 null_hash;
    uint256_set_null(&null_hash);

    if (!sighash_has_anyone_can_pay(hash_type)) {
        if (cache)
            *hash_prevouts = cache->hash_prevouts;
        else
            get_prevout_hash(tx, hash_prevouts);
    } else {
        *hash_prevouts = null_hash;
    }

    if (!sighash_has_anyone_can_pay(hash_type) &&
        sighash_get_base_type(hash_type) != BASE_SIGHASH_SINGLE &&
        sighash_get_base_type(hash_type) != BASE_SIGHASH_NONE) {
        if (cache)
            *hash_sequence = cache->hash_sequence;
        else
            get_sequence_hash(tx, hash_sequence);
    } else {
        *hash_sequence = null_hash;
    }
}

/* Outputs digest: all outputs, the single output at nIn, or the null hash. */
static void sighash_overwinter_outputs(
    const struct transaction *tx,
    unsigned int nIn,
    struct sighash_type hash_type,
    const struct domain_consensus_precomputed_tx_data *cache,
    struct uint256 *hash_outputs)
{
    memset(hash_outputs, 0, sizeof(*hash_outputs));

    struct uint256 null_hash;
    uint256_set_null(&null_hash);

    if (sighash_get_base_type(hash_type) != BASE_SIGHASH_SINGLE &&
        sighash_get_base_type(hash_type) != BASE_SIGHASH_NONE) {
        if (cache)
            *hash_outputs = cache->hash_outputs;
        else
            get_outputs_hash(tx, hash_outputs);
    } else if (sighash_get_base_type(hash_type) == BASE_SIGHASH_SINGLE &&
               nIn < tx->num_vout) {
        struct byte_stream s;
        stream_init(&s, 256);
        tx_out_serialize(&tx->vout[nIn], &s);
        blake2b_hash_personal(s.data, s.size, OUTPUTS_PERSONAL, hash_outputs);
        stream_free(&s);
    } else {
        *hash_outputs = null_hash;
    }
}

/* Write script_code->size as a compact-size prefix into varbuf and set *varlen. */
static void sighash_script_compact_size(
    const struct script *script_code,
    unsigned char varbuf[9],
    size_t *varlen)
{
    *varlen = 0;
    memset(varbuf, 0, 9);
    if (script_code->size < 0xfd) {
        varbuf[0] = (unsigned char)script_code->size;
        *varlen = 1;
    } else if (script_code->size <= 0xffff) {
        varbuf[0] = 0xfd;
        uint16_t s16 = (uint16_t)script_code->size;
        memcpy(varbuf + 1, &s16, 2);
        *varlen = 3;
    } else if (script_code->size <= 0xffffffffUL) {
        varbuf[0] = 0xfe;
        uint32_t s32 = (uint32_t)script_code->size;
        memcpy(varbuf + 1, &s32, 4);
        *varlen = 5;
    } else {
        varbuf[0] = 0xff;
        uint64_t s64 = (uint64_t)script_code->size;
        memcpy(varbuf + 1, &s64, 8);
        *varlen = 9;
    }
}

static bool sighash_overwinter_sapling(
    const struct script *script_code,
    const struct transaction *tx,
    unsigned int nIn,
    struct sighash_type hash_type,
    int64_t amount,
    uint32_t consensus_branch_id,
    const struct domain_consensus_precomputed_tx_data *cache,
    enum domain_consensus_sig_version sigversion,
    struct uint256 *result)
{
    struct uint256 hash_prevouts, hash_sequence, hash_outputs;
    sighash_overwinter_prevout_sequence(tx, hash_type, cache,
                                        &hash_prevouts, &hash_sequence);
    sighash_overwinter_outputs(tx, nIn, hash_type, cache, &hash_outputs);

    uint32_t le_branch = consensus_branch_id;
    unsigned char personalization[16] = {0};
    memcpy(personalization, "ZcashSigHash", 12);
    memcpy(personalization + 12, &le_branch, 4);

    struct blake2b_ctx ctx;
    blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, personalization);

    uint32_t header = tx_get_header(tx);
    blake2b_update(&ctx, &header, 4);
    blake2b_update(&ctx, &tx->version_group_id, 4);
    blake2b_update(&ctx, hash_prevouts.data, 32);
    blake2b_update(&ctx, hash_sequence.data, 32);
    blake2b_update(&ctx, hash_outputs.data, 32);

    /* JoinSplits hash */
    {
        struct uint256 hash_joinsplits;
        if (tx->num_joinsplit > 0) {
            if (cache)
                hash_joinsplits = cache->hash_joinsplits;
            else
                get_joinsplits_hash(tx, &hash_joinsplits);
        } else {
            uint256_set_null(&hash_joinsplits);
        }
        blake2b_update(&ctx, hash_joinsplits.data, 32);
    }

    if (sigversion == DOMAIN_CONSENSUS_SIGVERSION_SAPLING) {
        /* ShieldedSpends hash */
        struct uint256 hash_shielded_spends;
        if (tx->num_shielded_spend > 0) {
            if (cache)
                hash_shielded_spends = cache->hash_shielded_spends;
            else
                get_shielded_spends_hash(tx, &hash_shielded_spends);
        } else {
            uint256_set_null(&hash_shielded_spends);
        }
        blake2b_update(&ctx, hash_shielded_spends.data, 32);

        /* ShieldedOutputs hash */
        struct uint256 hash_shielded_outputs;
        if (tx->num_shielded_output > 0) {
            if (cache)
                hash_shielded_outputs = cache->hash_shielded_outputs;
            else
                get_shielded_outputs_hash(tx, &hash_shielded_outputs);
        } else {
            uint256_set_null(&hash_shielded_outputs);
        }
        blake2b_update(&ctx, hash_shielded_outputs.data, 32);
    }

    blake2b_update(&ctx, &tx->lock_time, 4);
    blake2b_update(&ctx, &tx->expiry_height, 4);

    if (sigversion == DOMAIN_CONSENSUS_SIGVERSION_SAPLING) {
        blake2b_update(&ctx, &tx->value_balance, 8);
    }

    blake2b_update(&ctx, &hash_type.raw, 4);

    if (nIn != NOT_AN_INPUT) {
        /* Prevout */
        blake2b_update(&ctx, tx->vin[nIn].prevout.hash.data, 32);
        blake2b_update(&ctx, &tx->vin[nIn].prevout.n, 4);

        /* Script code as varint-length-prefixed bytes */
        unsigned char varbuf[9];
        size_t varlen = 0;
        sighash_script_compact_size(script_code, varbuf, &varlen);
        blake2b_update(&ctx, varbuf, varlen);
        blake2b_update(&ctx, script_code->data, script_code->size);

        blake2b_update(&ctx, &amount, 8);
        blake2b_update(&ctx, &tx->vin[nIn].sequence, 4);
    }

    blake2b_final(&ctx, result->data, 32);
    return true;
}

/* Serialize inputs */
static void sighash_sprout_write_inputs(
    struct byte_stream *s,
    const struct script *script_code,
    const struct transaction *tx,
    unsigned int nIn,
    struct sighash_type hash_type)
{
    unsigned int n_inputs = sighash_has_anyone_can_pay(hash_type) ? 1 : (unsigned int)tx->num_vin;
    stream_write_compact_size(s, n_inputs);
    for (unsigned int i = 0; i < n_inputs; i++) {
        unsigned int idx = sighash_has_anyone_can_pay(hash_type) ? nIn : i;

        outpoint_serialize(&tx->vin[idx].prevout, s);

        if (idx != nIn) {
            /* Blank out other inputs' scripts */
            stream_write_compact_size(s, 0);
        } else {
            stream_write_compact_size(s, script_code->size);
            stream_write_bytes(s, script_code->data, script_code->size);
        }

        if (idx != nIn &&
            (sighash_get_base_type(hash_type) == BASE_SIGHASH_SINGLE ||
             sighash_get_base_type(hash_type) == BASE_SIGHASH_NONE)) {
            stream_write_u32_le(s, 0);
        } else {
            stream_write_u32_le(s, tx->vin[idx].sequence);
        }
    }
}

static bool sighash_sprout(
    const struct script *script_code,
    const struct transaction *tx,
    unsigned int nIn,
    struct sighash_type hash_type,
    struct uint256 *result)
{
    struct byte_stream s;
    stream_init(&s, 256);

    stream_write_u32_le(&s, (uint32_t)tx->version);

    sighash_sprout_write_inputs(&s, script_code, tx, nIn, hash_type);

    /* Serialize outputs */
    unsigned int n_outputs;
    if (sighash_get_base_type(hash_type) == BASE_SIGHASH_NONE)
        n_outputs = 0;
    else if (sighash_get_base_type(hash_type) == BASE_SIGHASH_SINGLE)
        n_outputs = nIn + 1;
    else
        n_outputs = (unsigned int)tx->num_vout;

    stream_write_compact_size(&s, n_outputs);
    for (unsigned int i = 0; i < n_outputs; i++) {
        if (sighash_get_base_type(hash_type) == BASE_SIGHASH_SINGLE && i != nIn) {
            /* Null output */
            stream_write_i64_le(&s, -1);
            stream_write_compact_size(&s, 0);
        } else {
            tx_out_serialize(&tx->vout[i], &s);
        }
    }

    stream_write_u32_le(&s, tx->lock_time);

    /* Include JoinSplit data (required for Sprout JoinSplit signature).
     * Must match zclassicd CTransactionSignatureSerializer::Serialize
     * exactly: serialize vjoinsplit for version >= 2, then pubkey,
     * then a 64-byte null signature placeholder. */
    if (tx->version >= 2) {
        stream_write_compact_size(&s, tx->num_joinsplit);
        for (size_t i = 0; i < tx->num_joinsplit; i++)
            js_description_serialize(&tx->v_joinsplit[i], &s);
        if (tx->num_joinsplit > 0) {
            stream_write_bytes(&s, tx->joinsplit_pubkey.data, 32);
            /* Null signature — 64 zero bytes placeholder */
            uint8_t null_sig[64] = {0};
            stream_write_bytes(&s, null_sig, 64);
        }
    }

    stream_write_u32_le(&s, hash_type.raw);

    /* Double SHA-256 */
    hash256(s.data, s.size, result->data);
    stream_free(&s);
    return true;
}

bool domain_consensus_signature_hash(
        const struct script *script_code,
        const struct transaction *tx,
        unsigned int n_in,
        struct sighash_type hash_type,
        int64_t amount,
        uint32_t consensus_branch_id,
        const struct domain_consensus_precomputed_tx_data *cache,
        struct uint256 *result)
{
    if (n_in >= tx->num_vin && n_in != NOT_AN_INPUT)
        LOG_FAIL("sighash", "nIn=%u out of range (num_vin=%zu)", n_in, tx->num_vin);

    enum domain_consensus_sig_version sigver =
        domain_consensus_signature_hash_version(tx);

    if (sigver == DOMAIN_CONSENSUS_SIGVERSION_OVERWINTER ||
        sigver == DOMAIN_CONSENSUS_SIGVERSION_SAPLING) {
        return sighash_overwinter_sapling(script_code, tx, n_in, hash_type,
                                           amount, consensus_branch_id,
                                           cache, sigver, result);
    }

    /* CONSENSUS — do NOT "fix" this into Bitcoin's uint256(1) sentinel.
     * zclassicd THROWS here (zclassic-cpp/src/script/interpreter.cpp:1158-1163,
     * logic_error — Zcash deleted the Bitcoin one-hash sentinel) and
     * TransactionSignatureChecker::CheckSig catches it (:1197-1202) returning
     * false, so OP_CHECKSIG pushes false — exactly what this LOG_FAIL→false
     * produces via tx_verifier.c. Returning uint256(1)+true instead would
     * FORK: we'd accept a signature over constant hash 1 that zclassicd
     * rejects. The Overwinter/Sapling branch (:208-217 above) must keep
     * SUCCEEDING with the null outputs digest per ZIP-143/243 — do not
     * harmonize the regimes. Pinned end-to-end by test_sighash_edge.c. */
    if (sighash_get_base_type(hash_type) == BASE_SIGHASH_SINGLE &&
        n_in >= tx->num_vout)
        LOG_FAIL("sighash", "SIGHASH_SINGLE nIn=%u >= num_vout=%zu", n_in, tx->num_vout);

    return sighash_sprout(script_code, tx, n_in, hash_type, result);
}
