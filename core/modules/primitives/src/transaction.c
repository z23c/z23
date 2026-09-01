/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "primitives/transaction.h"
#include "core/hash.h"
#include "core/serialize.h"
#include <stdlib.h>
#include <stdio.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* Logging policy for this file:
 *
 *   Stream read/write failures inside (de)serializers propagate as plain
 *   `return false;` — they fire on every truncated peer message during
 *   IBD, and logging at every site would flood node.log. Callers
 *   (core/modules/net/src/msg_tx.c, core/modules/net/src/compact_blocks.c,
 *   core/modules/primitives/src/block.c) emit a single LOG_FAIL / event at the
 *   parser boundary instead.
 *
 *   Real errors — consensus bound violations (MAX_TX_INPUTS,
 *   MAX_SCRIPT_SIZE, MAX_SHIELDED_*, MAX_JOINSPLITS), version sanity,
 *   alloc failure, MoneyRange — DO use LOG_FAIL / LOG_RETURN with
 *   specific context. These indicate either a DoS-bound attack or an
 *   out-of-memory condition; both are interesting in node.log. */

void transaction_init(struct transaction *tx)
{
    tx->overwintered = false;
    tx->version = 1;
    tx->version_group_id = 0;
    tx->vin = NULL;
    tx->num_vin = 0;
    tx->vout = NULL;
    tx->num_vout = 0;
    tx->lock_time = 0;
    tx->expiry_height = 0;
    tx->value_balance = 0;
    tx->v_shielded_spend = NULL;
    tx->num_shielded_spend = 0;
    tx->v_shielded_output = NULL;
    tx->num_shielded_output = 0;
    tx->v_joinsplit = NULL;
    tx->num_joinsplit = 0;
    uint256_set_null(&tx->joinsplit_pubkey);
    memset(tx->joinsplit_sig, 0, 64);
    memset(tx->binding_sig, 0, 64);
    uint256_set_null(&tx->hash);
}

void transaction_free(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
    free(tx->v_shielded_spend);
    free(tx->v_shielded_output);
    free(tx->v_joinsplit);
    tx->vin = NULL;
    tx->vout = NULL;
    tx->v_shielded_spend = NULL;
    tx->v_shielded_output = NULL;
    tx->v_joinsplit = NULL;
    tx->num_vin = 0;
    tx->num_vout = 0;
    tx->num_shielded_spend = 0;
    tx->num_shielded_output = 0;
    tx->num_joinsplit = 0;
}

/* Negative = production: element arrays are left indeterminate outside the
 * fields the per-element initializers write. See transaction.h. */
static int g_alloc_poison = -1;

int transaction_alloc_poison_set(int fill_byte)
{
    int prev = g_alloc_poison;
    g_alloc_poison = fill_byte;
    return prev;
}

/* Shared body of tx_in_array_alloc / tx_out_array_alloc. `count` is bounded
 * by MAX_TX_INPUTS / MAX_TX_OUTPUTS (65536) at every call site and elem_size
 * is ~10 KB, so count*elem_size tops out near 660 MB and cannot overflow. */
static void *tx_array_alloc(size_t count, size_t elem_size, const char *label)
{
    if (count == 0)
        return NULL;   /* no 1-byte stub — see transaction_alloc */
    size_t bytes = count * elem_size;
    void *p = zcl_malloc(bytes, label);
    if (p && g_alloc_poison >= 0)
        memset(p, g_alloc_poison, bytes);
    return p;
}

struct tx_in *tx_in_array_alloc(size_t count, const char *label)
{
    return tx_array_alloc(count, sizeof(struct tx_in), label);
}

struct tx_out *tx_out_array_alloc(size_t count, const char *label)
{
    return tx_array_alloc(count, sizeof(struct tx_out), label);
}

bool transaction_alloc(struct transaction *tx, size_t num_vin, size_t num_vout)
{
    if (num_vin > MAX_TX_INPUTS || num_vout > MAX_TX_OUTPUTS)
        LOG_FAIL("tx", "alloc out of range: vin=%zu (max %d) vout=%zu (max %d)",
                 num_vin, MAX_TX_INPUTS, num_vout, MAX_TX_OUTPUTS);

    /* Zero-size calls must not allocate. glibc's calloc(0, n) returns a
     * unique 1-byte pointer that must be freed; callers that later replace
     * tx->vin/tx->vout with a fresh allocation (e.g. transaction_deserialize
     * partial paths) would silently leak that stub. Treat zero as "no
     * array" and leave the pointer NULL so transaction_free is a no-op.
     *
     * Not zero-filled: the tx_in_init / tx_out_set_null loops below define
     * every field, and the script tail past `.size` is never read. */
    tx->vin  = tx_in_array_alloc(num_vin,  "tx_vin");
    tx->vout = tx_out_array_alloc(num_vout, "tx_vout");
    if ((num_vin && !tx->vin) || (num_vout && !tx->vout)) {
        free(tx->vin);
        free(tx->vout);
        tx->vin = NULL;
        tx->vout = NULL;
        LOG_FAIL("tx", "alloc failed: vin=%zu (%zu MB) vout=%zu",
                 num_vin, num_vin * sizeof(struct tx_in) / (1024*1024), num_vout);
    }
    tx->num_vin = num_vin;
    tx->num_vout = num_vout;

    for (size_t i = 0; i < num_vin; i++)
        tx_in_init(&tx->vin[i]);
    for (size_t i = 0; i < num_vout; i++)
        tx_out_set_null(&tx->vout[i]);

    return true;
}

bool transaction_copy(struct transaction *dst, const struct transaction *src)
{
    transaction_init(dst);
    dst->overwintered = src->overwintered;
    dst->version = src->version;
    dst->version_group_id = src->version_group_id;
    dst->lock_time = src->lock_time;
    dst->expiry_height = src->expiry_height;
    dst->value_balance = src->value_balance;
    dst->hash = src->hash;

    if (!transaction_alloc(dst, src->num_vin, src->num_vout)) {
        transaction_free(dst);
        return false;
    }

    for (size_t i = 0; i < src->num_vin; i++) {
        dst->vin[i].prevout = src->vin[i].prevout;
        dst->vin[i].sequence = src->vin[i].sequence;
        memcpy(dst->vin[i].script_sig.data, src->vin[i].script_sig.data,
               src->vin[i].script_sig.size);
        dst->vin[i].script_sig.size = src->vin[i].script_sig.size;
    }

    for (size_t i = 0; i < src->num_vout; i++) {
        dst->vout[i].value = src->vout[i].value;
        memcpy(dst->vout[i].script_pub_key.data,
               src->vout[i].script_pub_key.data,
               src->vout[i].script_pub_key.size);
        dst->vout[i].script_pub_key.size = src->vout[i].script_pub_key.size;
    }

    if (src->num_shielded_spend > 0) {
        dst->v_shielded_spend = zcl_calloc(src->num_shielded_spend,
                                        sizeof(struct spend_description), "tx_shielded_spend");
        if (!dst->v_shielded_spend) {
            transaction_free(dst);
            LOG_FAIL("tx", "calloc failed for %zu shielded_spend descs",
                     src->num_shielded_spend);
        }
        dst->num_shielded_spend = src->num_shielded_spend;
        memcpy(dst->v_shielded_spend, src->v_shielded_spend,
               src->num_shielded_spend * sizeof(struct spend_description));
    }

    if (src->num_shielded_output > 0) {
        dst->v_shielded_output = zcl_calloc(src->num_shielded_output,
                                         sizeof(struct output_description), "tx_shielded_output");
        if (!dst->v_shielded_output) {
            transaction_free(dst);
            LOG_FAIL("tx", "calloc failed for %zu shielded_output descs",
                     src->num_shielded_output);
        }
        dst->num_shielded_output = src->num_shielded_output;
        memcpy(dst->v_shielded_output, src->v_shielded_output,
               src->num_shielded_output * sizeof(struct output_description));
    }

    if (src->num_joinsplit > 0) {
        dst->v_joinsplit = zcl_calloc(src->num_joinsplit,
                                   sizeof(struct js_description), "tx_joinsplit");
        if (!dst->v_joinsplit) {
            transaction_free(dst);
            LOG_FAIL("tx", "calloc failed for %zu joinsplit descs",
                     src->num_joinsplit);
        }
        dst->num_joinsplit = src->num_joinsplit;
        memcpy(dst->v_joinsplit, src->v_joinsplit,
               src->num_joinsplit * sizeof(struct js_description));
    }

    dst->joinsplit_pubkey = src->joinsplit_pubkey;
    memcpy(dst->joinsplit_sig, src->joinsplit_sig, 64);
    memcpy(dst->binding_sig, src->binding_sig, 64);

    return true;
}

int64_t transaction_get_value_out(const struct transaction *tx)
{
    int64_t total = 0;
    for (size_t i = 0; i < tx->num_vout; i++) {
        total += tx->vout[i].value;
        if (!MoneyRange(tx->vout[i].value) || !MoneyRange(total))
            LOG_RETURN(-1, "tx", "vout[%zu] MoneyRange violation: value=%lld total=%lld",
                       i, (long long)tx->vout[i].value, (long long)total);
    }

    if (tx->value_balance <= 0) {
        int64_t neg = -tx->value_balance;
        total += neg;
        if (!MoneyRange(neg) || !MoneyRange(total))
            LOG_RETURN(-1, "tx", "value_balance MoneyRange violation: neg=%lld total=%lld",
                       (long long)neg, (long long)total);
    }

    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        total += tx->v_joinsplit[i].vpub_old;
        if (!MoneyRange(tx->v_joinsplit[i].vpub_old) || !MoneyRange(total))
            LOG_RETURN(-1, "tx", "joinsplit[%zu].vpub_old MoneyRange violation: vpub=%lld total=%lld",
                       i, (long long)tx->v_joinsplit[i].vpub_old, (long long)total);
    }
    return total;
}

int64_t transaction_get_shielded_value_in(const struct transaction *tx)
{
    int64_t total = 0;
    if (tx->value_balance >= 0) {
        total += tx->value_balance;
        if (!MoneyRange(tx->value_balance) || !MoneyRange(total))
            LOG_RETURN(-1, "tx", "value_balance(in) MoneyRange violation: vb=%lld total=%lld",
                       (long long)tx->value_balance, (long long)total);
    }
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        total += tx->v_joinsplit[i].vpub_new;
        if (!MoneyRange(tx->v_joinsplit[i].vpub_new) || !MoneyRange(total))
            LOG_RETURN(-1, "tx", "joinsplit[%zu].vpub_new MoneyRange violation: vpub=%lld total=%lld",
                       i, (long long)tx->v_joinsplit[i].vpub_new, (long long)total);
    }
    return total;
}

bool outpoint_serialize(const struct outpoint *op, struct byte_stream *s)
{
    return stream_write_bytes(s, op->hash.data, 32) &&
           stream_write_u32_le(s, op->n);
}

bool outpoint_deserialize(struct outpoint *op, struct byte_stream *s)
{
    return stream_read_bytes(s, op->hash.data, 32) &&
           stream_read_u32_le(s, &op->n);
}

bool tx_in_serialize(const struct tx_in *in, struct byte_stream *s)
{
    if (!outpoint_serialize(&in->prevout, s)) return false;
    if (!stream_write_compact_size(s, in->script_sig.size)) return false;
    if (in->script_sig.size > 0 &&
        !stream_write_bytes(s, in->script_sig.data, in->script_sig.size))
        return false;
    return stream_write_u32_le(s, in->sequence);
}

bool tx_in_deserialize(struct tx_in *in, struct byte_stream *s)
{
    if (!outpoint_deserialize(&in->prevout, s)) return false;
    uint64_t script_len;
    if (!stream_read_compact_size(s, &script_len)) return false;
    if (script_len > MAX_SCRIPT_SIZE)
        LOG_FAIL("tx", "input script_sig too large: %llu > MAX_SCRIPT_SIZE(%d)",
                 (unsigned long long)script_len, MAX_SCRIPT_SIZE);
    /* Set .size only AFTER the bytes are in. A short stream must not leave a
     * script claiming `size` bytes over buffer content that was never
     * written — the element arrays are no longer zero-filled, so that would
     * be a window of indeterminate bytes behind a non-zero length. The
     * accept/reject decision is unchanged either way (it is driven by the
     * read failing, never by content); this only keeps the rejected object
     * describing itself honestly. */
    if (script_len > 0 &&
        !stream_read_bytes(s, in->script_sig.data, (size_t)script_len))
        return false;
    in->script_sig.size = (size_t)script_len;
    return stream_read_u32_le(s, &in->sequence);
}

bool tx_out_serialize(const struct tx_out *out, struct byte_stream *s)
{
    if (!stream_write_i64_le(s, out->value)) return false;
    if (!stream_write_compact_size(s, out->script_pub_key.size)) return false;
    if (out->script_pub_key.size > 0)
        return stream_write_bytes(s, out->script_pub_key.data,
                                  out->script_pub_key.size);
    return true;
}

bool tx_out_deserialize(struct tx_out *out, struct byte_stream *s)
{
    if (!stream_read_i64_le(s, &out->value)) return false;
    uint64_t script_len;
    if (!stream_read_compact_size(s, &script_len)) return false;
    if (script_len > MAX_SCRIPT_SIZE)
        LOG_FAIL("tx", "output script_pub_key too large: %llu > MAX_SCRIPT_SIZE(%d)",
                 (unsigned long long)script_len, MAX_SCRIPT_SIZE);
    /* .size after the read, for the reason given in tx_in_deserialize. */
    if (script_len > 0 &&
        !stream_read_bytes(s, out->script_pub_key.data, (size_t)script_len))
        return false;
    out->script_pub_key.size = (size_t)script_len;
    return true;
}

bool spend_description_serialize(const struct spend_description *sd,
                                  struct byte_stream *s)
{
    return stream_write_bytes(s, sd->cv.data, 32) &&
           stream_write_bytes(s, sd->anchor.data, 32) &&
           stream_write_bytes(s, sd->nullifier.data, 32) &&
           stream_write_bytes(s, sd->rk.data, 32) &&
           stream_write_bytes(s, sd->zkproof, GROTH_PROOF_SIZE) &&
           stream_write_bytes(s, sd->spend_auth_sig, 64);
}

bool spend_description_deserialize(struct spend_description *sd,
                                    struct byte_stream *s)
{
    return stream_read_bytes(s, sd->cv.data, 32) &&
           stream_read_bytes(s, sd->anchor.data, 32) &&
           stream_read_bytes(s, sd->nullifier.data, 32) &&
           stream_read_bytes(s, sd->rk.data, 32) &&
           stream_read_bytes(s, sd->zkproof, GROTH_PROOF_SIZE) &&
           stream_read_bytes(s, sd->spend_auth_sig, 64);
}

bool output_description_serialize(const struct output_description *od,
                                   struct byte_stream *s)
{
    return stream_write_bytes(s, od->cv.data, 32) &&
           stream_write_bytes(s, od->cm.data, 32) &&
           stream_write_bytes(s, od->ephemeral_key.data, 32) &&
           stream_write_bytes(s, od->enc_ciphertext, ZC_SAPLING_ENCCIPHERTEXT_SIZE) &&
           stream_write_bytes(s, od->out_ciphertext, ZC_SAPLING_OUTCIPHERTEXT_SIZE) &&
           stream_write_bytes(s, od->zkproof, GROTH_PROOF_SIZE);
}

bool output_description_deserialize(struct output_description *od,
                                     struct byte_stream *s)
{
    return stream_read_bytes(s, od->cv.data, 32) &&
           stream_read_bytes(s, od->cm.data, 32) &&
           stream_read_bytes(s, od->ephemeral_key.data, 32) &&
           stream_read_bytes(s, od->enc_ciphertext, ZC_SAPLING_ENCCIPHERTEXT_SIZE) &&
           stream_read_bytes(s, od->out_ciphertext, ZC_SAPLING_OUTCIPHERTEXT_SIZE) &&
           stream_read_bytes(s, od->zkproof, GROTH_PROOF_SIZE);
}

bool js_description_serialize(const struct js_description *jsd,
                               struct byte_stream *s)
{
    if (!stream_write_i64_le(s, jsd->vpub_old)) return false;
    if (!stream_write_i64_le(s, jsd->vpub_new)) return false;
    if (!stream_write_bytes(s, jsd->anchor.data, 32)) return false;
    for (int i = 0; i < ZC_NUM_JS_INPUTS; i++)
        if (!stream_write_bytes(s, jsd->nullifiers[i].data, 32)) return false;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++)
        if (!stream_write_bytes(s, jsd->commitments[i].data, 32)) return false;
    if (!stream_write_bytes(s, jsd->ephemeral_key.data, 32)) return false;
    if (!stream_write_bytes(s, jsd->random_seed.data, 32)) return false;
    for (int i = 0; i < ZC_NUM_JS_INPUTS; i++)
        if (!stream_write_bytes(s, jsd->macs[i].data, 32)) return false;

    size_t proof_size = jsd->use_groth ? GROTH_PROOF_SIZE : PHGR_PROOF_SIZE;
    if (!stream_write_bytes(s, jsd->proof, proof_size)) return false;

    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++)
        if (!stream_write_bytes(s, jsd->ciphertexts[i], ZC_SPROUT_CIPHERTEXT_SIZE))
            return false;
    return true;
}

bool js_description_deserialize(struct js_description *jsd, bool use_groth,
                                 struct byte_stream *s)
{
    jsd->use_groth = use_groth;
    if (!stream_read_i64_le(s, &jsd->vpub_old)) return false;
    if (!stream_read_i64_le(s, &jsd->vpub_new)) return false;
    if (!stream_read_bytes(s, jsd->anchor.data, 32)) return false;
    for (int i = 0; i < ZC_NUM_JS_INPUTS; i++)
        if (!stream_read_bytes(s, jsd->nullifiers[i].data, 32)) return false;
    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++)
        if (!stream_read_bytes(s, jsd->commitments[i].data, 32)) return false;
    if (!stream_read_bytes(s, jsd->ephemeral_key.data, 32)) return false;
    if (!stream_read_bytes(s, jsd->random_seed.data, 32)) return false;
    for (int i = 0; i < ZC_NUM_JS_INPUTS; i++)
        if (!stream_read_bytes(s, jsd->macs[i].data, 32)) return false;

    size_t proof_size = use_groth ? GROTH_PROOF_SIZE : PHGR_PROOF_SIZE;
    memset(jsd->proof, 0, PHGR_PROOF_SIZE);
    if (!stream_read_bytes(s, jsd->proof, proof_size)) return false;

    for (int i = 0; i < ZC_NUM_JS_OUTPUTS; i++)
        if (!stream_read_bytes(s, jsd->ciphertexts[i], ZC_SPROUT_CIPHERTEXT_SIZE))
            return false;
    return true;
}

bool transaction_hash_serialized(const struct transaction *tx,
                                 struct uint256 *out)
{
    if (!tx || !out) {
        LOG_FAIL("transaction", "hash_serialized: NULL %s",
                 tx ? "out" : "tx");
        return false;
    }
    struct byte_stream s;
    stream_init(&s, 4096);
    if (!transaction_serialize(tx, &s)) {
        LOG_FAIL("transaction",
                 "hash_serialized: serialize failed (alloc or stream)");
        stream_free(&s);
        return false;
    }
    hash256(s.data, s.size, out->data);
    stream_free(&s);
    return true;
}

void transaction_compute_hash(struct transaction *tx)
{
    /* Thin mutating wrapper over the const sibling. On serialize
     * failure (only reachable via OOM on the growable scratch stream)
     * tx->hash is left untouched: at least deterministic. Hashing a
     * partial scratch buffer would be neither. */
    (void)transaction_hash_serialized(tx, &tx->hash);
}

bool transaction_serialize(const struct transaction *tx, struct byte_stream *s)
{
    uint32_t header = (uint32_t)tx->version;
    if (tx->overwintered) header |= (1u << 31);
    if (!stream_write_u32_le(s, header)) return false;

    if (tx->overwintered)
        if (!stream_write_u32_le(s, tx->version_group_id)) return false;

    bool is_overwinter_v3 = tx->overwintered &&
        tx->version_group_id == OVERWINTER_VERSION_GROUP_ID &&
        tx->version == OVERWINTER_TX_VERSION;
    bool is_sapling_v4 = tx->overwintered &&
        tx->version_group_id == SAPLING_VERSION_GROUP_ID &&
        tx->version == SAPLING_TX_VERSION;

    if (!stream_write_compact_size(s, tx->num_vin)) return false;
    for (size_t i = 0; i < tx->num_vin; i++)
        if (!tx_in_serialize(&tx->vin[i], s)) return false;

    if (!stream_write_compact_size(s, tx->num_vout)) return false;
    for (size_t i = 0; i < tx->num_vout; i++)
        if (!tx_out_serialize(&tx->vout[i], s)) return false;

    if (!stream_write_u32_le(s, tx->lock_time)) return false;

    if (is_overwinter_v3 || is_sapling_v4)
        if (!stream_write_u32_le(s, tx->expiry_height)) return false;

    if (is_sapling_v4) {
        if (!stream_write_i64_le(s, tx->value_balance)) return false;

        if (!stream_write_compact_size(s, tx->num_shielded_spend)) return false;
        for (size_t i = 0; i < tx->num_shielded_spend; i++)
            if (!spend_description_serialize(&tx->v_shielded_spend[i], s))
                return false;

        if (!stream_write_compact_size(s, tx->num_shielded_output)) return false;
        for (size_t i = 0; i < tx->num_shielded_output; i++)
            if (!output_description_serialize(&tx->v_shielded_output[i], s))
                return false;
    }

    if (tx->version >= 2) {
        if (!stream_write_compact_size(s, tx->num_joinsplit)) return false;
        bool use_groth = tx->overwintered && tx->version >= SAPLING_TX_VERSION;
        for (size_t i = 0; i < tx->num_joinsplit; i++)
            if (!js_description_serialize(&tx->v_joinsplit[i], s))
                return false;
        (void)use_groth;

        if (tx->num_joinsplit > 0) {
            if (!stream_write_bytes(s, tx->joinsplit_pubkey.data, 32))
                return false;
            if (!stream_write_bytes(s, tx->joinsplit_sig, 64))
                return false;
        }
    }

    if (is_sapling_v4 &&
        (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0)) {
        if (!stream_write_bytes(s, tx->binding_sig, 64))
            return false;
    }

    return true;
}

bool transaction_deserialize(struct transaction *tx, struct byte_stream *s)
{
    transaction_init(tx);

    uint32_t header;
    if (!stream_read_u32_le(s, &header)) return false;
    tx->overwintered = (header >> 31) != 0;
    tx->version = (int32_t)(header & 0x7FFFFFFF);

    if (tx->overwintered) {
        if (!stream_read_u32_le(s, &tx->version_group_id)) return false;
    }

    bool is_overwinter_v3 = tx->overwintered &&
        tx->version_group_id == OVERWINTER_VERSION_GROUP_ID &&
        tx->version == OVERWINTER_TX_VERSION;
    bool is_sapling_v4 = tx->overwintered &&
        tx->version_group_id == SAPLING_VERSION_GROUP_ID &&
        tx->version == SAPLING_TX_VERSION;

    if (tx->overwintered && !(is_overwinter_v3 || is_sapling_v4))
        LOG_FAIL("tx", "unrecognized overwintered version: version=%d group_id=0x%08x",
                 tx->version, tx->version_group_id);

    uint64_t num_vin;
    if (!stream_read_compact_size(s, &num_vin)) return false;
    if (num_vin > MAX_TX_INPUTS)
        LOG_FAIL("tx", "num_vin out of range: %llu > MAX_TX_INPUTS(%d)",
                 (unsigned long long)num_vin, MAX_TX_INPUTS);
    /* Reject before the giant calloc when the remaining stream cannot
     * possibly hold num_vin entries. A vin is >=41 wire bytes (outpoint 36 +
     * 1-byte compact scriptSig length + 4-byte sequence). num_vin is already
     * <=MAX_TX_INPUTS(65536), so num_vin*41 cannot overflow. This refuses only
     * counts that the element loop would fail to read anyway (so the accept
     * set is unchanged) BEFORE transaction_alloc page-touches ~627 MB. */
    if (num_vin * 41 > stream_remaining(s))
        LOG_FAIL("tx", "num_vin %llu exceeds remaining bytes %zu (>=41/vin)",
                 (unsigned long long)num_vin, stream_remaining(s));
    if (!transaction_alloc(tx, (size_t)num_vin, 0)) return false;

    for (size_t i = 0; i < tx->num_vin; i++)
        if (!tx_in_deserialize(&tx->vin[i], s)) return false;

    uint64_t num_vout;
    if (!stream_read_compact_size(s, &num_vout)) return false;
    if (num_vout > MAX_TX_OUTPUTS)
        LOG_FAIL("tx", "num_vout out of range: %llu > MAX_TX_OUTPUTS(%d)",
                 (unsigned long long)num_vout, MAX_TX_OUTPUTS);
    /* A vout is >=9 wire bytes (8-byte value + 1-byte compact scriptPubKey
     * length). num_vout <=MAX_TX_OUTPUTS(65536), so num_vout*9 cannot
     * overflow. Reject implausible counts before the ~626 MB calloc. */
    if (num_vout * 9 > stream_remaining(s))
        LOG_FAIL("tx", "num_vout %llu exceeds remaining bytes %zu (>=9/vout)",
                 (unsigned long long)num_vout, stream_remaining(s));
    tx->vout = tx_out_array_alloc((size_t)num_vout, "tx_vout");
    if (num_vout > 0 && !tx->vout)
        LOG_FAIL("tx", "alloc failed for %llu tx_vout entries",
                 (unsigned long long)num_vout);
    tx->num_vout = (size_t)num_vout;
    for (size_t i = 0; i < tx->num_vout; i++) {
        tx_out_set_null(&tx->vout[i]);
        if (!tx_out_deserialize(&tx->vout[i], s)) return false;
    }

    if (!stream_read_u32_le(s, &tx->lock_time)) return false;

    if (is_overwinter_v3 || is_sapling_v4) {
        if (!stream_read_u32_le(s, &tx->expiry_height)) return false;
    }

    if (is_sapling_v4) {
        if (!stream_read_i64_le(s, &tx->value_balance)) return false;

        uint64_t num_spend;
        if (!stream_read_compact_size(s, &num_spend)) return false;
        if (num_spend > MAX_SHIELDED_SPENDS)
            LOG_FAIL("tx", "num_shielded_spend out of range: %llu > MAX_SHIELDED_SPENDS(%d)",
                     (unsigned long long)num_spend, MAX_SHIELDED_SPENDS);
        /* A spend description is a fixed 384 wire bytes (cv32+anchor32+
         * nullifier32+rk32+zkproof192+spendAuthSig64). num_spend
         * <=MAX_SHIELDED_SPENDS(4096), so num_spend*384 cannot overflow. */
        if (num_spend * 384 > stream_remaining(s))
            LOG_FAIL("tx", "num_shielded_spend %llu exceeds remaining bytes %zu (384/spend)",
                     (unsigned long long)num_spend, stream_remaining(s));
        if (num_spend > 0) {
            tx->v_shielded_spend = zcl_calloc((size_t)num_spend,
                                           sizeof(struct spend_description), "tx_shielded_spend");
            if (!tx->v_shielded_spend)
                LOG_FAIL("tx", "calloc failed for %llu shielded_spend entries",
                         (unsigned long long)num_spend);
            tx->num_shielded_spend = (size_t)num_spend;
            for (size_t i = 0; i < tx->num_shielded_spend; i++)
                if (!spend_description_deserialize(&tx->v_shielded_spend[i], s))
                    return false;
        }

        uint64_t num_output;
        if (!stream_read_compact_size(s, &num_output)) return false;
        if (num_output > MAX_SHIELDED_OUTPUTS)
            LOG_FAIL("tx", "num_shielded_output out of range: %llu > MAX_SHIELDED_OUTPUTS(%d)",
                     (unsigned long long)num_output, MAX_SHIELDED_OUTPUTS);
        /* An output description is a fixed 948 wire bytes (cv32+cm32+
         * ephemeralKey32+encCiphertext580+outCiphertext80+zkproof192).
         * num_output <=MAX_SHIELDED_OUTPUTS(4096), so num_output*948 cannot
         * overflow. */
        if (num_output * 948 > stream_remaining(s))
            LOG_FAIL("tx", "num_shielded_output %llu exceeds remaining bytes %zu (948/output)",
                     (unsigned long long)num_output, stream_remaining(s));
        if (num_output > 0) {
            tx->v_shielded_output = zcl_calloc((size_t)num_output,
                                            sizeof(struct output_description), "tx_shielded_output");
            if (!tx->v_shielded_output)
                LOG_FAIL("tx", "calloc failed for %llu shielded_output entries",
                         (unsigned long long)num_output);
            tx->num_shielded_output = (size_t)num_output;
            for (size_t i = 0; i < tx->num_shielded_output; i++)
                if (!output_description_deserialize(&tx->v_shielded_output[i], s))
                    return false;
        }
    }

    if (tx->version >= 2) {
        bool use_groth = tx->overwintered && tx->version >= SAPLING_TX_VERSION;
        uint64_t num_js;
        if (!stream_read_compact_size(s, &num_js)) return false;
        if (num_js > MAX_JOINSPLITS)
            LOG_FAIL("tx", "num_joinsplit out of range: %llu > MAX_JOINSPLITS(%d)",
                     (unsigned long long)num_js, MAX_JOINSPLITS);
        /* A joinsplit description is >=1634 wire bytes: 1442 fixed bytes
         * (vpub_old8+vpub_new8+anchor32+nullifiers64+commitments64+
         * ephemeralKey32+randomSeed32+macs64+ciphertexts1138) plus the
         * proof, which is the SMALLER GROTH form (192) here so the guard
         * never false-rejects the larger PHGR form (296). num_js
         * <=MAX_JOINSPLITS(4096), so num_js*1634 cannot overflow. */
        if (num_js * 1634 > stream_remaining(s))
            LOG_FAIL("tx", "num_joinsplit %llu exceeds remaining bytes %zu (>=1634/js)",
                     (unsigned long long)num_js, stream_remaining(s));
        if (num_js > 0) {
            tx->v_joinsplit = zcl_calloc((size_t)num_js,
                                      sizeof(struct js_description), "tx_joinsplit");
            if (!tx->v_joinsplit)
                LOG_FAIL("tx", "calloc failed for %llu joinsplit entries",
                         (unsigned long long)num_js);
            tx->num_joinsplit = (size_t)num_js;
            for (size_t i = 0; i < tx->num_joinsplit; i++)
                if (!js_description_deserialize(&tx->v_joinsplit[i],
                                                 use_groth, s))
                    return false;

            if (!stream_read_bytes(s, tx->joinsplit_pubkey.data, 32))
                return false;
            if (!stream_read_bytes(s, tx->joinsplit_sig, 64))
                return false;
        }
    }

    if (is_sapling_v4 &&
        (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0)) {
        if (!stream_read_bytes(s, tx->binding_sig, 64))
            return false;
    }

    transaction_compute_hash(tx);
    return true;
}

size_t transaction_serialize_size(const struct transaction *tx)
{
    struct byte_stream s;
    stream_init(&s, 4096);
    transaction_serialize(tx, &s);
    size_t result = s.size;
    stream_free(&s);
    return result;
}
