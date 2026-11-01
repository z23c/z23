/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure coinbase-transaction shaping. Replays from inputs alone.
 * No clock, RNG, allocation, or I/O. */

#include "domain/consensus/coinbase.h"

#include "consensus/params.h"
#include "consensus/upgrades.h"
#include "core/amount.h"
#include "primitives/transaction.h"
#include "script/script.h"

#include <string.h>

/* Heights are bounded so a minimal CScriptNum push always fits the
 * coinbase scriptSig buffer; 2^24-1 covers ~79 years of 2.5-minute blocks
 * past the cap with margin. (The cap is a builder-side guard only — the
 * validator parses whatever encoding is on disk.) */
#define DCB_HEIGHT_MAX 0x00FFFFFF /* 2^24 - 1 */

/* Replicate zclassicd's CScriptNum::serialize for a non-negative value:
 * minimal little-endian magnitude, with a trailing 0x00 sign byte appended
 * when the top byte's high bit is set (keeping the value non-negative).
 * Writes up to 5 bytes into `buf`, returns the byte count (0 for value 0).
 * This is the exact `CScriptNum(value).getvch()` for value >= 0. */
static size_t dcb_scriptnum_serialize(uint32_t value, uint8_t buf[5])
{
    size_t n = 0;
    uint32_t v = value;
    while (v) {
        buf[n++] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    if (n > 0 && (buf[n - 1] & 0x80))
        buf[n++] = 0x00; /* sign byte: value is positive */
    return n;
}

/* Replicate `CScript() << nHeight` (CScript::push_int64) for height >= 0:
 *   0        -> OP_0 (0x00)
 *   1..16    -> OP_1..OP_16 (0x50 + n), a single opcode byte
 *   else     -> minimal data push: [len][CScriptNum LE bytes]
 * Writes at `out->data + off`, returns the new offset. Byte-for-byte the
 * coinbase height encoding zclassicd's CreateNewBlock emits and its
 * ContextualCheckBlock BIP34 check (`CScript expect = CScript() << nHeight`)
 * verifies — so a block we mine is accepted by zclassicd and our own
 * bip34_check_coinbase_height at every height, not just where the magnitude
 * happens to be 3 bytes wide. */
static size_t dcb_push_height(struct script *out, size_t off, int n_height)
{
    if (n_height == 0) {
        out->data[off++] = 0x00; /* OP_0 */
    } else if (n_height >= 1 && n_height <= 16) {
        out->data[off++] = (uint8_t)(0x50 + n_height); /* OP_1..OP_16 */
    } else {
        uint8_t buf[5];
        size_t len = dcb_scriptnum_serialize((uint32_t)n_height, buf);
        out->data[off++] = (uint8_t)len; /* push N bytes (len < OP_PUSHDATA1) */
        memcpy(out->data + off, buf, len);
        off += len;
    }
    return off;
}

/* Replicate `CScript() << CScriptNum(value)` — ALWAYS a minimal data push
 * of the CScriptNum serialization (unlike `<< int`, small values are NOT
 * collapsed to OP_N). value 0 serializes to the empty vector, which the
 * `CScript << vector` operator pushes as a single length-0 byte (0x00).
 * Writes at `out->data + off`, returns the new offset. */
static size_t dcb_push_scriptnum(struct script *out, size_t off,
                                 uint32_t value)
{
    uint8_t buf[5];
    size_t len = dcb_scriptnum_serialize(value, buf);
    out->data[off++] = (uint8_t)len; /* len byte (0 for value 0) */
    memcpy(out->data + off, buf, len);
    off += len;
    return off;
}

struct zcl_result domain_consensus_coinbase_script_sig_placeholder(
        int n_height,
        struct script *out)
{
    if (!out)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT,
                       "coinbase_script_sig_placeholder: null out at height %d",
                       n_height);
    if (n_height < 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT,
                       "coinbase_script_sig_placeholder: negative height %d",
                       n_height);
    if (n_height > DCB_HEIGHT_MAX)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE,
                       "coinbase_script_sig_placeholder: height %d exceeds "
                       "builder height cap (2^24-1)", n_height);

    size_t n = dcb_push_height(out, 0, n_height); /* CScript() << nHeight */
    out->data[n++] = (uint8_t)OP_0;               /* << OP_0 (single byte) */
    out->size = (uint16_t)n;
    return ZCL_OK;
}

struct zcl_result domain_consensus_coinbase_script_sig_with_extra_nonce(
        int n_height,
        uint32_t extra_nonce,
        struct script *out)
{
    if (!out)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT,
                       "coinbase_script_sig_with_extra_nonce: null out at "
                       "height %d", n_height);
    if (n_height < 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT,
                       "coinbase_script_sig_with_extra_nonce: negative "
                       "height %d", n_height);
    if (n_height > DCB_HEIGHT_MAX)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE,
                       "coinbase_script_sig_with_extra_nonce: height %d "
                       "exceeds builder height cap (2^24-1)", n_height);

    /* `CScript() << nHeight << CScriptNum(nExtraNonce)` — exactly the
     * scriptSig zclassicd's IncrementExtraNonce builds (miner.cpp). The
     * extra nonce is a CScriptNum data push (minimal LE + sign byte), so a
     * zero nonce is a single length-0 byte (0x00), not a 4-byte field. */
    size_t n = dcb_push_height(out, 0, n_height);
    n = dcb_push_scriptnum(out, n, extra_nonce);
    out->size = (uint16_t)n;
    return ZCL_OK;
}

/* Reject null out_tx, null inputs, null params, null miner_script,
 * negative height, height above DCB_HEIGHT_MAX, negative fees, or
 * negative subsidy. Returns ZCL_OK when none of those hold. */
static struct zcl_result dcb_build_reject_bad_inputs(
        const struct domain_consensus_coinbase_inputs *in,
        const struct transaction *out_tx)
{
    if (!out_tx)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT,
                       "coinbase_build: null out_tx");
    if (!in)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NULL_PARAMS,
                       "coinbase_build: null inputs");
    if (!in->params)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NULL_PARAMS,
                       "coinbase_build: null consensus_params");
    if (!in->miner_script)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NULL_SCRIPT,
                       "coinbase_build: null miner_script");
    if (in->n_height < 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT,
                       "coinbase_build: negative height %d", in->n_height);
    if (in->n_height > DCB_HEIGHT_MAX)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE,
                       "coinbase_build: height %d exceeds builder height "
                       "cap (2^24-1)", in->n_height);
    if (in->total_fees < 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NEG_FEES,
                       "coinbase_build: negative fees %lld",
                       (long long)in->total_fees);
    if (in->subsidy < 0)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NEG_SUBSIDY,
                       "coinbase_build: negative subsidy %lld",
                       (long long)in->subsidy);
    return ZCL_OK;
}

struct zcl_result domain_consensus_coinbase_build(
        const struct domain_consensus_coinbase_inputs *in,
        struct transaction *out_tx)
{
    struct zcl_result input_err = dcb_build_reject_bad_inputs(in, out_tx);
    if (!input_err.ok)
        return input_err;
    if (out_tx->num_vin != 1 || out_tx->num_vout != 1 ||
        !out_tx->vin || !out_tx->vout)
        return ZCL_ERR(DOMAIN_CONSENSUS_COINBASE_ERR_NOT_PREALLOC,
                       "coinbase_build: out_tx not preallocated (vin=%zu/%p, "
                       "vout=%zu/%p; need 1/non-null each)",
                       out_tx->num_vin, (const void *)out_tx->vin,
                       out_tx->num_vout, (const void *)out_tx->vout);

    /* --- vin[0]: null prevout + placeholder height-OP_0 scriptSig. --- */
    uint256_set_null(&out_tx->vin[0].prevout.hash);
    out_tx->vin[0].prevout.n = 0xffffffff;

    struct zcl_result rs = domain_consensus_coinbase_script_sig_placeholder(
            in->n_height, &out_tx->vin[0].script_sig);
    if (!rs.ok)
        return rs;

    /* --- vout[0]: miner script + subsidy+fees. --- */
    out_tx->vout[0].script_pub_key = *in->miner_script;
    out_tx->vout[0].value = in->subsidy + in->total_fees;

    /* --- Version per epoch. Match legacy `create_new_block` precisely:
     *     - Sapling active -> v4 / 0x892F2085, overwintered=true (set by
     *       primitives helpers via the version_group_id field).
     *     - else Overwinter active -> v3 / 0x03C48270.
     *     - else: leave version/group_id as initialised (legacy code
     *       falls through to whatever transaction_init() set). --- */
    if (consensus_network_upgrade_active(in->params, in->n_height,
                                         UPGRADE_SAPLING)) {
        out_tx->version          = SAPLING_TX_VERSION;
        out_tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    } else if (consensus_network_upgrade_active(in->params, in->n_height,
                                                UPGRADE_OVERWINTER)) {
        out_tx->version          = OVERWINTER_TX_VERSION;
        out_tx->version_group_id = OVERWINTER_VERSION_GROUP_ID;
    }
    out_tx->expiry_height = 0;

    transaction_compute_hash(out_tx);
    return ZCL_OK;
}
