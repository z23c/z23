/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Swap settlement service — build + sign the transaction that spends an
 * HTLC P2SH funding output (redeem or refund). See the header for the
 * contract. The scriptSig push formats follow dcrdex RedeemP2SHContract /
 * RefundP2SHContract (Blue Oak Model License 1.0.0), implemented in
 * core/modules/script/src/htlc.c. */

#include "services/swap_settlement_service.h"
#include "script/htlc.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "validation/sighash.h"
#include "script/sighashtype.h"
#include "util/log_macros.h"
#include <inttypes.h>
#include <string.h>

/* Shared builder for both settlement paths. `secret` non-NULL selects the
 * redeem (claim) branch; NULL selects the refund branch. */
static struct zcl_result swap_settle_build(const struct swap_settle_ctx *c,
                                           const struct privkey *key,
                                           const struct pubkey *pub,
                                           uint32_t lock_time,
                                           uint32_t sequence,
                                           const uint8_t *secret,
                                           struct transaction *out)
{
    if (!c || !key || !pub || !out)
        return ZCL_ERR(-1, "swap_settle: NULL argument");

    /* Initialize out BEFORE the first thing that can fail. The public header
     * already promises "out_tx is initialized by the callee", and a caller
     * that believes it will transaction_free(out_tx) on the error path — over
     * whatever pointer and count its own stack happened to hold, since a
     * struct transaction declared in the caller's frame is uninitialized
     * until this call touches it. Five of the returns below are reachable
     * with entirely non-NULL arguments (contract length, funding value, fee,
     * fee >= funding), so the promise has to hold on every return, not only
     * on the ones past this line. Same shape as the peer-reachable wild free
     * fixed in compact_block_reconstruct() (bce343876). */
    transaction_init(out);

    if (!c->contract || c->contract_len == 0 || c->contract_len > 256)
        return ZCL_ERR(-2, "swap_settle: bad contract length %zu",
                       c->contract_len);
    if (c->funding_value <= 0)
        return ZCL_ERR(-3, "swap_settle: non-positive funding value %" PRId64,
                       c->funding_value);
    if (c->fee < 0)
        return ZCL_ERR(-4, "swap_settle: negative fee %" PRId64, c->fee);

    int64_t out_value = c->funding_value - c->fee;
    if (out_value <= 0)
        return ZCL_ERR(-5, "swap_settle: fee %" PRId64 " leaves no value "
                       "(funding %" PRId64 ")", c->fee, c->funding_value);

    if (!transaction_alloc(out, 1, 1))
        return ZCL_ERR(-6, "swap_settle: transaction_alloc(1,1) failed");

    out->overwintered = true;
    out->version = SAPLING_TX_VERSION;
    out->version_group_id = SAPLING_VERSION_GROUP_ID;
    out->expiry_height = c->expiry_height;
    out->lock_time = lock_time;

    out->vin[0].prevout = c->funding;
    out->vin[0].sequence = sequence;
    out->vin[0].script_sig.size = 0;

    out->vout[0].value = out_value;
    out->vout[0].script_pub_key = c->dest_spk;

    /* scriptCode for the sighash is the full HTLC contract (BIP16 P2SH). */
    struct script script_code;
    script_init(&script_code);
    memcpy(script_code.data, c->contract, c->contract_len);
    script_code.size = c->contract_len;

    struct precomputed_tx_data txdata;
    precompute_tx_data(out, &txdata);

    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 sighash;
    if (!signature_hash(&script_code, out, 0, ht, c->funding_value,
                        c->branch_id, &txdata, &sighash)) {
        transaction_free(out);
        return ZCL_ERR(-7, "swap_settle: signature_hash failed");
    }

    unsigned char sig[SIGNATURE_SIZE + 1];
    size_t siglen = 0;
    if (!privkey_sign(key, &sighash, sig, &siglen)) {
        transaction_free(out);
        return ZCL_ERR(-8, "swap_settle: privkey_sign failed");
    }
    sig[siglen++] = (unsigned char)SIGHASH_ALL;

    uint8_t ss[512];
    size_t sslen;
    if (secret)
        sslen = htlc_build_redeem_scriptsig(ss, sizeof(ss), sig, siglen,
                                            pub->vch, pub->size, secret,
                                            c->contract, c->contract_len);
    else
        sslen = htlc_build_refund_scriptsig(ss, sizeof(ss), sig, siglen,
                                            pub->vch, pub->size,
                                            c->contract, c->contract_len);
    if (sslen == 0 || sslen > MAX_SCRIPT_SIZE) {
        transaction_free(out);
        return ZCL_ERR(-9, "swap_settle: scriptSig build failed (len=%zu)",
                       sslen);
    }

    memcpy(out->vin[0].script_sig.data, ss, sslen);
    out->vin[0].script_sig.size = sslen;

    transaction_compute_hash(out);
    return ZCL_OK;
}

struct zcl_result swap_settlement_build_redeem(const struct swap_settle_ctx *c,
                                               const struct privkey *key,
                                               const struct pubkey *pub,
                                               const uint8_t secret[32],
                                               struct transaction *out_tx)
{
    if (!secret)
        return ZCL_ERR(-1, "swap_settlement_build_redeem: NULL secret");
    /* Claim path: no CLTV constraint, so the input can be final. */
    return swap_settle_build(c, key, pub, /*lock_time=*/0,
                             /*sequence=*/0xFFFFFFFFu, secret, out_tx);
}

struct zcl_result swap_settlement_build_refund(const struct swap_settle_ctx *c,
                                               const struct privkey *key,
                                               const struct pubkey *pub,
                                               uint32_t locktime,
                                               struct transaction *out_tx)
{
    if (locktime == 0)
        return ZCL_ERR(-1, "swap_settlement_build_refund: locktime is 0 "
                       "(contract has no refund deadline)");
    /* Refund path: lock_time must reach the contract CLTV, and the input
     * must be non-final (sequence != 0xFFFFFFFF) or CLTV is skipped. */
    return swap_settle_build(c, key, pub, /*lock_time=*/locktime,
                             /*sequence=*/0xFFFFFFFEu, /*secret=*/NULL,
                             out_tx);
}
