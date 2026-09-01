/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_contract — HTLC / escrow contract overlay over the deterministic
 * simnet. See sim/simnet_contract.h for the enforced-vs-skipped contract.
 */

#include "sim/simnet_contract.h"

#include "core/amount.h"
#include "core/hash.h"
#include "core/uint256.h"
#include "crypto/sha256.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/script_flags.h"
#include "script/standard.h"
#include "sim/simnet_mempool.h"
#include "sim/simnet_wallet.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <string.h>

/* A stub scriptSig signature. In-sim the script is never executed; in the
 * direct-interpreter check the signature-accepting checker decides validity —
 * BUT OP_CHECKSIG still runs the canonical-DER encoding gate on the signature
 * BYTES before calling the checker, so the stub must be well-formed DER. This
 * is a minimal 8-byte DER body {30 06 02 01 01 02 01 01} + a 1-byte sighash
 * (0x01), the same shape tests/harness/src/test_multisig_consensus_branches.c
 * relies on. */
static const uint8_t SC_STUB_SIG[] =
    { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };
#define SC_STUB_SIG_LEN (sizeof(SC_STUB_SIG))

bool simnet_contract_htlc_init(struct simnet_contract_htlc *c,
                               const uint8_t secret[32],
                               const uint8_t recipient_pubkey[33],
                               const uint8_t refunder_pubkey[33],
                               uint32_t locktime)
{
    if (!c || !secret || !recipient_pubkey || !refunder_pubkey)
        LOG_FAIL("simnet.contract", "htlc_init NULL argument");

    memset(c, 0, sizeof(*c));
    memcpy(c->secret, secret, 32);
    memcpy(c->recipient_pubkey, recipient_pubkey, 33);
    memcpy(c->refunder_pubkey, refunder_pubkey, 33);
    c->locktime = locktime;

    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, c->secret, 32);
    sha256_finalize(&ctx, c->secret_hash);

    /* pkh = HASH160(pubkey): binds the script's OP_HASH160 guard to the
     * pubkey each scriptSig will carry, so the guard is satisfied and the
     * preimage equality is the only variable in the redeem-path check. */
    hash160(c->recipient_pubkey, 33, c->recipient_pkh);
    hash160(c->refunder_pubkey, 33, c->refunder_pkh);

    struct htlc_params hp;
    memset(&hp, 0, sizeof(hp));
    memcpy(hp.secret_hash, c->secret_hash, 32);
    memcpy(hp.recipient_pkh, c->recipient_pkh, 20);
    memcpy(hp.refunder_pkh, c->refunder_pkh, 20);
    hp.locktime = locktime;

    c->contract_len = htlc_build_script(&hp, c->contract, HTLC_CONTRACT_SIZE);
    if (c->contract_len != HTLC_CONTRACT_SIZE)
        LOG_FAIL("simnet.contract", "htlc_build_script wrong size %zu",
                 c->contract_len);

    struct script redeem;
    script_set(&redeem, c->contract, c->contract_len);
    struct script_id sid;
    script_id_from_script(&sid, &redeem);
    script_for_p2sh(&c->p2sh, &sid);
    return true;
}

bool simnet_contract_fund(struct simnet *s, struct simnet_wallet *funder,
                          const struct simnet_contract_htlc *c, int64_t value,
                          struct simnet_tx_result *out)
{
    if (!s || !funder || !c || value <= 0)
        LOG_FAIL("simnet.contract", "fund bad argument");

    if (!simnet_wallet_send(funder, &c->p2sh, value, out))
        LOG_FAIL("simnet.contract", "funding send rejected");
    if (!simnet_mempool_mint(s))
        LOG_FAIL("simnet.contract", "mint of funding block failed");
    if (!simnet_coin_value(s, &out->txid, 0, NULL))
        LOG_FAIL("simnet.contract", "funded coin absent post-mint");
    return true;
}

/* Assemble a single-input P2SH spend with a caller-built scriptSig, then set
 * the output value to input - fee at the simnet default rate. */
static bool sc_build_spend(struct transaction *tx,
                           const struct uint256 *fund_txid,
                           int64_t fund_value,
                           const uint8_t *script_sig, size_t ss_len,
                           const struct script *pay_to,
                           uint32_t lock_time, uint32_t sequence,
                           struct simnet_tx_result *out)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        LOG_FAIL("simnet.contract", "transaction_alloc failed");

    tx->version = 1;
    tx->lock_time = lock_time;
    tx->vin[0].prevout.hash = *fund_txid;
    tx->vin[0].prevout.n = 0;
    script_set(&tx->vin[0].script_sig, script_sig, ss_len);
    tx->vin[0].sequence = sequence;
    tx->vout[0].value = fund_value; /* placeholder; fee applied below */
    tx->vout[0].script_pub_key = *pay_to;
    transaction_compute_hash(tx);

    struct fee_rate rate = simnet_wallet_default_fee_rate();
    size_t size = transaction_serialize_size(tx);
    int64_t fee = fee_rate_get_fee(&rate, size);
    if (fee <= 0 || fund_value <= fee) {
        transaction_free(tx);
        LOG_FAIL("simnet.contract", "fee %lld exceeds input value %lld",
                 (long long)fee, (long long)fund_value);
    }
    tx->vout[0].value = fund_value - fee;
    transaction_compute_hash(tx);

    if (out) {
        memset(out, 0, sizeof(*out));
        out->txid = tx->hash;
        out->fee = fee;
        out->tx_size = transaction_serialize_size(tx);
        out->input_value = fund_value;
        out->output_value = fund_value - fee;
        out->change_vout = UINT32_MAX;
    }
    return true;
}

bool simnet_contract_build_redeem(struct transaction *tx,
                                  const struct uint256 *fund_txid,
                                  int64_t fund_value,
                                  const struct simnet_contract_htlc *c,
                                  const uint8_t preimage[32],
                                  const struct script *pay_to,
                                  struct simnet_tx_result *out)
{
    if (!tx || !fund_txid || !c || !preimage || !pay_to)
        LOG_FAIL("simnet.contract", "build_redeem NULL argument");

    uint8_t ss[256];
    size_t ss_len = htlc_build_redeem_scriptsig(ss, sizeof(ss), SC_STUB_SIG,
                                                SC_STUB_SIG_LEN,
                                                c->recipient_pubkey, 33,
                                                preimage, c->contract,
                                                c->contract_len);
    if (ss_len == 0)
        LOG_FAIL("simnet.contract", "redeem scriptSig build failed");

    /* Redeem path: final tx (nLockTime=0, sequence=0). */
    return sc_build_spend(tx, fund_txid, fund_value, ss, ss_len, pay_to,
                          0u, 0u, out);
}

bool simnet_contract_build_refund(struct transaction *tx,
                                  const struct uint256 *fund_txid,
                                  int64_t fund_value,
                                  const struct simnet_contract_htlc *c,
                                  const struct script *pay_to,
                                  struct simnet_tx_result *out)
{
    if (!tx || !fund_txid || !c || !pay_to)
        LOG_FAIL("simnet.contract", "build_refund NULL argument");

    uint8_t ss[256];
    size_t ss_len = htlc_build_refund_scriptsig(ss, sizeof(ss), SC_STUB_SIG,
                                                SC_STUB_SIG_LEN,
                                                c->refunder_pubkey, 33,
                                                c->contract, c->contract_len);
    if (ss_len == 0)
        LOG_FAIL("simnet.contract", "refund scriptSig build failed");

    /* Refund path: nLockTime=locktime, non-final sequence (0xFFFFFFFE). The
     * non-final sequence is what makes domain_consensus_tx_is_final() gate
     * this until the tip reaches locktime. */
    return sc_build_spend(tx, fund_txid, fund_value, ss, ss_len, pay_to,
                          c->locktime, 0xFFFFFFFEu, out);
}

/* Signature-accepting checker: isolates the preimage guard for the direct
 * interpreter run. check_sig always succeeds, check_lock_time always succeeds
 * (the redeem/IF branch never reaches OP_CLTV anyway). */
static bool sc_checker_check_sig(const struct sig_checker *self,
                                 const unsigned char *sig, size_t siglen,
                                 const unsigned char *pubkey, size_t pklen,
                                 const struct script *script_code,
                                 uint32_t consensus_branch_id)
{
    (void)self; (void)sig; (void)siglen; (void)pubkey; (void)pklen;
    (void)script_code; (void)consensus_branch_id;
    return true;
}

static bool sc_checker_check_lock_time(const struct sig_checker *self,
                                       int64_t lock_time)
{
    (void)self; (void)lock_time;
    return true;
}

bool simnet_contract_check_redeem_script(const struct simnet_contract_htlc *c,
                                         const uint8_t preimage[32],
                                         int *out_script_err)
{
    if (out_script_err)
        *out_script_err = (int)SCRIPT_ERR_OK;
    if (!c || !preimage)
        LOG_FAIL("simnet.contract", "check_redeem_script NULL argument");

    uint8_t ss[256];
    size_t ss_len = htlc_build_redeem_scriptsig(ss, sizeof(ss), SC_STUB_SIG,
                                                SC_STUB_SIG_LEN,
                                                c->recipient_pubkey, 33,
                                                preimage, c->contract,
                                                c->contract_len);
    if (ss_len == 0)
        LOG_FAIL("simnet.contract", "check_redeem_script scriptSig build");

    struct script script_sig, script_pub_key;
    script_set(&script_sig, ss, ss_len);
    script_pub_key = c->p2sh;

    struct sig_checker checker;
    memset(&checker, 0, sizeof(checker));
    checker.check_sig = sc_checker_check_sig;
    checker.check_lock_time = sc_checker_check_lock_time;

    ScriptError serror = SCRIPT_ERR_OK;
    bool ok = verify_script(&script_sig, &script_pub_key,
                            SCRIPT_VERIFY_P2SH, &checker, 0, &serror);
    if (out_script_err)
        *out_script_err = (int)serror;
    return ok;
}
