/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "validation/tx_verifier.h"
#include "script/sighashtype.h"
#include "util/log_macros.h"
#include <string.h>

void tx_sig_checker_init(struct tx_sig_checker *c,
                         const struct transaction *tx,
                         unsigned int nIn,
                         int64_t amount,
                         uint32_t consensus_branch_id,
                         const struct precomputed_tx_data *txdata)
{
    c->tx = tx;
    c->nIn = nIn;
    c->amount = amount;
    c->consensus_branch_id = consensus_branch_id;
    c->txdata = txdata;
}

static bool check_sig_cb(const struct sig_checker *self,
                         const unsigned char *sig, size_t siglen,
                         const unsigned char *pubkey, size_t pubkeylen,
                         const struct script *script_code,
                         uint32_t consensus_branch_id)
{
    struct tx_sig_checker *c = (struct tx_sig_checker *)self->ctx;
    (void)consensus_branch_id;

    if (siglen == 0)
        LOG_FAIL("tx_verify", "empty signature (siglen=0)");

    struct pubkey pk;
    pubkey_set(&pk, pubkey, (unsigned int)pubkeylen);
    if (!pubkey_is_valid(&pk))
        LOG_FAIL("tx_verify", "invalid pubkey (len=%zu)", pubkeylen);

    struct sighash_type ht = { .raw = sig[siglen - 1] };

    struct uint256 sighash;
    if (!signature_hash(script_code, c->tx, c->nIn, ht, c->amount,
                        c->consensus_branch_id, c->txdata, &sighash))
        LOG_FAIL("tx_verify", "sighash computation failed for input %u", c->nIn);

    return pubkey_verify(&pk, &sighash, sig, siglen - 1);
}

static bool check_lock_time_cb(const struct sig_checker *self,
                                int64_t lock_time)
{
    struct tx_sig_checker *c = (struct tx_sig_checker *)self->ctx;

    if (!((c->tx->lock_time < LOCKTIME_THRESHOLD &&
           lock_time < (int64_t)LOCKTIME_THRESHOLD) ||
          (c->tx->lock_time >= LOCKTIME_THRESHOLD &&
           lock_time >= (int64_t)LOCKTIME_THRESHOLD)))
        LOG_FAIL("tx_verify", "lock_time type mismatch: script=%lld tx=%u",
                 (long long)lock_time, c->tx->lock_time);

    if (lock_time > (int64_t)c->tx->lock_time)
        LOG_FAIL("tx_verify", "lock_time %lld > tx lock_time %u",
                 (long long)lock_time, c->tx->lock_time);

    if (c->tx->vin[c->nIn].sequence == 0xffffffff)
        LOG_FAIL("tx_verify", "sequence is final (0xffffffff) for input %u", c->nIn);

    return true;
}

static bool verify_sig_cb(const struct sig_checker *self,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *pubkey, size_t pubkeylen,
                          const struct uint256 *sighash)
{
    (void)self;
    struct pubkey pk;
    pubkey_set(&pk, pubkey, (unsigned int)pubkeylen);
    if (!pubkey_is_valid(&pk))
        LOG_FAIL("tx_verify", "invalid pubkey in verify_sig (len=%zu)", pubkeylen);
    return pubkey_verify(&pk, sighash, sig, siglen);
}

struct sig_checker tx_make_sig_checker(struct tx_sig_checker *c)
{
    struct sig_checker checker;
    checker.check_sig = check_sig_cb;
    checker.check_lock_time = check_lock_time_cb;
    checker.verify_signature = verify_sig_cb;
    checker.ctx = c;
    return checker;
}

bool tx_sig_checker_check_sig(const struct tx_sig_checker *c,
                              const unsigned char *sig, size_t siglen,
                              const unsigned char *pubkey, size_t pubkeylen,
                              const struct script *script_code)
{
    struct sig_checker dummy;
    dummy.ctx = (void *)c;
    return check_sig_cb(&dummy, sig, siglen, pubkey, pubkeylen, script_code,
                        c->consensus_branch_id);
}

bool tx_sig_checker_check_lock_time(const struct tx_sig_checker *c,
                                    int64_t lock_time)
{
    struct sig_checker dummy;
    dummy.ctx = (void *)c;
    return check_lock_time_cb(&dummy, lock_time);
}
