/* purpose: Check a v6 P2PKH input against authenticated prevout data. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "transaction_v6_transparent_internal.h"
#include "primitives/transaction_v6_decode.h"
#include "script/interpreter.h"
#include "validation/tx_verifier.h"
#include "core/serialize.h"
#include "util/log_macros.h"
#include <limits.h>

struct checker_context {
    struct sig_checker native;
    const struct transaction *tx;
    const struct transaction_v6_prevout *prevouts;
    const struct script *script;
    size_t count, index;
};
static bool check_lock_time(const struct sig_checker *checker, int64_t lock_time)
{
    const struct checker_context *c = checker->ctx;
    return c->native.check_lock_time(&c->native, lock_time);
}
static bool verify_signature(const struct sig_checker *checker, const unsigned char *sig, size_t siglen,
    const unsigned char *key, size_t keylen, const struct uint256 *hash)
{
    const struct checker_context *c = checker->ctx;
    return c->native.verify_signature(&c->native, sig, siglen, key, keylen, hash);
}
static bool check_signature(const struct sig_checker *checker, const unsigned char *sig, size_t siglen,
    const unsigned char *key, size_t keylen, const struct script *code, uint32_t branch)
{
    (void)code;
    const struct checker_context *c = checker->ctx;
    if (!siglen || keylen > UINT_MAX) return false;
    struct uint256 hash;
    struct sighash_type type = {.raw = sig[siglen - 1]};
    if (!transaction_v6_sighash(c->tx, c->prevouts, c->count, (unsigned)c->index, type,
                                c->script, c->prevouts[c->index].amount, branch, &hash))
        LOG_FAIL("tx", "Cannot compute v6 P2PKH signature hash");
    return c->native.verify_signature(&c->native, sig, siglen - 1, key, keylen, &hash);
}
static struct zcl_result verify_decoded(const struct transaction *tx,
    const struct transaction_v6_prevout *prevouts, size_t count, size_t index,
    uint32_t expected_branch, unsigned int script_flags)
{
    if (count != tx->num_vin || index >= count || index > UINT_MAX ||
        !v6_transparent_prevouts_valid(prevouts, count))
        return ZCL_ERR(-1, "Invalid v6 P2PKH prevouts");
    const struct transaction_v6_prevout *prev = &prevouts[index];
    if (prev->script_size != 25 || !prev->script) return ZCL_ERR(-1, "Expected a P2PKH prevout");
    struct script pub; script_set(&pub, prev->script, prev->script_size);
    if (!script_is_p2pkh(&pub)) return ZCL_ERR(-1, "Expected a P2PKH prevout");
    struct tx_sig_checker native_context;
    tx_sig_checker_init(&native_context, tx, (unsigned)index, prev->amount, expected_branch, NULL);
    struct checker_context context = {tx_make_sig_checker(&native_context), tx, prevouts, &pub, count, index};
    struct sig_checker checker = {.check_sig = check_signature, .check_lock_time = check_lock_time,
                                  .verify_signature = verify_signature, .ctx = &context};
    ScriptError error;
    if (!verify_script(&tx->vin[index].script_sig, &pub, script_flags, &checker, expected_branch, &error))
        return ZCL_ERR(-1, "Invalid v6 P2PKH signature");
    return ZCL_OK;
}
struct zcl_result v6_transparent_verify_p2pkh(const uint8_t *wire, size_t length,
    const struct transaction_v6_prevout *prevouts, size_t count, size_t index,
    uint32_t expected_branch, unsigned int script_flags)
{
    if (!wire || !prevouts || count > SIZE_MAX / sizeof *prevouts)
        return ZCL_ERR(-1, "Invalid v6 P2PKH inputs");
    struct transaction tx; struct byte_stream stream;
    transaction_init(&tx); stream_init_from_data(&stream, wire, length);
    if (!transaction_v6_decode_prefix(&tx, &stream, length) || stream_remaining(&stream)) {
        transaction_free(&tx);
        return ZCL_ERR(-1, "Cannot decode v6 P2PKH transaction");
    }
    struct zcl_result r = verify_decoded(&tx, prevouts, count, index, expected_branch, script_flags);
    transaction_free(&tx); return r;
}
