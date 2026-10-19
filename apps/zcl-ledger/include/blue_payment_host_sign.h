/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#ifndef ZCL_BLUE_PAYMENT_HOST_SIGN_H
#define ZCL_BLUE_PAYMENT_HOST_SIGN_H

#include "blue_payment_live.h"
#include "blue_payment_host_verify.h"

/* Called only after all reviewed inputs have been bound. It must wait for
 * the owner's final physical SIGN ZCL touch and return false on refusal. */
typedef bool (*blue_payment_host_approval)(void *context);

/* Requires 1..16 inputs and protocol 12/capability 31, then collects
 * signatures in input order. Every reply is checked against its expected
 * path, public-key hash, and ZIP-243 digest. Verified replies remain private
 * until every input passes; callbacks cannot alter an earlier returned reply.
 * Expectations are frozen before identity and approval callbacks. If caller
 * storage differs after a callback, the function rejects all signatures and
 * attempts a review abort. The caller keeps all arrays alive and prevents
 * concurrent writes.
 * Once bounded arguments are accepted, identity, approval, transport, or
 * verification failure attempts to abort the device review, then clears
 * every output slot, including signatures already obtained. Invalid arguments
 * also request an abort when an exchange callback is available. The output
 * array must not overlap the expected paths, hashes, or digests; rejected
 * overlap leaves input not yet checked by the device untouched and makes no signing request.
 * Callers must
 * ignore output slots after any failure. No broadcast occurs. */
bool blue_payment_host_sign(size_t count, const uint8_t *paths,
    const uint8_t (*hashes)[20], const uint8_t (*digests)[32],
    blue_payment_live_exchange exchange,
    blue_payment_host_approval approval, void *device_context,
    blue_payment_pubkey_hash_fn hash,
    blue_payment_verify_signature_fn verify, void *verify_context,
    blue_payment_verified_signature *signatures);

#endif
