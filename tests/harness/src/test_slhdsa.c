/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: runs the platform/modules/slhdsa self-test (NIST ACVP vectors,
 * round trips, bit-flip rejection, input validation) as a harness group, and
 * states the verify contract directly from the registered root. */

#include "test/test_core.h"
#include "slhdsa/slhdsa.h"

#include <stdio.h>
#include <string.h>

#define main slhdsa_module_main
#include "../../../platform/modules/slhdsa/tests/test_slhdsa.c"
#undef main

static bool test_slhdsa_counter_random(void *context, uint8_t *out, size_t len)
{
    (void)context;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i * 7u + 3u);
    return true;
}

static int slhdsa_verify_contract(void)
{
    int failures = 0;
    TEST("slhdsa verify: accepts a valid signature, rejects every altered input") {
        static uint8_t pk[ZCL_SLHDSA_MAX_PUBLIC_KEY_SIZE];
        static uint8_t sk[ZCL_SLHDSA_MAX_SECRET_KEY_SIZE];
        static uint8_t sig[ZCL_SLHDSA_MAX_SIGNATURE_SIZE];
        const enum zcl_slhdsa_param param = ZCL_SLHDSA_SHAKE_128S;
        const size_t pl = zcl_slhdsa_public_key_size(param);
        const size_t sl = zcl_slhdsa_signature_size(param);
        const uint8_t msg[] = { 'z', 'r', 's', '1' };
        const uint8_t ctx[] = { 'c', 't', 'x' };
        const size_t kl = zcl_slhdsa_secret_key_size(param);
        enum zcl_slhdsa_status st = zcl_slhdsa_keygen(
            param, test_slhdsa_counter_random, nullptr, pk, pl, sk, kl);
        ASSERT(st == ZCL_SLHDSA_OK);
        st = zcl_slhdsa_sign_deterministic(param, sk, kl, msg, sizeof msg, ctx,
                                           sizeof ctx, sig, sl);
        ASSERT(st == ZCL_SLHDSA_OK);
        st = zcl_slhdsa_verify(param, pk, pl, msg, sizeof msg, ctx, sizeof ctx,
                               sig, sl);
        ASSERT(st == ZCL_SLHDSA_OK);
        st = zcl_slhdsa_verify(param, pk, pl, msg, sizeof msg - 1, ctx,
                               sizeof ctx, sig, sl);
        ASSERT(st == ZCL_SLHDSA_ERR_VERIFY);
        st = zcl_slhdsa_verify(param, pk, pl, msg, sizeof msg, ctx,
                               sizeof ctx - 1, sig, sl);
        ASSERT(st == ZCL_SLHDSA_ERR_VERIFY);
        st = zcl_slhdsa_verify(param, pk, pl, msg, sizeof msg, ctx, sizeof ctx,
                               sig, sl - 1);
        ASSERT(st == ZCL_SLHDSA_ERR_LENGTH);
        sig[sl / 2] ^= 1u;
        st = zcl_slhdsa_verify(param, pk, pl, msg, sizeof msg, ctx, sizeof ctx,
                               sig, sl);
        ASSERT(st == ZCL_SLHDSA_ERR_VERIFY);
        PASS();
    } _test_next:;
    return failures;
}

int test_slhdsa(void);
int test_slhdsa(void)
{
    int failures = 0;
    TEST("slhdsa module: NIST vectors, round trips, bit flips, validation") {
        ASSERT(slhdsa_module_main() == 0);
        PASS();
    } _test_next:;
    failures += slhdsa_verify_contract();
    return failures;
}
