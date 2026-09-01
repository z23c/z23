/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Runtime complement to the no-silent-ready gate: adversarial peers can feed
 * invalid blocks/headers, but the simulator must reject them with a typed
 * blocker, keep the tip still, and accept the next honest block.
 */

#include "test/test_core.h"

#include "sim/simnet_byzantine.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>

#define SB_CHECK(name, expr) do {                         \
    printf("%s... ", (name));                             \
    if ((expr)) printf("OK\n");                           \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

static bool run_one(enum simnet_byzantine_class kind,
                    const char *expected_reason,
                    enum blocker_class expected_class)
{
    blocker_reset_for_testing();
    blocker_set_clock_for_testing(1000000 + (int64_t)kind * 100000);

    struct simnet_byzantine_observation obs;
    bool ran = simnet_byzantine_class_tier(kind) ==
               SIMNET_BYZ_TIER_CONNECT_BLOCK
        ? simnet_byzantine_run_connect_case(kind, &obs)
        : simnet_byzantine_run_header_case(kind, &obs);
    if (!ran)
        return false;

    bool reason_ok = strcmp(obs.reject_reason, expected_reason) == 0;
    enum blocker_class observed_class =
        (enum blocker_class)blocker_class_for(obs.blocker_id);
    bool class_ok = obs.blocker_class == expected_class &&
                    blocker_exists(obs.blocker_id) &&
                    observed_class == expected_class;
    return obs.rejected &&
           reason_ok &&
           class_ok &&
           obs.tip_after == obs.tip_before &&
           obs.honest_after_accepted &&
           obs.invariant_ok;
}

static bool mutation_self_check_flags_silent_advance(void)
{
    struct simnet_byzantine_observation obs;
    memset(&obs, 0, sizeof(obs));
    obs.kind = SIMNET_BYZ_BAD_MERKLE;
    obs.tier = SIMNET_BYZ_TIER_CONNECT_BLOCK;
    obs.rejected = true;
    snprintf(obs.reject_reason, sizeof(obs.reject_reason), "%s",
             "bad-txnmrklroot");
    obs.blocker_class = BLOCKER_PERMANENT;
    snprintf(obs.blocker_id, sizeof(obs.blocker_id), "%s",
             "simnet_byz.bad_merkle");
    obs.tip_before = 100;
    obs.tip_after = 101;
    obs.honest_after_accepted = true;
    return !simnet_byzantine_observation_ok(&obs);
}

int test_simnet_byzantine(void)
{
    printf("\n=== simnet_byzantine adversarial-peer invariants ===\n");
    int failures = 0;

    blocker_module_init();

    SB_CHECK("tier1 bad_merkle -> bad-txnmrklroot/permanent",
             run_one(SIMNET_BYZ_BAD_MERKLE, "bad-txnmrklroot",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier1 bad_cb_amount -> bad-cb-amount/permanent",
             run_one(SIMNET_BYZ_BAD_CB_AMOUNT, "bad-cb-amount",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier1 bip30 duplicate -> bad-txns-BIP30/permanent",
             run_one(SIMNET_BYZ_BIP30_DUP_TXID, "bad-txns-BIP30",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier1 missing spend -> bad-txns-inputs-missingorspent/permanent",
             run_one(SIMNET_BYZ_MISSING_SPEND,
                     "bad-txns-inputs-missingorspent",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier1 immature spend -> bad-txns-premature-spend-of-coinbase/permanent",
             run_one(SIMNET_BYZ_IMMATURE_SPEND,
                     "bad-txns-premature-spend-of-coinbase",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier1 negative output -> bad-txns-vout-negative/permanent",
             run_one(SIMNET_BYZ_NEGATIVE_OUTPUT,
                     "bad-txns-vout-negative", BLOCKER_PERMANENT));
    SB_CHECK("tier1 overflow output -> bad-txns-vout-toolarge/permanent",
             run_one(SIMNET_BYZ_OVERFLOW_OUTPUT,
                     "bad-txns-vout-toolarge", BLOCKER_PERMANENT));
    SB_CHECK("tier1 oversize vtx -> bad-blk-length/permanent",
             run_one(SIMNET_BYZ_OVERSIZE_VTX, "bad-blk-length",
                     BLOCKER_PERMANENT));

    SB_CHECK("tier2 invalid_pow admission -> invalid-solution/permanent",
             run_one(SIMNET_BYZ_INVALID_POW, "invalid-solution",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier2 bad_bits admission -> bad-diffbits/permanent",
             run_one(SIMNET_BYZ_BAD_BITS, "bad-diffbits",
                     BLOCKER_PERMANENT));
    SB_CHECK("tier2 bad_timestamp admission -> time-too-old/permanent",
             run_one(SIMNET_BYZ_BAD_TIMESTAMP, "time-too-old",
                     BLOCKER_PERMANENT));

    SB_CHECK("mutation self-check flags rejected-but-tip-advanced",
             mutation_self_check_flags_silent_advance());

    blocker_reset_for_testing();

    printf("=== simnet_byzantine: %d failures ===\n", failures);
    return failures;
}
