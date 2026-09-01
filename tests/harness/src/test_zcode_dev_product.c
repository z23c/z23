/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: named development-profile expansion and exact-policy KATs. */

#include "test/test_core.h"

#include "base/hex.h"
#include "vcs/zcode_dev_product.h"

#include <string.h>

int test_zcode_dev_product(void)
{
    int failures = 0;

    TEST("zcode dev product: named profiles expand to exact existing policies") {
        static const struct {
            const char *name;
            uint32_t proofs;
            bool warnings;
            bool sanitizers;
            bool fuzz;
            bool reproduction;
            bool review;
        } cases[] = {
            { "quick", 3u, false, false, false, false, false },
            { "standard", 3u, true, true, false, false, false },
            { "strong", 23u, true, true, true, true, false },
            { "release", 31u, true, true, true, true, true },
        };
        uint8_t prior_root[32] = {0};
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct vcs_zcode_dev_profile expanded;
            ASSERT(vcs_zcode_dev_profile_expand(cases[i].name, &expanded));
            ASSERT(strcmp(expanded.name, cases[i].name) == 0);
            ASSERT(expanded.policy.required_proofs == cases[i].proofs);
            ASSERT(expanded.warning_fatal == cases[i].warnings);
            ASSERT(expanded.sanitizers == cases[i].sanitizers);
            ASSERT(expanded.deterministic_fuzz == cases[i].fuzz);
            ASSERT(expanded.local_reproduction == cases[i].reproduction);
            ASSERT(expanded.separate_review == cases[i].review);
            ASSERT(vcs_zcode_proof_policy_validate(&expanded.policy) ==
                   VCS_ZCODE_DEV_OK);
            uint8_t wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
            uint8_t wire_again[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
            uint8_t root[32], root_again[32];
            ASSERT(vcs_zcode_proof_policy_serialize(&expanded.policy, wire) ==
                   VCS_ZCODE_DEV_OK);
            ASSERT(vcs_zcode_proof_policy_serialize(&expanded.policy,
                                                    wire_again) ==
                   VCS_ZCODE_DEV_OK);
            ASSERT(memcmp(wire, wire_again, sizeof(wire)) == 0);
            ASSERT(vcs_zcode_proof_policy_root(&expanded.policy, root) ==
                   VCS_ZCODE_DEV_OK);
            ASSERT(vcs_zcode_proof_policy_root(&expanded.policy, root_again) ==
                   VCS_ZCODE_DEV_OK);
            ASSERT(memcmp(root, root_again, sizeof(root)) == 0);
            if (i != 0) ASSERT(memcmp(root, prior_root, sizeof(root)) != 0);
            memcpy(prior_root, root, sizeof(root));
        }
        struct vcs_zcode_dev_profile zeroed;
        memset(&zeroed, 0xa5, sizeof(zeroed));
        ASSERT(!vcs_zcode_dev_profile_expand("unknown", &zeroed));
        const uint8_t zero[sizeof(zeroed)] = {0};
        ASSERT(memcmp(&zeroed, zero, sizeof(zeroed)) == 0);
        struct vcs_zcode_dev_profile profile;
        ASSERT(vcs_zcode_dev_profile_expand("standard", &profile));
        uint8_t wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES], expected[36];
        ASSERT(zcl_hex_decode_lower(
            "5a43504f4c590d0a01000300000002000200000000000100000000000000000080510100",
            expected, sizeof(expected)));
        ASSERT(vcs_zcode_proof_policy_serialize(&profile.policy, wire) ==
               VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(wire, expected, sizeof(wire)) == 0);
        PASS();
    } _test_next:;

    return failures;
}
