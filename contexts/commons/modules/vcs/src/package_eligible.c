/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_eligible — implementation of the ZCODE reward eligibility
 * gate list declared in vcs/package_eligible.h. Pure assembly of
 * caller-gathered facts into the frozen eight-gate report; no I/O, no
 * trust decisions of its own. */

#include "vcs/package_eligible.h"

#include <stdio.h>
#include <string.h>

const char *vcs_reward_gate_string(enum vcs_reward_gate gate)
{
    switch (gate) {
    case VCS_REWARD_GATE_PACKAGE_ROOT: return "package-root-verifies";
    case VCS_REWARD_GATE_RELEASE_SIGNATURE:
        return "release-signature-verifies";
    case VCS_REWARD_GATE_LICENSE: return "license-accepted";
    case VCS_REWARD_GATE_PARENT_LINEAGE: return "parent-lineage-valid";
    case VCS_REWARD_GATE_GCC_BUILD: return "gcc-build-passes";
    case VCS_REWARD_GATE_CLANG_BUILD: return "clang-build-passes";
    case VCS_REWARD_GATE_TESTS_PASS: return "tests-pass";
    case VCS_REWARD_GATE_VERIFIER_QUORUM: return "verifier-quorum";
    case VCS_REWARD_GATE_COUNT: break;
    }
    return "unknown-gate";
}

static void gate_row(struct vcs_reward_eligibility *out, size_t *failed,
                     enum vcs_reward_gate gate, bool passed,
                     const char *detail)
{
    struct vcs_reward_gate_row *row = &out->gates[gate];
    row->gate = gate;
    row->passed = passed;
    snprintf(row->detail, sizeof(row->detail), "%s",
             detail ? detail : "");
    if (!passed)
        (*failed)++;
}

void vcs_reward_eligibility_evaluate(
    const struct vcs_reward_eligibility_input *in,
    struct vcs_reward_eligibility *out)
{
    memset(out, 0, sizeof(*out));
    if (!in) {
        /* A null input is a total failure: every gate fails unnamed. */
        out->eligible = false;
        out->failed_count = VCS_REWARD_GATE_COUNT;
        for (size_t i = 0; i < VCS_REWARD_GATE_COUNT; i++) {
            out->gates[i].gate = (enum vcs_reward_gate)i;
            out->gates[i].passed = false;
            snprintf(out->gates[i].detail, sizeof(out->gates[i].detail),
                     "no eligibility input");
        }
        return;
    }
    size_t failed = 0;
    char detail[VCS_REWARD_GATE_DETAIL_MAX];

    /* 1. package-root-verifies. */
    {
        bool passed = in->manifest_parsed && in->root_matches &&
                      in->chunks_checked &&
                      in->chunks_verified == in->chunks_total;
        if (!in->manifest_parsed)
            snprintf(detail, sizeof(detail),
                     "manifest wire does not parse");
        else if (!in->root_matches)
            snprintf(detail, sizeof(detail),
                     "manifest root != envelope package_root");
        else if (!in->chunks_checked)
            snprintf(detail, sizeof(detail), "CAS chunks not consulted");
        else if (in->chunks_verified != in->chunks_total)
            snprintf(detail, sizeof(detail),
                     "%u of %u committed chunks verified",
                     in->chunks_verified, in->chunks_total);
        else
            snprintf(detail, sizeof(detail),
                     "all %u committed chunks verified", in->chunks_total);
        gate_row(out, &failed, VCS_REWARD_GATE_PACKAGE_ROOT, passed,
                 detail);
    }

    /* 2. release-signature-verifies. */
    gate_row(out, &failed, VCS_REWARD_GATE_RELEASE_SIGNATURE,
             in->release_verifies,
             in->release_verifies
                 ? "envelope verifies against the embedded publisher key"
                 : "envelope does not verify (fields, low-S, or ECDSA)");

    /* 3. license-accepted. */
    gate_row(out, &failed, VCS_REWARD_GATE_LICENSE, in->license_accepted,
             in->license_accepted
                 ? "SPDX id on the v1 allowlist and LICENSE file present"
                 : "license not on the v1 allowlist or LICENSE file "
                   "missing");

    /* 4. parent-lineage-valid. */
    gate_row(out, &failed, VCS_REWARD_GATE_PARENT_LINEAGE,
             in->lineage_valid,
             in->lineage_detail ? in->lineage_detail
                                : (in->lineage_valid ? "lineage valid"
                                                     : "lineage invalid"));

    /* 5-7. build/test gates: the headline signal is a recorded
     * bit-identical reproduction (an installable reproduced receipt IS
     * the build-and-test evidence); the counted quorum attestations are
     * the latency fast path read otherwise. */
    {
        const struct {
            enum vcs_reward_gate gate;
            bool pass;
            const char *name;
        } build_gates[] = {
            { VCS_REWARD_GATE_GCC_BUILD, in->gcc_pass, "gcc" },
            { VCS_REWARD_GATE_CLANG_BUILD, in->clang_pass, "clang" },
        };
        for (size_t i = 0; i < sizeof(build_gates) / sizeof(build_gates[0]);
             i++) {
            if (in->reproduction_verified) {
                gate_row(out, &failed, build_gates[i].gate, true,
                         "subsumed by the recorded bit-identical "
                         "reproduction (the reproduced installable "
                         "receipt is the build evidence; quorum is the "
                         "fast path)");
                continue;
            }
            bool passed = in->quorum_verified && build_gates[i].pass;
            if (!in->quorum_verified)
                snprintf(detail, sizeof(detail), "no verified quorum");
            else if (!build_gates[i].pass)
                snprintf(detail, sizeof(detail),
                         "%s outcome not PASS in the counted quorum "
                         "attestations", build_gates[i].name);
            else
                snprintf(detail, sizeof(detail),
                         "%s outcome PASS in the counted quorum "
                         "attestations", build_gates[i].name);
            gate_row(out, &failed, build_gates[i].gate, passed, detail);
        }
        if (in->reproduction_verified) {
            gate_row(out, &failed, VCS_REWARD_GATE_TESTS_PASS, true,
                     "subsumed by the recorded bit-identical reproduction "
                     "of an installable receipt (build+test pass is what "
                     "makes a receipt installable)");
        } else {
            bool tests = in->quorum_verified && in->tests_pass;
            gate_row(out, &failed, VCS_REWARD_GATE_TESTS_PASS, tests,
                     !in->quorum_verified
                         ? "no verified quorum"
                         : tests ? "quorum class is test-pass"
                                 : "quorum class is not test-pass");
        }
    }

    /* 8. verifier-quorum: satisfied outright by the headline signal; the
     * 2-of-N approved-signer quorum is the latency optimization over it. */
    gate_row(out, &failed, VCS_REWARD_GATE_VERIFIER_QUORUM,
             in->reproduction_verified || in->quorum_verified,
             in->reproduction_verified
                 ? "bit-identical third-party reproduction recorded — the "
                   "signer quorum is the latency fast path over it and "
                   "was not required"
                 : in->quorum_verified
                     ? "2+ approved independent verifiers signed matching "
                       "pass attestations (fast path: no reproduction "
                       "recorded)"
                     : "no 2-of-N approved independent matching pass "
                       "quorum and no recorded reproduction");

    out->failed_count = failed;
    out->eligible = failed == 0;
    out->reproduction_verified = in->reproduction_verified;
}
