/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_eligible — the ZCODE reward eligibility gate list (slice 7).
 * A release earns NOTHING until EVERY gate passes; this layer assembles
 * the frozen gate list from facts the caller gathered (manifest/CAS
 * verification, envelope signature, license, parent lineage, the slice-6
 * attestation quorum, and any recorded bit-identical reproduction) and
 * reports eligible=true/false with every failed gate named. Pure
 * evaluation over caller-supplied facts: no filesystem, network, wallet,
 * build, execution, or node-state authority. Deterministic: same facts,
 * same report.
 *
 * The eight gates (frozen order — the report walks them in enum order):
 *   1. package-root-verifies   the manifest parses, its root equals the
 *                              envelope's package_root, and every
 *                              committed chunk was re-verified from the CAS
 *   2. release-signature-verifies  the envelope verifies (fields, low-S,
 *                              ECDSA against the embedded publisher key)
 *   3. license-accepted        the SPDX id is on the v1 allowlist and the
 *                              package carries its LICENSE text file
 *   4. parent-lineage-valid    the named parent release exists, verifies,
 *                              shares the publisher key, and the sequence
 *                              increments by exactly one (a root release
 *                              passes trivially)
 *   5. gcc-build-passes        a counted quorum attestation reports the
 *                              gcc outcome PASS
 *   6. clang-build-passes      a counted quorum attestation reports the
 *                              clang outcome PASS
 *   7. tests-pass              the quorum class is test-pass
 *   8. verifier-quorum         >= 2 approved independent verifier keys
 *                              signed matching attestations (slice 6)
 *
 * TRUST MODEL: the headline acceptance signal is BIT-IDENTICAL
 * REPRODUCTION (contexts/commons/modules/vcs/package_reproduce.*) — an independent rebuild of
 * the same package/recipe/lock emitting byte-for-byte the committed
 * artifacts, provable by ANY third party. The approved-signer quorum is
 * the LATENCY OPTIMIZATION over it: it lets a release earn before a local
 * reproduction exists. When the caller supplies reproduction_verified,
 * gates 5-8 pass on that stronger fact (a reproduced installable receipt
 * subsumes the per-compiler/test verdict claims: the verified artifact IS
 * the build-and-test evidence) and every such row says so. Without a
 * recorded reproduction, gates 5-7 are read from the SAME counted quorum
 * attestations that gate 8 evaluates; with neither, they fail — a release
 * never earns from a single verifier or from self-verification. */

#ifndef ZCL_VCS_PACKAGE_ELIGIBLE_H
#define ZCL_VCS_PACKAGE_ELIGIBLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_REWARD_GATE_DETAIL_MAX 160u

/* The enum order is frozen: it appears in typed JSON. */
enum vcs_reward_gate {
    VCS_REWARD_GATE_PACKAGE_ROOT = 0,
    VCS_REWARD_GATE_RELEASE_SIGNATURE,
    VCS_REWARD_GATE_LICENSE,
    VCS_REWARD_GATE_PARENT_LINEAGE,
    VCS_REWARD_GATE_GCC_BUILD,
    VCS_REWARD_GATE_CLANG_BUILD,
    VCS_REWARD_GATE_TESTS_PASS,
    VCS_REWARD_GATE_VERIFIER_QUORUM,
    VCS_REWARD_GATE_COUNT /* 8: not a gate */
};

const char *vcs_reward_gate_string(enum vcs_reward_gate gate);

/* Every fact the gate list consumes, gathered by the caller. */
struct vcs_reward_eligibility_input {
    /* Gate 1. chunks_checked false means the CAS was not consulted. */
    bool manifest_parsed;
    bool root_matches;
    bool chunks_checked;
    uint32_t chunks_verified;
    uint32_t chunks_total;
    /* Gate 2 (vcs_package_release_verify == VCS_PACKAGE_RELEASE_OK). */
    bool release_verifies;
    /* Gate 3: envelope license on the allowlist AND the LICENSE text
     * file present in the manifest. */
    bool license_accepted;
    /* Gate 4 (caller-walked; a root release reports true with the detail
     * naming it a root release). */
    bool lineage_valid;
    const char *lineage_detail; /* borrowed; may be NULL */
    /* Gates 5-8, from the slice-6 quorum evaluation over the counted
     * (matching, approved, independent) attestations. */
    bool quorum_verified;
    bool gcc_pass;
    bool clang_pass;
    bool tests_pass;
    /* The headline signal (gates 5-8): a bit-identical third-party
     * reproduction of the release's artifacts is recorded
     * (vcs/package_reproduce.h). When true it passes gates 5-8 outright;
     * the quorum facts above are the latency fast path over it. */
    bool reproduction_verified;
};

struct vcs_reward_gate_row {
    enum vcs_reward_gate gate;
    bool passed;
    char detail[VCS_REWARD_GATE_DETAIL_MAX];
};

struct vcs_reward_eligibility {
    bool eligible;
    struct vcs_reward_gate_row gates[VCS_REWARD_GATE_COUNT];
    size_t failed_count;
    /* Echo of the input fact that heads the trust model: gates 5-8 passed
     * on a recorded bit-identical reproduction (true) or on the signer
     * quorum fast path / not at all (false). */
    bool reproduction_verified;
};

/* Evaluate the gate list. Gates are walked in enum order; every gate is
 * reported (no early exit) so the reply names every failed gate. */
void vcs_reward_eligibility_evaluate(
    const struct vcs_reward_eligibility_input *in,
    struct vcs_reward_eligibility *out);

#endif /* ZCL_VCS_PACKAGE_ELIGIBLE_H */
