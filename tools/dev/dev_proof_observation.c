/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Persist and verify signed per-group runner observations. */
#include "dev_proof_observation.h"

#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OBSERVATION_MAX_ROOTS 8192u

static bool obs_fail(char *why, size_t cap, const char *reason)
{
    if (why && cap) (void)snprintf(why, cap, "%s", reason);
    return false;
}

static bool obs_root_matches(const struct zcl_dev_verdict_leaf_v1 *leaf,
                             const uint8_t expected[ZCL_DEV_PROOF_ROOT_BYTES])
{
    uint8_t derived[ZCL_DEV_PROOF_ROOT_BYTES];
    char why[80];
    return zcl_dev_verdict_leaf_root(leaf, derived, why, sizeof(why)) &&
           memcmp(derived, expected, sizeof(derived)) == 0;
}

bool zcl_dev_observation_record(const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    enum zcl_dev_verdict_leaf_verdict verdict, uint64_t elapsed_ms,
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES], char *why, size_t why_len)
{
    if (!store_root || !store_root[0] || !key || !group || !root ||
        strlen(group) > ZCL_DEV_VERDICT_LEAF_GROUP_MAX)
        return obs_fail(why, why_len, "observation_arguments_invalid");
    time_t now = time(NULL);
    if (now <= 0)
        return obs_fail(why, why_len, "observation_clock_unavailable");
    struct zcl_dev_verdict_leaf_v1 leaf = {0};
    memcpy(leaf.key, key, sizeof(leaf.key));
    leaf.group_len = (uint8_t)strlen(group);
    memcpy(leaf.group, group, leaf.group_len);
    leaf.verdict = verdict;
    leaf.observed_unix = (uint64_t)now;
    leaf.elapsed_ms = elapsed_ms;
    leaf.log_seq = 1;
    if (!zcl_dev_verdict_leaf_sign(&leaf, why, why_len) ||
        !zcl_dev_verdict_leaf_root(&leaf, root, why, why_len))
        return false;
    uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
    if (!zcl_dev_verdict_leaf_serialize(&leaf, wire, why, why_len))
        return false;
    if (!vcs_object_store_init(store_root) ||
        !vcs_object_put_addressed(store_root, root, wire, sizeof(wire)))
        return obs_fail(why, why_len, "observation_store_failed");
    uint8_t *stored = NULL;
    size_t stored_len = 0;
    bool exact = vcs_object_load_raw_bounded(store_root, root, sizeof(wire),
                                              &stored, &stored_len) == 0 &&
                 stored_len == sizeof(wire) &&
                 memcmp(stored, wire, sizeof(wire)) == 0;
    free(stored);
    if (!exact) return obs_fail(why, why_len, "observation_store_mismatch");
    if (why && why_len) why[0] = 0;
    return true;
}

static bool obs_load_eligible(const char *store_root,
    const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES],
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    enum zcl_dev_verdict_leaf_verdict *verdict, bool *unavailable,
    bool *missing)
{
    uint8_t *wire = NULL;
    size_t len = 0;
    *unavailable = false;
    *missing = false;
    if (vcs_object_load_raw_bounded(store_root, root,
                                    ZCL_DEV_VERDICT_LEAF_WIRE_BYTES,
                                    &wire, &len) != 0) {
        *unavailable = true;
        *missing = !vcs_object_has(store_root, root);
        return false;
    }
    struct zcl_dev_verdict_leaf_v1 leaf;
    char why[80];
    bool eligible = zcl_dev_verdict_leaf_parse(wire, len, &leaf, why,
                                               sizeof(why)) &&
                    obs_root_matches(&leaf, root) &&
                    zcl_dev_verdict_leaf_verify(&leaf, key, group, why,
                                                sizeof(why));
    free(wire);
    if (eligible) *verdict = leaf.verdict;
    return eligible;
}

enum zcl_dev_observation_verdict zcl_dev_observation_admit(
    const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_roots,
    size_t *ineligible, char *why, size_t why_len)
{
    if (ineligible) *ineligible = 0;
    if (!store_root || !store_root[0] || !key || !group ||
        (n_roots && !roots) || n_roots > OBSERVATION_MAX_ROOTS) {
        (void)obs_fail(why, why_len, "observation_arguments_invalid");
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    bool pass = false, fail = false, absent = false, unreadable = false;
    for (size_t i = 0; i < n_roots; i++) {
        enum zcl_dev_verdict_leaf_verdict verdict = 0;
        bool missing = false, unavailable = false;
        if (!obs_load_eligible(store_root, roots[i], key, group,
                               &verdict, &unavailable, &missing)) {
            if (!unavailable && ineligible) (*ineligible)++;
            absent |= missing;
            unreadable |= unavailable && !missing;
            continue;
        }
        pass |= verdict == ZCL_DEV_VERDICT_LEAF_PASS;
        fail |= verdict == ZCL_DEV_VERDICT_LEAF_FAIL;
    }
    if (pass && fail) {
        (void)obs_fail(why, why_len, "proof_observation_conflict");
        return ZCL_DEV_OBSERVATION_CONFLICT;
    }
    if (absent || unreadable) {
        (void)obs_fail(why, why_len, absent ? "observation_object_missing"
                                          : "observation_object_unreadable");
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    if (pass || fail) {
        if (why && why_len) why[0] = 0;
        return pass ? ZCL_DEV_OBSERVATION_PASS : ZCL_DEV_OBSERVATION_FAIL;
    }
    (void)obs_fail(why, why_len, "proof_observation_missing");
    return ZCL_DEV_OBSERVATION_MISSING;
}
