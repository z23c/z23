/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Persist and verify signed per-group runner observations. */
#include "dev_proof_observation_admission.h"

#include "platform/time_compat.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static bool obs_store_exact(const char *store_root,
    const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES],
    const uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES],
    char *why, size_t why_len)
{
    if (!vcs_object_store_init(store_root) ||
        !vcs_object_put_addressed(store_root, root, wire,
                                  ZCL_DEV_VERDICT_LEAF_WIRE_BYTES))
        return obs_fail(why, why_len, "observation_store_failed");
    uint8_t *stored = NULL;
    size_t stored_len = 0;
    bool exact = vcs_object_load_raw_bounded(store_root, root,
                    ZCL_DEV_VERDICT_LEAF_WIRE_BYTES,
                    &stored, &stored_len) == 0 &&
                 stored_len == ZCL_DEV_VERDICT_LEAF_WIRE_BYTES &&
                 memcmp(stored, wire, ZCL_DEV_VERDICT_LEAF_WIRE_BYTES) == 0;
    free(stored);
    if (!exact) return obs_fail(why, why_len, "observation_store_mismatch");
    return true;
}

bool zcl_dev_observation_record(const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    enum zcl_dev_verdict_leaf_verdict verdict, uint64_t elapsed_ms,
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES], char *why, size_t why_len)
{
    if (!store_root || !store_root[0] || !key || !group || !root ||
        strlen(group) > ZCL_DEV_VERDICT_LEAF_GROUP_MAX)
        return obs_fail(why, why_len, "observation_arguments_invalid");
    int64_t now = platform_time_wall_unix();
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
    if (!obs_store_exact(store_root, root, wire, why, why_len)) return false;
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

struct obs_tally {
    bool pass, fail, absent, unreadable;
    size_t ineligible;
};

static void obs_tally_roots(struct obs_tally *t, const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_roots)
{
    for (size_t i = 0; i < n_roots; i++) {
        enum zcl_dev_verdict_leaf_verdict verdict = 0;
        bool missing = false, unavailable = false;
        if (!obs_load_eligible(store_root, roots[i], key, group,
                               &verdict, &unavailable, &missing)) {
            if (!unavailable) t->ineligible++;
            t->absent |= missing;
            t->unreadable |= unavailable && !missing;
            continue;
        }
        t->pass |= verdict == ZCL_DEV_VERDICT_LEAF_PASS;
        t->fail |= verdict == ZCL_DEV_VERDICT_LEAF_FAIL;
    }
}

static enum zcl_dev_observation_verdict obs_tally_verdict(
    const struct obs_tally *t, char *why, size_t why_len)
{
    if (t->pass && t->fail) {
        (void)obs_fail(why, why_len, "proof_observation_conflict");
        return ZCL_DEV_OBSERVATION_CONFLICT;
    }
    if (t->absent || t->unreadable) {
        (void)obs_fail(why, why_len, t->absent ? "observation_object_missing"
                                             : "observation_object_unreadable");
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    if (t->pass || t->fail) {
        if (why && why_len) why[0] = 0;
        return t->pass ? ZCL_DEV_OBSERVATION_PASS : ZCL_DEV_OBSERVATION_FAIL;
    }
    (void)obs_fail(why, why_len, "proof_observation_missing");
    return ZCL_DEV_OBSERVATION_MISSING;
}

enum zcl_dev_observation_verdict zcl_dev_observation_admit_known(
    const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*proposed_roots)[ZCL_DEV_PROOF_ROOT_BYTES],
    size_t n_proposed,
    const uint8_t (*known_roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_known,
    size_t *ineligible, char *why, size_t why_len)
{
    if (ineligible) *ineligible = 0;
    if (!store_root || !store_root[0] || !key || !group ||
        (n_proposed && !proposed_roots) || (n_known && !known_roots) ||
        n_proposed > OBSERVATION_MAX_ROOTS ||
        n_known > OBSERVATION_MAX_ROOTS - n_proposed) {
        (void)obs_fail(why, why_len, "observation_arguments_invalid");
        return ZCL_DEV_OBSERVATION_MISSING;
    }
    struct obs_tally tally = {0};
    obs_tally_roots(&tally, store_root, key, group, proposed_roots, n_proposed);
    obs_tally_roots(&tally, store_root, key, group, known_roots, n_known);
    if (ineligible) *ineligible = tally.ineligible;
    return obs_tally_verdict(&tally, why, why_len);
}

enum zcl_dev_observation_verdict zcl_dev_observation_admit(
    const char *store_root,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    const uint8_t (*roots)[ZCL_DEV_PROOF_ROOT_BYTES], size_t n_roots,
    size_t *ineligible, char *why, size_t why_len)
{
    return zcl_dev_observation_admit_known(store_root, key, group, roots,
                                          n_roots, NULL, 0, ineligible,
                                          why, why_len);
}
