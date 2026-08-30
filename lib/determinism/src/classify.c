/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the three-bucket classifier and the partition accumulator that
 * proves the buckets sum to the registry size. */

#include "determinism/classify.h"

#include "base/log_macros.h"

#include <string.h>

const char *zcl_det_class_name(enum zcl_det_class klass)
{
    switch (klass) {
    case ZCL_DET_CLASS_DETERMINISTIC: return "DETERMINISTIC";
    case ZCL_DET_CLASS_NONDETERMINISTIC: return "NONDETERMINISTIC";
    case ZCL_DET_CLASS_UNKNOWN: return "UNKNOWN";
    }
    return "INVALID";
}

const char *zcl_det_unknown_reason_name(enum zcl_det_unknown_reason reason)
{
    switch (reason) {
    case ZCL_DET_UNKNOWN_NONE: return "";
    case ZCL_DET_UNKNOWN_NOT_RUN: return "not-run";
    case ZCL_DET_UNKNOWN_NO_VECTOR: return "no-vector";
    case ZCL_DET_UNKNOWN_PARTIAL: return "partial-coverage";
    }
    return "invalid";
}

bool zcl_det_classify(const struct zcl_det_observation *obs, size_t n,
                      struct zcl_det_verdict *out)
{
    if (!obs || !out) LOG_FAIL("determinism", "null observations or verdict");
    if (n == 0 || n > 32)
        LOG_FAIL("determinism", "perturbation count %zu out of range 1..32", n);

    memset(out, 0, sizeof(*out));

    uint32_t observed = 0;
    uint32_t with_vector = 0;
    for (size_t i = 0; i < n; i++) {
        if (!obs[i].observed) continue;
        observed |= (uint32_t)1u << i;
        if (obs[i].check_count > 0) with_vector |= (uint32_t)1u << i;
    }
    out->observed_mask = observed;

    /* Never dispatched anywhere. Say so; do not call it clean. */
    if (observed == 0) {
        out->klass = ZCL_DET_CLASS_UNKNOWN;
        out->reason = ZCL_DET_UNKNOWN_NOT_RUN;
        return true;
    }

    /* Dispatched under some perturbations and gated out under others: the
     * runs are not comparable, so neither answer is earned. */
    const uint32_t all = (n == 32) ? UINT32_MAX : (((uint32_t)1u << n) - 1u);
    if (observed != all) {
        out->klass = ZCL_DET_CLASS_UNKNOWN;
        out->reason = ZCL_DET_UNKNOWN_PARTIAL;
        return true;
    }

    /* Ran everywhere and asserted nothing anywhere: no vector to hash. This
     * is a per-group EXCLUSION, and it is named and counted as one. */
    if (with_vector == 0) {
        out->klass = ZCL_DET_CLASS_UNKNOWN;
        out->reason = ZCL_DET_UNKNOWN_NO_VECTOR;
        return true;
    }

    /* From here the group ran under every perturbation and produced a vector
     * under at least one, so BASE's digest is the reference even when BASE's
     * own vector is empty — an empty vector where another run has 12 checks is
     * a different SET of assertions, which is exactly a split. The digest of
     * an empty vector is well defined (the domain tag plus a zero count), so
     * the comparison below already covers that case with no special path. */
    out->check_count = obs[ZCL_DET_P_BASE].check_count;

    uint32_t split = 0;
    for (size_t i = 1; i < n; i++) {
        if (memcmp(obs[i].digest, obs[ZCL_DET_P_BASE].digest,
                   ZCL_DET_DIGEST_LEN) != 0)
            split |= (uint32_t)1u << i;
    }
    out->split_mask = split;
    out->klass = split ? ZCL_DET_CLASS_NONDETERMINISTIC
                       : ZCL_DET_CLASS_DETERMINISTIC;
    return true;
}

void zcl_det_split_mask_string(uint32_t mask,
                               const enum zcl_det_perturbation *order,
                               size_t n, char *out, size_t out_cap)
{
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    if (!order || n == 0 || n > 32) return;
    size_t used = 0;
    for (size_t i = 0; i < n; i++) {
        if (!(mask & ((uint32_t)1u << i))) continue;
        const char *name = zcl_det_perturbation_name(order[i]);
        size_t len = strlen(name);
        size_t need = len + (used ? 1u : 0u);
        if (used + need + 1 > out_cap) return;
        if (used) out[used++] = '+';
        memcpy(out + used, name, len);
        used += len;
        out[used] = '\0';
    }
}

void zcl_det_partition_add(struct zcl_det_partition *p,
                           const struct zcl_det_verdict *v)
{
    if (!p || !v) return;
    p->total++;
    switch (v->klass) {
    case ZCL_DET_CLASS_DETERMINISTIC:    p->deterministic++; return;
    case ZCL_DET_CLASS_NONDETERMINISTIC: p->nondeterministic++; return;
    case ZCL_DET_CLASS_UNKNOWN:
        switch (v->reason) {
        case ZCL_DET_UNKNOWN_NOT_RUN:    p->unknown_not_run++; return;
        case ZCL_DET_UNKNOWN_NO_VECTOR:  p->unknown_no_vector++; return;
        case ZCL_DET_UNKNOWN_PARTIAL:    p->unknown_partial++; return;
        case ZCL_DET_UNKNOWN_NONE:       return; /* leaves the sum short */
        }
        return;
    }
}

bool zcl_det_partition_is_exact(const struct zcl_det_partition *p)
{
    if (!p) return false;
    size_t sum = p->deterministic + p->nondeterministic + p->unknown_not_run +
                 p->unknown_no_vector + p->unknown_partial;
    return sum == p->total;
}
