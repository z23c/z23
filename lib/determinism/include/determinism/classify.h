/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: place every measured group in exactly one of three buckets, and
 * refuse to guess when it could not be measured.
 *
 * THE BUCKETS PARTITION. Every group lands in exactly one of DETERMINISTIC,
 * NONDETERMINISTIC and UNKNOWN. The counts sum to the registry size. This is
 * asserted, not assumed — test_determinism enumerates observation tables
 * exhaustively and checks that exactly one bucket is chosen every time.
 *
 * UNKNOWN IS NEVER FOLDED INTO EITHER OTHER BUCKET. A group that could not be
 * measured — the runner never dispatched it, it produced no verdict vector at
 * all, it was dispatched under some perturbations and gated out under others —
 * is UNKNOWN and is named and counted as UNKNOWN. Folding it into
 * DETERMINISTIC would report a green number for work nobody did; folding it
 * into NONDETERMINISTIC would accuse a group nobody observed. A tool that
 * guesses here is worse than no tool.
 *
 * WHICH PERTURBATION SPLIT IT. A NONDETERMINISTIC verdict carries the set of
 * perturbations whose digest differs from BASE. That set is the finding — it
 * names the cause. A verdict that only said "varies" would be useless. */
#ifndef ZCL_DETERMINISM_CLASSIFY_H
#define ZCL_DETERMINISM_CLASSIFY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "determinism/perturbation.h"
#include "determinism/verdict.h"

enum zcl_det_class {
    ZCL_DET_CLASS_DETERMINISTIC = 1,
    ZCL_DET_CLASS_NONDETERMINISTIC = 2,
    ZCL_DET_CLASS_UNKNOWN = 3,
};

enum zcl_det_unknown_reason {
    ZCL_DET_UNKNOWN_NONE = 0,
    /* The runner dispatched this group under no perturbation at all: gated
     * out by an environment flag, filtered by a selector, or absent. */
    ZCL_DET_UNKNOWN_NOT_RUN = 1,
    /* It ran, and emitted no "<name>... <outcome>" line under any
     * perturbation. There is nothing to hash. This is a per-group exclusion
     * that must be named and counted, never silently skipped. */
    ZCL_DET_UNKNOWN_NO_VECTOR = 2,
    /* It ran under some perturbations and not others. The measurement is not
     * comparable, so it yields no verdict either way. */
    ZCL_DET_UNKNOWN_PARTIAL = 3,
};

/* One group under one perturbation. */
struct zcl_det_observation {
    bool observed;     /* the runner dispatched it and replayed its output */
    uint32_t check_count;
    uint8_t digest[ZCL_DET_DIGEST_LEN];
};

struct zcl_det_verdict {
    enum zcl_det_class klass;
    enum zcl_det_unknown_reason reason;
    uint32_t observed_mask;  /* bit i: perturbation i produced an observation */
    uint32_t split_mask;     /* bit i: perturbation i's digest differs from BASE */
    uint32_t check_count;    /* BASE's vector length, 0 when not measured */
};

/* `obs` is indexed by enum zcl_det_perturbation, length `n`. Returns false
 * only on a malformed call (null, n == 0, n > 32); a group that cannot be
 * classified is reported as UNKNOWN, which is an answer, not an error. */
bool zcl_det_classify(const struct zcl_det_observation *obs, size_t n,
                      struct zcl_det_verdict *out);

const char *zcl_det_class_name(enum zcl_det_class klass);
const char *zcl_det_unknown_reason_name(enum zcl_det_unknown_reason reason);

/* Render the split mask as "CC_SET+ENV_PAD" into `out`. Empty when the mask is
 * empty. Used by the report and by the ratchet baseline, which stores the cause
 * beside every non-deterministic group.
 *
 * `order` is the caller's profile order — the SAME array whose slot i the
 * observation table used — and bit i of the mask means order[i]. It is a
 * required argument on purpose: a version that assumed the enum's own order
 * would silently print the wrong cause for any caller that measured a subset,
 * and a wrong cause is worse than no cause. */
void zcl_det_split_mask_string(uint32_t mask,
                               const enum zcl_det_perturbation *order,
                               size_t n, char *out, size_t out_cap);

/* The running partition, so a report can prove the buckets sum. */
struct zcl_det_partition {
    size_t deterministic;
    size_t nondeterministic;
    size_t unknown_not_run;
    size_t unknown_no_vector;
    size_t unknown_partial;
    size_t total;
};

void zcl_det_partition_add(struct zcl_det_partition *p,
                           const struct zcl_det_verdict *v);
bool zcl_det_partition_is_exact(const struct zcl_det_partition *p);

#endif /* ZCL_DETERMINISM_CLASSIFY_H */
