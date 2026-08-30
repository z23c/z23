/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: place every measured group in exactly one of four buckets, and
 * refuse to guess when it could not be measured.
 *
 * THE BUCKETS PARTITION. Every group lands in exactly one of DETERMINISTIC,
 * NONDETERMINISTIC, TIMING_SENSITIVE and UNKNOWN. The counts sum to the
 * registry size. This is asserted, not assumed — test_determinism enumerates
 * observation tables exhaustively and checks that exactly one bucket is chosen
 * every time.
 *
 * UNKNOWN IS NEVER FOLDED INTO ANY OTHER BUCKET. A group that could not be
 * measured — the runner never dispatched it, it produced no verdict vector at
 * all, it was dispatched under some perturbations and gated out under others —
 * is UNKNOWN and is named and counted as UNKNOWN. Folding it into
 * DETERMINISTIC would report a green number for work nobody did; folding it
 * into NONDETERMINISTIC would accuse a group nobody observed. A tool that
 * guesses here is worse than no tool.
 *
 * WHY TIMING_SENSITIVE IS ITS OWN BUCKET, NOT A NOTE ON NONDETERMINISTIC.
 * These are two different defects and only one of them is a bug in the test's
 * logic.
 *
 *   NONDETERMINISTIC  the vector moved on a plain re-run at identical load, or
 *                     moved when the environment moved. The test does not
 *                     settle on one answer, and no amount of care by the
 *                     re-runner will make it.
 *   TIMING_SENSITIVE  the vector moved ONLY when the machine's load moved. The
 *                     logic is settled; the grading rule reads a wall clock.
 *
 * The second is the dangerous one for a corroboration network. An honest node
 * re-running such a group on a busier box computes a different verdict vector
 * and REFUTES a receipt that was never wrong. That is a false accusation
 * manufactured by scheduling, and the producer cannot answer it — it has no
 * evidence to offer except "my box was quieter". Collapsing the two buckets
 * would hide exactly the population that generates those accusations.
 *
 * Neither class may carry a receipt. The buckets differ in what to DO: a
 * NONDETERMINISTIC group needs its logic fixed, a TIMING_SENSITIVE group needs
 * its grading rule replaced with something that is not a clock.
 *
 * WHICH PERTURBATION SPLIT IT. A NONDETERMINISTIC or TIMING_SENSITIVE verdict
 * carries the set of perturbations whose digest differs from the reference.
 * That set is the finding — it names the cause. A verdict that only said
 * "varies" would be useless.
 *
 * AND THE CEILING ON THE SEPARATION ITSELF. What the SCHEDULING perturbations
 * measure is "the answer changed between a small worker pool and a large one
 * on an otherwise quiet box". That is not "the answer changed under arbitrary
 * contention". A group can read DETERMINISTIC here and still refute a receipt
 * on a loaded node, so DETERMINISTIC is necessary for receipt eligibility and
 * is not sufficient for it.
 *
 * ONE DIFFERING OBSERVATION IS A HYPOTHESIS, NOT A PROOF. Each slot here holds
 * a single run, so a verdict of NONDETERMINISTIC rests on one pair of samples.
 * On a shared box that is not enough. Another lane in this tree ran three cold
 * suites and got a different failing group each time, every one of them a
 * wall-clock or poll budget and every one green when re-run alone; it also
 * watched a group fail at HEAD, pass at its base commit — which looks exactly
 * like a regression — and then pass three times out of three at HEAD once the
 * box was quieter. "Passes at base, fails at head" is not sufficient evidence
 * of a regression here, and by the same argument one split is not sufficient
 * evidence of nondeterminism.
 *
 * Two things carry that weight instead of a bigger sample. The scan records
 * the load every profile ran at and refuses to write a baseline at all when
 * the two reference profiles disagree, so a contaminated sweep produces
 * UNCONFIRMED rather than a list. And the baseline is shrink-only, which makes
 * a row cheap to be wrong about in the safe direction: a false positive is
 * removed by the next clean sweep, while a false negative would need a new row
 * and the gate does not accept one. Read a row as "this needs explaining",
 * not as "this is proven broken". */
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
    /* Appended, so the values above keep their numbers and the golden receipt
     * bytes are unchanged. Once a receipt exists outside this branch, adding
     * another value here requires a version bump, not another append. */
    ZCL_DET_CLASS_TIMING_SENSITIVE = 4,
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

/* `obs` and `order` are parallel arrays of length `n`: slot i holds the
 * observation made under perturbation order[i]. Slot 0 is the reference every
 * other slot is compared against, and it must be ZCL_DET_P_BASE.
 *
 * `order` is required, not optional, because it is what separates
 * NONDETERMINISTIC from TIMING_SENSITIVE: the classifier has to know which
 * CLASS each splitting slot belongs to, and a slot index alone does not say.
 * An earlier version took only the table and hardcoded slot 0 as BASE, which
 * was correct only for a caller measuring the whole enum in enum order — any
 * caller measuring a subset got the right verdict for the wrong reason.
 *
 * Returns false only on a malformed call (null, n == 0, n > 32, order[0] not
 * BASE); a group that cannot be classified is reported as UNKNOWN, which is an
 * answer, not an error. */
bool zcl_det_classify(const struct zcl_det_observation *obs,
                      const enum zcl_det_perturbation *order, size_t n,
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
    size_t timing_sensitive;
    size_t unknown_not_run;
    size_t unknown_no_vector;
    size_t unknown_partial;
    size_t total;
};

void zcl_det_partition_add(struct zcl_det_partition *p,
                           const struct zcl_det_verdict *v);
bool zcl_det_partition_is_exact(const struct zcl_det_partition *p);

#endif /* ZCL_DETERMINISM_CLASSIFY_H */
