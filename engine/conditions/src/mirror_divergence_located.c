/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Condition: mirror_divergence_located (fail-loud validation pack,
 * check 6)
 *
 * Detects the PERMANENT mirror.divergence_located blocker: the locator
 * bisected a hash-disagreement vs the co-located zclassicd down to the
 * FIRST diverging height. The page already fired with
 * (first_div_h, ours, theirs); this Condition keeps the divergence
 * escalating until repaired.
 *
 * WINDOW_REBUILD TRIGGER SEAM: replace this re-witness remedy with
 * window_rebuild(first_div_h) (the blocker reason + `z23 dumpstate`
 * validation_pack carry it). Clear ON WITNESSED success only. Until
 * then: HOLD + PAGE, the operator owns the repair. */

#include "conditions/condition_registry.h"
#include "framework/condition.h"
#include "util/blocker.h"

#include <stdbool.h>

static bool detect_mirror_divergence_located(void)
{
    return blocker_exists("mirror.divergence_located");
}

static enum condition_remedy_result remedy_mirror_divergence_located(void)
{
    /* WINDOW_REBUILD TRIGGER SEAM: rebuild from first_div_h.
     * No automated repair yet — FAILED escalates to the operator. */
    return COND_REMEDY_FAILED;
}

static bool witness_mirror_divergence_located(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: remedy returns COND_REMEDY_FAILED (no automated
    // repair), so this read can never be credited as a remedy-caused
    // clear. The PERMANENT blocker is cleared only by a real repair
    // (operator / window_rebuild), so a clear here witnesses the
    // divergence actually resolved.
    return !detect_mirror_divergence_located();
}

static struct condition c_mirror_divergence_located = {
    .name = "mirror_divergence_located",
    .severity = COND_CRITICAL,
    .poll_secs = 60,
    .backoff_secs = 600,
    .max_attempts = 2,
    .detect = detect_mirror_divergence_located,
    .remedy = remedy_mirror_divergence_located,
    .witness = witness_mirror_divergence_located,
    .witness_window_secs = 120,
};

void register_mirror_divergence_located(void)
{
    (void)condition_register(&c_mirror_divergence_located);
}
