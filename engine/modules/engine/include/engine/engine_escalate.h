/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_escalate - which engine runs the NEXT attempt of a task.
 *
 * Cheapest first, escalate only on MEASURED model failure. The tier a task
 * kind starts at is the cheapest engine that is expected to finish it; a
 * stronger (dearer) tier is paid for only after the gate has shown the
 * cheaper one did not deliver. Nothing a model says about itself enters
 * this decision: the caller classifies each attempt from the gate and the
 * delivered diff (see engine_verdict.h) and passes the classification in.
 *
 * Pure logic: no process, file or clock. A function of its arguments.
 *
 * THE RULES, applied in this order (the first that matches decides):
 *
 *   1. last attempt ACCEPTED            -> STOP_ACCEPTED
 *   2. last attempt REFUSED             -> STOP_REFUSED  (a contract refusal
 *                                          is never fixed by a stronger model)
 *   3. attempts >= max_attempts         -> STOP_BUDGET
 *   4. max_cost_tokens > 0 (a cost cap is set), then:
 *        any attempt cost_known=false   -> STOP_COST_UNKNOWN (unknown is not
 *                                          zero; the cap cannot be proven)
 *        checked sum overflows          -> STOP_BUDGET "cost overflow"
 *        sum >= max_cost_tokens         -> STOP_BUDGET
 *      max_cost_tokens == 0 means no cost cap; costs are then not read.
 *   5. two INFRA_FAILED in a row        -> STOP_INFRA
 *   6. choose the wanted tier:
 *        no history                     -> kind_tier
 *        last INFRA_FAILED (first one)  -> the SAME tier (the gate host
 *                                          failed, not the model)
 *        last GATE_FAILED / NO_CHANGE   -> one tier up from the last attempt
 *                                          (light -> standard -> heavy)
 *   7. wanted tier above the ceiling    -> STOP_CEILING "ceiling reached"
 *   8. the first tier in [wanted, ceiling] for which the lead has an engine
 *      row (engine_for_lead_tier) -> RUN on it; none -> STOP_CEILING
 *      "no engine for lead at tier".
 */

#ifndef ZCL_ENGINE_ESCALATE_H
#define ZCL_ENGINE_ESCALATE_H

#include "engine/engine.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum engine_attempt_outcome {
    ENGINE_ATTEMPT_ACCEPTED = 0,
    ENGINE_ATTEMPT_GATE_FAILED, /* tests/lint failed on the model's change */
    ENGINE_ATTEMPT_NO_CHANGE,   /* the model delivered nothing usable */
    ENGINE_ATTEMPT_INFRA_FAILED,/* build host, devbuild, disk, gate timeout */
    ENGINE_ATTEMPT_REFUSED      /* contract / pre-dispatch refusal */
};

struct engine_attempt {
    enum engine_tier tier;
    enum engine_attempt_outcome outcome;
    uint64_t cost_tokens; /* uncached input + output; 0 if unknown */
    bool cost_known;
};

struct engine_budget {
    uint32_t max_attempts;     /* 0 allows no attempt at all */
    uint64_t max_cost_tokens;  /* 0 = no cost cap */
    enum engine_tier ceiling;  /* highest tier that may be used */
};

enum engine_next_action {
    ENGINE_NEXT_RUN = 0,
    ENGINE_NEXT_STOP_ACCEPTED,
    ENGINE_NEXT_STOP_BUDGET,
    ENGINE_NEXT_STOP_CEILING,
    ENGINE_NEXT_STOP_INFRA,
    ENGINE_NEXT_STOP_REFUSED,
    ENGINE_NEXT_STOP_COST_UNKNOWN
};

struct engine_next {
    enum engine_next_action action;
    enum engine_tier tier;              /* meaningful for RUN */
    const struct engine_vendor *engine; /* non-NULL only for RUN */
    const char *reason;                 /* static string naming the rule */
};

/* Decide the next step. Returns 0 and fills `out`, or a negative errno
 * (-EINVAL) and leaves `out` untouched for: NULL lead/budget/out, empty
 * lead, NULL history with n > 0, kind_tier or ceiling outside
 * LIGHT..HEAVY, or any history entry with an out-of-range tier/outcome.
 * `history` is read-only and oldest-first. */
int engine_escalate_next(const char *lead, enum engine_tier kind_tier,
                         const struct engine_attempt *history, size_t n,
                         const struct engine_budget *budget,
                         struct engine_next *out);

#endif /* ZCL_ENGINE_ESCALATE_H */
