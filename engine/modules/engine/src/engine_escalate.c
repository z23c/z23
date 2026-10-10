/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Escalation policy. The rule table lives in engine/engine_escalate.h. */

#include "engine/engine_escalate.h"

#include <errno.h>

static bool tier_valid(enum engine_tier t)
{
    return t >= ENGINE_TIER_LIGHT && t <= ENGINE_TIER_HEAVY;
}

static bool args_valid(const char *lead, enum engine_tier kind_tier,
                       const struct engine_attempt *h, size_t n,
                       const struct engine_budget *b, const struct engine_next *out)
{
    if (!lead || !lead[0] || !b || !out || (n > 0 && !h))
        return false;
    if (!tier_valid(kind_tier) || !tier_valid(b->ceiling))
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!tier_valid(h[i].tier)
            || (unsigned)h[i].outcome > (unsigned)ENGINE_ATTEMPT_REFUSED)
            return false;
    }
    return true;
}

static void stop(struct engine_next *o, enum engine_next_action a,
                 const char *reason)
{
    o->action = a;
    o->tier = ENGINE_TIER_NONE;
    o->engine = NULL;
    o->reason = reason;
}

/* Rule 4. Returns true and fills `o` when the cost cap decides. */
static bool cost_stop(const struct engine_attempt *h, size_t n,
                      const struct engine_budget *b, struct engine_next *o)
{
    if (b->max_cost_tokens == 0)
        return false;
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        if (!h[i].cost_known) {
            stop(o, ENGINE_NEXT_STOP_COST_UNKNOWN,
                 "cost cap set but an attempt cost is unknown");
            return true;
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (__builtin_add_overflow(sum, h[i].cost_tokens, &sum)) {
            stop(o, ENGINE_NEXT_STOP_BUDGET, "cost overflow");
            return true;
        }
    }
    if (sum >= b->max_cost_tokens) {
        stop(o, ENGINE_NEXT_STOP_BUDGET, "token budget spent");
        return true;
    }
    return false;
}

/* Rules 1-5: every stop that does not depend on the tier ladder. */
static bool terminal_stop(const struct engine_attempt *h, size_t n,
                          const struct engine_budget *b, struct engine_next *o)
{
    if (n > 0 && h[n - 1].outcome == ENGINE_ATTEMPT_ACCEPTED) {
        stop(o, ENGINE_NEXT_STOP_ACCEPTED, "last attempt accepted");
        return true;
    }
    if (n > 0 && h[n - 1].outcome == ENGINE_ATTEMPT_REFUSED) {
        stop(o, ENGINE_NEXT_STOP_REFUSED, "contract refusal is never escalated");
        return true;
    }
    if (n >= b->max_attempts) {
        stop(o, ENGINE_NEXT_STOP_BUDGET, "attempt budget spent");
        return true;
    }
    if (cost_stop(h, n, b, o))
        return true;
    if (n >= 2 && h[n - 1].outcome == ENGINE_ATTEMPT_INFRA_FAILED
        && h[n - 2].outcome == ENGINE_ATTEMPT_INFRA_FAILED) {
        stop(o, ENGINE_NEXT_STOP_INFRA, "two infra failures in a row");
        return true;
    }
    return false;
}

/* Rule 6. */
static enum engine_tier wanted_tier(enum engine_tier kind_tier,
                                    const struct engine_attempt *h, size_t n)
{
    if (n == 0)
        return kind_tier;
    if (h[n - 1].outcome == ENGINE_ATTEMPT_INFRA_FAILED)
        return h[n - 1].tier;
    return (enum engine_tier)((int)h[n - 1].tier + 1);
}

int engine_escalate_next(const char *lead, enum engine_tier kind_tier,
                         const struct engine_attempt *history, size_t n,
                         const struct engine_budget *budget,
                         struct engine_next *out)
{
    if (!args_valid(lead, kind_tier, history, n, budget, out))
        return -EINVAL;

    struct engine_next r;
    if (terminal_stop(history, n, budget, &r)) {
        *out = r;
        return 0;
    }
    const int want = (int)wanted_tier(kind_tier, history, n);
    if (want > (int)budget->ceiling) {
        stop(&r, ENGINE_NEXT_STOP_CEILING, "ceiling reached");
        *out = r;
        return 0;
    }
    for (int t = want; t <= (int)budget->ceiling; t++) {
        const struct engine_vendor *v =
            engine_for_lead_tier(lead, (enum engine_tier)t);
        if (v) {
            r.action = ENGINE_NEXT_RUN;
            r.tier = (enum engine_tier)t;
            r.engine = v;
            r.reason = n == 0 ? "first attempt at the kind tier"
                       : history[n - 1].outcome == ENGINE_ATTEMPT_INFRA_FAILED
                           ? "retry the same tier after infra failure"
                           : "escalate one tier after measured failure";
            *out = r;
            return 0;
        }
    }
    stop(&r, ENGINE_NEXT_STOP_CEILING, "no engine for lead at tier");
    *out = r;
    return 0;
}
