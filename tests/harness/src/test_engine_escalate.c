/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_engine_escalate: the escalation policy is table-driven. Each row is
 * one history and the single decision the rules in engine/engine_escalate.h
 * must make from it. The claude lead has light/standard/heavy rows in the
 * registry; the gpt lead has none yet, which is itself a rule under test. */

#include "test/test_core.h"

#include "engine/engine_escalate.h"

#include <stdio.h>
#include <string.h>

#define EE_CHECK(name, expr)                                             \
    do {                                                                 \
        const bool ee_ok_ = (expr);                                      \
        if (!ee_ok_) failures++;                                         \
        printf("engine_escalate: %s %s\n", ee_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

#define L ENGINE_TIER_LIGHT
#define S ENGINE_TIER_STANDARD
#define H ENGINE_TIER_HEAVY
#define ACC ENGINE_ATTEMPT_ACCEPTED
#define GF  ENGINE_ATTEMPT_GATE_FAILED
#define NC  ENGINE_ATTEMPT_NO_CHANGE
#define IF  ENGINE_ATTEMPT_INFRA_FAILED
#define REF ENGINE_ATTEMPT_REFUSED
#define A(t, o, c) { (t), (o), (c), true }
#define AU(t, o)   { (t), (o), 0, false }

struct row {
    const char *name;
    const char *lead;
    enum engine_tier kind;
    struct engine_attempt h[6];
    size_t n;
    struct engine_budget b;
    enum engine_next_action action;
    enum engine_tier tier;      /* checked for RUN */
    const char *reason;         /* exact, or NULL to skip */
};

#define B_OPEN { 10, 0, H }

static const struct row k_rows[] = {
    { "no history runs the kind tier (light)", "claude", L, {{0}}, 0, B_OPEN,
      ENGINE_NEXT_RUN, L, NULL },
    { "no history runs the kind tier (standard)", "claude", S, {{0}}, 0, B_OPEN,
      ENGINE_NEXT_RUN, S, NULL },
    { "accepted stops", "claude", L, { A(L, ACC, 5) }, 1, B_OPEN,
      ENGINE_NEXT_STOP_ACCEPTED, 0, NULL },
    { "accepted wins over a spent budget", "claude", L,
      { A(L, GF, 5), A(S, ACC, 5) }, 2, { 2, 0, H },
      ENGINE_NEXT_STOP_ACCEPTED, 0, NULL },
    { "gate failure escalates light to standard", "claude", L,
      { A(L, GF, 5) }, 1, B_OPEN, ENGINE_NEXT_RUN, S, NULL },
    { "no change escalates standard to heavy", "claude", L,
      { A(L, GF, 5), A(S, NC, 5) }, 2, B_OPEN, ENGINE_NEXT_RUN, H, NULL },
    { "failure at heavy hits the ceiling", "claude", L,
      { A(L, GF, 1), A(S, GF, 1), A(H, GF, 1) }, 3, B_OPEN,
      ENGINE_NEXT_STOP_CEILING, 0, "ceiling reached" },
    { "ceiling=standard stops after standard fails", "claude", L,
      { A(L, GF, 1), A(S, GF, 1) }, 2, { 10, 0, S },
      ENGINE_NEXT_STOP_CEILING, 0, "ceiling reached" },
    { "ceiling=standard still runs standard", "claude", L,
      { A(L, GF, 1) }, 1, { 10, 0, S }, ENGINE_NEXT_RUN, S, NULL },
    { "kind tier above ceiling", "claude", H, {{0}}, 0, { 10, 0, S },
      ENGINE_NEXT_STOP_CEILING, 0, "ceiling reached" },
    { "infra retries the same tier", "claude", L,
      { A(L, IF, 1) }, 1, B_OPEN, ENGINE_NEXT_RUN, L, NULL },
    { "infra after an escalation retries the escalated tier", "claude", L,
      { A(L, GF, 1), A(S, IF, 1) }, 2, B_OPEN, ENGINE_NEXT_RUN, S, NULL },
    { "two infra in a row stop", "claude", L,
      { A(L, IF, 1), A(L, IF, 1) }, 2, B_OPEN,
      ENGINE_NEXT_STOP_INFRA, 0, NULL },
    { "infra, model failure, infra is not consecutive", "claude", L,
      { A(L, IF, 1), A(L, GF, 1), A(S, IF, 1) }, 3, B_OPEN,
      ENGINE_NEXT_RUN, S, NULL },
    { "refusal at attempt 1 never escalates", "claude", L,
      { A(L, REF, 0) }, 1, B_OPEN, ENGINE_NEXT_STOP_REFUSED, 0, NULL },
    { "attempt budget", "claude", L,
      { A(L, GF, 1), A(S, GF, 1) }, 2, { 2, 0, H },
      ENGINE_NEXT_STOP_BUDGET, 0, "attempt budget spent" },
    { "zero attempts allowed", "claude", L, {{0}}, 0, { 0, 0, H },
      ENGINE_NEXT_STOP_BUDGET, 0, NULL },
    { "cost budget reached", "claude", L,
      { A(L, GF, 60), A(S, GF, 40) }, 2, { 10, 100, H },
      ENGINE_NEXT_STOP_BUDGET, 0, "token budget spent" },
    { "cost budget not yet reached", "claude", L,
      { A(L, GF, 60), A(S, GF, 39) }, 2, { 10, 100, H },
      ENGINE_NEXT_RUN, H, NULL },
    { "unknown cost under a cost cap", "claude", L,
      { AU(L, GF) }, 1, { 10, 100, H }, ENGINE_NEXT_STOP_COST_UNKNOWN, 0, NULL },
    { "unknown cost without a cost cap is fine", "claude", L,
      { AU(L, GF) }, 1, B_OPEN, ENGINE_NEXT_RUN, S, NULL },
    { "cost sum overflow", "claude", L,
      { A(L, GF, UINT64_MAX), A(S, GF, 2) }, 2, { 10, 100, H },
      ENGINE_NEXT_STOP_BUDGET, 0, "cost overflow" },
    { "gpt lead has no rows", "gpt", L, {{0}}, 0, B_OPEN,
      ENGINE_NEXT_STOP_CEILING, 0, "no engine for lead at tier" },
    { "unknown lead has no rows", "nobody", S,
      { A(S, GF, 1) }, 1, B_OPEN,
      ENGINE_NEXT_STOP_CEILING, 0, "no engine for lead at tier" },
};

static int check_row(const struct row *r)
{
    int failures = 0;
    struct engine_next o;
    memset(&o, 0xAB, sizeof o);
    const int rc = engine_escalate_next(r->lead, r->kind, r->h, r->n, &r->b, &o);
    const bool run = r->action == ENGINE_NEXT_RUN;
    bool ok = rc == 0 && o.action == r->action;
    if (ok && run)
        ok = o.tier == r->tier && o.engine != NULL
             && o.engine == engine_for_lead_tier(r->lead, r->tier);
    if (ok && !run)
        ok = o.engine == NULL;
    if (ok && r->reason)
        ok = o.reason && strcmp(o.reason, r->reason) == 0;
    if (ok)
        ok = o.reason && o.reason[0];
    EE_CHECK(r->name, ok);
    return failures;
}

static int case_invalid(void)
{
    int failures = 0;
    const struct engine_budget b = B_OPEN;
    const struct engine_attempt good[1] = { A(L, GF, 1) };
    const struct engine_attempt bad_tier[1] = { A(ENGINE_TIER_NONE, GF, 1) };
    const struct engine_attempt bad_out[1] = { A(L, (enum engine_attempt_outcome)99, 1) };
    const struct engine_budget b_none = { 10, 0, ENGINE_TIER_NONE };
    struct engine_next o, ref;
    memset(&o, 0x5A, sizeof o);
    memcpy(&ref, &o, sizeof o);

    EE_CHECK("NULL lead refused",
             engine_escalate_next(NULL, L, good, 1, &b, &o) < 0);
    EE_CHECK("empty lead refused",
             engine_escalate_next("", L, good, 1, &b, &o) < 0);
    EE_CHECK("NULL budget refused",
             engine_escalate_next("claude", L, good, 1, NULL, &o) < 0);
    EE_CHECK("NULL out refused",
             engine_escalate_next("claude", L, good, 1, &b, NULL) < 0);
    EE_CHECK("NULL history with n>0 refused",
             engine_escalate_next("claude", L, NULL, 1, &b, &o) < 0);
    EE_CHECK("kind tier NONE refused",
             engine_escalate_next("claude", ENGINE_TIER_NONE, NULL, 0, &b, &o) < 0);
    EE_CHECK("kind tier out of range refused",
             engine_escalate_next("claude", (enum engine_tier)9, NULL, 0, &b, &o) < 0);
    EE_CHECK("ceiling NONE refused",
             engine_escalate_next("claude", L, NULL, 0, &b_none, &o) < 0);
    EE_CHECK("history tier NONE refused",
             engine_escalate_next("claude", L, bad_tier, 1, &b, &o) < 0);
    EE_CHECK("history outcome out of range refused",
             engine_escalate_next("claude", L, bad_out, 1, &b, &o) < 0);
    EE_CHECK("out untouched on every refusal", memcmp(&o, &ref, sizeof o) == 0);
    return failures;
}

int test_engine_escalate(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof k_rows / sizeof k_rows[0]; i++)
        failures += check_row(&k_rows[i]);
    failures += case_invalid();
    printf("engine_escalate: %d failure(s)\n", failures);
    return failures;
}
