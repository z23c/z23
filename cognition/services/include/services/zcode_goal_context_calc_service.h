/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure goal tokenization and candidate ranking ABI. */

#ifndef ZCL_SERVICES_ZCODE_GOAL_CONTEXT_CALC_SERVICE_H
#define ZCL_SERVICES_ZCODE_GOAL_CONTEXT_CALC_SERVICE_H

#include "services/zcode_goal_context_service.h"

#include <stdbool.h>
#include <stddef.h>

#define ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID "zcode.goal-context.calc.v1"
#define ZCODE_GOAL_CONTEXT_CALC_ABI_FINGERPRINT \
    "zcode.goal-context.calc.abi.v1:8683e1da"
#define ZCODE_GOAL_CONTEXT_CALC_SCHEMA_FINGERPRINT \
    "zcl.zcode_work_context.v1+goal-tokens.v1+candidate-rank.v1"
#define ZCODE_GOAL_CONTEXT_CALC_WIRE_FINGERPRINT \
    "goal-tokenization+candidate-ranking.v1"
#define ZCODE_GOAL_CONTEXT_CALC_KAT_FINGERPRINT \
    "1f7706241e21a6a0630abe43242a44101d059739bd45f5a64f62a5adc16e2a66"

struct zcode_goal_tokens_v1 {
    bool valid;
    bool budget_exhausted;
    size_t count;
    char values[ZCODE_GOAL_MAX_TOKENS][ZCODE_GOAL_TOKEN_MAX + 1u];
};

struct zcode_goal_context_view_v1 {
    bool valid;
    char capability[160];
    char next_action[128];
};

struct zcode_goal_context_calc_service_v1 {
    bool (*tokenize)(const char *goal, struct zcode_goal_tokens_v1 *out);
    bool (*rank)(struct zcode_goal_candidate *candidates, size_t count);
    bool (*render_status)(struct zcode_goal_context_view_v1 *out);
};

const struct zcode_goal_context_calc_service_v1 *
zcode_goal_context_calc_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcode_goal_context_calc_service_contract(void);

#endif /* ZCL_SERVICES_ZCODE_GOAL_CONTEXT_CALC_SERVICE_H */
