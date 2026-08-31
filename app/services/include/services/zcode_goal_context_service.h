/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic plain-language goal selection over the code index. */
#ifndef ZCL_SERVICES_ZCODE_GOAL_CONTEXT_SERVICE_H
#define ZCL_SERVICES_ZCODE_GOAL_CONTEXT_SERVICE_H

#include "base/result.h"
#include "codeindex/codeindex.h"

#include <stddef.h>
#include <stdint.h>

#define ZCODE_GOAL_MAX_TOKENS 16u
#define ZCODE_GOAL_TOKEN_MAX 63u
#define ZCODE_GOAL_MAX_CANDIDATES 16u

struct zcode_goal_candidate {
    struct ci_symbol symbol;
    char symbol_id[400];
    char matched_token[ZCODE_GOAL_TOKEN_MAX + 1u];
    char why[64];
    uint32_t match_mask;
    int score;
};

struct zcode_goal_selection {
    char tokens[ZCODE_GOAL_MAX_TOKENS][ZCODE_GOAL_TOKEN_MAX + 1u];
    size_t token_count;
    struct zcode_goal_candidate candidates[ZCODE_GOAL_MAX_CANDIDATES];
    size_t candidate_count;
    size_t total_matches;
    size_t dropped_candidates;
    bool budget_exhausted;
    struct ci_symbol selected;
    char selected_symbol_id[400];
    char why[64];
    uint64_t generation_us;
    uint64_t retrieval_us;
    size_t retrieval_corpus_files;
    size_t retrieval_ranked_files;
    bool retrieval_truncated;
    uint32_t service_generation;
};

/* Select a bounded ranked symbol from goal text. exact_symbol may name an
 * exact symbol or stable ID and bypasses ranking. This builds/refreshes only
 * the existing rebuildable code index; it creates no canonical authority. */
struct zcl_result zcode_goal_context_select(
    const char *workspace, const char *goal, const char *exact_symbol,
    struct zcode_goal_selection *out);

#endif /* ZCL_SERVICES_ZCODE_GOAL_CONTEXT_SERVICE_H */
