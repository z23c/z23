/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, explainable goal-to-symbol selection for ZCODE work. */

#include "services/zcode_goal_context_service.h"

#include "hotswap/hotswap_service.h"
#include "platform/time_compat.h"
#include "services/zcode_goal_context_calc_service.h"

#include <stdio.h>
#include <string.h>

#define ZGOAL_HITS_PER_TOKEN 16
#define ZGOAL_FALLBACK_GROUPS 128
#define ZGOAL_FALLBACK_FILES 64
#define ZGOAL_FALLBACK_SYMBOLS 32

static void zgoal_why(uint32_t mask, char out[64])
{
    out[0] = '\0';
    static const struct { uint32_t bit; const char *name; } fields[] = {
        { CI_SEARCH_MATCH_NAME, "name" },
        { CI_SEARCH_MATCH_SIGNATURE, "signature" },
        { CI_SEARCH_MATCH_PATH, "path" },
        { CI_SEARCH_MATCH_DOC, "documentation" },
    };
    size_t used = 0;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!(mask & fields[i].bit)) continue;
        int n = snprintf(out + used, 64u - used, "%s%s",
                         used ? "+" : "", fields[i].name);
        if (n < 0 || (size_t)n >= 64u - used) break;
        used += (size_t)n;
    }
}

static bool zgoal_same(const struct zcode_goal_candidate *candidate,
                       const struct ci_symbol *symbol)
{
    return strcmp(candidate->symbol.name, symbol->name) == 0 &&
           strcmp(candidate->symbol.def_path, symbol->def_path) == 0 &&
           strcmp(candidate->symbol.decl_path, symbol->decl_path) == 0;
}

static bool zgoal_add(struct zcode_goal_selection *out,
                      const struct ci_search_hit *hit, const char *token);

static int zgoal_fallback_score(const struct ci_symbol *symbol)
{
    int score = 0;
    if (symbol->kind == 'T') score += 400;
    else if (symbol->kind == 't') score += 250;
    else if (symbol->kind == 'Y' || symbol->kind == 'S' ||
             symbol->kind == 'E') score += 100;
    if (strstr(symbol->def_path, "/src/") ||
        strncmp(symbol->def_path, "src/", 4) == 0)
        score += 80;
    if (strstr(symbol->def_path, "/test") ||
        strncmp(symbol->def_path, "test", 4) == 0)
        score -= 200;
    if (strcmp(symbol->name, "main") == 0) score -= 300;
    return score;
}

/* A plain-language goal may describe behavior without sharing any spelling
 * with a tiny project's symbols.  In that case select a deterministic real
 * project entry point rather than requiring the user to discover and supply
 * an internal name.  This is explicitly context policy, not evidence that the
 * chosen symbol semantically satisfies the goal. */
static struct zcl_result zgoal_project_fallback(
    struct codeindex *index, struct zcode_goal_selection *out)
{
    struct ci_group groups[ZGOAL_FALLBACK_GROUPS];
    int group_count = codeindex_groups(index, groups, ZGOAL_FALLBACK_GROUPS);
    if (group_count < 0)
        return ZCL_ERR(-1, "indexed project fallback could not list groups");
    if (group_count == ZGOAL_FALLBACK_GROUPS) out->budget_exhausted = true;

    for (int g = 0; g < group_count; g++) {
        struct ci_file files[ZGOAL_FALLBACK_FILES];
        int file_count = codeindex_files_in_group(
            index, groups[g].path, files, ZGOAL_FALLBACK_FILES);
        if (file_count < 0)
            return ZCL_ERR(-1, "indexed project fallback could not list files");
        if (file_count == ZGOAL_FALLBACK_FILES) out->budget_exhausted = true;
        for (int f = 0; f < file_count; f++) {
            struct ci_symbol symbols[ZGOAL_FALLBACK_SYMBOLS];
            int symbol_count = codeindex_symbols_in_file(
                index, files[f].path, symbols, ZGOAL_FALLBACK_SYMBOLS);
            if (symbol_count < 0)
                return ZCL_ERR(-1,
                               "indexed project fallback could not list symbols");
            if (symbol_count == ZGOAL_FALLBACK_SYMBOLS)
                out->budget_exhausted = true;
            for (int s = 0; s < symbol_count; s++) {
                struct ci_search_hit hit = {
                    .symbol = symbols[s],
                    .score = zgoal_fallback_score(&symbols[s]),
                };
                if (!zgoal_add(out, &hit, "project"))
                    return ZCL_ERR(-1,
                                   "fallback selected symbol identity failed");
                for (size_t c = 0; c < out->candidate_count; c++) {
                    if (!zgoal_same(&out->candidates[c], &symbols[s]))
                        continue;
                    (void)snprintf(out->candidates[c].why,
                                   sizeof(out->candidates[c].why),
                                   "project_entry_fallback");
                    break;
                }
            }
        }
    }
    if (out->candidate_count == 0)
        return ZCL_ERR(-1, "project contains no indexed context symbol");
    return ZCL_OK;
}

static bool zgoal_add(struct zcode_goal_selection *out,
                      const struct ci_search_hit *hit, const char *token)
{
    out->total_matches++;
    for (size_t i = 0; i < out->candidate_count; i++) {
        if (!zgoal_same(&out->candidates[i], &hit->symbol)) continue;
        out->candidates[i].match_mask |= hit->match_mask;
        if (hit->score + 25 > out->candidates[i].score) {
            out->candidates[i].score = hit->score + 25;
            (void)snprintf(out->candidates[i].matched_token,
                           sizeof(out->candidates[i].matched_token), "%s",
                           token);
        }
        zgoal_why(out->candidates[i].match_mask,
                  out->candidates[i].why);
        return true;
    }
    if (out->candidate_count >= ZCODE_GOAL_MAX_CANDIDATES) {
        out->dropped_candidates++;
        out->budget_exhausted = true;
        return true;
    }
    struct zcode_goal_candidate *candidate =
        &out->candidates[out->candidate_count++];
    candidate->symbol = hit->symbol;
    candidate->match_mask = hit->match_mask;
    candidate->score = hit->score;
    (void)snprintf(candidate->matched_token,
                   sizeof(candidate->matched_token), "%s", token);
    zgoal_why(candidate->match_mask, candidate->why);
    return codeindex_symbol_record_id(&candidate->symbol,
                                      candidate->symbol_id,
                                      sizeof(candidate->symbol_id)) >= 0;
}

static struct zcl_result zgoal_exact(
    struct codeindex *index, const char *exact,
    struct zcode_goal_selection *out)
{
    bool found = false;
    bool ok = strchr(exact, ':')
        ? codeindex_symbol_by_id(index, exact, &out->selected, &found)
        : codeindex_symbol(index, exact, &out->selected, &found);
    if (!ok || !found)
        return ZCL_ERR(-1, "exact context symbol is not indexed: %s", exact);
    if (codeindex_symbol_record_id(&out->selected,
                                   out->selected_symbol_id,
                                   sizeof(out->selected_symbol_id)) < 0)
        return ZCL_ERR(-1, "exact context symbol has no stable identity");
    (void)snprintf(out->why, sizeof(out->why), "exact_symbol_override");
    return ZCL_OK;
}

struct zcl_result zcode_goal_context_select(
    const char *workspace, const char *goal, const char *exact_symbol,
    struct zcode_goal_selection *out)
{
    if (!workspace || !goal || !goal[0] || !out || strlen(goal) > 4096)
        return ZCL_ERR(-1, "goal selection requires workspace and bounded goal");
    memset(out, 0, sizeof(*out));
    int64_t started = platform_time_monotonic_us();
    struct codeindex *index = codeindex_open(workspace);
    if (!index) return ZCL_ERR(-1, "code index could not open for goal selection");
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_goal_context_calc_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID, &lease);
    if (!service) service = zcode_goal_context_calc_service_builtin();
    out->service_generation = zcl_hotswap_service_generation();
    struct zcl_result result = ZCL_OK;
    if (exact_symbol && exact_symbol[0]) {
        result = zgoal_exact(index, exact_symbol, out);
    } else {
        struct zcode_goal_tokens_v1 tokens;
        if (!service->tokenize(goal, &tokens) || !tokens.valid) {
            result = ZCL_ERR(-1, "pure goal tokenization refused bounded input");
        } else {
            out->token_count = tokens.count;
            out->budget_exhausted = tokens.budget_exhausted;
            memcpy(out->tokens, tokens.values, sizeof(out->tokens));
        }
        for (size_t i = 0; i < out->token_count && result.ok; i++) {
            struct ci_search_hit hits[ZGOAL_HITS_PER_TOKEN];
            int count = codeindex_search_text(index, out->tokens[i], hits,
                                              ZGOAL_HITS_PER_TOKEN);
            if (count < 0) {
                result = ZCL_ERR(-1, "indexed goal search failed for '%s'",
                                 out->tokens[i]);
                break;
            }
            if (count == ZGOAL_HITS_PER_TOKEN)
                out->budget_exhausted = true;
            for (int j = 0; j < count; j++) {
                if (!zgoal_add(out, &hits[j], out->tokens[i])) {
                    result = ZCL_ERR(-1, "selected symbol identity failed");
                    break;
                }
            }
        }
        if (result.ok && out->candidate_count == 0)
            result = zgoal_project_fallback(index, out);
        if (result.ok) {
            if (!service->rank(out->candidates, out->candidate_count))
                result = ZCL_ERR(-1,
                                 "pure candidate ranking refused bounded input");
        }
        if (result.ok) {
            out->selected = out->candidates[0].symbol;
            (void)snprintf(out->selected_symbol_id,
                           sizeof(out->selected_symbol_id), "%s",
                           out->candidates[0].symbol_id);
            if (strcmp(out->candidates[0].why,
                       "project_entry_fallback") == 0)
                (void)snprintf(out->why, sizeof(out->why), "%s",
                               out->candidates[0].why);
            else
                /* The token is free text and degrades gracefully when cut;
                 * `why` is a closed-set composite whose longest value is
                 * "name+signature+path+documentation" (33), and a clipped
                 * composite names no member of that vocabulary. Spend the
                 * 63 usable bytes accordingly: 29 + : + 33. */
                (void)snprintf(out->why, sizeof(out->why), "%.29s:%.33s",
                               out->candidates[0].matched_token,
                               out->candidates[0].why);
        }
    }
    zcl_hotswap_service_release(&lease);
    codeindex_close(index);
    int64_t elapsed = platform_time_monotonic_us() - started;
    out->generation_us = elapsed > 0 ? (uint64_t)elapsed : 1u;
    if (!result.ok) memset(&out->selected, 0, sizeof(out->selected));
    return result;
}

static bool zgoal_calc_frozen_kat(const void *opaque, char *why,
                                  size_t why_sz)
{
    const struct zcode_goal_context_calc_service_v1 *service = opaque;
    struct zcode_goal_tokens_v1 tokens;
    if (!service || !service->tokenize || !service->rank ||
        !service->render_status ||
        !service->tokenize("Repair repairs repairing checksum and data data",
                           &tokens) || !tokens.valid || tokens.count != 2 ||
        strcmp(tokens.values[0], "checksum") != 0 ||
        strcmp(tokens.values[1], "data") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen goal tokenization vector failed");
        return false;
    }
    struct zcode_goal_candidate candidates[3] = {
        {.score = 7}, {.score = 9}, {.score = 9},
    };
    (void)snprintf(candidates[0].symbol.name,
                   sizeof(candidates[0].symbol.name), "%s", "zeta");
    (void)snprintf(candidates[1].symbol.name,
                   sizeof(candidates[1].symbol.name), "%s", "beta");
    (void)snprintf(candidates[2].symbol.name,
                   sizeof(candidates[2].symbol.name), "%s", "alpha");
    if (!service->rank(candidates, 3) ||
        strcmp(candidates[0].symbol.name, "alpha") != 0 ||
        strcmp(candidates[1].symbol.name, "beta") != 0 ||
        strcmp(candidates[2].symbol.name, "zeta") != 0 ||
        service->rank(candidates, 0)) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen goal ranking vector failed");
        return false;
    }
    struct zcode_goal_context_view_v1 view;
    if (!service->render_status(&view) || !view.valid ||
        strcmp(view.next_action,
               "zcode work start --input='<workspace and goal>'") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen goal context status vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_zgoal_calc_contract = {
    .service_id = ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID,
    .source_tu = "app/services/src/zcode_goal_context_calc_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_goal_context_calc_service_v1),
    .abi_fingerprint = ZCODE_GOAL_CONTEXT_CALC_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_GOAL_CONTEXT_CALC_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_GOAL_CONTEXT_CALC_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_GOAL_CONTEXT_CALC_KAT_FINGERPRINT,
    .frozen_kat = zgoal_calc_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcode_goal_context_calc_service_contract(void)
{
    return &k_zgoal_calc_contract;
}
