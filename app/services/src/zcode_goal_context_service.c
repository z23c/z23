/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, explainable goal-to-symbol selection for ZCODE work. */

#include "services/zcode_goal_context_service.h"

#include "base/safe_alloc.h"
#include "hotswap/hotswap_service.h"
#include "platform/time_compat.h"
#include "services/zcode_goal_context_calc_service.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZGOAL_HITS_PER_TOKEN 16
#define ZGOAL_FALLBACK_GROUPS 128
#define ZGOAL_FALLBACK_FILES 64
#define ZGOAL_FALLBACK_SYMBOLS 32
#define ZGOAL_SELECTIVITY_STEP 10
#define ZGOAL_STORY_FILES (ZCODE_GOAL_MAX_CANDIDATES + 1u)
#define ZGOAL_STORY_RANK_BASE 2000
#define ZGOAL_STORY_RANK_STEP 25

struct zgoal_token_hits {
    struct ci_search_hit hits[ZGOAL_HITS_PER_TOKEN];
    int count;
    size_t token_index;
};

struct zgoal_story_candidate {
    struct zcode_goal_candidate candidate;
    int strongest_evidence;
};

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
static int zgoal_fallback_score(const struct ci_symbol *symbol);

static int zgoal_story_cmp(const void *left_opaque, const void *right_opaque)
{
    const struct zgoal_story_candidate *left = left_opaque;
    const struct zgoal_story_candidate *right = right_opaque;
    if (left->candidate.score != right->candidate.score)
        return left->candidate.score > right->candidate.score ? -1 : 1;
    int by_name = strcmp(left->candidate.symbol.name,
                         right->candidate.symbol.name);
    if (by_name) return by_name;
    int by_def = strcmp(left->candidate.symbol.def_path,
                        right->candidate.symbol.def_path);
    return by_def ? by_def : strcmp(left->candidate.symbol.decl_path,
                                    right->candidate.symbol.decl_path);
}

static bool zgoal_story_add(struct zgoal_story_candidate *pool,
                            size_t *pool_count, size_t pool_cap,
                            struct zcode_goal_selection *out,
                            const struct ci_search_hit *hit,
                            const char *token, int selectivity)
{
    if (hit->score < 0 || hit->score > INT_MAX - selectivity)
        return false;
    int evidence = hit->score + selectivity;
    out->total_matches++;
    for (size_t i = 0; i < *pool_count; i++) {
        struct zcode_goal_candidate *candidate = &pool[i].candidate;
        if (!zgoal_same(candidate, &hit->symbol))
            continue; /* raw-return-ok:pure-symbol-identity-predicate */
        if (candidate->score > INT_MAX - evidence) return false;
        candidate->score += evidence;
        candidate->match_mask |= hit->match_mask;
        if (evidence > pool[i].strongest_evidence) {
            pool[i].strongest_evidence = evidence;
            (void)snprintf(candidate->matched_token,
                           sizeof(candidate->matched_token), "%s", token);
        }
        zgoal_why(candidate->match_mask, candidate->why);
        return true;
    }
    if (*pool_count >= pool_cap) return false;
    struct zgoal_story_candidate *added = &pool[(*pool_count)++];
    added->candidate.symbol = hit->symbol;
    added->candidate.match_mask = hit->match_mask;
    added->candidate.score = evidence;
    added->strongest_evidence = evidence;
    (void)snprintf(added->candidate.matched_token,
                   sizeof(added->candidate.matched_token), "%s", token);
    zgoal_why(added->candidate.match_mask, added->candidate.why);
    return codeindex_symbol_record_id(&added->candidate.symbol,
                                      added->candidate.symbol_id,
                                      sizeof(added->candidate.symbol_id)) >= 0;
}

static struct zcl_result zgoal_literal_candidates(
    struct codeindex *index, struct zcode_goal_selection *out)
{
    if (out->token_count == 0) return ZCL_OK;
    struct zgoal_token_hits *batches = zcl_calloc(
        out->token_count, sizeof(*batches), "goal token hit batches");
    size_t pool_cap = out->token_count * ZGOAL_HITS_PER_TOKEN;
    struct zgoal_story_candidate *pool = zcl_calloc(
        pool_cap, sizeof(*pool), "goal story candidates");
    if (!batches || !pool) {
        free(pool);
        free(batches);
        return ZCL_ERR(-1, "goal token hit allocation failed");
    }
    struct zcl_result result = ZCL_OK;
    for (size_t i = 0; i < out->token_count; i++) {
        batches[i].token_index = i;
        batches[i].count = codeindex_search_text(
            index, out->tokens[i], batches[i].hits, ZGOAL_HITS_PER_TOKEN);
        if (batches[i].count < 0) {
            result = ZCL_ERR(-1, "indexed goal search failed for '%s'",
                             out->tokens[i]);
            break;
        }
        if (batches[i].count == ZGOAL_HITS_PER_TOKEN)
            out->budget_exhausted = true;
    }
    if (result.ok) {
        size_t pool_count = 0;
        for (size_t i = 0; i < out->token_count && result.ok; i++) {
            const char *token = out->tokens[batches[i].token_index];
            int selectivity =
                (ZGOAL_HITS_PER_TOKEN - batches[i].count) *
                ZGOAL_SELECTIVITY_STEP;
            for (int j = 0; j < batches[i].count; j++) {
                if (!zgoal_story_add(pool, &pool_count, pool_cap, out,
                                     &batches[i].hits[j], token,
                                     selectivity)) {
                    result = ZCL_ERR(-1,
                                     "story candidate evidence overflowed");
                    break;
                }
            }
        }
        if (result.ok) {
            qsort(pool, pool_count, sizeof(*pool), zgoal_story_cmp);
            out->candidate_count = pool_count < ZCODE_GOAL_MAX_CANDIDATES
                ? pool_count : ZCODE_GOAL_MAX_CANDIDATES;
            out->dropped_candidates = pool_count - out->candidate_count;
            if (out->dropped_candidates != 0) out->budget_exhausted = true;
            for (size_t i = 0; i < out->candidate_count; i++)
                out->candidates[i] = pool[i].candidate;
        }
    }
    free(pool);
    free(batches);
    return result;
}

static int zgoal_symbol_preference(const struct ci_symbol *symbol)
{
    int score = zgoal_fallback_score(symbol);
    if (symbol->doc[0]) score += 20;
    if (symbol->decl_path[0]) score += 10;
    return score;
}

static const struct zcode_goal_candidate *zgoal_candidate_for_file(
    const struct zcode_goal_candidate *candidates, size_t count,
    const char *path)
{
    const struct zcode_goal_candidate *best = NULL;
    for (size_t i = 0; i < count; i++) {
        const struct ci_symbol *symbol = &candidates[i].symbol;
        if (strcmp(symbol->def_path, path) != 0 &&
            strcmp(symbol->decl_path, path) != 0)
            continue;
        if (!best || candidates[i].score > best->score)
            best = &candidates[i];
    }
    return best;
}

static bool zgoal_file_candidate(
    struct codeindex *index, const char *path, size_t rank,
    const struct zcode_goal_candidate *literal, size_t literal_count,
    struct zcode_goal_candidate *out, bool *truncated)
{
    const struct zcode_goal_candidate *observed = zgoal_candidate_for_file(
        literal, literal_count, path);
    if (observed) {
        *out = *observed;
    } else {
        struct ci_symbol *symbols = zcl_calloc(
            ZGOAL_FALLBACK_SYMBOLS, sizeof(*symbols),
            "goal story file symbols");
        if (!symbols) return false;
        int count = codeindex_symbols_in_file(
            index, path, symbols, ZGOAL_FALLBACK_SYMBOLS);
        if (count < 0) {
            free(symbols);
            return false;
        }
        if (count == ZGOAL_FALLBACK_SYMBOLS) *truncated = true;
        if (count == 0) {
            free(symbols);
            return true;
        }
        int best = 0;
        for (int i = 1; i < count; i++) {
            int preference = zgoal_symbol_preference(&symbols[i]);
            int selected = zgoal_symbol_preference(&symbols[best]);
            if (preference > selected ||
                (preference == selected &&
                 strcmp(symbols[i].name, symbols[best].name) < 0))
                best = i;
        }
        memset(out, 0, sizeof(*out));
        out->symbol = symbols[best];
        bool identified = codeindex_symbol_record_id(
            &out->symbol, out->symbol_id, sizeof(out->symbol_id)) >= 0;
        free(symbols);
        if (!identified) return false;
    }
    int rank_bonus = ZGOAL_STORY_RANK_BASE -
        (int)rank * ZGOAL_STORY_RANK_STEP;
    if (rank_bonus <= 0 || out->score > INT_MAX - rank_bonus) return false;
    out->score += rank_bonus;
    if (!out->matched_token[0])
        (void)snprintf(out->matched_token, sizeof(out->matched_token), "%s",
                       "story");
    (void)snprintf(out->why, sizeof(out->why), "%s", "bm25_story_file");
    return true;
}

static bool zgoal_candidate_present(
    const struct zcode_goal_candidate *candidates, size_t count,
    const struct zcode_goal_candidate *candidate)
{
    for (size_t i = 0; i < count; i++)
        if (zgoal_same(&candidates[i], &candidate->symbol)) return true;
    return false;
}

static struct zcl_result zgoal_story_candidates(
    struct codeindex *index, const char *goal,
    struct zcode_goal_selection *out)
{
    int64_t started = platform_time_monotonic_us();
    struct ci_story_hit hits[ZGOAL_STORY_FILES];
    bool truncated = false;
    int count = codeindex_search_story(
        index, goal, hits, ZGOAL_STORY_FILES,
        &out->retrieval_corpus_files, &truncated);
    int64_t elapsed = platform_time_monotonic_us() - started;
    out->retrieval_us = elapsed > 0 ? (uint64_t)elapsed : 1u;
    if (count < 0) return ZCL_ERR(-1, "story retrieval failed");
    out->retrieval_truncated = truncated;
    out->retrieval_ranked_files = (size_t)count;
    if (count == 0) return ZCL_OK;

    struct zcode_goal_candidate literal[ZCODE_GOAL_MAX_CANDIDATES];
    size_t literal_count = out->candidate_count;
    memcpy(literal, out->candidates, sizeof(literal));
    memset(out->candidates, 0, sizeof(out->candidates));
    out->candidate_count = 0;
    for (int i = 0; i < count &&
                    out->candidate_count < ZCODE_GOAL_MAX_CANDIDATES; i++) {
        struct zcode_goal_candidate candidate = {0};
        bool file_truncated = false;
        if (!zgoal_file_candidate(index, hits[i].path, (size_t)i, literal,
                                  literal_count, &candidate, &file_truncated))
            return ZCL_ERR(-1, "story file symbol selection failed: %s",
                           hits[i].path);
        out->budget_exhausted = out->budget_exhausted || file_truncated;
        if (!candidate.symbol.name[0] || zgoal_candidate_present(
                out->candidates, out->candidate_count, &candidate))
            continue;
        out->candidates[out->candidate_count++] = candidate;
    }
    for (size_t i = 0; i < literal_count &&
                       out->candidate_count < ZCODE_GOAL_MAX_CANDIDATES; i++) {
        if (zgoal_candidate_present(out->candidates, out->candidate_count,
                                    &literal[i]))
            continue;
        out->candidates[out->candidate_count++] = literal[i];
    }
    if (truncated || (size_t)count > out->candidate_count)
        out->budget_exhausted = true;
    return ZCL_OK;
}

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

struct zcl_result zcode_goal_context_select_indexed(
    struct codeindex *index, const char *goal, const char *exact_symbol,
    struct zcode_goal_selection *out)
{
    if (!index || !goal || !goal[0] || !out || strlen(goal) > 4096)
        return ZCL_ERR(-1,
                       "goal selection requires an index and bounded goal");
    memset(out, 0, sizeof(*out));
    int64_t started = platform_time_monotonic_us();
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
        if (result.ok)
            result = zgoal_literal_candidates(index, out);
        if (result.ok && out->candidate_count != 0)
            result = zgoal_story_candidates(index, goal, out);
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
    int64_t elapsed = platform_time_monotonic_us() - started;
    out->generation_us = elapsed > 0 ? (uint64_t)elapsed : 1u;
    if (!result.ok) memset(&out->selected, 0, sizeof(out->selected));
    return result;
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
    if (!index)
        return ZCL_ERR(-1, "code index could not open for goal selection");
    struct zcl_result result = zcode_goal_context_select_indexed(
        index, goal, exact_symbol, out);
    codeindex_close(index);
    int64_t elapsed = platform_time_monotonic_us() - started;
    out->generation_us = elapsed > 0 ? (uint64_t)elapsed : 1u;
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
