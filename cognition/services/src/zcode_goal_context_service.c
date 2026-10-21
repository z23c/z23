/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, explainable goal-to-symbol selection for ZCODE work. */

#include "services/zcode_goal_context_service.h"

#include "base/safe_alloc.h"
#include "hotswap/hotswap_service.h"
#include "platform/time_compat.h"
#include "services/zcode_goal_context_calc_service.h"

#include <limits.h>
#include <ctype.h>
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
#define ZGOAL_IDENTIFIER_QUERY_BYTES \
    (ZCODE_GOAL_MAX_TOKENS * (ZCODE_GOAL_TOKEN_MAX + 1u))

struct zgoal_story_stream {
    struct ci_story_hit hits[ZGOAL_STORY_FILES];
    int count;
    size_t next;
    bool truncated;
};

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

static struct zcl_result zgoal_frozen_literal_candidates(
    struct codeindex *index, struct zcode_goal_selection *out)
{
    for (size_t i = 0; i < out->token_count; i++) {
        struct ci_search_hit hits[ZGOAL_HITS_PER_TOKEN];
        int count = codeindex_search_text(
            index, out->tokens[i], hits, ZGOAL_HITS_PER_TOKEN);
        if (count < 0)
            return ZCL_ERR(-1, "indexed goal search failed for '%s'",
                           out->tokens[i]);
        if (count == ZGOAL_HITS_PER_TOKEN) out->budget_exhausted = true;
        for (int j = 0; j < count; j++)
            if (!zgoal_add(out, &hits[j], out->tokens[i]))
                return ZCL_ERR(-1, "selected symbol identity failed");
    }
    return ZCL_OK;
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

/* Explicit code atoms are useful even after the prose token budget fills.
 * Hyphenated prose alone and decimal numbers are not identifier evidence. */
static bool zgoal_identifier_char(unsigned char c)
{
    return isalnum(c) || c == '_' || c == '.' || c == '-' || c == '/';
}

static bool zgoal_identifier_atom(const char *word, size_t length)
{
    bool letter = false, marker = false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)word[i];
        if (isalpha(c)) letter = true;
        if (c == '_' || (c == '.' && i > 0 && i + 1 < length))
            marker = true;
    }
    return letter && marker;
}

/* A whole path suffix starts at a component boundary. In particular foo.c
 * does not verify foo.cpp, nor does calc verify calculate. Case is literal. */
static bool zgoal_path_atom(const char *path, const char *atom)
{
    size_t path_length = strlen(path), atom_length = strlen(atom);
    return atom_length && path_length >= atom_length &&
        !strcmp(path + path_length - atom_length, atom) &&
        (path_length == atom_length || path[path_length - atom_length - 1] == '/');
}

/* identifier_query contains only bounded atoms separated by one space. */
static bool zgoal_next_query_atom(const char **cursor,
    char atom[ZCODE_GOAL_TOKEN_MAX + 1u])
{
    const char *p = *cursor;
    if (!*p) return false;
    size_t length = 0;
    while (*p && *p != ' ') atom[length++] = *p++;
    atom[length] = '\0';
    if (*p) p++;
    *cursor = p;
    return true;
}

static struct zcl_result zgoal_exact_pool_add(
    struct zgoal_story_candidate *pool, size_t *count, size_t cap,
    const struct ci_symbol *symbol, const char *atom,
    struct zcode_goal_selection *out)
{
    uint32_t mask = !strcmp(symbol->name, atom) ? CI_SEARCH_MATCH_NAME : 0;
    if (zgoal_path_atom(symbol->def_path, atom) || zgoal_path_atom(symbol->decl_path, atom))
        mask |= CI_SEARCH_MATCH_PATH;
    if (!mask) return ZCL_OK;
    struct zcode_goal_candidate candidate = {.symbol = *symbol,
        .score = zgoal_symbol_preference(symbol), .match_mask = mask};
    if (codeindex_symbol_record_id(symbol, candidate.symbol_id, sizeof(candidate.symbol_id)) < 0)
        return ZCL_ERR(-1, "exact atom identity failed");
    (void)snprintf(candidate.matched_token, sizeof(candidate.matched_token), "%s", atom);
    (void)snprintf(candidate.why, sizeof(candidate.why), "%s", "exact_identifier");
    out->total_matches++;
    size_t i = 0;
    for (; i < *count; i++)
        if (!strcmp(pool[i].candidate.symbol_id, candidate.symbol_id)) break;
    struct zgoal_story_candidate entry = {.candidate = candidate};
    if (i < *count) {
        if (zgoal_story_cmp(&entry, &pool[i]) < 0) pool[i] = entry;
    } else if (*count < cap) pool[(*count)++] = entry;
    return ZCL_OK;
}

static void zgoal_exact_pool_finish(struct zgoal_story_candidate *pool, size_t count,
    struct zcode_goal_candidate exact[ZCODE_GOAL_MAX_CANDIDATES],
    size_t *exact_count, struct zcode_goal_selection *out)
{
    qsort(pool, count, sizeof(*pool), zgoal_story_cmp);
    *exact_count = count < ZCODE_GOAL_MAX_CANDIDATES ? count : ZCODE_GOAL_MAX_CANDIDATES;
    if (count > *exact_count) {
        out->dropped_candidates += count - *exact_count;
        out->budget_exhausted = true;
    }
    for (size_t i = 0; i < *exact_count; i++) exact[i] = pool[i].candidate;
}

/* Bounded whole-atom evidence precedes fuzzy retrieval. Reuse the provider's
 * text search, but verify names/paths ourselves: its substring hits and scores
 * do not establish exactness. Keep all verified identities up to the existing
 * token/hit bounds, then use existing symbol preference and lexical ties,
 * independent of mention order. Saturation is incomplete evidence, not unique
 * resolution; ambiguous basenames can contribute several genuine targets. */
static struct zcl_result zgoal_exact_atoms(struct codeindex *index,
    const char *query, struct zcode_goal_candidate exact[ZCODE_GOAL_MAX_CANDIDATES],
    size_t *exact_count, struct zcode_goal_selection *out)
{
    size_t cap = ZCODE_GOAL_MAX_TOKENS * ZGOAL_HITS_PER_TOKEN;
    struct zgoal_story_candidate *pool = zcl_calloc(cap, sizeof(*pool), "goal exact atoms");
    if (!pool) return ZCL_ERR(-1, "goal exact atom allocation failed");
    size_t count = 0;
    struct zcl_result result = ZCL_OK;
    const char *p = query;
    char atom[ZCODE_GOAL_TOKEN_MAX + 1u];
    while (result.ok && zgoal_next_query_atom(&p, atom)) {
        struct ci_search_hit hits[ZGOAL_HITS_PER_TOKEN];
        int hit_count = codeindex_search_text(index, atom, hits, ZGOAL_HITS_PER_TOKEN);
        if (hit_count < 0) { result = ZCL_ERR(-1, "exact atom search failed"); break; }
        if (hit_count == ZGOAL_HITS_PER_TOKEN) out->budget_exhausted = true;
        for (int h = 0; h < hit_count && result.ok; h++)
            result = zgoal_exact_pool_add(pool, &count, cap, &hits[h].symbol, atom, out);
    }
    if (result.ok) zgoal_exact_pool_finish(pool, count, exact, exact_count, out);
    free(pool);
    return result;
}

/* An identity discovered through a declaration can later supply its better
 * definition record. Keep its established tier/rank/provenance, not two slots. */
static bool zgoal_identity_present(struct zcode_goal_candidate *candidates,
    size_t count, const struct zcode_goal_candidate *candidate)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(candidates[i].symbol_id, candidate->symbol_id)) continue;
        struct zgoal_story_candidate current = {.candidate = candidates[i]};
        struct zgoal_story_candidate incoming = {.candidate = *candidate};
        current.candidate.score = zgoal_symbol_preference(&current.candidate.symbol);
        incoming.candidate.score = zgoal_symbol_preference(&incoming.candidate.symbol);
        if (zgoal_story_cmp(&incoming, &current) < 0)
            candidates[i].symbol = candidate->symbol;
        return true;
    }
    return false;
}

static bool zgoal_next_goal_atom(const char **cursor, const char **start, size_t *length)
{
    const char *p = *cursor;
    while (*p && !zgoal_identifier_char((unsigned char)*p)) p++;
    if (!*p) return false;
    *start = p;
    while (zgoal_identifier_char((unsigned char)*p)) p++;
    *cursor = p;
    *length = (size_t)(p - *start);
    while (*length && ((*start)[*length - 1] == '.' || (*start)[*length - 1] == '-'))
        (*length)--;
    return true;
}

/* Slash-only prose needs a verified indexed path, including extensionless
 * paths such as src/Makefile. Scan the same bounded hit set completely. */
static struct zcl_result zgoal_indexed_path_atom(struct codeindex *index,
    const char *start, size_t length, bool *verified, bool *truncated)
{
    char atom[ZCODE_GOAL_TOKEN_MAX + 1u];
    memcpy(atom, start, length); atom[length] = '\0';
    struct ci_search_hit hits[ZGOAL_HITS_PER_TOKEN];
    int count = codeindex_search_text(index, atom, hits, ZGOAL_HITS_PER_TOKEN);
    if (count < 0) return ZCL_ERR(-1, "indexed path atom search failed");
    if (count == ZGOAL_HITS_PER_TOKEN) *truncated = true;
    *verified = false;
    for (int i = 0; i < count; i++)
        if (zgoal_path_atom(hits[i].symbol.def_path, atom) ||
            zgoal_path_atom(hits[i].symbol.decl_path, atom)) *verified = true;
    return ZCL_OK;
}

static void zgoal_identifier_append(
    char atoms[ZCODE_GOAL_MAX_TOKENS][ZCODE_GOAL_TOKEN_MAX + 1u], size_t *count,
    char query[ZGOAL_IDENTIFIER_QUERY_BYTES], size_t *used,
    const char *start, size_t length, bool *truncated)
{
    for (size_t i = 0; i < *count; i++)
        if (strlen(atoms[i]) == length && !memcmp(atoms[i], start, length)) return;
    if (*count == ZCODE_GOAL_MAX_TOKENS) { *truncated = true; return; }
    memcpy(atoms[*count], start, length); atoms[*count][length] = '\0';
    if (*used) query[(*used)++] = ' ';
    memcpy(query + *used, atoms[(*count)++], length); *used += length;
    query[*used] = '\0';
}

static struct zcl_result zgoal_identifier_query(struct codeindex *index, const char *goal,
    char query[ZGOAL_IDENTIFIER_QUERY_BYTES], bool *truncated, bool *focused)
{
    char atoms[ZCODE_GOAL_MAX_TOKENS][ZCODE_GOAL_TOKEN_MAX + 1u];
    size_t count = 0, used = 0, length;
    query[0] = '\0';
    const char *p = goal, *start;
    while (zgoal_next_goal_atom(&p, &start, &length)) {
        bool structured = zgoal_identifier_atom(start, length);
        if (!structured && !memchr(start, '/', length)) continue;
        if (length > ZCODE_GOAL_TOKEN_MAX) { *truncated = true; continue; }
        if (!structured) {
            bool verified = false;
            struct zcl_result result = zgoal_indexed_path_atom(index, start, length, &verified, truncated);
            if (!result.ok) return result;
            if (!verified) continue;
        }
        zgoal_identifier_append(atoms, &count, query, &used, start, length, truncated);
    }
    *focused = count != 0;
    return ZCL_OK;
}

static bool zgoal_component_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static unsigned char zgoal_component_lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}

/* Compound focus is conjunctive, unlike BM25's sum of matching fragments.
 * Require every ASCII component in order within one indexed field. Whole
 * word boundaries reject foo/main/extended when only foo/main is present.
 * Delimiter variation and intervening words remain fuzzy evidence: a dotted
 * service ID can match its versioned C type without becoming an exact name. */
static bool zgoal_compound_field(const char *atom, const char *field)
{
    bool any = false;
    while (*atom) {
        while (*atom && !zgoal_component_char((unsigned char)*atom)) atom++;
        const char *part = atom;
        while (zgoal_component_char((unsigned char)*atom)) atom++;
        size_t length = (size_t)(atom - part);
        if (!length) break;
        bool matched = false;
        while (*field) {
            while (*field && !zgoal_component_char((unsigned char)*field)) field++;
            const char *word = field;
            while (zgoal_component_char((unsigned char)*field)) field++;
            if ((size_t)(field - word) != length) continue;
            size_t i = 0;
            for (; i < length; i++)
                if (zgoal_component_lower((unsigned char)word[i]) !=
                    zgoal_component_lower((unsigned char)part[i])) break;
            if (i == length) { matched = true; break; }
        }
        if (!matched) return false;
        any = true;
    }
    return any;
}

static bool zgoal_symbol_compound(const char *atom, const struct ci_symbol *symbol)
{
    const char *fields[] = {symbol->name, symbol->def_path, symbol->decl_path,
        symbol->signature, symbol->doc, symbol->guard};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (zgoal_compound_field(atom, fields[i])) return true;
    return false;
}

static bool zgoal_focus_supported(const char *query, const struct ci_symbol *symbols, int count)
{
    const char *p = query;
    char atom[ZCODE_GOAL_TOKEN_MAX + 1u];
    while (zgoal_next_query_atom(&p, atom))
        for (int i = 0; i < count; i++)
            if (zgoal_symbol_compound(atom, &symbols[i])) return true;
    return false;
}

/* Admit every focused row independently. An arbitrary BM25 hit, an empty
 * file, or one supported prefix cannot lend ranking authority to later rows.
 * No source-body reads: only the existing bounded indexed symbol fields. */
static struct zcl_result zgoal_focus_admit(
    struct codeindex *index, struct zgoal_story_stream *stream,
    const char *query, bool *available, bool *truncated)
{
    *available = false;
    struct ci_symbol *symbols = zcl_calloc(ZGOAL_FALLBACK_SYMBOLS, sizeof(*symbols),
                                         "goal focused evidence symbols");
    if (!symbols) return ZCL_ERR(-1, "focused evidence allocation failed");
    struct zcl_result result = ZCL_OK;
    int retained = 0;
    for (int row = 0; row < stream->count; row++) {
        int count = codeindex_symbols_in_file(index, stream->hits[row].path,
                                              symbols, ZGOAL_FALLBACK_SYMBOLS);
        if (count < 0) { result = ZCL_ERR(-1, "focused evidence lookup failed"); break; }
        if (count == ZGOAL_FALLBACK_SYMBOLS) *truncated = true;
        if (zgoal_focus_supported(query, symbols, count))
            stream->hits[retained++] = stream->hits[row];
    }
    if (result.ok) {
        stream->count = retained;
        stream->next = 0;
        *available = retained != 0;
    }
    free(symbols);
    return result;
}

static void zgoal_merge_add(struct zcode_goal_selection *out,
    const struct zcode_goal_candidate *candidate, bool ordinal)
{
    bool present = ordinal
        ? zgoal_identity_present(out->candidates, out->candidate_count, candidate)
        : zgoal_candidate_present(out->candidates, out->candidate_count, candidate);
    if (present) return;
    struct zcode_goal_candidate added = *candidate;
    if (ordinal) added.score = ZGOAL_STORY_RANK_BASE -
        (int)out->candidate_count * ZGOAL_STORY_RANK_STEP;
    out->candidates[out->candidate_count++] = added;
}

static struct zcl_result zgoal_merge_story_row(struct codeindex *index,
    struct zgoal_story_stream *stream, bool identifier, bool ordinal,
    const struct zcode_goal_candidate *literal, size_t literal_count,
    struct zcode_goal_selection *out)
{
    size_t rank = stream->next++;
    struct zcode_goal_candidate candidate = {0};
    bool file_truncated = false;
    if (!zgoal_file_candidate(index, stream->hits[rank].path, rank,
                              literal, literal_count, &candidate, &file_truncated))
        return ZCL_ERR(-1, "story file symbol selection failed: %s", stream->hits[rank].path);
    out->budget_exhausted = out->budget_exhausted || file_truncated;
    if (!candidate.symbol.name[0]) return ZCL_OK;
    if (identifier) {
        (void)snprintf(candidate.matched_token, sizeof(candidate.matched_token), "%s", "identifier");
        (void)snprintf(candidate.why, sizeof(candidate.why), "%s", "bm25_identifier_file");
    }
    zgoal_merge_add(out, &candidate, ordinal);
    return ZCL_OK;
}

static bool zgoal_streams_incomplete(const struct zgoal_story_stream streams[2], size_t retained)
{
    return streams[0].truncated || streams[1].truncated ||
        (size_t)streams[0].count + (size_t)streams[1].count > retained ||
        streams[0].next < (size_t)streams[0].count ||
        streams[1].next < (size_t)streams[1].count;
}

/* Interleave ranks, never compare BM25 score magnitudes from different queries.
 * Duplicates consume provider rows but no output slots. Literal evidence still
 * chooses the symbol within each retrieved file; it cannot erase the merge. */
static struct zcl_result zgoal_merge_story_streams(
    struct codeindex *index, struct zgoal_story_stream streams[2], bool focused,
    const struct zcode_goal_candidate *exact, size_t exact_count,
    struct zcode_goal_selection *out)
{
    struct zcode_goal_candidate literal[ZCODE_GOAL_MAX_CANDIDATES];
    size_t literal_count = out->candidate_count;
    memcpy(literal, out->candidates, sizeof(literal));
    memset(out->candidates, 0, sizeof(out->candidates));
    out->candidate_count = exact_count;
    for (size_t i = 0; i < exact_count; i++) {
        out->candidates[i] = exact[i];
        out->candidates[i].score = ZGOAL_STORY_RANK_BASE - (int)i * ZGOAL_STORY_RANK_STEP;
    }
    bool ordinal = focused || exact_count != 0;
    unsigned turn = focused ? 1u : 0u;
    while (out->candidate_count < ZCODE_GOAL_MAX_CANDIDATES &&
           (streams[0].next < (size_t)streams[0].count ||
            streams[1].next < (size_t)streams[1].count)) {
        unsigned slot = turn++ % 2u;
        if (streams[slot].next >= (size_t)streams[slot].count) slot = 1u - slot;
        struct zcl_result result = zgoal_merge_story_row(index, &streams[slot], slot == 1u,
            ordinal, literal, literal_count, out);
        if (!result.ok) return result;
    }
    for (size_t i = 0; i < literal_count &&
                       out->candidate_count < ZCODE_GOAL_MAX_CANDIDATES; i++) {
        zgoal_merge_add(out, &literal[i], ordinal);
    }
    if (zgoal_streams_incomplete(streams, out->candidate_count))
        out->budget_exhausted = true;
    return ZCL_OK;
}

static struct zcl_result zgoal_story_retrieve(struct codeindex *index, const char *goal,
    const char *identifier_query, bool focused, int64_t started,
    struct zgoal_story_stream streams[2], struct zcode_goal_selection *out)
{
    streams[0].count = codeindex_search_story(
        index, goal, streams[0].hits, ZGOAL_STORY_FILES,
        &out->retrieval_corpus_files, &streams[0].truncated);
    if (streams[0].count < 0) return ZCL_ERR(-1, "story retrieval failed");
    if (focused) {
        size_t corpus_files = 0;
        streams[1].count = codeindex_search_story(index, identifier_query,
            streams[1].hits, ZGOAL_STORY_FILES, &corpus_files, &streams[1].truncated);
        if (streams[1].count < 0 || corpus_files != out->retrieval_corpus_files)
            return ZCL_ERR(-1, "identifier story retrieval failed or corpus changed");
    }
    int64_t elapsed = platform_time_monotonic_us() - started;
    out->retrieval_us = elapsed > 0 ? (uint64_t)elapsed : 1u;
    out->retrieval_truncated = streams[0].truncated || streams[1].truncated;
    /* Total returned provider ranks across both queries, including duplicates. */
    out->retrieval_ranked_files = (size_t)streams[0].count + (size_t)streams[1].count;
    return ZCL_OK;
}

static struct zcl_result zgoal_story_candidates(
    struct codeindex *index, const char *goal,
    struct zcode_goal_selection *out)
{
    int64_t started = platform_time_monotonic_us();
    char identifier_query[ZGOAL_IDENTIFIER_QUERY_BYTES];
    bool focused = false;
    struct zcl_result parsed = zgoal_identifier_query(index, goal, identifier_query,
        &out->budget_exhausted, &focused);
    if (!parsed.ok) return parsed;
    struct zcode_goal_candidate exact[ZCODE_GOAL_MAX_CANDIDATES];
    size_t exact_count = 0;
    if (focused) {
        struct zcl_result found = zgoal_exact_atoms(index, identifier_query, exact, &exact_count, out);
        if (!found.ok) return found;
    }
    if (!focused && out->candidate_count == 0) return ZCL_OK;
    struct zgoal_story_stream streams[2] = {0};
    struct zcl_result retrieved = zgoal_story_retrieve(index, goal, identifier_query,
        focused, started, streams, out);
    if (!retrieved.ok) return retrieved;
    if (!out->retrieval_ranked_files && !exact_count) return ZCL_OK;
    bool usable_focus = false;
    if (focused) {
        struct zcl_result ready = zgoal_focus_admit(
            index, &streams[1], identifier_query, &usable_focus, &out->budget_exhausted);
        if (!ready.ok) return ready;
    }
    return zgoal_merge_story_streams(index, streams, usable_focus, exact, exact_count, out);
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

static struct zcl_result zgoal_select_indexed(
    struct codeindex *index, const char *goal, const char *exact_symbol,
    bool frozen_literal, struct zcode_goal_selection *out)
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
        if (result.ok) result = frozen_literal
            ? zgoal_frozen_literal_candidates(index, out)
            : zgoal_literal_candidates(index, out);
        if (result.ok && !frozen_literal)
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

struct zcl_result zcode_goal_context_select_indexed(
    struct codeindex *index, const char *goal, const char *exact_symbol,
    struct zcode_goal_selection *out)
{
    return zgoal_select_indexed(index, goal, exact_symbol, false, out);
}

struct zcl_result zcode_goal_context_select_literal_indexed(
    struct codeindex *index, const char *goal,
    struct zcode_goal_selection *out)
{
    return zgoal_select_indexed(index, goal, NULL, true, out);
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
    .source_tu = "cognition/services/src/zcode_goal_context_calc_service.c",
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
