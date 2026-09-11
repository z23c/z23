/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * discover.search scoring and document emit, split so each function stays
 * under cyclomatic 15. Match ranks and JSON fields are unchanged. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include <ctype.h>
#include <string.h>

static bool contains_folded(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !needle[0])
        return false;
    size_t needle_len = strlen(needle);
    for (const unsigned char *h = (const unsigned char *)haystack; *h; h++) {
        size_t i = 0;
        while (i < needle_len && h[i] &&
               tolower(h[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == needle_len)
            return true;
    }
    return false;
}

static bool normalize_query(const char *query, char out[129])
{
    if (!query)
        return false;
    size_t pos = 0;
    bool pending_space = false;
    for (const unsigned char *p = (const unsigned char *)query; *p; p++) {
        if (*p < 0x20 && !isspace(*p))
            return false;
        if (isspace(*p)) {
            if (pos)
                pending_space = true;
            continue;
        }
        if (*p >= 0x80 || pos + (pending_space ? 1U : 0U) + 1U >= 129)
            return false;
        if (pending_space)
            out[pos++] = ' ';
        pending_space = false;
        out[pos++] = (char)tolower(*p);
    }
    out[pos] = 0;
    return pos > 0;
}

static int match_exact(const struct zcl_command_spec *spec, const char *query,
                       const char **reason)
{
    if (strcmp(spec->path, query) == 0) {
        *reason = "exact_path";
        return 1000;
    }
    if (command_registry_csv_token_equal(spec->aliases, query)) {
        *reason = "exact_alias";
        return 900;
    }
    if (command_registry_csv_token_equal(spec->tags, query)) {
        *reason = "exact_tag";
        return 700;
    }
    if (strncmp(spec->path, query, strlen(query)) == 0) {
        *reason = "path_prefix";
        return 650;
    }
    return 0;
}

static int match_folded(const struct zcl_command_spec *spec, const char *query,
                        const char **reason)
{
    if (contains_folded(spec->path, query)) {
        *reason = "path";
        return 550;
    }
    if (contains_folded(spec->tags, query)) {
        *reason = "tag";
        return 450;
    }
    if (contains_folded(spec->summary, query)) {
        *reason = "summary";
        return 300;
    }
    return 0;
}

static int match_terms(const struct zcl_command_spec *spec, const char *query,
                       const char **reason)
{
    if (!strchr(query, ' '))
        return 0;
    size_t words = 0, matched = 0;
    for (const char *p = query; *p;) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ' ')
            p++;
        size_t wl = (size_t)(p - start);
        char word[129];
        if (wl == 0 || wl >= sizeof(word))
            return 0;
        memcpy(word, start, wl);
        word[wl] = 0;
        words++;
        if (contains_folded(spec->path, word) ||
            contains_folded(spec->tags, word) ||
            contains_folded(spec->summary, word))
            matched++;
    }
    if (words >= 2 && matched == words) {
        *reason = "terms";
        return 250;
    }
    return 0;
}

static int command_match_score(const struct zcl_command_spec *spec,
                               const char *query, const char **reason)
{
    int score = match_exact(spec, query, reason);
    if (score)
        return score;
    score = match_folded(spec, query, reason);
    if (score)
        return score;
    return match_terms(spec, query, reason);
}

struct search_hit {
    const struct zcl_command_spec *spec;
    const char *reason;
    int score;
};

static bool hit_before(const struct search_hit *a, const struct search_hit *b)
{
    return a->score > b->score ||
           (a->score == b->score && strcmp(a->spec->path, b->spec->path) < 0);
}

static void search_collect(const struct zcl_command_registry *registry,
                           const char *normalized, struct search_hit *hits,
                           size_t *hit_count, size_t *total)
{
    *hit_count = 0;
    *total = 0;
    for (size_t i = 0; i < registry->count; i++) {
        const char *reason = NULL;
        int score = command_match_score(&registry->commands[i], normalized,
                                        &reason);
        if (score == 0)
            continue;
        (*total)++;
        struct search_hit candidate = {.spec = &registry->commands[i],
                                       .reason = reason,
                                       .score = score};
        size_t insert = *hit_count;
        while (insert > 0 && hit_before(&candidate, &hits[insert - 1]))
            insert--;
        if (insert >= ZCL_COMMAND_SEARCH_LIMIT)
            continue;
        size_t end = *hit_count < ZCL_COMMAND_SEARCH_LIMIT
                         ? *hit_count
                         : ZCL_COMMAND_SEARCH_LIMIT - 1;
        while (end > insert) {
            hits[end] = hits[end - 1];
            end--;
        }
        hits[insert] = candidate;
        if (*hit_count < ZCL_COMMAND_SEARCH_LIMIT)
            (*hit_count)++;
    }
}

static bool search_push_match(struct json_value *matches,
                              const struct search_hit *hit)
{
    struct json_value match;
    json_init(&match);
    json_set_object(&match);
    bool ok = json_push_kv_str(&match, "path", hit->spec->path) &&
              json_push_kv_str(&match, "reason", hit->reason) &&
              json_push_kv_str(&match, "risk",
                               zcl_command_risk_name(hit->spec->risk)) &&
              json_push_kv_str(&match, "latency",
                               zcl_command_latency_name(hit->spec->latency)) &&
              json_push_kv_str(&match, "availability",
                               zcl_command_availability_name(
                                   hit->spec->availability)) &&
              json_push_back(matches, &match);
    json_free(&match);
    return ok;
}

static bool search_push_next(struct json_value *root,
                             const struct search_hit *hit)
{
    struct json_value next, input;
    json_init(&next);
    json_init(&input);
    json_set_object(&next);
    json_set_object(&input);
    bool ok = json_push_kv_str(&next, "command", "discover.describe") &&
              json_push_kv_str(&input, "path", hit->spec->path) &&
              json_push_kv(&next, "input", &input) &&
              json_push_kv(root, "next", &next);
    json_free(&input);
    json_free(&next);
    return ok;
}

static bool search_emit(struct json_value *root, struct json_value *matches,
                        const char *normalized, const char *digest,
                        const struct search_hit *hits, size_t hit_count,
                        size_t total)
{
    bool ok = json_push_kv_str(root, "schema", "zcl.command_search.v1") &&
              json_push_kv_str(root, "query", normalized) &&
              json_push_kv_str(root, "registry_digest", digest);
    for (size_t i = 0; ok && i < hit_count; i++)
        ok = search_push_match(matches, &hits[i]);
    ok = ok && json_push_kv(root, "matches", matches) &&
         json_push_kv_int(root, "count", (int64_t)hit_count) &&
         json_push_kv_int(root, "total_matches", (int64_t)total) &&
         json_push_kv_bool(root, "truncated", total > hit_count);
    if (hit_count > 0)
        ok = ok && search_push_next(root, &hits[0]);
    return ok;
}

size_t zcl_command_registry_search_json(
    const struct zcl_command_registry *registry, const char *query, char *out,
    size_t out_size)
{
    char normalized[129];
    if (!registry || !normalize_query(query, normalized))
        return 0;
    struct search_hit hits[ZCL_COMMAND_SEARCH_LIMIT] = {0};
    size_t hit_count = 0, total = 0;
    search_collect(registry, normalized, hits, &hit_count, &total);

    char digest[72];
    zcl_command_registry_digest(registry, digest);
    struct json_value root, matches;
    json_init(&root);
    json_init(&matches);
    json_set_object(&root);
    json_set_array(&matches);
    bool ok = search_emit(&root, &matches, normalized, digest, hits, hit_count,
                          total);
    size_t result =
        ok ? command_registry_write_bounded_json(&root, out, out_size,
                                                 ZCL_COMMAND_LIST_BUDGET)
           : 0;
    json_free(&matches);
    json_free(&root);
    return result;
}
