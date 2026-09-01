/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the `code have` leaf — answer "does this checkout ALREADY DO X?"
 * in one call, before an agent writes the thing a second time.
 *
 * This is a separate translation unit from native_code_command.c on purpose:
 * that file is already near the 1500-line ceiling, and this leaf answers a
 * different question from the rest of the `code` tree. The others navigate
 * code you have already located; this one decides whether to go looking.
 *
 * The reply is deliberately shaped for a SKIMMING reader. `verdict` is the
 * first thing to read and is derived by cognition/modules/codeindex from the very fields
 * rendered below it — see codeindex_capability_verdict(). Nothing here
 * recomputes or second-guesses it, so the headline can never disagree with the
 * evidence printed under it.
 *
 * It opens the SOURCE VIEW of the index, not the full one. A capability answer
 * comes from source rows and recorded call sites; compiler include edges do
 * not enter it. The full open treats depfile movement as staleness, so every
 * `make` would cost the next `code have` a multi-second reindex — which is
 * exactly when an agent is most likely to want it and least likely to wait.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_capability.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CODE_HAVE_DEFAULT = 3,
    CODE_HAVE_MAX     = 5,
    /* Symbol names rendered per capability. The store may know more; the
     * `symbol_count` field always reports the true total. */
    CODE_HAVE_SYM_SHOW = 8,
};

static const char *have_str(const struct zcl_command_request *request,
                            const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

static int have_limit(const struct zcl_command_request *request)
{
    const struct json_value *v = json_get(request->input, "limit");
    if (!v) return CODE_HAVE_DEFAULT;
    long n = (long)json_get_int(v);
    if (n < 1) n = 1;
    if (n > CODE_HAVE_MAX) n = CODE_HAVE_MAX;
    return (int)n;
}

static void have_push_str(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

/* Bounded copy of at most `max` chars, with a visible "..." when cut. */
static void have_trunc(char *dst, size_t cap, const char *src, size_t max)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t lim = max;
    if (lim > cap - 1) lim = cap - 1;
    size_t i = 0;
    for (; i < lim && src[i]; i++) dst[i] = src[i];
    if (src[i] != '\0' && i + 3 < cap) {
        dst[i++] = '.'; dst[i++] = '.'; dst[i++] = '.';
    }
    dst[i] = '\0';
}

static const char *have_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

void zcl_native_handle_code_have(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    const char *text = have_str(request, "text");
    if (!text) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_TEXT",
                               "normalize", false, false,
                               "code have requires a capability to look for, "
                               "for example {\"text\":\"validation\"}", "");
        return;
    }
    int limit = have_limit(request);

    struct codeindex *ci = codeindex_open_source_view(have_source_root(request));
    if (!ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index",
                               have_source_root(request));
        return;
    }

    struct ci_capability caps[CODE_HAVE_MAX];
    struct ci_capability_query q;
    int n = codeindex_capabilities(ci, text, caps, limit, &q);
    if (n < 0) {
        codeindex_close(ci);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_QUERY",
                               "dispatch", true, false,
                               "the capability query failed", text);
        return;
    }

    enum ci_capability_verdict verdict =
        codeindex_capability_verdict(caps, n, &q);
    const char *label = codeindex_capability_verdict_label(verdict);

    struct json_value arr, stems;
    json_init(&arr);   json_set_array(&arr);
    json_init(&stems); json_set_array(&stems);
    for (int i = 0; i < q.term_count; i++) have_push_str(&stems, q.stems[i]);

    for (int i = 0; i < n; i++) {
        struct json_value o, syms;
        json_init(&o);    json_set_object(&o);
        json_init(&syms); json_set_array(&syms);
        int show = caps[i].symbols_listed;
        if (show > CODE_HAVE_SYM_SHOW) show = CODE_HAVE_SYM_SHOW;
        for (int k = 0; k < show; k++) have_push_str(&syms, caps[i].symbols[k]);
        char purpose[200];
        have_trunc(purpose, sizeof(purpose), caps[i].purpose, 180);
        (void)json_push_kv_str(&o, "what", caps[i].what);
        (void)json_push_kv_str(&o, "header", caps[i].header);
        (void)json_push_kv_str(&o, "group", caps[i].group);
        (void)json_push_kv_str(&o, "purpose", purpose);
        (void)json_push_kv(&o, "symbols", &syms);
        (void)json_push_kv_int(&o, "symbol_count", caps[i].symbol_count);
        (void)json_push_kv_int(&o, "used_by_files", caps[i].used_by_files);
        (void)json_push_kv_str(&o, "count_basis", caps[i].count_basis);
        (void)json_push_kv_str(&o, "example_caller", caps[i].example_caller);
        (void)json_push_kv_int(&o, "terms_matched", caps[i].terms_matched);
        (void)json_push_kv_str(&o, "confidence",
                               codeindex_capability_confidence(&caps[i], &q));
        json_free(&syms);
        (void)json_push_back(&arr, &o);
        json_free(&o);
    }

    (void)json_push_kv_str(&reply->data, "query", text);
    (void)json_push_kv(&reply->data, "capabilities", &arr);
    (void)json_push_kv_str(&reply->data, "verdict", label);
    (void)json_push_kv_int(&reply->data, "count", n);

    /* What the search DID. A NOT FOUND that cannot say what it looked for is
     * indistinguishable from a broken query, and the difference decides
     * whether the caller trusts the next answer. */
    struct json_value searched;
    json_init(&searched); json_set_object(&searched);
    (void)json_push_kv(&searched, "stems", &stems);
    (void)json_push_kv_int(&searched, "matching_symbol_rows", q.symbol_rows);
    (void)json_push_kv_int(&searched, "matching_file_rows", q.file_rows);
    (void)json_push_kv_int(&searched, "candidates_considered", q.candidates);
    (void)json_push_kv_bool(&searched, "relaxed_to_partial_terms", q.relaxed);
    (void)json_push_kv_bool(&searched, "candidate_table_truncated", q.truncated);
    (void)json_push_kv_int(&searched, "query_terms_dropped", q.terms_dropped);
    (void)json_push_kv(&reply->data, "searched", &searched);
    json_free(&searched);
    json_free(&stems);
    json_free(&arr);

    /* One line an agent can act on without parsing anything.
     *
     * PARTIAL carries its own warning. This query matches terms independently,
     * so a multi-word query naming ONE concept ("rate limiting") can rank a
     * file that contains both words for unrelated reasons — the observed case
     * matched "rate" in a metric name and "limit" inside the word "limited".
     * The verdict is right to hedge, but a hedge a skimmer reads as an answer
     * is the same failure as a wrong answer, so the line says what to do. */
    const char *advice = "";
    if (verdict == CI_CAPABILITY_ALREADY_EXISTS)
        advice = " — reuse it, do not rebuild it";
    else if (verdict == CI_CAPABILITY_PARTIAL)
        advice = " — your terms matched separately, not as one concept; "
                 "open this before trusting or reusing it";
    char summary[440];
    if (n > 0)
        (void)snprintf(summary, sizeof(summary),
                       "%s — %s (%s), %d symbol(s), used by %d file(s) [%s]%s",
                       label, caps[0].what, caps[0].header,
                       caps[0].symbol_count, caps[0].used_by_files,
                       caps[0].count_basis, advice);
    else if (q.term_count == 0)
        (void)snprintf(summary, sizeof(summary),
                       "%s — no searchable term survived in '%s' (words under "
                       "3 characters and common filler are dropped)",
                       label, text);
    else
        (void)snprintf(summary, sizeof(summary),
                       "%s — nothing in the indexed source matches all %d "
                       "term(s); this means the recorded names, docs and file "
                       "purposes do not say so, not that the tree cannot do it",
                       label, q.term_count);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    codeindex_close(ci);
}
