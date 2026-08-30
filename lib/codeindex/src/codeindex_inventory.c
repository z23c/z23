/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Join public headers, symbols, uses, tests, bodies, and contracts
 * into the source-derived capability inventory.
 *
 * Direct uses are lower bounds; registered-test reachability is not assertion
 * coverage; alpha-shape equality is only an UNPROVEN duplicate candidate.
 */

#include "codeindex_inventory_internal.h"

#include "base/checked.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

bool inv_report_array_grow(void **arr, int *cap, int count,
                           size_t elem_size, const char *label)
{
    if (count < *cap) return true;
    int new_cap = *cap ? *cap : 8;
    while (new_cap <= count) {
        if (new_cap > INT_MAX / 2)
            LOG_FAIL("codeindex.inventory",
                     "report array '%s' capacity overflow", label);
        new_cap *= 2;
    }
    size_t bytes;
    if (!zcl_size_mul((size_t)new_cap, elem_size, &bytes))
        LOG_FAIL("codeindex.inventory",
                 "report array '%s' byte-size overflow", label);
    void *p = zcl_realloc(*arr, bytes, label);
    if (!p) return false;
    *arr = p;
    *cap = new_cap;
    return true;
}

struct inv_body_order { int index; const struct inv_body *body; };
struct inv_def_order { const char *name; const struct ci_symbol *symbol; };
struct inv_body_name_order { const char *name; const struct inv_body *body; };

static int inv_digest_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

static int inv_body_exact_cmp(const void *a, const void *b)
{
    const struct inv_body_order *x = a, *y = b;
    int c = inv_digest_cmp(x->body->exact_sha3, y->body->exact_sha3);
    if (c) return c;
    c = strcmp(x->body->path, y->body->path);
    if (c) return c;
    return (x->body->line > y->body->line) - (x->body->line < y->body->line);
}

static int inv_body_shape_cmp(const void *a, const void *b)
{
    const struct inv_body_order *x = a, *y = b;
    int c = inv_digest_cmp(x->body->shape_sha3, y->body->shape_sha3);
    if (c) return c;
    c = strcmp(x->body->path, y->body->path);
    if (c) return c;
    return (x->body->line > y->body->line) - (x->body->line < y->body->line);
}

static int inv_def_order_cmp(const void *a, const void *b)
{
    const struct inv_def_order *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    if (c) return c;
    c = strcmp(x->symbol->def_path, y->symbol->def_path);
    if (c) return c;
    return (x->symbol->def_line > y->symbol->def_line) -
           (x->symbol->def_line < y->symbol->def_line);
}

static int inv_body_name_order_cmp(const void *a, const void *b)
{
    const struct inv_body_name_order *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    if (c) return c;
    c = strcmp(x->body->path, y->body->path);
    if (c) return c;
    return (x->body->line > y->body->line) -
           (x->body->line < y->body->line);
}

static int inv_duplicate_value_cmp(const void *a, const void *b)
{
    const struct ci_inventory_duplicate *x = a, *y = b;
    if (x->kind != y->kind)
        return (x->kind > y->kind) - (x->kind < y->kind);
    bool x_renamed = strcmp(x->symbol_a, x->symbol_b) != 0;
    bool y_renamed = strcmp(y->symbol_a, y->symbol_b) != 0;
    if (x_renamed != y_renamed) return x_renamed ? -1 : 1;
    if (x->body_tokens != y->body_tokens)
        return (y->body_tokens > x->body_tokens) -
               (y->body_tokens < x->body_tokens);
    int c = strcmp(x->path_a, y->path_a);
    if (c) return c;
    if (x->line_a != y->line_a)
        return (x->line_a > y->line_a) - (x->line_a < y->line_a);
    c = strcmp(x->path_b, y->path_b);
    if (c) return c;
    return (x->line_b > y->line_b) - (x->line_b < y->line_b);
}

static int inv_invariant_value_cmp(const void *a, const void *b)
{
    const struct ci_inventory_invariant *x = a, *y = b;
    if (x->constant_return_body != y->constant_return_body)
        return x->constant_return_body ? -1 : 1;
    if (x->production_use_files != y->production_use_files)
        return (y->production_use_files > x->production_use_files) -
               (y->production_use_files < x->production_use_files);
    int c = strcmp(x->header, y->header);
    if (c) return c;
    c = strcmp(x->symbol, y->symbol);
    if (c) return c;
    c = strcmp(x->definition_path, y->definition_path);
    if (c) return c;
    return (x->definition_line > y->definition_line) -
           (x->definition_line < y->definition_line);
}

static int inv_definition_arm_value_cmp(const void *a, const void *b)
{
    const struct ci_inventory_definition_arm *x = a, *y = b;
    int c = strcmp(x->header, y->header);
    if (c) return c;
    c = strcmp(x->symbol, y->symbol);
    if (c) return c;
    c = strcmp(x->definition_path, y->definition_path);
    if (c) return c;
    return (x->definition_line > y->definition_line) -
           (x->definition_line < y->definition_line);
}

static bool inv_header_guard_symbol(const struct ci_symbol *s)
{
    return s && s->kind == 'M' && s->guard[0] &&
        strcmp(s->name, s->guard) == 0;
}

static bool inv_same_header_symbol(const struct ci_symbol *a,
                                   const struct ci_symbol *b)
{
    return a && b && a->kind == b->kind && strcmp(a->name, b->name) == 0;
}

static int inv_count_public_symbols(const struct inv_scan *scan)
{
    int count = 0;
    for (int oi = 0; oi < scan->occurrence_count; oi++) {
        const struct inv_symbol_occurrence *o = &scan->occurrences[oi];
        int fi = o->file_index;
        if (!scan->files[fi].is_public_header ||
            inv_header_guard_symbol(&o->symbol)) continue;
        bool duplicate = false;
        for (int prev = oi - 1; prev >= 0 &&
             scan->occurrences[prev].file_index == fi; prev--) {
            const struct inv_symbol_occurrence *p = &scan->occurrences[prev];
            if (inv_same_header_symbol(&p->symbol, &o->symbol) &&
                !inv_header_guard_symbol(&p->symbol)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) count++;
    }
    return count;
}

static int inv_def_lower(const struct inv_def_order *defs, int count,
                         const char *name)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (strcmp(defs[mid].name, name) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static const struct ci_symbol *inv_definition_for(
    const struct inv_def_order *defs, int count,
    const struct ci_symbol *declaration)
{
    if (declaration->def_path[0]) return declaration;
    const struct ci_symbol *best = NULL;
    int at = inv_def_lower(defs, count, declaration->name);
    for (; at < count && strcmp(defs[at].name, declaration->name) == 0; at++) {
        const struct ci_symbol *s = defs[at].symbol;
        if (s->kind != declaration->kind) continue;
        if (!best) { best = s; continue; }
        if (best->def_line != s->def_line ||
            strcmp(best->def_path, s->def_path) != 0)
            return NULL;
    }
    return best;
}

static const struct inv_body *inv_body_for(
    const struct inv_body_name_order *bodies, int count, const char *name,
    const char *definition_path)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (strcmp(bodies[mid].name, name) < 0) lo = mid + 1;
        else hi = mid;
    }
    const struct inv_body *fallback = NULL;
    for (int i = lo; i < count && strcmp(bodies[i].name, name) == 0; i++) {
        const struct inv_body *b = bodies[i].body;
        if (definition_path && definition_path[0] &&
            strcmp(b->path, definition_path) == 0)
            return b;
        if (!definition_path || !definition_path[0]) {
            if (fallback) return NULL;
            fallback = b;
        }
    }
    return fallback;
}

static bool inv_occurrence_is_baselined_arm(
    const struct inv_scan *scan, const struct inv_symbol_occurrence *occ)
{
    if (!occ->symbol.def_path[0]) return false;
    for (int i = 0; i < scan->arm_symbol_count; i++)
        if (strcmp(scan->arm_symbols[i].path, occ->symbol.def_path) == 0 &&
            strcmp(scan->arm_symbols[i].name, occ->symbol.name) == 0)
            return true;
    return false;
}

/* Sorted index over the baselined-arm occurrences, keyed by (kind, name), so
 * inv_multi_arm_definition_count can look up a symbol's arm count in
 * O(log n + matches) instead of rescanning every occurrence for every
 * function symbol -- the scan is O(symbols * occurrences) otherwise. */
struct inv_arm_key { char kind; const char *name; };

static int inv_arm_key_cmp(const void *a, const void *b)
{
    const struct inv_arm_key *x = a, *y = b;
    if (x->kind != y->kind) return (x->kind > y->kind) - (x->kind < y->kind);
    return strcmp(x->name, y->name);
}

static int inv_arm_key_lower(const struct inv_arm_key *keys, int count,
                             char kind, const char *name)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int c = keys[mid].kind != kind
            ? (keys[mid].kind > kind) - (keys[mid].kind < kind)
            : strcmp(keys[mid].name, name);
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static int inv_multi_arm_definition_count(const struct inv_arm_key *keys,
                                          int key_count, const char *name,
                                          char kind)
{
    int at = inv_arm_key_lower(keys, key_count, kind, name);
    int count = 0;
    for (; at < key_count && keys[at].kind == kind &&
           strcmp(keys[at].name, name) == 0; at++)
        count++;
    return count;
}

static void inv_include_token(const char *path, char out[256])
{
    const char *p = strstr(path, "/include/");
    inv_cpy(out, 256, p ? p + strlen("/include/") : path);
}

static bool inv_build_capabilities(const struct inv_scan *scan,
                                   struct ci_inventory_report *report,
                                   int **out_cap_for_symbol)
{
    int caps = 0;
    for (int i = 0; i < scan->file_count; i++)
        if (scan->files[i].is_public_header) caps++;
    int symbols = inv_count_public_symbols(scan);
    report->capabilities = zcl_calloc((size_t)caps,
                                      sizeof(*report->capabilities),
                                      "ci_inventory_capabilities");
    report->symbols = zcl_calloc((size_t)symbols, sizeof(*report->symbols),
                                 "ci_inventory_public_symbols");
    int *cap_for_symbol = zcl_malloc((size_t)symbols * sizeof(*cap_for_symbol),
                                     "ci_inventory_symbol_caps");
    struct inv_def_order *defs = zcl_malloc(
        (size_t)scan->occurrence_count * sizeof(*defs),
        "ci_inventory_definition_order");
    struct inv_body_name_order *bodies = zcl_malloc(
        (size_t)scan->body_count * sizeof(*bodies),
        "ci_inventory_body_name_order");
    struct inv_arm_key *arm_keys = zcl_malloc(
        (size_t)scan->occurrence_count * sizeof(*arm_keys),
        "ci_inventory_arm_keys");
    if ((caps && !report->capabilities) || (symbols && !report->symbols) ||
        (symbols && !cap_for_symbol) || (scan->occurrence_count && !defs) ||
        (scan->body_count && !bodies) ||
        (scan->occurrence_count && !arm_keys)) {
        free(cap_for_symbol); free(defs); free(bodies); free(arm_keys);
        return false;
    }
    int def_count = 0;
    for (int i = 0; i < scan->occurrence_count; i++)
        if (scan->occurrences[i].symbol.def_path[0]) {
            defs[def_count].name = scan->occurrences[i].symbol.name;
            defs[def_count++].symbol = &scan->occurrences[i].symbol;
        }
    for (int i = 0; i < scan->body_count; i++) {
        bodies[i].name = scan->bodies[i].name;
        bodies[i].body = &scan->bodies[i];
    }
    int arm_key_count = 0;
    for (int i = 0; i < scan->occurrence_count; i++)
        if (inv_occurrence_is_baselined_arm(scan, &scan->occurrences[i])) {
            arm_keys[arm_key_count].kind = scan->occurrences[i].symbol.kind;
            arm_keys[arm_key_count++].name = scan->occurrences[i].symbol.name;
        }
    qsort(defs, (size_t)def_count, sizeof(*defs), inv_def_order_cmp);
    qsort(bodies, (size_t)scan->body_count, sizeof(*bodies),
          inv_body_name_order_cmp);
    qsort(arm_keys, (size_t)arm_key_count, sizeof(*arm_keys),
          inv_arm_key_cmp);

    int ci = 0, si = 0, occ_begin = 0;
    for (int fi = 0; fi < scan->file_count; fi++) {
        while (occ_begin < scan->occurrence_count &&
               scan->occurrences[occ_begin].file_index < fi) occ_begin++;
        int occ_end = occ_begin;
        while (occ_end < scan->occurrence_count &&
               scan->occurrences[occ_end].file_index == fi) occ_end++;
        const struct inv_file *file = &scan->files[fi];
        if (!file->is_public_header) continue;
        struct ci_inventory_capability *cap = &report->capabilities[ci];
        inv_cpy(cap->header, sizeof(cap->header), file->path);
        inv_include_token(file->path, cap->include_token);
        inv_cpy(cap->group, sizeof(cap->group), file->group);
        inv_cpy(cap->purpose, sizeof(cap->purpose), file->purpose);
        /* A header comment is a declaration of intent, never behavioral
         * evidence.  Keep the text, but keep its status UNPROVEN even when
         * present. */
        cap->purpose_unproven = true;
        cap->symbol_offset = si;
        for (int oi = occ_begin; oi < occ_end; oi++) {
            const struct inv_symbol_occurrence *occ = &scan->occurrences[oi];
            if (inv_header_guard_symbol(&occ->symbol))
                continue;
            bool duplicate = false;
            for (int at = cap->symbol_offset; at < si; at++) {
                if (report->symbols[at].kind == occ->symbol.kind &&
                    strcmp(report->symbols[at].name, occ->symbol.name) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            struct ci_inventory_symbol *dst = &report->symbols[si];
            inv_cpy(dst->name, sizeof(dst->name), occ->symbol.name);
            dst->kind = occ->symbol.kind;
            inv_cpy(dst->declaration_path, sizeof(dst->declaration_path),
                    occ->symbol.decl_path[0] ? occ->symbol.decl_path
                                             : occ->symbol.def_path);
            dst->declaration_line = occ->symbol.decl_line
                ? occ->symbol.decl_line : occ->symbol.def_line;
            inv_cpy(dst->signature, sizeof(dst->signature), occ->symbol.signature);
            inv_cpy(dst->contract, sizeof(dst->contract), occ->symbol.doc);
            dst->definition_arm_count =
                (dst->kind == 'T' || dst->kind == 't')
                    ? inv_multi_arm_definition_count(arm_keys, arm_key_count,
                                                     dst->name, dst->kind)
                    : 0;
            dst->multi_arm_definition = dst->definition_arm_count > 0;
            const struct ci_symbol *def = dst->multi_arm_definition ? NULL :
                inv_definition_for(defs, def_count, &occ->symbol);
            if (dst->multi_arm_definition) {
                inv_cpy(dst->definition_evidence,
                        sizeof(dst->definition_evidence),
                        "multiple_preprocessor_arms_UNPROVEN");
                report->multi_arm_symbol_count++;
            } else if (def) {
                inv_cpy(dst->definition_path, sizeof(dst->definition_path),
                        def->def_path);
                dst->definition_line = def->def_line;
                inv_cpy(dst->definition_evidence,
                        sizeof(dst->definition_evidence),
                        def == &occ->symbol ? "declaration_is_definition"
                                            : "unique_name_and_kind");
            } else {
                inv_cpy(dst->definition_evidence,
                        sizeof(dst->definition_evidence),
                        "unresolved_UNPROVEN");
            }
            const struct inv_body *body = dst->multi_arm_definition ? NULL :
                inv_body_for(bodies, scan->body_count, dst->name,
                             dst->definition_path);
            if (body) {
                dst->constant_return_body = body->constant_return;
                inv_cpy(dst->constant_return_value,
                        sizeof(dst->constant_return_value), body->constant_value);
                if (!dst->definition_path[0]) {
                    inv_cpy(dst->definition_path, sizeof(dst->definition_path),
                            body->path);
                    dst->definition_line = body->line;
                    inv_cpy(dst->definition_evidence,
                            sizeof(dst->definition_evidence),
                            "unique_function_body");
                }
            }
            if (!dst->definition_path[0] && !dst->multi_arm_definition)
                report->unresolved_symbol_definitions++;
            if (dst->kind == 'T' || dst->kind == 't') cap->function_count++;
            else if (dst->kind == 'S' || dst->kind == 'Y' || dst->kind == 'E')
                cap->type_count++;
            else if (dst->kind == 'M') cap->macro_count++;
            cap_for_symbol[si] = ci;
            si++;
        }
        cap->symbol_count = si - cap->symbol_offset;
        ci++;
    }
    report->capability_count = ci;
    report->symbol_count = si;
    report->public_headers = ci;
    report->symbols_exposed = si;
    *out_cap_for_symbol = cap_for_symbol;
    free(defs);
    free(bodies);
    free(arm_keys);
    return true;
}

static bool inv_duplicate_push(struct ci_inventory_report *report,
                               enum ci_inventory_duplicate_kind kind,
                               const struct inv_body *a,
                               const struct inv_body *b)
{
    int n = report->duplicate_count;
    if (!inv_report_array_grow((void **)&report->duplicates,
                               &report->duplicate_cap, n,
                               sizeof(*report->duplicates),
                               "ci_inventory_duplicates"))
        return false;
    struct ci_inventory_duplicate *d = &report->duplicates[n];
    memset(d, 0, sizeof(*d));
    d->kind = kind;
    inv_cpy(d->symbol_a, sizeof(d->symbol_a), a->name);
    inv_cpy(d->path_a, sizeof(d->path_a), a->path);
    d->line_a = a->line;
    inv_cpy(d->symbol_b, sizeof(d->symbol_b), b->name);
    inv_cpy(d->path_b, sizeof(d->path_b), b->path);
    d->line_b = b->line;
    d->body_tokens = a->token_count;
    d->body_lines = a->end_line - a->line + 1;
    inv_cpy(d->evidence, sizeof(d->evidence),
            kind == CI_INVENTORY_DUPLICATE_EXACT_BODY
                ? "identical comment/space-normalized token body"
                : "UNPROVEN: identifiers/callees/literals reduced to roles");
    if (kind == CI_INVENTORY_DUPLICATE_ALPHA_SHAPE)
        inv_cpy(d->proof_needed, sizeof(d->proof_needed),
                "differential tests over the shared input domain or reviewed semantic equivalence of callees, literals, effects, and errors");
    report->duplicate_count++;
    return true;
}

static bool inv_body_in_scope(const struct inv_scan *scan,
                              const struct inv_body *body,
                              int min_tokens, int min_lines)
{
    const struct inv_file *f = &scan->files[body->file_index];
    return !f->is_header && !f->is_test && !f->is_example &&
        body->token_count >= min_tokens &&
        body->end_line - body->line + 1 >= min_lines;
}

static bool inv_derive_duplicates(const struct inv_scan *scan,
                                  struct ci_inventory_report *report)
{
    struct inv_body_order *order = zcl_malloc(
        (size_t)scan->body_count * sizeof(*order), "ci_inventory_body_order");
    if (scan->body_count && !order) return false;
    int count = 0;
    for (int i = 0; i < scan->body_count; i++)
        if (inv_body_in_scope(scan, &scan->bodies[i], 20, 3)) {
            order[count].index = i;
            order[count++].body = &scan->bodies[i];
        }
    qsort(order, (size_t)count, sizeof(*order), inv_body_exact_cmp);
    for (int i = 0; i < count;) {
        int end = i + 1;
        while (end < count && inv_digest_cmp(order[end].body->exact_sha3,
                                              order[i].body->exact_sha3) == 0)
            end++;
        for (int j = i + 1; j < end; j++)
            if (!inv_duplicate_push(report, CI_INVENTORY_DUPLICATE_EXACT_BODY,
                                    order[i].body, order[j].body)) {
                free(order); return false;
            }
        i = end;
    }

    count = 0;
    for (int i = 0; i < scan->body_count; i++)
        if (inv_body_in_scope(scan, &scan->bodies[i], 50, 5)) {
            order[count].index = i;
            order[count++].body = &scan->bodies[i];
        }
    qsort(order, (size_t)count, sizeof(*order), inv_body_shape_cmp);
    for (int i = 0; i < count;) {
        int end = i + 1;
        while (end < count && inv_digest_cmp(order[end].body->shape_sha3,
                                              order[i].body->shape_sha3) == 0)
            end++;
        for (int j = i + 1; j < end; j++) {
            if (inv_digest_cmp(order[i].body->exact_sha3,
                               order[j].body->exact_sha3) == 0)
                continue;
            if (!inv_duplicate_push(report,
                                    CI_INVENTORY_DUPLICATE_ALPHA_SHAPE,
                                    order[i].body, order[j].body)) {
                free(order); return false;
            }
        }
        i = end;
    }
    free(order);
    qsort(report->duplicates, (size_t)report->duplicate_count,
          sizeof(*report->duplicates), inv_duplicate_value_cmp);
    return true;
}

static bool inv_contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !needle[0]) return false;
    size_t n = strlen(needle);
    for (const char *p = haystack; *p; p++)
        if (strncasecmp(p, needle, n) == 0) return true;
    return false;
}

static bool inv_contract_like(const char *doc)
{
    static const char *const words[] = {
        "must", "never", "only", "return", "reject", "refus", "valid",
        "guarante", "ensure", "require", "bound", "check", "fail",
        "true", "false", "atomic", "safe", "exact", NULL
    };
    if (!doc || !doc[0]) return false;
    for (size_t i = 0; words[i]; i++)
        if (inv_contains_ci(doc, words[i])) return true;
    return false;
}

static bool inv_invariant_push(struct ci_inventory_report *report,
                               const struct ci_inventory_capability *cap,
                               const struct ci_inventory_symbol *symbol,
                               const struct inv_body *variant)
{
    const char *path = variant ? variant->path : symbol->definition_path;
    int line = variant ? variant->line : symbol->definition_line;
    if (variant && strcmp(path, symbol->definition_path) == 0)
        line = symbol->definition_line;
    for (int i = 0; variant && i < report->invariant_count; i++)
        if (report->invariants[i].definition_line == line &&
            strcmp(report->invariants[i].symbol, symbol->name) == 0 &&
            strcmp(report->invariants[i].definition_path, path) == 0)
            return true;
    int n = report->invariant_count;
    if (!inv_report_array_grow((void **)&report->invariants,
                               &report->invariant_cap, n,
                               sizeof(*report->invariants),
                               "ci_inventory_invariants"))
        return false;
    struct ci_inventory_invariant *gap = &report->invariants[n];
    memset(gap, 0, sizeof(*gap));
    inv_cpy(gap->header, sizeof(gap->header), cap->header);
    inv_cpy(gap->symbol, sizeof(gap->symbol), symbol->name);
    inv_cpy(gap->definition_path, sizeof(gap->definition_path), path);
    gap->definition_line = line;
    inv_cpy(gap->contract, sizeof(gap->contract), symbol->contract);
    gap->production_use_files = symbol->production_use_files;
    gap->test_use_files = symbol->test_use_files;
    gap->test_evidence = variant ? CI_INVENTORY_TEST_NONE
                                 : symbol->test_evidence;
    if (!variant)
        inv_cpy(gap->registered_test_group,
                sizeof(gap->registered_test_group),
                symbol->registered_test_group);
    gap->multi_arm_definition = symbol->multi_arm_definition;
    inv_cpy(gap->definition_scope, sizeof(gap->definition_scope),
            symbol->multi_arm_definition
                ? (variant ? "preprocessor_arm_UNPROVEN"
                           : "multi_arm_aggregate_UNPROVEN")
                : "single_definition");
    if (variant)
        inv_cpy(gap->preprocessor_guard,
                sizeof(gap->preprocessor_guard),
                variant->preprocessor_guard);
    inv_cpy(gap->constant_return_evidence,
            sizeof(gap->constant_return_evidence),
            variant ? "parsed_definition_body" :
            (symbol->multi_arm_definition
                ? "aggregate_withheld_UNPROVEN" : "parsed_definition_body"));
    gap->constant_return_body = variant ? true : symbol->constant_return_body;
    inv_cpy(gap->constant_return_value, sizeof(gap->constant_return_value),
            variant ? variant->constant_value : symbol->constant_return_value);
    inv_cpy(gap->verdict, sizeof(gap->verdict), "UNPROVEN");
    inv_cpy(gap->proof_needed, sizeof(gap->proof_needed),
            gap->constant_return_body
                ? (variant
                    ? (symbol->multi_arm_definition
                        ? "preprocess each named arm and run outcome-distinguishing registered tests; this constant belongs only to this arm, never the aggregate symbol"
                        : "preprocess and run a registered positive/negative test reaching this exact definition variant and proving its constant result is intentional")
                    : "registered positive/negative test proving the constant result is intentional for every documented input class")
                : "registered test reaching this symbol and asserting the header claim with outcome-distinguishing cases");
    report->invariant_count++;
    return true;
}

/* Sorted index over the constant-return, non-header/non-test/non-example
 * bodies, keyed by name, so the shadow-definition scan below can look up a
 * symbol's candidate bodies in O(log n + matches) instead of rescanning
 * every body in the codebase for every function symbol -- same O(symbols *
 * bodies) shape as the multi-arm scan fixed above. Dedup inside
 * inv_invariant_push and the final qsort by (symbol, definition_path,
 * definition_line) make push order immaterial to the emitted set. */
struct inv_const_body_order { const char *name; const struct inv_body *body; };

static int inv_const_body_order_cmp(const void *a, const void *b)
{
    const struct inv_const_body_order *x = a, *y = b;
    return strcmp(x->name, y->name);
}

static int inv_const_body_lower(const struct inv_const_body_order *order,
                                int count, const char *name)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (strcmp(order[mid].name, name) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static bool inv_derive_invariants(const struct inv_scan *scan,
                                  struct ci_inventory_report *report)
{
    for (int c = 0; c < report->capability_count; c++) {
        const struct ci_inventory_capability *cap = &report->capabilities[c];
        for (int i = cap->symbol_offset; i < cap->symbol_offset + cap->symbol_count;
             i++) {
            const struct ci_inventory_symbol *symbol = &report->symbols[i];
            if (symbol->kind != 'T' && symbol->kind != 't') continue;
            if (symbol->test_evidence == CI_INVENTORY_TEST_REGISTERED_REACHABLE)
                continue;
            if (!symbol->constant_return_body && !inv_contract_like(symbol->contract))
                continue;
            if (!inv_invariant_push(report, cap, symbol, NULL)) return false;
            }
        }
    struct inv_const_body_order *const_bodies = zcl_malloc(
        (size_t)scan->body_count * sizeof(*const_bodies),
        "ci_inventory_const_bodies");
    if (scan->body_count && !const_bodies) return false;
    int const_body_count = 0;
    for (int b = 0; b < scan->body_count; b++) {
        const struct inv_body *body = &scan->bodies[b];
        const struct inv_file *file = &scan->files[body->file_index];
        if (!body->constant_return || file->is_header || file->is_test ||
            file->is_example)
            continue;
        const_bodies[const_body_count].name = body->name;
        const_bodies[const_body_count++].body = body;
    }
    qsort(const_bodies, (size_t)const_body_count, sizeof(*const_bodies),
          inv_const_body_order_cmp);
    for (int c = 0; c < report->capability_count; c++) {
        const struct ci_inventory_capability *cap = &report->capabilities[c];
        for (int i = cap->symbol_offset; i < cap->symbol_offset + cap->symbol_count;
             i++) {
            const struct ci_inventory_symbol *symbol = &report->symbols[i];
            if (symbol->kind != 'T' && symbol->kind != 't') continue;
            int at = inv_const_body_lower(const_bodies, const_body_count,
                                          symbol->name);
            for (; at < const_body_count &&
                   strcmp(const_bodies[at].name, symbol->name) == 0; at++) {
                const struct inv_body *body = const_bodies[at].body;
                if (symbol->test_evidence ==
                        CI_INVENTORY_TEST_REGISTERED_REACHABLE &&
                    strcmp(symbol->definition_path, body->path) == 0)
                    continue;
                if (!inv_invariant_push(report, cap, symbol, body)) {
                    free(const_bodies);
                    return false;
                }
            }
        }
    }
    free(const_bodies);
    qsort(report->invariants, (size_t)report->invariant_count,
          sizeof(*report->invariants), inv_invariant_value_cmp);
    return true;
}

static bool inv_definition_arm_push(
    struct ci_inventory_report *report,
    const struct ci_inventory_capability *cap,
    const struct ci_inventory_symbol *symbol,
    const struct inv_symbol_occurrence *occ,
    const struct inv_body *body)
{
    int n = report->definition_arm_count;
    if (!inv_report_array_grow((void **)&report->definition_arms,
                               &report->definition_arm_cap, n,
                               sizeof(*report->definition_arms),
                               "ci_inventory_definition_arms"))
        return false;
    struct ci_inventory_definition_arm *arm = &report->definition_arms[n];
    memset(arm, 0, sizeof(*arm));
    inv_cpy(arm->header, sizeof(arm->header), cap->header);
    inv_cpy(arm->symbol, sizeof(arm->symbol), symbol->name);
    inv_cpy(arm->definition_path, sizeof(arm->definition_path),
            occ->symbol.def_path);
    arm->definition_line = occ->symbol.def_line;
    inv_cpy(arm->preprocessor_guard, sizeof(arm->preprocessor_guard),
            occ->symbol.guard);
    inv_cpy(arm->constant_return_evidence,
            sizeof(arm->constant_return_evidence),
            body ? "parsed_definition_body" : "body_binding_UNPROVEN");
    arm->constant_return_body = body && body->constant_return;
    if (body)
        inv_cpy(arm->constant_return_value,
                sizeof(arm->constant_return_value), body->constant_value);
    inv_cpy(arm->verdict, sizeof(arm->verdict), "UNPROVEN");
    inv_cpy(arm->proof_needed, sizeof(arm->proof_needed),
            body && occ->symbol.guard[0]
                ? "preprocess the translation unit for this guard and run registered outcome-distinguishing tests against the emitted arm"
                : "recover the missing preprocessor-arm binding, preprocess the selected profile, and run registered outcome-distinguishing tests");
    report->definition_arm_count++;
    return true;
}

static const struct inv_body *inv_body_for_occurrence(
    const struct inv_scan *scan, const struct inv_symbol_occurrence *occ)
{
    int next_definition = 0;
    for (int i = 0; i < scan->occurrence_count; i++) {
        const struct inv_symbol_occurrence *other = &scan->occurrences[i];
        if (other == occ || strcmp(other->symbol.name, occ->symbol.name) != 0 ||
            strcmp(other->symbol.def_path, occ->symbol.def_path) != 0 ||
            other->symbol.def_line <= occ->symbol.def_line)
            continue;
        if (!next_definition || other->symbol.def_line < next_definition)
            next_definition = other->symbol.def_line;
    }
    const struct inv_body *best = NULL;
    for (int i = 0; i < scan->body_count; i++) {
        const struct inv_body *body = &scan->bodies[i];
        if (strcmp(body->name, occ->symbol.name) != 0 ||
            strcmp(body->path, occ->symbol.def_path) != 0 ||
            body->line < occ->symbol.def_line ||
            (next_definition && body->line >= next_definition))
            continue;
        if (!best || body->line < best->line) best = body;
    }
    return best;
}

static bool inv_derive_definition_arms(const struct inv_scan *scan,
                                       struct ci_inventory_report *report)
{
    for (int c = 0; c < report->capability_count; c++) {
        const struct ci_inventory_capability *cap = &report->capabilities[c];
        for (int i = cap->symbol_offset;
             i < cap->symbol_offset + cap->symbol_count; i++) {
            const struct ci_inventory_symbol *symbol = &report->symbols[i];
            if (!symbol->multi_arm_definition) continue;
            int found = 0;
            for (int oi = 0; oi < scan->occurrence_count; oi++) {
                const struct inv_symbol_occurrence *occ =
                    &scan->occurrences[oi];
                if (occ->symbol.kind != symbol->kind ||
                    strcmp(occ->symbol.name, symbol->name) != 0 ||
                    !inv_occurrence_is_baselined_arm(scan, occ))
                    continue;
                const struct inv_body *body =
                    inv_body_for_occurrence(scan, occ);
                if (!inv_definition_arm_push(report, cap, symbol, occ, body))
                    return false;
                found++;
            }
            if (found != symbol->definition_arm_count)
                LOG_FAIL("codeindex.inventory",
                         "multi-arm count changed during derivation: %s",
                         symbol->name);
        }
    }
    qsort(report->definition_arms, (size_t)report->definition_arm_count,
          sizeof(*report->definition_arms), inv_definition_arm_value_cmp);
    return true;
}

struct ci_inventory_report *codeindex_inventory_analyze(const char *root)
{
    if (!root || !root[0]) LOG_NULL("codeindex.inventory", "empty source root");
    struct inv_scan scan = { .root = root };
    struct ci_inventory_report *report = zcl_calloc(1, sizeof(*report),
                                                    "ci_inventory_report");
    if (!report) return NULL;
    int *cap_for_symbol = NULL;
    if (!inv_scan_all(&scan, report->source_root_sha3) ||
        !inv_build_capabilities(&scan, report, &cap_for_symbol) ||
        !inv_count_uses(&scan, report, cap_for_symbol) ||
        !inv_registered_reachability(&scan, report) ||
        !inv_derive_duplicates(&scan, report) ||
        !inv_derive_definition_arms(&scan, report) ||
        !inv_derive_invariants(&scan, report)) {
        free(cap_for_symbol);
        inv_scan_release(&scan);
        codeindex_inventory_free(report);
        LOG_NULL("codeindex.inventory", "inventory derivation failed");
    }
    report->files_scanned = scan.file_count;
    report->registered_test_groups = scan.group_count;
    report->arm_baseline_symbols = scan.arm_symbol_count;
    report->scanner_partial_symbols = scan.scanner_partial_symbols;
    for (int i = 0; i < scan.file_count; i++) {
        if (scan.files[i].is_test) report->test_files++;
        else if (!scan.files[i].is_example) report->production_files++;
    }
    free(cap_for_symbol);
    inv_scan_release(&scan);
    return report;
}

void codeindex_inventory_free(struct ci_inventory_report *report)
{
    if (!report) return;
    free(report->capabilities);
    free(report->symbols);
    free(report->duplicates);
    free(report->invariants);
    free(report->definition_arms);
    free(report->test_root_gaps);
    free(report);
}
