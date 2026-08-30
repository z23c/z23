/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Derive conservative use counts and path-bound registered-test evidence. */

#include "codeindex_inventory_internal.h"

#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

struct inv_ev_symbol_order { int index; const char *name; };
struct inv_ev_cap_order {
    int index;
    const char *token;
    const char *header;
};
struct inv_ev_body_order { int index; const struct inv_body *body; };
struct inv_ev_body_mark { bool reached; char group[128]; };

static int inv_ev_symbol_cmp(const void *a, const void *b)
{
    const struct inv_ev_symbol_order *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    return c ? c : (x->index > y->index) - (x->index < y->index);
}

static int inv_ev_cap_cmp(const void *a, const void *b)
{
    const struct inv_ev_cap_order *x = a, *y = b;
    int c = strcmp(x->token, y->token);
    return c ? c : (x->index > y->index) - (x->index < y->index);
}

static int inv_ev_ref_cmp(const void *a, const void *b)
{
    const struct inv_ref *x = a, *y = b;
    int c = strcmp(x->callee, y->callee);
    if (c) return c;
    if (x->file_index != y->file_index)
        return (x->file_index > y->file_index) -
               (x->file_index < y->file_index);
    if (x->line != y->line)
        return (x->line > y->line) - (x->line < y->line);
    return strcmp(x->enclosing, y->enclosing);
}

static int inv_ev_body_cmp(const void *a, const void *b)
{
    const struct inv_ev_body_order *x = a, *y = b;
    int c = strcmp(x->body->name, y->body->name);
    if (c) return c;
    c = strcmp(x->body->path, y->body->path);
    if (c) return c;
    return (x->body->line > y->body->line) -
           (x->body->line < y->body->line);
}

static int inv_ev_name_lower(const struct inv_ev_symbol_order *order,
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

static int inv_ev_body_lower(const struct inv_ev_body_order *order,
                             int count, const char *name)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (strcmp(order[mid].body->name, name) < 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static int inv_ev_cap_exact(const struct inv_ev_cap_order *order, int count,
                            const char *token)
{
    int lo = 0, hi = count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int c = strcmp(order[mid].token, token);
        if (c == 0) return order[mid].index;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

static int inv_ev_resolve_include(const struct inv_scan *scan,
                                  const struct inv_ev_cap_order *order,
                                  int cap_count, int file_index,
                                  const char *token)
{
    int exact = inv_ev_cap_exact(order, cap_count, token);
    if (exact >= 0) return exact;
    char relative[512];
    inv_cpy(relative, sizeof(relative), scan->files[file_index].path);
    char *slash = strrchr(relative, '/');
    if (slash) {
        slash[1] = '\0';
        size_t used = strlen(relative), add = strlen(token);
        if (used + add + 1 < sizeof(relative)) {
            memcpy(relative + used, token, add + 1);
            int found = -1;
            for (int i = 0; i < cap_count; i++) {
                if (strcmp(order[i].header, relative) != 0) continue;
                if (found >= 0) return -1;
                found = order[i].index;
            }
            if (found >= 0) return found;
        }
    }
    int found = -1;
    size_t tn = strlen(token);
    for (int i = 0; i < cap_count; i++) {
        const char *candidate = order[i].token;
        size_t cn = strlen(candidate);
        if (cn < tn || strcmp(candidate + cn - tn, token) != 0 ||
            (cn > tn && candidate[cn - tn - 1] != '/')) continue;
        if (found >= 0) return -1;
        found = order[i].index;
    }
    return found;
}

static void inv_ev_bit_set(uint8_t *bits, size_t stride, int cap, int file)
{
    size_t bit = (size_t)cap * stride * 8u + (size_t)file;
    bits[bit / 8u] |= (uint8_t)(1u << (bit % 8u));
}

static bool inv_ev_bit_get(const uint8_t *bits, size_t stride,
                           int cap, int file)
{
    size_t bit = (size_t)cap * stride * 8u + (size_t)file;
    return (bits[bit / 8u] & (uint8_t)(1u << (bit % 8u))) != 0;
}

static bool inv_ev_same_target(const struct ci_inventory_symbol *a,
                               const struct ci_inventory_symbol *b)
{
    if (a->definition_path[0] || b->definition_path[0])
        return a->definition_line == b->definition_line &&
               strcmp(a->definition_path, b->definition_path) == 0;
    return a->declaration_line == b->declaration_line &&
           strcmp(a->declaration_path, b->declaration_path) == 0;
}

static bool inv_ev_target_visible(const struct inv_scan *scan,
                                  const struct ci_inventory_report *report,
                                  const int *cap_for_symbol,
                                  const uint8_t *cap_files, size_t stride,
                                  int symbol, int file)
{
    if (strcmp(report->symbols[symbol].definition_path,
               scan->files[file].path) == 0)
        return true;
    return inv_ev_bit_get(cap_files, stride, cap_for_symbol[symbol], file);
}

bool inv_count_uses(struct inv_scan *scan,
                    struct ci_inventory_report *report,
                    const int *cap_for_symbol)
{
    int nc = report->capability_count;
    struct inv_ev_symbol_order *symbols = zcl_malloc(
        (size_t)report->symbol_count * sizeof(*symbols),
        "ci_inventory_evidence_symbols");
    struct inv_ev_cap_order *caps = zcl_malloc(
        (size_t)nc * sizeof(*caps), "ci_inventory_evidence_caps");
    size_t stride = ((size_t)scan->file_count + 7u) / 8u;
    uint8_t *cap_files = zcl_calloc((size_t)nc, stride,
                                    "ci_inventory_cap_file_bits");
    if ((report->symbol_count && !symbols) || (nc && !caps) ||
        (nc && stride && !cap_files)) {
        free(symbols); free(caps); free(cap_files); return false;
    }
    int function_count = 0;
    for (int i = 0; i < report->symbol_count; i++) {
        if (report->symbols[i].kind != 'T' && report->symbols[i].kind != 't')
            continue;
        symbols[function_count].index = i;
        symbols[function_count++].name = report->symbols[i].name;
    }
    for (int i = 0; i < nc; i++) {
        caps[i].index = i;
        caps[i].token = report->capabilities[i].include_token;
        caps[i].header = report->capabilities[i].header;
    }
    qsort(symbols, (size_t)function_count, sizeof(*symbols), inv_ev_symbol_cmp);
    qsort(caps, (size_t)nc, sizeof(*caps), inv_ev_cap_cmp);
    for (int i = 0; i < scan->include_count; i++) {
        const struct inv_include *inc = &scan->includes[i];
        int cap = inv_ev_resolve_include(scan, caps, nc, inc->file_index,
                                         inc->token);
        if (cap < 0) { report->unresolved_include_sites++; continue; }
        if (!scan->files[inc->file_index].is_example)
            inv_ev_bit_set(cap_files, stride, cap, inc->file_index);
    }
    qsort(scan->refs, (size_t)scan->ref_count, sizeof(*scan->refs),
          inv_ev_ref_cmp);
    for (int ri = 0; ri < scan->ref_count;) {
        int end = ri + 1;
        while (end < scan->ref_count &&
               strcmp(scan->refs[end].callee, scan->refs[ri].callee) == 0 &&
               scan->refs[end].file_index == scan->refs[ri].file_index)
            end++;
        int begin = inv_ev_name_lower(symbols, function_count,
                                      scan->refs[ri].callee);
        int finish = begin;
        while (finish < function_count &&
               strcmp(symbols[finish].name, scan->refs[ri].callee) == 0)
            finish++;
        if (begin < finish) {
            int first = symbols[begin].index;
            bool one_target = true;
            for (int i = begin + 1; i < finish; i++)
                if (!inv_ev_same_target(&report->symbols[first],
                                        &report->symbols[symbols[i].index])) {
                    one_target = false; break;
                }
            int chosen = -1;
            if (!one_target) {
                for (int i = begin; i < finish; i++) {
                    int candidate = symbols[i].index;
                    if (!inv_ev_target_visible(scan, report, cap_for_symbol,
                                               cap_files, stride, candidate,
                                               scan->refs[ri].file_index))
                        continue;
                    if (chosen < 0) chosen = candidate;
                    else if (!inv_ev_same_target(&report->symbols[chosen],
                                                 &report->symbols[candidate])) {
                        chosen = -2; break;
                    }
                }
                if (chosen < 0) report->ambiguous_symbol_use_sites++;
            }
            if (one_target || chosen >= 0) {
                int target = one_target ? first : chosen;
                for (int i = begin; i < finish; i++) {
                    int index = symbols[i].index;
                    if (!inv_ev_same_target(&report->symbols[target],
                                            &report->symbols[index]))
                        continue;
                    struct ci_inventory_symbol *symbol = &report->symbols[index];
                    const struct inv_file *file =
                        &scan->files[scan->refs[ri].file_index];
                    if (file->is_test) {
                        symbol->test_use_files++;
                        if (symbol->test_evidence == CI_INVENTORY_TEST_NONE)
                            symbol->test_evidence = CI_INVENTORY_TEST_SOURCE_ONLY;
                    } else if (!file->is_example) symbol->production_use_files++;
                    if (!file->is_example)
                        inv_ev_bit_set(cap_files, stride, cap_for_symbol[index],
                                       scan->refs[ri].file_index);
                }
            }
        }
        ri = end;
    }
    for (int cap = 0; cap < nc; cap++) for (int file = 0;
         file < scan->file_count; file++) {
        if (!inv_ev_bit_get(cap_files, stride, cap, file)) continue;
        if (scan->files[file].is_test) report->capabilities[cap].test_use_files++;
        else if (!scan->files[file].is_example)
            report->capabilities[cap].production_use_files++;
    }
    free(symbols); free(caps); free(cap_files);
    return true;
}

static int inv_ev_body_in_file(const struct inv_ev_body_order *order,
                               int begin, int end, int file)
{
    int found = -1;
    for (int i = begin; i < end; i++) {
        if (order[i].body->file_index != file) continue;
        if (found >= 0) return -1;
        found = order[i].index;
    }
    return found;
}

static bool inv_ev_cap_exposes_body(const struct ci_inventory_report *report,
                                    int cap, const char *name,
                                    const struct inv_body *body)
{
    const struct ci_inventory_capability *c = &report->capabilities[cap];
    for (int i = c->symbol_offset; i < c->symbol_offset + c->symbol_count; i++) {
        const struct ci_inventory_symbol *s = &report->symbols[i];
        if ((s->kind == 'T' || s->kind == 't') &&
            strcmp(s->name, name) == 0 &&
            strcmp(s->definition_path, body->path) == 0)
            return true;
    }
    return false;
}

static int inv_ev_resolve_body(const struct inv_ev_body_order *order,
                               int body_count, const struct inv_scan *scan,
                               const struct ci_inventory_report *report,
                               const uint8_t *cap_files, size_t stride,
                               const char *name, int caller_file)
{
    int begin = inv_ev_body_lower(order, body_count, name), end = begin;
    while (end < body_count && strcmp(order[end].body->name, name) == 0) end++;
    if (begin == end) return -1;
    int local = inv_ev_body_in_file(order, begin, end, caller_file);
    if (local >= 0) return local;
    if (end == begin + 1) return order[begin].index;
    if (caller_file < 0) return -1;
    int found = -1;
    for (int i = begin; i < end; i++) {
        bool visible = false;
        for (int cap = 0; cap < report->capability_count && !visible; cap++)
            visible = inv_ev_bit_get(cap_files, stride, cap, caller_file) &&
                inv_ev_cap_exposes_body(report, cap, name, order[i].body);
        if (!visible) continue;
        if (found >= 0 && found != order[i].index) return -1;
        found = order[i].index;
    }
    (void)scan;
    return found;
}

static bool inv_ev_root_gap_push(struct ci_inventory_report *report,
                                 const struct inv_registered_group *group,
                                 const char *reason, const char *proof)
{
    int n = report->test_root_gap_count;
    void *p = zcl_realloc(report->test_root_gaps,
        (size_t)(n + 1) * sizeof(*report->test_root_gaps),
        "ci_inventory_test_root_gaps");
    if (!p) return false;
    report->test_root_gaps = p;
    struct ci_inventory_test_root_gap *gap = &report->test_root_gaps[n];
    memset(gap, 0, sizeof(*gap));
    inv_cpy(gap->group, sizeof(gap->group), group->name);
    inv_cpy(gap->root_symbol, sizeof(gap->root_symbol), group->root_symbol);
    inv_cpy(gap->reason, sizeof(gap->reason), reason);
    inv_cpy(gap->verdict, sizeof(gap->verdict), "UNPROVEN");
    inv_cpy(gap->proof_needed, sizeof(gap->proof_needed), proof);
    report->test_root_gap_count++;
    return true;
}

bool inv_registered_reachability(const struct inv_scan *scan,
                                 struct ci_inventory_report *report)
{
    struct inv_ev_body_order *order = zcl_malloc(
        (size_t)scan->body_count * sizeof(*order), "ci_inventory_body_evidence");
    struct inv_ev_body_mark *marks = zcl_calloc(
        (size_t)scan->body_count, sizeof(*marks), "ci_inventory_body_marks");
    struct inv_ev_cap_order *caps = zcl_malloc(
        (size_t)report->capability_count * sizeof(*caps),
        "ci_inventory_test_caps");
    size_t stride = ((size_t)scan->file_count + 7u) / 8u;
    uint8_t *cap_files = zcl_calloc((size_t)report->capability_count, stride,
                                    "ci_inventory_test_cap_files");
    if ((scan->body_count && (!order || !marks)) ||
        (report->capability_count && (!caps || (stride && !cap_files)))) {
        free(order); free(marks); free(caps); free(cap_files); return false;
    }
    for (int i = 0; i < scan->body_count; i++) {
        order[i].index = i; order[i].body = &scan->bodies[i];
    }
    for (int i = 0; i < report->capability_count; i++) {
        caps[i].index = i; caps[i].token = report->capabilities[i].include_token;
        caps[i].header = report->capabilities[i].header;
    }
    qsort(order, (size_t)scan->body_count, sizeof(*order), inv_ev_body_cmp);
    qsort(caps, (size_t)report->capability_count, sizeof(*caps), inv_ev_cap_cmp);
    for (int i = 0; i < scan->include_count; i++) {
        int cap = inv_ev_resolve_include(scan, caps, report->capability_count,
            scan->includes[i].file_index, scan->includes[i].token);
        if (cap >= 0) inv_ev_bit_set(cap_files, stride, cap,
                                    scan->includes[i].file_index);
    }
    for (int i = 0; i < scan->group_count; i++) {
        int begin = inv_ev_body_lower(order, scan->body_count,
                                      scan->groups[i].root_symbol);
        int end = begin;
        while (end < scan->body_count &&
               strcmp(order[end].body->name,
                      scan->groups[i].root_symbol) == 0) end++;
        if (end == begin + 1) {
            int at = order[begin].index;
            marks[at].reached = true;
            inv_cpy(marks[at].group, sizeof(marks[at].group),
                    scan->groups[i].name);
            report->registered_test_roots_found++;
        } else if (begin == end) {
            if (!inv_ev_root_gap_push(report, &scan->groups[i],
                    "body_not_found_or_macro_generated",
                    "preprocess the registered test translation unit with its exact build defines and bind the emitted root body")) {
                free(order); free(marks); free(caps); free(cap_files);
                return false;
            }
            report->registered_test_roots_missing++;
        } else {
            if (!inv_ev_root_gap_push(report, &scan->groups[i],
                    "multiple_conditional_or_duplicate_bodies",
                    "preprocess the registered test translation unit for the selected platform and bind exactly one emitted root body")) {
                free(order); free(marks); free(caps); free(cap_files);
                return false;
            }
            report->ambiguous_registered_test_roots++;
        }
    }
    bool changed;
    int rounds = 0;
    do {
        changed = false;
        for (int i = 0; i < scan->ref_count; i++) {
            if (!scan->refs[i].enclosing[0]) continue;
            int from = inv_ev_resolve_body(order, scan->body_count, scan, report,
                cap_files, stride, scan->refs[i].enclosing,
                scan->refs[i].file_index);
            if (from < 0 || !marks[from].reached) continue;
            int to = inv_ev_resolve_body(order, scan->body_count, scan, report,
                cap_files, stride, scan->refs[i].callee,
                scan->refs[i].file_index);
            if (to < 0 || marks[to].reached) continue;
            marks[to].reached = true;
            inv_cpy(marks[to].group, sizeof(marks[to].group), marks[from].group);
            changed = true;
        }
        rounds++;
    } while (changed && rounds <= scan->body_count);
    for (int i = 0; i < scan->ref_count; i++) {
        if (!scan->refs[i].enclosing[0]) continue;
        int from = inv_ev_resolve_body(order, scan->body_count, scan, report,
            cap_files, stride, scan->refs[i].enclosing,
            scan->refs[i].file_index);
        if (from < 0 || !marks[from].reached) continue;
        int begin = inv_ev_body_lower(order, scan->body_count,
                                      scan->refs[i].callee);
        if (begin >= scan->body_count ||
            strcmp(order[begin].body->name, scan->refs[i].callee) != 0)
            continue;
        if (inv_ev_resolve_body(order, scan->body_count, scan, report,
                cap_files, stride, scan->refs[i].callee,
                scan->refs[i].file_index) < 0)
            report->ambiguous_test_call_edges++;
    }
    for (int i = 0; i < report->symbol_count; i++) {
        struct ci_inventory_symbol *symbol = &report->symbols[i];
        if ((symbol->kind != 'T' && symbol->kind != 't') ||
            !symbol->definition_path[0]) continue;
        int begin = inv_ev_body_lower(order, scan->body_count, symbol->name);
        int found = -1;
        for (int at = begin; at < scan->body_count &&
             strcmp(order[at].body->name, symbol->name) == 0; at++) {
            const struct inv_body *body = order[at].body;
            if (strcmp(body->path, symbol->definition_path) != 0) continue;
            if (found >= 0) { found = -2; break; }
            found = order[at].index;
        }
        if (found < 0 || !marks[found].reached) continue;
        symbol->test_evidence = CI_INVENTORY_TEST_REGISTERED_REACHABLE;
        inv_cpy(symbol->registered_test_group,
                sizeof(symbol->registered_test_group), marks[found].group);
    }
    for (int c = 0; c < report->capability_count; c++) {
        struct ci_inventory_capability *cap = &report->capabilities[c];
        for (int i = cap->symbol_offset; i < cap->symbol_offset + cap->symbol_count;
             i++) if (report->symbols[i].test_evidence ==
                      CI_INVENTORY_TEST_REGISTERED_REACHABLE)
            cap->registered_test_symbols++;
    }
    free(order); free(marks); free(caps); free(cap_files);
    return true;
}
