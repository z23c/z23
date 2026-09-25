/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run one frozen corpus entry through the landing proof's own
 * selector and price what it selected against the conservative reference. */

#include "dev_shadow_select.h"

#include "devloop.h"
#include "test_group_catalog.h"
#include "test_group_host_need.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define SHADOW_PATCH_MAX (1024u * 1024u)
#define SHADOW_REVERSE_CAP 8192

static void shadow_eval_why(char *why, size_t why_len, const char *fmt, ...)
{
    if (!why || why_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, why_len, fmt, ap);
    va_end(ap);
}

/* ── one bit per catalog group ────────────────────────────────────────── */
struct shadow_marks {
    size_t n;
    bool *reference;
    bool *selected;
    bool *floor;
    bool *edge;
};

static void shadow_marks_free(struct shadow_marks *m)
{
    free(m->reference);
    free(m->selected);
    free(m->floor);
    free(m->edge);
}

static bool shadow_marks_init(struct shadow_marks *m)
{
    memset(m, 0, sizeof(*m));
    m->n = zcl_test_group_catalog_count();
    m->reference = zcl_calloc(m->n, sizeof(bool), "shadow_ref");
    m->selected = zcl_calloc(m->n, sizeof(bool), "shadow_sel");
    m->floor = zcl_calloc(m->n, sizeof(bool), "shadow_floor");
    m->edge = zcl_calloc(m->n, sizeof(bool), "shadow_edge");
    return m->n > 0 && m->reference && m->selected && m->floor && m->edge;
}

static size_t shadow_catalog_index(const char *full)
{
    size_t n = zcl_test_group_catalog_count();
    for (size_t i = 0; i < n; i++)
        if (strcmp(zcl_test_group_catalog_at(i), full) == 0) return i;
    return SIZE_MAX;
}

struct shadow_mark_sink {
    bool *bits;
};

static bool shadow_mark_visit(const char *full, void *ctx)
{
    struct shadow_mark_sink *sink = ctx;
    size_t i = shadow_catalog_index(full);
    if (i == SIZE_MAX) return false;
    sink->bits[i] = true;
    return true;
}

static bool shadow_mark_tokens(const char (*groups)[ZCL_DEVLOOP_GROUP_MAX],
                               size_t len, bool *bits)
{
    struct shadow_mark_sink sink = {bits};
    for (size_t i = 0; i < len; i++)
        if (!zcl_test_group_family_expand(groups[i], shadow_mark_visit, &sink))
            return false;
    return true;
}

/* The landing reference: the universal selector's catalog, minus exactly the
 * groups whose declared host need this tree cannot meet. */
static bool shadow_mark_reference(const char *root, struct shadow_marks *m)
{
    for (size_t i = 0; i < m->n; i++) {
        struct zcl_test_group_host_need need;
        if (!zcl_test_group_host_need(zcl_test_group_catalog_at(i), &need))
            return false;
        m->reference[i] = need.kind == ZCL_HOST_NEED_NONE ||
                          zcl_test_group_host_need_met(root, &need);
    }
    return true;
}

/* A module's directory: everything before its src/, include/ or tests/. */
static void shadow_component_of(const char *path, char *out, size_t cap)
{
    static const char *const cuts[] = {"/src/", "/include/", "/tests/"};
    size_t len = strlen(path);
    for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        const char *hit = strstr(path, cuts[i]);
        if (hit && (size_t)(hit - path) < len) len = (size_t)(hit - path);
    }
    if (len == strlen(path)) {
        const char *slash = strrchr(path, '/');
        len = slash ? (size_t)(slash - path) : 0;
    }
    if (len >= cap) len = cap - 1;
    memcpy(out, path, len);
    out[len] = '\0';
}

/* Cross-component edges: graph-dimension selections reached through a file
 * outside the changed component. */
static bool shadow_mark_edges(const struct zcl_devloop_plan *plan,
                              const char *component, struct shadow_marks *m)
{
    for (size_t i = 0; i < plan->selections_len; i++) {
        const struct zcl_devloop_selection *s = &plan->selections[i];
        if (s->dim == ZCL_DEVLOOP_DIM_OPAQUE) continue;
        char via_component[ZCL_SHADOW_PATH_MAX];
        shadow_component_of(s->via, via_component, sizeof(via_component));
        if (strcmp(via_component, component) == 0) continue;
        struct shadow_mark_sink sink = {m->edge};
        if (!zcl_test_group_family_expand(s->group, shadow_mark_visit, &sink))
            return false;
    }
    return true;
}

/* ── patch bytes ──────────────────────────────────────────────────────── */

static bool shadow_read_file(const char *path, uint8_t *buf, size_t cap,
                             size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    *len = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && *len < cap;
    fclose(f);
    return ok;
}

static bool shadow_load_patch(const struct zcl_shadow_eval_ctx *ctx,
                              const struct zcl_shadow_entry *e, uint8_t *buf,
                              size_t cap, size_t *len)
{
    if (e->kind != ZCL_SHADOW_KIND_REAL) {
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s.patch", ctx->fixture_dir,
                         e->id);
        return n > 0 && (size_t)n < sizeof(path) &&
               shadow_read_file(path, buf, cap, len);
    }
    const char *argv[24];
    if (!zcl_shadow_real_patch_argv(ctx->root, e->commit, argv, 24))
        return false;
    struct zcl_spawn_binary_observation obs = {0};
    struct zcl_result r =
        zcl_spawn_capture_binary(argv, buf, cap, 60000, &obs);
    if (!r.ok) return false;
    *len = obs.output_len;
    return true;
}

static bool shadow_same_file_set(const struct zcl_shadow_entry *e,
                                 const struct zcl_shadow_patch_facts *p)
{
    if (e->file_count != p->file_count) return false;
    for (size_t i = 0; i < e->file_count; i++) {
        bool found = false;
        for (size_t j = 0; j < p->file_count; j++)
            found = found || strcmp(e->files[i], p->files[j]) == 0;
        if (!found) return false;
    }
    return true;
}

/* ── build actions ────────────────────────────────────────────────────── */

struct shadow_tu_set {
    char (*paths)[256];
    size_t len;
    size_t cap;
};

static bool shadow_tu_add(struct shadow_tu_set *s, const char *path)
{
    for (size_t i = 0; i < s->len; i++)
        if (strcmp(s->paths[i], path) == 0) return true;
    if (s->len >= s->cap) return false;
    (void)snprintf(s->paths[s->len++], 256, "%s", path);
    return true;
}

/* Every TU whose depfile names `file`. A reader other than the file itself
 * of a NON-contract file is a private premise: that TU depends on bytes the
 * contract root does not cover. */
static bool shadow_tu_add_reverse(struct codeindex *ci, const char *component,
                                  const char *file, struct shadow_tu_set *set,
                                  char (*tmp)[256], bool *known,
                                  uint32_t *private_readers)
{
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    int n = codeindex_reverse_includes(ci, file, tmp, SHADOW_REVERSE_CAP,
                                       &dim);
    if (n < 0) return false;
    *known = *known && dim == CODEINDEX_INCLUDE_DIM_COMPLETE;
    bool contract = zcl_shadow_path_is_contract(component, file);
    for (int i = 0; i < n; i++) {
        if (!shadow_tu_add(set, tmp[i])) return false;
        if (!contract && strcmp(tmp[i], file) != 0) (*private_readers)++;
    }
    return true;
}

/* How many translation units must recompile: the changed TUs themselves plus
 * every TU whose depfile names a changed file; every TU for a build-graph
 * edit. `known` is false when the include graph could not answer. */
static bool shadow_count_build(const char *root,
                               const struct zcl_shadow_entry *e,
                               struct zcl_shadow_result *out)
{
    size_t total = 0;
    int64_t newest = 0;
    out->build_known = false;
    if (!codeindex_depfile_graph(root, &total, &newest)) return false;
    out->build_total = (uint32_t)total;
    for (size_t i = 0; i < e->file_count; i++)
        if (zcl_shadow_path_is_build_graph(e->files[i])) {
            out->build_invalidated = out->build_total;
            out->build_known = total > 0;
            return true;
        }
    struct codeindex *ci = codeindex_open_existing(root);
    if (!ci) return true;
    struct shadow_tu_set set = {0};
    set.cap = SHADOW_REVERSE_CAP + ZCL_SHADOW_MAX_FILES;
    set.paths = zcl_calloc(set.cap, sizeof(*set.paths), "shadow_tus");
    char (*tmp)[256] = zcl_calloc(SHADOW_REVERSE_CAP, sizeof(*tmp),
                                  "shadow_rev");
    bool known = total > 0, ok = set.paths && tmp;
    for (size_t i = 0; ok && i < e->file_count; i++) {
        if (codeindex_path_is_translation_unit(e->files[i]))
            ok = shadow_tu_add(&set, e->files[i]);
        ok = ok && shadow_tu_add_reverse(ci, e->component, e->files[i], &set,
                                         tmp, &known, &out->private_readers);
    }
    out->build_invalidated = (uint32_t)set.len;
    out->build_known = ok && known;
    free(set.paths);
    free(tmp);
    codeindex_close(ci);
    return ok;
}

/* ── premises ─────────────────────────────────────────────────────────── */

static bool shadow_is_source(const char *path)
{
    size_t n = strlen(path);
    return (n > 2 && (strcmp(path + n - 2, ".c") == 0 ||
                      strcmp(path + n - 2, ".h") == 0)) ||
           (n > 4 && strcmp(path + n - 4, ".def") == 0);
}

static bool shadow_is_harness(const char *path)
{
    if (strncmp(path, "tests/harness/", 14) != 0) return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strncmp(base, "test_", 5) != 0 ||
           strcmp(base, "test_parallel.c") == 0;
}

static uint32_t shadow_file_fields(const struct zcl_shadow_patch_facts *p,
                                   size_t i)
{
    const char *path = p->files[i];
    uint32_t bits = 0;
    size_t n = strlen(path);
    if (shadow_is_source(path)) bits |= 1u << ZCL_SHADOW_FIELD_SOURCE_CLOSURE;
    if (p->created[i] && n > 2 && strcmp(path + n - 2, ".h") == 0)
        bits |= 1u << ZCL_SHADOW_FIELD_NEGATIVE_LOOKUPS;
    if (zcl_shadow_path_is_generator_input(path))
        bits |= 1u << ZCL_SHADOW_FIELD_GENERATED_INPUTS;
    if (zcl_shadow_path_is_build_graph(path))
        bits |= (1u << ZCL_SHADOW_FIELD_FLAGS) |
                (1u << ZCL_SHADOW_FIELD_BUILD_GRAPH);
    if (shadow_is_harness(path)) bits |= 1u << ZCL_SHADOW_FIELD_HARNESS;
    if (strstr(path, "/fixtures/")) bits |= 1u << ZCL_SHADOW_FIELD_FIXTURES;
    return bits;
}

static uint32_t shadow_premise_fields(const struct zcl_shadow_patch_facts *p,
                                      const struct zcl_devloop_plan *plan)
{
    uint32_t bits = 0;
    bool impl = false;
    for (size_t i = 0; i < p->file_count; i++) {
        bits |= shadow_file_fields(p, i);
        size_t n = strlen(p->files[i]);
        impl = impl || (n > 2 && strcmp(p->files[i] + n - 2, ".c") == 0);
    }
    if (impl && (plan->closure_groups_len > 0 || plan->closure_universal))
        bits |= 1u << ZCL_SHADOW_FIELD_DEPENDENCY_CLOSURE;
    if (p->contract_change != ZCL_SHADOW_CONTRACT_NONE)
        bits |= 1u << ZCL_SHADOW_FIELD_INTEGRATION_EDGES;
    if (p->contract_change == ZCL_SHADOW_CONTRACT_MOVED)
        bits |= (1u << ZCL_SHADOW_FIELD_INVARIANTS) |
                (1u << ZCL_SHADOW_FIELD_ABI_GENERATION);
    return bits;
}

static bool shadow_global_premise(uint32_t fields)
{
    return (fields & ((1u << ZCL_SHADOW_FIELD_FLAGS) |
                      (1u << ZCL_SHADOW_FIELD_NEGATIVE_LOOKUPS) |
                      (1u << ZCL_SHADOW_FIELD_HARNESS) |
                      (1u << ZCL_SHADOW_FIELD_GENERATED_INPUTS))) != 0;
}

/* ── pricing ──────────────────────────────────────────────────────────── */

struct shadow_pricing {
    const struct zcl_shadow_weights *w;
    uint32_t median_group;
    uint32_t median_gate;
};

static uint64_t shadow_group_ms(const struct shadow_pricing *p,
                                const char *full, uint32_t *unweighted)
{
    uint32_t ms = 0;
    if (zcl_shadow_weight_ms(p->w, ZCL_SHADOW_OBLIGATION_TEST_GROUP, full,
                             &ms))
        return ms;
    (*unweighted)++;
    return p->median_group;
}

static uint64_t shadow_lint_ms(const struct shadow_pricing *p, uint32_t *count)
{
    uint64_t sum = 0;
    *count = 0;
    for (size_t i = 0; i < p->w->count; i++)
        if (p->w->rows[i].kind == ZCL_SHADOW_OBLIGATION_LINT_GATE) {
            sum += p->w->rows[i].mean_ms;
            (*count)++;
        }
    return sum;
}

static void shadow_price(const struct shadow_pricing *p,
                         const struct shadow_marks *m,
                         struct zcl_shadow_result *out)
{
    uint32_t lint_count = 0, ignored = 0;
    uint64_t lint = shadow_lint_ms(p, &lint_count);
    out->lint_selected = out->lint_reference = lint_count;
    out->fresh_cost_ms = out->reference_cost_ms = lint;
    for (size_t i = 0; i < m->n; i++) {
        const char *full = zcl_test_group_catalog_at(i);
        if (m->selected[i]) {
            out->groups_selected++;
            out->fresh_cost_ms += shadow_group_ms(p, full, &out->unweighted);
        }
        if (m->reference[i]) {
            out->groups_reference++;
            out->reference_cost_ms += shadow_group_ms(p, full, &ignored);
        }
        out->floor_groups += m->floor[i] ? 1u : 0u;
        out->edges_selected += (m->edge[i] && m->selected[i]) ? 1u : 0u;
        out->edges_reference += (m->reference[i] && !m->floor[i]) ? 1u : 0u;
    }
}

/* The compositional rule, applied in shadow: when the contract root did not
 * move and no changed private file is read by another TU, every selected
 * caller outside the changed component's own floor is reusable provided the
 * floor passes fresh. Its cost leaves the fresh bill. */
static void shadow_price_rule(const struct shadow_pricing *p,
                              const struct shadow_marks *m, bool admissible,
                              struct zcl_shadow_result *out)
{
    out->rule_cost_ms = out->fresh_cost_ms;
    out->rule_reusable = 0;
    if (!admissible) return;
    uint32_t ignored = 0;
    for (size_t i = 0; i < m->n; i++) {
        if (!m->selected[i] || m->floor[i]) continue;
        out->rule_reusable++;
        out->rule_cost_ms -=
            shadow_group_ms(p, zcl_test_group_catalog_at(i), &ignored);
    }
}

/* ── evaluation ───────────────────────────────────────────────────────── */

static bool shadow_plan(const struct zcl_shadow_eval_ctx *ctx,
                        const struct zcl_shadow_entry *e,
                        struct zcl_devloop_plan *plan, bool *refused)
{
    const char *files[ZCL_SHADOW_MAX_FILES];
    for (size_t i = 0; i < e->file_count; i++) files[i] = e->files[i];
    *refused = false;
    if (!zcl_devloop_plan_files(files, e->file_count, plan)) {
        *refused = true;
        return true;
    }
    if (!zcl_devloop_plan_add_closure(ctx->root, files, e->file_count, plan))
        return false;
    const char *reason = "";
    *refused = !zcl_devloop_plan_proof_admissible(plan, &reason);
    return true;
}

static bool shadow_select(const struct zcl_shadow_eval_ctx *ctx,
                          const struct zcl_shadow_entry *e,
                          const struct zcl_devloop_plan *plan, bool refused,
                          struct shadow_marks *m)
{
    if (!shadow_mark_reference(ctx->root, m)) return false;
    if (refused || plan->closure_universal) {
        memcpy(m->selected, m->reference, m->n * sizeof(bool));
    } else if (!shadow_mark_tokens(plan->path_groups, plan->path_groups_len,
                                   m->selected) ||
               !shadow_mark_tokens(plan->closure_groups,
                                   plan->closure_groups_len, m->selected)) {
        return false;
    }
    if (refused) return true;
    return shadow_mark_tokens(plan->path_groups, plan->path_groups_len,
                              m->floor) &&
           shadow_mark_edges(plan, e->component, m);
}

static void shadow_scope(const struct zcl_shadow_entry *e,
                         const struct zcl_devloop_plan *plan, bool refused,
                         struct zcl_shadow_result *out)
{
    struct zcl_shadow_scope_facts f = {0};
    f.bytes_mismatch = !out->bytes_verified;
    f.plan_refused = refused && !plan->closure_universal;
    f.consensus_policy = !refused && (plan->consensus_risk || plan->sealed_core);
    f.closure_universal = !refused && plan->closure_universal;
    for (size_t i = 0; i < e->file_count; i++) {
        f.build_graph_input = f.build_graph_input ||
                              zcl_shadow_path_is_build_graph(e->files[i]);
        f.generated_input = f.generated_input ||
                            zcl_shadow_path_is_generator_input(e->files[i]);
    }
    f.negative_lookup =
        (out->premise_fields & (1u << ZCL_SHADOW_FIELD_NEGATIVE_LOOKUPS)) != 0;
    out->fallback = zcl_shadow_classify(&f);
    out->selector_universal = refused || plan->closure_universal;
}

static void shadow_premise_counts(struct zcl_shadow_result *out)
{
    if (shadow_global_premise(out->premise_fields) || out->selector_universal)
        out->premise_groups = out->groups_reference;
    else if (out->patch.contract_change != ZCL_SHADOW_CONTRACT_NONE ||
             out->private_readers > 0)
        out->premise_groups = out->groups_selected;
    else
        out->premise_groups = out->floor_groups;
    out->key_gap_fields =
        out->premise_fields & zcl_shadow_component_input_key_gaps();
    if (out->premise_fields & (1u << ZCL_SHADOW_FIELD_SOURCE_CLOSURE))
        out->key_gap_fields |= 1u << ZCL_SHADOW_FIELD_UNIT_ID;
}

static bool shadow_load_and_verify(const struct zcl_shadow_eval_ctx *ctx,
                                   const struct zcl_shadow_entry *e,
                                   struct zcl_shadow_result *out, char *why,
                                   size_t why_len)
{
    uint8_t *bytes = zcl_malloc(SHADOW_PATCH_MAX, "shadow_patch");
    size_t len = 0;
    if (!bytes) return false;
    bool ok = shadow_load_patch(ctx, e, bytes, SHADOW_PATCH_MAX, &len);
    if (!ok) shadow_eval_why(why, why_len, "patch_bytes_unavailable_%s", e->id);
    if (ok) {
        uint8_t digest[32];
        zcl_sha3_256(bytes, len, digest);
        out->bytes_verified = memcmp(digest, e->patch_sha3, 32) == 0;
        ok = zcl_shadow_patch_analyze(e->component, bytes, len, &out->patch,
                                      why, why_len);
        out->bytes_verified =
            out->bytes_verified && ok && shadow_same_file_set(e, &out->patch);
    }
    free(bytes);
    return ok;
}

static bool shadow_evaluate_plan(const struct zcl_shadow_eval_ctx *ctx,
                                 const struct zcl_shadow_entry *e,
                                 struct zcl_devloop_plan *plan,
                                 struct zcl_shadow_result *out, char *why,
                                 size_t why_len)
{
    bool refused = false;
    struct shadow_marks m;
    bool ok = shadow_marks_init(&m) && shadow_plan(ctx, e, plan, &refused) &&
              shadow_select(ctx, e, plan, refused, &m) &&
              shadow_count_build(ctx->root, e, out);
    if (!ok) {
        shadow_eval_why(why, why_len, "selector_unavailable_%s", e->id);
        shadow_marks_free(&m);
        return false;
    }
    struct shadow_pricing p = {
        ctx->weights,
        zcl_shadow_weights_median(ctx->weights,
                                  ZCL_SHADOW_OBLIGATION_TEST_GROUP),
        zcl_shadow_weights_median(ctx->weights,
                                  ZCL_SHADOW_OBLIGATION_LINT_GATE),
    };
    shadow_price(&p, &m, out);
    out->premise_fields = shadow_premise_fields(&out->patch, plan);
    shadow_scope(e, plan, refused, out);
    shadow_premise_counts(out);
    bool rule_ok = out->fallback == ZCL_SHADOW_FALLBACK_NONE &&
                   out->patch.contract_change == ZCL_SHADOW_CONTRACT_NONE &&
                   out->build_known && out->private_readers == 0;
    shadow_price_rule(&p, &m, rule_ok, out);
    uint32_t reused = out->groups_reference > out->groups_selected
                          ? out->groups_reference - out->groups_selected : 0;
    out->validation_cost_us = (uint64_t)reused * ctx->validation_ns / 1000u;
    shadow_marks_free(&m);
    return true;
}

bool zcl_shadow_evaluate(const struct zcl_shadow_eval_ctx *ctx,
                         const struct zcl_shadow_entry *entry,
                         struct zcl_shadow_result *out, char *why,
                         size_t why_len)
{
    if (!ctx || !ctx->root || !ctx->weights || !entry || !out) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->id, sizeof(out->id), "%s", entry->id);
    (void)snprintf(out->component, sizeof(out->component), "%s",
                   entry->component);
    out->kind = entry->kind;
    if (!shadow_load_and_verify(ctx, entry, out, why, why_len)) return false;
    struct zcl_devloop_plan *plan =
        zcl_calloc(1, sizeof(*plan), "shadow_plan");
    if (!plan) return false;
    bool ok = shadow_evaluate_plan(ctx, entry, plan, out, why, why_len);
    free(plan);
    return ok;
}
