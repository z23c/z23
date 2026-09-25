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
    bool *explained;   /* reached by an include-explained selection */
    bool *name_only;   /* reached by an unexplained caller hop */
    bool *predicted;   /* the rule-enabled fresh set */
};

static void shadow_marks_free(struct shadow_marks *m)
{
    free(m->reference);
    free(m->selected);
    free(m->floor);
    free(m->edge);
    free(m->explained);
    free(m->name_only);
    free(m->predicted);
}

static bool shadow_marks_init(struct shadow_marks *m)
{
    memset(m, 0, sizeof(*m));
    m->n = zcl_test_group_catalog_count();
    m->reference = zcl_calloc(m->n, sizeof(bool), "shadow_ref");
    m->selected = zcl_calloc(m->n, sizeof(bool), "shadow_sel");
    m->floor = zcl_calloc(m->n, sizeof(bool), "shadow_floor");
    m->edge = zcl_calloc(m->n, sizeof(bool), "shadow_edge");
    m->explained = zcl_calloc(m->n, sizeof(bool), "shadow_expl");
    m->name_only = zcl_calloc(m->n, sizeof(bool), "shadow_name_only");
    m->predicted = zcl_calloc(m->n, sizeof(bool), "shadow_pred");
    return m->n > 0 && m->reference && m->selected && m->floor && m->edge &&
           m->explained && m->name_only && m->predicted;
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

/* Cross-component edges: graph-dimension selections reached through a file
 * outside the changed component. */
static bool shadow_mark_edges(const struct zcl_devloop_plan *plan,
                              const char *component, struct shadow_marks *m)
{
    for (size_t i = 0; i < plan->selections_len; i++) {
        const struct zcl_devloop_selection *s = &plan->selections[i];
        if (s->dim == ZCL_DEVLOOP_DIM_OPAQUE) continue;
        char via_component[ZCL_SHADOW_PATH_MAX];
        zcl_shadow_component_of(s->via, via_component, sizeof(via_component));
        if (strcmp(via_component, component) == 0) continue;
        struct shadow_mark_sink sink = {m->edge};
        if (!zcl_test_group_family_expand(s->group, shadow_mark_visit, &sink))
            return false;
    }
    return true;
}

/* Which selected groups the include graph explains and which only a bare
 * caller-name match reached (the codeindex_callers() name-only lookup). */
static bool shadow_mark_explained(const char *root,
                                  const struct zcl_shadow_entry *e,
                                  const struct zcl_devloop_plan *plan,
                                  struct shadow_marks *m,
                                  struct zcl_shadow_proof_graph *g)
{
    bool *explained = zcl_calloc(plan->selections_len + 1, sizeof(bool),
                                 "shadow_explained");
    if (!explained) return false;
    bool ok = zcl_shadow_explained_selections(root, e, plan, explained,
                                              &g->caller_hops,
                                              &g->collision_hops);
    for (size_t i = 0; ok && i < plan->selections_len; i++) {
        struct shadow_mark_sink sink = {explained[i] ? m->explained
                                                     : m->name_only};
        ok = zcl_test_group_family_expand(plan->selections[i].group,
                                          shadow_mark_visit, &sink);
    }
    free(explained);
    return ok;
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

static enum zcl_shadow_layer shadow_layer_of(const struct shadow_marks *m,
                                             size_t i)
{
    if (m->floor[i]) return ZCL_SHADOW_LAYER_CONTRACT;
    return m->edge[i] ? ZCL_SHADOW_LAYER_INTEGRATION : ZCL_SHADOW_LAYER_CALLER;
}

static void shadow_price_selected(const struct shadow_pricing *p,
                                  const struct shadow_marks *m, size_t i,
                                  struct zcl_shadow_result *out)
{
    uint64_t ms = shadow_group_ms(p, zcl_test_group_catalog_at(i),
                                  &out->unweighted);
    enum zcl_shadow_layer layer = shadow_layer_of(m, i);
    out->groups_selected++;
    out->fresh_cost_ms += ms;
    out->graph.nodes[layer]++;
    out->graph.ms[layer] += ms;
    if (!m->floor[i] && !m->explained[i] && m->name_only[i]) {
        out->graph.collision_groups++;
        out->graph.collision_ms += ms;
    }
}

static void shadow_price(const struct shadow_pricing *p,
                         const struct shadow_marks *m,
                         struct zcl_shadow_result *out)
{
    uint32_t lint_count = 0, ignored = 0;
    uint64_t lint = shadow_lint_ms(p, &lint_count);
    out->lint_selected = out->lint_reference = lint_count;
    out->lint_cost_ms = lint;
    out->fresh_cost_ms = out->reference_cost_ms = lint;
    for (size_t i = 0; i < m->n; i++) {
        if (m->selected[i]) shadow_price_selected(p, m, i, out);
        if (m->reference[i]) {
            out->groups_reference++;
            out->reference_cost_ms +=
                shadow_group_ms(p, zcl_test_group_catalog_at(i), &ignored);
        }
        out->floor_groups += m->floor[i] ? 1u : 0u;
        out->edges_selected += (m->edge[i] && m->selected[i]) ? 1u : 0u;
        out->edges_reference += (m->reference[i] && !m->floor[i]) ? 1u : 0u;
    }
}

/* Comma-separated catalog names of `bits`; "..." marks a list that did not
 * fit, which zcl_shadow_render_prediction() refuses to record. */
static void shadow_names_of(const struct shadow_marks *m, const bool *bits,
                            char *out, size_t cap)
{
    size_t pos = 0;
    out[0] = '\0';
    for (size_t i = 0; i < m->n; i++) {
        if (!bits[i]) continue;
        int n = snprintf(out + pos, cap - pos, "%s%s", pos ? "," : "",
                         zcl_test_group_catalog_at(i));
        if (n <= 0 || (size_t)n >= cap - pos) {
            (void)snprintf(out + (pos > cap - 4 ? cap - 4 : pos), 4, "...");
            return;
        }
        pos += (size_t)n;
    }
}

static uint32_t shadow_lint_max(const struct shadow_pricing *p)
{
    uint32_t max = 0;
    for (size_t i = 0; i < p->w->count; i++)
        if (p->w->rows[i].kind == ZCL_SHADOW_OBLIGATION_LINT_GATE &&
            p->w->rows[i].mean_ms > max)
            max = p->w->rows[i].mean_ms;
    return max;
}

static void shadow_rule_block(bool all, struct zcl_shadow_result *out)
{
    const char *why = "";
    if (all)
        why = "fallback";
    else if (out->patch.contract_change == ZCL_SHADOW_CONTRACT_MOVED)
        why = "contract_moved";
    else if (out->patch.contract_change == ZCL_SHADOW_CONTRACT_ADDITIVE)
        why = "contract_additive";
    else if (out->private_readers > 0)
        why = "private_reader";
    else if (!out->build_known)
        why = "build_graph_unknown";
    (void)snprintf(out->rule_block, sizeof(out->rule_block), "%s", why);
}

/* A carried obligation's standing today: it reads no changed source and the
 * rule (or the absence of any dependency) admits it, but the only verdicts
 * this host holds were written by its own uid, under a key that folds the
 * whole source tree into one root. */
static enum zcl_shadow_eligibility
shadow_carried_eligibility(const struct zcl_shadow_result *out)
{
    struct zcl_shadow_eligibility_claim claim = {
        .sensitivity = ZCL_SHADOW_SENSITIVITY_IMAGE,
        .source_changed = false,
        .rule = ZCL_SHADOW_REUSE_ADMIT,
        .missing_key_fields = out->key_gap_fields,
        .inputs_match = out->key_gap_fields == 0,
        .source = ZCL_SHADOW_SOURCE_LOCAL_SAME_UID,
    };
    return zcl_shadow_reuse_eligible(&claim);
}

static void shadow_carry(const struct shadow_pricing *p, size_t i,
                         enum zcl_shadow_eligibility why,
                         struct zcl_shadow_result *out)
{
    uint32_t ignored = 0;
    out->carried_groups++;
    out->carried_by_reason[why]++;
    if (why != ZCL_SHADOW_ELIGIBLE) return;
    out->eligible_groups++;
    out->eligible_cost_ms -=
        shadow_group_ms(p, zcl_test_group_catalog_at(i), &ignored);
}

static void shadow_keep(const struct shadow_pricing *p,
                        const struct shadow_marks *m, size_t i,
                        struct zcl_shadow_result *out)
{
    uint32_t ignored = 0;
    uint64_t ms = shadow_group_ms(p, zcl_test_group_catalog_at(i), &ignored);
    out->predicted_groups++;
    out->rule_cost_ms += ms;
    if (ms > out->critical_rule_ms) out->critical_rule_ms = (uint32_t)ms;
    if (m->selected[i]) out->graph.predicted[shadow_layer_of(m, i)]++;
}

static void shadow_layer_names(struct shadow_marks *m,
                               struct zcl_shadow_result *out)
{
    bool *bits = zcl_calloc(m->n, sizeof(bool), "shadow_layer_bits");
    if (!bits) return;
    for (unsigned layer = 0; layer < ZCL_SHADOW_LAYER__COUNT; layer++) {
        for (size_t i = 0; i < m->n; i++)
            bits[i] = m->predicted[i] && m->selected[i] &&
                      shadow_layer_of(m, i) == (enum zcl_shadow_layer)layer;
        shadow_names_of(m, bits, out->fresh_layer_names[layer],
                        sizeof(out->fresh_layer_names[layer]));
    }
    free(bits);
}

/* The reuse-enabled selector's prediction, fixed before any proof runs:
 *  - a fallback reason, or a selector that could not enumerate, runs the
 *    reference (ALL);
 *  - otherwise, when the compositional rule holds (contract root unchanged,
 *    no private reader, build graph known), only the contract layer runs
 *    fresh and callers and integration edges are carried;
 *  - otherwise every selected group runs.
 * Lint gates are source-sensitive and always run. rule_cost_ms is this
 * prediction's bill; eligible_cost_ms is the bill when only reuse that is
 * receivable today is taken. */
static void shadow_predict(const struct shadow_pricing *p,
                           struct shadow_marks *m, bool rule_ok,
                           struct zcl_shadow_result *out)
{
    bool all = out->fallback != ZCL_SHADOW_FALLBACK_NONE ||
               out->selector_universal;
    uint32_t ignored = 0;
    enum zcl_shadow_eligibility carried = shadow_carried_eligibility(out);
    out->predict_mode = all ? ZCL_SHADOW_PREDICT_ALL : ZCL_SHADOW_PREDICT_EXACT;
    out->rule_cost_ms = out->lint_cost_ms;
    out->eligible_cost_ms = out->reference_cost_ms;
    out->critical_rule_ms = out->critical_reference_ms = shadow_lint_max(p);
    shadow_rule_block(all, out);
    for (size_t i = 0; i < m->n; i++) {
        uint64_t ms = m->reference[i] ? shadow_group_ms(
                          p, zcl_test_group_catalog_at(i), &ignored) : 0;
        if (ms > out->critical_reference_ms)
            out->critical_reference_ms = (uint32_t)ms;
        bool keep = all ? m->reference[i]
                        : m->selected[i] && (!rule_ok || m->floor[i]);
        if (!all && m->selected[i] && !keep) out->rule_reusable++;
        if (keep) {
            m->predicted[i] = true;
            shadow_keep(p, m, i, out);
        } else if (m->reference[i]) {
            shadow_carry(p, i, carried, out);
        }
    }
    if (!out->selector_universal)
        shadow_names_of(m, m->selected, out->selected_names,
                        sizeof(out->selected_names));
    if (!all) {
        shadow_names_of(m, m->predicted, out->predicted_names,
                        sizeof(out->predicted_names));
        shadow_layer_names(m, out);
    }
}

/* ── evaluation ───────────────────────────────────────────────────────── */

static bool shadow_plan(const struct zcl_shadow_eval_ctx *ctx,
                        const struct zcl_shadow_entry *e,
                        struct zcl_devloop_plan *plan, bool *refused,
                        char *reason_out, size_t reason_cap)
{
    const char *files[ZCL_SHADOW_MAX_FILES];
    for (size_t i = 0; i < e->file_count; i++) files[i] = e->files[i];
    *refused = false;
    if (!zcl_devloop_plan_files(files, e->file_count, plan)) {
        *refused = true;
        (void)snprintf(reason_out, reason_cap, "plan_files_refused");
        return true;
    }
    if (!zcl_devloop_plan_add_closure(ctx->root, files, e->file_count, plan))
        return false;
    const char *reason = "";
    *refused = !zcl_devloop_plan_proof_admissible(plan, &reason);
    if (*refused)
        (void)snprintf(reason_out, reason_cap, "%s", reason ? reason : "");
    return true;
}

static bool shadow_select(const struct zcl_shadow_eval_ctx *ctx,
                          const struct zcl_shadow_entry *e,
                          const struct zcl_devloop_plan *plan, bool refused,
                          struct shadow_marks *m,
                          struct zcl_shadow_proof_graph *g)
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
    if (refused || plan->closure_universal) return true;
    return shadow_mark_tokens(plan->path_groups, plan->path_groups_len,
                              m->floor) &&
           shadow_mark_edges(plan, e->component, m) &&
           shadow_mark_explained(ctx->root, e, plan, m, g);
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
    bool ok = shadow_marks_init(&m) &&
              shadow_plan(ctx, e, plan, &refused, out->selector_reason,
                          sizeof(out->selector_reason)) &&
              shadow_select(ctx, e, plan, refused, &m, &out->graph) &&
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
    shadow_predict(&p, &m, rule_ok, out);
    uint32_t reused = out->groups_reference > out->predicted_groups
                          ? out->groups_reference - out->predicted_groups : 0;
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
