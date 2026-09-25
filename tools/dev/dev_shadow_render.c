/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Render shadow-selection results as flat key=value report lines
 * with per-set totals and the lookup-key gaps behind broad invalidation. */

#include "dev_shadow_select.h"

#include "base/hex.h"

#include <string.h>

static void shadow_root16(const uint8_t root[ZCL_SHADOW_ROOT_BYTES],
                          char out[17])
{
    char full[2 * ZCL_SHADOW_ROOT_BYTES + 1];
    zcl_hex_encode(root, ZCL_SHADOW_ROOT_BYTES, full);
    memcpy(out, full, 16);
    out[16] = '\0';
}

static void shadow_fields_text(uint32_t bits, char *out, size_t cap)
{
    size_t pos = 0;
    out[0] = '\0';
    for (unsigned f = 0; f < ZCL_SHADOW_FIELD__COUNT; f++) {
        if (!(bits & (1u << f))) continue;
        int n = snprintf(out + pos, cap - pos, "%s%s", pos ? "," : "",
                         zcl_shadow_field_name((enum zcl_shadow_field)f));
        if (n <= 0 || (size_t)n >= cap - pos) break;
        pos += (size_t)n;
    }
    if (pos == 0) (void)snprintf(out, cap, "-");
}

static const char *shadow_divergence(const struct zcl_shadow_result *r)
{
    uint32_t f = r->premise_fields;
    if (f & ((1u << ZCL_SHADOW_FIELD_FLAGS) | (1u << ZCL_SHADOW_FIELD_HARNESS)))
        return "global";
    if (f & ((1u << ZCL_SHADOW_FIELD_NEGATIVE_LOOKUPS) |
             (1u << ZCL_SHADOW_FIELD_GENERATED_INPUTS)))
        return "premise-outside-depfile";
    if (r->premise_groups < r->groups_selected)
        return "build-wider-than-premise";
    return "aligned";
}

static bool shadow_render_main(FILE *out, const struct zcl_shadow_result *r)
{
    char before[17], after[17];
    shadow_root16(r->patch.contract_before, before);
    shadow_root16(r->patch.contract_after, after);
    uint32_t reused = r->groups_reference > r->groups_selected
                          ? r->groups_reference - r->groups_selected : 0;
    return fprintf(out,
        "SHADOW id=%s kind=%s component=%s contract_root_before=%s "
        "contract_root_after=%s contract_change=%s "
        "build_actions_invalidated=%u/%u proof_obligations_invalidated=%u/%u "
        "proofs_reused=%u proofs_fresh=%u integration_edges_rerun=%u/%u "
        "fresh_cost_ms=%llu reference_cost_ms=%llu fallback_reason=%s "
        "lint_gates=%u/%u test_groups=%u/%u mandatory_independent=%u "
        "rule_reusable=%u rule_cost_ms=%llu validation_cost_us=%llu "
        "selector=%s bytes=%s build_graph=%s unweighted=%u\n",
        r->id, zcl_shadow_kind_name(r->kind), r->component, before, after,
        zcl_shadow_contract_change_name(r->patch.contract_change),
        r->build_invalidated, r->build_total,
        r->groups_selected + r->lint_selected,
        r->groups_reference + r->lint_reference, reused,
        r->groups_selected + r->lint_selected, r->edges_selected,
        r->edges_reference, (unsigned long long)r->fresh_cost_ms,
        (unsigned long long)r->reference_cost_ms,
        zcl_shadow_fallback_name(r->fallback), r->lint_selected,
        r->lint_reference, r->groups_selected, r->groups_reference,
        r->floor_groups + r->lint_selected, r->rule_reusable,
        (unsigned long long)r->rule_cost_ms,
        (unsigned long long)r->validation_cost_us,
        r->selector_universal ? "universal" : "exact",
        r->bytes_verified ? "verified" : "MISMATCH",
        r->build_known ? "complete" : "partial", r->unweighted) > 0;
}

bool zcl_shadow_render_entry(FILE *out, const struct zcl_shadow_result *r)
{
    if (!out || !r || !shadow_render_main(out, r)) return false;
    char fields[256], gaps[256];
    shadow_fields_text(r->premise_fields, fields, sizeof(fields));
    shadow_fields_text(r->key_gap_fields, gaps, sizeof(gaps));
    return fprintf(out,
        "SHADOW-PREMISE id=%s build_deps_tus=%u private_readers=%u "
        "premise_fields=%s premise_groups=%u selected_groups=%u "
        "floor_groups=%u divergence=%s missing_key_inputs=%s\n",
        r->id, r->build_invalidated, r->private_readers, fields,
        r->premise_groups, r->groups_selected, r->floor_groups,
        shadow_divergence(r), gaps) > 0;
}

struct shadow_totals {
    size_t entries;
    uint64_t fresh_ms, reference_ms, rule_ms, validation_us;
    uint64_t groups_selected, groups_reference;
    size_t fallbacks[ZCL_SHADOW_FALLBACK__COUNT];
};

static void shadow_totals_add(struct shadow_totals *t,
                              const struct zcl_shadow_result *r)
{
    t->entries++;
    t->fresh_ms += r->fresh_cost_ms;
    t->reference_ms += r->reference_cost_ms;
    t->rule_ms += r->rule_cost_ms;
    t->validation_us += r->validation_cost_us;
    t->groups_selected += r->groups_selected;
    t->groups_reference += r->groups_reference;
    if ((unsigned)r->fallback < ZCL_SHADOW_FALLBACK__COUNT)
        t->fallbacks[r->fallback]++;
}

static bool shadow_render_set(FILE *out, const char *name,
                              const struct shadow_totals *t)
{
    if (t->entries == 0) return true;
    double n = (double)t->entries;
    return fprintf(out,
        "SHADOW-TOTALS set=%s entries=%zu "
        "fresh_worker_s_per_candidate_selected=%.1f "
        "fresh_worker_s_per_candidate_reference=%.1f "
        "fresh_worker_s_per_candidate_rule=%.1f "
        "validation_s_per_candidate=%.4f groups_per_candidate_selected=%.1f "
        "groups_per_candidate_reference=%.1f fallback_none=%zu "
        "fallback_unknown_scope=%zu fallback_policy=%zu "
        "fallback_conflict=%zu fallback_dependency_change=%zu\n",
        name, t->entries, (double)t->fresh_ms / 1000.0 / n,
        (double)t->reference_ms / 1000.0 / n, (double)t->rule_ms / 1000.0 / n,
        (double)t->validation_us / 1e6 / n, (double)t->groups_selected / n,
        (double)t->groups_reference / n,
        t->fallbacks[ZCL_SHADOW_FALLBACK_NONE],
        t->fallbacks[ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE],
        t->fallbacks[ZCL_SHADOW_FALLBACK_POLICY],
        t->fallbacks[ZCL_SHADOW_FALLBACK_CONFLICT],
        t->fallbacks[ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE]) > 0;
}

static uint64_t shadow_avoidable(const struct zcl_shadow_result *r)
{
    return r->fresh_cost_ms > r->rule_cost_ms
               ? r->fresh_cost_ms - r->rule_cost_ms : 0;
}

static uint64_t shadow_broad(const struct zcl_shadow_result *r)
{
    return r->reference_cost_ms > r->rule_cost_ms
               ? r->reference_cost_ms - r->rule_cost_ms : 0;
}

static bool shadow_render_avoidable(FILE *out,
                                    const struct zcl_shadow_result *rows,
                                    size_t count)
{
    size_t best = SIZE_MAX;
    for (size_t i = 0; i < count; i++)
        if (best == SIZE_MAX ||
            shadow_avoidable(&rows[i]) > shadow_avoidable(&rows[best]))
            best = i;
    if (best == SIZE_MAX) return true;
    return fprintf(out,
        "SHADOW-AVOIDABLE id=%s avoidable_ms=%llu reusable_groups=%u "
        "selected_groups=%u floor_groups=%u\n",
        rows[best].id, (unsigned long long)shadow_avoidable(&rows[best]),
        rows[best].rule_reusable, rows[best].groups_selected,
        rows[best].floor_groups) > 0;
}

/* Which absent lookup-key inputs account for the broad invalidation: for each
 * field, the entries whose premises moved it and the reference cost above
 * what the rule would still have run. Printed largest first. */
static bool shadow_render_key_gaps(FILE *out,
                                   const struct zcl_shadow_result *rows,
                                   size_t count)
{
    uint64_t cost[ZCL_SHADOW_FIELD__COUNT] = {0};
    uint32_t hits[ZCL_SHADOW_FIELD__COUNT] = {0};
    for (size_t i = 0; i < count; i++)
        for (unsigned f = 0; f < ZCL_SHADOW_FIELD__COUNT; f++)
            if (rows[i].key_gap_fields & (1u << f)) {
                hits[f]++;
                cost[f] += shadow_broad(&rows[i]);
            }
    bool done[ZCL_SHADOW_FIELD__COUNT] = {false};
    for (unsigned round = 0; round < ZCL_SHADOW_FIELD__COUNT; round++) {
        unsigned best = ZCL_SHADOW_FIELD__COUNT;
        for (unsigned f = 0; f < ZCL_SHADOW_FIELD__COUNT; f++)
            if (!done[f] && hits[f] &&
                (best == ZCL_SHADOW_FIELD__COUNT || cost[f] > cost[best]))
                best = f;
        if (best == ZCL_SHADOW_FIELD__COUNT) break;
        done[best] = true;
        if (fprintf(out,
                    "SHADOW-KEYGAP field=%s entries=%u "
                    "broad_invalidation_ms=%llu\n",
                    zcl_shadow_field_name((enum zcl_shadow_field)best),
                    hits[best], (unsigned long long)cost[best]) <= 0)
            return false;
    }
    return true;
}

bool zcl_shadow_render_totals(FILE *out, const struct zcl_shadow_result *rows,
                              size_t count)
{
    if (!out || (count > 0 && !rows)) return false;
    struct shadow_totals all = {0}, real = {0}, synthetic = {0};
    for (size_t i = 0; i < count; i++) {
        shadow_totals_add(&all, &rows[i]);
        shadow_totals_add(rows[i].kind == ZCL_SHADOW_KIND_REAL ? &real
                                                               : &synthetic,
                          &rows[i]);
    }
    return shadow_render_set(out, "real", &real) &&
           shadow_render_set(out, "synthetic", &synthetic) &&
           shadow_render_set(out, "all", &all) &&
           shadow_render_avoidable(out, rows, count) &&
           shadow_render_key_gaps(out, rows, count);
}
