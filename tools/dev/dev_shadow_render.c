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

static double shadow_pct(uint64_t part, uint64_t whole)
{
    return whole ? 100.0 * (double)part / (double)whole : 0.0;
}

static uint32_t shadow_rule_fresh(const struct zcl_shadow_result *r)
{
    return r->predicted_groups + r->lint_selected;
}

static bool shadow_render_main(FILE *out, const struct zcl_shadow_result *r)
{
    char before[17], after[17];
    shadow_root16(r->patch.contract_before, before);
    shadow_root16(r->patch.contract_after, after);
    uint32_t total = r->groups_reference + r->lint_reference;
    uint32_t fresh = shadow_rule_fresh(r);
    uint64_t carried = r->reference_cost_ms > r->rule_cost_ms
                           ? r->reference_cost_ms - r->rule_cost_ms : 0;
    return fprintf(out,
        "SHADOW id=%s kind=%s component=%s contract_root_before=%s "
        "contract_root_after=%s contract_change=%s "
        "build_actions_invalidated=%u/%u proof_obligations_invalidated=%u/%u "
        "proofs_reused=%u proofs_fresh=%u integration_edges_rerun=%u/%u "
        "fresh_cost_ms=%llu reference_cost_ms=%llu savings_pct=%.1f "
        "eligible_fresh_cost_ms=%llu critical_path_ms=%u/%u "
        "fallback_reason=%s predict=%s selector_obligations=%u/%u "
        "selector_cost_ms=%llu lint_gates=%u/%u lint_cost_ms=%llu "
        "mandatory_independent=%u validation_cost_us=%llu selector=%s "
        "bytes=%s build_graph=%s unweighted=%u selector_reason=%s\n",
        r->id, zcl_shadow_kind_name(r->kind), r->component, before, after,
        zcl_shadow_contract_change_name(r->patch.contract_change),
        r->build_invalidated, r->build_total, fresh, total, total - fresh,
        fresh, r->graph.predicted[ZCL_SHADOW_LAYER_INTEGRATION],
        r->graph.nodes[ZCL_SHADOW_LAYER_INTEGRATION],
        (unsigned long long)r->rule_cost_ms,
        (unsigned long long)r->reference_cost_ms,
        shadow_pct(carried, r->reference_cost_ms),
        (unsigned long long)r->eligible_cost_ms, r->critical_rule_ms,
        r->critical_reference_ms,
        zcl_shadow_fallback_name(r->fallback),
        r->predict_mode == ZCL_SHADOW_PREDICT_ALL ? "all" : "exact",
        r->groups_selected + r->lint_selected, total,
        (unsigned long long)r->fresh_cost_ms, r->lint_selected,
        r->lint_reference, (unsigned long long)r->lint_cost_ms,
        r->graph.predicted[ZCL_SHADOW_LAYER_CONTRACT] + r->lint_selected,
        (unsigned long long)r->validation_cost_us,
        r->selector_universal ? "universal" : "exact",
        r->bytes_verified ? "verified" : "MISMATCH",
        r->build_known ? "complete" : "partial", r->unweighted,
        r->selector_reason[0] ? r->selector_reason : "-") > 0;
}

bool zcl_shadow_render_graph(FILE *out, const struct zcl_shadow_result *r)
{
    if (!out || !r) return false;
    const struct zcl_shadow_proof_graph *g = &r->graph;
    char after[17];
    shadow_root16(r->patch.contract_after, after);
    return fprintf(out,
        "SHADOW-GRAPH id=%s contract=%s@%s change=%s "
        "contract_nodes=%u contract_ms=%llu contract_fresh=%u "
        "caller_nodes=%u caller_ms=%llu caller_fresh=%u "
        "integration_nodes=%u integration_ms=%llu integration_fresh=%u "
        "caller_hops=%u name_only_hops=%u name_only_groups=%u "
        "name_only_ms=%llu\n",
        r->id, r->component, after,
        zcl_shadow_contract_change_name(r->patch.contract_change),
        g->nodes[ZCL_SHADOW_LAYER_CONTRACT],
        (unsigned long long)g->ms[ZCL_SHADOW_LAYER_CONTRACT],
        g->predicted[ZCL_SHADOW_LAYER_CONTRACT],
        g->nodes[ZCL_SHADOW_LAYER_CALLER],
        (unsigned long long)g->ms[ZCL_SHADOW_LAYER_CALLER],
        g->predicted[ZCL_SHADOW_LAYER_CALLER],
        g->nodes[ZCL_SHADOW_LAYER_INTEGRATION],
        (unsigned long long)g->ms[ZCL_SHADOW_LAYER_INTEGRATION],
        g->predicted[ZCL_SHADOW_LAYER_INTEGRATION], g->caller_hops,
        g->collision_hops, g->collision_groups,
        (unsigned long long)g->collision_ms) > 0;
}

bool zcl_shadow_render_entry(FILE *out, const struct zcl_shadow_result *r)
{
    if (!out || !r || !shadow_render_main(out, r)) return false;
    char fields[256], gaps[256];
    shadow_fields_text(r->premise_fields, fields, sizeof(fields));
    shadow_fields_text(r->key_gap_fields, gaps, sizeof(gaps));
    if (!zcl_shadow_render_graph(out, r) || !zcl_shadow_render_fresh(out, r))
        return false;
    return fprintf(out,
        "SHADOW-PREMISE id=%s build_deps_tus=%u private_readers=%u "
        "premise_fields=%s premise_groups=%u selected_groups=%u "
        "floor_groups=%u divergence=%s missing_key_inputs=%s\n",
        r->id, r->build_invalidated, r->private_readers, fields,
        r->premise_groups, r->groups_selected, r->floor_groups,
        shadow_divergence(r), gaps) > 0;
}

/* Where the reuse-enabled bill still goes, by obligation class. */
enum shadow_block {
    SHADOW_BLOCK_LINT = 0,        /* every lint gate, every candidate */
    SHADOW_BLOCK_CONTRACT,        /* the changed unit's own obligations */
    SHADOW_BLOCK_MOVED,           /* contract moved or private reader */
    SHADOW_BLOCK_FALLBACK,        /* a fallback reran the reference */
    SHADOW_BLOCK__COUNT
};

static const char *const shadow_block_names[SHADOW_BLOCK__COUNT] = {
    "lint_gates", "contract_layer", "contract_moved_or_private_reader",
    "fallback_reference",
};

struct shadow_totals {
    size_t entries;
    uint64_t fresh_ms, reference_ms, rule_ms, validation_us, lint_ms;
    uint64_t eligible_ms, critical_rule_ms, critical_reference_ms;
    uint64_t eligible_groups;
    uint64_t groups_selected, groups_reference, groups_predicted;
    uint64_t obligations_fresh, obligations_total;
    uint64_t name_only_ms, name_only_groups;
    uint64_t block_ms[SHADOW_BLOCK__COUNT];
    size_t fallbacks[ZCL_SHADOW_FALLBACK__COUNT];
};

static enum shadow_block shadow_block_of(const struct zcl_shadow_result *r)
{
    if (r->predict_mode == ZCL_SHADOW_PREDICT_ALL) return SHADOW_BLOCK_FALLBACK;
    return r->rule_reusable > 0 || r->groups_selected == r->floor_groups
               ? SHADOW_BLOCK_CONTRACT : SHADOW_BLOCK_MOVED;
}

static void shadow_totals_add(struct shadow_totals *t,
                              const struct zcl_shadow_result *r)
{
    t->entries++;
    t->fresh_ms += r->fresh_cost_ms;
    t->reference_ms += r->reference_cost_ms;
    t->rule_ms += r->rule_cost_ms;
    t->lint_ms += r->lint_cost_ms;
    t->eligible_ms += r->eligible_cost_ms;
    t->critical_rule_ms += r->critical_rule_ms;
    t->critical_reference_ms += r->critical_reference_ms;
    t->eligible_groups += r->eligible_groups;
    t->validation_us += r->validation_cost_us;
    t->groups_selected += r->groups_selected;
    t->groups_reference += r->groups_reference;
    t->groups_predicted += r->predicted_groups;
    t->obligations_fresh += shadow_rule_fresh(r);
    t->obligations_total += r->groups_reference + r->lint_reference;
    t->name_only_ms += r->graph.collision_ms;
    t->name_only_groups += r->graph.collision_groups;
    t->block_ms[SHADOW_BLOCK_LINT] += r->lint_cost_ms;
    t->block_ms[shadow_block_of(r)] += r->rule_cost_ms - r->lint_cost_ms;
    if ((unsigned)r->fallback < ZCL_SHADOW_FALLBACK__COUNT)
        t->fallbacks[r->fallback]++;
}

static bool shadow_render_set(FILE *out, const char *name,
                              const struct shadow_totals *t)
{
    if (t->entries == 0) return true;
    double n = (double)t->entries;
    uint64_t carried = t->reference_ms > t->rule_ms
                           ? t->reference_ms - t->rule_ms : 0;
    uint64_t sel_carried = t->reference_ms > t->fresh_ms
                               ? t->reference_ms - t->fresh_ms : 0;
    return fprintf(out,
        "SHADOW-TOTALS set=%s entries=%zu "
        "fresh_obligations=%llu/%llu "
        "fresh_worker_s_per_candidate_selected=%.1f "
        "fresh_worker_s_per_candidate_reference=%.1f "
        "fresh_worker_s_per_candidate_rule=%.1f "
        "savings_pct_rule=%.1f savings_pct_selected=%.1f "
        "fresh_worker_s_per_candidate_eligible_now=%.1f "
        "eligible_reused_groups=%llu "
        "critical_path_s_per_candidate_rule=%.1f "
        "critical_path_s_per_candidate_reference=%.1f lint_s_per_candidate=%.1f "
        "validation_s_per_candidate=%.4f groups_per_candidate_selected=%.1f "
        "groups_per_candidate_rule=%.1f groups_per_candidate_reference=%.1f "
        "name_only_groups=%llu name_only_s=%.1f fallback_none=%zu "
        "fallback_unknown_scope=%zu fallback_policy=%zu "
        "fallback_conflict=%zu fallback_dependency_change=%zu\n",
        name, t->entries, (unsigned long long)t->obligations_fresh,
        (unsigned long long)t->obligations_total,
        (double)t->fresh_ms / 1000.0 / n, (double)t->reference_ms / 1000.0 / n,
        (double)t->rule_ms / 1000.0 / n, shadow_pct(carried, t->reference_ms),
        shadow_pct(sel_carried, t->reference_ms),
        (double)t->eligible_ms / 1000.0 / n,
        (unsigned long long)t->eligible_groups,
        (double)t->critical_rule_ms / 1000.0 / n,
        (double)t->critical_reference_ms / 1000.0 / n,
        (double)t->lint_ms / 1000.0 / n, (double)t->validation_us / 1e6 / n,
        (double)t->groups_selected / n, (double)t->groups_predicted / n,
        (double)t->groups_reference / n,
        (unsigned long long)t->name_only_groups,
        (double)t->name_only_ms / 1000.0,
        t->fallbacks[ZCL_SHADOW_FALLBACK_NONE],
        t->fallbacks[ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE],
        t->fallbacks[ZCL_SHADOW_FALLBACK_POLICY],
        t->fallbacks[ZCL_SHADOW_FALLBACK_CONFLICT],
        t->fallbacks[ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE]) > 0;
}

/* The obligation classes still billed fresh, largest first. */
static bool shadow_render_blockers(FILE *out, const char *name,
                                   const struct shadow_totals *t)
{
    bool done[SHADOW_BLOCK__COUNT] = {false};
    for (unsigned round = 0; t->entries && round < SHADOW_BLOCK__COUNT;
         round++) {
        unsigned best = SHADOW_BLOCK__COUNT;
        for (unsigned b = 0; b < SHADOW_BLOCK__COUNT; b++)
            if (!done[b] && (best == SHADOW_BLOCK__COUNT ||
                             t->block_ms[b] > t->block_ms[best]))
                best = b;
        done[best] = true;
        if (fprintf(out,
                    "SHADOW-BLOCKER set=%s class=%s fresh_s=%.1f "
                    "share_of_reference_pct=%.1f\n",
                    name, shadow_block_names[best],
                    (double)t->block_ms[best] / 1000.0,
                    shadow_pct(t->block_ms[best], t->reference_ms)) <= 0)
            return false;
    }
    return true;
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
           shadow_render_blockers(out, "real", &real) &&
           shadow_render_blockers(out, "all", &all) &&
           shadow_render_avoidable(out, rows, count) &&
           shadow_render_key_gaps(out, rows, count);
}

static const char *shadow_layer_reason(const struct zcl_shadow_result *r,
                                       unsigned layer)
{
    if (layer == ZCL_SHADOW_LAYER_CONTRACT)
        return "contract_obligation_of_changed_unit";
    return r->rule_block[0] ? r->rule_block : "rule_refused";
}

static bool shadow_render_carried(FILE *out, const struct zcl_shadow_result *r)
{
    char reasons[512];
    size_t pos = 0;
    reasons[0] = '\0';
    for (unsigned e = 0; e < ZCL_SHADOW_ELIGIBILITY__COUNT; e++) {
        if (!r->carried_by_reason[e]) continue;
        int n = snprintf(reasons + pos, sizeof(reasons) - pos, "%s%s:%u",
                         pos ? "," : "",
                         zcl_shadow_eligibility_name(
                             (enum zcl_shadow_eligibility)e),
                         r->carried_by_reason[e]);
        if (n <= 0 || (size_t)n >= sizeof(reasons) - pos) break;
        pos += (size_t)n;
    }
    /* What would still refuse with a complete, matching key: provenance. */
    struct zcl_shadow_eligibility_claim keyed = {
        .sensitivity = ZCL_SHADOW_SENSITIVITY_IMAGE,
        .rule = ZCL_SHADOW_REUSE_ADMIT,
        .inputs_match = true,
        .source = ZCL_SHADOW_SOURCE_LOCAL_SAME_UID,
    };
    return fprintf(out,
        "SHADOW-CARRIED id=%s groups=%u eligible=%u reasons=%s "
        "with_complete_key=%s eligible_fresh_cost_ms=%llu "
        "rule_fresh_cost_ms=%llu\n",
        r->id, r->carried_groups, r->eligible_groups, pos ? reasons : "-",
        zcl_shadow_eligibility_name(zcl_shadow_reuse_eligible(&keyed)),
        (unsigned long long)r->eligible_cost_ms,
        (unsigned long long)r->rule_cost_ms) > 0;
}

bool zcl_shadow_render_fresh(FILE *out, const struct zcl_shadow_result *r)
{
    if (!out || !r) return false;
    if (fprintf(out,
                "SHADOW-FRESH id=%s obligations=lint_gates count=%u "
                "sensitivity=%s reason=changed_source_always_reruns\n",
                r->id, r->lint_selected,
                zcl_shadow_sensitivity_name(zcl_shadow_obligation_sensitivity(
                    ZCL_SHADOW_OBLIGATION_LINT_GATE))) <= 0)
        return false;
    if (r->predict_mode == ZCL_SHADOW_PREDICT_ALL) {
        if (fprintf(out,
                    "SHADOW-FRESH id=%s obligations=test_groups count=%u "
                    "sensitivity=image reason=fallback:%s groups=all\n",
                    r->id, r->predicted_groups,
                    zcl_shadow_fallback_name(r->fallback)) <= 0)
            return false;
        return shadow_render_carried(out, r);
    }
    for (unsigned layer = 0; layer < ZCL_SHADOW_LAYER__COUNT; layer++) {
        if (!r->graph.predicted[layer]) continue;
        if (fprintf(out,
                    "SHADOW-FRESH id=%s layer=%s count=%u sensitivity=image "
                    "reason=%s groups=%s\n",
                    r->id, zcl_shadow_layer_name((enum zcl_shadow_layer)layer),
                    r->graph.predicted[layer], shadow_layer_reason(r, layer),
                    r->fresh_layer_names[layer]) <= 0)
            return false;
    }
    return shadow_render_carried(out, r);
}
