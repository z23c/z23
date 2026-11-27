/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/migration_activation.h"
#include <string.h>

static bool validate_rules(const struct migration_activation_rule *rules, size_t count,
                           uint64_t prior, uint64_t *all_out)
{
    if (!rules || !count || count > 64) return false;
    const struct migration_activation_rule *by_id[64] = {0};
    uint64_t all = 0;
    for (size_t i = 0; i < count; ++i) {
        unsigned id = rules[i].id;
        if (id >= 64 || by_id[id]) return false;
        by_id[id] = &rules[i];
        all |= UINT64_C(1) << id;
    }
    if (prior & ~all) return false;
    for (unsigned i = 0; i < 64; ++i) {
        const struct migration_activation_rule *rule = by_id[i];
        if (!rule) continue;
        uint64_t bit = UINT64_C(1) << i;
        if ((rule->requires | rule->conflicts) & (~all | bit)) return false;
        if ((prior & bit) && ((rule->requires & ~prior) || (rule->conflicts & prior))) return false;
        for (unsigned j = 0; j < 64; ++j) {
            if (!by_id[j]) continue;
            bool forward = (rule->conflicts & (UINT64_C(1) << j)) != 0;
            bool reverse = (by_id[j]->conflicts & bit) != 0;
            if (forward != reverse) return false;
        }
    }
    uint64_t remaining = all;
    for (;;) {
        uint64_t remove = 0;
        for (unsigned i = 0; i < 64; ++i) {
            uint64_t bit = UINT64_C(1) << i;
            if (by_id[i] && (remaining & bit) && !(by_id[i]->requires & remaining))
                remove |= bit;
        }
        if (!remove) break;
        remaining &= ~remove;
    }
    *all_out = all;
    return remaining == 0;
}

static bool bundle_conflicts(uint64_t members, uint64_t against,
                             const struct migration_activation_rule *rules, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        uint64_t bit = UINT64_C(1) << rules[i].id;
        if ((members & bit) && (rules[i].conflicts & against)) return true;
    }
    return false;
}

static bool bundle_missing_dependency(uint64_t members, uint64_t available,
                                      const struct migration_activation_rule *rules, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        uint64_t bit = UINT64_C(1) << rules[i].id;
        if ((members & bit) && (rules[i].requires & ~available)) return true;
    }
    return false;
}

static bool validate_proposals(const struct migration_activation_proposal *proposals,
                               size_t count, const struct migration_activation_rule *rules,
                               size_t rule_count, uint64_t all)
{
    if (count > 256 || (count && !proposals)) return false;
    for (size_t i = 0; i < count; ++i) {
        if (!proposals[i].members || (proposals[i].members & ~all) ||
            bundle_conflicts(proposals[i].members, proposals[i].members, rules, rule_count)) return false;
        for (size_t j = 0; j < i; ++j)
            if (!memcmp(proposals[i].revision, proposals[j].revision, 32)) return false;
    }
    return true;
}

static uint64_t selected_members(const struct migration_activation_proposal *proposals,
                                 size_t count, const bool selected[256], uint64_t prior)
{
    uint64_t result = prior;
    for (size_t i = 0; i < count; ++i)
        if (selected[i]) result |= proposals[i].members;
    return result;
}

static void prune_conflicts(const struct migration_activation_rule *rules, size_t rule_count,
                            const struct migration_activation_proposal *proposals, size_t count,
                            uint64_t prior, bool selected[256])
{
    for (size_t i = 0; i < count; ++i)
        if (selected[i] && bundle_conflicts(proposals[i].members, prior, rules, rule_count))
            selected[i] = false;
    uint64_t eligible = selected_members(proposals, count, selected, 0);
    bool drop[256] = {0};
    for (size_t i = 0; i < count; ++i)
        if (selected[i] && bundle_conflicts(proposals[i].members, eligible, rules, rule_count))
            drop[i] = true;
    for (size_t i = 0; i < count; ++i)
        if (drop[i]) selected[i] = false;
}

static void prune_dependencies(const struct migration_activation_rule *rules, size_t rule_count,
                               const struct migration_activation_proposal *proposals, size_t count,
                               uint64_t prior, bool selected[256])
{
    for (;;) {
        uint64_t available = selected_members(proposals, count, selected, prior);
        bool drop[256] = {0}, changed = false;
        for (size_t i = 0; i < count; ++i)
            if (selected[i] && bundle_missing_dependency(proposals[i].members, available, rules, rule_count))
                drop[i] = true;
        for (size_t i = 0; i < count; ++i) {
            if (drop[i]) { selected[i] = false; changed = true; }
        }
        if (!changed) return;
    }
}

enum migration_activation_result migration_activation_resolve(
    const struct migration_activation_rule *rules, size_t nr,
    const struct migration_activation_proposal *proposals, size_t np,
    uint64_t prior, uint64_t consented_migrations,
    const struct migration_activation_qualified *qualified, size_t nq,
    int32_t height, uint64_t *out)
{
    uint64_t all;
    if (!out || height < 1 || nq > 256 || (nq && !qualified) ||
        !validate_rules(rules, nr, prior, &all) ||
        !validate_proposals(proposals, np, rules, nr, all)) return MIGRATION_ACTIVATION_INVALID;
    bool selected[256] = {0};
    for (size_t i = 0; i < nq; ++i) {
        if (qualified[i].height < 1) return MIGRATION_ACTIVATION_INVALID;
        for (size_t j = 0; j < i; ++j)
            if (!memcmp(qualified[i].revision, qualified[j].revision, 32)) return MIGRATION_ACTIVATION_INVALID;
        if (qualified[i].height != height) continue;
        size_t j = 0;
        while (j < np && memcmp(qualified[i].revision, proposals[j].revision, 32)) ++j;
        if (j == np) return MIGRATION_ACTIVATION_UNKNOWN_REVISION;
        selected[j] = true;
    }
    prune_conflicts(rules, nr, proposals, np, prior, selected);
    prune_dependencies(rules, nr, proposals, np, prior, selected);
    uint64_t result = selected_members(proposals, np, selected, prior);
    if ((result & ~prior) & ~consented_migrations) return MIGRATION_ACTIVATION_NO_CONSENT;
    *out = result;
    return MIGRATION_ACTIVATION_OK;
}
