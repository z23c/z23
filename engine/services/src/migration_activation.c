/* purpose: Resolve migration sets from qualified branch-local signals. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/migration_activation.h"
#include <limits.h>
#include <string.h>

static bool valid_rule_edges(const struct migration_activation_rule *const by_id[64],
                             uint64_t all, uint64_t prior)
{
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
    return true;
}

static bool rules_acyclic(const struct migration_activation_rule *const by_id[64], uint64_t all)
{
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
    return remaining == 0;
}

static bool validate_rules(const struct migration_activation_rule *rules, size_t count,
                           uint64_t prior, uint64_t *all_out)
{
    if (count > 64 || (count && !rules)) return false;
    const struct migration_activation_rule *by_id[64] = {0};
    uint64_t all = 0;
    for (size_t i = 0; i < count; ++i) {
        unsigned id = rules[i].id;
        if (id >= 64 || by_id[id]) return false;
        by_id[id] = &rules[i];
        all |= UINT64_C(1) << id;
    }
    if (!valid_rule_edges(by_id, all, prior) || !rules_acyclic(by_id, all)) return false;
    *all_out = all;
    return true;
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

static struct zcl_result select_qualified(
    const struct migration_activation_proposal *proposals, size_t np,
    const struct migration_activation_qualified *qualified, size_t nq,
    int32_t height, bool selected[256])
{
    for (size_t i = 0; i < nq; ++i) {
        if (qualified[i].height < 1)
            return ZCL_ERR(MIGRATION_ACTIVATION_INVALID, "qualified revision has invalid height");
        for (size_t j = 0; j < i; ++j)
            if (!memcmp(qualified[i].revision, qualified[j].revision, 32))
                return ZCL_ERR(MIGRATION_ACTIVATION_INVALID, "duplicate qualified revision");
        if (qualified[i].height != height) continue;
        size_t j = 0;
        while (j < np && memcmp(qualified[i].revision, proposals[j].revision, 32)) ++j;
        if (j == np)
            return ZCL_ERR(MIGRATION_ACTIVATION_UNKNOWN_REVISION, "qualified revision has no local migration mapping");
        selected[j] = true;
    }
    return ZCL_OK;
}

struct zcl_result migration_activation_resolve(
    const struct migration_activation_rule *rules, size_t nr,
    const struct migration_activation_proposal *proposals, size_t np,
    uint64_t prior, uint64_t consented_migrations,
    const struct migration_activation_qualified *qualified, size_t nq,
    int32_t height, uint64_t *out)
{
    uint64_t all;
    if (!out || height < 1 || nq > 256 || (nq && !qualified) ||
        !validate_rules(rules, nr, prior, &all) ||
        !validate_proposals(proposals, np, rules, nr, all))
        return ZCL_ERR(MIGRATION_ACTIVATION_INVALID, "invalid migration rules, proposals, or request");
    bool selected[256] = {0};
    struct zcl_result choice = select_qualified(proposals, np, qualified, nq, height, selected);
    if (!choice.ok) return choice;
    prune_conflicts(rules, nr, proposals, np, prior, selected);
    prune_dependencies(rules, nr, proposals, np, prior, selected);
    uint64_t result = selected_members(proposals, np, selected, prior);
    if ((result & ~prior) & ~consented_migrations)
        return ZCL_ERR(MIGRATION_ACTIVATION_NO_CONSENT, "local consent missing for resolved migrations");
    *out = result;
    return ZCL_OK;
}

static bool tally_matches(const struct miner_signal_tally *tally,
                          const struct miner_signal_catalog *catalog, size_t slot,
                          const struct miner_signal_schedule *expected,
                          int32_t parent_height, const struct uint256 *parent_hash,
                          int64_t observed)
{
    const struct miner_signal_schedule *s = &tally->schedule;
    return s->start == expected->start && s->window == expected->window &&
        s->activation == catalog->entries[slot].activation && s->slots == catalog->count &&
        s->slot == slot && !memcmp(s->catalog, expected->catalog, 32) &&
        tally->parent_height == parent_height && uint256_eq(&tally->parent_hash, parent_hash) &&
        tally->votes >= 0 && tally->votes <= observed;
}

static bool collect_qualified(const struct miner_signal_catalog *catalog,
    const struct miner_signal_tally *tallies, const struct miner_signal_schedule *expected,
    int32_t parent_height, const struct uint256 *parent_hash,
    struct migration_activation_qualified qualified[256], size_t *count)
{
    int64_t observed = (int64_t)parent_height - expected->start + 1;
    if (observed > expected->window) observed = expected->window;
    int32_t candidate = parent_height + 1;
    *count = 0;
    for (size_t i = 0; i < catalog->count; ++i) {
        const struct miner_signal_tally *tally = &tallies[i];
        if (!tally_matches(tally, catalog, i, expected, parent_height, parent_hash, observed)) return false;
        enum miner_signal_phase phase;
        if (!miner_signal_phase_at(tally, candidate, &phase).ok) return false;
        if (phase == MINER_SIGNAL_ACTIVE && tally->schedule.activation == candidate) {
            memcpy(qualified[*count].revision, catalog->entries[i].rule_revision, 32);
            qualified[(*count)++].height = candidate;
        }
    }
    return true;
}

struct zcl_result migration_activation_next_from_parent(
    const struct miner_signal_catalog *catalog,
    const struct miner_signal_tally *tallies, size_t tally_count,
    int32_t parent_height, const struct uint256 *parent_hash,
    const struct migration_activation_rule *rules, size_t rule_count,
    const struct migration_activation_proposal *proposals, size_t proposal_count,
    uint64_t prior, uint64_t consented_migrations, uint64_t *active)
{
    if (!catalog || !tallies || !parent_hash || !active ||
        parent_height == INT32_MAX || tally_count != catalog->count)
        return ZCL_ERR(MIGRATION_ACTIVATION_INVALID, "invalid migration activation input or parent tally");
    struct miner_signal_schedule expected;
    if (!miner_signal_catalog_select(catalog, 0, &expected).ok ||
        parent_height < expected.start - 1)
        return ZCL_ERR(MIGRATION_ACTIVATION_INVALID, "invalid migration activation input or parent tally");
    struct migration_activation_qualified qualified[256];
    size_t qualified_count;
    if (!collect_qualified(catalog, tallies, &expected, parent_height, parent_hash,
                           qualified, &qualified_count))
        return ZCL_ERR(MIGRATION_ACTIVATION_INVALID, "invalid or mismatched parent tally");
    return migration_activation_resolve(rules, rule_count, proposals, proposal_count,
                                        prior, consented_migrations, qualified,
                                        qualified_count, parent_height + 1, active);
}
