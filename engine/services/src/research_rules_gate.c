/* purpose: Decide research validity from the candidate's parent branch. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/research_rules_gate.h"
#include "services/research_block_size.h"
#include <stdio.h>

static bool gate_missing_parent(const struct block *block, const struct block_index *parent)
{
    return block && !parent && !uint256_is_null(&block->header.hashPrevBlock);
}

struct research_gate_decision research_rules_gate_for(
    const struct research_rules_binding *binding, const struct chain_params *params,
    const struct block *block, const struct block_index *parent, const char *datadir)
{
    struct research_gate_decision d = { .verdict = RESEARCH_GATE_PASS };
    if (!binding) return d;
    if (gate_missing_parent(block, parent)) {
        d.verdict = RESEARCH_GATE_HOLD;
        d.rule = "research-rules-unavailable";
        snprintf(d.detail, sizeof d.detail, "%s", "research parent unavailable");
        return d;
    }
    struct zcl_result r = research_rules_for_index(binding, parent, datadir, &d.rules);
    if (!r.ok) {
        d.verdict = RESEARCH_GATE_HOLD;
        d.rule = "research-rules-unavailable";
        snprintf(d.detail, sizeof d.detail, "%s", r.message);
        return d;
    }
    enum research_block_size_verdict size = research_block_size_check_under(
        block, research_block_size_limit_for(params, &d.rules));
    if (size != RESEARCH_BLOCK_SIZE_OK) {
        d.verdict = size == RESEARCH_BLOCK_SIZE_EXCEEDED ? RESEARCH_GATE_REJECT : RESEARCH_GATE_HOLD;
        d.rule = size == RESEARCH_BLOCK_SIZE_EXCEEDED ? "research-block-size-limit" :
                                                        "research-rules-unavailable";
        snprintf(d.detail, sizeof d.detail, "%s", size == RESEARCH_BLOCK_SIZE_EXCEEDED ?
                 "research block size limit exceeded" : "research block size unavailable");
        return d;
    }
    if (d.rules.active[RESEARCH_RULE_DEPOSIT_FREEZE]) {
        d.offender = research_rules_deposit_violation(block);
        if (d.offender) {
            d.verdict = d.offender == SIZE_MAX ? RESEARCH_GATE_HOLD : RESEARCH_GATE_REJECT;
            d.rule = d.offender == SIZE_MAX ? "research-rules-unavailable" : "research-deposit-freeze";
            snprintf(d.detail, sizeof d.detail, "%s", d.offender == SIZE_MAX ?
                     "research block body unavailable" : "research deposit freeze");
            if (d.offender == SIZE_MAX) d.offender = 0;
        }
    }
    return d;
}

struct research_gate_decision research_rules_gate(
    const struct chain_params *params, const struct block *block,
    const struct block_index *parent, const char *datadir)
{
    return research_rules_gate_for(research_rules_binding(), params, block, parent, datadir);
}
