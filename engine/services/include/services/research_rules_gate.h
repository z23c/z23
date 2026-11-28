/* purpose: Decide research validity from the candidate's parent branch. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_RESEARCH_RULES_GATE_H
#define ZCL_SERVICES_RESEARCH_RULES_GATE_H

#include "services/research_rules.h"

enum research_gate_verdict { RESEARCH_GATE_PASS, RESEARCH_GATE_REJECT, RESEARCH_GATE_HOLD };
struct research_gate_decision {
    enum research_gate_verdict verdict;
    struct research_rules_state rules;
    const char *rule;
    char detail[ZCL_RESULT_MSG_MAX];
    size_t offender;
};
struct research_gate_decision research_rules_gate_for(
    const struct research_rules_binding *binding, const struct chain_params *params,
    const struct block *block, const struct block_index *parent, const char *datadir);
struct research_gate_decision research_rules_gate(
    const struct chain_params *params, const struct block *block,
    const struct block_index *parent, const char *datadir);
#endif
