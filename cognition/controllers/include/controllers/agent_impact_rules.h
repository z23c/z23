/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_IMPACT_RULES_H
#define ZCL_CONTROLLERS_AGENT_IMPACT_RULES_H

#include <stdbool.h>
#include <stddef.h>

#define ZCL_AGENT_IMPACT_MAX_GROUPS 64
#define ZCL_AGENT_IMPACT_GROUP_MAX 64

struct agent_impact_acc {
    const char *groups[ZCL_AGENT_IMPACT_MAX_GROUPS];
    char group_storage[ZCL_AGENT_IMPACT_MAX_GROUPS][ZCL_AGENT_IMPACT_GROUP_MAX];
    size_t groups_len;
    size_t shared_rule_hits;
    bool code_changed;
    bool docs_only;
    bool consensus_risk;
    bool agent_api_changed;
    bool groups_lost; /* Sticky loss of a unique or overlong token. */
};

/* Zero-initialize acc. NULL/empty inputs and duplicates are no-ops. A full
 * accumulator or token >= GROUP_MAX sets groups_lost, retaining stored groups
 * and their order. Later additions never clear loss; this is not admission. */
void agent_impact_add_group(struct agent_impact_acc *acc, const char *group);
/* Same loss contract; space, tab and comma delimit tokens. Continues after
 * rejected tokens. NULL inputs are no-ops. */
void agent_impact_add_group_list(struct agent_impact_acc *acc, const char *groups);
bool agent_impact_path_is_direct_development_contract(const char *path);
bool agent_impact_apply_shared_rules(const char *path,
                                     struct agent_impact_acc *acc);
size_t agent_impact_rule_count(void);

#endif
