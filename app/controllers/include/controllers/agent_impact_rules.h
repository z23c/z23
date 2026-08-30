/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_IMPACT_RULES_H
#define ZCL_CONTROLLERS_AGENT_IMPACT_RULES_H

#include <stdbool.h>
#include <stddef.h>

#define ZCL_AGENT_IMPACT_MAX_GROUPS 32
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
};

void agent_impact_add_group(struct agent_impact_acc *acc, const char *group);
bool agent_impact_apply_shared_rules(const char *path,
                                     struct agent_impact_acc *acc);
size_t agent_impact_rule_count(void);

#endif
