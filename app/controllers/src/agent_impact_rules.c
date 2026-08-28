/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_impact_rules.h"

#include <fnmatch.h>
#include <stdio.h>
#include <string.h>

void agent_impact_add_group(struct agent_impact_acc *acc, const char *group)
{
    if (!acc || !group || !group[0])
        return;
    for (size_t i = 0; i < acc->groups_len; i++) {
        if (strcmp(acc->groups[i], group) == 0)
            return;
    }
    if (acc->groups_len <
        sizeof(acc->groups) / sizeof(acc->groups[0])) {
        size_t i = acc->groups_len;
        snprintf(acc->group_storage[i], sizeof(acc->group_storage[i]),
                 "%s", group);
        acc->groups[i] = acc->group_storage[i];
        acc->groups_len++;
    }
}

static bool agent_impact_match_one_pattern(const char *path,
                                           const char *pattern,
                                           size_t len)
{
    if (!path || !pattern || len == 0)
        return false;

    char buf[256];
    if (len >= sizeof(buf))
        return false;
    memcpy(buf, pattern, len);
    buf[len] = 0;
    return fnmatch(buf, path, 0) == 0;
}

static bool agent_impact_match_any_pattern(const char *path,
                                           const char *patterns)
{
    if (!path || !path[0] || !patterns || !patterns[0])
        return false;

    const char *start = patterns;
    while (*start) {
        const char *bar = strchr(start, '|');
        size_t len = bar ? (size_t)(bar - start) : strlen(start);
        if (agent_impact_match_one_pattern(path, start, len))
            return true;
        if (!bar)
            break;
        start = bar + 1;
    }
    return false;
}

static void agent_impact_add_group_list(struct agent_impact_acc *acc,
                                        const char *groups)
{
    if (!acc || !groups)
        return;

    const char *p = groups;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != ',')
            p++;
        size_t len = (size_t)(p - start);
        char group[ZCL_AGENT_IMPACT_GROUP_MAX];
        if (len == 0 || len >= sizeof(group))
            continue;
        memcpy(group, start, len);
        group[len] = 0;
        agent_impact_add_group(acc, group);
    }
}

bool agent_impact_apply_shared_rules(const char *path,
                                     struct agent_impact_acc *acc)
{
    bool matched = false;

#define AGENT_IMPACT_RULE(patterns, groups) \
    do { \
        if (agent_impact_match_any_pattern(path, (patterns))) { \
            agent_impact_add_group_list((acc), (groups)); \
            if (acc) \
                acc->shared_rule_hits++; \
            matched = true; \
        } \
    } while (0);
#include "controllers/agent_impact_rules.def"
#undef AGENT_IMPACT_RULE

    return matched;
}

size_t agent_impact_rule_count(void)
{
    size_t count = 0;
#define AGENT_IMPACT_RULE(patterns, groups) \
    do { \
        (void)(patterns); \
        (void)(groups); \
        count++; \
    } while (0);
#include "controllers/agent_impact_rules.def"
#undef AGENT_IMPACT_RULE
    return count;
}
