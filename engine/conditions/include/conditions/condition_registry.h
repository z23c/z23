/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITION_REGISTRY_H
#define ZCL_CONDITION_REGISTRY_H

/* Not a Condition itself: this is the aggregator for the canonical ordered
 * entries in condition_registry.def. */
enum {
    CONDITION_REGISTRY_COUNT =
#define ZCL_CONDITION(name) +1
        0
#include "conditions/condition_registry.def"
#undef ZCL_CONDITION
};

void condition_registry_register_all(void);

#endif /* ZCL_CONDITION_REGISTRY_H */
