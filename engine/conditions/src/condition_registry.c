/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/condition_registry.h"

#include "conditions/blocker_handoff_registry.h"

#define ZCL_CONDITION(name) void register_##name(void);
#include "conditions/condition_registry.def"
#undef ZCL_CONDITION

void condition_registry_register_all(void)
{
#define ZCL_CONDITION(name) register_##name();
#include "conditions/condition_registry.def"
#undef ZCL_CONDITION

    /* Publish this registry's OTHER projection: which condition (or ESCAPE,
     * or nobody) remedies which named blocker, plus the decision an operator
     * owns when the answer is nobody. Registering the healers and publishing
     * the map of what they heal is one act — a blocker whose remedy names a
     * condition is only a truthful claim once that condition exists, which is
     * exactly here. See conditions/blocker_handoff_registry.h. */
    blocker_handoff_registry_install();
}
