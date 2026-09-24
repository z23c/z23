/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the pure command-input validator,
 * zcl_command_registry_input_validate(), in its own translation unit so the
 * HOT_FORK command-input capsule (engine/composition/hotfork_capsules.def)
 * compiles only the validation chain — this file plus its per-key rule
 * siblings command_registry_input_types.c,
 * command_registry_input_budget.c and command_registry_devagent_input.c —
 * and never the dispatcher shell (command_registry.c: latency ring, request
 * sequence, SHA-256 digest, execute). Deterministic and effect-free: it reads
 * the caller's spec and parsed JSON, writes only the caller's `why` buffer,
 * and owns no file-scope state. Behaviour is unchanged from its former home
 * in command_registry.c. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include <stdio.h>
#include <string.h>

bool zcl_command_registry_input_validate(const struct zcl_command_spec *spec,
                                         const struct json_value *input,
                                         char *why, size_t why_size)
{
    if (why && why_size)
        why[0] = 0;
    if (!spec || !input || input->type != JSON_OBJ) {
        if (why) snprintf(why, why_size, "input must be one JSON object");
        return false;
    }
    if (strcmp(spec->input_schema, "zcl.command.empty_input.v1") == 0 &&
        input->num_children != 0) {
        if (why) snprintf(why, why_size, "command accepts no input keys");
        return false;
    }
    for (size_t i = 0; i < input->num_children; i++) {
        const char *key = input->keys[i];
        if (!command_registry_input_key_declared(spec, input, i, why, why_size))
            return false;
        bool type_ok = false;
        if (!command_registry_input_value_type_ok(spec, key,
                                                  &input->children[i],
                                                  &type_ok) ||
            !type_ok)
            return command_registry_input_type_why(key, &input->children[i],
                                                   why, why_size);
    }
    return command_registry_input_required_discovery(spec, input, why,
                                                     why_size);
}
