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
#include "session/fleet_board_proto.h"

#include <stdio.h>
#include <string.h>

static bool cr_input_failure(const struct zcl_command_spec *spec,
    const char *key, const struct json_value *value, char *why, size_t why_size)
{
    if (!strcmp(spec->path, "fleet.steer.wiki-write") && !strcmp(key, "text")) {
        if (why && why_size) snprintf(why, why_size,
            "inline wiki text must be a nonempty UTF-8 string of at most %u bytes",
            (unsigned)FLEET_BOARD_WIKI_TEXT_MAX);
        return false;
    }
    return command_registry_input_type_why(key, value, why, why_size);
}

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
            return cr_input_failure(spec, key, &input->children[i],
                                                   why, why_size);
    }
    return command_registry_input_required_discovery(spec, input, why,
                                                     why_size);
}

bool zcl_command_registry_input_key_is_boolean(
    const struct zcl_command_spec *spec, const char *key)
{
    if (!spec || !key)
        return false;
    struct json_value probe;
    json_init(&probe);
    json_set_object(&probe);
    bool type_ok = false;
    bool is_boolean = json_push_kv_bool(&probe, key, true) &&
                      command_registry_input_value_type_ok(
                          spec, key, &probe.children[0], &type_ok) &&
                      type_ok;
    json_free(&probe);
    return is_boolean;
}
