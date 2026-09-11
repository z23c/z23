/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Catalog-shape checks for zcl_command_registry_validate(), split so the
 * dispatcher and each predicate stay at or under cyclomatic 15. Why-strings
 * are unchanged from the original inline chain. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include <stdio.h>
#include <string.h>

static bool cr_validate_shape(const struct zcl_command_spec *spec, size_t i,
                              char *why, size_t why_size)
{
    if (!command_registry_path_valid(spec->path) || !spec->summary ||
        !spec->summary[0] || !command_registry_enum_values_valid(spec) ||
        !command_registry_csv_valid_paths(spec->aliases)) {
        if (why)
            snprintf(why, why_size, "malformed command at index %zu", i);
        return false;
    }
    return true;
}

static bool cr_validate_parent_path(const struct zcl_command_spec *spec,
                                    char *why, size_t why_size)
{
    if (spec->parent && spec->parent[0] &&
        !command_registry_path_valid(spec->parent)) {
        if (why)
            snprintf(why, why_size, "invalid parent for %s", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf_schema(const struct zcl_command_spec *spec,
                                    char *why, size_t why_size)
{
    if (!spec->input_schema || !spec->input_schema[0] || !spec->output_schema ||
        !spec->output_schema[0] || !spec->example || !spec->example[0]) {
        if (why)
            snprintf(why, why_size, "leaf %s lacks schema/example", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf_handler(const struct zcl_command_spec *spec,
                                     char *why, size_t why_size)
{
    if (spec->availability == ZCL_COMMAND_READY && !spec->handler) {
        if (why)
            snprintf(why, why_size, "ready leaf %s lacks handler", spec->path);
        return false;
    }
    if (spec->availability == ZCL_COMMAND_PLANNED && spec->handler) {
        if (why)
            snprintf(why, why_size, "planned leaf %s has handler", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf_semantics(const struct zcl_command_spec *spec,
                                       char *why, size_t why_size)
{
    if (spec->availability == ZCL_COMMAND_READY &&
        (!spec->semantics || !spec->semantics[0] ||
         strcmp(spec->semantics, spec->summary) == 0)) {
        if (why)
            snprintf(why, why_size, "ready leaf %s lacks distinct semantics",
                     spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_leaf(const struct zcl_command_spec *spec, char *why,
                             size_t why_size)
{
    if (!cr_validate_leaf_schema(spec, why, why_size))
        return false;
    if (!cr_validate_leaf_handler(spec, why, why_size))
        return false;
    return cr_validate_leaf_semantics(spec, why, why_size);
}

static bool cr_validate_branch_or_leaf(const struct zcl_command_spec *spec,
                                       char *why, size_t why_size)
{
    if (command_registry_is_branch(spec)) {
        if (spec->handler || spec->availability != ZCL_COMMAND_READY) {
            if (why)
                snprintf(why, why_size,
                         "branch %s must be ready without handler", spec->path);
            return false;
        }
        return true;
    }
    return cr_validate_leaf(spec, why, why_size);
}

static bool cr_validate_budget_reason(const struct zcl_command_spec *spec,
                                      char *why, size_t why_size)
{
    if (spec->budget_bytes != 0 &&
        (spec->budget_bytes < 256 || spec->budget_bytes > 65536)) {
        if (why)
            snprintf(why, why_size, "leaf %s budget_bytes out of range",
                     spec->path);
        return false;
    }
    if (spec->availability != ZCL_COMMAND_READY &&
        (!spec->availability_reason || !spec->availability_reason[0])) {
        if (why)
            snprintf(why, why_size, "non-ready %s lacks reason", spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_effect_traits(const struct zcl_command_spec *spec,
                                      char *why, size_t why_size)
{
    if (spec->effect == ZCL_COMMAND_EFFECT_READ &&
        spec->risk != ZCL_COMMAND_RISK_READ) {
        if (why)
            snprintf(why, why_size, "read effect/risk conflict for %s",
                     spec->path);
        return false;
    }
    const uint32_t known_traits =
        ZCL_COMMAND_TRAIT_DETERMINISTIC | ZCL_COMMAND_TRAIT_REVERSIBLE |
        ZCL_COMMAND_TRAIT_IDEMPOTENT | ZCL_COMMAND_TRAIT_DRY_RUN |
        ZCL_COMMAND_TRAIT_DEV_ONLY | ZCL_COMMAND_TRAIT_DISPLAY_ONLY;
    if ((spec->traits & ~(known_traits | ZCL_COMMAND_TRAIT_PROSE)) != 0) {
        if (why)
            snprintf(why, why_size, "unknown command trait for %s", spec->path);
        return false;
    }
    if ((spec->traits & ZCL_COMMAND_TRAIT_DISPLAY_ONLY) != 0 &&
        (spec->effect != ZCL_COMMAND_EFFECT_MUTATE ||
         spec->risk != ZCL_COMMAND_RISK_APP_WRITE ||
         spec->confirmation != ZCL_COMMAND_CONFIRM_NONE ||
         spec->required_capabilities != ZCL_COMMAND_CAP_NONE)) {
        if (why)
            snprintf(why, why_size, "display-only contract conflict for %s",
                     spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_collisions(const struct zcl_command_registry *registry,
                                   const struct zcl_command_spec *spec,
                                   size_t i, char *why, size_t why_size)
{
    for (size_t j = 0; j < i; j++) {
        const struct zcl_command_spec *other = &registry->commands[j];
        if (strcmp(spec->path, other->path) == 0 ||
            command_registry_csv_token_equal(spec->aliases, other->path) ||
            command_registry_csv_token_equal(other->aliases, spec->path)) {
            if (why)
                snprintf(why, why_size, "path/alias collision for %s",
                         spec->path);
            return false;
        }
        const char *at = spec->aliases;
        while (at && *at) {
            const char *end = strchr(at, ',');
            size_t len = end ? (size_t)(end - at) : strlen(at);
            char token[ZCL_COMMAND_MAX_PATH];
            memcpy(token, at, len);
            token[len] = 0;
            if (command_registry_csv_token_equal(other->aliases, token)) {
                if (why)
                    snprintf(why, why_size, "duplicate alias %s", token);
                return false;
            }
            if (!end)
                break;
            at = end + 1;
        }
    }
    return true;
}

static bool cr_validate_parent_exists(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, char *why, size_t why_size)
{
    if (!spec->parent || !spec->parent[0])
        return true;
    bool found_parent = false;
    for (size_t j = 0; j < registry->count; j++) {
        if (strcmp(registry->commands[j].path, spec->parent) == 0 &&
            command_registry_is_branch(&registry->commands[j])) {
            found_parent = true;
            break;
        }
    }
    if (!found_parent) {
        if (why)
            snprintf(why, why_size, "missing branch parent %s for %s",
                     spec->parent, spec->path);
        return false;
    }
    return true;
}

static bool cr_validate_one(const struct zcl_command_registry *registry,
                            const struct zcl_command_spec *spec, size_t i,
                            char *why, size_t why_size)
{
    if (!cr_validate_shape(spec, i, why, why_size))
        return false;
    if (!cr_validate_parent_path(spec, why, why_size))
        return false;
    if (!cr_validate_branch_or_leaf(spec, why, why_size))
        return false;
    if (!cr_validate_budget_reason(spec, why, why_size))
        return false;
    if (!cr_validate_effect_traits(spec, why, why_size))
        return false;
    if (!cr_validate_collisions(registry, spec, i, why, why_size))
        return false;
    return cr_validate_parent_exists(registry, spec, why, why_size);
}

bool zcl_command_registry_validate(const struct zcl_command_registry *registry,
                                   char *why, size_t why_size)
{
    if (why && why_size)
        why[0] = 0;
    if (!registry || !registry->commands || registry->count == 0) {
        if (why)
            snprintf(why, why_size, "empty registry");
        return false;
    }
    for (size_t i = 0; i < registry->count; i++) {
        if (!cr_validate_one(registry, &registry->commands[i], i, why,
                             why_size))
            return false;
    }
    return true;
}
