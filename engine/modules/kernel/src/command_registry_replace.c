/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pre-publish checks for zcl_command_registry_replace_batch(). Each
 * override is still refused with the same why-string and LOG_FAIL as the
 * original inline loop. */

#include "kernel/command_registry.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

static bool replace_one_spec(const struct zcl_command_registry *registry,
                             const struct zcl_command_handler_override *ovr,
                             size_t i, const struct zcl_command_spec **spec,
                             char *why, size_t why_sz)
{
    if (!ovr->path || !ovr->path[0] || !ovr->handler) {
        if (why && why_sz)
            snprintf(why, why_sz, "override %zu: null/empty path or handler",
                     i);
        LOG_FAIL("kernel.command",
                 "override %zu: null/empty path or handler", i);
    }
    bool was_alias = false;
    *spec = zcl_command_registry_find(registry, ovr->path, &was_alias);
    if (!*spec || was_alias || strcmp((*spec)->path, ovr->path) != 0) {
        if (why && why_sz)
            snprintf(why, why_sz, "no canonical leaf named '%s'", ovr->path);
        LOG_FAIL("kernel.command", "no canonical leaf named '%s'", ovr->path);
    }
    return true;
}

static bool replace_one_ready(const struct zcl_command_spec *spec,
                              const char *path, char *why, size_t why_sz)
{
    if (command_registry_is_branch(spec)) {
        if (why && why_sz)
            snprintf(why, why_sz, "leaf '%s' is a branch, not swappable",
                     path);
        LOG_FAIL("kernel.command", "leaf '%s' is a branch, not swappable",
                 path);
    }
    if (spec->availability != ZCL_COMMAND_READY) {
        if (why && why_sz)
            snprintf(why, why_sz, "leaf '%s' is not READY", path);
        LOG_FAIL("kernel.command", "leaf '%s' is not READY", path);
    }
    if (spec->effect != ZCL_COMMAND_EFFECT_READ) {
        if (why && why_sz)
            snprintf(why, why_sz,
                     "leaf '%s' is mutating/destructive (effect=%s)", path,
                     zcl_command_effect_name(spec->effect));
        LOG_FAIL("kernel.command",
                 "refusing mutating/destructive leaf '%s' (effect=%s)", path,
                 zcl_command_effect_name(spec->effect));
    }
    return true;
}

static bool replace_one_unique(const struct zcl_command_handler_override *overrides,
                               size_t i, const char *path, char *why,
                               size_t why_sz)
{
    for (size_t j = 0; j < i; j++) {
        if (strcmp(overrides[j].path, path) == 0) {
            if (why && why_sz)
                snprintf(why, why_sz, "duplicate override '%s'", path);
            LOG_FAIL("kernel.command", "duplicate override '%s'", path);
        }
    }
    return true;
}

static bool replace_one(const struct zcl_command_registry *registry,
                        const struct zcl_command_handler_override *overrides,
                        size_t i, char *why, size_t why_sz)
{
    const struct zcl_command_handler_override *ovr = &overrides[i];
    const struct zcl_command_spec *spec = NULL;
    if (!replace_one_spec(registry, ovr, i, &spec, why, why_sz))
        return false;
    if (!replace_one_ready(spec, ovr->path, why, why_sz))
        return false;
    return replace_one_unique(overrides, i, ovr->path, why, why_sz);
}

bool command_registry_replace_validate(
    const struct zcl_command_registry *registry,
    const struct zcl_command_handler_override *overrides, size_t count,
    char *why, size_t why_sz)
{
    for (size_t i = 0; i < count; i++) {
        if (!replace_one(registry, overrides, i, why, why_sz))
            return false;
    }
    return true;
}
