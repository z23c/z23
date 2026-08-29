/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: closed-shape validation of the parsed zcode-package.json metadata
 * object, split out of package_prepare.c. Every function here is a pure
 * check over a `struct json_value` tree plus an optional detail buffer — it
 * touches none of package_prepare.c's directory-walk state
 * (`struct prepare_walk`) or file descriptors, so it shares nothing with
 * that file beyond the one declaration in package_prepare_internal.h. */

#define _POSIX_C_SOURCE 200809L

#include "package_prepare_internal.h"

#include <stdio.h>
#include <string.h>

static bool prepare_key_allowed(const char *key, const char *const *allowed,
                                size_t allowed_count)
{
    for (size_t i = 0; i < allowed_count; i++)
        if (strcmp(key, allowed[i]) == 0)
            return true;
    return false;
}

bool prepare_meta_closed(const struct json_value *meta,
                         char *detail, size_t detail_cap)
{
    static const char *const top_keys[] = {
        "schema", "name", "semver", "language", "license",
        "include_dir", "source_dir", "dependencies", "files",
    };
    static const char *const dep_keys[] = { "root", "name", "semver" };
    for (size_t i = 0; i < meta->num_children; i++) {
        if (!prepare_key_allowed(meta->keys[i], top_keys,
                                 sizeof(top_keys) / sizeof(top_keys[0]))) {
            if (detail && detail_cap)
                (void)snprintf(detail, detail_cap,
                               "unknown metadata key: %s", meta->keys[i]);
            return false;
        }
    }
    const struct json_value *dependencies = json_get(meta, "dependencies");
    if (!dependencies || dependencies->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < dependencies->num_children; i++) {
        const struct json_value *dep = &dependencies->children[i];
        if (dep->type != JSON_OBJ)
            return false;
        for (size_t j = 0; j < dep->num_children; j++) {
            if (!prepare_key_allowed(dep->keys[j], dep_keys,
                                     sizeof(dep_keys) / sizeof(dep_keys[0]))) {
                if (detail && detail_cap)
                    (void)snprintf(detail, detail_cap,
                                   "dependency %zu unknown key: %s", i,
                                   dep->keys[j]);
                return false;
            }
        }
    }
    const struct json_value *files = json_get(meta, "files");
    if (files && files->type != JSON_ARR)
        return false;
    if (files) {
        for (size_t i = 0; i < files->num_children; i++)
            if (files->children[i].type != JSON_STR)
                return false;
    }
    return true;
}
