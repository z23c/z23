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
        "capabilities",
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
    /* "capabilities": the union of capability classes (see
     * engine/composition/capability_classes.def) the package's SHIPPED files can reach.
     * OPTIONAL in this shape check and MANDATORY for a registry package —
     * tools/lint/check_package_capabilities.sh is what refuses an absent
     * field, because "absent" and "reaches nothing" must never collapse into
     * one reading and only a gate that derives the value can tell them
     * apart. What is checked HERE is the part a receiving node can check
     * without this repository: the field is an array of non-empty CAP_*
     * strings in strict ascending order with no duplicates. Ordering is a
     * real constraint rather than tidiness — the manifest bytes are hashed
     * into the package root, so two spellings of one set would be two roots
     * for one package. The class names themselves are NOT validated against
     * capability_classes.def here: that table is this tree's, and a package
     * from elsewhere may legitimately name a class this build has never
     * heard of. Refusing it would be this node judging a stranger's
     * vocabulary, which is not what the field is for. */
    const struct json_value *capabilities = json_get(meta, "capabilities");
    if (capabilities) {
        if (capabilities->type != JSON_ARR)
            return false;
        const char *prev = NULL;
        for (size_t i = 0; i < capabilities->num_children; i++) {
            const struct json_value *entry = &capabilities->children[i];
            if (entry->type != JSON_STR)
                return false;
            const char *s = json_get_str(entry);
            if (!s || strncmp(s, "CAP_", 4) != 0 || s[4] == '\0')
                return false;
            for (const char *p = s + 4; *p; p++)
                if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')
                      || *p == '_'))
                    return false;
            if (prev && strcmp(prev, s) >= 0) {
                if (detail && detail_cap)
                    (void)snprintf(detail, detail_cap,
                                   "capabilities not strictly ascending: "
                                   "%s after %s", s, prev);
                return false;
            }
            prev = s;
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
