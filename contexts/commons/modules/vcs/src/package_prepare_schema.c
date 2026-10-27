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

/* Return the first key of `obj` that is not in `allowed`, or NULL when
 * every key of `obj` is allowed. */
static const char *prepare_first_unknown_key(const struct json_value *obj,
                                             const char *const *allowed,
                                             size_t allowed_count)
{
    for (size_t i = 0; i < obj->num_children; i++)
        if (!prepare_key_allowed(obj->keys[i], allowed, allowed_count))
            return obj->keys[i];
    return NULL;
}

/* True when `arr` is absent (NULL) or is a JSON array whose children are
 * all JSON strings. */
static bool prepare_str_array_closed(const struct json_value *arr)
{
    if (!arr)
        return true;
    if (arr->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < arr->num_children; i++)
        if (arr->children[i].type != JSON_STR)
            return false;
    return true;
}

/* Check a "dependencies" array: every entry must be a JSON object whose
 * keys are only root, name and semver. */
static bool prepare_dependencies_closed(const struct json_value *dependencies,
                                        char *detail, size_t detail_cap)
{
    static const char *const dep_keys[] = { "root", "name", "semver" };
    for (size_t i = 0; i < dependencies->num_children; i++) {
        const struct json_value *dep = &dependencies->children[i];
        if (dep->type != JSON_OBJ)
            return false;
        const char *unknown = prepare_first_unknown_key(
            dep, dep_keys, sizeof(dep_keys) / sizeof(dep_keys[0]));
        if (unknown) {
            if (detail && detail_cap)
                (void)snprintf(detail, detail_cap,
                               "dependency %zu unknown key: %s", i, unknown);
            return false;
        }
    }
    return true;
}

/* True when `s` is a capability class name: "CAP_" followed by one or more
 * characters from A-Z, 0-9 or '_'. NULL is not a name. */
static bool prepare_capability_name_valid(const char *s)
{
    if (!s)
        return false;
    bool has_cap_prefix = strncmp(s, "CAP_", 4) == 0;
    if (!has_cap_prefix || s[4] == '\0')
        return false;
    for (const char *p = s + 4; *p; p++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')
              || *p == '_'))
            return false;
    return true;
}

static bool prepare_capabilities_closed(const struct json_value *meta,
                                        char *detail, size_t detail_cap)
{
    /* "capabilities": the union of capability classes (see
     * engine/composition/capability_classes.def) the package's SHIPPED files can reach.
     * OPTIONAL in this shape check and MANDATORY for a registry package —
     * tools/lint/lintc/gate_package_capabilities.c is what refuses an absent
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
            bool name_ok = prepare_capability_name_valid(s);
            if (!name_ok)
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
    return true;
}

bool prepare_meta_closed(const struct json_value *meta,
                         char *detail, size_t detail_cap)
{
    static const char *const top_keys[] = {
        "schema", "name", "semver", "language", "license",
        "include_dir", "source_dir", "dependencies", "files",
        "capabilities", "programs",
    };
    const char *unknown = prepare_first_unknown_key(
        meta, top_keys, sizeof(top_keys) / sizeof(top_keys[0]));
    if (unknown) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "unknown metadata key: %s", unknown);
        return false;
    }
    const struct json_value *dependencies = json_get(meta, "dependencies");
    if (!dependencies || dependencies->type != JSON_ARR)
        return false;
    if (!prepare_dependencies_closed(dependencies, detail, detail_cap))
        return false;
    if (!prepare_capabilities_closed(meta, detail, detail_cap))
        return false;
    const struct json_value *files = json_get(meta, "files");
    if (!prepare_str_array_closed(files))
        return false;
    /* "programs": the `app/<stem>.c` translation units this package ships as
     * executables. OPTIONAL, and absent means the package installs a library
     * only — which is why the key can never be inferred from the tree: a
     * package that merely carries an app/ directory keeps encoding its
     * recipe as schema 1 and keeps its root. What is checked HERE is the
     * shape a receiving node can check on its own; the path grammar,
     * membership in the package's own files and the install-output
     * uniqueness rule are enforced by prepare, which has the manifest and
     * the package name this shape check does not. */
    const struct json_value *programs = json_get(meta, "programs");
    if (!prepare_str_array_closed(programs))
        return false;
    return true;
}
