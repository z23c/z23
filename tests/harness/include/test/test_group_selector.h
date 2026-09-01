/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TEST_GROUP_SELECTOR_H
#define ZCL_TEST_GROUP_SELECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Keep the human-facing --only convenience and proof-facing exact selection
 * on one predicate. Proof automation must pass exact=true: a stale mapping
 * for "api" must not turn green by accidentally running "native_api_contract".
 */
static inline bool test_group_selector_matches(const char *registered_name,
                                               const char *selector,
                                               bool exact)
{
    if (!registered_name || !selector || !selector[0])
        return false;
    return exact ? strcmp(registered_name, selector) == 0
                 : strstr(registered_name, selector) != NULL;
}

/* Comma-separated exact set used by the proof executor. Empty members never
 * match; the runner separately validates that every member is registered
 * before it dispatches anything. */
static inline bool test_group_selector_matches_exact_set(
    const char *registered_name, const char *selectors)
{
    if (!registered_name || !selectors || !selectors[0])
        return false;
    size_t name_len = strlen(registered_name);
    const char *p = selectors;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == name_len && memcmp(registered_name, p, len) == 0)
            return true;
        if (!end)
            break;
        p = end + 1;
    }
    return false;
}

#endif /* ZCL_TEST_GROUP_SELECTOR_H */
