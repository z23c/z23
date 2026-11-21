/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Harness code that picks the test groups needing rebuilds after a source change. */

#include "test/selection_build_needs.h"

#include "test/test_group_selector.h"
#include "test_group_catalog.h"

bool zcl_test_selection_build_needs(const char *only, bool only_exact,
                                    zcl_test_selection_gate_fn gated,
                                    struct zcl_test_group_host_need *needs,
                                    size_t cap, size_t *n)
{
    if (!needs || !n)
        return false;
    *n = 0;
    for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
        const char *group = zcl_test_group_catalog_at(i);
        if (!test_group_selector_selects(group, only, only_exact) ||
            (gated && gated(group)))
            continue;
        if (!zcl_test_group_build_needs_add(group, needs, cap, n))
            return false;
    }
    return true;
}
