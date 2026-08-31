/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Supply independently spelled semantic-duplicate KAT functions. */

#include "test/code_inventory_semantic_fixture.h"

uint64_t ci_semantic_bound(uint64_t limit)
{
    return limit & 255u;
}

uint64_t ci_semantic_loop(uint64_t limit)
{
    uint64_t remaining = ci_semantic_bound(limit);
    uint64_t total = 0;
    while (remaining != 0) {
        total += remaining;
        remaining--;
    }
    return total;
}

uint64_t ci_semantic_formula(uint64_t limit)
{
    uint64_t term = ci_semantic_bound(limit);
    if ((term & 1u) == 0)
        return (term / 2u) * (term + 1u);
    return term * ((term + 1u) / 2u);
}

uint64_t ci_semantic_changed(uint64_t limit)
{
    uint64_t term = ci_semantic_bound(limit);
    uint64_t result;
    if ((term & 1u) == 0)
        result = (term / 2u) * (term + 1u);
    else
        result = term * ((term + 1u) / 2u);
    return result ^ 1u;
}

uint64_t ci_semantic_indirect(uint64_t limit)
{
    uint64_t (*dispatch)(uint64_t) = ci_semantic_bound;
    uint64_t term = dispatch(limit);
    return term * (term + 1u) / 2u;
}
