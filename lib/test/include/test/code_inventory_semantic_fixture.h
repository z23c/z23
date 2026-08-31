/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Tracked functions for the code-inventory semantic evidence KAT. */

#ifndef ZCL_TEST_CODE_INVENTORY_SEMANTIC_FIXTURE_H
#define ZCL_TEST_CODE_INVENTORY_SEMANTIC_FIXTURE_H

#include <stdint.h>

uint64_t ci_semantic_bound(uint64_t limit);
uint64_t ci_semantic_loop(uint64_t limit);
uint64_t ci_semantic_formula(uint64_t limit);
uint64_t ci_semantic_changed(uint64_t limit);
uint64_t ci_semantic_indirect(uint64_t limit);

#endif /* ZCL_TEST_CODE_INVENTORY_SEMANTIC_FIXTURE_H */
