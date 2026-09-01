/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Private trusted-base predicates used only by reducer derivation. */

#ifndef ZCL_REDUCER_FRONTIER_TRUSTED_BASE_INTERNAL_H
#define ZCL_REDUCER_FRONTIER_TRUSTED_BASE_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* True only when coins_kv is proven authority and its NEXT-height applied
 * frontier covers `height`. A provenance marker alone is not coverage. */
bool reducer_frontier_coin_authority_covers(struct sqlite3 *db, int32_t height);

#endif
