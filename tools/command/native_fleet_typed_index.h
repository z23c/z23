/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bound and index owned typed mail observations without becoming an authority. */
#ifndef ZCL_NATIVE_FLEET_TYPED_INDEX_H
#define ZCL_NATIVE_FLEET_TYPED_INDEX_H

#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>

struct zcl_fleet_typed_entry;
struct zcl_fleet_typed_index {
    struct zcl_fleet_typed_entry *entries;
    size_t count, capacity, bytes, row_limit, byte_limit;
    bool poisoned;
};

/* Owned deep copies survive source mutation/free. byte_limit covers reserved
 * entries and JSON allocation payload, excluding allocator overhead and RSS.
 * Append uses O(N) entry moves; lookup is O(log N + matches). No persistence.
 * Zero limits refuse all candidate rows.
 * Initialize once, free once. A failed append poisons all subsequent queries;
 * free and rebuild before reuse. */
void zcl_fleet_typed_index_init(struct zcl_fleet_typed_index *index,
                                size_t row_limit, size_t byte_limit);
bool zcl_fleet_typed_index_append(struct zcl_fleet_typed_index *index,
                                  const struct json_value *row);
bool zcl_fleet_typed_index_build(struct zcl_fleet_typed_index *index,
                                 const struct json_value *rows);
void zcl_fleet_typed_index_free(struct zcl_fleet_typed_index *index);

/* Visits exact locator/counterpart candidates in decreasing result row_offset,
 * preserving first insertion for ties. Return true from visit to stop. The
 * caller must perform the live sender-binding check; no candidate is proof.
 * The callback must not mutate or free the index. Rows are borrowed until
 * the next append or free. Non-directives yield no candidates; a directive
 * without an integer seq is invalid. False means no trustworthy result. */
typedef bool (*zcl_fleet_typed_visit)(const struct json_value *row, void *ctx);
bool zcl_fleet_typed_index_visit(struct zcl_fleet_typed_index *index,
                                 const struct json_value *directive,
                                 zcl_fleet_typed_visit visit, void *ctx);
#endif
