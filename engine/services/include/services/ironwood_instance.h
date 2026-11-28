/* purpose: Project public Ironwood action statements to Halo2 field rows. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_INSTANCE_H
#define ZCL_IRONWOOD_INSTANCE_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>

struct v6_wire_view;
enum { IRONWOOD_INSTANCE_ROWS = 10, IRONWOOD_FIELD_BYTES = 32 };
struct ironwood_instance_rows {
    uint8_t row[IRONWOOD_INSTANCE_ROWS][IRONWOOD_FIELD_BYTES];
};
struct zcl_result ironwood_instance_from_statement(const uint8_t *statement, size_t size,
                                                    struct ironwood_instance_rows *out);
/* Public data only. Output is unchanged on failure and must not overlap the
 * input view or its backing bytes. This is not proof or transaction validation. */
struct zcl_result ironwood_instance_project(const struct v6_wire_view *view, uint64_t action,
                                            struct ironwood_instance_rows *out);
#endif
