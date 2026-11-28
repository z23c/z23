/* purpose: Project public Ironwood action statements to Halo2 field rows. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_instance.h"
#include "ironwood_pasta_internal.h"
#include "primitives/transaction_v6_wire.h"
#include <string.h>

struct zcl_result ironwood_instance_from_statement(const uint8_t *s, size_t size,
                                                    struct ironwood_instance_rows *out)
{
    struct ironwood_instance_rows rows = {0};
    uint8_t affine[64];
    if (!s || size != V6_IRONWOOD_STATEMENT_SIZE || !out)
        return ZCL_ERR(-1, "Invalid Ironwood statement input");
    if (s[160] > 1 || s[161] > 1 || s[162] > 1)
        return ZCL_ERR(-1, "Invalid Ironwood statement flag");
    static const size_t offsets[] = {0, 64, 128};
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; ++i) {
        struct zcl_result field = ironwood_pasta_fp_canonical(s + offsets[i]);
        if (!field.ok) return field;
    }
    struct zcl_result point = ironwood_pasta_point(s + 32, IRONWOOD_PALLAS, true, affine);
    if (!point.ok) return point;
    memcpy(rows.row[1], affine, 32); memcpy(rows.row[2], affine + 32, 32);
    point = ironwood_pasta_point(s + 96, IRONWOOD_PALLAS, false, affine);
    if (!point.ok) return point;
    memcpy(rows.row[4], affine, 32); memcpy(rows.row[5], affine + 32, 32);
    memcpy(rows.row[0], s, 32); memcpy(rows.row[3], s + 64, 32);
    memcpy(rows.row[6], s + 128, 32);
    for (size_t i = 0; i < 3; ++i) rows.row[7+i][0] = s[160+i];
    *out = rows;
    return ZCL_OK;
}

struct zcl_result ironwood_instance_project(const struct v6_wire_view *view, uint64_t action,
                                            struct ironwood_instance_rows *out)
{
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE];
    if (!out || !v6_core_ironwood_statement(view, action, s, sizeof s))
        return ZCL_ERR(-1, "Invalid Ironwood action statement");
    return ironwood_instance_from_statement(s, sizeof s, out);
}
