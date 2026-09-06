/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The closed objective catalog, pasted from
 *          engine/composition/objectives.def, and the met/unmet/unmeasured
 *          verdict shared by every rendering of it. */

#include "native_fleet_objectives.h"

#include <stdio.h>
#include <string.h>

static const struct zcl_objective_row k_objectives[] = {
#define Z23_OBJECTIVE(id_, source_, direction_, target_, unit_, why_) \
    {id_, source_, direction_, target_, unit_, why_},
#include "../../engine/composition/objectives.def"
#undef Z23_OBJECTIVE
};

size_t zcl_objectives_catalog(const struct zcl_objective_row **out)
{
    if (out)
        *out = k_objectives;
    return sizeof(k_objectives) / sizeof(k_objectives[0]);
}

/* True when a measured value clears its row's target, in the row's own
 * direction. Equal to target always counts as met, in either direction. */
static bool objectives_met(const struct zcl_objective_row *row,
                           int64_t value)
{
    if (strcmp(row->direction, "max") == 0)
        return value >= row->target;
    return value <= row->target;
}

void zcl_objectives_status(const struct zcl_objective_row *row,
                           const struct zcl_objective_value *value, char *out,
                           size_t cap)
{
    if (!row || !value || !out || cap == 0)
        return;
    if (!value->measured) {
        (void)snprintf(out, cap, "unmeasured(%s)", value->reason);
        return;
    }
    (void)snprintf(out, cap, "%s",
                   objectives_met(row, value->value) ? "met" : "unmet");
}
