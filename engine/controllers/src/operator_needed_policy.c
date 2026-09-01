/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The single implementation behind controllers/operator_needed_policy.h.
 * Every row comes from controllers/operator_needed_policy.def — there is no
 * editable table in this file. Add or change a reason there. */

#include "controllers/operator_needed_policy.h"

#include <stddef.h>

enum reason_need_policy {
    NEED_NEVER = 0,
    NEED_ALWAYS,
    NEED_IF_WARNINGS
};

struct reason_row {
    const char *name;
    const char *status;
    const char *summary;
    enum reason_need_policy need;
};

static const struct reason_row g_reasons[] = {
#define ZCL_STATUS_REASON(suffix, status_str, summary_str, need) \
    { #suffix, status_str, summary_str, need },
#include "controllers/operator_needed_policy.def"
#undef ZCL_STATUS_REASON
};

/* A row per enumerator, checked by the compiler rather than by a test that
 * someone has to remember to run. */
_Static_assert(sizeof(g_reasons) / sizeof(g_reasons[0]) ==
                   (size_t)ZCL_STATUS_REASON__COUNT,
               "operator_needed_policy.def rows and enum node_status_reason "
               "are out of step");

static const struct reason_row *reason_row(enum node_status_reason reason)
{
    if ((int)reason < 0 || (int)reason >= (int)ZCL_STATUS_REASON__COUNT)
        return NULL;
    return &g_reasons[(int)reason];
}

bool node_status_reason_operator_needed(enum node_status_reason reason,
                                        int64_t warning_count)
{
    const struct reason_row *row = reason_row(reason);
    /* Unknown reason: an operator problem, never a silent green. */
    if (!row)
        return true;
    switch (row->need) {
    case NEED_NEVER:
        return false;
    case NEED_ALWAYS:
        return true;
    case NEED_IF_WARNINGS:
        return warning_count > 0;
    }
    return true;
}

const char *node_status_reason_status(enum node_status_reason reason)
{
    const struct reason_row *row = reason_row(reason);
    return row ? row->status : "degraded";
}

const char *node_status_reason_summary(enum node_status_reason reason)
{
    const struct reason_row *row = reason_row(reason);
    return row ? row->summary
               : "node status reason is out of range - treat as needing an "
                 "operator";
}

const char *node_status_reason_name(enum node_status_reason reason)
{
    const struct reason_row *row = reason_row(reason);
    return row ? row->name : "OUT_OF_RANGE";
}
