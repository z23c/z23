/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private rendering constants for the pure C23 economics island. */

#ifndef ZCL_ZCODE_C23_ECONOMICS_INTERNAL_H
#define ZCL_ZCODE_C23_ECONOMICS_INTERNAL_H

#define ZCODE_C23_ECONOMICS_QUEUE_ORDER \
    "strict-oldest-first:maturity_height,maturity_mtp,claim_root"
#define ZCODE_C23_ECONOMICS_CATEGORY_ORDER \
    "zero_root=0;else_first=(root[0]+1)%8;then=cyclic"
#define ZCODE_C23_ECONOMICS_CONCENTRATION_CAP \
    "per-recipient cap=min(epoch_capacity,max(1 ZC23,floor(epoch_capacity/100)))"
#define ZCODE_C23_BACKLOG_PROJECTION_MISSING \
    "blocked:claim_projection_missing"
#define ZCODE_C23_BACKLOG_EMPTY "ready:empty_projection"
#define ZCODE_C23_BACKLOG_INELIGIBLE "waiting:claims_ineligible"
#define ZCODE_C23_BACKLOG_EPOCH_READY "ready:epoch_plan"
#define ZCODE_C23_BACKLOG_CLAIM_NEXT "zcode commons claim plan"
#define ZCODE_C23_BACKLOG_STATUS_NEXT "zcode commons backlog"
#define ZCODE_C23_BACKLOG_EPOCH_NEXT \
    "zcode commons schedule claim plan"

#endif /* ZCL_ZCODE_C23_ECONOMICS_INTERNAL_H */
