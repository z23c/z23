/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native body functions for metrics and consensus-report reads. See
 * controllers/native_handler_body.h for their shared contract. */

#ifndef ZCL_CONTROLLERS_META_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_META_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Prometheus-text metrics dump wrapped in a JSON
 * envelope. args is unused (no parameters). */
char *zcl_native_metrics_body(const struct json_value *args,
                              struct zcl_native_body_err *err);

/* Consensus-reject counter snapshot (per
 * (kind, reason) counts plus totals/overflow). args is unused (no
 * parameters). */
char *zcl_native_consensus_report_body(const struct json_value *args,
                                       struct zcl_native_body_err *err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_META_NATIVE_HANDLERS_H */
