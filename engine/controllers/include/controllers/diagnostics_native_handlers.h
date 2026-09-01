/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native body functions for diagnostic commands. See
 * controllers/native_handler_body.h for the shared contract. */

#ifndef ZCL_CONTROLLERS_DIAGNOSTICS_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_DIAGNOSTICS_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"

#ifdef __cplusplus
extern "C" {
#endif

/* sql/limit -> dbquery (SELECT-only). */
char *zcl_native_sql_body(const struct json_value *args,
                           struct zcl_native_body_err *err);

/* pattern/since_secs/max_lines/level -> getnodelog. */
char *zcl_native_node_log_body(const struct json_value *args,
                                struct zcl_native_body_err *err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_DIAGNOSTICS_NATIVE_HANDLERS_H */
