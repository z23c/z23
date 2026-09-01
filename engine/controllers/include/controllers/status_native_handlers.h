/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral operator read compositions.
 *
 * Each function takes a command argument object and returns one
 * heap-allocated JSON body (caller frees). On failure it returns NULL and
 * fills struct zcl_native_body_err after logging context.
 */

#ifndef ZCL_CONTROLLERS_STATUS_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_STATUS_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"

#ifdef __cplusplus
extern "C" {
#endif

char *zcl_native_status_body(const struct json_value *args,
                             struct zcl_native_body_err *err);
char *zcl_native_status_brief_body(const struct json_value *args,
                                   struct zcl_native_body_err *err);
char *zcl_native_status_journey_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);
char *zcl_native_kpi_body(const struct json_value *args,
                          struct zcl_native_body_err *err);
char *zcl_native_syncdiag_body(const struct json_value *args,
                               struct zcl_native_body_err *err);
char *zcl_native_blockers_body(const struct json_value *args,
                               struct zcl_native_body_err *err);
char *zcl_native_timeline_body(const struct json_value *args,
                               struct zcl_native_body_err *err);
char *zcl_native_agent_diagnose_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);
char *zcl_native_postmortem_list_body(const struct json_value *args,
                                      struct zcl_native_body_err *err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_STATUS_NATIVE_HANDLERS_H */
