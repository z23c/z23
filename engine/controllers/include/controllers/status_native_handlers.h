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
/* The same body with the caller's own connect and total deadline in
 * milliseconds, instead of ZCL_STATUS_DEADLINE_MS. */
char *zcl_native_status_brief_body_within(long deadline_ms,
                                          struct zcl_native_body_err *err);
char *zcl_native_status_journey_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);
/* The raw JSON texts the journey reads: the status brief body and the five
 * RPC replies (custody snapshot, wallet, backup, mempool, pace). Any may be
 * NULL; a missing source makes its facts unknown, never true. */
struct zcl_status_journey_sources {
    const char *brief;
    const char *money;
    const char *wallet;
    const char *backup;
    const char *mempool;
    const char *pace;
};
/* Compose the journey body from already-fetched sources. No I/O. */
char *zcl_native_status_journey_compose(
    const struct zcl_status_journey_sources *src,
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
