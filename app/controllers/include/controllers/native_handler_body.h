/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral handler-body contract.
 *
 * A body function takes a command argument object and returns one
 * heap-allocated JSON body (caller frees). The native command registry calls
 * these functions directly and wraps successful bodies in zcl.result.v1.
 *
 * Contract:
 *   - success: return the body; err->status = ZCL_NATIVE_BODY_OK. A body
 *     that itself carries an RPC-level {"error":...} object is still a
 *     SUCCESS return; the caller decides how to surface it.
 *   - failure: return NULL; set err->status + err->message. The message
 *     must explain the failure. All LOG_* calls stay inside the body function.
 */

#ifndef ZCL_CONTROLLERS_NATIVE_HANDLER_BODY_H
#define ZCL_CONTROLLERS_NATIVE_HANDLER_BODY_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zcl_native_body_status {
    ZCL_NATIVE_BODY_OK = 0,
    /* Caller-supplied input failed validation before any side effect. */
    ZCL_NATIVE_BODY_INVALID = 1,
    /* An upstream RPC/service returned nothing. */
    ZCL_NATIVE_BODY_UNAVAILABLE = 2,
    /* Allocation or serialization failed. */
    ZCL_NATIVE_BODY_INTERNAL = 3,
    /* An upstream success body violated its declared protocol shape. */
    ZCL_NATIVE_BODY_PROTOCOL = 4,
};

struct zcl_native_body_err {
    enum zcl_native_body_status status;
    /* Human-readable failure context for the command envelope. */
    char message[192];
};

typedef char *(*zcl_native_body_fn)(const struct json_value *args,
                                    struct zcl_native_body_err *err);

/* ── Defaulted JSON accessors ─────────────────────────────────────
 * Shared by the native body functions. */
static inline int64_t
json_get_int_or(const struct json_value *obj, const char *key, int64_t dflt)
{
    const struct json_value *v = json_get(obj, key);
    return v ? json_get_int(v) : dflt;
}

static inline bool
json_get_bool_or(const struct json_value *obj, const char *key, bool dflt)
{
    const struct json_value *v = json_get(obj, key);
    return v ? json_get_bool(v) : dflt;
}

static inline const char *
json_get_str_or(const struct json_value *obj, const char *key, const char *dflt)
{
    const struct json_value *v = json_get(obj, key);
    return v ? json_get_str(v) : dflt;
}

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_NATIVE_HANDLER_BODY_H */
