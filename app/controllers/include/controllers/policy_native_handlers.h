/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SWAPPABLE half of the package-policy projection.
 *
 * The body below is a PURE decision projection: it answers from its arguments
 * and compiled-in constants only — no wall-clock, no filesystem, no network,
 * no node RPC, no datadir. That is what makes `zcode.package.policy.limits` a
 * probe leaf the hot-swap loader can dispatch in-process, with no running
 * node, before it publishes anything.
 *
 * Its resident counterpart is controllers/policy_native_resident.h.
 */

#ifndef ZCL_CONTROLLERS_POLICY_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_POLICY_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"

#ifdef __cplusplus
extern "C" {
#endif

/* zcode.package.policy.limits — project the frozen ZCODE local P2P ratio and
 * anti-spam policy table for one resolved contributor tier.
 *
 * Optional args (all defaulted, so an empty object is valid):
 *   tier              "new-user" | "earned-contributor" | "verified-seeder"
 *                     — when absent the tier is DERIVED from the facts below.
 *   earned_score      earned ZCODE score (default 0)
 *   uploaded_bytes    verified bytes served   (default 0)
 *   downloaded_bytes  verified bytes received (default 0)
 */
char *zcl_native_policy_limits_body(const struct json_value *args,
                                    struct zcl_native_body_err *err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_POLICY_NATIVE_HANDLERS_H */
