/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native body functions for read-only ZCL application commands: names,
 * tokens, messaging inbox, file market, and atomic swaps. See
 * controllers/native_handler_body.h for the shared contract.
 *
 * Only the read surface is re-homed here: the destructive app-layer commands
 * (name register/update/transfer/renew/set-record/set-text, message send,
 * market offer/buy, swap initiate/participate, message mark-read) land in the
 * catalog as PLANNED native leaves (fail-closed, exit 3) until the app-write
 * plan/commit handshake is wired — mirroring the wallet-send precedent in
 * engine/composition/commands/core.def. The backing RPC methods stay available at the
 * node RPC layer, so no capability is lost by keeping them PLANNED here. */

#ifndef ZCL_CONTROLLERS_APP_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_APP_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"

#ifdef __cplusplus
extern "C" {
#endif

/* No args -> zslp_listtokens; wraps the RPC's bare array as
 * {"tokens":[...]} — the native body contract requires an object. */
char *zcl_native_zslp_listtokens_body(const struct json_value *args,
                                      struct zcl_native_body_err *err);

/* name -> name_resolve. */
char *zcl_native_name_resolve_body(const struct json_value *args,
                                   struct zcl_native_body_err *err);

/* No args -> name_list. */
char *zcl_native_name_list_body(const struct json_value *args,
                                struct zcl_native_body_err *err);

/* No args -> msg_inbox (full inbox, newest first). */
char *zcl_native_msg_inbox_body(const struct json_value *args,
                                struct zcl_native_body_err *err);

/* No args -> zmarket_list. */
char *zcl_native_zmarket_list_body(const struct json_value *args,
                                   struct zcl_native_body_err *err);

/* No args -> zmarket_status. */
char *zcl_native_zmarket_status_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);

/* No args -> zmarket_content_list; output is path-free and owner-private. */
char *zcl_native_zmarket_content_list_body(
    const struct json_value *args, struct zcl_native_body_err *err);

/* No args -> swap_chains. */
char *zcl_native_swap_chains_body(const struct json_value *args,
                                  struct zcl_native_body_err *err);

/* Optional state filter -> swap_list. */
char *zcl_native_swap_list_body(const struct json_value *args,
                                struct zcl_native_body_err *err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_APP_NATIVE_HANDLERS_H */
