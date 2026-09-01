/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native body functions for wallet read commands. See
 * controllers/native_handler_body.h for the shared contract. */

#ifndef ZCL_CONTROLLERS_WALLET_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_WALLET_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"
#include "kernel/command_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

/* minconf/maxconf -> listunspent. */
char *zcl_native_listunspent_body(const struct json_value *args,
                                   struct zcl_native_body_err *err);

/* count/skip -> listtransactions. */
char *zcl_native_listtransactions_body(const struct json_value *args,
                                        struct zcl_native_body_err *err);

/* txid -> gettransaction. */
char *zcl_native_gettransaction_body(const struct json_value *args,
                                      struct zcl_native_body_err *err);

/* address -> validateaddress, projected to the public key for a wallet-owned
 * transparent key address. Never returns or reads a private key. */
char *zcl_native_address_public_key_body(
    const struct json_value *args, struct zcl_native_body_err *err);

/* listwalletkeys[false] projected to
 * {t_addresses:[...], z_addresses:[...]}. */
char *zcl_native_listaddresses_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);

/* address -> z_getbalance, projected to
 * {address, balance, minconf}. z_getbalance answers with a bare decimal
 * string; the object names the address and confirmation floor the number
 * was computed under. */
char *zcl_native_z_getbalance_body(const struct json_value *args,
                                    struct zcl_native_body_err *err);

/* z_listunspent[0] projected to {count, notes:[...]}. A wallet with no
 * shielded notes answers count=0 with an empty list, never a missing key. */
char *zcl_native_z_listunspent_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);

/* Shared by every wallet native handler, published here rather than
 * copied: wallet_restore_native_handlers.c carried a byte-for-byte
 * duplicate of wnh_fail (wrn_fail), now deleted. One helper, one
 * definition — a second copy is how the two drift apart. */
void wnh_fail(struct zcl_command_reply *reply,
              enum zcl_command_exit exit_code, const char *code,
              const char *message, const char *evidence);

/* Call a node RPC, publishing a typed BLOCKED failure into `reply` and
 * returning false when the node does not answer. `out` is only
 * initialised on true. */
bool wnh_call_rpc(struct zcl_command_reply *reply, const char *method,
                  const char *params_json, struct json_value *out);

/* Same typed wallet-RPC adapter with an explicit bounded total deadline.
 * Reserved for methods whose documented work class exceeds the generic
 * client ceiling; callers still choose from compile-time policy, never
 * operator/agent input. */
bool wnh_call_rpc_deadline(struct zcl_command_reply *reply, const char *method,
                           const char *params_json, long total_ms,
                           struct json_value *out);

/* Shared non-secret plan rendering for the mutating wallet controller
 * siblings. */
void wnh_plan_token(char out[17], const char *a, const char *b,
                    const char *c);
bool wnh_commit_input(const struct json_value *input, char *out,
                      size_t out_cap);
void wnh_emit_plan(struct zcl_command_reply *reply, const char *path,
                   const char *action, const char *token,
                   const char *commit_input);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_WALLET_NATIVE_HANDLERS_H */
