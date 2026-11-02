/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native body functions for wallet read commands. See
 * controllers/native_handler_body.h for the shared contract. */

#ifndef ZCL_CONTROLLERS_WALLET_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_WALLET_NATIVE_HANDLERS_H

#include "controllers/native_handler_body.h"
#include "core/amount.h"
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

/* Typed activity reads: the node answers walletsummary and wallethistory;
 * the reply is forwarded unchanged. history takes limit, cursor, txid. */
char *zcl_native_wallet_summary_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);
char *zcl_native_wallet_history_body(const struct json_value *args,
                                     struct zcl_native_body_err *err);
char *zcl_native_wallet_latest_body(const struct json_value *args,
                                    struct zcl_native_body_err *err);

/* Shared by every wallet native handler, published here rather than
 * copied: wallet_restore_native_handlers.c carried a byte-for-byte
 * duplicate of wnh_fail (wrn_fail), now deleted. One helper, one
 * definition — a second copy is how the two drift apart. */
void wnh_fail(struct zcl_command_reply *reply,
              enum zcl_command_exit exit_code, const char *code,
              const char *message, const char *evidence);

/* The reply code and exit class a create failure maps to: the service codes
 * name refusals (-61 / -62 / -66 / -68 / -70), every other code is
 * CREATE_FAILED. Published for the test that pins the table. */
const char *wrp_create_failure_code(int code, enum zcl_command_exit *ex);

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

/* Validated inputs of one shielded send or sweep call: read and checked once,
 * then carried by both the plan and the commit stage. */
struct wnh_shielded_send_in {
    const char *wallet_scope;
    const char *from;
    const char *to;
    const char *idem;
    const char *memo;
    const char *memo_hex;
    const char *plan_token;
    CAmount amount_zats;
    CAmount fee_zats;      /* quoted at plan; carried by the commit input */
    bool has_fee;
    char amount[32];
};

/* Exact decimal text for a zatoshi amount (8 places, the RPC wire form). */
bool wnh_zat_text(CAmount zats, char out[32]);
/* The idempotency key is required and shape-checked. */
bool wnh_shielded_key_ok(struct zcl_command_reply *reply, const char *idem);
/* The fee the plan quoted, when the caller supplies it (the commit does). */
bool wnh_shielded_fee_input(struct zcl_command_reply *reply,
                            const struct zcl_command_request *request,
                            struct wnh_shielded_send_in *in);
/* Refuse a send whose node-side record says it must not run again. True when
 * the body is a committed send to render. */
bool wnh_shielded_send_state_ok(struct zcl_command_reply *reply,
                                const struct json_value *body);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_WALLET_NATIVE_HANDLERS_H */
