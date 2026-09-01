/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Safe JSON-RPC params builder.
 *
 * Hand-rolled snprintf(payload, ..., "[\"%s\"]", user_input) is vulnerable
 * to JSON injection when user_input contains `"`, `\`, or control chars:
 * a caller can punch through the string context and rewrite the params
 * array.  Every handler that builds RPC param arrays must go through this
 * builder — it routes every string through the project's JSON encoder,
 * which escapes the dangerous characters.
 *
 * Usage (flat case):
 *   struct rpc_arg_builder p;
 *   rpc_arg_builder_init(&p);
 *   rpc_arg_builder_push_str(&p, untrusted_addr);
 *   rpc_arg_builder_push_real(&p, amount);
 *   char *params = rpc_arg_builder_to_json(&p);   // consumes p
 *   char *out = node_rpc_call("sendtoaddress", params);
 *   free(params);
 *
 * Usage (nested case — z_sendmany's [from, [{address, amount}]]):
 *   struct rpc_arg_builder p;
 *   rpc_arg_builder_init(&p);
 *   rpc_arg_builder_push_str(&p, from);
 *
 *   struct json_value recip; json_init(&recip); json_set_object(&recip);
 *   json_push_kv_str(&recip,  "address", to);
 *   json_push_kv_real(&recip, "amount",  amount);
 *   struct json_value recip_arr; json_init(&recip_arr);
 *   json_set_array(&recip_arr); json_push_back(&recip_arr, &recip);
 *   rpc_arg_builder_push_value(&p, &recip_arr);
 *   json_free(&recip); json_free(&recip_arr);
 *
 *   char *params = rpc_arg_builder_to_json(&p);
 */

#ifndef ZCL_CONTROLLERS_RPC_PARAMS_H
#define ZCL_CONTROLLERS_RPC_PARAMS_H

#include "json/json.h"

#include <stdbool.h>
#include <stdint.h>

struct rpc_arg_builder {
    struct json_value arr;  /* JSON_ARR — do not touch directly */
};

void rpc_arg_builder_init(struct rpc_arg_builder *p);
void rpc_arg_builder_free(struct rpc_arg_builder *p);

/* Append a typed value. NULL strings are treated as the empty string. */
void rpc_arg_builder_push_str(struct rpc_arg_builder *p, const char *s);
void rpc_arg_builder_push_int(struct rpc_arg_builder *p, int64_t i);
void rpc_arg_builder_push_real(struct rpc_arg_builder *p, double d);

/* Append an already-built JSON value (object or array) as one positional
 * argument — the nested case above. The value is deep-copied; the caller
 * keeps ownership of `v` and must still json_free it. A NULL `v` appends
 * JSON null. */
void rpc_arg_builder_push_value(struct rpc_arg_builder *p,
                                const struct json_value *v);

/* Serialize to a malloc'd, NUL-terminated JSON array string ready to
 * pass as the params_json argument to node_rpc_call(). Also frees the
 * builder's internal storage (equivalent to rpc_arg_builder_free(p)).
 * Returns NULL on allocation failure. */
char *rpc_arg_builder_to_json(struct rpc_arg_builder *p);

#endif
