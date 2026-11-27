/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Render research v6 transaction inspection for the decoder RPC.
 */
#ifndef Z23_TRANSACTION_V6_RPC_H
#define Z23_TRANSACTION_V6_RPC_H
#include "json/json.h"
#include <stdbool.h>
/* Decode and render structurally; this does not validate spends or proofs. */
enum v6_rpc_status { V6_RPC_OK, V6_RPC_INVALID, V6_RPC_RESOURCE };
enum v6_rpc_status transaction_v6_rpc_decode(const char *hex, struct json_value *result);
#endif
