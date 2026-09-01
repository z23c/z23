/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_CLIENT_H
#define ZCL_RPC_CLIENT_H

#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Decide whether positional CLI argument param_idx of `method` must be parsed
 * as JSON rather than passed through as a string. Backed by a static
 * (method, idx) table of every parameter that RPC handlers expect typed
 * (numbers, bools, arrays, objects). Returns true if the (method, param_idx)
 * pair is present in that table; false (pass-through as a string) otherwise.
 * O(table size) linear scan; method is matched by exact strcmp. */
bool rpc_should_convert_param(const char *method, int param_idx);

/* Build a JSON array of the `num_params` CLI string arguments in str_params,
 * suitable as the "params" of a JSON-RPC request for `method`. Each argument
 * either stays a JSON string (pass-through) or, when
 * rpc_should_convert_param(method, i) is true, is parsed as a JSON value
 * (number/bool/array/object). Parsing wraps the argument in [ ... ] and parses
 * a one-element array, so a bare token like 0 or true or {"a":1} is accepted.
 * On success initializes *result to the array and returns true; the caller owns
 * *result and must json_free it. On any parse failure (a convertible argument
 * that is not valid JSON, or an allocation failure) returns false; *result is
 * left partially built and must still be json_free'd by the caller. */
bool rpc_convert_values(const char *method, const char **str_params,
                        size_t num_params, struct json_value *result);

/* Print a JSON-RPC response body using Bitcoin-style CLI output semantics.
 * Returns 0 for a valid, non-error result; nonzero for empty, malformed,
 * missing-result, or JSON-RPC error bodies. */
int rpc_cli_print_json_result(const char *json_str, FILE *out, FILE *err);

/* JSON-RPC call to a local node (e.g., zclassicd on port 8232).
 * creds must be a literal "user:pass" string (base64-encoded internally
 * for the HTTP Basic auth header).
 * Returns bytes read, or -1 on error. Response includes HTTP headers. */
int rpc_call_local(int port, const char *creds,
                   const char *method, const char *params_json,
                   char *out, size_t outmax);

/* Skip HTTP headers, return pointer to body */
const char *rpc_http_body(const char *response);

#endif
