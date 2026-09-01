/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_PROTOCOL_H
#define ZCL_RPC_PROTOCOL_H

#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>

enum http_status_code {
    HTTP_OK                    = 200,
    HTTP_BAD_REQUEST           = 400,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_NOT_FOUND             = 404,
    HTTP_BAD_METHOD            = 405,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_SERVICE_UNAVAILABLE   = 503
};

enum rpc_error_code {
    RPC_INVALID_REQUEST  = -32600,
    RPC_METHOD_NOT_FOUND = -32601,
    RPC_INVALID_PARAMS   = -32602,
    RPC_INTERNAL_ERROR   = -32603,
    RPC_PARSE_ERROR      = -32700,

    RPC_MISC_ERROR                  = -1,
    RPC_FORBIDDEN_BY_SAFE_MODE      = -2,
    RPC_TYPE_ERROR                  = -3,
    RPC_INVALID_ADDRESS_OR_KEY      = -5,
    RPC_OUT_OF_MEMORY               = -7,
    RPC_INVALID_PARAMETER           = -8,
    RPC_DATABASE_ERROR              = -20,
    RPC_DESERIALIZATION_ERROR       = -22,
    RPC_VERIFY_ERROR                = -25,
    RPC_VERIFY_REJECTED             = -26,
    RPC_VERIFY_ALREADY_IN_CHAIN     = -27,
    RPC_IN_WARMUP                   = -28,

    RPC_CLIENT_NOT_CONNECTED        = -9,
    RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10,
    RPC_CLIENT_NODE_ALREADY_ADDED   = -23,
    RPC_CLIENT_NODE_NOT_ADDED       = -24,
    RPC_CLIENT_NODE_NOT_CONNECTED   = -29,
    RPC_CLIENT_INVALID_IP_OR_SUBNET = -30,

    RPC_WALLET_ERROR                = -4,
    RPC_WALLET_INSUFFICIENT_FUNDS   = -6,
    RPC_WALLET_ACCOUNTS_UNSUPPORTED = -11,
    RPC_WALLET_KEYPOOL_RAN_OUT      = -12,
    RPC_WALLET_UNLOCK_NEEDED        = -13,
    RPC_WALLET_PASSPHRASE_INCORRECT = -14,
    RPC_WALLET_WRONG_ENC_STATE      = -15,
    RPC_WALLET_ENCRYPTION_FAILED    = -16,
    RPC_WALLET_ALREADY_UNLOCKED     = -17
};

/* Serialize a JSON-RPC request {"method":...,"params":...,"id":...} into out.
 * params and id are referenced as-is (not copied/escaped beyond JSON encoding).
 * The body is written, then a single '\n' terminator is appended and out is
 * NUL-terminated when there is room (out_size leaves 2 bytes for "\n\0").
 * Returns the body length plus one (the count of bytes written including the
 * newline, excluding the NUL). Truncates silently if out_size is too small. */
size_t json_rpc_request(const char *method,
                        const struct json_value *params,
                        const struct json_value *id,
                        char *out, size_t out_size);

void json_rpc_error(struct json_value *out, int code, const char *message);

/* Extended error object: {code, message, method}.
 * method may be NULL (omitted from output). */
void json_rpc_error_full(struct json_value *out, int code,
                         const char *message, const char *method);

/* Write a complete JSON-RPC error response string:
 *   {"result":null,"error":{"code":N,"message":"...","method":"..."},"id":V}
 * method may be NULL.  id_json may be NULL (emits "null").
 * Returns bytes written (excluding NUL). */
size_t json_rpc_error_response(char *buf, size_t buflen, int code,
                               const char *message, const char *method,
                               const char *id_json);

#endif
