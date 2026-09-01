/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "rpc/protocol.h"
#include <stdio.h>
#include <string.h>

size_t json_rpc_request(const char *method,
                        const struct json_value *params,
                        const struct json_value *id,
                        char *out, size_t out_size)
{
    struct json_value req;
    json_init(&req);
    json_set_object(&req);
    json_push_kv_str(&req, "method", method);
    json_push_kv(&req, "params", params);
    json_push_kv(&req, "id", id);
    size_t n = json_write(&req, out, out_size > 1 ? out_size - 2 : 0);
    if (n + 1 < out_size) { out[n] = '\n'; out[n + 1] = '\0'; }
    json_free(&req);
    return n + 1;
}

void json_rpc_error(struct json_value *out, int code, const char *message)
{
    json_init(out);
    json_set_object(out);
    json_push_kv_int(out, "code", code);
    json_push_kv_str(out, "message", message);
}

void json_rpc_error_full(struct json_value *out, int code,
                         const char *message, const char *method)
{
    json_init(out);
    json_set_object(out);
    json_push_kv_int(out, "code", code);
    json_push_kv_str(out, "message", message);
    if (method)
        json_push_kv_str(out, "method", method);
}

size_t json_rpc_error_response(char *buf, size_t buflen, int code,
                               const char *message, const char *method,
                               const char *id_json)
{
    if (!buf || buflen == 0) return 0;
    size_t pos = 0;
    int n;
    if (method) {
        n = snprintf(buf + pos, buflen - pos,
                     "{\"result\":null,\"error\":{\"code\":%d,"
                     "\"message\":\"%s\",\"method\":\"%s\"},\"id\":%s}",
                     code, message ? message : "",
                     method, id_json ? id_json : "null");
    } else {
        n = snprintf(buf + pos, buflen - pos,
                     "{\"result\":null,\"error\":{\"code\":%d,"
                     "\"message\":\"%s\"},\"id\":%s}",
                     code, message ? message : "",
                     id_json ? id_json : "null");
    }
    if (n < 0) return 0;
    return (size_t)n < buflen ? (size_t)n : buflen - 1;
}

