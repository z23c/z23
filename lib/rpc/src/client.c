/* Copyright (c) 2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "rpc/client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encoding/utilstrencodings.h"
#include "platform/socket_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct convert_param {
    const char *method;
    int idx;
};

static const struct convert_param convert_table[] = {
    { "stop", 0 },
    { "setmocktime", 0 },
    { "getaddednodeinfo", 0 },
    { "setgenerate", 0 },
    { "setgenerate", 1 },
    { "generate", 0 },
    { "getnetworkhashps", 0 },
    { "getnetworkhashps", 1 },
    { "getnetworksolps", 0 },
    { "getnetworksolps", 1 },
    { "sendtoaddress", 1 },
    { "sendtoaddress", 4 },
    { "settxfee", 0 },
    { "getreceivedbyaddress", 1 },
    { "listreceivedbyaddress", 0 },
    { "listreceivedbyaddress", 1 },
    { "listreceivedbyaddress", 2 },
    { "getbalance", 1 },
    { "getbalance", 2 },
    { "getblockhash", 0 },
    { "move", 2 },
    { "move", 3 },
    { "sendfrom", 2 },
    { "sendfrom", 3 },
    { "listtransactions", 1 },
    { "listtransactions", 2 },
    { "listtransactions", 3 },
    { "walletpassphrase", 1 },
    { "getblocktemplate", 0 },
    { "listsinceblock", 1 },
    { "listsinceblock", 2 },
    { "sendmany", 1 },
    { "sendmany", 2 },
    { "sendmany", 4 },
    { "addmultisigaddress", 0 },
    { "addmultisigaddress", 1 },
    { "createmultisig", 0 },
    { "createmultisig", 1 },
    { "listunspent", 0 },
    { "listunspent", 1 },
    { "listunspent", 2 },
    { "getblock", 1 },
    { "getblockheader", 1 },
    { "gettransaction", 1 },
    { "getrawtransaction", 1 },
    { "createrawtransaction", 0 },
    { "createrawtransaction", 1 },
    { "createrawtransaction", 2 },
    { "createrawtransaction", 3 },
    { "signrawtransaction", 1 },
    { "signrawtransaction", 2 },
    { "sendrawtransaction", 1 },
    { "fundrawtransaction", 1 },
    { "gettxout", 1 },
    { "gettxout", 2 },
    { "gettxoutproof", 0 },
    { "lockunspent", 0 },
    { "lockunspent", 1 },
    { "importprivkey", 2 },
    { "importprivkey", 3 },
    { "rescanblockchain", 0 },
    { "rescanblockchain", 1 },
    { "importaddress", 2 },
    { "verifychain", 0 },
    { "verifychain", 1 },
    { "keypoolrefill", 0 },
    { "getrawmempool", 0 },
    { "estimatefee", 0 },
    { "estimatepriority", 0 },
    { "prioritisetransaction", 1 },
    { "prioritisetransaction", 2 },
    { "setban", 2 },
    { "setban", 3 },
    { "getblocksubsidy", 0 },
    { "z_listaddresses", 0 },
    { "z_listreceivedbyaddress", 1 },
    { "z_listunspent", 0 },
    { "z_listunspent", 1 },
    { "z_listunspent", 2 },
    { "z_listunspent", 3 },
    { "z_getbalance", 1 },
    { "z_gettotalbalance", 0 },
    { "z_gettotalbalance", 1 },
    { "z_gettotalbalance", 2 },
    { "z_mergetoaddress", 0 },
    { "z_mergetoaddress", 2 },
    { "z_mergetoaddress", 3 },
    { "z_mergetoaddress", 4 },
    { "z_sendmany", 1 },
    { "z_sendmany", 2 },
    { "z_sendmany", 3 },
    { "z_shieldcoinbase", 2 },
    { "z_shieldcoinbase", 3 },
    { "z_getoperationstatus", 0 },
    { "z_getoperationresult", 0 },
    { "z_importkey", 2 },
    { "z_importviewingkey", 2 },
    { "z_getpaymentdisclosure", 1 },
    { "z_getpaymentdisclosure", 2 },
    /* Agent-session actions take a structured policy/custody object as their
     * second argument.  Without this row zclassic-cli quoted the JSON and the
     * node correctly refused it as "second param must be an object", forcing
     * agents to bypass the supported client for custody discovery. */
    { "agentsession", 1 }
};

#define NUM_CONVERT_PARAMS \
    (sizeof(convert_table) / sizeof(convert_table[0]))

bool rpc_should_convert_param(const char *method, int param_idx)
{
    for (size_t i = 0; i < NUM_CONVERT_PARAMS; i++)
        if (convert_table[i].idx == param_idx &&
            strcmp(convert_table[i].method, method) == 0)
            return true;
    return false;
}

bool rpc_convert_values(const char *method, const char **str_params,
                        size_t num_params, struct json_value *result)
{
    json_init(result);
    json_set_array(result);

    for (size_t i = 0; i < num_params; i++) {
        if (!rpc_should_convert_param(method, (int)i)) {
            struct json_value sv;
            json_init(&sv);
            json_set_str(&sv, str_params[i]);
            json_push_back(result, &sv);
            json_free(&sv);
        } else {
            struct json_value parsed;
            size_t len = strlen(str_params[i]);
            char *wrapped = zcl_malloc(len + 3, "rpc_wrapped_param");
            if (!wrapped) return false;
            wrapped[0] = '[';
            memcpy(wrapped + 1, str_params[i], len);
            wrapped[len + 1] = ']';
            wrapped[len + 2] = '\0';
            if (!json_read(&parsed, wrapped, len + 2) ||
                parsed.type != JSON_ARR || json_size(&parsed) != 1) {
                free(wrapped);
                json_free(&parsed);
                return false;
            }
            json_push_back(result, json_at(&parsed, 0));
            json_free(&parsed);
            free(wrapped);
        }
    }
    return true;
}

static int rpc_cli_print_json_value(const struct json_value *value,
                                    FILE *out, FILE *err)
{
    size_t cap = 4096;
    char *buf = zcl_malloc(cap, "rpc_cli_json_result");
    if (!buf) {
        fprintf(err, "Error: failed to allocate RPC result buffer\n");
        return 1;
    }

    size_t n = json_write(value, buf, cap);
    if (n >= cap) {
        if (n == (size_t)-1) {
            free(buf);
            fprintf(err, "Error: failed to serialize RPC result\n");
            return 1;
        }
        cap = n + 1;
        char *wide = zcl_malloc(cap, "rpc_cli_json_result_wide");
        if (!wide) {
            free(buf);
            fprintf(err, "Error: failed to allocate RPC result buffer\n");
            return 1;
        }
        free(buf);
        buf = wide;
        n = json_write(value, buf, cap);
        if (n >= cap) {
            free(buf);
            fprintf(err, "Error: failed to serialize RPC result\n");
            return 1;
        }
    }

    fprintf(out, "%s\n", buf);
    free(buf);
    return 0;
}

int rpc_cli_print_json_result(const char *json_str, FILE *out, FILE *err)
{
    if (!out)
        out = stdout;
    if (!err)
        err = stderr;
    if (!json_str || json_str[0] == '\0') {
        fprintf(err, "Error: empty RPC response\n");
        return 1;
    }

    struct json_value v;
    if (!json_read(&v, json_str, strlen(json_str))) {
        fprintf(err, "Error: invalid JSON-RPC response: %.200s\n",
                json_str);
        return 1;
    }

    const struct json_value *rpc_err = json_get(&v, "error");
    const struct json_value *res = json_get(&v, "result");

    if (rpc_err && rpc_err->type != JSON_NULL) {
        const struct json_value *msg = json_get(rpc_err, "message");
        if (msg && msg->type == JSON_STR) {
            fprintf(err, "Error: %s\n", json_get_str(msg));
        } else {
            fprintf(err, "Error: ");
            rpc_cli_print_json_value(rpc_err, err, err);
        }
        json_free(&v);
        return 1;
    }

    if (!res) {
        fprintf(err, "Error: missing result in JSON-RPC response\n");
        json_free(&v);
        return 1;
    }

    int rc = 0;
    if (res->type == JSON_STR) {
        fprintf(out, "%s\n", json_get_str(res));
    } else if (res->type == JSON_INT) {
        fprintf(out, "%lld\n", (long long)json_get_int(res));
    } else if (res->type == JSON_REAL) {
        fprintf(out, "%.8f\n", json_get_real(res));
    } else if (res->type == JSON_BOOL) {
        fprintf(out, "%s\n", json_get_bool(res) ? "true" : "false");
    } else if (res->type == JSON_NULL) {
        fprintf(out, "null\n");
    } else {
        rc = rpc_cli_print_json_value(res, out, err);
    }
    json_free(&v);
    return rc;
}

/* ── Shared RPC caller for local node communication ────────────── */

int rpc_call_local(int port, const char *creds,
                   const char *method, const char *params_json,
                   char *out, size_t outmax)
{
    if (port < 1 || port > UINT16_MAX || !creds || !method || !params_json ||
        !out || outmax == 0)
        return -1;

    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                   true, false);
    if (sock == PLATFORM_SOCKET_INVALID) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (platform_socket_parse_address(AF_INET, "127.0.0.1",
                                      &addr.sin_addr) != 1) {
        platform_socket_close(sock);
        return -1;
    }
    addr.sin_port = htons((uint16_t)port);

    if (platform_socket_set_receive_timeout(sock, 30000) != 0 ||
        platform_socket_set_send_timeout(sock, 30000) != 0) {
        platform_socket_close(sock);
        return -1;
    }

    if (platform_socket_connect(sock, (struct sockaddr *)&addr,
                                sizeof(addr)) != 0) {
        platform_socket_close(sock);
        return -1;
    }

    char body[4096];
    int blen = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params_json);
    if (blen < 0 || blen >= (int)sizeof(body)) {
        platform_socket_close(sock);
        LOG_ERR("rpc", "local rpc body truncated: len=%d cap=%zu",
                blen, sizeof(body));
    }
    size_t body_len = strlen(body);

    /* HTTP Basic auth: base64("user:pass") */
    char auth_b64[256];
    EncodeBase64((const unsigned char *)creds, strlen(creds),
                 auth_b64, sizeof(auth_b64));

    char req[8192];
    int rlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
        auth_b64, body_len, body);
    if (rlen < 0 || rlen >= (int)sizeof(req)) {
        platform_socket_close(sock);
        LOG_ERR("rpc", "local rpc request truncated: len=%d cap=%zu",
                rlen, sizeof(req));
    }

    if (!platform_socket_send_all(sock, req, (size_t)rlen)) {
        platform_socket_close(sock);
        return -1;
    }

    size_t total = 0;
    while (total < outmax - 1) {
        int r = platform_socket_receive(sock, out + total,
                                        outmax - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    out[total] = '\0';
    platform_socket_close(sock);
    return (int)total;
}

const char *rpc_http_body(const char *response)
{
    const char *p = strstr(response, "\r\n\r\n");
    return p ? p + 4 : response;
}
