/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Legacy-node JSON-RPC client. See header for the contract.
 *
 * The conf parser and HTTP/1.1 wire path were unified here from
 * header_probe.c (hp_parse_zclassic_conf, hp_http_rpc_call_dyn) so
 * legacy_body_pull shares one transport. Base64 for the Basic-auth
 * header comes from the canonical EncodeBase64. */

#include "rpc/legacy_rpc_client.h"

#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/socket_compat.h"
#include "rpc/zclassicd_port.h"
#include "util/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LRC_TIMEOUT_SECS    5
#define LRC_TIMEOUT_MAX_MS  60000u
/* 8 MB hard cap. A full getblock verbose=0 response is the serialized
 * block as hex (≤2 MB consensus block → ≤4 MB hex) plus the JSON-RPC
 * envelope; 8 MB leaves comfortable headroom for the largest block.
 * This is a bridge/oracle transport, not a consensus path. */
#define LRC_RESP_MAX        (8u << 20)

/* ── zclassic.conf parser ──────────────────────────────────────── */

bool legacy_rpc_parse_conf(char *out_user, size_t user_sz,
                           char *out_pass, size_t pass_sz,
                           int *out_port)
{
    const char *home = getenv("HOME");
    if (!home || !home[0]) return false;

    char path[512];
    snprintf(path, sizeof(path), "%s/.zclassic/zclassic.conf", home);
    FILE *f = fopen(path, "r");
    if (!f) return false;

    char line[512];
    bool got_user = false, got_pass = false;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *val = eq + 1;
        char *kend = eq - 1;
        while (kend > key && (*kend == ' ' || *kend == '\t')) *kend-- = '\0';
        while (*val == ' ' || *val == '\t') val++;
        char *vend = val + strlen(val);
        while (vend > val && (vend[-1] == '\n' || vend[-1] == '\r' ||
                              vend[-1] == ' '  || vend[-1] == '\t'))
            *--vend = '\0';

        if (strcmp(key, "rpcuser") == 0) {
            snprintf(out_user, user_sz, "%s", val);
            got_user = true;
        } else if (strcmp(key, "rpcpassword") == 0) {
            snprintf(out_pass, pass_sz, "%s", val);
            got_pass = true;
        } else if (strcmp(key, "rpcport") == 0 && out_port) {
            int n = atoi(val);
            if (n > 0 && n < 65536) *out_port = n;
        }
    }
    fclose(f);
    return got_user && got_pass;
}

bool legacy_rpc_fill_missing_creds(char *user, size_t user_sz,
                                   char *pass, size_t pass_sz,
                                   int *port, bool port_is_explicit)
{
    bool need_user = !user || user_sz == 0 || user[0] == '\0';
    bool need_pass = !pass || pass_sz == 0 || pass[0] == '\0';
    if (!need_user && !need_pass)
        return true;

    int conf_port = port ? *port : 0;
    char u[64] = {0}, p[128] = {0};
    if (legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), &conf_port)) {
        if (need_user && user && user_sz)
            snprintf(user, user_sz, "%s", u);
        if (need_pass && pass && pass_sz)
            snprintf(pass, pass_sz, "%s", p);
        if (port && !port_is_explicit)
            *port = conf_port;
    }

    return user && user[0] != '\0' && pass && pass[0] != '\0';
}

/* ── HTTP/1.1 JSON-RPC call ────────────────────────────────────── */

bool legacy_rpc_authenticated_call(const char *body_json,
                                   char **out_resp,
                                   char *err, size_t err_sz)
{
    return legacy_rpc_authenticated_call_with_timeout(
        body_json, LRC_TIMEOUT_SECS * 1000u, out_resp, err, err_sz);
}

bool legacy_rpc_authenticated_call_with_timeout(const char *body_json,
                                                uint32_t timeout_ms,
                                                char **out_resp,
                                                char *err, size_t err_sz)
{
    char user[128] = {0};
    char pass[256] = {0};
    int port = ZCLASSICD_RPC_DEFAULT_PORT;

    if (out_resp) *out_resp = NULL;
    if (!body_json || !out_resp) {
        if (err && err_sz) snprintf(err, err_sz, "bad args");
        return false;
    }
    if (!legacy_rpc_parse_conf(user, sizeof(user), pass, sizeof(pass),
                               &port)) {
        if (err && err_sz)
            snprintf(err, err_sz, "missing zclassicd rpc credentials");
        return false;
    }

    return legacy_rpc_call_with_timeout("127.0.0.1", port, user, pass,
                                        body_json, timeout_ms, out_resp,
                                        err, err_sz);
}

bool legacy_rpc_call(const char *host, int port,
                     const char *user, const char *pass,
                     const char *body_json,
                     char **out_resp,
                     char *err, size_t err_sz)
{
    return legacy_rpc_call_with_timeout(host, port, user, pass, body_json,
                                        LRC_TIMEOUT_SECS * 1000u, out_resp,
                                        err, err_sz);
}

bool legacy_rpc_call_with_timeout(const char *host, int port,
                                  const char *user, const char *pass,
                                  const char *body_json,
                                  uint32_t timeout_ms,
                                  char **out_resp,
                                  char *err, size_t err_sz)
{
    if (out_resp) *out_resp = NULL;
    if (!host || port < 1 || port > UINT16_MAX || !body_json || !out_resp ||
        timeout_ms == 0 || timeout_ms > LRC_TIMEOUT_MAX_MS) {
        if (err && err_sz) snprintf(err, err_sz, "bad args");
        return false;
    }

    platform_socket_t sock = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                   true, false);
    if (sock == PLATFORM_SOCKET_INVALID) {
        char detail[64];
        snprintf(err, err_sz, "socket: %s",
                 platform_socket_error_string(platform_socket_last_error(),
                                              detail, sizeof(detail)));
        return false;
    }
    (void)platform_socket_set_receive_timeout(sock, timeout_ms);
    (void)platform_socket_set_send_timeout(sock, timeout_ms);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (platform_socket_parse_address(AF_INET, host, &sa.sin_addr) != 1) {
        platform_socket_close(sock);
        snprintf(err, err_sz, "bad host: %s", host);
        return false;
    }
    if (platform_socket_connect(sock, (struct sockaddr *)&sa,
                                sizeof(sa)) != 0) {
        char detail[64];
        snprintf(err, err_sz, "connect %s:%d: %s",
                 host, port,
                 platform_socket_error_string(platform_socket_last_error(),
                                              detail, sizeof(detail)));
        platform_socket_close(sock);
        return false;
    }

    char userpass[256];
    snprintf(userpass, sizeof(userpass), "%s:%s",
             user ? user : "", pass ? pass : "");
    char b64[384];
    EncodeBase64((const unsigned char *)userpass, strlen(userpass),
                 b64, sizeof(b64));

    size_t body_len = strlen(body_json);
    size_t req_cap  = 768 + body_len;
    char *req = zcl_malloc(req_cap, "lrc_req");
    if (!req) {
        platform_socket_close(sock);
        snprintf(err, err_sz, "oom req");
        return false;
    }
    int reqlen = snprintf(req, req_cap,
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: engine/application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        host, port, b64, body_len, body_json);
    if (reqlen < 0 || (size_t)reqlen >= req_cap) {
        free(req); platform_socket_close(sock);
        snprintf(err, err_sz, "request buffer overflow");
        return false;
    }
    if (!platform_socket_send_all(sock, req, (size_t)reqlen)) {
        char detail[64];
        snprintf(err, err_sz, "send: %s",
                 platform_socket_error_string(platform_socket_last_error(),
                                              detail, sizeof(detail)));
        free(req); platform_socket_close(sock); return false;
    }
    free(req);

    size_t cap = 64 << 10;
    size_t total = 0;
    char *buf = zcl_malloc(cap, "lrc_resp");
    if (!buf) {
        platform_socket_close(sock);
        snprintf(err, err_sz, "oom resp");
        return false;
    }
    for (;;) {
        if (total + 1 >= cap) {
            if (cap >= LRC_RESP_MAX) {
                snprintf(err, err_sz, "response > %u byte cap", LRC_RESP_MAX);
                free(buf); platform_socket_close(sock); return false;
            }
            size_t ncap = cap * 2;
            if (ncap > LRC_RESP_MAX) ncap = LRC_RESP_MAX;
            char *nbuf = zcl_realloc(buf, ncap, "lrc_resp");
            if (!nbuf) {
                snprintf(err, err_sz, "oom resp grow");
                free(buf); platform_socket_close(sock); return false;
            }
            buf = nbuf;
            cap = ncap;
        }
        int n = platform_socket_receive(sock, buf + total, cap - total - 1);
        if (n < 0) {
            char detail[64];
            snprintf(err, err_sz, "recv: %s",
                     platform_socket_error_string(platform_socket_last_error(),
                                                  detail, sizeof(detail)));
            free(buf); platform_socket_close(sock); return false;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    platform_socket_close(sock);

    if (total == 0) {
        snprintf(err, err_sz, "empty response");
        free(buf);
        return false;
    }

    *out_resp = buf;
    return true;
}

/* ── HTTP body locator ─────────────────────────────────────────── */

const char *legacy_rpc_http_body(const char *raw)
{
    if (!raw) return NULL;
    const char *p = strstr(raw, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

/* ── JSON-RPC result parsers ───────────────────────────────────── */

static void lrc_set_error(char *err, size_t err_sz, const char *fmt, ...)
{
    if (!err || err_sz == 0)
        return;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_sz, fmt, ap);
    va_end(ap);
}

static bool lrc_error_message(const struct json_value *root,
                              char *err, size_t err_sz,
                              const char *fallback)
{
    const struct json_value *jerr = json_get(root, "error");
    if (jerr && jerr->type == JSON_OBJ) {
        const struct json_value *code = json_get(jerr, "code");
        const struct json_value *msg = json_get(jerr, "message");
        if (code && code->type == JSON_INT && msg && msg->type == JSON_STR) {
            lrc_set_error(err, err_sz, "rpc error %lld: %s",
                          (long long)json_get_int(code), json_get_str(msg));
            return true;
        }
        if (msg && msg->type == JSON_STR) {
            lrc_set_error(err, err_sz, "rpc error: %s", json_get_str(msg));
            return true;
        }
        if (code && code->type == JSON_INT) {
            lrc_set_error(err, err_sz, "rpc error %lld",
                          (long long)json_get_int(code));
            return true;
        }
    }
    lrc_set_error(err, err_sz, "%s", fallback);
    return false;
}

static bool lrc_read_response_json(const char *raw,
                                   struct json_value *out,
                                   char *err, size_t err_sz)
{
    const char *body = legacy_rpc_http_body(raw);
    if (!body) {
        lrc_set_error(err, err_sz, "no http body separator");
        return false;
    }
    if (!json_read(out, body, strlen(body))) {
        lrc_set_error(err, err_sz, "json parse failed");
        json_free(out);
        return false;
    }
    return true;
}

bool legacy_rpc_parse_result_int(const char *raw,
                                 int64_t *out,
                                 char *err, size_t err_sz)
{
    if (!out) {
        lrc_set_error(err, err_sz, "bad integer output pointer");
        return false;
    }
    struct json_value v = {0};
    if (!lrc_read_response_json(raw, &v, err, err_sz)) return false;

    const struct json_value *result = json_get(&v, "result");
    if (!result || result->type != JSON_INT) {
        lrc_error_message(&v, err, err_sz, "no .result or wrong type");
        json_free(&v);
        return false;
    }

    *out = json_get_int(result);
    json_free(&v);
    return true;
}

bool legacy_rpc_parse_result_string(const char *raw,
                                    char *out, size_t out_sz,
                                    char *err, size_t err_sz)
{
    if (!out || out_sz == 0) {
        lrc_set_error(err, err_sz, "bad string output buffer");
        return false;
    }
    struct json_value v = {0};
    if (!lrc_read_response_json(raw, &v, err, err_sz)) return false;

    const struct json_value *result = json_get(&v, "result");
    if (!result || result->type != JSON_STR) {
        lrc_error_message(&v, err, err_sz, "no .result or wrong type");
        json_free(&v);
        return false;
    }

    const char *s = json_get_str(result);
    size_t slen = s ? strlen(s) : 0;
    if (slen + 1 > out_sz) {
        lrc_set_error(err, err_sz, "result string too long (%zu)", slen);
        json_free(&v);
        return false;
    }
    memcpy(out, s ? s : "", slen);
    out[slen] = '\0';
    json_free(&v);
    return true;
}

bool legacy_rpc_parse_result_string_array(const char *raw,
                                          int expected,
                                          char *out_strs,
                                          size_t slot_sz,
                                          char *err, size_t err_sz)
{
    if (expected < 0 || (!out_strs && expected > 0) || slot_sz == 0) {
        lrc_set_error(err, err_sz, "bad array output buffer");
        return false;
    }
    struct json_value v = {0};
    if (!lrc_read_response_json(raw, &v, err, err_sz)) return false;

    if (v.type != JSON_ARR) {
        lrc_set_error(err, err_sz, "response not a JSON array");
        json_free(&v);
        return false;
    }
    if ((int)v.num_children != expected) {
        lrc_set_error(err, err_sz, "array len %zu != expected %d",
                      v.num_children, expected);
        json_free(&v);
        return false;
    }

    for (int i = 0; i < expected; i++) {
        const struct json_value *item = json_at(&v, (size_t)i);
        if (!item || item->type != JSON_OBJ) {
            lrc_set_error(err, err_sz, "item[%d] not an object", i);
            json_free(&v);
            return false;
        }
        const struct json_value *r = json_get(item, "result");
        if (!r || r->type != JSON_STR) {
            const struct json_value *jerr = json_get(item, "error");
            const char *msg = "no string result";
            if (jerr && jerr->type == JSON_OBJ) {
                const struct json_value *m = json_get(jerr, "message");
                if (m && m->type == JSON_STR) msg = json_get_str(m);
            }
            lrc_set_error(err, err_sz, "item[%d] rpc error: %s", i, msg);
            json_free(&v);
            return false;
        }

        const char *s = json_get_str(r);
        size_t slen = s ? strlen(s) : 0;
        if (slen + 1 > slot_sz) {
            lrc_set_error(err, err_sz, "item[%d] string too long (%zu > %zu)",
                          i, slen, slot_sz);
            json_free(&v);
            return false;
        }
        char *dst = out_strs + (size_t)i * slot_sz;
        memcpy(dst, s ? s : "", slen);
        dst[slen] = '\0';
    }

    json_free(&v);
    return true;
}
