/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: allowlist and non-blocking peek classifier for the RPC reserved
 * fast lane. */

#include "httpserver_fastlane.h"

#include "rpc/httpserver.h"
#include "rpc/protocol.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#endif

#define FASTLANE_PEEK_CAP 4096

/* dumpstate status_frontdoor composes only atomics, trylock reads and the
 * in-memory blocker registry (engine/controllers/src/status_frontdoor.c,
 * guarded by the check_dumper_never_blocks lint). Other dumpstate keys are
 * not proven lock-free and stay on the general workers. */
bool rpc_http_fastlane_allows(const char *method,
                              const struct json_value *params)
{
    if (method == NULL || params == NULL || strcmp(method, "dumpstate") != 0)
        return false;
    if (params->type != JSON_ARR || json_size(params) != 1)
        return false;
    const char *key = json_get_str(json_at(params, 0));
    return key != NULL && strcmp(key, "status_frontdoor") == 0;
}

bool rpc_http_test_fastlane_allows(const char *method, const char *params_json)
{
    struct json_value params;
    json_init(&params);
    bool ok = params_json != NULL &&
              json_read(&params, params_json, strlen(params_json)) &&
              rpc_http_fastlane_allows(method, &params);
    json_free(&params);
    return ok;
}

/* Content-Length of the header block [buf, buf+hdr_len), or -1. */
static long fastlane_content_length(const char *buf, size_t hdr_len)
{
    for (const char *p = buf; p < buf + hdr_len; ) {
        const char *eol = memchr(p, '\n', (size_t)(buf + hdr_len - p));
        if (eol == NULL)
            break;
        if ((size_t)(eol - p) > 15 && strncasecmp(p, "Content-Length:", 15) == 0)
            return strtol(p + 15, NULL, 10);
        p = eol + 1;
    }
    return -1;
}

static bool fastlane_body_allowed(const char *body, size_t len)
{
    struct json_value request;
    json_init(&request);
    struct json_request req;
    json_request_init(&req);
    bool allowed = json_read(&request, body, len) &&
                   json_request_parse(&req, &request) &&
                   rpc_http_fastlane_allows(req.method, &req.params);
    json_request_free(&req);
    json_free(&request);
    return allowed;
}

bool rpc_http_fastlane_conn_matches(const struct rpc_conn *conn)
{
#if defined(_WIN32)
    (void)conn;
    return false;
#else
    if (conn->ssl != NULL || conn->fd == PLATFORM_SOCKET_INVALID)
        return false;
    char buf[FASTLANE_PEEK_CAP + 1];
    ssize_t got = recv(conn->fd, buf, FASTLANE_PEEK_CAP,
                       MSG_PEEK | MSG_DONTWAIT);
    if (got < 5)
        return false;
    buf[got] = 0;
    if (strncmp(buf, "POST ", 5) != 0)
        return false;
    const char *end = strstr(buf, "\r\n\r\n");
    if (end == NULL)
        return false;
    size_t hdr_len = (size_t)(end - buf) + 4;
    long clen = fastlane_content_length(buf, hdr_len);
    if (clen <= 0 || (size_t)clen > (size_t)got - hdr_len)
        return false;
    return fastlane_body_allowed(buf + hdr_len, (size_t)clen);
#endif
}
