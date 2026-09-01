/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * How a JSON-RPC reply is shaped and turned into bytes.
 *
 * Split out of httpserver.c because neither step touches a socket, a
 * thread, the admission queue or any credential: they take a json_value
 * and give back an envelope or a sized buffer. Keeping them in their own
 * translation unit means the two functions the regression test drives
 * have no module state behind them at all — production and the test run
 * the same code because there is nothing else it could run. */

#include "rpc/httpserver.h"

#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdlib.h>

/* Upper bound on a single serialized JSON-RPC response body. Generous
 * enough for the largest legitimate responses (gettxoutsetinfo, a full
 * listunspent / getrawmempool true) while bounding the one-shot
 * allocation an authenticated client can drive. A response that would
 * exceed this returns a proper RPC error envelope instead of a partial
 * or out-of-band send. */
#define RPC_HTTP_MAX_RESP_BYTES ((size_t)128 * 1024 * 1024)

bool rpc_http_test_build_response_envelope(bool rpc_ok,
                                           const char *method,
                                           struct json_value *rpc_result,
                                           const struct json_value *id,
                                           struct json_value *response)
{
    struct json_value null_err = {0};
    struct json_value null_res = {0};
    bool ok = true;

    if (!rpc_result || !id || !response)
        return false;

    json_init(response);
    json_set_object(response);

    if (rpc_ok) {
        ok = ok && json_push_kv(response, "result", rpc_result);
        json_set_null(&null_err);
        ok = ok && json_push_kv(response, "error", &null_err);
        json_free(&null_err);
    } else {
        json_set_null(&null_res);
        ok = ok && json_push_kv(response, "result", &null_res);
        json_free(&null_res);
        if (rpc_result->type == JSON_OBJ)
            ok = ok && json_push_kv_str(rpc_result, "method",
                                        method ? method : "");
        ok = ok && json_push_kv(response, "error", rpc_result);
    }

    ok = ok && json_push_kv(response, "id", id);
    return ok;
}

/* Two-pass serialization of a JSON-RPC response. json_write() returns
 * the FULL required length regardless of the buffer it is handed (it
 * only writes where pos < buflen, and a zero-length buffer is never
 * dereferenced), so we size first with a zero-length probe, reject
 * anything past RPC_HTTP_MAX_RESP_BYTES, then allocate exactly len+1
 * and write the body. This replaces the old fixed 4 MiB buffer whose
 * unclamped length was fed straight to write() — for a response larger
 * than the buffer that read (len - 4 MiB) bytes past the allocation and
 * shipped adjacent heap memory to the client (crash/DoS + info-leak).
 *
 * On success: *out_buf owns a heap buffer the caller must free(), and
 * *out_len is the exact body length to send. Returns false (with
 * *out_buf == NULL) on OOM or when the response exceeds the cap; the
 * caller sends a proper RPC error envelope instead.
 *
 * Exposed (non-static) so the regression test exercises the exact same
 * sizing path the HTTP response uses — same convention as
 * rpc_http_test_build_response_envelope above. */
bool rpc_http_test_serialize_response(const struct json_value *response,
                                      char **out_buf, size_t *out_len)
{
    if (!response || !out_buf || !out_len) {
        if (out_buf) *out_buf = NULL;
        if (out_len) *out_len = 0;
        return false;
    }
    *out_buf = NULL;
    *out_len = 0;

    /* Pass 1: size the body without writing (zero-length buffer). */
    size_t need = json_write(response, NULL, 0);
    if (need > RPC_HTTP_MAX_RESP_BYTES) {
        LOG_FAIL("rpc", "response too large: %zu > %zu bytes", need,
                 RPC_HTTP_MAX_RESP_BYTES);
        return false;
    }

    char *buf = zcl_malloc(need + 1, "http_resp_buf");
    if (!buf) {
        LOG_FAIL("rpc", "response buffer alloc failed: %zu bytes", need + 1);
        return false;
    }

    /* Pass 2: write exactly into a buffer sized to hold the whole body.
     * json_write writes the NUL only when pos < buflen; need+1 guarantees
     * room for it, and the returned length is the body length to send. */
    size_t wrote = json_write(response, buf, need + 1);
    if (wrote != need) {
        /* Should be impossible (the two passes serialize the same value),
         * but never ship a length that disagrees with what we wrote. Free
         * before logging since LOG_FAIL returns. */
        free(buf);
        LOG_FAIL("rpc", "response size mismatch: sized %zu wrote %zu", need,
                 wrote);
    }

    *out_buf = buf;
    *out_len = wrote;
    return true;
}
