/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for RPC error envelope consistency (wave 10 #8).
 * Verifies that json_rpc_error, json_rpc_error_full, and
 * json_rpc_error_response all produce the target shape:
 *   {error: {code, message[, method]}}
 */

#include "test/test_core.h"
#include "rpc/protocol.h"
#include "rpc/httpserver.h"
#include "json/json.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int test_rpc_error_envelope(void)
{
    int failures = 0;

    /* ── json_rpc_error: basic {code, message} ──────────────── */

    printf("rpc_error basic shape... ");
    {
        struct json_value err;
        json_rpc_error(&err, -32601, "Method not found");
        bool ok = err.type == JSON_OBJ;
        const struct json_value *code = json_get(&err, "code");
        const struct json_value *msg = json_get(&err, "message");
        ok = ok && code && code->type == JSON_INT && json_get_int(code) == -32601;
        ok = ok && msg && msg->type == JSON_STR
                && strcmp(json_get_str(msg), "Method not found") == 0;
        /* No method field in basic version */
        ok = ok && json_get(&err, "method") == NULL;
        json_free(&err);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── json_rpc_error_full: {code, message, method} ────────── */

    printf("rpc_error_full with method... ");
    {
        struct json_value err;
        json_rpc_error_full(&err, -32601, "Method not found", "getinfo");
        bool ok = err.type == JSON_OBJ;
        const struct json_value *code = json_get(&err, "code");
        const struct json_value *msg = json_get(&err, "message");
        const struct json_value *meth = json_get(&err, "method");
        ok = ok && code && json_get_int(code) == -32601;
        ok = ok && msg && strcmp(json_get_str(msg), "Method not found") == 0;
        ok = ok && meth && strcmp(json_get_str(meth), "getinfo") == 0;
        json_free(&err);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_error_full with NULL method omits field... ");
    {
        struct json_value err;
        json_rpc_error_full(&err, -32700, "Parse error", NULL);
        bool ok = err.type == JSON_OBJ;
        ok = ok && json_get(&err, "code") != NULL;
        ok = ok && json_get(&err, "message") != NULL;
        ok = ok && json_get(&err, "method") == NULL;
        json_free(&err);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── json_rpc_error_response: full string output ──────────── */

    printf("error_response with method produces valid JSON... ");
    {
        char buf[512];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            -32601, "Method not found", "getinfo", "1");
        bool ok = n > 0 && n < sizeof(buf);
        /* Parse and verify structure */
        struct json_value v;
        ok = ok && json_read(&v, buf, n);
        if (ok) {
            const struct json_value *res = json_get(&v, "result");
            const struct json_value *err = json_get(&v, "error");
            const struct json_value *id = json_get(&v, "id");
            ok = ok && res && res->type == JSON_NULL;
            ok = ok && err && err->type == JSON_OBJ;
            ok = ok && id && json_get_int(id) == 1;
            if (err && err->type == JSON_OBJ) {
                ok = ok && json_get_int(json_get(err, "code")) == -32601;
                const struct json_value *m = json_get(err, "message");
                ok = ok && m && strcmp(json_get_str(m), "Method not found") == 0;
                const struct json_value *mt = json_get(err, "method");
                ok = ok && mt && strcmp(json_get_str(mt), "getinfo") == 0;
            }
        }
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("error_response without method omits method field... ");
    {
        char buf[512];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            -32700, "Parse error", NULL, NULL);
        bool ok = n > 0;
        struct json_value v;
        ok = ok && json_read(&v, buf, n);
        if (ok) {
            const struct json_value *err = json_get(&v, "error");
            ok = ok && err && err->type == JSON_OBJ;
            if (err) {
                ok = ok && json_get_int(json_get(err, "code")) == -32700;
                ok = ok && json_get(err, "method") == NULL;
            }
            const struct json_value *id = json_get(&v, "id");
            ok = ok && id && id->type == JSON_NULL;
        }
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("error_response with string id... ");
    {
        char buf[512];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            -32600, "Invalid request", NULL, "\"abc\"");
        bool ok = n > 0;
        struct json_value v;
        ok = ok && json_read(&v, buf, n);
        if (ok) {
            const struct json_value *id = json_get(&v, "id");
            ok = ok && id && id->type == JSON_STR
                  && strcmp(json_get_str(id), "abc") == 0;
        }
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Error code constants ─────────────────────────────────── */

    printf("RPC error code constants match JSON-RPC spec... ");
    {
        bool ok = (RPC_PARSE_ERROR == -32700);
        ok = ok && (RPC_INVALID_REQUEST == -32600);
        ok = ok && (RPC_METHOD_NOT_FOUND == -32601);
        ok = ok && (RPC_INVALID_PARAMS == -32602);
        ok = ok && (RPC_INTERNAL_ERROR == -32603);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── All pre-dispatch error shapes ─────────────────────────── */

    printf("ban error: has code + message... ");
    {
        char buf[256];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            -32003, "IP banned", NULL, NULL);
        struct json_value v;
        bool ok = json_read(&v, buf, n);
        if (ok) {
            const struct json_value *err = json_get(&v, "error");
            ok = ok && err && err->type == JSON_OBJ;
            ok = ok && json_get(err, "code") != NULL;
            ok = ok && json_get(err, "message") != NULL;
            ok = ok && json_get(&v, "result") != NULL;
        }
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rate limit error: has code + message... ");
    {
        char buf[256];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            -32005, "Rate limit exceeded", NULL, NULL);
        struct json_value v;
        bool ok = json_read(&v, buf, n);
        if (ok) {
            const struct json_value *err = json_get(&v, "error");
            ok = ok && err && err->type == JSON_OBJ;
            ok = ok && json_get_int(json_get(err, "code")) == -32005;
        }
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("warmup error: includes method field... ");
    {
        struct json_value err;
        json_rpc_error_full(&err, RPC_IN_WARMUP, "Loading block index...",
                            "getblockcount");
        bool ok = err.type == JSON_OBJ;
        const struct json_value *meth = json_get(&err, "method");
        ok = ok && meth && strcmp(json_get_str(meth), "getblockcount") == 0;
        ok = ok && json_get_int(json_get(&err, "code")) == RPC_IN_WARMUP;
        json_free(&err);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("method-not-found error: includes method field... ");
    {
        struct json_value err;
        json_rpc_error_full(&err, RPC_METHOD_NOT_FOUND, "Method not found",
                            "nonexistent");
        bool ok = err.type == JSON_OBJ;
        const struct json_value *meth = json_get(&err, "method");
        ok = ok && meth && strcmp(json_get_str(meth), "nonexistent") == 0;
        json_free(&err);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("OOM error: includes method when available... ");
    {
        char buf[512];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            RPC_OUT_OF_MEMORY, "Internal error: out of memory",
            "z_sendmany", "42");
        struct json_value v;
        bool ok = json_read(&v, buf, n);
        if (ok) {
            const struct json_value *err = json_get(&v, "error");
            ok = ok && err && err->type == JSON_OBJ;
            const struct json_value *mt = json_get(err, "method");
            ok = ok && mt && strcmp(json_get_str(mt), "z_sendmany") == 0;
            ok = ok && json_get_int(json_get(&v, "id")) == 42;
        }
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Buffer edge cases ────────────────────────────────────── */

    printf("error_response truncates safely on small buffer... ");
    {
        char buf[32];
        size_t n = json_rpc_error_response(buf, sizeof(buf),
            -32700, "Parse error", NULL, NULL);
        /* Should not crash, output truncated */
        bool ok = n <= sizeof(buf) - 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("error_response zero buffer returns 0... ");
    {
        size_t n = json_rpc_error_response(NULL, 0, -1, "x", NULL, NULL);
        bool ok = (n == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Response serialization: >4 MiB heap-OOB-read regression ──────
     *
     * Old bug: handle_client() used a fixed 4 MiB buffer and fed
     * json_write()'s UNCLAMPED required length straight to write(). For
     * any response larger than 4 MiB that read (resp_len - 4 MiB) bytes
     * PAST the heap allocation and shipped adjacent heap memory to the
     * authenticated client (crash/DoS under ASan + info-leak).
     *
     * rpc_http_test_serialize_response() is the production sizing path:
     * it sizes with a zero-length json_write() probe, then allocates
     * exactly len+1, so the length handed to write() can never exceed
     * the allocation. These cases drive a response well over 4 MiB and
     * assert the contract holds — the body is fully sized and the
     * returned length equals what json_write() reports for the same
     * value (never an out-of-band send). */

    printf(">4MiB response is fully sized, never OOB... ");
    {
        /* Build a result array of long strings whose serialized form
         * comfortably exceeds the old 4 MiB fixed buffer. 1200 entries
         * of ~4 KiB each ≈ 4.9 MiB of body. */
        struct json_value result;
        json_init(&result);
        json_set_array(&result);

        char chunk[4096];
        memset(chunk, 'a', sizeof(chunk) - 1);
        chunk[sizeof(chunk) - 1] = '\0';

        bool built = true;
        for (int i = 0; i < 1200 && built; i++) {
            struct json_value s;
            json_init(&s);
            json_set_str(&s, chunk);
            built = json_push_back(&result, &s);
            json_free(&s);
        }

        struct json_value id;
        json_init(&id);
        json_set_int(&id, 1);

        struct json_value response;
        json_init(&response);
        bool env_ok = rpc_http_test_build_response_envelope(
            true, "listunspent", &result, &id, &response);

        /* Independent oracle: the required length for this exact value. */
        size_t required = json_write(&response, NULL, 0);

        char *buf = NULL;
        size_t len = 0;
        bool ser_ok = rpc_http_test_serialize_response(&response, &buf, &len);

        bool ok = built && env_ok && ser_ok;
        /* Must actually exceed the old 4 MiB buffer or the test proves
         * nothing about the bug class. */
        ok = ok && required > 4u * 1024u * 1024u;
        /* The length we would send must equal the required length, and
         * the buffer must be a real, separately-sized allocation — never
         * a 4 MiB buffer with an over-large length. */
        ok = ok && buf != NULL && len == required;
        /* The whole body must be present and re-parse cleanly — a real
         * OOB/partial send would not round-trip. Allocation is len+1 so
         * buf[len] is a valid index for the terminating NUL. */
        if (ok) {
            ok = ok && buf[len] == '\0';
            struct json_value parsed;
            json_init(&parsed);
            bool rt = json_read(&parsed, buf, len);
            ok = ok && rt;
            if (rt) {
                const struct json_value *res = json_get(&parsed, "result");
                ok = ok && res && res->type == JSON_ARR
                        && json_size(res) == 1200;
            }
            json_free(&parsed);
        }

        free(buf);
        json_free(&response);
        json_free(&result);
        json_free(&id);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("small response serializes exactly (no over-send)... ");
    {
        struct json_value result;
        json_init(&result);
        json_set_str(&result, "pong");

        struct json_value id;
        json_init(&id);
        json_set_int(&id, 7);

        struct json_value response;
        json_init(&response);
        bool env_ok = rpc_http_test_build_response_envelope(
            true, "ping", &result, &id, &response);

        size_t required = json_write(&response, NULL, 0);

        char *buf = NULL;
        size_t len = 0;
        bool ser_ok = rpc_http_test_serialize_response(&response, &buf, &len);

        bool ok = env_ok && ser_ok && buf != NULL;
        /* Exact-fit: length sent == required length, NUL in bounds. */
        ok = ok && len == required && buf[len] == '\0';
        struct json_value parsed;
        json_init(&parsed);
        ok = ok && json_read(&parsed, buf, len);
        json_free(&parsed);

        free(buf);
        json_free(&response);
        json_free(&result);
        json_free(&id);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("serialize_response NULL args fail safely... ");
    {
        char *buf = (char *)0x1; /* poison: must be cleared to NULL */
        size_t len = 99;         /* poison: must be cleared to 0 */
        bool r = rpc_http_test_serialize_response(NULL, &buf, &len);
        bool ok = (r == false) && (buf == NULL) && (len == 0);
        /* Also tolerate NULL out-params without crashing. */
        ok = ok && rpc_http_test_serialize_response(NULL, NULL, NULL) == false;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("\n%d rpc error envelope tests, %d failed\n",
           18, failures);
    return failures;
}
