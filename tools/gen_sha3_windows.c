/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gen_sha3_windows: one-shot tool that queries a fully-synced
 * zclassic{,d} reference node over JSON-RPC, computes SHA3-256 over
 * windows of SHA3_WINDOW_SIZE consecutive block payloads, and emits
 *
 *   core/modules/chain/include/chain/sha3_windows.h  (declarations — stable)
 *   core/modules/chain/src/sha3_windows.c            (table + verifier)
 *
 * Usage:
 *   gen_sha3_windows --rpc-host=127.0.0.1 --rpc-port=8232 \
 *                    --rpc-user=USER --rpc-pass=PASS \
 *                    [--out-h=PATH] [--out-c=PATH] [--max-height=H]
 *   gen_sha3_windows --check-window=N [same RPC options]
 *
 * Missing --rpc-user / --rpc-pass are read from ~/.zclassic/zclassic.conf.
 * --max-height is useful for smoke tests; defaults to the chain tip.
 * --check-window computes one window and compares it to the compiled table
 * without writing output files.
 *
 * Links only standalone libs:
 *   platform/modules/sha3/src/sha3.c          (zcl_sha3_256 + streaming ctx)
 *   platform/modules/encoding/src/utilstrencodings.c (ParseHex)
 *   platform/modules/json/src/json.c            (json_read, json_get, ...)
 *
 * No DB, no node libs, no Tor — fast standalone build. */

#define _POSIX_C_SOURCE 200809L

#include "platform/time_compat.h"
#include "base/hex.h"
#include "chain/sha3_windows.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_OUT_H "core/modules/chain/include/chain/sha3_windows.h"
#define DEFAULT_OUT_C "core/modules/chain/src/sha3_windows.c"

/* Generous response cap: a 2 MB block prints ~4 MB hex + JSON wrapper. */
#define RPC_RESP_CAP (16u * 1024u * 1024u)

/* ── Base64 (for HTTP Basic auth) ───────────────────────────────────── */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *src, size_t len,
                          char *out, size_t out_sz)
{
    size_t i = 0, o = 0;
    while (i < len && o + 4 < out_sz) {
        uint32_t v = (uint32_t)src[i] << 16;
        int remain = (int)(len - i);
        if (remain > 1) v |= (uint32_t)src[i + 1] << 8;
        if (remain > 2) v |= src[i + 2];
        out[o++] = b64_table[(v >> 18) & 0x3f];
        out[o++] = b64_table[(v >> 12) & 0x3f];
        out[o++] = (remain > 1) ? b64_table[(v >> 6) & 0x3f] : '=';
        out[o++] = (remain > 2) ? b64_table[v & 0x3f] : '=';
        i += 3;
    }
    out[o] = '\0';
}

/* ── HTTP/1.1 POST with Basic auth ─────────────────────────────────── */

static int connect_host(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

static ssize_t recv_all(int fd, char *out, size_t out_cap)
{
    size_t used = 0;
    while (used < out_cap) {
        ssize_t n = recv(fd, out + used, out_cap - used, 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        used += (size_t)n;
    }
    return (ssize_t)used;
}

struct rpc_ctx {
    const char *host;
    int port;
    char auth_b64[768];
    char *resp;        /* RPC_RESP_CAP bytes */
};

static bool rpc_init(struct rpc_ctx *r, const char *host, int port,
                     const char *user, const char *pass)
{
    r->host = host;
    r->port = port;
    char raw[512];
    snprintf(raw, sizeof(raw), "%s:%s", user, pass);
    base64_encode((const unsigned char *)raw, strlen(raw),
                  r->auth_b64, sizeof(r->auth_b64));
    r->resp = malloc(RPC_RESP_CAP);  // raw-alloc-ok:standalone-dev-tool
    if (!r->resp) {
        fprintf(stderr, "[gen_sha3_windows] malloc(%u) failed\n",
                (unsigned)RPC_RESP_CAP);
        return false;
    }
    return true;
}

static void rpc_free(struct rpc_ctx *r)
{
    free(r->resp);
    r->resp = NULL;
}

/* Send a JSON-RPC call. Returns pointer into r->resp at the response
 * body (NUL-terminated), or NULL on error. body_len_out optional. */
static const char *rpc_call(struct rpc_ctx *r, const char *method,
                            const char *params_json, size_t *body_len_out)
{
    char body[512];
    int blen = snprintf(body, sizeof(body),
                        "{\"jsonrpc\":\"1.0\",\"method\":\"%s\","
                        "\"params\":%s,\"id\":1}",
                        method, params_json ? params_json : "[]");
    if (blen <= 0 || (size_t)blen >= sizeof(body))
        return NULL;

    char header[1024];
    int hlen = snprintf(header, sizeof(header),
                        "POST / HTTP/1.1\r\n"
                        "Host: %s:%d\r\n"
                        "Authorization: Basic %s\r\n"
                        "Content-Type: text/plain;\r\n"
                        "Connection: close\r\n"
                        "Content-Length: %d\r\n"
                        "\r\n",
                        r->host, r->port, r->auth_b64, blen);
    if (hlen <= 0 || (size_t)hlen >= sizeof(header))
        return NULL;

    int fd = connect_host(r->host, r->port);
    if (fd < 0) {
        fprintf(stderr, "[gen_sha3_windows] connect %s:%d failed: %s\n",
                r->host, r->port, strerror(errno));
        return NULL;
    }
    if (!send_all(fd, header, (size_t)hlen) ||
        !send_all(fd, body, (size_t)blen)) {
        close(fd);
        return NULL;
    }

    ssize_t total = recv_all(fd, r->resp, RPC_RESP_CAP - 1);
    close(fd);
    if (total <= 0) {
        fprintf(stderr, "[gen_sha3_windows] recv failed (%zd)\n", total);
        return NULL;
    }
    r->resp[total] = '\0';

    char *body_start = strstr(r->resp, "\r\n\r\n");
    if (!body_start) {
        fprintf(stderr, "[gen_sha3_windows] no http body separator\n");
        return NULL;
    }
    body_start += 4;
    /* zclassicd uses Content-Length; chunked transfer not supported. */
    size_t body_len = (size_t)total - (size_t)(body_start - r->resp);
    if (body_len_out) *body_len_out = body_len;
    return body_start;
}

/* Parse a JSON-RPC envelope and return a pointer to the "result"
 * sub-tree, or NULL on error. Caller still owns `env`. */
static const struct json_value *rpc_result(struct json_value *env,
                                           const char *body, size_t body_len)
{
    json_init(env);
    if (!json_read(env, body, body_len)) {
        fprintf(stderr, "[gen_sha3_windows] json parse failed\n");
        return NULL;
    }
    const struct json_value *err = json_get(env, "error");
    if (err && err->type != JSON_NULL) {
        const struct json_value *msg = json_get(err, "message");
        fprintf(stderr, "[gen_sha3_windows] RPC error: %s\n",
                msg && msg->type == JSON_STR ? msg->val.s : "(unknown)");
        return NULL;
    }
    const struct json_value *res = json_get(env, "result");
    if (!res) {
        fprintf(stderr, "[gen_sha3_windows] no result field\n");
        return NULL;
    }
    return res;
}

/* ── Config ────────────────────────────────────────────────────────── */

struct cli {
    const char *host;
    int port;
    char user[128];
    char pass[128];
    const char *out_h;
    const char *out_c;
    int max_height;     /* -1 = use chain tip */
    int check_window;   /* -1 = generate table */
    bool extend;        /* keep compiled rows, append new full windows */
    int confirm_depth;  /* min blocks a window must be buried below tip */
};

static void load_conf_auth(char user[128], char pass[128])
{
    const char *home = getenv("HOME");
    if (!home) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/.zclassic/zclassic.conf", home);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        if (strncmp(line, "rpcuser=", 8) == 0)
            snprintf(user, 128, "%s", line + 8);
        else if (strncmp(line, "rpcpassword=", 12) == 0)
            snprintf(pass, 128, "%s", line + 12);
    }
    fclose(f);
}

static bool parse_nonnegative_int(const char *s, int *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || v < 0 || v > INT32_MAX)
        return false;
    *out = (int)v;
    return true;
}

static bool parse_cli(int argc, char **argv, struct cli *c)
{
    c->host = "127.0.0.1";
    c->port = 8232;
    c->user[0] = '\0';
    c->pass[0] = '\0';
    c->out_h = DEFAULT_OUT_H;
    c->out_c = DEFAULT_OUT_C;
    c->max_height = -1;
    c->check_window = -1;
    c->extend = false;
    c->confirm_depth = 240;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--rpc-host=", 11) == 0) c->host = a + 11;
        else if (strncmp(a, "--rpc-port=", 11) == 0) c->port = atoi(a + 11);
        else if (strncmp(a, "--rpc-user=", 11) == 0)
            snprintf(c->user, sizeof(c->user), "%s", a + 11);
        else if (strncmp(a, "--rpc-pass=", 11) == 0)
            snprintf(c->pass, sizeof(c->pass), "%s", a + 11);
        else if (strncmp(a, "--out-h=", 8) == 0) c->out_h = a + 8;
        else if (strncmp(a, "--out-c=", 8) == 0) c->out_c = a + 8;
        else if (strncmp(a, "--max-height=", 13) == 0)
            c->max_height = atoi(a + 13);
        else if (strncmp(a, "--check-window=", 15) == 0) {
            if (!parse_nonnegative_int(a + 15, &c->check_window)) {
                fprintf(stderr, "--check-window must be >= 0\n");
                return false;
            }
        }
        else if (strcmp(a, "--extend") == 0) c->extend = true;
        else if (strncmp(a, "--confirm-depth=", 16) == 0) {
            if (!parse_nonnegative_int(a + 16, &c->confirm_depth)) {
                fprintf(stderr, "--confirm-depth must be >= 0\n");
                return false;
            }
        }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            printf("Usage: %s [--rpc-host=H] [--rpc-port=N] "
                   "[--rpc-user=U] [--rpc-pass=P] [--out-h=PATH] "
                   "[--out-c=PATH] [--max-height=H] "
                   "[--check-window=N] [--extend] "
                   "[--confirm-depth=N]\n", argv[0]);
            return false;
        }
        else {
            fprintf(stderr, "unknown arg: %s\n", a);
            return false;
        }
    }
    if (c->user[0] == '\0' || c->pass[0] == '\0')
        load_conf_auth(c->user, c->pass);
    if (c->user[0] == '\0' || c->pass[0] == '\0') {
        fprintf(stderr, "no RPC credentials (pass --rpc-user/--rpc-pass "
                        "or populate ~/.zclassic/zclassic.conf)\n");
        return false;
    }
    return true;
}

/* ── Streaming hex decoder feeding SHA3 ─────────────────────────────── */

/* Decode hex string `hex[0..hex_len)` into bytes and feed into ctx.
 * Returns number of bytes hashed, or (size_t)-1 on error.
 * Whitespace and other JSON noise should not appear inside the hex
 * value because we extract it from the JSON parser as a clean string. */
static size_t sha3_consume_hex(struct sha3_256_ctx *ctx,
                               const char *hex, size_t hex_len)
{
    if ((hex_len & 1u) != 0) return (size_t)-1;
    uint8_t buf[8192];
    size_t bytes_total = 0;
    size_t off = 0;
    while (off < hex_len) {
        size_t chunk_hex = hex_len - off;
        if (chunk_hex > sizeof(buf) * 2) chunk_hex = sizeof(buf) * 2;
        for (size_t i = 0; i < chunk_hex; i += 2) {
            signed char hi = HexDigit(hex[off + i]);
            signed char lo = HexDigit(hex[off + i + 1]);
            if (hi == -1 || lo == -1) return (size_t)-1;
            buf[i >> 1] = (uint8_t)((hi << 4) | lo);
        }
        size_t chunk_bytes = chunk_hex >> 1;
        sha3_256_write(ctx, buf, chunk_bytes);
        bytes_total += chunk_bytes;
        off += chunk_hex;
    }
    return bytes_total;
}

/* ── Output emitters ───────────────────────────────────────────────── */

static bool emit_header(const char *path)
{
    /* Header is stable — it doesn't change between runs. */
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return false; }
    fputs(
        "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
        " *\n"
        " * SHA3-256 window commitments over consecutive block payloads.\n"
        " *\n"
        " * For a chain at height H_tip, the table contains\n"
        " * ceil((H_tip + 1) / SHA3_WINDOW_SIZE) entries. Entry i covers\n"
        " * heights [i*SHA3_WINDOW_SIZE .. min((i+1)*SHA3_WINDOW_SIZE - 1, H_tip)].\n"
        " *\n"
        " * Each `hash` is SHA3-256 over the concatenation of the raw block\n"
        " * payloads (hex-decoded, equivalent to `getblock <hash> 0` bytes) in\n"
        " * height order.\n"
        " *\n"
        " * Generated by tools/gen_sha3_windows. Do not edit by hand. */\n"
        "\n"
        "#ifndef ZCL_CHAIN_SHA3_WINDOWS_H\n"
        "#define ZCL_CHAIN_SHA3_WINDOWS_H\n"
        "\n"
        "#include <stdbool.h>\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "#define SHA3_WINDOW_SIZE 1000\n"
        "\n"
        "struct sha3_window {\n"
        "    int32_t start_height;\n"
        "    uint8_t hash[32];\n"
        "};\n"
        "\n"
        "extern const struct sha3_window g_sha3_windows[];\n"
        "extern const size_t g_sha3_windows_count;\n"
        "\n"
        "bool sha3_windows_verify_window(int window_index,\n"
        "                                const uint8_t *block_payloads_concat,\n"
        "                                size_t total_len);\n"
        "\n"
        "#endif /* ZCL_CHAIN_SHA3_WINDOWS_H */\n",
        f);
    fclose(f);
    return true;
}

static bool emit_c_open(FILE **out_f, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return false; }
    fputs(
        "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
        " *\n"
        " * Generated by tools/gen_sha3_windows. Do not edit by hand. */\n"
        "\n"
        "#include \"chain/sha3_windows.h\"\n"
        "\n"
        "#include \"crypto/sha3.h\"\n"
        "\n"
        "#include <string.h>\n"
        "\n"
        "const struct sha3_window g_sha3_windows[] = {\n",
        f);
    *out_f = f;
    return true;
}

static void emit_c_row(FILE *f, int32_t start_height, const uint8_t hash[32])
{
    fprintf(f, "    { %d, { ", (int)start_height);
    for (int i = 0; i < 32; i++) {
        fprintf(f, "0x%02x%s", hash[i], i == 31 ? " " : ", ");
    }
    fputs("} },\n", f);
}

static void emit_c_close(FILE *f, size_t count)
{
    fputs("};\n\n", f);
    fprintf(f, "const size_t g_sha3_windows_count = %zu;\n", count);
    fputs(
        "\n"
        "bool sha3_windows_verify_window(int window_index,\n"
        "                                const uint8_t *block_payloads_concat,\n"
        "                                size_t total_len)\n"
        "{\n"
        "    if (window_index < 0)\n"
        "        return false;\n"
        "    if ((size_t)window_index >= g_sha3_windows_count)\n"
        "        return false;\n"
        "    if (block_payloads_concat == NULL && total_len != 0)\n"
        "        return false;\n"
        "\n"
        "    uint8_t digest[32];\n"
        "    sha3_256(block_payloads_concat, total_len, digest);\n"
        "\n"
        "    return memcmp(digest, g_sha3_windows[window_index].hash, 32) == 0;\n"
        "}\n",
        f);
    fclose(f);
}

/* ── Per-block / per-window worker ─────────────────────────────────── */

static double now_secs(void);

static bool fetch_block_hex_into_sha3(struct rpc_ctx *r, int height,
                                      struct sha3_256_ctx *ctx)
{
    /* Step 1: getblockhash <height> */
    char params[64];
    snprintf(params, sizeof(params), "[%d]", height);

    size_t body_len = 0;
    const char *body = rpc_call(r, "getblockhash", params, &body_len);
    if (!body) return false;

    struct json_value env;
    const struct json_value *res = rpc_result(&env, body, body_len);
    if (!res || res->type != JSON_STR) {
        json_free(&env);
        return false;
    }
    char block_hash[80];
    snprintf(block_hash, sizeof(block_hash), "%s", res->val.s);
    json_free(&env);

    /* Step 2: getblock <hash> 0 (raw hex) */
    char params2[128];
    snprintf(params2, sizeof(params2), "[\"%s\",0]", block_hash);

    body_len = 0;
    body = rpc_call(r, "getblock", params2, &body_len);
    if (!body) return false;

    /* The result is a single JSON string of hex. We parse the full
     * envelope (the parser handles arbitrarily long strings). */
    struct json_value env2;
    const struct json_value *res2 = rpc_result(&env2, body, body_len);
    if (!res2 || res2->type != JSON_STR) {
        fprintf(stderr, "[gen_sha3_windows] height=%d: result not a hex string\n", height);
        json_free(&env2);
        return false;
    }
    const char *hex = res2->val.s;
    size_t hex_len = strlen(hex);
    size_t consumed = sha3_consume_hex(ctx, hex, hex_len);
    json_free(&env2);
    if (consumed == (size_t)-1) {
        fprintf(stderr, "[gen_sha3_windows] height=%d: bad hex\n", height);
        return false;
    }
    return true;
}

static bool compute_window_digest(struct rpc_ctx *r, int start, int end,
                                  uint8_t digest[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    for (int h = start; h <= end; h++) {
        if (!fetch_block_hex_into_sha3(r, h, &ctx))
            return false;
    }
    sha3_256_finalize(&ctx, digest);
    return true;
}

static int check_one_window(struct rpc_ctx *r, int window, int tip)
{
    if (window < 0) {
        fprintf(stderr, "--check-window must be >= 0\n");
        return 1;
    }
    if ((size_t)window >= g_sha3_windows_count) {
        fprintf(stderr,
                "[gen_sha3_windows] window %d is outside compiled table "
                "(count=%zu)\n", window, g_sha3_windows_count);
        return 1;
    }

    int start = window * SHA3_WINDOW_SIZE;
    int end = start + SHA3_WINDOW_SIZE - 1;
    if (end > tip) {
        fprintf(stderr,
                "[gen_sha3_windows] window %d h=%d..%d exceeds tip=%d\n",
                window, start, end, tip);
        return 1;
    }

    uint8_t actual[32];
    double t0 = now_secs();
    if (!compute_window_digest(r, start, end, actual))
        return 1;

    char expected_hex[65], actual_hex[65];
    zcl_hex_encode(g_sha3_windows[window].hash, 32, expected_hex);
    zcl_hex_encode(actual, 32, actual_hex);
    bool ok = memcmp(actual, g_sha3_windows[window].hash, 32) == 0;
    printf("[gen_sha3_windows] check window=%d h=%d..%d "
           "expected=%s actual=%s ok=%s (%.1fs)\n",
           window, start, end, expected_hex, actual_hex,
           ok ? "yes" : "no", now_secs() - t0);
    return ok ? 0 : 1;
}

/* ── Main ──────────────────────────────────────────────────────────── */

static double now_secs(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Extend the compiled table in place: keep every locked row verbatim,
 * recompute the trailing row as a FULL window (the original generator
 * could emit a partial trailing window when minted mid-window — a latent
 * false-tripwire), and append new full windows buried at least
 * confirm_depth blocks below the source tip.
 *
 * Fail-closed: before trusting the source for ANY new evidence, the row
 * adjacent to the recompute boundary is recomputed and must match the
 * locked table byte-for-byte. On mismatch nothing is written. */
static int run_extend(struct rpc_ctx *r, const struct cli *c, int tip)
{
    size_t compiled = g_sha3_windows_count;
    if (compiled < 2) {
        fprintf(stderr, "[extend] compiled table too small (%zu rows); "
                        "run a full generate instead\n", compiled);
        return 1;
    }

    size_t full = (size_t)(tip + 1) / SHA3_WINDOW_SIZE;
    while (full > 0 &&
           (int64_t)full * SHA3_WINDOW_SIZE - 1 + c->confirm_depth >
               (int64_t)tip)
        full--;
    if (full < compiled) {
        fprintf(stderr, "[extend] source tip=%d yields %zu confirmable "
                        "full windows < compiled %zu; refusing\n",
                tip, full, compiled);
        return 1;
    }

    /* Continuity proof against the deepest row we keep verbatim. */
    size_t probe = compiled - 2;
    {
        int start = (int)(probe * SHA3_WINDOW_SIZE);
        int end = start + SHA3_WINDOW_SIZE - 1;
        uint8_t digest[32];
        if (!compute_window_digest(r, start, end, digest)) return 1;
        if (memcmp(digest, g_sha3_windows[probe].hash, 32) != 0) {
            char want[65], got[65];
            zcl_hex_encode(g_sha3_windows[probe].hash, 32, want);
            zcl_hex_encode(digest, 32, got);
            fprintf(stderr, "[extend] continuity FAILED at window %zu "
                            "(h=%d..%d): locked=%s source=%s — the source "
                            "node disagrees with locked history; refusing "
                            "to emit anything\n",
                    probe, start, end, want, got);
            return 1;
        }
        printf("[extend] continuity OK at window %zu (h=%d..%d)\n",
               probe, start, end);
    }

    /* Recompute the trailing compiled row as a full window. */
    uint8_t last_digest[32];
    bool last_replaced = false;
    {
        size_t wi = compiled - 1;
        int start = (int)(wi * SHA3_WINDOW_SIZE);
        int end = start + SHA3_WINDOW_SIZE - 1;
        if (!compute_window_digest(r, start, end, last_digest)) return 1;
        last_replaced =
            memcmp(last_digest, g_sha3_windows[wi].hash, 32) != 0;
        if (last_replaced) {
            char want[65], got[65];
            zcl_hex_encode(g_sha3_windows[wi].hash, 32, want);
            zcl_hex_encode(last_digest, 32, got);
            printf("[extend] REPLACING trailing window %zu (h=%d..%d): "
                   "locked=%s (partial-window mint) full=%s\n",
                   wi, start, end, want, got);
        }
    }

    if (!emit_header(c->out_h)) return 1;
    FILE *fc = NULL;
    if (!emit_c_open(&fc, c->out_c)) return 1;

    for (size_t i = 0; i + 1 < compiled; i++)
        emit_c_row(fc, g_sha3_windows[i].start_height,
                   g_sha3_windows[i].hash);
    emit_c_row(fc, (int32_t)((compiled - 1) * SHA3_WINDOW_SIZE),
               last_digest);

    double t0 = now_secs();
    for (size_t wi = compiled; wi < full; wi++) {
        int start = (int)(wi * SHA3_WINDOW_SIZE);
        int end = start + SHA3_WINDOW_SIZE - 1;
        uint8_t digest[32];
        if (!compute_window_digest(r, start, end, digest)) {
            fclose(fc);
            return 1;
        }
        emit_c_row(fc, (int32_t)start, digest);
        size_t done = wi - compiled + 1, todo = full - compiled;
        if ((done % 5u) == 0u || done == todo) {
            double dt = now_secs() - t0;
            double rate = done / (dt > 0 ? dt : 1.0);
            printf("[extend] %zu/%zu new windows, ETA %.0fs\n",
                   done, todo, (todo - done) / (rate > 0 ? rate : 1.0));
            fflush(stdout);
        }
    }

    emit_c_close(fc, full);
    printf("[extend] wrote %s and %s: %zu rows (%zu kept, trailing row "
           "%s, %zu appended), coverage h=0..%zu\n",
           c->out_h, c->out_c, full, compiled - 1,
           last_replaced ? "REPLACED (was partial)" : "unchanged",
           full - compiled, full * SHA3_WINDOW_SIZE - 1);
    return 0;
}

int main(int argc, char **argv)
{
    struct cli c;
    if (!parse_cli(argc, argv, &c)) return 1;

    struct rpc_ctx r;
    if (!rpc_init(&r, c.host, c.port, c.user, c.pass)) return 1;

    /* Resolve chain tip if --max-height not given. */
    int tip = c.max_height;
    if (tip < 0) {
        size_t body_len = 0;
        const char *body = rpc_call(&r, "getblockcount", "[]", &body_len);
        if (!body) { rpc_free(&r); return 1; }
        struct json_value env;
        const struct json_value *res = rpc_result(&env, body, body_len);
        if (!res || res->type != JSON_INT) {
            json_free(&env);
            rpc_free(&r);
            return 1;
        }
        tip = (int)res->val.i;
        json_free(&env);
    }
    if (tip < 0) {
        fprintf(stderr, "tip height = %d, nothing to do\n", tip);
        rpc_free(&r);
        return 1;
    }

    size_t num_windows = ((size_t)tip + 1u + SHA3_WINDOW_SIZE - 1u) /
                         SHA3_WINDOW_SIZE;
    printf("[gen_sha3_windows] host=%s:%d tip=%d windows=%zu\n",
           c.host, c.port, tip, num_windows);

    if (c.check_window >= 0) {
        int rc = check_one_window(&r, c.check_window, tip);
        rpc_free(&r);
        return rc;
    }

    if (c.extend) {
        int rc = run_extend(&r, &c, tip);
        rpc_free(&r);
        return rc;
    }

    /* Full windows only: a partial trailing window has no end marker in
     * the emitted struct and false-fires the runtime tripwire once the
     * window completes on-chain. */
    if (num_windows * SHA3_WINDOW_SIZE > (size_t)tip + 1u) {
        num_windows--;
        printf("[gen_sha3_windows] dropping partial trailing window "
               "(coverage capped at h=%zu, tip=%d)\n",
               num_windows * SHA3_WINDOW_SIZE - 1, tip);
    }

    if (!emit_header(c.out_h)) { rpc_free(&r); return 1; }

    FILE *fc = NULL;
    if (!emit_c_open(&fc, c.out_c)) { rpc_free(&r); return 1; }

    double t0 = now_secs();
    double t_last = t0;

    for (size_t wi = 0; wi < num_windows; wi++) {
        int start = (int)(wi * SHA3_WINDOW_SIZE);
        int end = start + SHA3_WINDOW_SIZE - 1;
        if (end > tip) end = tip;

        uint8_t digest[32];
        if (!compute_window_digest(&r, start, end, digest)) {
            fclose(fc);
            rpc_free(&r);
            return 1;
        }
        emit_c_row(fc, (int32_t)start, digest);

        if (((wi + 1) % 50u) == 0u || wi + 1 == num_windows) {
            double now = now_secs();
            double dt = now - t0;
            double pct = 100.0 * (double)(wi + 1) / (double)num_windows;
            double rate = (wi + 1) / (dt > 0 ? dt : 1.0);
            double eta = (num_windows - (wi + 1)) / (rate > 0 ? rate : 1.0);
            printf("[windows] %zu/%zu (%.1f%%) ETA %.0fs (%.1fs since last)\n",
                   wi + 1, num_windows, pct, eta, now - t_last);
            fflush(stdout);
            t_last = now;
        }
    }

    emit_c_close(fc, num_windows);
    rpc_free(&r);
    printf("[gen_sha3_windows] wrote %s and %s (%zu rows, %.1fs total)\n",
           c.out_h, c.out_c, num_windows, now_secs() - t0);
    return 0;
}
