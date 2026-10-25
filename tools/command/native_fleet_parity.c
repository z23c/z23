/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.parity.sample` leaf: the producer for fleet goal C8.
 *          One call compares one block hash of two nodes and appends one JSON
 *          line to parity.jsonl next to the C6 soak evidence.
 *
 * WHAT IT DECIDES. Nothing. It records whether the two hashes were equal; the
 * judge reads the ledger. An RPC failure is a recorded ok:false sample, since
 * a hole is itself evidence; only failing to lock or append is an error.
 * The height is min(tip_a, tip_b) - 100, below the reorg margin. Auth comes
 * from each node's .cookie file via the node RPC client, never from argv. */

#include "native_fleet_parity.h"

#include "native_fleet_goals.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "platform/clock.h"
#include "util/file_tree_ops.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define FP_PATH_MAX 512
#define FP_CONNECT_MS 2000L
#define FP_TOTAL_MS 10000L
#define FP_PORT_MAX 65535

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

/* ── sample ─────────────────────────────────────────────────────────── */

static bool fp_int_result(zcl_parity_rpc_fn rpc, void *ctx, int side,
                          const char *method, const char *params,
                          int64_t *out)
{
    char *raw = rpc(ctx, side, method, params);
    struct json_value v;
    bool ok;
    if (!raw)
        return false;
    json_init(&v);
    ok = json_read(&v, raw, strlen(raw)) && v.type == JSON_INT &&
         json_get_int(&v) >= 0;
    if (ok)
        *out = json_get_int(&v);
    json_free(&v);
    free(raw);
    return ok;
}

/* A bare JSON string of exactly 64 hex digits, lower-cased into `out`. */
static bool fp_hash_result(zcl_parity_rpc_fn rpc, void *ctx, int side,
                           const char *params, char *out)
{
    char *raw = rpc(ctx, side, "getblockhash", params);
    struct json_value v;
    const char *s;
    bool ok = false;
    if (!raw)
        return false;
    json_init(&v);
    if (json_read(&v, raw, strlen(raw)) && v.type == JSON_STR) {
        s = json_get_str(&v);
        ok = s && strlen(s) == ZCL_PARITY_HASH_HEX;
        for (size_t i = 0; ok && i < ZCL_PARITY_HASH_HEX; i++) {
            ok = isxdigit((unsigned char)s[i]) != 0;
            out[i] = (char)tolower((unsigned char)s[i]);
        }
        out[ok ? ZCL_PARITY_HASH_HEX : 0] = '\0';
    }
    json_free(&v);
    free(raw);
    return ok;
}

void zcl_parity_take(zcl_parity_rpc_fn rpc, void *ctx, int64_t ts,
                     struct zcl_parity_sample *out)
{
    int64_t tip_a = 0, tip_b = 0;
    char params[48];
    memset(out, 0, sizeof(*out));
    out->ts = ts;
    out->height = -1;
    if (!fp_int_result(rpc, ctx, 0, "getblockcount", NULL, &tip_a) ||
        !fp_int_result(rpc, ctx, 1, "getblockcount", NULL, &tip_b))
        return;
    out->height = (tip_a < tip_b ? tip_a : tip_b) - ZCL_PARITY_BACK;
    if (out->height < 0) {
        out->height = -1;
        return;
    }
    (void)snprintf(params, sizeof(params), "[%lld]", (long long)out->height);
    out->ok = fp_hash_result(rpc, ctx, 0, params, out->our_hash) &&
              fp_hash_result(rpc, ctx, 1, params, out->oracle_hash);
    if (!out->ok) {
        out->our_hash[0] = out->oracle_hash[0] = '\0';
        return;
    }
    out->match = strcmp(out->our_hash, out->oracle_hash) == 0;
}

/* ── ledger line ────────────────────────────────────────────────────── */

static bool fp_push_hash(struct json_value *o, const char *key, const char *h)
{
    struct json_value nul;
    bool ok;
    if (h[0])
        return json_push_kv_str(o, key, h);
    json_init(&nul);
    ok = json_push_kv(o, key, &nul);
    json_free(&nul);
    return ok;
}

/* The sample as a JSON object; nulls when it did not complete. */
static bool fp_object(struct json_value *o, const struct zcl_parity_sample *s)
{
    struct json_value nul;
    bool ok;
    json_set_object(o);
    ok = json_push_kv_int(o, "ts", s->ts);
    if (s->height >= 0) {
        ok = ok && json_push_kv_int(o, "height", s->height);
    } else {
        json_init(&nul);
        ok = ok && json_push_kv(o, "height", &nul);
        json_free(&nul);
    }
    ok = ok && fp_push_hash(o, "our_hash", s->our_hash) &&
         fp_push_hash(o, "oracle_hash", s->oracle_hash);
    if (s->ok) {
        ok = ok && json_push_kv_bool(o, "match", s->match);
    } else {
        json_init(&nul);
        ok = ok && json_push_kv(o, "match", &nul);
        json_free(&nul);
    }
    return ok && json_push_kv_str(o, "source", "rpc-getblockhash") &&
           json_push_kv_bool(o, "ok", s->ok);
}

bool zcl_parity_line(const struct zcl_parity_sample *sample, char *buf,
                     size_t cap, size_t *len)
{
    struct json_value o;
    size_t n = 0;
    bool ok;
    json_init(&o);
    ok = fp_object(&o, sample);
    if (ok && cap > 1)
        n = json_write(&o, buf, cap - 1);
    json_free(&o);
    if (!ok || n == 0 || n >= cap - 1)
        return false;
    buf[n++] = '\n';
    *len = n;
    return true;
}

/* ── append ─────────────────────────────────────────────────────────── */

static bool fp_write_all(const char *path, const char *line, size_t len)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    ssize_t w;
    if (fd < 0)
        return false;
    w = write(fd, line, len);
    if (w == (ssize_t)len && fsync(fd) != 0)
        w = -1;
    return close(fd) == 0 && w == (ssize_t)len;
}

bool zcl_parity_append(const char *dir, const char *line, size_t len,
                       const char **why)
{
    char lock[FP_PATH_MAX], file[FP_PATH_MAX];
    int fd;
    bool ok;
    if (snprintf(lock, sizeof(lock), "%s/parity.lock", dir) >= FP_PATH_MAX ||
        snprintf(file, sizeof(file), "%s/parity.jsonl", dir) >= FP_PATH_MAX) {
        *why = "the evidence path is too long";
        return false;
    }
    if (!zcl_mkdir_p(dir, 0700).ok) {
        *why = "the evidence directory could not be made";
        return false;
    }
    fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        *why = "the parity lock file could not be opened";
        return false;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        *why = "the parity ledger is locked by another writer";
        return false;
    }
    ok = fp_write_all(file, line, len);
    (void)close(fd);
    if (!ok)
        *why = "the parity ledger could not be appended";
    return ok;
}

/* ── leaf ───────────────────────────────────────────────────────────── */

struct fp_endpoints {
    int port[2];
    const char *cookie_dir[2];
};

static char *fp_rpc(void *ctx, int side, const char *method, const char *params)
{
    const struct fp_endpoints *e = ctx;
    return node_rpc_call_at_deadline(e->cookie_dir[side], e->port[side], method,
                                     params, FP_CONNECT_MS, FP_TOTAL_MS);
}

static void fp_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence, bool mutated,
                      enum zcl_command_exit exit_code)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           "parity", false, mutated, message, evidence);
}

static const char *fp_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v)[0] ? json_get_str(v)
                                                           : NULL;
}

/* A TCP port given as a JSON integer or a decimal string, 1..65535. */
static bool fp_port(const struct json_value *in, const char *key, int *out)
{
    const struct json_value *v = in ? json_get(in, key) : NULL;
    long long n = -1;
    char *end;
    if (v && v->type == JSON_INT) {
        n = json_get_int(v);
    } else if (v && v->type == JSON_STR && json_get_str(v)[0]) {
        errno = 0;
        n = strtoll(json_get_str(v), &end, 10);
        if (errno != 0 || *end != '\0')
            n = -1;
    }
    if (n < 1 || n > FP_PORT_MAX)
        return false;
    *out = (int)n;
    return true;
}

static bool fp_inputs(const struct zcl_command_request *request,
                      struct fp_endpoints *e, struct zcl_command_reply *reply)
{
    static const char *const side[2] = { "a", "b" };
    char key[24];
    for (int i = 0; i < 2; i++) {
        (void)snprintf(key, sizeof(key), "%s_port", side[i]);
        if (!fp_port(request->input, key, &e->port[i])) {
            fp_refuse(reply, "PARITY_PORT_INVALID",
                      "a_port and b_port are RPC ports, 1 to 65535", key, false,
                      ZCL_COMMAND_EXIT_INVALID);
            return false;
        }
        (void)snprintf(key, sizeof(key), "%s_cookie_dir", side[i]);
        e->cookie_dir[i] = fp_str(request->input, key);
        if (!e->cookie_dir[i] || e->cookie_dir[i][0] != '/') {
            fp_refuse(reply, "PARITY_COOKIE_DIR_INVALID",
                      "a_cookie_dir and b_cookie_dir are absolute directories "
                      "holding the node's .cookie file", key, false,
                      ZCL_COMMAND_EXIT_INVALID);
            return false;
        }
    }
    return true;
}

static bool fp_reply_sample(struct zcl_command_reply *reply,
                            const struct zcl_parity_sample *s, const char *dir)
{
    struct json_value o;
    bool ok;
    json_init(&o);
    ok = fp_object(&o, s);
    if (ok) {
        json_free(&reply->data);
        json_init(&reply->data);
        json_copy(&reply->data, &o);
        ok = json_push_kv_str(&reply->data, "dir", dir);
    }
    json_free(&o);
    return ok;
}

static void fp_sample_run(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply)
{
    struct fp_endpoints e;
    struct zcl_parity_sample s;
    char dir_buf[FP_PATH_MAX], line[ZCL_PARITY_LINE_MAX];
    const char *why = "";
    const char *dir;
    size_t len = 0;

    if (!fp_inputs(request, &e, reply))
        return;
    dir = zcl_goals_state_path(fp_str(request->input, "dir"),
                               "ZCL_SOAK_EVIDENCE_DIR",
                               ".local/state/zclassic23-soak-evidence", false,
                               dir_buf, sizeof(dir_buf));
    if (!dir || dir[0] != '/') {
        fp_refuse(reply, "PARITY_DIR_UNAVAILABLE",
                  "dir, ZCL_SOAK_EVIDENCE_DIR or HOME must give an absolute "
                  "evidence directory", "dir", false, ZCL_COMMAND_EXIT_INVALID);
        return;
    }
    zcl_parity_take(fp_rpc, &e, clock_now_wall_ms() / 1000, &s);
    if (!zcl_parity_line(&s, line, sizeof(line), &len)) {
        fp_refuse(reply, "PARITY_ROW_FAILED", "the parity line did not fit",
                  "row", false, ZCL_COMMAND_EXIT_INTERNAL);
        return;
    }
    if (!zcl_parity_append(dir, line, len, &why)) {
        fp_refuse(reply, "PARITY_WRITE_FAILED", why, "state", false,
                  ZCL_COMMAND_EXIT_FAILED);
        return;
    }
    reply->error.mutated = true;
    if (!fp_reply_sample(reply, &s, dir)) {
        fp_refuse(reply, "PARITY_REPLY_FAILED",
                  "the sample was appended but the reply could not be built",
                  "reply", true, ZCL_COMMAND_EXIT_INTERNAL);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_fleet_parity_sample(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_parity_sample.v1");
    if (!request || !request->input) {
        fp_refuse(reply, "PARITY_PORT_INVALID",
                  "a_port, a_cookie_dir, b_port and b_cookie_dir are required",
                  "input", false, ZCL_COMMAND_EXIT_INVALID);
        return;
    }
    fp_sample_run(request, reply);
}
