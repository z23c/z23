/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lab.run, lab.test and lab.show. An agent writes one C23 file; the
 * lab compiles it with the in-tree compile cache, runs it confined, and
 * returns the compiler diagnostics, the program's exit status and output, and
 * any sanitizer finding as one receipt. Receipts are content addressed by the
 * source bytes and the canonical inputs, so an identical request is answered
 * from the stored receipt without compiling or running anything. */
#include "command/lab.h"
#include "command/lab_priv.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct lab_req {
    const char *file;
    const char *stdin_data;
    const char *args[LAB_ARGS_MAX];
    size_t n_args;
    bool sanitize, fresh, compile_only;
    uint32_t timeout_ms, mem_mb;
};

void lab_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                           message, "lab");
}

/* ── inputs ─────────────────────────────────────────────────────────── */

const char *lab_in_str(const struct zcl_command_request *rq,
                              const char *key)
{
    const struct json_value *v = rq->input ? json_get(rq->input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

bool lab_in_bool(const struct zcl_command_request *rq, const char *key,
                        bool fallback)
{
    const struct json_value *v = rq->input ? json_get(rq->input, key) : NULL;
    return v && v->type == JSON_BOOL ? json_get_bool(v) : fallback;
}

bool lab_in_uint(const struct zcl_command_request *rq, const char *key,
                        uint32_t fallback, uint32_t max, uint32_t *out)
{
    const struct json_value *v = rq->input ? json_get(rq->input, key) : NULL;
    *out = fallback;
    if (!v)
        return true;
    if (v->type != JSON_INT || json_get_int(v) < 1 || json_get_int(v) > max)
        return false;
    *out = (uint32_t)json_get_int(v);
    return true;
}

static bool lab_in_args(const struct zcl_command_request *rq,
                        struct lab_req *r)
{
    const struct json_value *v = rq->input ? json_get(rq->input, "args") : NULL;
    if (!v)
        return true;
    if (v->type != JSON_ARR || v->num_children > LAB_ARGS_MAX)
        return false;
    for (size_t i = 0; i < v->num_children; i++) {
        if (v->children[i].type != JSON_STR)
            return false;
        r->args[r->n_args++] = json_get_str(&v->children[i]);
    }
    return true;
}

static bool lab_req_parse(const struct zcl_command_request *rq,
                          struct lab_req *r, struct zcl_command_reply *reply)
{
    memset(r, 0, sizeof(*r));
    r->file = lab_in_str(rq, "file");
    r->stdin_data = lab_in_str(rq, "stdin");
    r->sanitize = lab_in_bool(rq, "sanitize", true);
    r->fresh = lab_in_bool(rq, "fresh", false);
    r->compile_only = lab_in_bool(rq, "compile_only", false);
    if (!r->file || !r->file[0]) {
        lab_fail(reply, "LAB_BAD_INPUT", "normalize",
                 "usage: lab run <file.c> — file is a path to one C source file");
        return false;
    }
    if (!lab_in_uint(rq, "timeout_ms", LAB_TIMEOUT_DEFAULT_MS,
                     LAB_TIMEOUT_MAX_MS, &r->timeout_ms) ||
        !lab_in_uint(rq, "mem_mb", LAB_MEM_DEFAULT_MB, LAB_MEM_MAX_MB,
                     &r->mem_mb) ||
        !lab_in_args(rq, r) ||
        (r->stdin_data && strlen(r->stdin_data) > LAB_STDIN_MAX)) {
        lab_fail(reply, "LAB_BAD_INPUT", "normalize",
                 "timeout_ms is 1..60000, mem_mb 1..2048, args at most 32 "
                 "strings, stdin at most 65536 bytes");
        return false;
    }
    return true;
}

/* ── context ────────────────────────────────────────────────────────── */

static void lab_err_reply(struct zcl_command_reply *reply, enum lab_err err)
{
    switch (err) {
    case LAB_E_NOT_FOUND:
        lab_fail(reply, "LAB_FILE_NOT_FOUND", "load", "the source file does not exist");
        break;
    case LAB_E_TOO_LARGE:
        lab_fail(reply, "LAB_TOO_LARGE", "load", "the source exceeds 262144 bytes");
        break;
    case LAB_E_NO_COMPILER:
        lab_fail(reply, "LAB_NO_COMPILER", "toolchain", "no `cc` was found on PATH");
        break;
    case LAB_E_UNSUPPORTED:
        lab_fail(reply, "LAB_UNSUPPORTED", "load", "the lab runs on Linux hosts only");
        break;
    case LAB_E_STATE:
        lab_fail(reply, "LAB_STATE", "state",
                 "the lab state directory could not be prepared");
        break;
    default:
        lab_fail(reply, "LAB_BAD_FILE", "load",
                 "the source must be a .c path naming a regular file you own");
        break;
    }
}

bool lab_ctx_open(struct lab_ctx *ctx, const char *file,
                         struct zcl_command_reply *reply)
{
    memset(ctx, 0, sizeof(*ctx));
    enum lab_err err = file ? lab_source_load(file, &ctx->src) : LAB_OK;
    if (err == LAB_OK)
        err = lab_dirs_open(&ctx->dirs);
    if (err == LAB_OK && file)
        err = lab_toolchain_find(&ctx->tc);
    if (err != LAB_OK) {
        lab_source_free(&ctx->src);
        lab_err_reply(reply, err);
    }
    return err == LAB_OK;
}

void lab_ctx_close(struct lab_ctx *ctx)
{
    lab_source_free(&ctx->src);
}

void lab_unconfined(struct zcl_command_reply *reply)
{
    lab_fail(reply, "LAB_UNCONFINED", "confine",
             "Landlock and seccomp cannot be applied on this host, so the "
             "program was not run; compile_only still works");
}

/* ── cache ──────────────────────────────────────────────────────────── */

static bool lab_json_str_is(const struct json_value *v, const char *key,
                            const char *want)
{
    const struct json_value *f = json_get(v, key);
    return f && f->type == JSON_STR && strcmp(json_get_str(f), want) == 0;
}

/* Answer from the stored receipt when it exists for this compiler. */
bool lab_cache_serve(struct lab_ctx *ctx, struct zcl_command_reply *reply)
{
    struct json_value stored, cache;
    json_init(&stored);
    json_init(&cache);
    bool hit = lab_receipt_load(&ctx->dirs, ctx->root, &stored) &&
               lab_json_str_is(&stored, "compiler_id", ctx->tc.identity);
    if (hit) {
        json_set_object(&cache);
        json_free(&reply->data);
        reply->data = stored;
        json_init(&stored);
        hit = json_push_kv_bool(&cache, "hit", true) &&
              json_push_kv(&reply->data, "cache", &cache);
    }
    json_free(&stored);
    json_free(&cache);
    return hit;
}

/* Store the receipt built in reply->data, then mark it as a fresh result. */
bool lab_publish(struct lab_ctx *ctx, struct zcl_command_reply *reply)
{
    struct json_value cache;
    json_init(&cache);
    json_set_object(&cache);
    (void)lab_receipt_store(&ctx->dirs, ctx->root, &reply->data);
    bool ok = json_push_kv_bool(&cache, "hit", false) &&
              json_push_kv(&reply->data, "cache", &cache);
    json_free(&cache);
    return ok;
}

/* ── root ───────────────────────────────────────────────────────────────── */

static void lab_root_common(struct lab_hasher *h, const struct lab_ctx *ctx,
                            const struct lab_req *r)
{
    lab_hasher_field(h, "source", ctx->src.bytes, ctx->src.len);
    lab_hasher_u64(h, "sanitize", r->sanitize);
    lab_hasher_u64(h, "timeout_ms", r->timeout_ms);
    lab_hasher_u64(h, "mem_mb", r->mem_mb);
}

static bool lab_root_run(struct lab_ctx *ctx, const struct lab_req *r)
{
    struct lab_hasher *h = lab_hasher_new("run");
    if (!h)
        return false;
    lab_root_common(h, ctx, r);
    lab_hasher_u64(h, "compile_only", r->compile_only);
    lab_hasher_field(h, "stdin", r->stdin_data ? r->stdin_data : "",
                     r->stdin_data ? strlen(r->stdin_data) : 0);
    lab_hasher_u64(h, "argc", r->n_args);
    for (size_t i = 0; i < r->n_args; i++)
        lab_hasher_field(h, "arg", r->args[i], strlen(r->args[i]));
    lab_hasher_finish(h, ctx->root);
    return true;
}

/* ── receipt ────────────────────────────────────────────────────────── */

bool lab_attach(struct json_value *d, const char *key,
                       struct json_value *sec, bool built)
{
    bool ok = built && json_push_kv(d, key, sec);
    json_free(sec);
    return ok;
}

bool lab_head(struct json_value *d, const struct lab_ctx *ctx,
                     const char *kind, const struct lab_compile *comp)
{
    struct json_value sec;
    json_init(&sec);
    return json_push_kv_str(d, "root", ctx->root) &&
           json_push_kv_str(d, "kind", kind) &&
           json_push_kv_str(d, "file", ctx->src.path) &&
           json_push_kv_str(d, "compiler_id", ctx->tc.identity) &&
           lab_attach(d, "compile", &sec, lab_json_compile(&sec, comp));
}

bool lab_tail(struct json_value *d, const struct lab_compile *comp,
              bool requested, bool applied, size_t findings, const char *first)
{
    struct json_value san, conf;
    json_init(&san);
    json_init(&conf);
    return lab_attach(d, "sanitizer", &san,
                      lab_json_sanitizer(&san, comp, requested, findings, first)) &&
           lab_attach(d, "confinement", &conf,
                      lab_json_confinement(&conf, applied, lab_pidns_available()));
}

static bool lab_build_run(struct json_value *d, const struct lab_ctx *ctx,
                          const struct lab_req *r,
                          const struct lab_compile *comp,
                          const struct lab_proc *p, bool ran)
{
    char first[LAB_FIRST_MAX + 1] = "";
    size_t findings = 0;
    struct json_value run;
    json_init(&run);
    if (comp->sanitized && ran)
        findings = lab_scan_sanitizer(p->err, p->err_len, first, sizeof(first));
    return lab_head(d, ctx, "run", comp) &&
           lab_attach(d, "run", &run, lab_json_run(&run, p, ran, NULL)) &&
           lab_tail(d, comp, r->sanitize, ran, findings, first);
}

/* ── lab.run ────────────────────────────────────────────────────────── */

static void lab_fill_inputs(const struct lab_req *r, struct lab_inputs *in)
{
    in->stdin_data = r->stdin_data ? r->stdin_data : "";
    in->stdin_len = r->stdin_data ? strlen(r->stdin_data) : 0;
    in->args = r->args;
    in->n_args = r->n_args;
    in->sanitize = r->sanitize;
    in->timeout_ms = r->timeout_ms;
    in->mem_mb = r->mem_mb;
}

static void lab_run_execute(struct lab_ctx *ctx, const struct lab_req *r,
                            struct zcl_command_reply *reply)
{
    struct lab_compile *comp = zcl_calloc(1, sizeof(*comp), "lab.compile");
    struct lab_proc proc;
    struct lab_inputs in;
    bool have = lab_proc_init(&proc);
    bool ran = false, ok = false;
    if (!comp || !have) {
        lab_fail(reply, "LAB_ALLOC", "run", "the lab could not allocate");
    } else {
        lab_compile_source(&ctx->dirs, &ctx->tc, &ctx->src, ctx->root,
                           r->sanitize, comp);
        lab_fill_inputs(r, &in);
        if (comp->ok && !r->compile_only) {
            lab_run_binary(&ctx->dirs, comp->binary, comp->sanitized, &in, &proc);
            ran = proc.launch == LAB_LAUNCHED;
        }
        if (comp->unconfined || proc.launch == LAB_LAUNCH_UNCONFINED)
            lab_unconfined(reply);
        else
            ok = lab_build_run(&reply->data, ctx, r, comp, &proc, ran) &&
                 lab_publish(ctx, reply);
        if (!ok && reply->status == ZCL_COMMAND_STATUS_PASSED)
            lab_fail(reply, "LAB_ALLOC", "serialize", "the receipt could not be built");
    }
    lab_compile_cleanup(&ctx->dirs, ctx->root);
    if (have)
        lab_proc_free(&proc);
    free(comp);
}

/* Cache first, then the confinement check, then compile and run. */
static void lab_run_dispatch(struct lab_ctx *ctx, const struct lab_req *req,
                             struct zcl_command_reply *reply)
{
    if (!lab_root_run(ctx, req))
        lab_fail(reply, "LAB_ALLOC", "root", "the lab could not allocate");
    else if (!req->fresh && lab_cache_serve(ctx, reply))
        return;
    else if (!req->compile_only && !lab_confinement_available())
        lab_unconfined(reply);
    else
        lab_run_execute(ctx, req, reply);
}

void zcl_native_handle_lab_run(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    struct lab_req req;
    struct lab_ctx ctx;
    if (!lab_req_parse(request, &req, reply) ||
        !lab_ctx_open(&ctx, req.file, reply))
        return;
    lab_run_dispatch(&ctx, &req, reply);
    lab_ctx_close(&ctx);
    const struct json_value *compile = json_get(&reply->data, "compile");
    const struct json_value *compiled = compile ? json_get(compile, "ok") : NULL;
    if (reply->status == ZCL_COMMAND_STATUS_PASSED && compiled &&
        compiled->type == JSON_BOOL && !json_get_bool(compiled) &&
        !json_push_kv_str(&reply->data, "next_action",
                         "Fix the source at data.compile.diagnostics, then repeat your lab run command"))
        lab_fail(reply, "LAB_ALLOC", "serialize", "the guidance could not be built");
}

/* ── lab.show ───────────────────────────────────────────────────────── */

void zcl_native_handle_lab_show(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    const char *root = lab_in_str(request, "root");
    struct lab_ctx ctx;
    struct json_value stored;
    if (!root || !lab_root_valid(root)) {
        lab_fail(reply, "LAB_BAD_ROOT", "normalize",
                 "usage: lab show <root> — root is the 128-hex receipt root");
        return;
    }
    if (!lab_ctx_open(&ctx, NULL, reply))
        return;
    json_init(&stored);
    if (!lab_receipt_load(&ctx.dirs, root, &stored))
        lab_fail(reply, "LAB_NOT_FOUND", "load", "no stored receipt has that root");
    else if (!json_push_kv_str(&reply->data, "root", root) ||
             !json_push_kv(&reply->data, "receipt", &stored))
        lab_fail(reply, "LAB_ALLOC", "serialize", "the receipt could not be built");
    json_free(&stored);
}
