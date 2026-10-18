/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lab.promote. Turn one C23 file that passes its lab cases into a
 * signed one-shot plugin (interface 2): run the cases as lab.test does, build a
 * static release image with the lab's compiler, run every case again against
 * that image through the lab's confined runner, and only then pack it through
 * plugin.pack with the caller's key. Nothing is written to the output directory
 * unless every gate passed, and nothing is installed. */
#include "command/lab_priv.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct promote_req {
    const char *file;
    uint32_t timeout_ms, mem_mb;
    char root[LAB_ROOT_HEX + 1];
    size_t passed, failed;
};

static bool promote_parse(const struct zcl_command_request *rq,
                          struct promote_req *p)
{
    memset(p, 0, sizeof(*p));
    p->file = lab_in_str(rq, "file");
    return p->file && lab_in_str(rq, "name") && lab_in_str(rq, "version") &&
           lab_in_str(rq, "key") &&
           lab_in_uint(rq, "timeout_ms", LAB_TIMEOUT_DEFAULT_MS,
                       LAB_TIMEOUT_MAX_MS, &p->timeout_ms) &&
           lab_in_uint(rq, "mem_mb", LAB_MEM_DEFAULT_MB, LAB_MEM_MAX_MB,
                       &p->mem_mb);
}

/* Copy the listed members of the request into a new input object. */
static bool promote_forward(const struct zcl_command_request *rq,
                            struct json_value *out, const char *const *keys,
                            size_t n)
{
    json_init(out);
    json_set_object(out);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *v = json_get(rq->input, keys[i]);
        if (v && !json_push_kv(out, keys[i], v))
            return false;
    }
    return true;
}

static void promote_refuse(struct zcl_command_reply *reply, const char *code,
                           const char *phase, const char *message,
                           const char *evidence)
{
    lab_fail(reply, code, phase, message);
    snprintf(reply->error.evidence, sizeof(reply->error.evidence), "%s", evidence);
}

/* Step 1: lab.test on the same inputs, always fresh. A refusal of lab.test
 * itself stays in `reply`; false means the reply already carries a refusal. */
static bool promote_cases(const struct zcl_command_request *rq,
                          struct zcl_command_reply *reply,
                          struct promote_req *p)
{
    static const char *const keys[] = { "file", "cases", "sanitize",
                                        "timeout_ms", "mem_mb" };
    struct json_value in;
    char message[192];
    bool ok = promote_forward(rq, &in, keys, sizeof(keys) / sizeof(keys[0])) &&
              json_push_kv_bool(&in, "fresh", true);
    struct zcl_command_request sub = { .input = &in };
    if (ok)
        zcl_native_handle_lab_test(&sub, reply);
    else
        lab_fail(reply, "LAB_ALLOC", "run", "the lab could not allocate");
    json_free(&in);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED)
        return false;
    const struct json_value *root = json_get(&reply->data, "root");
    const struct json_value *pass = json_get(&reply->data, "passed");
    const struct json_value *fail = json_get(&reply->data, "failed");
    if (!root || root->type != JSON_STR || !pass || !fail ||
        !lab_root_valid(json_get_str(root))) {
        promote_refuse(reply, "LAB_ALLOC", "run", "the test receipt is unreadable", "");
        return false;
    }
    snprintf(p->root, sizeof(p->root), "%s", json_get_str(root));
    p->passed = (size_t)json_get_int(pass);
    p->failed = (size_t)json_get_int(fail);
    json_free(&reply->data);
    json_init(&reply->data);
    if (p->failed == 0 && p->passed > 0)
        return true;
    snprintf(message, sizeof(message),
             "%zu of %zu cases failed; nothing was written", p->failed,
             p->passed + p->failed);
    promote_refuse(reply, "LAB_PROMOTE_CASES_FAILED", "cases", message, p->root);
    snprintf(reply->error.next_action, sizeof(reply->error.next_action),
             "z23 lab show %s", p->root);
    return false;
}

static void promote_build_failed(struct zcl_command_reply *reply,
                                 const struct lab_compile *rel)
{
    char message[192];
    const char *why = rel->n_diag ? rel->diag[0].message
                      : rel->detail[0] ? rel->detail
                                       : "the linker failed; is a static libc installed";
    snprintf(message, sizeof(message), "the static release build failed: %.120s", why);
    promote_refuse(reply, "LAB_PROMOTE_BUILD_FAILED", "build", message, rel->command);
}

/* Step 4: pack as interface 2 with the caller's key, through plugin.pack. */
static bool promote_pack(const struct zcl_command_request *rq,
                         const struct lab_compile *rel,
                         struct zcl_command_reply *reply)
{
    static const char *const keys[] = { "name", "version", "key", "cap", "dir" };
    struct json_value in;
    bool ok = promote_forward(rq, &in, keys, sizeof(keys) / sizeof(keys[0])) &&
              json_push_kv_str(&in, "exe", rel->binary) &&
              json_push_kv_int(&in, "interface", 2);
    struct zcl_command_request sub = { .input = &in };
    if (ok)
        zcl_native_handle_plugin_pack(&sub, reply);
    else
        lab_fail(reply, "LAB_ALLOC", "pack", "the lab could not allocate");
    json_free(&in);
    return ok && reply->status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *promote_str(const struct json_value *d, const char *key)
{
    const struct json_value *v = json_get(d, key);
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

/* Replace the pack reply by the promote receipt. */
static void promote_report(struct zcl_command_reply *reply,
                           const struct promote_req *p,
                           const struct lab_compile *rel)
{
    char manifest[4096], name[128], version[128], generation[PLUGIN_HEX_SHA3_512 + 1];
    char key[PLUGIN_HEX_PUBLIC_KEY + 1], sha[PLUGIN_HEX_SHA3_512 + 1];
    char sig[4096], next[4200];
    size_t n;
    snprintf(manifest, sizeof(manifest), "%s", promote_str(&reply->data, "manifest"));
    snprintf(name, sizeof(name), "%s", promote_str(&reply->data, "name"));
    snprintf(version, sizeof(version), "%s", promote_str(&reply->data, "version"));
    snprintf(generation, sizeof(generation), "%s", promote_str(&reply->data, "generation"));
    snprintf(key, sizeof(key), "%s", promote_str(&reply->data, "public_key"));
    n = strlen(manifest);
    snprintf(sig, sizeof(sig), "%.*ssig", (int)(n >= 4 ? n - 4 : n), manifest);
    snprintf(next, sizeof(next), "z23 plugin install --manifest=%s", manifest);
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    if (plugin_hash_file(rel->binary, sha) != PLUGIN_OK ||
        !json_push_kv_str(&reply->data, "schema", "zcl.lab_promote.v1") ||
        !json_push_kv_str(&reply->data, "root", p->root) ||
        !json_push_kv_int(&reply->data, "cases_passed", (int64_t)p->passed) ||
        !json_push_kv_str(&reply->data, "release_command", rel->command) ||
        !json_push_kv_str(&reply->data, "release_sha3_512", sha) ||
        !json_push_kv_str(&reply->data, "name", name) ||
        !json_push_kv_str(&reply->data, "version", version) ||
        !json_push_kv_str(&reply->data, "manifest", manifest) ||
        !json_push_kv_str(&reply->data, "signature", sig) ||
        !json_push_kv_str(&reply->data, "generation", generation) ||
        !json_push_kv_str(&reply->data, "public_key", key) ||
        !json_push_kv_str(&reply->data, "next", next))
        lab_fail(reply, "LAB_ALLOC", "serialize", "the receipt could not be built");
}

/* Steps 3 and 4 for a built release image. */
static void promote_verify(const struct zcl_command_request *rq,
                           struct lab_ctx *ctx, const struct promote_req *p,
                           const struct lab_compile *rel,
                           struct zcl_command_reply *reply)
{
    size_t passed = 0, failed = 0;
    char message[192];
    enum lab_check c = lab_cases_check(rq, ctx, rel->binary, p->timeout_ms,
                                       p->mem_mb, &passed, &failed);
    if (c == LAB_CHECK_UNCONFINED) {
        lab_unconfined(reply);
    } else if (c != LAB_CHECK_RAN) {
        lab_fail(reply, "LAB_BAD_CASES", "verify", "the cases could not be read again");
    } else if (failed > 0) {
        snprintf(message, sizeof(message),
                 "the release image failed %zu of %zu cases that the sanitized "
                 "build passed; nothing was written", failed, passed + failed);
        promote_refuse(reply, "LAB_PROMOTE_RELEASE_DISAGREES", "verify", message,
                       rel->command);
    } else if (promote_pack(rq, rel, reply)) {
        promote_report(reply, p, rel);
    }
}

void zcl_native_handle_lab_promote(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct promote_req p;
    struct lab_ctx ctx;
    struct lab_compile *rel;
    char name[LAB_ROOT_HEX + 16];
    if (!promote_parse(request, &p)) {
        lab_fail(reply, "LAB_BAD_INPUT", "normalize",
                 "usage: lab promote <file.c> --cases=<json> --name=<n> "
                 "--version=<v> --key=<key file>; timeout_ms is 1..60000, "
                 "mem_mb 1..2048");
        return;
    }
    if (!promote_cases(request, reply, &p) || !lab_ctx_open(&ctx, p.file, reply))
        return;
    rel = zcl_calloc(1, sizeof(*rel), "lab.compile");
    snprintf(name, sizeof(name), "%s-release", p.root);
    if (!rel) {
        lab_fail(reply, "LAB_ALLOC", "build", "the lab could not allocate");
    } else {
        lab_compile_release(&ctx.dirs, &ctx.tc, &ctx.src, name, rel);
        if (rel->unconfined)
            lab_unconfined(reply);
        else if (!rel->ok)
            promote_build_failed(reply, rel);
        else
            promote_verify(request, &ctx, &p, rel, reply);
        lab_compile_cleanup(&ctx.dirs, name);
    }
    free(rel);
    lab_ctx_close(&ctx);
}
