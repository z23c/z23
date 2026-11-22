/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lab.promote. Turn one C23 file that passes its lab cases into a
 * signed one-shot plugin (interface 2): run the cases as lab.test does, build a
 * static release image with the lab's compiler, run every case again against
 * that image through the lab's confined runner, and only then pack it through
 * plugin.pack with the caller's key. Nothing is written to the output directory
 * unless every gate passed, and nothing is installed. include-source additionally
 * exports the loaded source and effective cases after the signed pack succeeds. */
#include "command/lab_priv.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "platform/file_sync.h"
#include "platform/path_replace.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"
#include "util/file_io.h"
#include "util/path_util.h"
#include "util/write_all.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct promote_req {
    struct zcl_command_request test;
    const struct json_value *cases;
    const struct json_value *export_cases;
    const char *file;
    bool include_source;
    uint32_t timeout_ms, mem_mb;
    char root[LAB_ROOT_HEX + 1];
    size_t passed, failed;
};

static bool promote_flag(const struct zcl_command_request *rq, const char *key,
                         bool *value)
{
    const struct json_value *v = rq->input ? json_get(rq->input, key) : NULL;
    *value = false;
    if (!v)
        return true;
    if (v->type == JSON_BOOL) {
        *value = json_get_bool(v);
        return true;
    }
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    if (s && (s[0] == '\0' || strcmp(s, "true") == 0 || strcmp(s, "1") == 0)) {
        *value = true;
        return true;
    }
    return s && (strcmp(s, "false") == 0 || strcmp(s, "0") == 0);
}

static bool promote_parse(const struct zcl_command_request *rq,
                          struct promote_req *p)
{
    memset(p, 0, sizeof(*p));
    p->file = lab_in_str(rq, "file");
    return promote_flag(rq, "include-source", &p->include_source) &&
           p->file && lab_in_str(rq, "name") && lab_in_str(rq, "version") &&
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

static size_t promote_min(size_t a, size_t b)
{
    return a < b ? a : b;
}

static const char *promote_nonempty(const char *value, const char *fallback)
{
    return value && value[0] ? value : fallback;
}

/* Append bounded, UTF-8-repaired detail without replacing refusal evidence. */
static void promote_case_message(char message[192], const char *name, const char *diff, bool compiler)
{
    struct json_value text;
    bool name_cut = false, diff_cut = false;
    size_t used = strlen(message);
    size_t room = sizeof(((struct zcl_command_reply *)0)->error.message) - used;
    size_t framing = compiler ? 22 : 16;
    if (room < framing) return;
    size_t name_cap = compiler ? 0 : promote_min(room - framing, 24);
    size_t diff_cap = room - framing - name_cap;
    if (!compiler) diff_cap = promote_min(diff_cap, 56);
    json_init(&text);
    json_set_object(&text);
    name = promote_nonempty(name, "unavailable");
    diff = promote_nonempty(diff, "diagnostic unavailable");
    if ((compiler || lab_json_text(&text, "name", name, strlen(name), name_cap, &name_cut)) &&
        lab_json_text(&text, "diff", diff, strlen(diff), diff_cap, &diff_cut)) {
        const char *clean = json_get_str(json_get(&text, "diff"));
        if (compiler)
            (void)snprintf(message + used, room, "; compiler error: %s%s",
                           clean, diff_cut ? "..." : "");
        else
            (void)snprintf(message + used, room, "; case \"%s%s\": %s%s",
                           json_get_str(json_get(&text, "name")), name_cut ? "..." : "",
                           clean, diff_cut ? "..." : "");
    }
    json_free(&text);
}


static void promote_diagnostic(char message[192], long long line, long long col,
                               const char *detail)
{
    char description[LAB_DIAG_MESSAGE + 64];
    if (col > 0)
        snprintf(description, sizeof(description), "line %lld col %lld: %s",
                 line, col, detail);
    else
        snprintf(description, sizeof(description), "line %lld: %s", line, detail);
    promote_case_message(message, NULL, description, true);
}


/* Prefer the compiler error when no case could run. */
static bool promote_compile_error(char message[192], const struct json_value *data)
{
    const struct json_value *compile = json_get(data, "compile");
    const struct json_value *ok = json_get(compile, "ok");
    if (!ok || ok->type != JSON_BOOL || json_get_bool(ok))
        return false;
    const struct json_value *rows = json_get(compile, "diagnostics");
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        const struct json_value *severity = json_get(row, "severity");
        const struct json_value *detail = json_get(row, "message");
        if (!severity || severity->type != JSON_STR ||
            strcmp(json_get_str(severity), "error") != 0 ||
            !detail || detail->type != JSON_STR || !json_get_str(detail)[0])
            continue;
        promote_diagnostic(message, (long long)json_get_int(json_get(row, "line")),
                           (long long)json_get_int(json_get(row, "col")), json_get_str(detail));
        return true;
    }
    return false;
}

static void promote_first_row(char message[192], const struct json_value *data)
{
    const struct json_value *rows = json_get(data, "cases");
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        const struct json_value *pass = json_get(row, "pass");
        if (pass && pass->type == JSON_BOOL && !json_get_bool(pass)) {
            promote_case_message(message, json_get_str(json_get(row, "name")),
                                 json_get_str(json_get(row, "diff")), false);
            return;
        }
    }
    promote_case_message(message, NULL, NULL, false);
}

/* Step 1: lab.test on the same inputs, always fresh. A refusal of lab.test
 * itself stays in `reply`; false means the reply already carries a refusal. */
static bool promote_cases(struct lab_ctx *ctx,
                          struct zcl_command_reply *reply,
                          struct promote_req *p)
{
    char message[192];
    lab_test_context(&p->test, ctx, reply, p->cases);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED)
        return false;
    const struct json_value *sanitizer = json_get(&reply->data, "sanitizer");
    const struct json_value *enabled = json_get(sanitizer, "enabled");
    bool sanitized = enabled && enabled->type == JSON_BOOL && json_get_bool(enabled);
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
    if (p->failed > 0) {
        snprintf(message, sizeof(message), "%zu of %zu cases failed; nothing was written",
                 p->failed, p->passed + p->failed);
        if (!promote_compile_error(message, &reply->data))
            promote_first_row(message, &reply->data);
    }
    json_free(&reply->data);
    json_init(&reply->data);
    if (p->failed == 0 && p->passed > 0) {
        if (!sanitized) {
            promote_refuse(reply, "LAB_PROMOTE_SANITIZER_REQUIRED", "run",
                           "promotion requires a sanitized test build; nothing was packed", p->root);
            return false;
        }
        return true;
    }
    if (p->failed == 0)
        snprintf(message, sizeof(message), "0 of %zu cases failed; nothing was written", p->passed);
    promote_refuse(reply, "LAB_PROMOTE_CASES_FAILED", "cases", message, p->root);
    snprintf(reply->error.next_action, sizeof(reply->error.next_action),
             "z23 lab show %s", p->root);
    return false;
}

static void promote_build_failed(struct zcl_command_reply *reply,
                                 const struct lab_compile *rel)
{
    char message[192];
    for (size_t i = 0; i < rel->n_diag; i++) {
        const struct lab_diag *d = &rel->diag[i];
        if (strcmp(d->severity, "error") == 0 && d->message[0]) {
            snprintf(message, sizeof(message), "the static release build failed");
            promote_diagnostic(message, d->line, d->col, d->message);
            promote_refuse(reply, "LAB_PROMOTE_BUILD_FAILED", "build", message, rel->command);
            return;
        }
    }
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
    char sig[4096];
    size_t n;
    snprintf(manifest, sizeof(manifest), "%s", promote_str(&reply->data, "manifest"));
    snprintf(name, sizeof(name), "%s", promote_str(&reply->data, "name"));
    snprintf(version, sizeof(version), "%s", promote_str(&reply->data, "version"));
    snprintf(generation, sizeof(generation), "%s", promote_str(&reply->data, "generation"));
    snprintf(key, sizeof(key), "%s", promote_str(&reply->data, "public_key"));
    const char *packed_sha = promote_str(&reply->data, "exe_sha3_512");
    if (!lab_root_valid(packed_sha)) {
        lab_fail(reply, "LAB_ALLOC", "serialize", "the pack digest is unavailable");
        reply->error.mutated = true;
        snprintf(reply->error.evidence, sizeof(reply->error.evidence), "%s", manifest);
        return;
    }
    snprintf(sha, sizeof(sha), "%s", packed_sha);
    n = strlen(manifest);
    snprintf(sig, sizeof(sig), "%.*ssig", (int)(n >= 4 ? n - 4 : n), manifest);
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    if (!json_push_kv_str(&reply->data, "schema", "zcl.lab_promote.v1") ||
        !json_push_kv_str(&reply->data, "root", p->root) ||
        !json_push_kv_int(&reply->data, "cases_passed", (int64_t)p->passed) ||
        !json_push_kv_str(&reply->data, "release_command", rel->command) ||
        !json_push_kv_str(&reply->data, "release_sha3_512", sha) ||
        !json_push_kv_str(&reply->data, "name", name) ||
        !json_push_kv_str(&reply->data, "version", version) ||
        !json_push_kv_str(&reply->data, "manifest", manifest) ||
        !json_push_kv_str(&reply->data, "signature", sig) ||
        !json_push_kv_str(&reply->data, "generation", generation) ||
        !json_push_kv_str(&reply->data, "public_key", key)) {
        lab_fail(reply, "LAB_ALLOC", "serialize", "the receipt could not be built");
        reply->error.mutated = true;
        snprintf(reply->error.evidence, sizeof(reply->error.evidence), "%s", manifest);
    }
}

static bool promote_write(const char *path, const uint8_t *bytes, size_t len)
{
    char tmp[4096 + 32];
    int n = snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", path, (long)getpid());
    int fd = n > 0 && (size_t)n < sizeof(tmp)
                 ? open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600)
                 : -1;
    bool ok = fd >= 0 && zcl_write_all(fd, bytes, len);
    if (fd >= 0) {
        if (ok && platform_file_sync(fd) != 0)
            ok = false;
        if (close(fd) != 0)
            ok = false;
    }
    if (ok && platform_path_replace(tmp, path) != 0)
        ok = false;
    if (!ok && fd >= 0)
        (void)unlink(tmp);
    return ok;
}

/* Return 0 for absent, 1 for unmarked, 2 for our valid descriptor, -1 on error. */
static int promote_sidecar_kind(const char *path)
{
    static const char prefix[] = LAB_COMPILER_NAME_PREFIX;
    static const char marker[] = LAB_COMPILER_NAME_MARKER;
    char data[sizeof(marker) + 72];
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
#if !defined(_WIN32)
    flags |= O_NONBLOCK;
#endif
    int fd = open(path, flags);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    struct stat st;
    ssize_t n = fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
                    ? read(fd, data, sizeof(data) - 1) : -1;
    bool closed = close(fd) == 0;
    if (n < 0 || !closed)
        return -1;
    if (n < (ssize_t)(sizeof(prefix) - 1) ||
        memcmp(data, prefix, sizeof(prefix) - 1) != 0)
        return 1;
    if (n <= (ssize_t)(sizeof(marker) - 1) || n != st.st_size ||
        memcmp(data, marker, sizeof(marker) - 1) != 0)
        return -1;
    data[n] = '\0';
    return strlen(data) == (size_t)n &&
           lab_compiler_name_valid(data + sizeof(marker) - 1) ? 2 : -1;
}

/* Preserve unmarked members; only this versioned sidecar is replaced or removed. */
static bool promote_name_sidecar(const char *dir, const char *exported,
                                 const char *compiler_name)
{
    static const char marker[] = LAB_COMPILER_NAME_MARKER;
    char path[4096], data[sizeof(marker) + 72];
    if (!zcl_path_join(path, sizeof(path), dir, LAB_COMPILER_NAME_FILE))
        return false;
    int kind = promote_sidecar_kind(path);
    if (kind < 0)
        return false;
    if (strcmp(exported, compiler_name) == 0)
        return kind != 2 || unlink(path) == 0;
    if (kind == 1 || !lab_compiler_name_valid(compiler_name))
        return false;
    int n = snprintf(data, sizeof(data), "%s%s", marker, compiler_name);
    return n > 0 && (size_t)n < sizeof(data) &&
           promote_write(path, (const uint8_t *)data, (size_t)n);
}


static bool promote_cases_array(const struct json_value *v, uint8_t **bytes,
                                size_t *len)
{
    size_t need = json_write(v, NULL, 0);
    uint8_t *out = need ? zcl_malloc(need + 1, "lab.promote.cases") : NULL;
    if (out && json_write(v, (char *)out, need + 1) == need) {
        *bytes = out;
        *len = need;
        return true;
    }
    free(out);
    return false;
}

static bool promote_cases_export(const struct json_value *v,
                                 const uint8_t **bytes, size_t *len,
                                 uint8_t **storage)
{
    *bytes = NULL;
    *len = 0;
    if (v && v->type == JSON_ARR) {
        bool ok = promote_cases_array(v, storage, len);
        *bytes = *storage;
        return ok;
    }
    const char *text = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    const char *start = text ? text + strspn(text, " \t\n\r") : NULL;
    if (start && *start == '[') {
        *bytes = (const uint8_t *)text;
        *len = strlen(text);
        return *len > 0;
    }
    bool ok = text && zcl_read_whole_file(text, 1024 * 1024, storage, len,
                                          "lab.promote.cases") && *len > 0;
    *bytes = *storage;
    return ok;
}

static bool promote_export(const struct zcl_command_request *rq,
                           const struct json_value *cases_value,
                           const struct lab_ctx *ctx,
                           struct zcl_command_reply *reply)
{
    const char *dir = lab_in_str(rq, "dir");
    const char *name = lab_in_str(rq, "name");
    char leaf[PLUGIN_NAME_MAX + 3], source[4096], cases[4096];
    int n = snprintf(leaf, sizeof(leaf), "%s.c", name);
    const uint8_t *case_bytes = NULL;
    uint8_t *case_storage = NULL;
    size_t case_len = 0;
    bool ok = n > 0 && (size_t)n < sizeof(leaf) &&
              zcl_path_join(source, sizeof(source), dir ? dir : ".", leaf) &&
              zcl_path_join(cases, sizeof(cases), dir ? dir : ".", "cases.json") &&
              promote_name_sidecar(dir ? dir : ".", leaf, ctx->src.base) &&
              promote_cases_export(cases_value, &case_bytes, &case_len, &case_storage) &&
              promote_write(source, ctx->src.bytes, ctx->src.len) &&
              promote_write(cases, case_bytes, case_len) &&
              json_push_kv_str(&reply->data, "source", source) &&
              json_push_kv_str(&reply->data, "cases", cases);
    free(case_storage);
    return ok;
}

/* Steps 3 and 4 for a built release image. */
static void promote_verify(const struct zcl_command_request *rq,
                           struct lab_ctx *ctx, const struct promote_req *p,
                           const struct lab_compile *rel,
                           struct zcl_command_reply *reply)
{
    size_t passed = 0, failed = 0;
    char message[192];
    struct lab_case_fail fail = { { 0 }, { 0 } };
    enum lab_check c = lab_cases_check_cases(&p->test, ctx, rel->binary, p->timeout_ms,
                                       p->mem_mb, &passed, &failed, &fail, p->cases);
    if (c == LAB_CHECK_UNCONFINED) {
        lab_unconfined(reply);
    } else if (c == LAB_CHECK_ALLOC) {
        lab_fail(reply, "LAB_ALLOC", "verify", "the lab could not allocate case results");
    } else if (c != LAB_CHECK_RAN) {
        lab_fail(reply, "LAB_BAD_CASES", "verify", "the cases could not be read again");
    } else if (failed > 0) {
        snprintf(message, sizeof(message),
                 "the release image failed %zu of %zu cases that the sanitized "
                 "build passed; nothing was written", failed, passed + failed);
        promote_case_message(message, fail.name, fail.diff, false);
        promote_refuse(reply, "LAB_PROMOTE_RELEASE_DISAGREES", "verify", message,
                       rel->command);
    } else if (promote_pack(rq, rel, reply)) {
        promote_report(reply, p, rel);
        if (reply->status == ZCL_COMMAND_STATUS_PASSED && p->include_source &&
            !promote_export(rq, p->export_cases, ctx, reply)) {
            promote_refuse(reply, "LAB_PROMOTE_EXPORT_FAILED", "export",
                           "the signed pack was written, but its source and cases "
                           "could not be exported; no reproduction is claimed",
                           rel->command);
            reply->error.mutated = true;
        }
    }
}

static void promote_snapshot(const struct zcl_command_request *request,
                             struct promote_req *p,
                             struct zcl_command_reply *reply)
{
    struct lab_ctx ctx;
    struct lab_compile *rel;
    char name[LAB_ROOT_HEX + 16];
    if (!lab_in_bool(request, "sanitize", true)) {
        promote_refuse(reply, "LAB_PROMOTE_SANITIZER_REQUIRED", "normalize",
                       "promotion requires sanitize=true", "");
        return;
    }
    if (!lab_ctx_read(&ctx, p->file, reply))
        return;
    if (!promote_cases(&ctx, reply, p)) {
        lab_ctx_close(&ctx);
        return;
    }
    rel = zcl_calloc(1, sizeof(*rel), "lab.compile");
    snprintf(name, sizeof(name), "%s-release", p->root);
    if (!rel) {
        lab_fail(reply, "LAB_ALLOC", "build", "the lab could not allocate");
    } else {
        lab_compile_release(&ctx.dirs, &ctx.tc, &ctx.src, name, rel);
        if (rel->unconfined)
            lab_unconfined(reply);
        else if (!rel->ok)
            promote_build_failed(reply, rel);
        else
            promote_verify(request, &ctx, p, rel, reply);
        lab_compile_cleanup(&ctx.dirs, name);
    }
    free(rel);
    lab_ctx_close(&ctx);
}

void lab_promote_with_ready(const struct zcl_command_request *request,
                            lab_promote_ready_fn ready, void *context,
                            struct zcl_command_reply *reply)
{
    struct promote_req p;
    if (!promote_parse(request, &p)) {
        lab_fail(reply, "LAB_BAD_INPUT", "normalize",
                 "promotion requires file, cases, name, version and key with valid limits");
        return;
    }
    struct lab_case_snapshot cases;
    struct json_value test_options;
    json_init(&test_options);
    if (!lab_cases_snapshot(request, &cases, reply))
        return;
    static const char *const keys[] = {
        "file", "sanitize", "timeout_ms", "mem_mb"
    };
    bool keep_file = p.include_source && cases.file_text;
    bool keep_case_value = (p.include_source && !keep_file) || cases.parsed.type != JSON_ARR;
    bool ok = promote_forward(request, &test_options, keys, sizeof(keys) / sizeof(keys[0])) &&
              (!keep_case_value || json_push_kv(&test_options, "cases", cases.value)) &&
              json_push_kv_bool(&test_options, "fresh", true);
    if (!keep_file) {
        free(cases.file_text);
        cases.file_text = NULL;
    }
    if (ok) {
        p.test.input = &test_options;
        p.export_cases = keep_file ? &cases.file_view : json_get(&test_options, "cases");
        p.cases = cases.parsed.type == JSON_ARR ? &cases.parsed
                  : p.export_cases;
        if (!ready || ready(context, reply))
            promote_snapshot(request, &p, reply);
    } else {
        lab_fail(reply, "LAB_ALLOC", "normalize", "the promotion snapshot could not be allocated");
    }
    free(cases.file_text);
    json_free(&cases.parsed);
    json_free(&test_options);
}

void zcl_native_handle_lab_promote(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    lab_promote_with_ready(request, NULL, NULL, reply);
}
