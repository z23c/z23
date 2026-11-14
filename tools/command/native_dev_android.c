/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Plan and track unsigned Android packages through native dev jobs. */
#define _GNU_SOURCE
#include "command/native_command.h"
#include "command/native_dev_job.h"
#include "config/command_catalog.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "util/spawn.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DA_PATH 1024
#define DA_ARGS 32
struct da_plan {
    char cwd[DA_PATH], head[41], tree[41], node[DA_PATH], source[41], hash[65];
    char sdk[DA_PATH], ndk[DA_PATH], java[DA_PATH], params[DA_PATH];
    char inputs[10][65], debug[DA_PATH], debug_hash[65];
};
static const char *da_str(const struct json_value *o, const char *k)
{ return zcl_dev_job_str(json_get(o, k)); }
static bool da_path(const char *s)
{
    if (!s || s[0] != '/' || strlen(s) >= DA_PATH - 64) return false;
    for (; *s; ++s) if ((unsigned char)*s < 32 || *s == '\x27' || *s == '$' || *s == '`' || *s == '\\') return false;
    return true;
}
static bool da_hash(const char *path, char out[65])
{
    struct stat st; unsigned char buf[16384], digest[32]; struct sha256_ctx ctx;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK); if (fd < 0) return false;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode); ssize_t n = 0;
    sha256_init(&ctx);
    while (ok && (n = read(fd, buf, sizeof(buf))) > 0) sha256_write(&ctx, buf, (size_t)n);
    int closed = close(fd);
    if (n < 0 || closed) ok = false;
    if (!ok) return false;
    sha256_finalize(&ctx, digest); zcl_hex_encode(digest, sizeof(digest), out); return true;
}
static bool da_git(const char *cwd, const char *const *argv, char *out, size_t cap)
{
    if (zcl_spawn_capture_in_dir_observed(argv, cwd, out, cap, 15000, NULL) != 0) return false;
    out[strcspn(out, "\r\n")] = 0; return true;
}
static bool da_source(struct da_plan *p)
{
    const char *head[] = {"git", "rev-parse", "HEAD", NULL};
    const char *tree[] = {"git", "rev-parse", "HEAD^{tree}", NULL};
    const char *status[] = {"git", "--no-optional-locks", "status", "--porcelain", "--untracked-files=all", NULL};
    char dirty[8192], head_text[128], tree_text[128];
    bool ok = zcl_dev_job_linked_worktree_registered(p->cwd) &&
        da_git(p->cwd, head, head_text, sizeof(head_text)) && strlen(head_text) == 40 &&
        da_git(p->cwd, tree, tree_text, sizeof(tree_text)) && strlen(tree_text) == 40 &&
        da_git(p->cwd, status, dirty, sizeof(dirty)) && !dirty[0];
    if (ok) { memcpy(p->head, head_text, 41); memcpy(p->tree, tree_text, 41); }
    return ok;
}
static bool da_copy(char *out, size_t cap, const char *value)
{
    if (!value) return false;
    int n = snprintf(out, cap, "%s", value);
    return n > 0 && (size_t)n < cap;
}
static const char *da_input(const struct json_value *in, const char *key, const char *env, const char *alt)
{
    const char *v = da_str(in, key); if (v) return v;
    v = env ? getenv(env) : NULL; if (v && *v) return v;
    return alt ? getenv(alt) : NULL;
}
static bool da_regular(const char *dir, const char *suffix, int mode)
{
    char p[DA_PATH]; struct stat st; int n = snprintf(p, sizeof(p), "%s/%s", dir, suffix);
    return n > 0 && (size_t)n < sizeof(p) && stat(p, &st) == 0 && S_ISREG(st.st_mode) && access(p, mode) == 0;
}
static bool da_hash_child(const char *dir, const char *name, char hash[65])
{
    char path[DA_PATH]; int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    return n > 0 && (size_t)n < sizeof(path) && da_hash(path, hash);
}
static bool da_collect_inputs(struct da_plan *p)
{
    return da_hash_child(p->params, "sapling-spend.params", p->inputs[0]) &&
        da_hash_child(p->params, "sapling-output.params", p->inputs[1]) &&
        da_hash_child(p->sdk, "build-tools/35.0.0/aapt", p->inputs[2]) &&
        da_hash_child(p->sdk, "build-tools/35.0.0/zipalign", p->inputs[3]) &&
        da_hash_child(p->sdk, "platforms/android-35/android.jar", p->inputs[4]) &&
        da_hash_child(p->ndk, "build/cmake/android.toolchain.cmake", p->inputs[5]) &&
        da_hash_child(p->java, "bin/jar", p->inputs[6]) &&
        da_hash_child(p->sdk, "build-tools/35.0.0/apksigner", p->inputs[7]) &&
        da_hash_child(p->java, "bin/keytool", p->inputs[8]) &&
        da_hash_child(p->cwd, "vendor/cross/aarch64-linux-android35/lib/libcrypto.a", p->inputs[9]);
}
static bool da_inputs(const struct zcl_command_request *req, struct da_plan *p, const char **reason)
{
    const struct json_value *in = req ? req->input : NULL;
    const char *cwd = da_str(in, "cwd"); char inferred[PATH_MAX];
    if (!cwd) {
        const char *root = zcl_native_source_root(req);
        if (!root || !realpath(root, inferred)) { *reason = "Cannot resolve the current worktree."; return false; }
        cwd = inferred;
    }
    const char *node = da_str(in, "node_bin"), *source = da_str(in, "node_source");
    const char *debug = da_str(in, "node_debug");
    const char *sdk = da_input(in, "sdk_root", "SDK_ROOT", "ANDROID_SDK_ROOT");
    const char *ndk = da_input(in, "ndk_root", "ANDROID_NDK_ROOT", "ANDROID_NDK_HOME");
    const char *java = da_input(in, "java_home", "JAVA_HOME", NULL);
    const char *params = da_input(in, "params_dir", "ZCASH_PARAMS_DIR", NULL);
    char default_node[DA_PATH], default_params[DA_PATH];
    if (cwd) {
        int a = snprintf(default_node, sizeof(default_node), "%s/build/bin/z23", cwd);
        int b = snprintf(default_params, sizeof(default_params), "%s/vendor/params", cwd);
        if (!node && a > 0 && (size_t)a < sizeof(default_node)) node = default_node;
        if (!params && b > 0 && (size_t)b < sizeof(default_params)) params = default_params;
    }
    if (!java) java = "/usr/lib/jvm/default";
    const char *paths[] = {cwd, node, debug, sdk, ndk, java, params};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (paths[i] && !da_path(paths[i])) {
            *reason = "Paths must be absolute and cannot contain dollar signs, quotes, backticks, backslashes or control characters; spaces are allowed.";
            return false;
        }
    }
    if (!da_copy(p->cwd, sizeof(p->cwd), cwd) || !da_path(p->cwd) || !da_source(p)) {
        *reason = "Use a clean registered worktree, including untracked source files."; return false;
    }
    if (!da_copy(p->node, sizeof(p->node), node) || !da_path(p->node) || access(p->node, X_OK) || !da_hash(p->node, p->hash)) {
        *reason = "Supply node_bin for an existing Android node. Build it with devbuild --wait make ZCL_TARGET=android-arm64 z23."; return false;
    }
    if (debug) {
        if (!da_copy(p->debug, sizeof(p->debug), debug) || !da_hash(debug, p->debug_hash)) {
            *reason = "Cannot read node_debug."; return false;
        }
    } else { strcpy(p->debug, "none"); strcpy(p->debug_hash, "none"); }
    unsigned char bytes[20];
    if (!da_copy(p->source, sizeof(p->source), source) || !zcl_hex_decode_lower(p->source, bytes, sizeof(bytes))) {
        *reason = "Supply the node_source commit; its provenance will remain unverified."; return false;
    }
    if (!da_copy(p->sdk, sizeof(p->sdk), sdk) || !da_path(p->sdk) ||
        !da_copy(p->ndk, sizeof(p->ndk), ndk) || !da_path(p->ndk) ||
        !da_copy(p->java, sizeof(p->java), java) || !da_path(p->java) ||
        !da_copy(p->params, sizeof(p->params), params) || !da_path(p->params)) {
        *reason = "Supply sdk_root, ndk_root, java_home and params_dir, or set their environment defaults."; return false;
    }
    if (!da_regular(p->sdk, "build-tools/35.0.0/aapt", X_OK) || !da_regular(p->sdk, "build-tools/35.0.0/zipalign", X_OK) || !da_regular(p->sdk, "build-tools/35.0.0/apksigner", X_OK) ||
        !da_regular(p->sdk, "platforms/android-35/android.jar", R_OK) || !da_regular(p->ndk, "build/cmake/android.toolchain.cmake", R_OK) ||
        !da_regular(p->java, "bin/jar", X_OK) || !da_regular(p->java, "bin/keytool", X_OK) || !da_regular(p->params, "sapling-spend.params", R_OK) ||
        !da_regular(p->params, "sapling-output.params", R_OK)) {
        *reason = "Install the Android SDK, NDK, JDK and verified Sapling parameters, then retry."; return false;
    }
    if (!da_regular(p->cwd, "vendor/cross/aarch64-linux-android35/lib/libcrypto.a", R_OK) ||
        !da_regular(p->cwd, "vendor/cross/aarch64-linux-android35/include/openssl/evp.h", R_OK)) {
        *reason = "Build Android vendor prerequisites in this worktree with devbuild --wait make ZCL_TARGET=android-arm64 z23."; return false;
    }
    if (!da_collect_inputs(p)) { *reason = "Cannot hash the Android build inputs."; return false; }
    return true;
}
static void da_fail(struct zcl_command_reply *r, const char *code, const char *message)
{ zcl_command_reply_fail(r, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID, code, "validate", false, false, message, "dev.android.plan"); }
static bool da_arg(struct json_value *a, const char *s)
{ struct json_value v; json_init(&v); json_set_str(&v, s); bool ok = json_push_back(a, &v); json_free(&v); return ok; }
static bool da_pair(struct json_value *a, const char *key, const char *value)
{ char item[DA_PATH + 96]; int n = snprintf(item, sizeof(item), "%s=%s", key, value); return n > 0 && (size_t)n < sizeof(item) && da_arg(a, item); }
static bool da_args(struct json_value *a, const struct da_plan *p, const char *out)
{
    bool ok = da_arg(a, "make") && da_arg(a, "-C") && da_arg(a, "apps/z23android") && da_arg(a, "aligned-apk") &&
        da_pair(a, "BUILD_DIR", out) && da_pair(a, "NODE_BIN", p->node) && da_pair(a, "SDK_ROOT", p->sdk) &&
        da_pair(a, "ANDROID_NDK_ROOT", p->ndk) && da_pair(a, "JAVA_HOME", p->java) && da_pair(a, "PARAMS_DIR", p->params) &&
        da_pair(a, "Z23_ANDROID_NODE_SHA256", p->hash) && da_pair(a, "Z23_ANDROID_NODE_SOURCE", p->source) &&
        da_pair(a, "Z23_ANDROID_TREE", p->tree) && da_arg(a, "PACK_PARAMS=1") &&
        da_arg(a, "DEVKEY_PROBE=OFF") && da_arg(a, "ZAPP_SHARE_FIXTURE=OFF") &&
        da_arg(a, "PACKAGE_PREVIEW=0") && da_arg(a, "APP_MANIFEST=AndroidManifest.xml") &&
        da_arg(a, "ANDROID_API=35") && da_arg(a, "BUILD_TOOLS_VERSION=35.0.0");
    for (size_t i = 0; ok && i < 10; ++i) {
        char key[40]; snprintf(key, sizeof(key), "Z23_ANDROID_INPUT_%zu", i);
        ok = da_pair(a, key, p->inputs[i]);
    }
    return ok && da_pair(a, "Z23_ANDROID_NODE_DEBUG", p->debug) &&
        da_pair(a, "Z23_ANDROID_NODE_DEBUG_SHA256", p->debug_hash);
}
static bool da_plan_input(const struct da_plan *p, struct json_value *in)
{
    json_init(in); json_set_object(in);
    return json_push_kv_str(in, "cwd", p->cwd) && json_push_kv_str(in, "node_bin", p->node) &&
        json_push_kv_str(in, "node_source", p->source) &&
        (!strcmp(p->debug, "none") || json_push_kv_str(in, "node_debug", p->debug)) &&
        json_push_kv_str(in, "sdk_root", p->sdk) && json_push_kv_str(in, "ndk_root", p->ndk) &&
        json_push_kv_str(in, "java_home", p->java) && json_push_kv_str(in, "params_dir", p->params);
}
static bool da_next(struct zcl_command_reply *r, const char *command,
                    const struct json_value *input, const char *reason)
{
    struct json_value action; json_init(&action); json_set_object(&action);
    bool ok = json_push_kv_str(&action, "command", command) &&
        json_push_kv(&action, "input", input) && json_push_kv(&r->data, "next_action", &action);
    json_free(&action);
    char wire[sizeof(r->next[0].input_json)];
    size_t n = ok ? json_write(input, wire, sizeof(wire)) : 0;
    if (n && n < sizeof(wire) && strcmp(command, "manual")) ok = zcl_command_reply_add_next(r, command, wire, reason);
    return ok;
}
static void da_emit_failed(struct zcl_command_reply *r, bool mutated)
{
    json_free(&r->data); json_init(&r->data); json_set_object(&r->data);
    zcl_command_reply_fail(r, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
        "ANDROID_REPLY_FAILED", "reply", false, mutated, "Could not construct the Android job response.", "dev.android");
}
static bool da_invoke(const struct zcl_command_request *req, struct zcl_command_reply *r,
                      const struct json_value *input, const char *path, zcl_command_handler_fn handler,
                      const struct json_value *semantic_argv)
{
    struct zcl_command_request local = *req; char why[256];
    local.input = input; local.spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!local.spec || !zcl_command_registry_input_validate(local.spec, input, why, sizeof(why))) {
        da_fail(r, "ANDROID_JOB_INPUT", "The native job contract rejected the generated input."); return false;
    }
    if (semantic_argv) zcl_dev_job_start_keyed(&local, r, semantic_argv);
    else handler(&local, r);
    return true;
}

void zcl_native_handle_dev_android_plan(const struct zcl_command_request *req, struct zcl_command_reply *r)
{
    struct da_plan p = {0}; const char *reason = NULL;
    if (!da_inputs(req, &p, &reason)) { da_fail(r, "ANDROID_INPUT_REQUIRED", reason); return; }
    struct json_value input; bool ok = da_plan_input(&p, &input) &&
        json_push_kv_str(&r->data, "state", "ready") &&
        json_push_kv_str(&r->data, "summary", "Ready to prepare an unsigned Android package.") &&
        json_push_kv_str(&r->data, "app_source", p.head) && json_push_kv_str(&r->data, "app_tree", p.tree) &&
        json_push_kv_str(&r->data, "node_source_provided", p.source) &&
        json_push_kv_str(&r->data, "node_provenance", "unverified") && json_push_kv_str(&r->data, "node_sha256", p.hash) &&
        da_next(r, "dev.android.prepare", &input, "start the unsigned package job");
    json_free(&input); if (!ok) da_emit_failed(r, false);
}
static bool da_handle(const struct json_value *h, struct da_plan *p, char out[DA_PATH]);
static bool da_existing_job(const char *id, const struct da_plan *p, const struct json_value *semantic, char out[DA_PATH])
{
    struct json_value handle; json_init(&handle); struct da_plan found = {0};
    bool ok = zcl_dev_job_read_handle(id, &handle) && da_handle(&handle, &found, out) &&
        !strcmp(found.cwd, p->cwd) && !strcmp(found.head, p->head);
    const struct json_value *argv = json_get(&handle, "argv");
    for (size_t i = 0; ok && i < DA_ARGS; ++i) {
        if (i == 4) continue;
        const char *a = zcl_dev_job_str(json_at(argv, i)), *b = zcl_dev_job_str(json_at(semantic, i));
        ok = a && b && !strcmp(a, b);
    }
    json_free(&handle); return ok;
}

void zcl_native_handle_dev_android_prepare(const struct zcl_command_request *req, struct zcl_command_reply *r)
{
    struct da_plan p = {0}; const char *reason = NULL; char build[DA_PATH], parent[DA_PATH], out[DA_PATH];
    struct stat st; bool mutated = false;
    if (!da_inputs(req, &p, &reason)) { da_fail(r, "ANDROID_INPUT_REQUIRED", reason); return; }
    int n = snprintf(build, sizeof(build), "%s/build", p.cwd);
    if (n < 0 || (size_t)n >= sizeof(build)) { da_fail(r, "OUTPUT_UNAVAILABLE", "Build path is too long."); return; }
    bool missing = lstat(build, &st) != 0 && errno == ENOENT;
    if (!platform_directory_ensure(build, 0700)) { da_fail(r, "OUTPUT_UNAVAILABLE", "Cannot create the build directory."); return; }
    mutated = missing;
    n = snprintf(parent, sizeof(parent), "%s/build/android-jobs", p.cwd);
    if (n < 0 || (size_t)n >= sizeof(parent)) { da_emit_failed(r, mutated); return; }
    missing = lstat(parent, &st) != 0 && errno == ENOENT;
    if (!platform_directory_ensure(parent, 0700)) { da_emit_failed(r, mutated); return; }
    mutated = mutated || missing;
    n = snprintf(out, sizeof(out), "%s/run-XXXXXX", parent);
    if (n < 0 || (size_t)n >= sizeof(out) || !mkdtemp(out)) { da_emit_failed(r, mutated); return; }
    struct json_value in, args, semantic; json_init(&in); json_set_object(&in);
    json_init(&args); json_set_array(&args); json_init(&semantic); json_set_array(&semantic);
    bool ok = da_args(&args, &p, out) && da_args(&semantic, &p, "/z23-android-output") &&
        json_push_kv(&in, "argv", &args) && json_push_kv_str(&in, "cwd", p.cwd) && json_push_kv_str(&in, "label", "android-unsigned-v1");
    json_free(&args);
    if (!ok) { json_free(&semantic); json_free(&in); if (rmdir(out)) mutated = true; da_emit_failed(r, mutated); return; }
    bool invoked = da_invoke(req, r, &in, "dev.loop.job.start", zcl_native_handle_dev_job_start, &semantic);
    json_free(&in);
    if (!invoked) { json_free(&semantic); if (rmdir(out)) mutated = true; r->error.mutated = mutated; return; }
    if (r->status != ZCL_COMMAND_STATUS_PASSED) { json_free(&semantic); r->error.mutated = true; return; }
    const char *id = da_str(&r->data, "job_id"); char saved_id[ZCL_DEV_JOB_ID_MAX + 1] = {0};
    if (id) snprintf(saved_id, sizeof(saved_id), "%s", id);
    const char *state = da_str(&r->data, "state");
    bool attached = state && !strcmp(state, "attached");
    bool removed = !attached || rmdir(out) == 0;
    char recorded[DA_PATH];
    ok = removed && id && da_existing_job(id, &p, &semantic, recorded);
    json_free(&semantic);
    struct json_value next; json_init(&next); json_set_object(&next);
    ok = ok && json_push_kv_str(&r->data, "output_dir", recorded) && json_push_kv_str(&next, "job_id", id) &&
        da_next(r, "dev.android.status", &next, "check the Android package job");
    json_free(&next);
    if (!ok) {
        da_emit_failed(r, true);
        snprintf(r->error.evidence, sizeof(r->error.evidence), "%s", saved_id);
    }
}
static const char *da_item(const struct json_value *a, size_t i)
{ return zcl_dev_job_str(json_at(a, i)); }
static const char *da_value(const struct json_value *a, size_t i, const char *key)
{
    const char *s = da_item(a, i); size_t n = strlen(key);
    return s && !strncmp(s, key, n) && s[n] == '=' && s[n + 1] ? s + n + 1 : NULL;
}
static bool da_handle(const struct json_value *h, struct da_plan *p, char out[DA_PATH])
{
    const struct json_value *a = json_get(h, "argv");
    const char *label = da_str(h, "label"), *cwd = da_str(h, "cwd"), *head = da_str(h, "head");
    if (!a || a->type != JSON_ARR || json_size(a) != DA_ARGS || !label || strcmp(label, "android-unsigned-v1") ||
        !da_item(a, 0) || strcmp(da_item(a, 0), "make") || !da_item(a, 1) || strcmp(da_item(a, 1), "-C") ||
        !da_item(a, 2) || strcmp(da_item(a, 2), "apps/z23android") || !da_item(a, 3) || strcmp(da_item(a, 3), "aligned-apk")) return false;
    const char *dir = da_value(a, 4, "BUILD_DIR"), *node = da_value(a, 5, "NODE_BIN");
    const char *sdk = da_value(a, 6, "SDK_ROOT"), *ndk = da_value(a, 7, "ANDROID_NDK_ROOT");
    const char *java = da_value(a, 8, "JAVA_HOME"), *params = da_value(a, 9, "PARAMS_DIR");
    const char *hash = da_value(a, 10, "Z23_ANDROID_NODE_SHA256"), *source = da_value(a, 11, "Z23_ANDROID_NODE_SOURCE");
    const char *tree = da_value(a, 12, "Z23_ANDROID_TREE");
    const char *fixed[] = {"PACK_PARAMS=1", "DEVKEY_PROBE=OFF", "ZAPP_SHARE_FIXTURE=OFF", "PACKAGE_PREVIEW=0", "APP_MANIFEST=AndroidManifest.xml", "ANDROID_API=35", "BUILD_TOOLS_VERSION=35.0.0"};
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i)
        if (!da_item(a, i + 13) || strcmp(da_item(a, i + 13), fixed[i])) return false;
    if (!da_copy(p->cwd, sizeof(p->cwd), cwd) || !da_copy(p->head, sizeof(p->head), head) ||
        !da_copy(out, DA_PATH, dir) || !da_copy(p->node, sizeof(p->node), node) ||
        !da_copy(p->sdk, sizeof(p->sdk), sdk) || !da_copy(p->ndk, sizeof(p->ndk), ndk) ||
        !da_copy(p->java, sizeof(p->java), java) || !da_copy(p->params, sizeof(p->params), params) ||
        !da_copy(p->hash, sizeof(p->hash), hash) || !da_copy(p->source, sizeof(p->source), source) ||
        !da_copy(p->tree, sizeof(p->tree), tree)) return false;
    for (size_t i = 0; i < 10; ++i) {
        char key[40]; snprintf(key, sizeof(key), "Z23_ANDROID_INPUT_%zu", i);
        if (!da_copy(p->inputs[i], sizeof(p->inputs[i]), da_value(a, i + 20, key))) return false;
    }
    if (!da_copy(p->debug, sizeof(p->debug), da_value(a, 30, "Z23_ANDROID_NODE_DEBUG")) ||
        !da_copy(p->debug_hash, sizeof(p->debug_hash), da_value(a, 31, "Z23_ANDROID_NODE_DEBUG_SHA256"))) return false;
    if (strcmp(p->debug, "none") && !da_path(p->debug)) return false;
    char prefix[DA_PATH]; int n = snprintf(prefix, sizeof(prefix), "%s/build/android-jobs/run-", p->cwd);
    const char *suffix = n > 0 && (size_t)n < sizeof(prefix) && !strncmp(out, prefix, (size_t)n) ? out + n : NULL;
    unsigned char digest[32], commit[20];
    return da_path(p->cwd) && da_path(out) && da_path(p->node) && suffix && strlen(suffix) == 6 && !strchr(suffix, '/') &&
        strlen(p->head) == 40 && zcl_hex_decode_lower(p->head, commit, sizeof(commit)) &&
        zcl_hex_decode_lower(p->source, commit, sizeof(commit)) && zcl_hex_decode_lower(p->tree, commit, sizeof(commit)) &&
        zcl_hex_decode_lower(p->hash, digest, sizeof(digest));
}
void zcl_native_handle_dev_android_status(const struct zcl_command_request *req, struct zcl_command_reply *r)
{
    const char *id = req ? da_str(req->input, "job_id") : NULL; struct json_value handle;
    json_init(&handle); struct da_plan expected = {0}; char out[DA_PATH];
    if (!id || !zcl_dev_job_read_handle(id, &handle) || !da_handle(&handle, &expected, out)) {
        json_free(&handle); da_fail(r, "ANDROID_JOB_REQUIRED", "Supply an Android job_id from dev android prepare."); return;
    }
    struct json_value wait; json_init(&wait); json_set_object(&wait);
    const struct json_value *timeout = json_get(req->input, "timeout_s");
    bool reply_ok = json_push_kv_str(&wait, "job_id", id) &&
        (timeout ? json_push_kv(&wait, "timeout_s", timeout) : json_push_kv_int(&wait, "timeout_s", 1));
    if (!reply_ok || !da_invoke(req, r, &wait, "dev.loop.job.wait", zcl_native_handle_dev_job_wait, NULL)) {
        json_free(&wait); json_free(&handle); if (!reply_ok) da_emit_failed(r, false); return;
    }
    json_free(&wait);
    const char *state = da_str(&r->data, "state");
    if (!state || strcmp(state, "passed")) {
        struct json_value next; bool running = state && !strcmp(state, "running");
        if (running) { json_init(&next); json_set_object(&next); reply_ok = json_push_kv_str(&next, "job_id", id); }
        else reply_ok = da_plan_input(&expected, &next);
        reply_ok = reply_ok && json_push_kv_str(&r->data, "summary", running ?
            "The Android package job is running." : "The Android package job did not complete successfully.") &&
            da_next(r, running ? "dev.android.status" : "dev.android.prepare", &next,
                    running ? "check progress" : "inspect the log, then retry");
        json_free(&next); json_free(&handle); if (!reply_ok) da_emit_failed(r, false); return;
    }
    struct stat out_st;
    struct da_plan observed = {0}; char nodehash[65], apkhash[65], apk[DA_PATH], apphash[65], stagedhash[65], file[DA_PATH];
    bool ok = lstat(out, &out_st) == 0 && S_ISDIR(out_st.st_mode) && out_st.st_uid == geteuid() &&
        (out_st.st_mode & 077) == 0 && da_copy(observed.cwd, sizeof(observed.cwd), expected.cwd) && da_source(&observed) &&
        !strcmp(observed.head, expected.head) && !strcmp(observed.tree, expected.tree) &&
        da_hash(expected.node, nodehash) && !strcmp(nodehash, expected.hash);
    bool input_ok = da_collect_inputs(&expected);
    for (size_t i = 0; input_ok && i < 10; ++i) {
        char key[40]; snprintf(key, sizeof(key), "Z23_ANDROID_INPUT_%zu", i);
        const char *recorded = da_value(json_get(&handle, "argv"), i + 20, key);
        input_ok = recorded && !strcmp(expected.inputs[i], recorded);
    }
    ok = ok && input_ok;
    if (strcmp(expected.debug, "none")) {
        char debug_hash[65];
        ok = ok && da_hash(expected.debug, debug_hash) && !strcmp(debug_hash, expected.debug_hash);
    } else ok = ok && !strcmp(expected.debug_hash, "none");
    int n = snprintf(apk, sizeof(apk), "%s/aligned.apk", out);
    ok = ok && n > 0 && (size_t)n < sizeof(apk) && da_hash(apk, apkhash);
    n = snprintf(file, sizeof(file), "%s/native/libz23android.so", out);
    ok = ok && n > 0 && (size_t)n < sizeof(file) && da_hash(file, apphash);
    n = snprintf(file, sizeof(file), "%s/package/lib/arm64-v8a/libz23node.so", out);
    ok = ok && n > 0 && (size_t)n < sizeof(file) && da_hash(file, stagedhash) && !strcmp(stagedhash, expected.hash);
    struct json_value *state_value = (struct json_value *)json_get(&r->data, "state");
    if (!ok) {
        json_set_str(state_value, "unproven");
        struct json_value next; json_init(&next);
        reply_ok = state_value->type == JSON_STR && da_plan_input(&expected, &next);
        reply_ok = reply_ok && json_push_kv_str(&r->data, "summary", "The unsigned package could not be verified against its inputs.") &&
            da_next(r, "dev.android.prepare", &next, "check inputs and retry");
        json_free(&next);
    } else {
        json_set_str(state_value, "artifact_observed");
        struct json_value next; json_init(&next); json_set_object(&next);
        reply_ok = state_value->type == JSON_STR &&
            json_push_kv_str(&r->data, "summary", "Unsigned APK observed; package, alignment and embedded node need verification.") &&
            json_push_kv_str(&r->data, "aligned_apk", apk) && json_push_kv_str(&r->data, "aligned_sha256", apkhash) &&
            json_push_kv_str(&r->data, "app_library_sha256", apphash) && json_push_kv_str(&r->data, "node_debug_sha256", expected.debug_hash) &&
            json_push_kv_str(&r->data, "embedded_node_verification", "not_checked") && json_push_kv_str(&r->data, "app_source", expected.head) &&
            json_push_kv_str(&r->data, "app_tree", expected.tree) && json_push_kv_str(&r->data, "node_sha256", expected.hash) &&
            json_push_kv_str(&r->data, "node_source_provided", expected.source) && json_push_kv_str(&r->data, "node_provenance", "unverified") &&
            json_push_kv_str(&r->data, "toolchain_provenance", "partially_observed") &&
            json_push_kv_str(&next, "instructions", "Transfer the APK. Run aapt dump badging <local-apk>, zipalign -c -P 16 4 <local-apk>, and unzip -p <local-apk> lib/arm64-v8a/libz23node.so | sha256sum. Compare node_sha256, then sign locally.") &&
            da_next(r, "manual", &next, "verify and sign on the local host");
        json_free(&next);
    }
    json_free(&handle); if (!reply_ok) da_emit_failed(r, false);
}
