/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Owner-authorized metadata-only successor for a saved personal copy. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "command/native_app_personalize_command.h"
#include "command/native_app_personalize_view.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "json/json.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs_object.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
bool app_personalize_namespace(const char *pubkey_hex, char *out, size_t out_cap)
{
    uint8_t pub[33], digest[32]; char hex[65];
    if (!pubkey_hex || strlen(pubkey_hex) != 66 || !out || out_cap < 63 ||
        !zcl_hex_decode_lower(pubkey_hex, pub, sizeof(pub))) return false;
    sha3_256(pub, sizeof(pub), digest); zcl_hex_encode(digest, sizeof(digest), hex);
    int n = snprintf(out, out_cap, "p-%.60s", hex);
    return n == 62 && (size_t)n < out_cap;
}
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#define AP_COMMAND "app.personalize"
#define AP_PATH 4400
#define AP_META_MAX (1024u * 1024u)
struct ap {
    struct zcl_command_reply *reply;
    struct zcl_package_copy copy;
    struct vcs_manifest manifest;
    struct json_value metadata;
    char dir[AP_PATH], datadir[AP_PATH], key[AP_PATH], scratch[AP_PATH];
    char short_name[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1], name[VCS_PACKAGE_RELEASE_NAME_MAX + 1];
    char namespace_name[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1];
    char original_name[VCS_PACKAGE_RELEASE_NAME_MAX + 1];
    uint8_t head[32], pub[33], plan[32], tree[32], version[32];
    mode_t meta_mode;
    bool key_absent, key_created, mutated, confirm, changed;
};
static bool ap_fail(struct ap *p, const char *code, const char *why)
{
    zcl_package_copy_fail(p->reply, code, p->mutated, why, AP_COMMAND);
    if (p->mutated) {
        struct json_value facts; json_init(&facts); json_set_object(&facts);
        (void)json_push_kv_bool(&facts, "key_created", p->key_created);
        (void)json_push_kv_str(&facts, "namespace", p->namespace_name);
        if (memcmp(p->version, (uint8_t[32]){0}, 32))
            zcl_package_copy_push_root(&facts, "candidate_version", p->version);
        (void)json_push_kv(&p->reply->data, "failure_facts", &facts);
        json_free(&facts);
    }
    return false;
}
static bool ap_hex(const struct json_value *in, const char *key, uint8_t out[32])
{
    const char *s = zcl_package_copy_str(in, key);
    return s && strlen(s) == 64 && zcl_hex_decode_lower(s, out, 32);
}
static bool ap_locations(struct ap *p, const struct json_value *in)
{
    const char *copy = zcl_package_copy_str(in, "copy");
    const char *data = zcl_package_copy_str(in, "datadir");
    if (!copy || copy[0] != '/' || !data || data[0] != '/' ||
        !realpath(copy, p->dir) || !realpath(data, p->datadir))
        return ap_fail(p, "BAD_INPUT", "absolute copy and datadir, saved version and expected head are required");
    return true;
}
static bool ap_legacy_keys(const struct json_value *in)
{
    static const char *const allowed[] = {
        "copy", "datadir", "version", "expected_head", "plan_id", "confirm"
    };
    unsigned seen = 0;
    for (size_t i = 0; i < in->num_children; ++i) {
        unsigned bit = 0;
        for (size_t j = 0; j < sizeof(allowed) / sizeof(allowed[0]); ++j)
            if (!strcmp(in->keys[i], allowed[j])) bit = 1u << j;
        if (!bit || (seen & bit)) return false;
        seen |= bit;
    }
    return true;
}
static bool ap_inputs(struct ap *p, const struct json_value *in, char version[65])
{
    if (!in || in->type != JSON_OBJ) return ap_fail(p, "BAD_INPUT", "input object required");
    if (!ap_legacy_keys(in)) return ap_fail(p, "BAD_INPUT", "Duplicate or unknown personalization input");
    if (!ap_locations(p, in)) return false;
    const char *v = zcl_package_copy_str(in, "version");
    const struct json_value *confirm = json_get(in, "confirm");
    uint8_t checked[32];
    if (!v || strlen(v) != 64 ||
        !zcl_hex_decode_lower(v, checked, 32) || !ap_hex(in, "expected_head", p->head) ||
        (confirm && confirm->type != JSON_BOOL))
        return ap_fail(p, "BAD_INPUT", "absolute copy and datadir, saved version and expected head are required");
    memcpy(version, v, 65); p->confirm = confirm && json_get_bool(confirm);
    return true;
}
static bool ap_open(struct ap *p, const char *version, enum zcl_package_copy_access access)
{
    if (!zcl_package_copy_open_selected_as(p->dir, access, &p->copy, p->reply, AP_COMMAND, version)) return false;
    enum zcl_package_copy_adoption auth = zcl_package_copy_adopted(p->datadir, &p->copy, NULL);
    if (auth != ZCL_PACKAGE_COPY_ADOPTED && auth != ZCL_PACKAGE_COPY_RECEIVED_TRUSTED)
        return ap_fail(p, "NOT_ADOPTED", "copy requires current local adoption or trusted receive");
    if (memcmp(p->head, p->copy.head_version, 32))
        return ap_fail(p, "HEAD_STALE", "copy head changed; request a new plan");
    return true;
}
#endif
bool app_personalize_key_probe(struct zcl_command_reply *reply,
    char *path, size_t path_cap, char pubkey_hex[67], bool *exists)
{
#if !defined(_WIN32)
    if (!reply || !path || !path_cap || !pubkey_hex || !exists) return false;
    *exists = false; pubkey_hex[0] = 0;
    const char *home = getenv("HOME");
    int n = home && home[0] == '/' ? snprintf(path, path_cap, "%s/.z23/zcode_publisher.key", home) : -1;
    if (n <= 0 || (size_t)n >= path_cap) {
        zcl_package_copy_fail(reply, "KEY_UNAVAILABLE", false, "absolute HOME is required", AP_COMMAND); return false;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) return true;
        zcl_package_copy_fail(reply, "KEY_UNAVAILABLE", false, "publisher key cannot be inspected", AP_COMMAND); return false;
    }
    struct plugin_dist_published detail; uint8_t pub[33];
    if (plugin_dist_release_key_sign(path, NULL, pub, NULL, &detail) != PLUGIN_DIST_OK) {
        zcl_package_copy_fail(reply, "KEY_REFUSED", false, "publisher key is not a valid private owner key", AP_COMMAND); return false;
    }
    zcl_hex_encode(pub, sizeof(pub), pubkey_hex); *exists = true; return true;
#else
    (void)path; (void)path_cap; (void)pubkey_hex; (void)exists;
    zcl_package_copy_fail(reply, "PLATFORM_UNAVAILABLE", false, "personalization is unavailable on this platform", "app.personalize");
    return false;
#endif
}
#if !defined(_WIN32)
static bool ap_key_path(struct ap *p)
{
    char hex[67]; bool exists;
    if (!app_personalize_key_probe(p->reply, p->key, sizeof(p->key), hex, &exists)) return false;
    p->key_absent = !exists;
    return !exists || zcl_hex_decode_lower(hex, p->pub, sizeof(p->pub));
}
static bool ap_key_unchanged(struct ap *p)
{
    char path[AP_PATH], hex[67]; bool exists; uint8_t pub[33];
    if (!app_personalize_key_probe(p->reply, path, sizeof(path), hex, &exists))
        return p->mutated ? ap_fail(p, "KEY_STALE", "publisher key cannot be rechecked; reconcile retained key or CAS changes") : false;
    if (strcmp(path, p->key) || exists == p->key_absent ||
        (exists && (!zcl_hex_decode_lower(hex, pub, sizeof(pub)) || memcmp(pub, p->pub, sizeof(pub)))))
        return ap_fail(p, "KEY_STALE", "publisher key changed; request a new plan");
    return true;
}
static bool ap_name_half(const char *name, size_t len)
{
    if (!len || len > VCS_PACKAGE_RELEASE_NAME_HALF_MAX || name[0] == '-' || name[len - 1] == '-') return false;
    for (size_t i = 0; i < len; ++i)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= '0' && name[i] <= '9') || name[i] == '-')) return false;
    return true;
}
static bool ap_one_name(const struct json_value *metadata)
{
    size_t count = 0;
    for (size_t i = 0; i < metadata->num_children; ++i)
        if (!strcmp(metadata->keys[i], "name")) ++count;
    return count == 1;
}
static bool ap_metadata_name(struct ap *p)
{
    if (!ap_one_name(&p->metadata))
        return ap_fail(p, "METADATA_INVALID", "metadata must contain exactly one name");
    const char *name = json_get_str(json_get(&p->metadata, "name"));
    const char *slash = name ? strchr(name, '/') : NULL;
    if (!slash || strchr(slash + 1, '/') ||
        !ap_name_half(name, (size_t)(slash - name)) ||
        !ap_name_half(slash + 1, strlen(slash + 1)))
        return ap_fail(p, "METADATA_INVALID", "package name must use valid publisher and short-name components");
    (void)snprintf(p->original_name, sizeof(p->original_name), "%s", name);
    memcpy(p->short_name, slash + 1, strlen(slash + 1) + 1);
    return true;
}
static bool ap_metadata(struct ap *p)
{
    if (!vcs_tree_load_readonly_bounded(p->dir, p->copy.selected_tree, 8u * 1024u * 1024u, 16384u, &p->manifest))
        return ap_fail(p, "SOURCE_UNREADABLE", "saved source manifest cannot be verified");
    const struct vcs_entry *entry = NULL;
    for (size_t i = 0; i < p->manifest.count; ++i)
        if (!strcmp(p->manifest.entries[i].path, "zcode-package.json")) entry = &p->manifest.entries[i];
    if (!entry || entry->size > AP_META_MAX) return ap_fail(p, "METADATA_INVALID", "saved package metadata is missing or oversized");
    uint8_t *bytes = NULL; size_t size = 0;
    bool ok = vcs_object_get_readonly_bounded(p->dir, entry->blob, VCS_TAG_BLOB, AP_META_MAX, &bytes, &size) == 0 &&
        size == entry->size && json_read(&p->metadata, (const char *)bytes, size) && p->metadata.type == JSON_OBJ;
    free(bytes);
    if (!ok) return ap_fail(p, "METADATA_INVALID", "saved package metadata cannot be decoded");
    if (!ap_metadata_name(p)) return false;
    p->meta_mode = (mode_t)(entry->mode & 0777u);
    return true;
}
static void ap_hash_string(struct sha3_256_ctx *h, const char *s)
{
    uint64_t n = strlen(s); uint8_t len[8];
    zcl_write_u64_le(len, n);
    sha3_256_write(h, len, 8); sha3_256_write(h, (const uint8_t *)s, (size_t)n);
}
static void ap_make_plan(struct ap *p)
{
    struct sha3_256_ctx h; sha3_256_init(&h);
    ap_hash_string(&h, "zcl.app_personalize.plan.v1"); ap_hash_string(&h, p->dir);
    ap_hash_string(&h, p->datadir); ap_hash_string(&h, p->key);
    sha3_256_write(&h, p->copy.fork_version, 32); sha3_256_write(&h, p->copy.parent_release, 32);
    sha3_256_write(&h, p->copy.selected_version, 32); sha3_256_write(&h, p->copy.selected_tree, 32);
    sha3_256_write(&h, p->head, 32);
    uint8_t absent = p->key_absent ? 1 : 0; sha3_256_write(&h, &absent, 1);
    if (!p->key_absent) sha3_256_write(&h, p->pub, sizeof(p->pub));
    sha3_256_finalize(&h, p->plan);
}
static bool ap_create_key(struct ap *p)
{
    if (!p->key_absent) return true;
    const char *home = getenv("HOME"); char store[AP_PATH], public_hex[PLUGIN_HEX_PUBLIC_KEY + 1];
    if (!zcl_path_join(store, sizeof(store), home, ".z23")) return ap_fail(p, "KEY_UNAVAILABLE", "key directory path is too long");
    p->mutated = true; /* mkdir or exclusive key creation may persist even on failure. */
    if (!zcl_mkdir_p(store, 0700).ok || plugin_keygen(p->key, public_hex) != PLUGIN_OK)
        return ap_fail(p, "KEY_CREATE_FAILED", "publisher key could not be exclusively created; replan");
    p->key_created = true;
    p->key_absent = false;
    struct plugin_dist_published detail;
    if (plugin_dist_release_key_sign(p->key, NULL, p->pub, NULL, &detail) != PLUGIN_DIST_OK)
        return ap_fail(p, "KEY_REFUSED", "created key cannot be verified");
    return true;
}
static bool ap_derive_name(struct ap *p)
{
    char public_hex[67]; zcl_hex_encode(p->pub, sizeof(p->pub), public_hex);
    if (!app_personalize_namespace(public_hex, p->namespace_name, sizeof(p->namespace_name)))
        return ap_fail(p, "KEY_REFUSED", "publisher namespace cannot be derived");
    int n = snprintf(p->name, sizeof(p->name), "%s/%s", p->namespace_name, p->short_name);
    return (n > 0 && (size_t)n < sizeof(p->name)) ||
        ap_fail(p, "METADATA_INVALID", "personalized name exceeds package limits");
}
static bool ap_set_name(struct ap *p)
{
    if (!ap_derive_name(p)) return false;
    struct json_value *field = NULL; size_t count = 0;
    for (size_t i = 0; i < p->metadata.num_children; ++i)
        if (!strcmp(p->metadata.keys[i], "name")) { field = &p->metadata.children[i]; ++count; }
    if (count != 1 || !field) return ap_fail(p, "METADATA_INVALID", "metadata must contain one name");
    json_set_str(field, p->name);
    if (field->type != JSON_STR) return ap_fail(p, "OUT_OF_MEMORY", "cannot encode personalized name");
    return true;
}
static bool ap_write_file(int fd, const char *wire, size_t n, mode_t mode)
{
    size_t at = 0;
    while (fd >= 0 && at < n) {
        ssize_t wrote = write(fd, wire + at, n - at);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        at += (size_t)wrote;
    }
    bool ok = fd >= 0 && at == n && fchmod(fd, mode) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    return ok;
}
static bool ap_write_metadata(struct ap *p)
{
    char path[AP_PATH]; size_t n = json_write(&p->metadata, NULL, 0);
    if (!n || n > AP_META_MAX || !zcl_path_join(path, sizeof(path), p->scratch, "zcode-package.json"))
        return ap_fail(p, "METADATA_INVALID", "personalized metadata is too large");
    char *wire = zcl_malloc(n + 1, "personalized metadata");
    if (!wire) return ap_fail(p, "OUT_OF_MEMORY", "cannot encode metadata");
    bool ok = json_write(&p->metadata, wire, n + 1) == n && chmod(path, p->meta_mode | S_IWUSR) == 0;
    int fd = ok ? open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW) : -1;
    ok = ap_write_file(fd, wire, n, p->meta_mode);
    free(wire);
    return ok || ap_fail(p, "METADATA_WRITE_FAILED", "private metadata draft could not be written");
}
static bool ap_commit(struct ap *p)
{
    if (!ap_key_unchanged(p) || !ap_create_key(p) || !ap_set_name(p)) return false;
    if (!platform_temp_directory_create("z23-personalize-", p->scratch, sizeof(p->scratch)) ||
        vcs_tree_materialize(p->dir, p->copy.selected_tree, p->scratch, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) != VCS_OK)
        return ap_fail(p, "MATERIALIZE_FAILED", "saved source could not be materialized privately");
    if (!ap_write_metadata(p)) return false;
    p->mutated = true; /* capture can retain CAS objects on any outcome. */
    if (vcs_tree_capture_into(p->scratch, p->dir, p->tree) != VCS_OK)
        return ap_fail(p, "CAPTURE_FAILED", "draft capture failed; CAS may retain objects");
    if (!memcmp(p->tree, p->copy.selected_tree, 32)) return ap_fail(p, "NO_CHANGES", "saved version already uses this publisher namespace");
    if (!ap_key_unchanged(p)) return false;
    const struct vcs_snapshot_meta meta = {.phase = ZCL_PACKAGE_COPY_SAVE_PHASE};
    const struct vcs_snapshot_tree_limits limits = {8u * 1024u * 1024u, 16384u, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES};
    int rc = vcs_snapshot_from_tree(p->copy.repo, p->tree, p->head, &meta, &limits, p->version);
    if (rc == VCS_EPARTIAL) {
        ap_fail(p, "SNAPSHOT_PARTIAL", "snapshot publication is uncertain; reconcile before retrying");
        return false;
    }
    if (rc != VCS_OK) return ap_fail(p, "SNAPSHOT_REFUSED", "snapshot failed or seal refused; reconcile before retrying");
    p->changed = true;
    return true;
}
/* Preserve the verified chain and selected tree across the fresh reopen. */
static bool ap_reopen(struct ap *p, const char *version, enum zcl_package_copy_access access)
{
    uint8_t fork[32], parent[32], selected[32], tree[32];
    memcpy(fork, p->copy.fork_version, 32); memcpy(parent, p->copy.parent_release, 32);
    memcpy(selected, p->copy.selected_version, 32); memcpy(tree, p->copy.selected_tree, 32);
    zcl_package_copy_close(&p->copy);
    if (access == ZCL_PACKAGE_COPY_CHECKED) p->mutated = true; /* Full open may persist recovery/index state. */
    if (!ap_open(p, version, access)) {
        if (p->mutated) {
            char code[sizeof(p->reply->error.code)], why[sizeof(p->reply->error.message)];
            (void)snprintf(code, sizeof(code), "%s", p->reply->error.code);
            (void)snprintf(why, sizeof(why), "%s", p->reply->error.message);
            return ap_fail(p, code[0] ? code : "COPY_OPEN_FAILED", why[0] ? why : "copy reopen failed; inspect state before retrying");
        }
        return false;
    }
    if (memcmp(fork, p->copy.fork_version, 32) || memcmp(parent, p->copy.parent_release, 32) ||
        memcmp(selected, p->copy.selected_version, 32) || memcmp(tree, p->copy.selected_tree, 32))
        return ap_fail(p, "COPY_CHANGED", "copy ancestry or selected source changed; request a new plan");
    return true;
}
static bool ap_existing_match(struct ap *p, bool *match)
{
    *match = false;
    if (p->key_absent) return true;
    if (!ap_derive_name(p)) return false;
    *match = !strcmp(p->original_name, p->name);
    return true;
}
static bool ap_confirmed(struct ap *p, const char *version)
{
    bool no_change;
    if (!ap_existing_match(p, &no_change)) return false;
    if (!ap_reopen(p, version, no_change ? ZCL_PACKAGE_COPY_READ : ZCL_PACKAGE_COPY_CHECKED)) return false;
    if (!no_change) return ap_commit(p);
    if (!ap_key_unchanged(p)) return false;
    memcpy(p->tree, p->copy.selected_tree, 32);
    memcpy(p->version, p->copy.selected_version, 32);
    return true;
}
static bool ap_root(struct json_value *data, const char *key, const uint8_t root[32])
{
    char hex[65]; zcl_hex_encode(root, 32, hex); return json_push_kv_str(data, key, hex);
}
static bool ap_plan_identity(struct ap *p, const char *public_hex)
{
    struct json_value *d = &p->reply->data;
    return ap_root(d, "plan_id", p->plan) && ap_root(d, "version", p->copy.selected_version) &&
        ap_root(d, "source_root", p->copy.selected_tree) && ap_root(d, "head_version", p->head) &&
        json_push_kv_str(d, "copy", p->dir) && json_push_kv_str(d, "key_path", p->key) &&
        json_push_kv_bool(d, "key_exists", !p->key_absent) &&
        json_push_kv_str(d, "publisher_fingerprint", public_hex);
}
static bool ap_plan_reply(struct ap *p)
{
    char public_hex[67] = {0};
    if (!p->key_absent) {
        zcl_hex_encode(p->pub, sizeof(p->pub), public_hex);
        if (!ap_derive_name(p)) return false;
    }
    struct json_value *d = &p->reply->data;
    return (ap_plan_identity(p, public_hex) && json_push_kv_str(d, "original_name", p->original_name) &&
        json_push_kv_str(d, "short_name", p->short_name) &&
        json_push_kv_bool(d, "namespace_pending", p->key_absent) &&
        json_push_kv_bool(d, "already_personalized", !p->key_absent && !strcmp(p->original_name, p->name)) &&
        json_push_kv_str(d, "namespace", p->namespace_name) && json_push_kv_str(d, "name", p->name)) ||
        ap_fail(p, "REPLY_FAILED", "cannot describe personalization plan");
}
static void ap_commit_reply(struct ap *p)
{
    bool ok = ap_root(&p->reply->data, "version", p->version) &&
        ap_root(&p->reply->data, "source_root", p->tree) &&
        json_push_kv_str(&p->reply->data, "name", p->name) &&
        json_push_kv_str(&p->reply->data, "namespace", p->namespace_name) &&
        json_push_kv_bool(&p->reply->data, "key_created", p->key_created) &&
        json_push_kv_bool(&p->reply->data, "changed", p->changed);
    if (!ok) {
        char version[65]; zcl_hex_encode(p->version, 32, version);
        zcl_package_copy_fail(p->reply, "REPLY_FAILED", p->mutated,
            p->changed ? "successor saved but reply allocation failed; reconcile candidate version" :
                         "existing version is unchanged but reply allocation failed", version);
    }
    p->reply->error.mutated = p->mutated;
}
static void ap_cleanup(struct ap *p)
{
    if (p->scratch[0]) (void)zcl_tree_remove(p->scratch);
    json_free(&p->metadata); vcs_manifest_free(&p->manifest);
    zcl_package_copy_close(&p->copy); free(p);
}
#endif
static bool ap_native_request(const struct zcl_command_request *request)
{
    return request && request->input &&
        (json_get(request->input, "name") || json_get(request->input, "expected_revision"));
}
void zcl_native_handle_app_personalize(const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (ap_native_request(request)) {
        app_personalize_view_run(request, reply); return;
    }
#if !defined(_WIN32)
    struct ap *p = zcl_calloc(1, sizeof(*p), "app-personalize");
    if (!p) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "cannot allocate personalization", AP_COMMAND); return; }
    p->reply = reply; json_init(&p->metadata); char version[65];
    bool ok = request && ap_inputs(p, request->input, version) &&
        ap_open(p, version, ZCL_PACKAGE_COPY_READ) && ap_key_path(p) && ap_metadata(p);
    if (ok) ap_make_plan(p);
    if (ok && !p->confirm) ok = ap_plan_reply(p);
    if (ok && p->confirm) {
        ok = zcl_package_copy_plan_matches(request->input, p->plan, reply, AP_COMMAND);
        if (ok) ok = ap_confirmed(p, version);
        if (ok) ap_commit_reply(p);
    }
    ap_cleanup(p);
#else
    (void)request;
    zcl_package_copy_fail(reply, "PLATFORM_UNAVAILABLE", false, "personalization is unavailable on this platform", "app.personalize");
#endif
}
