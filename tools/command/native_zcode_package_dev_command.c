/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read-only native preparation and sealing for development packages. */

#include "command/native_command.h"
#include "command/native_package_artifact.h"

#include "base/hex.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "vcs/package_accept.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/positioned_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *zpd_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zpd_int(const struct json_value *input, const char *key,
                    int64_t *out)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    if (!value || value->type != JSON_INT)
        return false;
    *out = json_get_int(value);
    return true;
}

static void zpd_fail(struct zcl_command_reply *reply, const char *code,
                     const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.package.dev");
}

static bool zpd_push_hex(struct json_value *out, const char *key,
                         const uint8_t *bytes, size_t len)
{
    if (len > (SIZE_MAX - 1u) / 2u)
        return false;
    char *hex = zcl_malloc(len * 2u + 1u, "zcode.package.dev.hex");
    if (!hex)
        return false;
    zcl_hex_encode(bytes, len, hex);
    bool ok = json_push_kv_str(out, key, hex);
    const char *observed = json_get_str(json_get(out, key));
    ok = ok && observed && strcmp(observed, hex) == 0;
    free(hex);
    return ok;
}
static bool zpd_push_string(struct json_value *out, const char *key, const char *text)
{
    if (!json_push_kv_str(out, key, text)) return false;
    const char *observed = json_get_str(json_get(out, key));
    return observed && strcmp(observed, text) == 0;
}

static bool zpd_prepare_source(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, struct vcs_package_prepared *prepared)
{
    if (!request || !reply)
        return false;
    const char *dir = zpd_str(request->input, "dir");
    const char *pubkey = zpd_str(request->input, "publisher_pubkey");
    int64_t sequence = 0;
    /* An unstated chain is THIS node's chain, not a literal. vcs_package_-
     * prepare defaults to "zclassic-main" because it is deliberately free of
     * chainparams — several standalone tools link it without them — so the
     * default belongs here, in the leaf that does know which chain it is on.
     * vcs_package_accept, the very next thing to touch this release, compares
     * chain_id against exactly this value, so without it every prepare on a
     * testnet or regtest node produced a release that could only ever be
     * refused as wrong-chain-id, on the publishing node as much as on any
     * peer that fetched the carrier. An explicit chain_id still wins. */
    const char *chain_id = zpd_str(request->input, "chain_id");
    char active_chain[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    if ((!chain_id || !chain_id[0]) &&
        vcs_package_accept_chain_id(active_chain, sizeof(active_chain)))
        chain_id = active_chain;
    struct vcs_package_prepare_options options = {
        .dir = dir,
        .reward_address = zpd_str(request->input, "reward_address"),
        .chain_id = chain_id,
    };
    if (!dir || !pubkey ||
        !zcl_hex_decode_lower(pubkey, options.publisher_pubkey,
                              sizeof(options.publisher_pubkey)) ||
        !zpd_int(request->input, "publisher_sequence", &sequence) ||
        sequence <= 0) {
        zpd_fail(reply, "BAD_PREPARE_INPUT",
                 "dir, a 66-lowercase-hex publisher_pubkey, and a positive publisher_sequence are required");
        return false;
    }
    options.publisher_sequence = (uint64_t)sequence;
    char detail[256] = {0};
    enum vcs_package_prepare_error err = vcs_package_prepare(
        &options, prepared, detail, sizeof(detail));
    if (err != VCS_PACKAGE_PREPARE_OK) {
        char message[384];
        (void)snprintf(message, sizeof(message), "%s: %s",
                       vcs_package_prepare_error_string(err), detail);
        zpd_fail(reply, "PACKAGE_PREPARE_FAILED", message);
        return false;
    }
    return true;
}
static bool zpd_prepare_push_wires(struct zcl_command_reply *reply,
    const struct vcs_package_prepared *prepared)
{
    return zpd_push_hex(&reply->data, "package_root", prepared->package_root, 32) &&
        zpd_push_hex(&reply->data, "release_signing_digest",
                     prepared->signing_digest, 32) &&
        zpd_push_hex(&reply->data, "recipe_root", prepared->recipe_root, 32) &&
        zpd_push_hex(&reply->data, "dependency_lock_root",
                     prepared->lock_root, 32) &&
        zpd_push_hex(&reply->data, "api_capsule_root",
                     prepared->capsule_root, 32) &&
        zpd_push_hex(&reply->data, "release_body_hex", prepared->release_body,
                     prepared->release_body_len) &&
        zpd_push_hex(&reply->data, "manifest_hex", prepared->manifest_wire,
                     prepared->manifest_wire_len) &&
        zpd_push_hex(&reply->data, "recipe_hex", prepared->recipe_wire,
                     prepared->recipe_wire_len) &&
        zpd_push_hex(&reply->data, "dependency_lock_hex", prepared->lock_wire,
                     prepared->lock_wire_len) &&
        zpd_push_hex(&reply->data, "api_capsule_hex", prepared->capsule_wire,
                     prepared->capsule_wire_len);
}
static bool zpd_prepare_push_fields(struct zcl_command_reply *reply,
    const struct vcs_package_prepared *prepared)
{
    return json_push_kv_str(&reply->data, "name", prepared->release.name) &&
        json_push_kv_str(&reply->data, "semver", prepared->release.semver) &&
        json_push_kv_str(&reply->data, "license", prepared->release.license) &&
        /* The chain this release binds to. It decides whether any peer will
         * ever accept the carrier, and it used to be invisible here. */
        json_push_kv_str(&reply->data, "chain_id", prepared->release.chain_id) &&
        json_push_kv_int(&reply->data, "publisher_sequence", (int64_t)prepared->release.publisher_sequence) &&
        json_push_kv_int(&reply->data, "file_count",
                         (int64_t)prepared->manifest.count) &&
        json_push_kv_int(&reply->data, "dependency_count",
                         (int64_t)(prepared->lock.count - 1u)) &&
        json_push_kv_int(&reply->data, "public_header_count",
                         (int64_t)prepared->capsule.count) &&
        json_push_kv_bool(&reply->data, "read_only", true) &&
        json_push_kv_str(&reply->data, "signature_status", "unsigned");
}
void zcl_native_handle_zcode_package_dev_prepare(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct vcs_package_prepared prepared;
    if (!zpd_prepare_source(request, reply, &prepared)) return;
    bool ok = zpd_prepare_push_wires(reply, &prepared) &&
        zpd_prepare_push_fields(reply, &prepared);
    vcs_package_prepared_free(&prepared);
    if (!ok)
        zpd_fail(reply, "PACKAGE_PREPARE_OUTPUT",
                 "bounded canonical output could not be rendered");
}

struct zpd_export_state {
    char directory[4096], parent[4096];
    bool attempted, durable, marker_removed;
};
#ifdef ZCL_TESTING
static _Thread_local unsigned zpd_export_failure_stage;
unsigned zcl_native_package_export_test_failure_stage(unsigned stage)
{
    unsigned prior = zpd_export_failure_stage; zpd_export_failure_stage = stage; return prior;
}
#endif
#if !defined(_WIN32)
struct zpd_export_wire { const char *name; const uint8_t *bytes; size_t length; };
static bool zpd_export_preflight(const struct zcl_command_request *request, struct zpd_export_state *state)
{
    const struct json_value *confirm = json_get(request->input, "confirm");
    const char *path = zpd_str(request->input, "artifact_dir"), *source = zpd_str(request->input, "dir");
    char source_absolute[4096];
    if (!confirm || confirm->type != JSON_BOOL || !json_get_bool(confirm) || !path || !source) return false;
    if (!platform_private_destination_resolve(path, state->directory, sizeof(state->directory), state->parent, sizeof(state->parent)) ||
        !platform_private_path_absent(state->directory) ||
        !zcl_native_package_artifact_absolute(source, source_absolute, sizeof(source_absolute))) return false;
    size_t length = strlen(source_absolute);
    if (length == 1 && source_absolute[0] == '/') return false;
    return strncmp(state->directory, source_absolute, length) != 0 ||
        (state->directory[length] != '/' && state->directory[length] != 0);
}
static bool zpd_export_usable(struct platform_private_file *held, const char *directory,
    const struct zpd_export_wire *wire)
{
    struct platform_private_file_identity identity;
    struct platform_positioned_file observed; platform_positioned_file_init(&observed);
    struct platform_positioned_file_snapshot snapshot;
    bool ok = platform_private_file_identity(held, &identity) &&
        platform_positioned_file_open_beneath(&observed, directory, wire->name) &&
        platform_positioned_file_is_private(&observed) &&
        platform_positioned_file_is_current_user_only(&observed) &&
        platform_positioned_file_snapshot(&observed, &snapshot);
    if (ok) ok = snapshot.volume == identity.volume && snapshot.file_low == identity.file &&
        !snapshot.file_high && snapshot.size == wire->length;
    platform_positioned_file_close(&observed); return ok;
}
static bool zpd_export_file(const char *directory, const struct zpd_export_wire *wire)
{
    char path[4200];
    int count = snprintf(path, sizeof(path), "%s/%s", directory, wire->name);
    if (count <= 0 || (size_t)count >= sizeof(path)) return false;
    struct platform_private_file file; platform_private_file_init(&file);
    bool ok = platform_private_file_create_locked(path, &file) &&
        platform_private_file_write_at(&file, wire->bytes, wire->length, 0) &&
        platform_private_file_authority_flush(&file) && zpd_export_usable(&file, directory, wire);
    platform_private_file_close(&file); return ok;
}
static void zpd_export_wires(const struct vcs_package_prepared *prepared, struct zpd_export_wire wires[5])
{
    wires[0] = (struct zpd_export_wire){"manifest.wire", prepared->manifest_wire, prepared->manifest_wire_len};
    wires[1] = (struct zpd_export_wire){"recipe.wire", prepared->recipe_wire, prepared->recipe_wire_len};
    wires[2] = (struct zpd_export_wire){"dependency-lock.wire", prepared->lock_wire, prepared->lock_wire_len};
    wires[3] = (struct zpd_export_wire){"api-capsule.wire", prepared->capsule_wire, prepared->capsule_wire_len};
    wires[4] = (struct zpd_export_wire){"release-body.wire", prepared->release_body, prepared->release_body_len};
}
static bool zpd_export_barrier(const char *directory, unsigned stage)
{
#ifdef ZCL_TESTING
    if (stage && zpd_export_failure_stage == stage) return false;
#else
    (void)stage;
#endif
    return platform_private_parent_flush(directory);
}
static bool zpd_export_write(struct zpd_export_state *state, const struct zpd_export_wire wires[5])
{
    state->attempted = true;
    if (!platform_private_directory_create(state->directory) || !platform_private_parent_flush(state->parent)) return false;
    char path[4200]; int count = snprintf(path, sizeof(path), "%s/EXPORT-PENDING", state->directory);
    if (count <= 0 || (size_t)count >= sizeof(path)) return false;
    struct platform_private_file marker; platform_private_file_init(&marker);
    struct platform_private_file_identity identity;
    static const char text[] = "Z23PREPARED1\n";
    bool ok = platform_private_file_create_locked(path, &marker) &&
        platform_private_file_identity(&marker, &identity) &&
        platform_private_file_write_at(&marker, text, sizeof(text) - 1, 0) &&
        platform_private_file_authority_flush(&marker) && zpd_export_barrier(state->directory, 1);
    for (size_t i = 0; i < 5 && ok; ++i) ok = zpd_export_file(state->directory, &wires[i]);
    if (ok) ok = zpd_export_barrier(state->directory, 0);
    if (ok) { ok = platform_private_file_retire_if_identity(&marker, path, &identity); state->marker_removed = ok; }
    if (ok) ok = zpd_export_barrier(state->directory, 2);
    platform_private_file_close(&marker); state->durable = ok; return ok;
}
#endif
static void zpd_export_failure(struct zcl_command_reply *reply, const struct zpd_export_state *state, const char *code)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
        code, "export", false, state->attempted,
        "inert artifact export refused or interrupted; preserve any artifacts, do not retry automatically",
        "zcode.package.dev.prepare.export");
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    const char *publication = state->durable ? "durable" : state->attempted ? "durability_unknown" : "not_published";
    bool ok = zpd_push_string(&facts, "artifact_publication", publication) &&
        json_push_kv_bool(&facts, "mutation_attempted", state->attempted) &&
        json_push_kv_bool(&facts, "pending_marker_removed", state->marker_removed) &&
        json_push_kv_bool(&facts, "automatic_retry", false);
    if (ok) ok = json_push_kv(&reply->data, "failure_facts", &facts);
    if (!ok) LOG_ERROR("zcode.package.export", "public failure facts allocation failed; mutation marker retained");
    json_free(&facts);
}
#if !defined(_WIN32)
static bool zpd_export_metadata(struct json_value *out, const struct zpd_export_wire wires[5])
{
    static const char *const names[] = {"manifest", "recipe", "dependency_lock", "api_capsule", "release_body"};
    for (size_t i = 0; i < 5; ++i) {
        char key[64]; uint8_t digest[32]; zcl_native_package_artifact_digest(digest, wires[i].bytes, wires[i].length);
        int count = snprintf(key, sizeof(key), "%s_bytes", names[i]);
        if (count <= 0 || (size_t)count >= sizeof(key) || !json_push_kv_int(out, key, (int64_t)wires[i].length)) return false;
        count = snprintf(key, sizeof(key), "%s_sha3", names[i]);
        if (count <= 0 || (size_t)count >= sizeof(key) || !zpd_push_hex(out, key, digest, 32)) return false;
    }
    return true;
}
static bool zpd_export_reply(struct zcl_command_reply *reply, const struct vcs_package_prepared *prepared,
    const struct zpd_export_wire wires[5])
{
    return zpd_export_metadata(&reply->data, wires) &&
        zpd_push_hex(&reply->data, "package_root", prepared->package_root, 32) &&
        zpd_push_hex(&reply->data, "recipe_root", prepared->recipe_root, 32) &&
        zpd_push_hex(&reply->data, "dependency_lock_root", prepared->lock_root, 32) &&
        zpd_push_hex(&reply->data, "api_capsule_root", prepared->capsule_root, 32) &&
        zpd_push_hex(&reply->data, "release_signing_digest", prepared->signing_digest, 32) &&
        zpd_push_string(&reply->data, "signature_status", "unsigned") &&
        zpd_push_string(&reply->data, "artifact_publication", "durable") &&
        json_push_kv_bool(&reply->data, "mutation_attempted", true) &&
        json_push_kv_bool(&reply->data, "read_only", false);
}
#endif
void zcl_native_handle_zcode_package_dev_prepare_export(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct zpd_export_state state = {0};
#if defined(_WIN32)
    zpd_export_failure(reply, &state, "EXPORT_DURABILITY_UNSUPPORTED");
#else
    if (!zpd_export_preflight(request, &state)) { zpd_export_failure(reply, &state, "BAD_EXPORT_INPUT"); return; }
    struct vcs_package_prepared prepared;
    if (!zpd_prepare_source(request, reply, &prepared)) return;
    struct zpd_export_wire wires[5]; zpd_export_wires(&prepared, wires);
    bool ok = zpd_export_write(&state, wires);
    if (ok) ok = zpd_export_reply(reply, &prepared, wires);
    vcs_package_prepared_free(&prepared);
    if (!ok) zpd_export_failure(reply, &state, "PACKAGE_EXPORT_FAILED");
#endif
}

static bool zpd_seal_decode_inputs(const struct zcl_command_request *request,
    uint8_t *signature, size_t signature_len, uint8_t **body, size_t *body_len)
{
    const char *signature_hex = zpd_str(request->input, "signature_hex");
    return zcl_native_package_artifact_read(request->input, "release_body_hex",
                        "release_body_file", "release_body_sha3",
                        VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES -
                            VCS_PACKAGE_RELEASE_SIGNATURE_BYTES,
                        body, body_len) &&
        signature_hex &&
        zcl_hex_decode_lower(signature_hex, signature, signature_len);
}
static enum vcs_package_release_error zpd_seal_release_validate(
    const uint8_t *wire, size_t wire_len, struct vcs_package_release *release,
    uint8_t *release_id, uint8_t **canonical, size_t *canonical_len)
{
    enum vcs_package_release_error err =
        vcs_package_release_parse(wire, wire_len, release);
    if (err == VCS_PACKAGE_RELEASE_OK)
        err = vcs_package_release_verify(release);
    if (err == VCS_PACKAGE_RELEASE_OK)
        err = vcs_package_release_id(release, release_id);
    if (err == VCS_PACKAGE_RELEASE_OK)
        err = vcs_package_release_serialize(release, canonical,
                                            canonical_len);
    return err;
}
static bool zpd_seal_render_reply(struct zcl_command_reply *reply,
    const uint8_t *wire, size_t wire_len, const uint8_t *release_id)
{
    return zpd_push_hex(&reply->data, "release_hex", wire, wire_len) &&
              zpd_push_hex(&reply->data, "release_id", release_id, 32) &&
              json_push_kv_str(&reply->data, "schema",
                               "zcl.zcode_release.v1") &&
              json_push_kv_str(&reply->data, "signature_status", "verified") &&
              json_push_kv_bool(&reply->data, "read_only", true);
}
void zcl_native_handle_zcode_package_dev_seal(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    uint8_t *body = NULL;
    size_t body_len = 0;
    uint8_t signature[VCS_PACKAGE_RELEASE_SIGNATURE_BYTES];
    if (!zpd_seal_decode_inputs(request, signature, sizeof(signature),
                               &body, &body_len)) {
        free(body);
        zpd_fail(reply, "BAD_SEAL_INPUT",
                 "exactly one bounded release body hex or file with expected SHA3, and a 128 lowercase hex signature are required");
        return;
    }
    size_t wire_len = body_len + sizeof(signature);
    uint8_t *wire = zcl_malloc(wire_len, "zcode.package.dev.release");
    if (!wire) {
        free(body);
        zpd_fail(reply, "PACKAGE_SEAL_ALLOC", "release wire allocation failed");
        return;
    }
    memcpy(wire, body, body_len);
    memcpy(wire + body_len, signature, sizeof(signature));
    free(body);
    struct vcs_package_release release;
    uint8_t release_id[32];
    uint8_t *canonical = NULL;
    size_t canonical_len = 0;
    enum vcs_package_release_error err = zpd_seal_release_validate(
        wire, wire_len, &release, release_id, &canonical, &canonical_len);
    if (err != VCS_PACKAGE_RELEASE_OK || canonical_len != wire_len ||
        memcmp(canonical, wire, wire_len) != 0) {
        char message[192];
        (void)snprintf(message, sizeof(message), "release verification: %s",
                       vcs_package_release_error_string(err));
        free(canonical); free(wire);
        zpd_fail(reply, "PACKAGE_SEAL_FAILED", message);
        return;
    }
    bool ok = zpd_seal_render_reply(reply, wire, wire_len, release_id);
    free(canonical); free(wire);
    if (!ok)
        zpd_fail(reply, "PACKAGE_SEAL_OUTPUT",
                 "verified release could not be rendered");
}
