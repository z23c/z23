/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only portable reproduction challenges. */
#include "vcs/zcode_reproduction_request.h"

#include "base/bytes.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/package_build.h"
#include "vcs/zcode_score_receipt.h"

#include <string.h>

static const uint8_t reproduction_magic[8] = {
    'Z', 'C', 'R', 'E', 'P', 'R', 'Q', '\n'
};

const char *vcs_zcode_reproduction_error_string(
    enum vcs_zcode_reproduction_error error)
{
    switch (error) {
    case VCS_ZCODE_REPRODUCTION_OK: return "ok";
    case VCS_ZCODE_REPRODUCTION_NULL: return "null";
    case VCS_ZCODE_REPRODUCTION_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_REPRODUCTION_MAGIC: return "magic";
    case VCS_ZCODE_REPRODUCTION_VERSION: return "version";
    case VCS_ZCODE_REPRODUCTION_FLAGS: return "flags";
    case VCS_ZCODE_REPRODUCTION_RESERVED: return "reserved";
    case VCS_ZCODE_REPRODUCTION_ROOT: return "root";
    case VCS_ZCODE_REPRODUCTION_ACTION: return "action";
    case VCS_ZCODE_REPRODUCTION_CONFINEMENT: return "confinement";
    case VCS_ZCODE_REPRODUCTION_TIME: return "time";
    case VCS_ZCODE_REPRODUCTION_BUDGET: return "budget";
    default: return "unknown";
    }
}

void vcs_zcode_reproduction_request_init(
    struct vcs_zcode_reproduction_request_v1 *request)
{
    if (!request) return;
    memset(request, 0, sizeof(*request));
    request->schema_version = VCS_ZCODE_REPRODUCTION_REQUEST_VERSION;
    request->flags = VCS_ZCODE_REPRODUCTION_REQUIRED_FLAGS;
    request->confinement = VCS_PACKAGE_BUILD_ISOLATION_FULL;
}

enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_validate(
    const struct vcs_zcode_reproduction_request_v1 *request)
{
    if (!request) return VCS_ZCODE_REPRODUCTION_NULL;
    if (request->schema_version != VCS_ZCODE_REPRODUCTION_REQUEST_VERSION)
        return VCS_ZCODE_REPRODUCTION_VERSION;
    if (request->flags != VCS_ZCODE_REPRODUCTION_REQUIRED_FLAGS)
        return VCS_ZCODE_REPRODUCTION_FLAGS;
    if (request->confinement != VCS_PACKAGE_BUILD_ISOLATION_FULL)
        return VCS_ZCODE_REPRODUCTION_CONFINEMENT;
    const uint8_t *const roots[] = {
        request->network_genesis_root, request->zc23_policy_root,
        request->task_root, request->candidate_root, request->package_root,
        request->release_root, request->recipe_root,
        request->dependency_lock_root, request->toolchain_capsule_root,
        request->reference_build_root, request->output_manifest_root,
        request->action_root, request->challenge_nonce,
        request->requester_contributor_binding_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_REPRODUCTION_ROOT;
    uint8_t expected_action[32];
    vcs_zcode_score_action_root(VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION,
                                expected_action);
    if (memcmp(request->action_root, expected_action, 32) != 0)
        return VCS_ZCODE_REPRODUCTION_ACTION;
    if (request->created_unix <= 0 ||
        request->expires_unix <= request->created_unix ||
        request->expires_unix - request->created_unix >
            VCS_ZCODE_REPRODUCTION_MAX_TTL_SECONDS)
        return VCS_ZCODE_REPRODUCTION_TIME;
    if (request->max_cpu_seconds == 0 ||
        request->max_cpu_seconds > VCS_ZCODE_REPRODUCTION_MAX_CPU_SECONDS ||
        request->max_processes == 0 ||
        request->max_processes > VCS_ZCODE_REPRODUCTION_MAX_PROCESSES ||
        request->max_memory_bytes == 0 ||
        request->max_memory_bytes > VCS_ZCODE_REPRODUCTION_MAX_MEMORY_BYTES ||
        request->max_output_bytes == 0 ||
        request->max_output_bytes > VCS_ZCODE_REPRODUCTION_MAX_OUTPUT_BYTES)
        return VCS_ZCODE_REPRODUCTION_BUDGET;
    return VCS_ZCODE_REPRODUCTION_OK;
}

enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_serialize(
    const struct vcs_zcode_reproduction_request_v1 *request,
    uint8_t out[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES])
{
    if (!request || !out) return VCS_ZCODE_REPRODUCTION_NULL;
    enum vcs_zcode_reproduction_error error =
        vcs_zcode_reproduction_request_validate(request);
    if (error != VCS_ZCODE_REPRODUCTION_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out,
                          VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, reproduction_magic, 8) &&
        zcl_codec_write_u16le(&writer, request->schema_version) &&
        zcl_codec_write_u16le(&writer, request->flags) &&
        zcl_codec_write_u8(&writer, request->confinement) &&
        zcl_codec_write_bytes(&writer, (const uint8_t[7]){0}, 7);
#define WRITE_ROOT(field_) \
    do { ok = ok && zcl_codec_write_bytes(&writer, request->field_, 32); } while (0)
    WRITE_ROOT(network_genesis_root);
    WRITE_ROOT(zc23_policy_root);
    WRITE_ROOT(task_root);
    WRITE_ROOT(candidate_root);
    WRITE_ROOT(package_root);
    WRITE_ROOT(release_root);
    WRITE_ROOT(recipe_root);
    WRITE_ROOT(dependency_lock_root);
    WRITE_ROOT(toolchain_capsule_root);
    WRITE_ROOT(reference_build_root);
    WRITE_ROOT(output_manifest_root);
    WRITE_ROOT(action_root);
    WRITE_ROOT(challenge_nonce);
    WRITE_ROOT(requester_contributor_binding_root);
#undef WRITE_ROOT
    ok = ok && zcl_codec_write_i64le(&writer, request->created_unix) &&
        zcl_codec_write_i64le(&writer, request->expires_unix) &&
        zcl_codec_write_u32le(&writer, request->max_cpu_seconds) &&
        zcl_codec_write_u32le(&writer, request->max_processes) &&
        zcl_codec_write_u64le(&writer, request->max_memory_bytes) &&
        zcl_codec_write_u64le(&writer, request->max_output_bytes) &&
        zcl_codec_write_u32le(&writer, 0);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
                   written == VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES
        ? VCS_ZCODE_REPRODUCTION_OK : VCS_ZCODE_REPRODUCTION_WIRE_SIZE;
}

enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_reproduction_request_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_REPRODUCTION_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES)
        return VCS_ZCODE_REPRODUCTION_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved[7];
    uint32_t reserved32 = 0;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &out->flags) &&
        zcl_codec_read_u8(&reader, &out->confinement) &&
        zcl_codec_read_bytes(&reader, reserved, 7);
#define READ_ROOT(field_) \
    do { ok = ok && zcl_codec_read_bytes(&reader, out->field_, 32); } while (0)
    READ_ROOT(network_genesis_root);
    READ_ROOT(zc23_policy_root);
    READ_ROOT(task_root);
    READ_ROOT(candidate_root);
    READ_ROOT(package_root);
    READ_ROOT(release_root);
    READ_ROOT(recipe_root);
    READ_ROOT(dependency_lock_root);
    READ_ROOT(toolchain_capsule_root);
    READ_ROOT(reference_build_root);
    READ_ROOT(output_manifest_root);
    READ_ROOT(action_root);
    READ_ROOT(challenge_nonce);
    READ_ROOT(requester_contributor_binding_root);
#undef READ_ROOT
    ok = ok && zcl_codec_read_i64le(&reader, &out->created_unix) &&
        zcl_codec_read_i64le(&reader, &out->expires_unix) &&
        zcl_codec_read_u32le(&reader, &out->max_cpu_seconds) &&
        zcl_codec_read_u32le(&reader, &out->max_processes) &&
        zcl_codec_read_u64le(&reader, &out->max_memory_bytes) &&
        zcl_codec_read_u64le(&reader, &out->max_output_bytes) &&
        zcl_codec_read_u32le(&reader, &reserved32) &&
        zcl_codec_reader_finish(&reader);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_REPRODUCTION_WIRE_SIZE;
    }
    if (memcmp(magic, reproduction_magic, 8) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_REPRODUCTION_MAGIC;
    }
    if (memcmp(reserved, (const uint8_t[7]){0}, 7) != 0 || reserved32 != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_REPRODUCTION_RESERVED;
    }
    enum vcs_zcode_reproduction_error error =
        vcs_zcode_reproduction_request_validate(out);
    if (error != VCS_ZCODE_REPRODUCTION_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_reproduction_error vcs_zcode_reproduction_request_root(
    const struct vcs_zcode_reproduction_request_v1 *request,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!request || !out) return VCS_ZCODE_REPRODUCTION_NULL;
    uint8_t wire[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES];
    enum vcs_zcode_reproduction_error error =
        vcs_zcode_reproduction_request_serialize(request, wire);
    if (error != VCS_ZCODE_REPRODUCTION_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_REPRODUCTION_REQUEST_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_REPRODUCTION_OK;
}
