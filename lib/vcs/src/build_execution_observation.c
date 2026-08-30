/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical physical observations for one immutable build action. */

#include "vcs/build_execution_observation.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t k_magic[8] = {'Z','B','O','B','S','V','1','\0'};

static void obs_hash_text(struct sha3_256_ctx *sha, const char *text)
{
    uint64_t len = text ? strlen(text) : 0;
    uint8_t le[8];
    zcl_write_u64_le(le, len);
    sha3_256_write(sha, le, sizeof(le));
    if (len) sha3_256_write(sha, (const uint8_t *)text, (size_t)len);
}

bool vcs_build_execution_observation_v1_valid(
    const struct vcs_build_execution_observation_v1 *o)
{
    if (!o || o->schema_version != VCS_BUILD_EXECUTION_OBSERVATION_VERSION ||
        (o->flags & VCS_BUILD_OBS_REQUIRED_FLAGS) !=
            VCS_BUILD_OBS_REQUIRED_FLAGS ||
        (o->flags & ~VCS_BUILD_OBS_REQUIRED_FLAGS) != 0 ||
        o->exit_status < 0 || o->exit_status > 255 ||
        !zcl_bytes_any_set(o->action_root, 32) ||
        !zcl_bytes_any_set(o->action_input_root, 32) ||
        !zcl_bytes_any_set(o->observed_input_bytes_root, 32) ||
        !zcl_bytes_any_set(o->artifact_root, 32) ||
        !zcl_bytes_any_set(o->output_bytes_root, 32) ||
        !zcl_bytes_any_set(o->toolchain_root, 32) || !zcl_bytes_any_set(o->flags_root, 32) ||
        !zcl_bytes_any_set(o->environment_root, 32) ||
        !zcl_bytes_any_set(o->declared_reads_root, 32) ||
        !zcl_bytes_any_set(o->observed_reads_root, 32) ||
        !zcl_bytes_any_set(o->declared_writes_root, 32) ||
        !zcl_bytes_any_set(o->observed_writes_root, 32) ||
        o->cpu_seconds_limit == 0 || o->memory_bytes_limit == 0 ||
        o->process_limit == 0 || o->file_limit == 0 ||
        o->file_bytes_limit == 0 || o->output_bytes_limit == 0 ||
        o->wall_millis_limit == 0)
        return false;
    return memcmp(o->declared_reads_root, o->observed_reads_root, 32) == 0;
}

bool vcs_build_execution_observation_v1_serialize(
    const struct vcs_build_execution_observation_v1 *o,
    uint8_t out[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES])
{
    if (!vcs_build_execution_observation_v1_valid(o) || !out) return false;
    memset(out, 0, VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES);
    memcpy(out, k_magic, sizeof(k_magic));
    zcl_write_u16_le(out + 8, o->schema_version);
    zcl_write_u16_le(out + 10, o->flags);
    zcl_write_u32_le(out + 12, (uint32_t)o->exit_status);
    size_t at = 16;
    const uint8_t *roots[] = {
        o->action_root, o->action_input_root,
        o->observed_input_bytes_root, o->artifact_root,
        o->output_bytes_root, o->toolchain_root, o->flags_root,
        o->environment_root, o->declared_reads_root,
        o->observed_reads_root, o->declared_writes_root,
        o->observed_writes_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(out + at, roots[i], 32);
        at += 32;
    }
    const uint64_t limits[] = {
        o->cpu_seconds_limit, o->memory_bytes_limit, o->process_limit,
        o->file_limit, o->file_bytes_limit, o->output_bytes_limit,
        o->wall_millis_limit,
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        zcl_write_u64_le(out + at, limits[i]);
        at += 8;
    }
    return at == VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES;
}

bool vcs_build_execution_observation_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_execution_observation_v1 *out)
{
    if (!wire || !out ||
        wire_len != VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES ||
        memcmp(wire, k_magic, sizeof(k_magic)) != 0)
        return false;
    memset(out, 0, sizeof(*out));
    out->schema_version = zcl_read_u16_le(wire + 8);
    out->flags = zcl_read_u16_le(wire + 10);
    out->exit_status = (int32_t)zcl_read_u32_le(wire + 12);
    size_t at = 16;
    uint8_t *roots[] = {
        out->action_root, out->action_input_root,
        out->observed_input_bytes_root, out->artifact_root,
        out->output_bytes_root, out->toolchain_root, out->flags_root,
        out->environment_root, out->declared_reads_root,
        out->observed_reads_root, out->declared_writes_root,
        out->observed_writes_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(roots[i], wire + at, 32);
        at += 32;
    }
    uint64_t *limits[] = {
        &out->cpu_seconds_limit, &out->memory_bytes_limit,
        &out->process_limit, &out->file_limit, &out->file_bytes_limit,
        &out->output_bytes_limit, &out->wall_millis_limit,
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        *limits[i] = zcl_read_u64_le(wire + at);
        at += 8;
    }
    return at == wire_len && vcs_build_execution_observation_v1_valid(out);
}

bool vcs_build_execution_observation_v1_root(
    const struct vcs_build_execution_observation_v1 *observation,
    uint8_t out[32])
{
    uint8_t wire[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES];
    if (!out || !vcs_build_execution_observation_v1_serialize(
                    observation, wire))
        return false;
    static const char domain[] = "zcl.build_execution_observation.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return true;
}

void vcs_build_execution_read_set_root(
    const uint8_t action_input_root[32],
    const uint8_t observed_input_bytes_root[32],
    const uint8_t toolchain_root[32],
    uint8_t out[32])
{
    static const char domain[] = "zcl.build_execution.read_set.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, action_input_root, 32);
    sha3_256_write(&sha, observed_input_bytes_root, 32);
    sha3_256_write(&sha, toolchain_root, 32);
    sha3_256_finalize(&sha, out);
}

void vcs_build_execution_declared_write_set_root(
    const char *declared_output, uint8_t out[32])
{
    static const char domain[] = "zcl.build_execution.declared_writes.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    obs_hash_text(&sha, declared_output);
    sha3_256_finalize(&sha, out);
}

void vcs_build_execution_observed_write_set_root(
    const char *observed_output, const uint8_t output_bytes_root[32],
    uint8_t out[32])
{
    static const char domain[] = "zcl.build_execution.observed_writes.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    obs_hash_text(&sha, observed_output);
    sha3_256_write(&sha, output_bytes_root, 32);
    sha3_256_finalize(&sha, out);
}
