/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical app-run observation codec; observation, never authority. */

#include "vcs/zcode_app_run_observation.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "vcs/signed_evidence.h"

#include <limits.h>
#include <string.h>

static const uint8_t app_run_magic[8] = {
    'Z', 'C', 'A', 'P', 'P', '1', '\r', '\n'
};

const char *vcs_zcode_app_run_observation_error_string(
    enum vcs_zcode_app_run_observation_error error)
{
    switch (error) {
    case VCS_ZCODE_APP_RUN_OK: return "ok";
    case VCS_ZCODE_APP_RUN_ERR_NULL: return "null-argument";
    case VCS_ZCODE_APP_RUN_ERR_VERSION: return "schema-version";
    case VCS_ZCODE_APP_RUN_ERR_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_APP_RUN_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO: return "root-zero";
    case VCS_ZCODE_APP_RUN_ERR_FLAGS: return "flags-invalid";
    case VCS_ZCODE_APP_RUN_ERR_EXIT_STATUS: return "exit-status-invalid";
    case VCS_ZCODE_APP_RUN_ERR_TIME_ORDER: return "time-order-invalid";
    case VCS_ZCODE_APP_RUN_ERR_RESERVED: return "reserved-nonzero";
    }
    return "unknown";
}

enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_validate(
    const struct vcs_zcode_app_run_observation_v1 *observation)
{
    if (!observation) return VCS_ZCODE_APP_RUN_ERR_NULL;
    if (observation->schema_version !=
        VCS_ZCODE_APP_RUN_OBSERVATION_VERSION)
        return VCS_ZCODE_APP_RUN_ERR_VERSION;
    const uint8_t *const roots[] = {
        observation->task_root, observation->candidate_root,
        observation->build_receipt_root, observation->artifact_root,
        observation->invocation_root, observation->stdout_root,
        observation->stderr_root, observation->confinement_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO;
    uint16_t flags = observation->flags;
    if ((flags & ~VCS_ZCODE_APP_RUN_KNOWN_FLAGS) != 0 ||
        (flags & VCS_ZCODE_APP_RUN_ATTEMPTED) == 0 ||
        ((flags & VCS_ZCODE_APP_RUN_LAUNCHED) != 0 &&
         (flags & VCS_ZCODE_APP_RUN_ATTEMPTED) == 0) ||
        ((flags & VCS_ZCODE_APP_RUN_EXITED) != 0 &&
         (flags & VCS_ZCODE_APP_RUN_LAUNCHED) == 0) ||
        ((flags & (VCS_ZCODE_APP_RUN_OUTPUT_COMPLETE |
                   VCS_ZCODE_APP_RUN_FULL_ISOLATION |
                   VCS_ZCODE_APP_RUN_NETWORK_DENIED)) != 0 &&
         (flags & VCS_ZCODE_APP_RUN_LAUNCHED) == 0))
        return VCS_ZCODE_APP_RUN_ERR_FLAGS;
    bool exited = (flags & VCS_ZCODE_APP_RUN_EXITED) != 0;
    if ((exited && (observation->exit_status < -255 ||
                    observation->exit_status > 255)) ||
        (!exited && observation->exit_status != INT32_MIN))
        return VCS_ZCODE_APP_RUN_ERR_EXIT_STATUS;
    if (observation->started_unix <= 0 ||
        observation->finished_unix < observation->started_unix)
        return VCS_ZCODE_APP_RUN_ERR_TIME_ORDER;
    if (zcl_bytes_any_set(observation->reserved,
                          sizeof(observation->reserved)))
        return VCS_ZCODE_APP_RUN_ERR_RESERVED;
    return VCS_ZCODE_APP_RUN_OK;
}

enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_serialize(
    const struct vcs_zcode_app_run_observation_v1 *observation,
    uint8_t out[VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES])
{
    enum vcs_zcode_app_run_observation_error error =
        vcs_zcode_app_run_observation_v1_validate(observation);
    if (error != VCS_ZCODE_APP_RUN_OK || !out)
        return out ? error : VCS_ZCODE_APP_RUN_ERR_NULL;
    size_t off = 0;
    memcpy(out + off, app_run_magic, sizeof(app_run_magic));
    off += sizeof(app_run_magic);
    zcl_write_u16_le(out + off, observation->schema_version); off += 2;
    zcl_write_u16_le(out + off, observation->flags); off += 2;
    const uint8_t *const roots[] = {
        observation->task_root, observation->candidate_root,
        observation->build_receipt_root, observation->artifact_root,
        observation->invocation_root, observation->stdout_root,
        observation->stderr_root, observation->confinement_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(out + off, roots[i], 32); off += 32;
    }
    zcl_write_i32_le(out + off, observation->exit_status); off += 4;
    zcl_write_i64_le(out + off, observation->started_unix); off += 8;
    zcl_write_i64_le(out + off, observation->finished_unix); off += 8;
    memcpy(out + off, observation->reserved,
           sizeof(observation->reserved));
    off += sizeof(observation->reserved);
    return off == VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES
        ? VCS_ZCODE_APP_RUN_OK : VCS_ZCODE_APP_RUN_ERR_WIRE_SIZE;
}

enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_app_run_observation_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_APP_RUN_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES)
        return VCS_ZCODE_APP_RUN_ERR_WIRE_SIZE;
    if (memcmp(wire, app_run_magic, sizeof(app_run_magic)) != 0)
        return VCS_ZCODE_APP_RUN_ERR_WIRE_MAGIC;
    size_t off = sizeof(app_run_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    uint8_t *const roots[] = {
        out->task_root, out->candidate_root, out->build_receipt_root,
        out->artifact_root, out->invocation_root, out->stdout_root,
        out->stderr_root, out->confinement_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        memcpy(roots[i], wire + off, 32); off += 32;
    }
    out->exit_status = zcl_read_i32_le(wire + off); off += 4;
    out->started_unix = zcl_read_i64_le(wire + off); off += 8;
    out->finished_unix = zcl_read_i64_le(wire + off); off += 8;
    memcpy(out->reserved, wire + off, sizeof(out->reserved));
    enum vcs_zcode_app_run_observation_error error =
        vcs_zcode_app_run_observation_v1_validate(out);
    if (error != VCS_ZCODE_APP_RUN_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_root(
    const struct vcs_zcode_app_run_observation_v1 *observation,
    uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES];
    enum vcs_zcode_app_run_observation_error error =
        vcs_zcode_app_run_observation_v1_serialize(observation, wire);
    if (error != VCS_ZCODE_APP_RUN_OK || !out)
        return out ? error : VCS_ZCODE_APP_RUN_ERR_NULL;
    static const char domain[] = VCS_ZCODE_APP_RUN_OBSERVATION_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire,
                                    sizeof(wire), out)
        ? VCS_ZCODE_APP_RUN_OK : VCS_ZCODE_APP_RUN_ERR_NULL;
}

bool vcs_zcode_app_run_observation_v1_proves_success(
    const struct vcs_zcode_app_run_observation_v1 *observation)
{
    return vcs_zcode_app_run_observation_v1_validate(observation) ==
               VCS_ZCODE_APP_RUN_OK &&
           (observation->flags & VCS_ZCODE_APP_RUN_PROVED_FLAGS) ==
               VCS_ZCODE_APP_RUN_PROVED_FLAGS &&
           observation->exit_status == 0;
}
