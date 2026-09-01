/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical physical observations for one immutable build action. */

#ifndef ZCL_VCS_BUILD_EXECUTION_OBSERVATION_H
#define ZCL_VCS_BUILD_EXECUTION_OBSERVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_BUILD_EXECUTION_OBSERVATION_VERSION 1u
#define VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES 456u

enum vcs_build_execution_observation_flags {
    VCS_BUILD_OBS_FULL_ISOLATION = 1u << 0,
    VCS_BUILD_OBS_NETWORK_DENIED = 1u << 1,
    VCS_BUILD_OBS_FRESH_SCRATCH = 1u << 2,
    VCS_BUILD_OBS_INPUT_READ_ONLY = 1u << 3,
    VCS_BUILD_OBS_ENVIRONMENT_SCRUBBED = 1u << 4,
    VCS_BUILD_OBS_OUTPUT_BOUNDED = 1u << 5,
    VCS_BUILD_OBS_READ_SET_COMPLETE = 1u << 6,
    VCS_BUILD_OBS_WRITE_SET_COMPLETE = 1u << 7,
};

#define VCS_BUILD_OBS_REQUIRED_FLAGS \
    (VCS_BUILD_OBS_FULL_ISOLATION | VCS_BUILD_OBS_NETWORK_DENIED | \
     VCS_BUILD_OBS_FRESH_SCRATCH | VCS_BUILD_OBS_INPUT_READ_ONLY | \
     VCS_BUILD_OBS_ENVIRONMENT_SCRUBBED | VCS_BUILD_OBS_OUTPUT_BOUNDED | \
     VCS_BUILD_OBS_READ_SET_COMPLETE | VCS_BUILD_OBS_WRITE_SET_COMPLETE)

struct vcs_build_execution_observation_v1 {
    uint16_t schema_version;
    uint16_t flags;
    int32_t exit_status;
    uint8_t action_root[32];
    uint8_t action_input_root[32];
    uint8_t observed_input_bytes_root[32];
    uint8_t artifact_root[32];
    uint8_t output_bytes_root[32];
    uint8_t toolchain_root[32];
    uint8_t flags_root[32];
    uint8_t environment_root[32];
    uint8_t declared_reads_root[32];
    uint8_t observed_reads_root[32];
    uint8_t declared_writes_root[32];
    uint8_t observed_writes_root[32];
    uint64_t cpu_seconds_limit;
    uint64_t memory_bytes_limit;
    uint64_t process_limit;
    uint64_t file_limit;
    uint64_t file_bytes_limit;
    uint64_t output_bytes_limit;
    uint64_t wall_millis_limit;
};

bool vcs_build_execution_observation_v1_valid(
    const struct vcs_build_execution_observation_v1 *observation);
bool vcs_build_execution_observation_v1_serialize(
    const struct vcs_build_execution_observation_v1 *observation,
    uint8_t out[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES]);
bool vcs_build_execution_observation_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_build_execution_observation_v1 *out);
bool vcs_build_execution_observation_v1_root(
    const struct vcs_build_execution_observation_v1 *observation,
    uint8_t out[32]);

void vcs_build_execution_read_set_root(
    const uint8_t action_input_root[32],
    const uint8_t observed_input_bytes_root[32],
    const uint8_t toolchain_root[32],
    uint8_t out[32]);
void vcs_build_execution_declared_write_set_root(
    const char *declared_output, uint8_t out[32]);
void vcs_build_execution_observed_write_set_root(
    const char *observed_output, const uint8_t output_bytes_root[32],
    uint8_t out[32]);

#endif /* ZCL_VCS_BUILD_EXECUTION_OBSERVATION_H */
