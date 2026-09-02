/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical evidence for one bounded application execution.
 *
 * This object records an observation; it grants no execution, install,
 * acceptance, publication, or deployment authority.  A canonical signed
 * zcode work receipt binds its root.  The build receipt names the prior
 * build observation, artifact_root names the exact executed bytes, and
 * invocation_root names the separately content-addressed invocation input.
 */

#ifndef ZCL_VCS_ZCODE_APP_RUN_OBSERVATION_H
#define ZCL_VCS_ZCODE_APP_RUN_OBSERVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_APP_RUN_OBSERVATION_VERSION 1u
#define VCS_ZCODE_APP_RUN_OBSERVATION_DOMAIN \
    "zcl.zcode.app_run_observation.v1"
#define VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES 296u

enum vcs_zcode_app_run_flag {
    VCS_ZCODE_APP_RUN_ATTEMPTED = 1u << 0,
    VCS_ZCODE_APP_RUN_LAUNCHED = 1u << 1,
    VCS_ZCODE_APP_RUN_EXITED = 1u << 2,
    VCS_ZCODE_APP_RUN_OUTPUT_COMPLETE = 1u << 3,
    VCS_ZCODE_APP_RUN_FULL_ISOLATION = 1u << 4,
    VCS_ZCODE_APP_RUN_NETWORK_DENIED = 1u << 5,
};

#define VCS_ZCODE_APP_RUN_KNOWN_FLAGS \
    (VCS_ZCODE_APP_RUN_ATTEMPTED | VCS_ZCODE_APP_RUN_LAUNCHED | \
     VCS_ZCODE_APP_RUN_EXITED | VCS_ZCODE_APP_RUN_OUTPUT_COMPLETE | \
     VCS_ZCODE_APP_RUN_FULL_ISOLATION | \
     VCS_ZCODE_APP_RUN_NETWORK_DENIED)

/* These flags prove the narrow claim that the named bytes ran to a captured
 * successful exit. Isolation and network denial are independent facts: their
 * absence must remain visible, but does not turn an observed run into UNKNOWN. */
#define VCS_ZCODE_APP_RUN_PROVED_FLAGS \
    (VCS_ZCODE_APP_RUN_ATTEMPTED | VCS_ZCODE_APP_RUN_LAUNCHED | \
     VCS_ZCODE_APP_RUN_EXITED | VCS_ZCODE_APP_RUN_OUTPUT_COMPLETE)

/* Every refusal names a frozen public spelling via
 * vcs_zcode_app_run_observation_error_string. Required roots are checked
 * across all 32 bytes; a root whose only nonzero byte is index 31 is still
 * present. Out-of-range codes spell "unknown". */
enum vcs_zcode_app_run_observation_error {
    VCS_ZCODE_APP_RUN_OK = 0,            /* "ok" */
    VCS_ZCODE_APP_RUN_ERR_NULL,          /* "null-argument" */
    VCS_ZCODE_APP_RUN_ERR_VERSION,       /* "schema-version" */
    VCS_ZCODE_APP_RUN_ERR_WIRE_SIZE,     /* "wire-size" */
    VCS_ZCODE_APP_RUN_ERR_WIRE_MAGIC,    /* "wire-magic" */
    VCS_ZCODE_APP_RUN_ERR_ROOT_ZERO,     /* "root-zero" */
    VCS_ZCODE_APP_RUN_ERR_FLAGS,         /* "flags-invalid" */
    VCS_ZCODE_APP_RUN_ERR_EXIT_STATUS,   /* "exit-status-invalid" */
    VCS_ZCODE_APP_RUN_ERR_TIME_ORDER,    /* "time-order-invalid" */
    VCS_ZCODE_APP_RUN_ERR_RESERVED,      /* "reserved-nonzero" */
};

struct vcs_zcode_app_run_observation_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t build_receipt_root[32];
    uint8_t artifact_root[32];
    uint8_t invocation_root[32];
    uint8_t stdout_root[32];
    uint8_t stderr_root[32];
    uint8_t confinement_root[32];
    int32_t exit_status; /* INT32_MIN when the process did not exit. */
    int64_t started_unix;
    int64_t finished_unix;
    uint8_t reserved[8];
};

const char *vcs_zcode_app_run_observation_error_string(
    enum vcs_zcode_app_run_observation_error error);
enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_validate(
    const struct vcs_zcode_app_run_observation_v1 *observation);
enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_serialize(
    const struct vcs_zcode_app_run_observation_v1 *observation,
    uint8_t out[VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES]);
enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_app_run_observation_v1 *out);
enum vcs_zcode_app_run_observation_error
vcs_zcode_app_run_observation_v1_root(
    const struct vcs_zcode_app_run_observation_v1 *observation,
    uint8_t out[32]);
bool vcs_zcode_app_run_observation_v1_proves_success(
    const struct vcs_zcode_app_run_observation_v1 *observation);

#endif /* ZCL_VCS_ZCODE_APP_RUN_OBSERVATION_H */
