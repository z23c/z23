/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Candidate-bound immutable inputs for fixed ZCODE actions. */

#ifndef ZCL_VCS_ZCODE_ACTION_INPUT_H
#define ZCL_VCS_ZCODE_ACTION_INPUT_H

#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_ACTION_INPUT_VERSION 1u
#define VCS_ZCODE_ACTION_INPUT_HEADER_BYTES 216u
#define VCS_ZCODE_ACTION_INPUT_ROOT_DOMAIN "zcl.zcode.action_input.v1"
#define VCS_ZCODE_COMPONENT_INPUT_KEY_DOMAIN \
    "zcl.zcode.component_input_key.v1"

/* Whole-package actions accept no caller-selected source or executable.
 * This fixed wire binds the already-authoritative task recipe and dependency
 * lock to one immutable candidate tree. */
#define VCS_ZCODE_PACKAGE_ACTION_INPUT_VERSION 1u
#define VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES 204u
#define VCS_ZCODE_PACKAGE_ACTION_INPUT_ROOT_DOMAIN \
    "zcl.zcode.package_action_input.v1"

enum vcs_zcode_action_input_result {
    VCS_ZCODE_ACTION_INPUT_OK = 0,
    VCS_ZCODE_ACTION_INPUT_NULL,
    VCS_ZCODE_ACTION_INPUT_SHAPE,
    VCS_ZCODE_ACTION_INPUT_LIMIT,
    VCS_ZCODE_ACTION_INPUT_BINDING,
    VCS_ZCODE_ACTION_INPUT_CAS,
    VCS_ZCODE_ACTION_INPUT_ALLOC,
};

struct vcs_zcode_action_input_v1 {
    uint16_t schema_version;
    uint8_t work_kind;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t candidate_source_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t acceptance_tests_root[32];
    uint8_t payload_blob_root[32];
    char *path;
    uint8_t *payload;
    size_t payload_len;
};

/* Execution closure for a reusable lookup key. The caller must independently
 * derive every root from the bytes or policy used by the executor. This API
 * checks nonzero roots and task-bound toolchain/policy roots, but cannot prove
 * that arbitrary compiler, environment, graph or harness roots are honest.
 * The key omits task, candidate, action, producer, verdict and time; those
 * remain bound by independently verified observation and action receipts. */
struct vcs_zcode_component_execution_v1 {
    uint8_t toolchain_capsule_root[32];
    uint8_t compiler_root[32];
    uint8_t flags_root[32];
    uint8_t environment_root[32];
    uint8_t build_graph_root[32];
    uint8_t harness_root[32];
    uint8_t proof_policy_root[32];
    uint8_t sandbox_policy_root[32];
    uint32_t policy_generation;
    uint8_t target;
    uint32_t max_cpu_seconds;
    uint64_t max_memory_bytes;
    uint64_t max_output_bytes;
};

struct vcs_zcode_package_action_input_v1 {
    uint16_t schema_version;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t candidate_source_root[32];
    uint8_t base_source_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t acceptance_recipe_root[32];
};

const char *vcs_zcode_action_input_result_string(
    enum vcs_zcode_action_input_result result);
void vcs_zcode_action_input_init(struct vcs_zcode_action_input_v1 *input);
void vcs_zcode_action_input_free(struct vcs_zcode_action_input_v1 *input);

/* Derive payload bytes from the candidate manifest and tagged blob CAS. */
enum vcs_zcode_action_input_result vcs_zcode_action_input_derive_cas(
    const char *repo_root, const uint8_t task_root[32],
    const uint8_t candidate_root[32], const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, uint8_t work_kind,
    const char *candidate_path, struct vcs_zcode_action_input_v1 *out);

enum vcs_zcode_action_input_result vcs_zcode_action_input_serialize(
    const struct vcs_zcode_action_input_v1 *input, uint8_t **wire,
    size_t *wire_len);
enum vcs_zcode_action_input_result vcs_zcode_action_input_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_action_input_v1 *out);
enum vcs_zcode_action_input_result vcs_zcode_action_input_root(
    const struct vcs_zcode_action_input_v1 *input, uint8_t out[32]);

/* Verify action-input CAS membership and derive a lookup key from the supplied
 * physical computation closure. A matching key never grants proof or
 * acceptance: the receiver still verifies artifact bytes, signatures,
 * freshness, trust domains, contradictory observations and the requested
 * action binding. */
enum vcs_zcode_action_input_result vcs_zcode_component_input_key_derive_cas(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_action_input_v1 *input,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const struct vcs_zcode_component_execution_v1 *execution,
    uint8_t out[32]);

/* Re-derive all semantic roots and prove path/payload membership in the
 * immutable candidate source manifest. */
enum vcs_zcode_action_input_result
vcs_zcode_action_input_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_action_input_v1 *input,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    uint8_t expected_work_kind);

/* Load by domain-separated address, rederive every binding, and optionally
 * return only the verified payload. The payload form allocates for caller. */
enum vcs_zcode_action_input_result vcs_zcode_action_input_load_payload_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t expected_work_kind, uint8_t **payload, size_t *payload_len);
enum vcs_zcode_action_input_result vcs_zcode_action_input_verify_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t expected_work_kind);

enum vcs_zcode_action_input_result vcs_zcode_package_action_input_derive(
    const char *repo_root, const uint8_t task_root[32],
    const uint8_t candidate_root[32], const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_package_action_input_v1 *out);
enum vcs_zcode_action_input_result vcs_zcode_package_action_input_serialize(
    const struct vcs_zcode_package_action_input_v1 *input,
    uint8_t out[VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES]);
enum vcs_zcode_action_input_result vcs_zcode_package_action_input_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_package_action_input_v1 *out);
enum vcs_zcode_action_input_result vcs_zcode_package_action_input_root(
    const struct vcs_zcode_package_action_input_v1 *input, uint8_t out[32]);
enum vcs_zcode_action_input_result
vcs_zcode_package_action_input_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_package_action_input_v1 *input,
    const uint8_t task_root[32], const uint8_t candidate_root[32]);
enum vcs_zcode_action_input_result vcs_zcode_package_action_input_load_cas(
    const char *repo_root, const uint8_t input_root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_package_action_input_v1 *out);

#endif /* ZCL_VCS_ZCODE_ACTION_INPUT_H */
