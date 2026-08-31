/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical content.v2 carrier for one fixed ZCODE build action. */

#ifndef ZCL_VCS_ZCODE_WORK_CONTEXT_H
#define ZCL_VCS_ZCODE_WORK_CONTEXT_H

#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_WORK_CONTEXT_VERSION 1u
#define VCS_ZCODE_WORK_CONTEXT_PATH "zcode-work-context.v1"
#define VCS_ZCODE_WORK_CONTEXT_FIXED_BYTES 628u
#define VCS_ZCODE_WORK_CONTEXT_PROFILE_MAX 31u

struct vcs_package_store;

enum vcs_zcode_work_context_result {
    VCS_ZCODE_WORK_CONTEXT_OK = 0,
    VCS_ZCODE_WORK_CONTEXT_NULL,
    VCS_ZCODE_WORK_CONTEXT_SHAPE,
    VCS_ZCODE_WORK_CONTEXT_LIMIT,
    VCS_ZCODE_WORK_CONTEXT_STALE,
    VCS_ZCODE_WORK_CONTEXT_ACTION,
    VCS_ZCODE_WORK_CONTEXT_STORE,
    VCS_ZCODE_WORK_CONTEXT_ABSENT,
    VCS_ZCODE_WORK_CONTEXT_CORRUPT,
    VCS_ZCODE_WORK_CONTEXT_ALLOC,
};

struct vcs_zcode_work_context_v1 {
    uint8_t source_sha256[32];
    char profile[VCS_ZCODE_WORK_CONTEXT_PROFILE_MAX + 1u];
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 proof_policy;
    uint8_t *fixed_input;
    size_t fixed_input_len;
    /* Optional second content.v2 file. Local-only contexts may omit it;
     * requester-to-worker contexts require the canonical candidate bundle. */
    uint8_t *candidate_authority;
    size_t candidate_authority_len;
    uint8_t *task_authority;
    size_t task_authority_len;
};

struct vcs_zcode_work_context_roots {
    uint8_t source_root[32];
    uint8_t source_manifest_id[32];
    uint8_t input_root[32];
    uint8_t action_root[32];
};

const char *vcs_zcode_work_context_result_string(
    enum vcs_zcode_work_context_result result);
void vcs_zcode_work_context_init(struct vcs_zcode_work_context_v1 *context);
void vcs_zcode_work_context_free(struct vcs_zcode_work_context_v1 *context);

/* Import the mandatory remote candidate authority carried beside this
 * context. A local-only context may omit it; remote admission may not. */
enum vcs_zcode_candidate_bundle_result
vcs_zcode_work_context_import_authority(
    const char *repo_root, const struct vcs_zcode_work_context_v1 *context);

/* The context wire is canonical but its network address is the enclosing
 * one-file content.v2 package root. This keeps transfer, resume, quotas, and
 * anti-abuse limits owned by the existing package store and swarm. */
enum vcs_zcode_work_context_result vcs_zcode_work_context_serialize(
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix,
    uint8_t **out, size_t *out_len);
enum vcs_zcode_work_context_result vcs_zcode_work_context_parse(
    const uint8_t *wire, size_t wire_len, int64_t now_unix,
    struct vcs_zcode_work_context_v1 *out);

/* Reconstruct the already-frozen fixed-action identity. The v1 carrier is
 * action-neutral: the signed request supplies the registered kind while the
 * context supplies the exact immutable input bytes. */
enum vcs_zcode_work_context_result vcs_zcode_work_context_action_root_for_kind(
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, uint8_t action_root[32], uint8_t input_root[32]);
enum vcs_zcode_work_context_result vcs_zcode_work_context_action_root(
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix,
    uint8_t action_root[32], uint8_t input_root[32]);

enum vcs_zcode_work_context_result vcs_zcode_work_context_put(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, int64_t now_unix,
    uint8_t package_root[32], uint8_t action_root[32]);
enum vcs_zcode_work_context_result vcs_zcode_work_context_put_for_kind(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, uint8_t package_root[32], uint8_t action_root[32]);
/* Remote carrier: the same metadata plus every candidate-tree file as normal
 * content.v2 chunks under candidate/. */
enum vcs_zcode_work_context_result
vcs_zcode_work_context_put_for_kind_with_candidate(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_context_v1 *context, const char *kind,
    int64_t now_unix, const char *repo_root, uint8_t package_root[32],
    uint8_t action_root[32]);
enum vcs_zcode_work_context_result vcs_zcode_work_context_get(
    struct vcs_package_store *store, const uint8_t package_root[32],
    int64_t now_unix, struct vcs_zcode_work_context_v1 *out);

/* Restore one remote carrier into an explicit receiver CAS. The receiver
 * imports the existing task/candidate authorities and complete candidate tree,
 * then independently binds the exact candidate-manifest bytes to the action's
 * source-manifest identity before admitting the fixed action objects. */
enum vcs_zcode_work_context_result
vcs_zcode_work_context_restore_for_kind(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *receiver_root, const char *kind, int64_t now_unix,
    struct vcs_zcode_work_context_roots *roots);

#endif /* ZCL_VCS_ZCODE_WORK_CONTEXT_H */
