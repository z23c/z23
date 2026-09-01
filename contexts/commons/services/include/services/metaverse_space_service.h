/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact-plan CAS and blob-carrier service for Sovereign Space v1. */

#ifndef ZCL_SERVICES_METAVERSE_SPACE_SERVICE_H
#define ZCL_SERVICES_METAVERSE_SPACE_SERVICE_H

#include "base/result.h"
#include "vcs/space.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_package_store;

enum metaverse_space_object_kind {
  METAVERSE_SPACE_OBJECT_NONE = 0,
  METAVERSE_SPACE_OBJECT_SERVICE_DESCRIPTOR,
  METAVERSE_SPACE_OBJECT_MANIFEST,
};

struct metaverse_space_plan_out {
  char object_root[65];
  char plan_token[65];
  size_t wire_bytes;
};

struct metaverse_space_commit_out {
  char object_root[65];
  bool already_committed;
};

struct metaverse_space_object {
  enum metaverse_space_object_kind kind;
  uint8_t root[32];
  union {
    struct vcs_service_descriptor_v1 service;
    struct vcs_space_manifest_v1 manifest;
  } as;
};

struct zcl_result metaverse_space_service_plan(
    const struct vcs_service_descriptor_v1 *descriptor,
    struct metaverse_space_plan_out *out);
struct zcl_result metaverse_space_service_commit(
    const char *workspace,
    const struct vcs_service_descriptor_v1 *descriptor,
    const char *plan_token, bool confirm,
    struct metaverse_space_commit_out *out);

struct zcl_result metaverse_space_manifest_plan(
    const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify,
    struct metaverse_space_plan_out *out);
struct zcl_result metaverse_space_manifest_commit(
    const char *workspace, const struct vcs_space_manifest_v1 *manifest,
    const struct vcs_space_manifest_verify_context *verify,
    const char *plan_token, bool confirm,
    struct metaverse_space_commit_out *out);

/* Every read re-parses the exact bytes and re-derives their semantic root.
 * Expired manifests remain inspectable evidence; callers separately run the
 * live/chain verifier before discovery or publication. */
struct zcl_result metaverse_space_show(
    const char *workspace, const char *object_root,
    struct metaverse_space_object *out);
struct zcl_result metaverse_space_show_bounded(
    const char *workspace, const char *object_root, size_t maximum_wire_bytes,
    struct metaverse_space_object *out, size_t *wire_bytes_out);

/* Mirror any committed service/manifest wire into the existing one-chunk blob
 * carrier. Admit performs the inverse and stores only after semantic-root
 * agreement. No network or policy decision lives in these byte adapters. */
struct zcl_result metaverse_space_publish(
    struct vcs_package_store *store, const char *workspace,
    const char *object_root, char out_blob_root[65],
    enum metaverse_space_object_kind *kind_out);
struct zcl_result metaverse_space_transport_root(
    const char *workspace, const char *object_root,
    char out_blob_root[65], enum metaverse_space_object_kind *kind_out);
struct zcl_result metaverse_space_blob_inspect(
    struct vcs_package_store *store, const char *blob_root,
    struct metaverse_space_object *out);
struct zcl_result metaverse_space_blob_inspect_bounded(
    struct vcs_package_store *store, const char *blob_root,
    size_t maximum_wire_bytes, struct metaverse_space_object *out,
    size_t *wire_bytes_out);
struct zcl_result metaverse_space_admit(
    struct vcs_package_store *store, const char *workspace,
    const char *expected_object_root, const char *blob_root,
    enum metaverse_space_object_kind *kind_out, bool *new_out);
struct zcl_result metaverse_space_admit_bounded(
    struct vcs_package_store *store, const char *workspace,
    const char *expected_object_root, const char *blob_root,
    size_t maximum_wire_bytes, enum metaverse_space_object_kind *kind_out,
    bool *new_out);

#endif /* ZCL_SERVICES_METAVERSE_SPACE_SERVICE_H */
